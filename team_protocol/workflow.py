from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .chatgpt import AuthContext, ChatGPTClient
from .cpa import build_cpa, build_cpa_filename
from .management import ManagementClient
from .registrar import (
    MailboxCredentials,
    RegistrarAdapter,
    RegistrarIdentityError,
    RegistrarProxyLease,
)
from .sub2api import Sub2APIClient, build_sub2api_account


_FINGERPRINT_STATE_STEP = "_fingerprint_profile"
_REGISTRAR_PROVIDER_STATE_STEP = "_registrar_provider_state"
_FINGERPRINT_BOUND_STEPS = (
    "old_login",
    "old_workspace",
    "invite",
    "old_leave",
    "new_login",
    "new_workspace",
    "pat",
)


@dataclass(frozen=True)
class AccountSpec:
    email: str
    password: str = ""


@dataclass(frozen=True)
class WorkflowConfig:
    old_account: AccountSpec
    new_account: AccountSpec
    workspace_id: str
    proxy: str
    pat_name: str
    pat_ttl: int
    output_dir: Path
    management_base_url: str
    management_key: str
    push: bool
    replace: bool
    remote_name: str
    invite_settle_seconds: float
    sub2api_base_url: str = "https://sub2api.upic.cloud"
    sub2api_email: str = ""
    sub2api_password: str = ""
    sub2api_push: bool = False
    sub2api_concurrency: int = 10
    sub2api_priority: int = 1


class CheckpointStore(Protocol):
    def get(self, name: str) -> Any: ...

    def set(self, name: str, value: Any) -> None: ...


class WorkflowCancelled(RuntimeError):
    pass


class WorkflowIdentityError(RuntimeError):
    ALLOWED_CODES = frozenset({"alias_disabled", "mailbox_credentials_invalid"})
    ALLOWED_ROLES = frozenset({"current", "next"})

    def __init__(self, code: str, role: str) -> None:
        normalized_code = str(code or "").strip()
        normalized_role = str(role or "").strip()
        if normalized_code not in self.ALLOWED_CODES:
            raise ValueError("unsupported workflow identity error code")
        if normalized_role not in self.ALLOWED_ROLES:
            raise ValueError("unsupported workflow identity role")
        self.code = normalized_code
        self.role = normalized_role
        super().__init__(f"{normalized_code}:{normalized_role}")


def _email_from_item(item: Mapping[str, Any]) -> str:
    user = item.get("user") if isinstance(item.get("user"), dict) else {}
    return str(
        item.get("email")
        or item.get("email_address")
        or item.get("user_email")
        or user.get("email")
        or ""
    ).strip().casefold()


def _items(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    for key in ("items", "users", "account_invites"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


class WorkflowRunner:
    def __init__(
        self,
        config: WorkflowConfig,
        *,
        checkpoint_store: CheckpointStore,
        old_mailbox: MailboxCredentials,
        new_mailbox: MailboxCredentials,
        expanded_proxy: str | None = None,
        registrar: Any = None,
        chatgpt: Any = None,
        management: Any = None,
        sub2api: Any = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        logger: Callable[[str], None] | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.config = config
        self.state = checkpoint_store
        if not callable(getattr(self.state, "get", None)) or not callable(
            getattr(self.state, "set", None)
        ):
            raise TypeError("checkpoint_store must provide get(name) and set(name, value)")
        self._mailboxes = {
            "old_login": old_mailbox,
            "new_login": new_mailbox,
        }
        self.registrar = registrar or RegistrarAdapter(config.output_dir / ".registrar")
        self.fingerprint_profile = None
        self.fingerprint_restored = False
        profile_resolver = getattr(self.registrar, "resolve_session_profile", None)
        profile_serializer = getattr(self.registrar, "serialize_session_profile", None)
        if callable(profile_resolver) and callable(profile_serializer):
            stored_profile = self.state.get(_FINGERPRINT_STATE_STEP)
            if stored_profile is not None and not isinstance(stored_profile, Mapping):
                raise RuntimeError("stored fingerprint profile is not a JSON object")
            if stored_profile is None and any(
                self.state.get(step) is not None for step in _FINGERPRINT_BOUND_STEPS
            ):
                raise RuntimeError(
                    "checkpoint contains OpenAI steps but no fingerprint profile"
                )
            self.fingerprint_restored = isinstance(stored_profile, Mapping)
            self.fingerprint_profile = profile_resolver(stored_profile)
            serialized_profile = profile_serializer(self.fingerprint_profile)
            if stored_profile != serialized_profile:
                self.state.set(_FINGERPRINT_STATE_STEP, serialized_profile)
        self._proxy_lease = RegistrarProxyLease(
            explicit_proxy=config.proxy if expanded_proxy is None else expanded_proxy,
            preexpanded=expanded_proxy is not None,
        )
        self._proxy_lease.__enter__()
        self.effective_proxy = self._proxy_lease.proxy
        try:
            chatgpt_kwargs: dict[str, Any] = {"proxy": self.effective_proxy}
            if self.fingerprint_profile is not None:
                chatgpt_kwargs["session_profile"] = self.fingerprint_profile
            self.chatgpt = chatgpt or ChatGPTClient(**chatgpt_kwargs)
        except Exception:
            self._proxy_lease.close()
            raise
        self.management = management
        self.sub2api = sub2api
        self.verbose = verbose
        self.stop_event = stop_event
        self.logger = logger
        self.event_callback = event_callback
        self._owns_chatgpt = chatgpt is None

    def close(self) -> None:
        try:
            if self._owns_chatgpt:
                self.chatgpt.close()
        finally:
            self._proxy_lease.close()

    def _log(self, message: str) -> None:
        if self.logger is not None:
            self.logger(message)
        if self.verbose:
            print(message)

    def _emit_event(self, event: dict[str, Any]) -> None:
        if self.event_callback is None:
            return
        try:
            self.event_callback(event)
        except Exception:
            pass

    def _run_stage(self, step: str, operation: Callable[[], Any]) -> Any:
        self._emit_event({"type": "step", "step": step, "state": "active"})
        try:
            result = operation()
        except WorkflowCancelled:
            self._emit_event({"type": "step", "step": step, "state": "cancelled"})
            raise
        except Exception:
            self._emit_event({"type": "step", "step": step, "state": "error"})
            raise
        self._emit_event(
            {
                "type": "step",
                "step": step,
                "state": "skipped" if result is None else "done",
            }
        )
        return result

    def _check_cancel(self) -> None:
        if self.stop_event is not None and self.stop_event.is_set():
            raise WorkflowCancelled("workflow cancelled")

    def _registrar_event(self, event: dict[str, Any]) -> None:
        level = str(event.get("level") or "info").upper()
        step = str(event.get("step") or "").strip()
        message = str(event.get("message") or "").strip()
        step_text = f"[{step}] " if step else ""
        self._log(f"[{level}] {step_text}{message}")

    def _login(self, spec: AccountSpec, step: str) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get(step)
        if isinstance(cached, dict):
            self._log(f"[resume] {step}")
            return cached
        mailbox = self._mailboxes.get(step)
        action = "register" if step == "new_login" else "login"
        self._log(f"[{action}] {spec.email}")
        login_kwargs: dict[str, Any] = {
            "email": spec.email,
            "account_password": spec.password,
            "mailbox": mailbox,
            "proxy": self.effective_proxy,
            "workspace_id": self.config.workspace_id,
            "verbose": self.verbose and self.logger is None,
            "stop_event": self.stop_event,
            "event_callback": self._registrar_event if self.logger is not None else None,
        }
        if self.fingerprint_profile is not None:
            login_kwargs["session_profile"] = self.fingerprint_profile
        provider_state = self.state.get(_REGISTRAR_PROVIDER_STATE_STEP)
        if provider_state is not None and not isinstance(provider_state, Mapping):
            raise RuntimeError("stored registrar provider state is not a JSON object")
        login_kwargs["provider_initial_state"] = dict(provider_state or {})
        login_kwargs["provider_state_callback"] = self._checkpoint_provider_state
        try:
            session = self.registrar.login(**login_kwargs)
        except RegistrarIdentityError as exc:
            self._check_cancel()
            role = "current" if step == "old_login" else "next"
            raise WorkflowIdentityError(exc.code, role) from exc
        except Exception:
            self._check_cancel()
            raise
        self._check_cancel()
        self.state.set(step, session)
        return session

    def _checkpoint_provider_state(self, provider_state: dict[str, Any]) -> None:
        if not isinstance(provider_state, dict):
            raise TypeError("registrar provider state callback must provide an object")
        self.state.set(_REGISTRAR_PROVIDER_STATE_STEP, provider_state)

    def _switch_workspace(self, source: Mapping[str, Any], step: str) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get(step)
        if isinstance(cached, dict):
            self._log(f"[resume] {step}")
            return cached
        context = AuthContext.from_mapping(source)
        if not context.session_token:
            raise RuntimeError("login result has no session_token")
        self._log(f"[workspace] {self.config.workspace_id}")
        session = self.chatgpt.refresh_session(
            context.session_token,
            account_id=self.config.workspace_id,
        )
        self._check_cancel()
        switched = AuthContext.from_mapping(session)
        if switched.account_id != self.config.workspace_id:
            raise RuntimeError(
                f"workspace switch returned {switched.account_id or '<empty>'}, expected {self.config.workspace_id}"
            )
        self.state.set(step, session)
        return session

    def _ensure_invited(self, old_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("invite")
        if isinstance(cached, dict):
            self._log("[resume] invite")
            return cached
        context = AuthContext.from_mapping(old_session)
        target = self.config.new_account.email.casefold()
        members = self.chatgpt.get_members(context.access_token, self.config.workspace_id)
        if any(_email_from_item(item) == target for item in _items(members)):
            result = {"action": "already-member", "email": self.config.new_account.email}
        else:
            invites = self.chatgpt.get_invites(context.access_token, self.config.workspace_id)
            if any(_email_from_item(item) == target for item in _items(invites)):
                result = {"action": "already-invited", "email": self.config.new_account.email}
            else:
                response = self.chatgpt.invite(
                    context.access_token,
                    self.config.workspace_id,
                    self.config.new_account.email,
                )
                result = {"action": "invited", "email": self.config.new_account.email, "response": response}
        self.state.set("invite", result)
        self._log(f"[invite] {result['action']} {self.config.new_account.email}")
        if self.config.invite_settle_seconds:
            if self.stop_event is not None:
                if self.stop_event.wait(self.config.invite_settle_seconds):
                    raise WorkflowCancelled("workflow cancelled")
            else:
                threading.Event().wait(self.config.invite_settle_seconds)
        return result

    def _leave_old_account(self, old_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("old_leave")
        if isinstance(cached, dict):
            self._log("[resume] old_leave")
            return cached
        context = AuthContext.from_mapping(old_session)
        if not context.user_id:
            raise RuntimeError("old account session has no user id")
        members = self.chatgpt.get_members(context.access_token, self.config.workspace_id)
        member_ids = {
            str(item.get("id") or item.get("user_id") or "").strip()
            for item in _items(members)
        }
        if context.user_id not in member_ids:
            result = {"action": "already-left", "user_id": context.user_id}
        else:
            response = self.chatgpt.leave(
                context.access_token,
                self.config.workspace_id,
                context.user_id,
            )
            result = {"action": "left", "user_id": context.user_id, "response": response}
        self.state.set("old_leave", result)
        self._log(f"[leave] {result['action']} {context.user_id}")
        return result

    def _create_pat(self, new_session: Mapping[str, Any]) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get("pat")
        if isinstance(cached, dict) and cached.get("access_token"):
            self._log("[resume] pat")
            return cached
        context = AuthContext.from_mapping(new_session)
        self._log(f"[pat] {self.config.pat_name}")
        result = self.chatgpt.create_personal_access_token(
            context.access_token,
            self.config.workspace_id,
            name=self.config.pat_name,
            ttl=self.config.pat_ttl,
        )
        if not result.get("access_token"):
            raise RuntimeError("PAT response has no access_token")
        self.state.set("pat", result)
        return result

    def _write_cpa(self, new_session: Mapping[str, Any], pat: Mapping[str, Any]) -> Path:
        self._check_cancel()
        cached = self.state.get("cpa")
        if isinstance(cached, dict):
            cached_path = Path(str(cached.get("path") or ""))
            if cached_path.exists():
                self._log("[resume] cpa")
                return cached_path
        payload = build_cpa(new_session, personal_access_token=str(pat.get("access_token") or ""))
        filename = build_cpa_filename(str(payload.get("email") or self.config.new_account.email))
        path = self.config.output_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.state.set("cpa", {"path": str(path.resolve()), "filename": filename})
        self._log(f"[cpa] {path.resolve()}")
        return path

    def _push(self, cpa_path: Path) -> dict[str, Any] | None:
        self._check_cancel()
        if not self.config.push:
            return None
        cached = self.state.get("push")
        if isinstance(cached, dict) and cached.get("verified"):
            self._log("[resume] push")
            return cached
        if not self.config.management_key:
            raise RuntimeError("management.api_key or CPA_MANAGEMENT_KEY is required when push=true")
        client = self.management or ManagementClient(
            self.config.management_base_url,
            self.config.management_key,
        )
        result = client.push_file(
            cpa_path,
            remote_name=self.config.remote_name or None,
            replace=self.config.replace,
        )
        payload = {
            "action": result.action,
            "filename": result.filename,
            "verified": result.verified,
            "message": result.message,
        }
        self.state.set("push", payload)
        self._log(f"[push] {result.action} verified={result.verified}")
        return payload

    def _push_sub2api(
        self,
        new_session: Mapping[str, Any],
        pat: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        self._check_cancel()
        if not self.config.sub2api_push:
            return None
        cached = self.state.get("push_sub2api")
        if isinstance(cached, dict) and cached.get("verified"):
            self._log("[resume] push_sub2api")
            return cached
        if not self.config.sub2api_email or not self.config.sub2api_password:
            raise RuntimeError("Sub2API email and password are required when sub2api.push=true")
        token = str(pat.get("access_token") or "").strip()
        account = build_sub2api_account(
            new_session,
            personal_access_token=token,
            concurrency=self.config.sub2api_concurrency,
            priority=self.config.sub2api_priority,
        )
        owns_client = self.sub2api is None
        client = self.sub2api or Sub2APIClient(
            self.config.sub2api_base_url,
            self.config.sub2api_email,
            self.config.sub2api_password,
        )
        try:
            result = client.push_account(account)
        finally:
            if owns_client:
                client.close()
        payload = {
            "action": result.action,
            "account_name": result.account_name,
            "verified": result.verified,
            "message": result.message,
        }
        self.state.set("push_sub2api", payload)
        self._log(f"[sub2api] {result.action} verified={result.verified}")
        return payload

    def run(self) -> dict[str, Any]:
        try:
            self._log(f"[proxy] {self._proxy_lease.description}")
            if self.fingerprint_profile is not None:
                profile_action = "已恢复" if self.fingerprint_restored else "已生成"
                self._log(
                    f"[fingerprint] {profile_action}并锁定 "
                    f"{getattr(self.fingerprint_profile, 'profile_id', '<unknown>')} "
                    f"impersonate={getattr(self.fingerprint_profile, 'impersonate', '<unknown>')}"
                )
            self._check_cancel()
            def old_login_stage() -> dict[str, Any]:
                login = self._login(self.config.old_account, "old_login")
                return self._switch_workspace(login, "old_workspace")

            old_workspace = self._run_stage("old_login", old_login_stage)
            invite = self._run_stage("invite", lambda: self._ensure_invited(old_workspace))
            old_leave = self._run_stage(
                "old_leave", lambda: self._leave_old_account(old_workspace)
            )

            def new_login_stage() -> dict[str, Any]:
                login = self._login(self.config.new_account, "new_login")
                return self._switch_workspace(login, "new_workspace")

            new_workspace = self._run_stage("new_login", new_login_stage)
            pat = self._run_stage("pat", lambda: self._create_pat(new_workspace))
            cpa_path = self._run_stage(
                "cpa", lambda: self._write_cpa(new_workspace, pat)
            )
            push = self._run_stage("push", lambda: self._push(cpa_path))
            sub2api = self._run_stage(
                "push_sub2api", lambda: self._push_sub2api(new_workspace, pat)
            )
            self._check_cancel()
            summary = {
                "old_email": self.config.old_account.email,
                "new_email": self.config.new_account.email,
                "workspace_id": self.config.workspace_id,
                "invite": invite.get("action"),
                "old_leave": old_leave.get("action"),
                "cpa_path": str(cpa_path.resolve()),
                "push": push,
                "sub2api": sub2api,
            }
            self.state.set("complete", summary)
            return summary
        finally:
            self.close()
