from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
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
    proxy_region_code,
)
from .sub2api import Sub2APIClient, build_sub2api_account


_FINGERPRINT_STATE_STEP = "_fingerprint_profile"
_BROWSERFORGE_STATE_STEP = "_browserforge_fingerprint"
_BROWSER_TOOLCHAIN_STATE_STEP = "_browser_toolchain"
_PROXY_GEO_STATE_STEP = "_proxy_geo"
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
_MAX_CLOCK_SKEW_SECONDS = 60.0


@dataclass(frozen=True)
class AccountSpec:
    email: str
    password: str = ""


@dataclass(frozen=True)
class AccountNetworkSpec:
    proxy: str
    proxy_sid: str
    proxy_geo: Mapping[str, Any] | None = None
    fingerprint_profile: Mapping[str, Any] | None = None
    browserforge_fingerprint: Mapping[str, Any] | None = None
    toolchain: Mapping[str, Any] | None = None
    persist_callback: Callable[[Mapping[str, Any]], Any] | None = None
    legacy_recovery: bool = False


@dataclass
class _AccountNetworkRuntime:
    proxy: str | None
    description: str
    proxy_geo: dict[str, Any] | None
    fingerprint_profile: Any
    fingerprint_restored: bool
    browserforge_fingerprint: Any = None


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
    sub2api_base_url: str = "https://sub2api.example.com"
    sub2api_email: str = ""
    sub2api_password: str = ""
    sub2api_api_key: str = ""
    sub2api_totp_secret: str = ""
    sub2api_push: bool = False
    sub2api_concurrency: int = 10
    sub2api_priority: int = 1
    sub2api_group_id: int | None = None


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


class _WorkspaceSwitchError(RuntimeError):
    pass


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
        old_network: AccountNetworkSpec | None = None,
        new_network: AccountNetworkSpec | None = None,
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
        if (old_network is None) != (new_network is None):
            raise ValueError("old_network and new_network must be supplied together")
        self._account_network_mode = old_network is not None
        self._proxy_leases: list[RegistrarProxyLease] = []
        self._networks: dict[str, _AccountNetworkRuntime] = {}
        self._chatgpt_clients: dict[str, Any] = {}
        self._owned_chatgpt_clients: list[Any] = []
        try:
            if self._account_network_mode:
                assert old_network is not None and new_network is not None
                account_specs = {"old": old_network, "new": new_network}
                account_leases: dict[str, RegistrarProxyLease] = {}
                for role, network in (("old", old_network), ("new", new_network)):
                    lease = RegistrarProxyLease(
                        explicit_proxy=network.proxy,
                        preexpanded=True,
                    )
                    lease.__enter__()
                    self._proxy_leases.append(lease)
                    account_leases[role] = lease
                geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
                current_geos: dict[str, Any] = {}
                if callable(geo_resolver):
                    with ThreadPoolExecutor(
                        max_workers=2,
                        thread_name_prefix="account-proxy-geo",
                    ) as executor:
                        futures = {
                            role: executor.submit(geo_resolver, lease.proxy)
                            for role, lease in account_leases.items()
                        }
                        current_geos = {
                            role: future.result()
                            for role, future in futures.items()
                        }
                for role in ("old", "new"):
                    self._networks[role] = self._resolve_account_network(
                        role,
                        account_specs[role],
                        account_leases[role],
                        current_geo=current_geos.get(role),
                    )
            else:
                lease = RegistrarProxyLease(
                    explicit_proxy=config.proxy if expanded_proxy is None else expanded_proxy,
                    preexpanded=expanded_proxy is not None,
                )
                lease.__enter__()
                self._proxy_leases.append(lease)
                legacy = self._resolve_legacy_network(lease)
                self._networks = {"old": legacy, "new": legacy}

            if chatgpt is not None:
                self._chatgpt_clients = {"old": chatgpt, "new": chatgpt}
            elif self._account_network_mode:
                for role in ("old", "new"):
                    runtime = self._networks[role]
                    kwargs: dict[str, Any] = {"proxy": runtime.proxy}
                    if runtime.fingerprint_profile is not None:
                        kwargs["session_profile"] = runtime.fingerprint_profile
                    client = ChatGPTClient(**kwargs)
                    self._chatgpt_clients[role] = client
                    self._owned_chatgpt_clients.append(client)
            else:
                runtime = self._networks["old"]
                kwargs = {"proxy": runtime.proxy}
                if runtime.fingerprint_profile is not None:
                    kwargs["session_profile"] = runtime.fingerprint_profile
                client = ChatGPTClient(**kwargs)
                self._chatgpt_clients = {"old": client, "new": client}
                self._owned_chatgpt_clients.append(client)
        except Exception:
            for client in self._owned_chatgpt_clients:
                try:
                    client.close()
                except Exception:
                    pass
            for lease in self._proxy_leases:
                lease.close()
            raise
        self._proxy_lease = self._proxy_leases[0]
        self.effective_proxy = self._networks["old"].proxy
        self.fingerprint_profile = self._networks["old"].fingerprint_profile
        self.fingerprint_restored = self._networks["old"].fingerprint_restored
        self.proxy_geo = self._networks["old"].proxy_geo
        self.chatgpt = self._chatgpt_clients["old"]
        self.management = management
        self.sub2api = sub2api
        self.verbose = verbose
        self.stop_event = stop_event
        self.logger = logger
        self.event_callback = event_callback
        self._owns_chatgpt = bool(self._owned_chatgpt_clients)

    def close(self) -> None:
        seen: set[int] = set()
        for client in self._owned_chatgpt_clients:
            marker = id(client)
            if marker in seen:
                continue
            seen.add(marker)
            try:
                client.close()
            except Exception:
                pass
        for lease in self._proxy_leases:
            try:
                lease.close()
            except Exception:
                pass

    def _resolve_browserforge_assets(
        self,
        profile: Any,
        *,
        stored_fingerprint: Mapping[str, Any] | None,
        stored_toolchain: Mapping[str, Any] | None,
        has_openai_checkpoint: bool,
        legacy_recovery: bool = False,
    ) -> tuple[Any, dict[str, Any] | None, dict[str, Any] | None]:
        resolver = getattr(self.registrar, "resolve_browserforge_fingerprint", None)
        serializer = getattr(self.registrar, "serialize_browserforge_fingerprint", None)
        toolchain_resolver = getattr(self.registrar, "browser_toolchain_metadata", None)
        if not callable(resolver):
            return None, None, None
        if not callable(serializer) or not callable(toolchain_resolver):
            raise RuntimeError("registrar BrowserForge integration is incomplete")
        if stored_fingerprint is None and has_openai_checkpoint and not legacy_recovery:
            raise RuntimeError(
                "checkpoint contains OpenAI steps but no BrowserForge fingerprint"
            )
        if stored_fingerprint is None and legacy_recovery:
            return None, None, None
        current_toolchain = dict(toolchain_resolver(profile))
        if stored_toolchain is not None and dict(stored_toolchain) != current_toolchain:
            raise RuntimeError("account browser toolchain no longer matches the locked identity")
        fingerprint = resolver(profile, stored_fingerprint)
        serialized = serializer(fingerprint)
        if stored_fingerprint is not None and dict(stored_fingerprint) != serialized:
            raise RuntimeError("stored BrowserForge fingerprint changed during restoration")
        return fingerprint, serialized, current_toolchain

    @staticmethod
    def _account_bound_steps(role: str) -> tuple[str, ...]:
        if role == "old":
            return ("old_login", "old_workspace", "invite", "old_leave")
        return ("new_login", "new_workspace_login", "new_workspace", "pat")

    def _resolve_account_network(
        self,
        role: str,
        spec: AccountNetworkSpec,
        lease: RegistrarProxyLease,
        *,
        current_geo: Mapping[str, Any] | None = None,
    ) -> _AccountNetworkRuntime:
        profile_resolver = getattr(self.registrar, "resolve_session_profile", None)
        profile_serializer = getattr(self.registrar, "serialize_session_profile", None)
        if not callable(profile_resolver) or not callable(profile_serializer):
            raise RuntimeError("registrar fingerprint integration is incomplete")
        stored_profile = spec.fingerprint_profile
        stored_geo = spec.proxy_geo
        stored_browserforge = spec.browserforge_fingerprint
        stored_toolchain = spec.toolchain
        for name, value in (
            ("fingerprint profile", stored_profile),
            ("proxy geo", stored_geo),
            ("BrowserForge fingerprint", stored_browserforge),
            ("browser toolchain", stored_toolchain),
        ):
            if value is not None and not isinstance(value, Mapping):
                raise RuntimeError(f"stored account {name} is not a JSON object")
        has_openai_checkpoint = any(
            self.state.get(step) is not None
            for step in self._account_bound_steps(role)
        )
        if stored_profile is None and has_openai_checkpoint:
            raise RuntimeError(
                f"checkpoint contains {role} OpenAI steps but no account fingerprint"
            )
        if stored_profile is not None and stored_geo is None:
            raise RuntimeError("stored account fingerprint has no proxy geo identity")

        geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
        if not callable(geo_resolver):
            raise RuntimeError("registrar proxy geo integration is incomplete")
        resolved_geo = current_geo if current_geo is not None else geo_resolver(lease.proxy)
        if not isinstance(resolved_geo, Mapping):
            raise RuntimeError("proxy geo resolver did not return an object")
        current_geo = dict(resolved_geo)
        if not current_geo.get("resolved"):
            raise RuntimeError("proxy geolocation could not be resolved in strict identity mode")
        if current_geo.get("timezone_exact") is False:
            raise RuntimeError("proxy geolocation did not provide an exact timezone")
        if str(current_geo.get("source") or "").strip() == "ipwho.is":
            if current_geo.get("clock_checked") is not True:
                raise RuntimeError("proxy geolocation could not verify the local UTC clock")
            try:
                clock_skew_seconds = float(current_geo["clock_skew_seconds"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "proxy geolocation returned an invalid UTC clock measurement"
                ) from exc
            if abs(clock_skew_seconds) > _MAX_CLOCK_SKEW_SECONDS:
                raise RuntimeError(
                    "local UTC clock differs from the proxy time source by more than "
                    f"{int(_MAX_CLOCK_SKEW_SECONDS)} seconds"
                )
        geo = dict(stored_geo) if isinstance(stored_geo, Mapping) else current_geo
        configured_region = proxy_region_code(lease.proxy or "")
        resolved_country = str(current_geo.get("country_code") or "").strip().upper()
        if configured_region and configured_region != resolved_country:
            raise RuntimeError(
                f"proxy region {configured_region} does not match resolved country {resolved_country or '<empty>'}"
            )

        restored = isinstance(stored_profile, Mapping)
        profile = profile_resolver(stored_profile, geo_hint=geo)
        serialized_profile = profile_serializer(profile)
        if stored_profile is not None and dict(stored_profile) != serialized_profile:
            raise RuntimeError("stored account fingerprint changed during restoration")
        browserforge, serialized_browserforge, toolchain = (
            self._resolve_browserforge_assets(
                profile,
                stored_fingerprint=stored_browserforge,
                stored_toolchain=stored_toolchain,
                has_openai_checkpoint=has_openai_checkpoint,
                legacy_recovery=spec.legacy_recovery,
            )
        )
        updates: dict[str, Any] = {
            "proxy_geo": geo,
            "fingerprint_profile": serialized_profile,
        }
        if serialized_browserforge is not None:
            updates["browserforge_fingerprint"] = serialized_browserforge
        if toolchain is not None:
            updates["toolchain"] = toolchain
        if spec.persist_callback is not None:
            spec.persist_callback(updates)
        return _AccountNetworkRuntime(
            proxy=lease.proxy,
            description=lease.description,
            proxy_geo=geo,
            fingerprint_profile=profile,
            fingerprint_restored=restored,
            browserforge_fingerprint=browserforge,
        )

    def _resolve_legacy_network(
        self,
        lease: RegistrarProxyLease,
    ) -> _AccountNetworkRuntime:
        profile_resolver = getattr(self.registrar, "resolve_session_profile", None)
        profile_serializer = getattr(self.registrar, "serialize_session_profile", None)
        if not callable(profile_resolver) or not callable(profile_serializer):
            return _AccountNetworkRuntime(
                proxy=lease.proxy,
                description=lease.description,
                proxy_geo=None,
                fingerprint_profile=None,
                fingerprint_restored=False,
            )
        stored_profile = self.state.get(_FINGERPRINT_STATE_STEP)
        if stored_profile is not None and not isinstance(stored_profile, Mapping):
            raise RuntimeError("stored fingerprint profile is not a JSON object")
        has_openai_checkpoint = any(
            self.state.get(step) is not None for step in _FINGERPRINT_BOUND_STEPS
        )
        if stored_profile is None and has_openai_checkpoint:
            raise RuntimeError("checkpoint contains OpenAI steps but no fingerprint profile")
        stored_geo = self.state.get(_PROXY_GEO_STATE_STEP)
        if stored_geo is not None and not isinstance(stored_geo, Mapping):
            raise RuntimeError("stored proxy geo hint is not a JSON object")
        if stored_profile is None and stored_geo is None:
            geo_resolver = getattr(self.registrar, "resolve_proxy_geo", None)
            if callable(geo_resolver):
                resolved_geo = geo_resolver(lease.proxy)
                if not isinstance(resolved_geo, Mapping):
                    raise RuntimeError("proxy geo resolver did not return an object")
                stored_geo = dict(resolved_geo)
                self.state.set(_PROXY_GEO_STATE_STEP, stored_geo)
        geo = dict(stored_geo) if isinstance(stored_geo, Mapping) else None
        restored = isinstance(stored_profile, Mapping)
        profile = profile_resolver(stored_profile, geo_hint=geo)
        serialized_profile = profile_serializer(profile)
        if stored_profile != serialized_profile:
            self.state.set(_FINGERPRINT_STATE_STEP, serialized_profile)

        stored_browserforge = self.state.get(_BROWSERFORGE_STATE_STEP)
        if stored_browserforge is not None and not isinstance(stored_browserforge, Mapping):
            raise RuntimeError("stored BrowserForge fingerprint is not a JSON object")
        stored_toolchain = self.state.get(_BROWSER_TOOLCHAIN_STATE_STEP)
        if stored_toolchain is not None and not isinstance(stored_toolchain, Mapping):
            raise RuntimeError("stored browser toolchain is not a JSON object")
        browserforge, serialized_browserforge, toolchain = (
            self._resolve_browserforge_assets(
                profile,
                stored_fingerprint=stored_browserforge,
                stored_toolchain=stored_toolchain,
                has_openai_checkpoint=has_openai_checkpoint,
            )
        )
        if serialized_browserforge is not None and stored_browserforge != serialized_browserforge:
            self.state.set(_BROWSERFORGE_STATE_STEP, serialized_browserforge)
        if toolchain is not None and stored_toolchain != toolchain:
            self.state.set(_BROWSER_TOOLCHAIN_STATE_STEP, toolchain)
        return _AccountNetworkRuntime(
            proxy=lease.proxy,
            description=lease.description,
            proxy_geo=geo,
            fingerprint_profile=profile,
            fingerprint_restored=restored,
            browserforge_fingerprint=browserforge,
        )

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

    @staticmethod
    def _validate_login_session(
        spec: AccountSpec, session: Mapping[str, Any]
    ) -> None:
        context = AuthContext.from_mapping(session)
        if not context.session_token:
            raise RuntimeError("login result has no session_token")
        if context.email and context.email.casefold() != spec.email.casefold():
            raise RuntimeError(
                f"login returned {context.email}, expected {spec.email}"
            )

    def _login(
        self,
        spec: AccountSpec,
        step: str,
        *,
        select_workspace: bool = True,
    ) -> dict[str, Any]:
        self._check_cancel()
        cached = self.state.get(step)
        if isinstance(cached, dict):
            self._validate_login_session(spec, cached)
            self._log(f"[resume] {step}")
            return cached
        role = "old" if step == "old_login" else "new"
        mailbox = self._mailboxes.get(f"{role}_login")
        network = self._networks[role]
        action = "register" if step == "new_login" else "login"
        self._log(f"[{action}] {spec.email}")
        login_kwargs: dict[str, Any] = {
            "email": spec.email,
            "account_password": spec.password,
            "mailbox": mailbox,
            "proxy": network.proxy,
            "workspace_id": self.config.workspace_id if select_workspace else None,
            "verbose": self.verbose and self.logger is None,
            "stop_event": self.stop_event,
            "event_callback": self._registrar_event if self.logger is not None else None,
        }
        if network.fingerprint_profile is not None:
            login_kwargs["session_profile"] = network.fingerprint_profile
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
        if not isinstance(session, Mapping):
            raise RuntimeError("login result is not an object")
        self._validate_login_session(spec, session)
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
        role = "old" if step == "old_workspace" else "new"
        session = self._chatgpt_clients[role].refresh_session(
            context.session_token,
            account_id=self.config.workspace_id,
        )
        self._check_cancel()
        switched = AuthContext.from_mapping(session)
        if switched.account_id != self.config.workspace_id:
            raise _WorkspaceSwitchError(
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
        client = self._chatgpt_clients["old"]
        members = client.get_members(context.access_token, self.config.workspace_id)
        if any(_email_from_item(item) == target for item in _items(members)):
            result = {"action": "already-member", "email": self.config.new_account.email}
        else:
            invites = client.get_invites(context.access_token, self.config.workspace_id)
            if any(_email_from_item(item) == target for item in _items(invites)):
                result = {"action": "already-invited", "email": self.config.new_account.email}
            else:
                response = client.invite(
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
        client = self._chatgpt_clients["old"]
        members = client.get_members(context.access_token, self.config.workspace_id)
        member_ids = {
            str(item.get("id") or item.get("user_id") or "").strip()
            for item in _items(members)
        }
        if context.user_id not in member_ids:
            result = {"action": "already-left", "user_id": context.user_id}
        else:
            response = client.leave(
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
        result = self._chatgpt_clients["new"].create_personal_access_token(
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
        verified_session_auth = bool(
            self.config.sub2api_email
            and self.config.sub2api_password
            and self.config.sub2api_totp_secret
        )
        if not verified_session_auth:
            raise RuntimeError(
                "Sub2API push requires administrator email, password, and TOTP secret"
            )
        token = str(pat.get("access_token") or "").strip()
        account = build_sub2api_account(
            new_session,
            personal_access_token=token,
            concurrency=self.config.sub2api_concurrency,
            priority=self.config.sub2api_priority,
            group_id=self.config.sub2api_group_id,
        )
        owns_client = self.sub2api is None
        client_options = {}
        if self.config.sub2api_api_key:
            client_options["api_key"] = self.config.sub2api_api_key
        if self.config.sub2api_totp_secret:
            client_options["totp_secret"] = self.config.sub2api_totp_secret
        client = self.sub2api or Sub2APIClient(
            self.config.sub2api_base_url,
            self.config.sub2api_email,
            self.config.sub2api_password,
            **client_options,
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
            roles = ("old", "new") if self._account_network_mode else ("old",)
            for role in roles:
                network = self._networks[role]
                label = f"[{role}] " if self._account_network_mode else ""
                self._log(f"[proxy] {label}{network.description}")
                if network.proxy_geo is not None:
                    geo_status = "已匹配" if network.proxy_geo.get("resolved") else "已回退"
                    self._log(
                        f"[geo] {label}{geo_status} country="
                        f"{network.proxy_geo.get('country_code') or '<unknown>'} "
                        f"locale={network.proxy_geo.get('locale') or '<unknown>'} "
                        f"timezone={network.proxy_geo.get('timezone_id') or '<unknown>'} "
                        f"source={network.proxy_geo.get('source') or '<unknown>'}"
                    )
                profile = network.fingerprint_profile
                if profile is not None:
                    profile_action = "已恢复" if network.fingerprint_restored else "已生成"
                    self._log(
                        f"[fingerprint] {label}{profile_action}并锁定 "
                        f"{getattr(profile, 'profile_id', '<unknown>')} "
                        f"impersonate={getattr(profile, 'impersonate', '<unknown>')} "
                        f"os={getattr(profile, 'os', '<unknown>')} "
                        f"locale={getattr(profile, 'locale', '<unknown>')} "
                        f"timezone={getattr(profile, 'timezone_id', '<unknown>')}"
                    )
            self._check_cancel()
            def old_login_stage() -> dict[str, Any]:
                login = self._login(self.config.old_account, "old_login")
                return self._switch_workspace(login, "old_workspace")

            old_workspace = self._run_stage("old_login", old_login_stage)
            new_login = self._run_stage(
                "new_login",
                lambda: self._login(
                    self.config.new_account,
                    "new_login",
                    select_workspace=False,
                ),
            )
            invite = self._run_stage("invite", lambda: self._ensure_invited(old_workspace))
            old_leave = self._run_stage(
                "old_leave", lambda: self._leave_old_account(old_workspace)
            )

            def pat_stage() -> tuple[dict[str, Any], dict[str, Any]]:
                try:
                    new_workspace = self._switch_workspace(new_login, "new_workspace")
                except _WorkspaceSwitchError:
                    self._log("[reauth] new account workspace selection")
                    workspace_login = self._login(
                        self.config.new_account,
                        "new_workspace_login",
                    )
                    new_workspace = self._switch_workspace(
                        workspace_login,
                        "new_workspace",
                    )
                return new_workspace, self._create_pat(new_workspace)

            new_workspace, pat = self._run_stage("pat", pat_stage)
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
