from __future__ import annotations

import json
import re
import secrets
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

_LOGIN_PATCH_LOCK = threading.RLock()


class _CallbackEventQueue:
    def __init__(self, callback: Callable[[dict[str, Any]], None]):
        self._callback = callback

    def put_nowait(self, event: dict[str, Any]) -> None:
        try:
            self._callback(event)
        except Exception:
            pass


@dataclass(frozen=True)
class MailboxCredentials:
    primary_email: str
    registration_email: str
    client_id: str
    refresh_token: str
    password: str = ""

    def as_auth_credential(self) -> str:
        return json.dumps(
            {
                "provider": "appleemail_hotmail",
                "primary_email": self.primary_email,
                "registration_email": self.registration_email,
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
                "password": self.password,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )


def _normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    lower = text.lower()
    scheme_aliases = {
        "sk5://": "socks5://",
        "sk5h://": "socks5h://",
        "s5://": "socks5://",
        "s5h://": "socks5h://",
        "socks://": "socks5://",
        "ss://": "socks5://",
        "ss5://": "socks5://",
        "ss5h://": "socks5h://",
    }
    for prefix, replacement in scheme_aliases.items():
        if lower.startswith(prefix):
            return replacement + text[len(prefix) :]
    return text if "://" in text else f"{default_scheme}://{text}"


def _render_proxy_template(value: str, index: int) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    random_hex = secrets.token_hex(4)
    random_long = secrets.token_hex(8)
    return (
        text.replace("{worker}", str(index))
        .replace("{index}", str(index))
        .replace("{rand}", random_hex)
        .replace("{rand8}", random_hex)
        .replace("{rand16}", random_long)
    )


def _mask_proxy_for_log(value: str) -> str:
    text = _normalize_proxy_url(value)
    if not text:
        return "直连"
    return re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://[^:/@\s]+:)([^@\s]+)(@)",
        r"\1******\3",
        text,
    )


class RegistrarProxyLease:
    def __init__(
        self,
        *,
        explicit_proxy: str = "",
        index: int = 1,
        preexpanded: bool = False,
    ):
        self.explicit_proxy = str(explicit_proxy or "").strip()
        self.index = int(index)
        self.preexpanded = bool(preexpanded)
        self.proxy: str | None = None
        self.source = "direct"
        self.description = "未配置代理，当前直连"
        self._entered = False

    def __enter__(self) -> "RegistrarProxyLease":
        if self._entered:
            return self
        self._entered = True
        self.proxy = None
        self.source = "direct"
        self.description = "未配置代理，当前直连"

        if self.explicit_proxy:
            rendered = (
                self.explicit_proxy
                if self.preexpanded
                else _render_proxy_template(self.explicit_proxy, self.index)
            )
            self.proxy = _normalize_proxy_url(rendered)
            self.source = "workflow"
            self.description = f"使用工作流代理：{_mask_proxy_for_log(self.proxy)}"
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self._entered = False

    def close(self) -> None:
        self.__exit__(None, None, None)


def primary_email_for_alias(email: str) -> str:
    normalized = str(email or "").strip().lower()
    if "@" not in normalized:
        return ""
    local, domain = normalized.rsplit("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


class RegistrarIdentityError(RuntimeError):
    ALLOWED_CODES = frozenset({"alias_disabled", "mailbox_credentials_invalid"})

    def __init__(self, code: str) -> None:
        normalized = str(code or "").strip()
        if normalized not in self.ALLOWED_CODES:
            raise ValueError("unsupported registrar identity error code")
        self.code = normalized
        super().__init__(normalized)


class RegistrarAdapter:
    def __init__(self, state_dir: str | Path | None = None):
        from .registrar_runtime import appleemail_provider, fingerprint_profiles, register

        self.state_dir = Path(state_dir or Path.cwd() / "output" / ".registrar").resolve()
        self._login = register.login_existing_account_for_token
        self._register_module = register
        self._event_emitter = register.EventEmitter
        self._provider_class = appleemail_provider.AppleEmailHotmailProvider
        self._mailbox_identity_error_class = (
            appleemail_provider.MailboxCredentialsInvalidError
        )
        self._create_session_profile = fingerprint_profiles.create_session_profile
        self._session_profile_class = fingerprint_profiles.SessionProfile

    def resolve_session_profile(self, serialized: Mapping[str, Any] | None = None) -> Any:
        if serialized is None:
            return self._create_session_profile(scope="auto_desktop")
        if not isinstance(serialized, Mapping):
            raise ValueError("stored fingerprint profile must be a JSON object")
        try:
            return self._session_profile_class(**dict(serialized)).validate()
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "stored fingerprint profile is incompatible; disable resume to start a new workflow"
            ) from exc

    @staticmethod
    def serialize_session_profile(profile: Any) -> dict[str, Any]:
        serializer = getattr(profile, "to_legacy_dict", None)
        if not callable(serializer):
            raise ValueError("fingerprint profile cannot be serialized")
        payload = serializer()
        if not isinstance(payload, dict):
            raise ValueError("fingerprint profile serializer did not return an object")
        json.dumps(payload, ensure_ascii=False)
        return payload

    def login(
        self,
        *,
        email: str,
        account_password: str,
        mailbox: MailboxCredentials,
        proxy: str | None = None,
        workspace_id: str | None = None,
        session_profile: Any = None,
        provider_initial_state: Mapping[str, Any] | None = None,
        provider_state_callback: Callable[[dict[str, Any]], None] | None = None,
        verbose: bool = True,
        stop_event: threading.Event | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        if provider_initial_state is not None and not isinstance(
            provider_initial_state, Mapping
        ):
            raise TypeError("provider_initial_state must be a mapping")
        provider = self._provider_class(
            accounts=[],
            api_base="https://www.appleemail.top",
            initial_state=dict(provider_initial_state or {}),
            state_callback=provider_state_callback,
        )
        explicit_password = bool(str(account_password or "").strip())
        internal_password = str(account_password or mailbox.password or "otp-only").strip()
        original_extractor = self._register_module._try_extract_chatgpt_session_token
        emitter_queue = _CallbackEventQueue(event_callback) if event_callback is not None else None
        emitter = self._event_emitter(q=emitter_queue, cli_mode=verbose)

        def _session_from_closure(session_get: Any) -> Any:
            try:
                values = [cell.cell_contents for cell in (session_get.__closure__ or ())]
                closure = dict(zip(session_get.__code__.co_freevars, values))
            except Exception:
                return None
            return closure.get("session")

        def _extract_with_workspace(*, continue_url: str, session_get: Any, **kwargs: Any):
            selected_url = str(continue_url or "").strip()
            target_workspace = str(workspace_id or "").strip()
            if target_workspace:
                session = _session_from_closure(session_get)
                if session is None:
                    raise RuntimeError("could not access registrar OAuth session for workspace selection")
                did = ""
                try:
                    did = str(session.cookies.get("oai-did") or "").strip()
                except Exception:
                    did = ""
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": "https://auth.openai.com",
                    "Referer": selected_url or "https://auth.openai.com/workspace",
                }
                if did:
                    headers["oai-device-id"] = did
                request_kwargs: dict[str, Any] = {
                    "json": {"workspace_id": target_workspace},
                    "headers": headers,
                    "timeout": 30,
                    "allow_redirects": False,
                    "verify": False,
                    "http_version": "v2",
                }
                if proxy:
                    request_kwargs["proxies"] = {"http": proxy, "https": proxy}
                response = session.post(
                    "https://auth.openai.com/api/accounts/workspace/select",
                    **request_kwargs,
                )
                if int(getattr(response, "status_code", 0) or 0) not in (200, 301, 302, 303, 307, 308):
                    raise RuntimeError(
                        f"workspace/select failed: HTTP {response.status_code} {str(response.text or '')[:240]}"
                    )
                location = str(getattr(response, "headers", {}).get("Location") or "").strip()
                if location:
                    selected_url = urllib.parse.urljoin("https://auth.openai.com/", location)
                elif int(response.status_code) == 200:
                    try:
                        payload = response.json()
                    except Exception:
                        payload = {}
                    extracted = self._register_module._extract_post_create_url(
                        payload,
                        "https://chatgpt.com",
                    )
                    if extracted:
                        selected_url = extracted
            return original_extractor(
                continue_url=selected_url,
                session_get=session_get,
                **kwargs,
            )

        with _LOGIN_PATCH_LOCK:
            self._register_module._try_extract_chatgpt_session_token = _extract_with_workspace
            try:
                try:
                    result = self._login(
                        email=email,
                        account_password=internal_password,
                        proxy=proxy,
                        mail_provider=provider,
                        mail_provider_name="appleemail_hotmail",
                        mail_auth_credential=mailbox.as_auth_credential(),
                        session_profile=session_profile,
                        emitter=emitter,
                        stop_event=stop_event,
                    )
                except self._mailbox_identity_error_class as exc:
                    raise RegistrarIdentityError(
                        "mailbox_credentials_invalid"
                    ) from exc
            finally:
                self._register_module._try_extract_chatgpt_session_token = original_extractor
        if not isinstance(result, dict) or not result.get("ok"):
            if isinstance(result, dict) and (
                result.get("identity_error_code") == "alias_disabled"
                or result.get("fatal_deactivated") is True
            ):
                raise RegistrarIdentityError("alias_disabled")
            error = result.get("error") if isinstance(result, dict) else result
            raise RuntimeError(str(error or "registrar login failed"))
        token_data = result.get("token_data")
        if not isinstance(token_data, dict):
            raise RuntimeError("registrar login did not return token_data")
        if not explicit_password:
            token_data.pop("account_password", None)
            token_data.pop("password", None)
        return token_data
