from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qs, urlencode, urlparse

from .cpa import OPENAI_AUTH_CLAIM, build_cpa, decode_jwt_payload


class Sub2APIError(RuntimeError):
    pass


@dataclass(frozen=True)
class Sub2APIPushResult:
    action: str
    account_name: str
    verified: bool
    message: str


def _clean_token(value: str) -> str:
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _totp_code(secret: str, *, at: float | None = None) -> str:
    raw_secret = str(secret or "").strip()
    if raw_secret.lower().startswith("otpauth://"):
        values = parse_qs(urlparse(raw_secret).query).get("secret") or []
        raw_secret = str(values[0] if values else "")
    normalized = "".join(raw_secret.split()).replace("-", "").upper().rstrip("=")
    if not normalized:
        raise ValueError("TOTP secret is required")
    padded = normalized + "=" * ((8 - len(normalized) % 8) % 8)
    try:
        key = base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("TOTP secret is not valid base32") from exc
    counter = int((time.time() if at is None else at) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _without_empty(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in values.items()
        if value is not None and (not isinstance(value, str) or value.strip())
    }


def build_sub2api_account(
    session: Mapping[str, Any],
    *,
    personal_access_token: str,
    concurrency: int = 10,
    priority: int = 1,
    group_id: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    token = _clean_token(personal_access_token)
    if not token:
        raise ValueError("personal access token is required for Sub2API")
    if concurrency < 0 or priority < 0:
        raise ValueError("Sub2API concurrency and priority must be non-negative")
    if group_id is not None and int(group_id) <= 0:
        raise ValueError("Sub2API group ID must be positive")

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cpa = build_cpa(session, personal_access_token=token, now=now)
    nested_tokens = (
        session.get("tokens") if isinstance(session.get("tokens"), dict) else {}
    )
    session_access_token = str(
        session.get("accessToken")
        or session.get("access_token")
        or nested_tokens.get("access_token")
        or ""
    )
    access_payload = decode_jwt_payload(session_access_token)
    auth_claim = access_payload.get(OPENAI_AUTH_CLAIM)
    auth_claim = auth_claim if isinstance(auth_claim, dict) else {}
    email = str(cpa.get("email") or "").strip()
    account_id = str(cpa.get("account_id") or "").strip()
    user_id = str(
        auth_claim.get("chatgpt_user_id")
        or auth_claim.get("user_id")
        or ((session.get("user") or {}).get("id") if isinstance(session.get("user"), dict) else "")
        or ""
    ).strip()
    plan_type = str(cpa.get("plan_type") or "").strip()
    name = email or str(cpa.get("name") or "ChatGPT Account").strip()
    exported_at = now.isoformat(timespec="seconds").replace("+00:00", "Z")

    credentials = _without_empty(
        {
            "access_token": token,
            "auth_mode": "personalAccessToken",
            "openai_auth_mode": "personal_access_token",
            "token_type": "Bearer",
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": user_id,
            "email": email,
            "plan_type": plan_type,
        }
    )
    extra = _without_empty(
        {
            "email": email,
            "email_key": email.casefold(),
            "name": name,
            "auth_provider": "codex_personal_access_token",
            "import_source": "codex_personal_access_token",
            "last_refresh": exported_at,
        }
    )
    account = {
        "name": name,
        "platform": "openai",
        "type": "oauth",
        "auto_pause_on_expired": True,
        "concurrency": int(concurrency),
        "priority": int(priority),
        "credentials": credentials,
        "extra": extra,
    }
    if group_id is not None:
        account["group_ids"] = [int(group_id)]
    return account


class Sub2APIClient:
    def __init__(
        self,
        base_url: str,
        email: str = "",
        password: str = "",
        *,
        api_key: str = "",
        totp_secret: str = "",
        timeout: float = 30.0,
        impersonate: str = "chrome145",
        session: Any = None,
    ):
        self.base_url = str(base_url or "").strip().rstrip("/")
        self.email = str(email or "").strip()
        self.password = str(password or "")
        self.api_key = str(api_key or "").strip()
        self.totp_secret = str(totp_secret or "").strip()
        self.timeout = timeout
        self.impersonate = impersonate
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("Sub2API base URL must start with http:// or https://")
        if not self.api_key and (not self.email or not self.password):
            raise ValueError(
                "Sub2API administrator API key or email and password are required"
            )
        if session is None:
            try:
                from curl_cffi import requests as curl_requests
            except ImportError as exc:
                raise RuntimeError("curl_cffi is required for Sub2API requests") from exc
            session = curl_requests.Session()
        self._session = session
        self._access_token = ""

    @property
    def _use_session_auth(self) -> bool:
        has_totp_session = bool(self.email and self.password and self.totp_secret)
        return has_totp_session or not self.api_key

    @property
    def api_base_url(self) -> str:
        return f"{self.base_url}/api/v1"

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "Sub2APIClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    @staticmethod
    def _unwrap(payload: Any) -> Any:
        if not isinstance(payload, dict):
            raise Sub2APIError("Sub2API response is not a JSON object")
        if "code" not in payload:
            return payload
        try:
            code = int(payload.get("code") or 0)
        except (TypeError, ValueError):
            code = -1
        if code != 0:
            raise Sub2APIError(str(payload.get("message") or f"Sub2API error code {code}"))
        return payload.get("data")

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: Mapping[str, Any] | None = None,
        authenticated: bool = True,
    ) -> Any:
        if authenticated and self._use_session_auth and not self._access_token:
            self.login()
        headers = {"Accept": "application/json"}
        if path == "/admin" or path.startswith("/admin/"):
            headers["X-Admin-UI-Request"] = "1"
        if path == "/user" or path.startswith("/user/"):
            headers["X-User-UI-Request"] = "1"
        if authenticated:
            if self._use_session_auth:
                headers["Authorization"] = f"Bearer {self._access_token}"
            else:
                headers["x-api-key"] = self.api_key
        response = self._session.request(
            method,
            f"{self.api_base_url}{path}",
            json=dict(json_data) if json_data is not None else None,
            headers=headers,
            impersonate=self.impersonate,
            timeout=self.timeout,
            verify=False,
        )
        try:
            payload = response.json()
        except Exception as exc:
            raise Sub2APIError(
                f"Sub2API HTTP {response.status_code} returned non-JSON content"
            ) from exc
        if not 200 <= response.status_code < 300:
            detail = payload.get("message") if isinstance(payload, dict) else None
            code = payload.get("code") if isinstance(payload, dict) else None
            code_label = f" [{code}]" if code else ""
            raise Sub2APIError(
                f"Sub2API HTTP {response.status_code} on {method.upper()} {path}"
                f"{code_label}: {detail or response.reason}"
            )
        return self._unwrap(payload)

    def login(self) -> None:
        data = self._request(
            "POST",
            "/auth/login",
            json_data={"email": self.email, "password": self.password},
            authenticated=False,
        )
        if isinstance(data, dict) and data.get("requires_2fa") is True:
            if not self.totp_secret:
                raise Sub2APIError(
                    "Sub2API login requires TOTP; configure the administrator TOTP secret"
                )
            temp_token = str(data.get("temp_token") or "").strip()
            if not temp_token:
                raise Sub2APIError("Sub2API 2FA login did not return a temporary token")
            try:
                totp_code = _totp_code(self.totp_secret)
            except ValueError as exc:
                raise Sub2APIError("Sub2API TOTP secret is invalid") from exc
            data = self._request(
                "POST",
                "/auth/login/2fa",
                json_data={"temp_token": temp_token, "totp_code": totp_code},
                authenticated=False,
            )
        token = str((data or {}).get("access_token") if isinstance(data, dict) else "").strip()
        if not token:
            raise Sub2APIError("Sub2API login did not return an access token")
        self._access_token = token

    def export_accounts(self) -> list[dict[str, Any]]:
        data = self._request("GET", "/admin/accounts/data?include_proxies=false")
        accounts = data.get("accounts") if isinstance(data, dict) else None
        return [dict(item) for item in (accounts or []) if isinstance(item, dict)]

    def verify_step_up(self) -> None:
        if not self._use_session_auth or not self.totp_secret:
            raise Sub2APIError(
                "Sub2API protected operations require a TOTP-verified administrator session"
            )
        try:
            code = _totp_code(self.totp_secret)
        except ValueError as exc:
            raise Sub2APIError("Sub2API TOTP secret is invalid") from exc
        self._request(
            "POST",
            "/user/totp/step-up",
            json_data={"code": code},
        )

    def list_groups(
        self,
        *,
        platform: str = "",
        include_inactive: bool = False,
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                key: value
                for key, value in {
                    "platform": str(platform or "").strip(),
                    "include_inactive": "true" if include_inactive else "",
                }.items()
                if value
            }
        )
        path = "/admin/groups/all" + (f"?{query}" if query else "")
        data = self._request("GET", path)
        if not isinstance(data, list):
            raise Sub2APIError("Sub2API groups response is not a list")
        return [dict(item) for item in data if isinstance(item, Mapping)]

    @staticmethod
    def _credentials(account: Mapping[str, Any]) -> Mapping[str, Any]:
        value = account.get("credentials")
        return value if isinstance(value, Mapping) else {}

    @classmethod
    def _same_identity(cls, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_credentials = cls._credentials(left)
        right_credentials = cls._credentials(right)
        left_account = str(left_credentials.get("chatgpt_account_id") or "").strip()
        right_account = str(right_credentials.get("chatgpt_account_id") or "").strip()
        left_email = str(left_credentials.get("email") or "").strip().casefold()
        right_email = str(right_credentials.get("email") or "").strip().casefold()
        if left_account and right_account and left_email and right_email:
            return left_account == right_account and left_email == right_email
        if left_account and right_account:
            return left_account == right_account
        return bool(left_email and right_email and left_email == right_email)

    @classmethod
    def _same_token(cls, left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        left_token = _clean_token(str(cls._credentials(left).get("access_token") or ""))
        right_token = _clean_token(str(cls._credentials(right).get("access_token") or ""))
        return bool(left_token and right_token and left_token == right_token)

    @staticmethod
    def _group_ids(account: Mapping[str, Any]) -> tuple[int, ...]:
        values: set[int] = set()
        raw_group_ids = account.get("group_ids")
        if isinstance(raw_group_ids, (list, tuple, set)):
            for value in raw_group_ids:
                try:
                    group_id = int(value)
                except (TypeError, ValueError):
                    continue
                if group_id > 0:
                    values.add(group_id)
        for key, id_key in (("account_groups", "group_id"), ("groups", "id")):
            raw_groups = account.get(key)
            if not isinstance(raw_groups, (list, tuple)):
                continue
            for item in raw_groups:
                if not isinstance(item, Mapping):
                    continue
                try:
                    group_id = int(item.get(id_key) or 0)
                except (TypeError, ValueError):
                    continue
                if group_id > 0:
                    values.add(group_id)
        return tuple(sorted(values))

    @classmethod
    def _groups_match(cls, remote: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
        expected_group_ids = set(cls._group_ids(expected))
        return not expected_group_ids or expected_group_ids.issubset(cls._group_ids(remote))

    @classmethod
    def _create_payload(cls, account: Mapping[str, Any]) -> dict[str, Any]:
        credentials = dict(cls._credentials(account))
        token = _clean_token(str(credentials.pop("access_token", "") or ""))
        if not token:
            raise Sub2APIError("Sub2API account has no personal access token")
        group_ids = list(cls._group_ids(account))
        payload = {
            "access_token": token,
            "name": str(account.get("name") or "").strip(),
            "concurrency": int(account.get("concurrency") or 0),
            "priority": int(account.get("priority") or 0),
            "auto_pause_on_expired": bool(account.get("auto_pause_on_expired", True)),
            "credential_extras": credentials,
            "extra": dict(account.get("extra") or {}) if isinstance(account.get("extra"), Mapping) else {},
            "skip_default_group_bind": bool(group_ids),
        }
        if group_ids:
            payload["group_ids"] = group_ids
        for key in ("expires_at", "rate_multiplier"):
            if account.get(key) is not None:
                payload[key] = account[key]
        return payload

    def push_account(
        self,
        account: Mapping[str, Any],
        *,
        dry_run: bool = False,
    ) -> Sub2APIPushResult:
        account = dict(account)
        account_name = str(account.get("name") or "ChatGPT Account")
        if self.totp_secret:
            self.verify_step_up()
        remote_accounts = self.export_accounts()
        matching_remote = next(
            (remote for remote in remote_accounts if self._same_token(remote, account)),
            None,
        )
        if matching_remote is not None:
            if not self._groups_match(matching_remote, account):
                raise Sub2APIError(
                    f"Sub2API account exists outside the configured group: {account_name}"
                )
            return Sub2APIPushResult(
                action="skipped",
                account_name=account_name,
                verified=True,
                message="Sub2API account already has the same token",
            )
        if any(self._same_identity(remote, account) for remote in remote_accounts):
            raise Sub2APIError(
                f"Sub2API account identity already exists with a different token: {account_name}"
            )
        if dry_run:
            return Sub2APIPushResult(
                action="would-create",
                account_name=account_name,
                verified=False,
                message="dry run: Sub2API account would be created",
            )

        self._request(
            "POST",
            "/admin/openai/create-from-codex-pat",
            json_data=self._create_payload(account),
        )
        matching_remote = next(
            (
                remote
                for remote in self.export_accounts()
                if self._same_token(remote, account)
            ),
            None,
        )
        if matching_remote is None:
            raise Sub2APIError(f"Sub2API post-create verification failed: {account_name}")
        if not self._groups_match(matching_remote, account):
            raise Sub2APIError(
                f"Sub2API post-create group verification failed: {account_name}"
            )
        return Sub2APIPushResult(
            action="created",
            account_name=account_name,
            verified=True,
            message="Sub2API account created and verified",
        )
