from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .cpa import OPENAI_AUTH_CLAIM, decode_jwt_payload


DEFAULT_PAT_SCOPES = [
    "chatgpt.workspace.feature.hermes.access",
    "chatgpt.workspace.feature.allow-codex-local-access.access",
]


class ChatGPTApiError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuthContext:
    access_token: str
    account_id: str
    user_id: str
    session_token: str
    email: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AuthContext":
        tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
        user = data.get("user") if isinstance(data.get("user"), dict) else {}
        account = data.get("account") if isinstance(data.get("account"), dict) else {}
        access_token = str(
            data.get("accessToken")
            or data.get("access_token")
            or tokens.get("access_token")
            or ""
        )
        payload = decode_jwt_payload(access_token)
        auth = payload.get(OPENAI_AUTH_CLAIM) if isinstance(payload.get(OPENAI_AUTH_CLAIM), dict) else {}
        account_id = str(
            account.get("id")
            or data.get("account_id")
            or data.get("chatgpt_account_id")
            or tokens.get("account_id")
            or auth.get("chatgpt_account_id")
            or ""
        )
        user_id = str(
            user.get("id")
            or data.get("user_id")
            or auth.get("chatgpt_user_id")
            or auth.get("user_id")
            or ""
        )
        session_token = str(data.get("sessionToken") or data.get("session_token") or "")
        email = str(user.get("email") or data.get("email") or "")
        return cls(
            access_token=access_token,
            account_id=account_id,
            user_id=user_id,
            session_token=session_token,
            email=email,
        )


class ChatGPTClient:
    BASE_URL = "https://chatgpt.com/backend-api"

    def __init__(
        self,
        *,
        impersonate: str = "chrome145",
        timeout: float = 30.0,
        proxy: str | None = None,
        session_profile: Any = None,
    ):
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:
            raise RuntimeError("curl_cffi is required for live ChatGPT requests") from exc
        self._curl_requests = curl_requests
        self._session = curl_requests.Session()
        self.session_profile = session_profile
        self.impersonate = str(getattr(session_profile, "impersonate", "") or impersonate)
        profile_headers = getattr(session_profile, "http_headers", {})
        self._fingerprint_headers = (
            {str(key): str(value) for key, value in profile_headers.items()}
            if isinstance(profile_headers, Mapping)
            else {}
        )
        self.timeout = timeout
        self.proxy = proxy

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "ChatGPTClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_data: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        merged_headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chatgpt.com/",
            "Origin": "https://chatgpt.com",
            **self._fingerprint_headers,
            **dict(headers or {}),
        }
        kwargs: dict[str, Any] = {
            "headers": merged_headers,
            "impersonate": self.impersonate,
            "timeout": self.timeout,
            "verify": False,
        }
        if json_data is not None:
            kwargs["json"] = dict(json_data)
        if self.proxy:
            kwargs["proxy"] = self.proxy
        response = self._session.request(method, url, **kwargs)
        if not 200 <= response.status_code < 300:
            detail = response.text.strip()
            raise ChatGPTApiError(f"HTTP {response.status_code}: {detail[:1000]}")
        try:
            data = response.json()
        except Exception as exc:
            raise ChatGPTApiError("response is not JSON") from exc
        if not isinstance(data, dict):
            raise ChatGPTApiError("response JSON is not an object")
        return data

    def invite(self, access_token: str, account_id: str, email: str) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{self.BASE_URL}/accounts/{account_id}/invites",
            headers={
                "Authorization": f"Bearer {access_token}",
                "chatgpt-account-id": account_id,
                "Content-Type": "application/json",
            },
            json_data={
                "email_addresses": [email],
                "role": "standard-user",
                "resend_emails": True,
            },
        )

    def get_members(self, access_token: str, account_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"{self.BASE_URL}/accounts/{account_id}/users?limit=100&offset=0",
            headers={
                "Authorization": f"Bearer {access_token}",
                "chatgpt-account-id": account_id,
            },
        )

    def get_invites(self, access_token: str, account_id: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"{self.BASE_URL}/accounts/{account_id}/invites",
            headers={
                "Authorization": f"Bearer {access_token}",
                "chatgpt-account-id": account_id,
            },
        )

    def leave(self, access_token: str, account_id: str, user_id: str) -> dict[str, Any]:
        return self._request(
            "DELETE",
            f"{self.BASE_URL}/accounts/{account_id}/users/{user_id}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "chatgpt-account-id": account_id,
            },
        )

    def create_personal_access_token(
        self,
        access_token: str,
        account_id: str,
        *,
        name: str,
        ttl: int = 5_184_000,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"{self.BASE_URL}/wham/auth-credentials",
            headers={
                "Authorization": f"Bearer {access_token}",
                "chatgpt-account-id": account_id,
                "Content-Type": "application/json",
            },
            json_data={"name": name, "scopes": scopes or DEFAULT_PAT_SCOPES, "ttl": ttl},
        )

    def refresh_session(self, session_token: str, *, account_id: str | None = None) -> dict[str, Any]:
        url = "https://chatgpt.com/api/auth/session"
        if account_id:
            url += (
                "?exchange_workspace_token=true"
                f"&workspace_id={account_id}"
                "&reason=setCurrentAccount"
            )
        return self._request(
            "GET",
            url,
            headers={
                "Cookie": f"__Secure-next-auth.session-token={session_token}",
                "Accept": "application/json",
            },
        )
