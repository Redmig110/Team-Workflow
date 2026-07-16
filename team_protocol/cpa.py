from __future__ import annotations

import base64
import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


OPENAI_AUTH_CLAIM = "https://api.openai.com/auth"
OPENAI_PROFILE_CLAIM = "https://api.openai.com/profile"


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _base64url_json(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_jwt_payload(token: str | None) -> dict[str, Any]:
    if not token or token.count(".") < 2:
        return {}
    try:
        payload = json.loads(_base64url_decode(token.split(".", 2)[1]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _claim_dict(payload: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


def _parse_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        seconds = float(value) / 1000 if float(value) > 1e11 else float(value)
        parsed = datetime.fromtimestamp(seconds, timezone.utc)
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_utc(value: datetime, *, milliseconds: bool) -> str:
    value = value.astimezone(timezone.utc)
    if milliseconds:
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _jwt_expiry(payload: Mapping[str, Any]) -> datetime | None:
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(float(exp), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def build_synthetic_id_token(
    *,
    email: str | None,
    account_id: str,
    plan_type: str | None,
    user_id: str | None,
    expires_at: datetime | None,
    now: datetime,
) -> str:
    auth_info: dict[str, Any] = {"chatgpt_account_id": account_id}
    if plan_type:
        auth_info["chatgpt_plan_type"] = plan_type
    if user_id:
        auth_info["chatgpt_user_id"] = user_id
        auth_info["user_id"] = user_id

    expires = expires_at or (now.replace(microsecond=0))
    if expires_at is None:
        expires = datetime.fromtimestamp(int(now.timestamp()) + 90 * 24 * 60 * 60, timezone.utc)

    payload: dict[str, Any] = {
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        OPENAI_AUTH_CLAIM: auth_info,
    }
    if email:
        payload["email"] = email

    header = {"alg": "none", "typ": "JWT", "cpa_synthetic": True}
    return f"{_base64url_json(header)}.{_base64url_json(payload)}.synthetic"


def build_cpa(
    session: Mapping[str, Any],
    *,
    personal_access_token: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    session_access_token = _first_non_empty(
        session.get("accessToken"),
        session.get("access_token"),
        (session.get("tokens") or {}).get("access_token") if isinstance(session.get("tokens"), dict) else None,
    )
    access_payload = decode_jwt_payload(
        session_access_token if isinstance(session_access_token, str) else None
    )
    access_auth = _claim_dict(access_payload, OPENAI_AUTH_CLAIM)
    access_profile = _claim_dict(access_payload, OPENAI_PROFILE_CLAIM)

    input_id_token = _first_non_empty(
        session.get("idToken"),
        session.get("id_token"),
        (session.get("tokens") or {}).get("id_token") if isinstance(session.get("tokens"), dict) else None,
    )
    id_payload = decode_jwt_payload(input_id_token if isinstance(input_id_token, str) else None)
    id_auth = _claim_dict(id_payload, OPENAI_AUTH_CLAIM)

    user = session.get("user") if isinstance(session.get("user"), dict) else {}
    account = session.get("account") if isinstance(session.get("account"), dict) else {}

    email = _first_non_empty(
        user.get("email"),
        session.get("email"),
        access_profile.get("email"),
        id_payload.get("email"),
        access_payload.get("email"),
    )
    account_id = _first_non_empty(
        account.get("id"),
        session.get("account_id"),
        session.get("chatgpt_account_id"),
        access_auth.get("chatgpt_account_id"),
        id_auth.get("chatgpt_account_id"),
    )
    if not isinstance(account_id, str) or not account_id:
        raise ValueError("session does not contain a ChatGPT account/workspace id")

    user_id = _first_non_empty(
        user.get("id"),
        session.get("user_id"),
        access_auth.get("chatgpt_user_id"),
        access_auth.get("user_id"),
        id_auth.get("chatgpt_user_id"),
        id_auth.get("user_id"),
    )
    plan_type = _first_non_empty(
        account.get("planType"),
        account.get("plan_type"),
        session.get("plan_type"),
        session.get("chatgpt_plan_type"),
        access_auth.get("chatgpt_plan_type"),
        id_auth.get("chatgpt_plan_type"),
    )
    refresh_token = _first_non_empty(session.get("refreshToken"), session.get("refresh_token"), "")
    expires_at = _jwt_expiry(access_payload) or _parse_datetime(
        _first_non_empty(session.get("expired"), session.get("expiresAt"), session.get("expires"))
    )

    synthetic = (
        bool(session.get("id_token_synthetic"))
        or not isinstance(input_id_token, str)
        or not input_id_token
    )
    id_token = input_id_token
    if not isinstance(id_token, str) or not id_token:
        id_token = build_synthetic_id_token(
            email=str(email) if email else None,
            account_id=account_id,
            plan_type=str(plan_type) if plan_type else None,
            user_id=str(user_id) if user_id else None,
            expires_at=expires_at,
            now=now,
        )

    cpa_access_token = str(personal_access_token or "").strip()
    if cpa_access_token.lower().startswith("bearer "):
        cpa_access_token = cpa_access_token[7:].strip()
    if not cpa_access_token and isinstance(session_access_token, str):
        candidate = session_access_token.strip()
        if candidate.lower().startswith("bearer "):
            candidate = candidate[7:].strip()
        if candidate.lower().startswith("at-"):
            cpa_access_token = candidate

    name = _first_non_empty(email, session.get("name"), "ChatGPT Account")
    result: dict[str, Any] = {
        "type": "codex",
        "account_id": account_id,
        "chatgpt_account_id": account_id,
        "email": email,
        "name": name,
        "plan_type": plan_type,
        "chatgpt_plan_type": plan_type,
        "id_token": id_token,
        "id_token_synthetic": True if synthetic else None,
        "access_token": cpa_access_token or None,
        "refresh_token": str(refresh_token or ""),
        "last_refresh": _iso_utc(now, milliseconds=True),
    }

    return {key: value for key, value in result.items() if value is not None}


def sanitize_file_token(value: str, fallback: str = "chatgpt-session") -> str:
    base = (value or fallback).strip() or fallback
    base = re.sub(r"\.[^.]+$", "", base)
    base = re.sub(r"[\\/:*?\"<>|]+", "-", base)
    base = re.sub(r"\s+", "-", base)
    base = re.sub(r"-+", "-", base).strip("-")
    return (base.lower()[:80] or fallback)


def build_cpa_filename(email: str, *, local_time: datetime | None = None) -> str:
    local_time = local_time or datetime.now().astimezone()
    timestamp = local_time.strftime("%Y-%m-%d_%H-%M-%S")
    return f"{sanitize_file_token(email)}.cpa.{timestamp}.json"


def load_json_object(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def semantic_cpa_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(payload))
    if normalized.get("type") == "codex" and "disabled" not in normalized:
        normalized["disabled"] = False
    return normalized
