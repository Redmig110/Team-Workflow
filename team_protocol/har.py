from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qs, unquote, urlparse


INVITE_PATH_RE = re.compile(r"^/backend-api/accounts/([^/]+)/invites$")
MEMBER_DELETE_RE = re.compile(r"^/backend-api/accounts/([^/]+)/users/([^/]+)$")


@dataclass(frozen=True)
class SessionSnapshot:
    index: int
    started_at: str
    data: dict[str, Any]

    @property
    def email(self) -> str:
        user = self.data.get("user") if isinstance(self.data.get("user"), dict) else {}
        return str(user.get("email") or self.data.get("email") or "")

    @property
    def account_id(self) -> str:
        account = self.data.get("account") if isinstance(self.data.get("account"), dict) else {}
        return str(account.get("id") or self.data.get("account_id") or "")


@dataclass(frozen=True)
class PatCredential:
    index: int
    started_at: str
    request: dict[str, Any]
    response: dict[str, Any]

    @property
    def token(self) -> str:
        return str(self.response.get("access_token") or "")

    @property
    def email(self) -> str:
        return str(self.response.get("creator_user_email") or "")

    @property
    def workspace_id(self) -> str:
        return str(self.response.get("workspace_id") or "")


def load_har(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("log"), dict):
        raise ValueError(f"{path} is not a valid HAR object")
    return value


def _entries(har: Mapping[str, Any]) -> list[dict[str, Any]]:
    log = har.get("log") if isinstance(har.get("log"), dict) else {}
    entries = log.get("entries") if isinstance(log, dict) else []
    return [entry for entry in entries if isinstance(entry, dict)]


def _content_text(entry: Mapping[str, Any]) -> str:
    response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    content = response.get("content") if isinstance(response.get("content"), dict) else {}
    text = content.get("text")
    return text if isinstance(text, str) else ""


def _request_body(entry: Mapping[str, Any]) -> str:
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
    text = post_data.get("text")
    return text if isinstance(text, str) else ""


def _parse_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def iter_session_snapshots(har: Mapping[str, Any]) -> Iterable[SessionSnapshot]:
    for index, entry in enumerate(_entries(har)):
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        url = str(request.get("url") or "")
        if not url.startswith("https://chatgpt.com/api/auth/session"):
            continue
        data = _parse_json(_content_text(entry))
        if not data.get("accessToken"):
            continue
        yield SessionSnapshot(index=index, started_at=str(entry.get("startedDateTime") or ""), data=data)


def iter_pat_credentials(har: Mapping[str, Any]) -> Iterable[PatCredential]:
    for index, entry in enumerate(_entries(har)):
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        url = urlparse(str(request.get("url") or ""))
        if request.get("method") != "POST" or url.path != "/backend-api/wham/auth-credentials":
            continue
        response = _parse_json(_content_text(entry))
        if not response.get("access_token"):
            continue
        yield PatCredential(
            index=index,
            started_at=str(entry.get("startedDateTime") or ""),
            request=_parse_json(_request_body(entry)),
            response=response,
        )


def _parse_started_at(value: str) -> datetime | None:
    raw = value.replace("Z", "+00:00") if value else ""
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def select_pat_credential(
    har: Mapping[str, Any],
    *,
    email: str | None = None,
    index: int | None = None,
) -> PatCredential | None:
    credentials = list(iter_pat_credentials(har))
    if index is not None:
        return next((item for item in credentials if item.index == index), None)
    if email:
        lowered = email.casefold()
        credentials = [item for item in credentials if item.email.casefold() == lowered]
    return credentials[-1] if credentials else None


def select_session_snapshot(
    har: Mapping[str, Any],
    *,
    email: str | None = None,
    index: int | None = None,
    mode: str = "latest",
) -> SessionSnapshot:
    snapshots = list(iter_session_snapshots(har))
    if index is not None:
        selected = next((item for item in snapshots if item.index == index), None)
        if selected is None:
            raise ValueError(f"HAR entry {index} is not a captured session response")
        return selected

    pat = select_pat_credential(har, email=email)
    target_email = email or (pat.email if pat else None)
    if target_email:
        lowered = target_email.casefold()
        snapshots = [item for item in snapshots if item.email.casefold() == lowered]
    if not snapshots:
        raise ValueError("HAR does not contain a session response with accessToken")

    if mode == "latest" or not pat:
        return snapshots[-1]
    pat_time = _parse_started_at(pat.started_at)
    if not pat_time:
        return snapshots[-1]
    timed = [(item, _parse_started_at(item.started_at)) for item in snapshots]
    timed = [(item, timestamp) for item, timestamp in timed if timestamp]
    if not timed:
        return snapshots[-1]
    if mode == "before-pat":
        before = [item for item, timestamp in timed if timestamp <= pat_time]
        return before[-1] if before else snapshots[0]
    if mode == "nearest-pat":
        return min(timed, key=lambda item: abs((item[1] - pat_time).total_seconds()))[0]
    raise ValueError(f"unknown session selection mode: {mode}")


def _event(index: int, entry: Mapping[str, Any], kind: str, **details: Any) -> dict[str, Any]:
    request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
    response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    return {
        "index": index,
        "time": str(entry.get("startedDateTime") or ""),
        "kind": kind,
        "method": str(request.get("method") or ""),
        "status": response.get("status"),
        "url": str(request.get("url") or ""),
        **details,
    }


def analyze_har(har: Mapping[str, Any]) -> dict[str, Any]:
    timeline: list[dict[str, Any]] = []
    signins: list[dict[str, Any]] = []
    invites: list[dict[str, Any]] = []
    leaves: list[dict[str, Any]] = []
    workspace_selections: list[dict[str, Any]] = []
    token_creations: list[dict[str, Any]] = []

    for index, entry in enumerate(_entries(har)):
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        method = str(request.get("method") or "")
        parsed = urlparse(str(request.get("url") or ""))
        path = parsed.path
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}

        if path == "/api/auth/signin/openai" and method == "POST":
            query = parse_qs(parsed.query)
            login_hint = unquote((query.get("login_hint") or [""])[0])
            item = _event(index, entry, "signin", login_hint=login_hint)
            signins.append(item)
            timeline.append(item)
            continue
        if parsed.netloc == "auth.openai.com" and path == "/api/accounts/email-otp/validate":
            body = _parse_json(_request_body(entry))
            item = _event(index, entry, "email_otp_validate", code_present=bool(body.get("code")))
            timeline.append(item)
            continue
        if parsed.netloc == "auth.openai.com" and path == "/api/accounts/workspace/select":
            body = _parse_json(_request_body(entry))
            item = _event(index, entry, "workspace_select", workspace_id=body.get("workspace_id"))
            workspace_selections.append(item)
            timeline.append(item)
            continue
        invite_match = INVITE_PATH_RE.match(path)
        if invite_match and method == "POST" and int(response.get("status") or 0) < 300:
            body = _parse_json(_request_body(entry))
            item = _event(
                index,
                entry,
                "invite",
                account_id=invite_match.group(1),
                request_body=body or None,
                request_body_captured=bool(body),
            )
            invites.append(item)
            timeline.append(item)
            continue
        leave_match = MEMBER_DELETE_RE.match(path)
        if leave_match and method == "DELETE" and int(response.get("status") or 0) < 300:
            item = _event(
                index,
                entry,
                "member_delete",
                account_id=leave_match.group(1),
                user_id=leave_match.group(2),
            )
            leaves.append(item)
            timeline.append(item)
            continue
        if path == "/api/auth/signout" and method == "POST":
            timeline.append(_event(index, entry, "signout"))
            continue
        if path == "/backend-api/wham/auth-credentials" and method == "POST":
            request_body = _parse_json(_request_body(entry))
            response_body = _parse_json(_content_text(entry))
            item = _event(
                index,
                entry,
                "personal_access_token_create",
                name=request_body.get("name"),
                scopes=request_body.get("scopes"),
                ttl=request_body.get("ttl"),
                credential_id=response_body.get("credential_id"),
                workspace_id=response_body.get("workspace_id"),
                creator_email=response_body.get("creator_user_email"),
                token_present=bool(response_body.get("access_token")),
            )
            token_creations.append(item)
            timeline.append(item)
            continue
        if path == "/api/auth/session" and _content_text(entry):
            data = _parse_json(_content_text(entry))
            if data.get("accessToken"):
                user = data.get("user") if isinstance(data.get("user"), dict) else {}
                account = data.get("account") if isinstance(data.get("account"), dict) else {}
                timeline.append(
                    _event(
                        index,
                        entry,
                        "session_snapshot",
                        email=user.get("email"),
                        user_id=user.get("id"),
                        account_id=account.get("id"),
                        plan_type=account.get("planType"),
                        session_token_present=bool(data.get("sessionToken")),
                    )
                )

    inferred_invitee = ""
    if invites and len(signins) >= 2:
        invite_index = invites[-1]["index"]
        later_signins = [item for item in signins if item["index"] > invite_index and item.get("login_hint")]
        if later_signins:
            inferred_invitee = str(later_signins[0]["login_hint"])

    return {
        "entry_count": len(_entries(har)),
        "signins": signins,
        "invites": invites,
        "member_deletes": leaves,
        "workspace_selections": workspace_selections,
        "token_creations": token_creations,
        "session_snapshots": len(list(iter_session_snapshots(har))),
        "inferences": {
            "invitee_email": inferred_invitee or None,
            "invite_request_body": (
                "HAR omitted POST body; team-manage-refresh confirms "
                '{"email_addresses":[email],"role":"standard-user","resend_emails":true}'
            )
            if invites and not invites[-1].get("request_body_captured")
            else None,
        },
        "timeline": sorted(timeline, key=lambda item: item["index"]),
    }
