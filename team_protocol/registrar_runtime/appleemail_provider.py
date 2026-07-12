"""AppleEmail API backed Outlook/Hotmail mailbox provider."""

from __future__ import annotations

import json
import hashlib
import random
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Iterable, Mapping, Optional

import requests

DEFAULT_APPLEEMAIL_API_BASE = "https://www.appleemail.top"
DEFAULT_ALIAS_COUNT = 5
DEFAULT_MAILBOXES = ("INBOX", "Junk")
DEFAULT_ALIAS_MODE = "random"
DEFAULT_OTP_EARLY_TOLERANCE_SECONDS = 8.0
_OTP_PATTERN = re.compile(r"(?<![#&A-Za-z0-9])(\d{6})(?![A-Za-z0-9])")
_EMAIL_ADDRESS_PATTERN = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+\.[A-Za-z]{2,}")
_MAILBOX_AUTH_ERROR_CODES = (
    "invalid_grant",
    "invalid_refresh_token",
    "refresh_token_revoked",
    "token_revoked",
    "aadsts70000",
    "aadsts700082",
)
_ALIAS_WORDS = (
    "river",
    "cloud",
    "stone",
    "forest",
    "silver",
    "winter",
    "orange",
    "violet",
    "pixel",
    "lucky",
    "north",
    "summer",
    "coffee",
    "planet",
    "bright",
    "maple",
    "sunny",
    "ocean",
    "garden",
    "shadow",
    "velvet",
    "signal",
    "rocket",
    "paper",
    "copper",
    "marble",
)


class MailboxCredentialsInvalidError(RuntimeError):
    """The mailbox service explicitly rejected persisted refresh credentials."""


def _is_explicit_mailbox_auth_rejection(response: Any) -> bool:
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code not in {400, 401, 403}:
        return False
    text = str(getattr(response, "text", "") or "").casefold()
    return any(code in text for code in _MAILBOX_AUTH_ERROR_CODES)


def _normalize_proxy_url(proxy: Any) -> str:
    value = str(proxy or "").strip()
    if not value:
        return ""
    if "://" in value:
        return value
    if ":" in value:
        return f"http://{value}"
    return ""


def _proxies_dict(proxy: Any) -> Optional[dict[str, str]]:
    normalized = _normalize_proxy_url(proxy)
    if not normalized:
        return None
    return {"http": normalized, "https": normalized}


@dataclass(frozen=True)
class AppleEmailAccount:
    primary_email: str
    client_id: str
    refresh_token: str
    password: str = ""
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppleEmailMailbox:
    primary_email: str
    registration_email: str
    client_id: str
    refresh_token: str
    password: str = ""

    def credential_json(self) -> str:
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


def _normalize_email(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if "@" in text else ""


def _random_alias_suffix() -> str:
    word = secrets.choice(_ALIAS_WORDS)
    number = secrets.randbelow(9000) + 1000
    tail = secrets.token_hex(1)
    return f"{word}{number}{tail}"


def _plus_aliases(
    primary_email: str,
    alias_count: int = DEFAULT_ALIAS_COUNT,
    alias_mode: str = DEFAULT_ALIAS_MODE,
) -> tuple[str, ...]:
    primary = _normalize_email(primary_email)
    if not primary:
        return ()
    local, domain = primary.rsplit("@", 1)
    count = max(0, int(alias_count or 0))
    aliases = [primary]
    mode = str(alias_mode or DEFAULT_ALIAS_MODE).strip().lower()
    seen = {primary}
    while len(aliases) < count + 1:
        suffix = str(len(aliases)) if mode in {"number", "numeric", "sequential"} else _random_alias_suffix()
        alias = f"{local}+{suffix}@{domain}"
        if alias in seen:
            continue
        seen.add(alias)
        aliases.append(alias)
    return tuple(aliases)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _empty_state() -> dict[str, Any]:
    return {
        "version": 1,
        "generated_aliases": {},
        "completed_aliases": {},
        "skipped_primaries": {},
        "deactivated_aliases": {},
        "relogin_status": {},
        "rate_limited_primaries": {},
    }


_STATE_MAPPING_KEYS = (
    "generated_aliases",
    "completed_aliases",
    "skipped_primaries",
    "deactivated_aliases",
    "relogin_status",
    "rate_limited_primaries",
)


def _normalize_state(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    state = _empty_state()
    if not isinstance(payload, Mapping):
        return state
    for key in _STATE_MAPPING_KEYS:
        value = payload.get(key)
        if isinstance(value, Mapping):
            state[key] = dict(value)
    state["version"] = int(payload.get("version") or 1)
    return state


def _safe_state_snapshot(state: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_state(state)
    return json.loads(json.dumps(normalized, ensure_ascii=False))


def _message_timestamp_seconds(message: Any) -> Optional[float]:
    if not isinstance(message, dict):
        return None
    for key in (
        "createdAt",
        "created_at",
        "receivedAt",
        "received_at",
        "sentAt",
        "sent_at",
        "date",
        "timestamp",
        "time",
    ):
        value = message.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (int, float)):
            numeric = float(value)
            return numeric / 1000.0 if numeric > 1e12 else numeric
        text = str(value or "").strip()
        if not text:
            continue
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            numeric = float(text)
            return numeric / 1000.0 if numeric > 1e12 else numeric
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(text)
            except (TypeError, ValueError, IndexError, OverflowError):
                continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return float(dt.timestamp())
    return None


def _iter_strings(value: Any) -> Iterable[str]:
    if value is None:
        return
    if isinstance(value, str):
        if value:
            yield value
        return
    if isinstance(value, (int, float, bool)):
        yield str(value)
        return
    if isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
        return
    if isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def _email_primary_key(email: str) -> str:
    normalized = _normalize_email(email)
    if not normalized:
        return ""
    local, domain = normalized.rsplit("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


def _email_has_plus_alias(email: str) -> bool:
    normalized = _normalize_email(email)
    if not normalized:
        return False
    local = normalized.rsplit("@", 1)[0]
    return "+" in local


def _message_recipient_text(message: Any) -> str:
    if not isinstance(message, dict):
        return ""
    return "\n".join(
        _iter_strings(
            {
                key: message.get(key)
                for key in (
                    "to",
                    "recipient",
                    "recipients",
                    "cc",
                    "bcc",
                    "headers",
                    "envelope",
                    "deliveredTo",
                    "delivered_to",
                    "originalTo",
                    "original_to",
                )
            }
        )
    )


def _message_targets_other_alias(message: Any, registration_email: str) -> bool:
    target = _normalize_email(registration_email)
    if not target:
        return False
    recipient_text = _message_recipient_text(message)
    if not recipient_text:
        return False
    lowered = recipient_text.lower()
    if target in lowered:
        return False
    target_primary = _email_primary_key(target)
    if not target_primary:
        return False
    recipient_emails = {
        _normalize_email(match.group(0))
        for match in _EMAIL_ADDRESS_PATTERN.finditer(recipient_text)
    }
    recipient_emails.discard("")
    for recipient in recipient_emails:
        if recipient == target:
            return False
        if _email_primary_key(recipient) != target_primary:
            continue
        # A primary-only recipient is common for APIs that normalize plus
        # aliases, so allow it when the requested target is a plus alias.
        # A different plus alias under the same primary is a clear mismatch.
        if _email_has_plus_alias(recipient) or not _email_has_plus_alias(target):
            return True
    return False


def _extract_code_from_message(message: Any, registration_email: str = "") -> str:
    priority_keys = (
        "code",
        "otp",
        "verification_code",
        "verificationCode",
        "verify_code",
        "verifyCode",
        "authCode",
        "auth_code",
        "验证码",
    )
    if isinstance(message, dict):
        for key in priority_keys:
            raw = message.get(key)
            if raw is None:
                continue
            match = _OTP_PATTERN.search(str(raw))
            if match:
                return match.group(1)

    haystack = "\n".join(_iter_strings(message))
    target = str(registration_email or "").strip().lower()
    # Do not make recipient filtering mandatory: some mailbox APIs normalize
    # the To field back to the primary mailbox or omit it entirely for aliases.
    # If the alias is visible, it helps us prefer the right mail; if not, fall
    # back to timestamp + OpenAI/ChatGPT/code markers instead of discarding.
    if target and target not in haystack.lower():
        recipient_fields = ""
        if isinstance(message, dict):
            recipient_fields = "\n".join(
                _iter_strings(
                    {
                        key: message.get(key)
                        for key in ("to", "recipient", "recipients", "cc", "bcc", "headers")
                    }
                )
            )
        if recipient_fields and target in recipient_fields.lower():
            match = _OTP_PATTERN.search(haystack)
            if match:
                return match.group(1)

    for marker in ("openai", "chatgpt", "verification", "验证码", "code"):
        if marker in haystack.lower():
            match = _OTP_PATTERN.search(haystack)
            if match:
                return match.group(1)
    match = _OTP_PATTERN.search(haystack)
    return match.group(1) if match else ""


def _normalize_messages(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("data", "mails", "mail", "messages", "result", "items", "list"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = _normalize_messages(value)
            if nested:
                return nested
    return [payload]


def _message_fingerprint(message: Any) -> str:
    if isinstance(message, dict):
        for key in (
            "id",
            "uid",
            "uuid",
            "message_id",
            "messageId",
            "internetMessageId",
            "internet_message_id",
        ):
            value = str(message.get(key) or "").strip()
            if value:
                return f"{key}:{value}"
    try:
        raw = json.dumps(message, ensure_ascii=False, sort_keys=True, default=str)
    except TypeError:
        raw = str(message)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


class AppleEmailHotmailProvider:
    """Mailbox provider compatible with register.run()."""

    def __init__(
        self,
        *,
        accounts: list[AppleEmailAccount],
        api_base: str = DEFAULT_APPLEEMAIL_API_BASE,
        mailboxes: Iterable[str] = DEFAULT_MAILBOXES,
        request_timeout: int = 20,
        initial_state: Optional[Mapping[str, Any]] = None,
        state_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.api_base = str(api_base or DEFAULT_APPLEEMAIL_API_BASE).strip().rstrip("/")
        self.mailboxes = tuple(str(item or "").strip() for item in mailboxes if str(item or "").strip()) or DEFAULT_MAILBOXES
        self.request_timeout = max(3, int(request_timeout or 20))
        if initial_state is not None:
            self._state = _safe_state_snapshot(initial_state)
        else:
            self._state = _empty_state()
        self._state_callback = state_callback
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._queue: list[AppleEmailMailbox] = []
        self._baselines: dict[str, dict[str, Any]] = {}
        self._active_primaries: set[str] = set()
        self._active_main_primaries: set[str] = set()
        self._thread_leases: dict[int, str] = {}
        self._thread_main_leases: dict[int, str] = {}
        skipped_primaries = self._state.get("skipped_primaries")
        completed_aliases = self._state.get("completed_aliases")
        deactivated_aliases = self._state.get("deactivated_aliases")
        self._skipped_primaries: set[str] = {
            str(primary or "").strip().lower()
            for primary in (skipped_primaries.keys() if isinstance(skipped_primaries, dict) else ())
            if str(primary or "").strip()
        }
        self._completed_aliases: set[str] = {
            str(email or "").strip().lower()
            for email in (completed_aliases.keys() if isinstance(completed_aliases, dict) else ())
            if str(email or "").strip()
        }
        self._completed_aliases.update(
            str(email or "").strip().lower()
            for email in (deactivated_aliases.keys() if isinstance(deactivated_aliases, dict) else ())
            if str(email or "").strip()
        )
        for account in accounts:
            primary = str(account.primary_email or "").strip().lower()
            if primary and primary in self._skipped_primaries:
                continue
            aliases = account.aliases or _plus_aliases(account.primary_email, DEFAULT_ALIAS_COUNT)
            for alias in aliases:
                registration_email = str(alias or "").strip().lower()
                if registration_email and registration_email in self._completed_aliases:
                    continue
                self._queue.append(
                    AppleEmailMailbox(
                        primary_email=primary or account.primary_email,
                        registration_email=registration_email or alias,
                        client_id=account.client_id,
                        refresh_token=account.refresh_token,
                        password=account.password,
                    )
                )
        self._current: Optional[AppleEmailMailbox] = None

    @property
    def remaining(self) -> int:
        with self._lock:
            return len(self._queue)

    def snapshot_state(self) -> dict[str, Any]:
        with self._lock:
            return _safe_state_snapshot(self._state)

    @staticmethod
    def _is_primary_mailbox(mailbox: AppleEmailMailbox) -> bool:
        primary = str(mailbox.primary_email or "").strip().lower()
        registration_email = str(mailbox.registration_email or "").strip().lower()
        return bool(primary and registration_email and primary == registration_email)

    def _find_selectable_mailbox_locked(self) -> int:
        """Return the next mailbox by TXT primary-group order.

        Queue construction is already grouped as:
        primary1, primary1_alias1..., primary2, primary2_alias1...

        Do not globally prefer all primaries.  This makes a restarted run resume
        with the aliases of the last completed primary before moving to the next
        TXT primary.  For concurrency, a primary group can still occupy at most
        one worker at a time because active primaries are skipped.
        """

        for index, candidate in enumerate(self._queue):
            primary = str(candidate.primary_email or "").strip().lower()
            if primary in self._skipped_primaries:
                continue
            if primary in self._active_primaries:
                continue
            return index
        return -1

    def create_mailbox(self, **kwargs: Any) -> tuple[str, str]:
        wait_timeout = max(1.0, float(kwargs.get("lease_wait_timeout") or 300.0))
        deadline = time.time() + wait_timeout
        with self._condition:
            while True:
                self._release_thread_lease_locked()
                if not self._queue:
                    return "", ""
                selected_index = self._find_selectable_mailbox_locked()
                if selected_index >= 0:
                    self._current = self._queue.pop(selected_index)
                    current = self._current
                    primary = str(current.primary_email or "").strip().lower()
                    if primary:
                        self._active_primaries.add(primary)
                        thread_id = threading.get_ident()
                        self._thread_leases[thread_id] = primary
                        if self._is_primary_mailbox(current):
                            self._active_main_primaries.add(primary)
                            self._thread_main_leases[thread_id] = primary
                    break
                remaining = deadline - time.time()
                if remaining <= 0:
                    return "", ""
                self._condition.wait(timeout=min(1.0, remaining))
        self._snapshot_existing_messages(current, proxy=kwargs.get("proxy"))
        return current.registration_email, current.credential_json()

    def skip_primary(self, auth_credential: str = "", email: str = "", reason: str = "") -> int:
        """Remove all queued aliases for the current primary mailbox.

        Called by the registration flow when OpenAI reports that the address
        already exists.  It prevents wasting attempts on the same Outlook /
        Hotmail primary and its remaining aliases.
        """

        primary = ""
        try:
            payload = json.loads(str(auth_credential or ""))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            primary = str(payload.get("primary_email") or "").strip().lower()
        if not primary and self._current is not None:
            primary = str(self._current.primary_email or "").strip().lower()
        if not primary:
            candidate_email = str(email or "").strip().lower()
            if "@" in candidate_email:
                local, domain = candidate_email.rsplit("@", 1)
                primary = f"{local.split('+', 1)[0]}@{domain}"
        if not primary:
            return 0

        with self._condition:
            before = len(self._queue)
            self._skipped_primaries.add(primary)
            skipped = self._state.setdefault("skipped_primaries", {})
            if isinstance(skipped, dict):
                skipped[primary] = {
                    "primary_email": primary,
                    "reason": str(reason or "").strip() or "skipped",
                    "updated_at": _utc_now_iso(),
                }
            self._queue = [
                mailbox
                for mailbox in self._queue
                if str(mailbox.primary_email or "").strip().lower() != primary
            ]
            self._baselines = {
                key: value
                for key, value in self._baselines.items()
                if primary not in str(key or "").lower()
            }
            removed = before - len(self._queue)
            self._save_state_locked()
            self._condition.notify_all()
            return removed

    def mark_email_completed(
        self,
        auth_credential: str = "",
        email: str = "",
        status: str = "success",
        reason: str = "",
    ) -> bool:
        """Persist that one registration email completed successfully.

        The provider will not return this registration address again after GUI
        restart.  Generated random aliases are also persisted separately so the
        same primary keeps the same alias set across restarts.
        """

        try:
            mailbox = self._mailbox_from_credential(auth_credential, email)
        except Exception:
            registration_email = _normalize_email(email)
            if not registration_email:
                return False
            if "+" in registration_email.rsplit("@", 1)[0]:
                local, domain = registration_email.rsplit("@", 1)
                primary = f"{local.split('+', 1)[0]}@{domain}"
            else:
                primary = registration_email
            mailbox = AppleEmailMailbox(
                primary_email=primary,
                registration_email=registration_email,
                client_id="",
                refresh_token="",
            )

        primary = _normalize_email(mailbox.primary_email)
        registration_email = _normalize_email(mailbox.registration_email or email)
        if not registration_email:
            return False

        with self._condition:
            completed = self._state.setdefault("completed_aliases", {})
            if isinstance(completed, dict):
                completed[registration_email] = {
                    "primary_email": primary,
                    "email": registration_email,
                    "status": str(status or "success").strip() or "success",
                    "reason": str(reason or "").strip(),
                    "updated_at": _utc_now_iso(),
                }
            self._completed_aliases.add(registration_email)
            self._queue = [
                queued
                for queued in self._queue
                if str(queued.registration_email or "").strip().lower() != registration_email
            ]
            self._save_state_locked()
            self._condition.notify_all()
        return True

    def _save_state_locked(self) -> None:
        snapshot = _safe_state_snapshot(self._state)
        if self._state_callback is not None:
            self._state_callback(snapshot)

    def release_thread_lease(self) -> None:
        with self._condition:
            self._release_thread_lease_locked()
            self._condition.notify_all()

    def _release_thread_lease_locked(self) -> None:
        thread_id = threading.get_ident()
        primary = self._thread_leases.pop(thread_id, "")
        if primary:
            self._active_primaries.discard(primary)
        main_primary = self._thread_main_leases.pop(thread_id, "")
        if main_primary:
            self._active_main_primaries.discard(main_primary)

    def wait_for_otp(
        self,
        auth_credential: str,
        email: str,
        *,
        timeout: int = 60,
        stop_event: Any = None,
        sent_at_ts: Optional[float] = None,
        proxy: Any = None,
        proxy_selector: Any = None,
        exclude_codes: Optional[set[str]] = None,
        **_: Any,
    ) -> str:
        mailbox = self._mailbox_from_credential(auth_credential, email)
        excluded = {str(code or "").strip() for code in (exclude_codes or set()) if str(code or "").strip()}
        selected_proxy = proxy
        if proxy_selector is not None:
            try:
                selected_proxy = proxy_selector() or proxy
            except Exception:
                selected_proxy = proxy
        try:
            deadline = time.time() + max(1, int(timeout or 60))
            while time.time() < deadline:
                if stop_event is not None and stop_event.is_set():
                    return ""
                code = self._fetch_code(
                    mailbox,
                    sent_at_ts=sent_at_ts,
                    proxy=selected_proxy,
                    exclude_codes=excluded,
                )
                if code:
                    return code
                delay = random.uniform(1.0, 1.8)
                if stop_event is not None:
                    stop_event.wait(delay)
                else:
                    time.sleep(delay)
            return ""
        finally:
            self.release_thread_lease()

    def _mailbox_from_credential(self, auth_credential: str, email: str) -> AppleEmailMailbox:
        try:
            payload = json.loads(str(auth_credential or ""))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict) and payload.get("primary_email"):
            return AppleEmailMailbox(
                primary_email=str(payload.get("primary_email") or "").strip().lower(),
                registration_email=str(payload.get("registration_email") or email or "").strip().lower(),
                client_id=str(payload.get("client_id") or "").strip(),
                refresh_token=str(payload.get("refresh_token") or "").strip(),
                password=str(payload.get("password") or "").strip(),
            )
        if self._current is not None:
            return self._current
        raise RuntimeError("AppleEmail mailbox credential missing")

    def _fetch_code(
        self,
        mailbox: AppleEmailMailbox,
        *,
        sent_at_ts: Optional[float],
        proxy: Any = None,
        exclude_codes: Optional[set[str]] = None,
    ) -> str:
        messages, last_error = self._collect_messages(mailbox, proxy=proxy)
        if not messages and last_error:
            return ""

        baseline = self._baseline_for(mailbox)
        baseline_fingerprints = baseline.get("fingerprints")
        if not isinstance(baseline_fingerprints, set):
            baseline_fingerprints = set()
        baseline_complete = bool(baseline.get("complete"))
        acquired_at = float(baseline.get("acquired_at") or 0.0)

        lower_bound_candidates = [
            float(value)
            for value in (sent_at_ts, acquired_at)
            if value is not None and float(value or 0.0) > 0
        ]
        lower_bound = max(lower_bound_candidates) - DEFAULT_OTP_EARLY_TOLERANCE_SECONDS if lower_bound_candidates else 0.0
        excluded = {str(code or "").strip() for code in (exclude_codes or set()) if str(code or "").strip()}

        def _sort_key(message: Any) -> float:
            return _message_timestamp_seconds(message) or 0.0

        for message in sorted(messages, key=_sort_key, reverse=True):
            fingerprint = _message_fingerprint(message)
            if fingerprint in baseline_fingerprints:
                continue
            ts = _message_timestamp_seconds(message)
            if lower_bound and ts is not None and ts < lower_bound:
                continue
            if lower_bound and ts is None and not baseline_complete:
                continue
            if _message_targets_other_alias(message, mailbox.registration_email):
                continue
            code = _extract_code_from_message(message, mailbox.registration_email)
            if code:
                if code in excluded:
                    return ""
                return code
        return ""

    def _baseline_key(self, mailbox: AppleEmailMailbox) -> str:
        return str(mailbox.registration_email or "").strip().lower()

    def _baseline_for(self, mailbox: AppleEmailMailbox) -> dict[str, Any]:
        with self._lock:
            baseline = self._baselines.get(self._baseline_key(mailbox))
            return dict(baseline or {})

    def _snapshot_existing_messages(self, mailbox: AppleEmailMailbox, proxy: Any = None) -> None:
        started_at = time.time()
        fingerprints: set[str] = set()
        complete = False
        try:
            messages, _last_error = self._collect_messages(mailbox, proxy=proxy)
            fingerprints = {_message_fingerprint(message) for message in messages}
            complete = True
        except MailboxCredentialsInvalidError:
            raise
        except Exception:
            complete = False
        with self._lock:
            self._baselines[self._baseline_key(mailbox)] = {
                "acquired_at": started_at,
                "fingerprints": fingerprints,
                "complete": complete,
            }

    def _collect_messages(self, mailbox: AppleEmailMailbox, proxy: Any = None) -> tuple[list[Any], str]:
        messages: list[Any] = []
        last_error = ""
        for folder in self.mailboxes:
            try:
                messages.extend(self._fetch_messages(mailbox, folder, proxy=proxy))
            except MailboxCredentialsInvalidError:
                raise
            except Exception as exc:
                last_error = str(exc)
            try:
                latest = self._fetch_latest_message(mailbox, folder, proxy=proxy)
                if latest:
                    messages.insert(0, latest)
            except MailboxCredentialsInvalidError:
                raise
            except Exception as exc:
                last_error = str(exc)
        return messages, last_error

    def _fetch_messages(self, mailbox: AppleEmailMailbox, folder: str, proxy: Any = None) -> list[Any]:
        response = requests.post(
            f"{self.api_base}/api/mail-all",
            json={
                "refresh_token": mailbox.refresh_token,
                "client_id": mailbox.client_id,
                "email": mailbox.primary_email,
                "mailbox": folder,
            },
            proxies=_proxies_dict(proxy),
            timeout=self.request_timeout,
        )
        if _is_explicit_mailbox_auth_rejection(response):
            raise MailboxCredentialsInvalidError("mailbox refresh credentials were rejected")
        response.raise_for_status()
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        return _normalize_messages(payload)

    def _fetch_latest_message(self, mailbox: AppleEmailMailbox, folder: str, proxy: Any = None) -> Any:
        response = requests.post(
            f"{self.api_base}/api/mail-new",
            json={
                "refresh_token": mailbox.refresh_token,
                "client_id": mailbox.client_id,
                "email": mailbox.primary_email,
                "mailbox": folder,
                "response_type": "json",
            },
            proxies=_proxies_dict(proxy),
            timeout=self.request_timeout,
        )
        if _is_explicit_mailbox_auth_rejection(response):
            raise MailboxCredentialsInvalidError("mailbox refresh credentials were rejected")
        response.raise_for_status()
        try:
            return response.json()
        except ValueError:
            return response.text
