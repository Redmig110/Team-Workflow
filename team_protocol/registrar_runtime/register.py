import json
import os
import re
import sys
import time
import uuid
import math
import random
import string
import secrets
import socket
import hashlib
import base64
import threading
import argparse
import queue
import tempfile
from http.cookies import SimpleCookie
from datetime import datetime, timezone, timedelta
from .chromium_time import chromium_local_timestamp
from urllib.parse import urlparse, parse_qs, urlencode, quote
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable
import urllib.parse
import urllib.request
import urllib.error

from curl_cffi import requests

from .fingerprint_profiles import (
    SessionProfile,
    create_session_profile,
    normalize_profile_scope,
)

# ==========================================
# 日志事件发射器
# ==========================================


class EventEmitter:
    """
    将注册流程中的日志事件发射到队列，供 SSE 消费。
    同时支持 CLI 模式（直接 print）。
    """

    def __init__(
        self,
        q: Optional[queue.Queue] = None,
        cli_mode: bool = False,
        defaults: Optional[Dict[str, Any]] = None,
    ):
        self._q = q
        self._cli_mode = cli_mode
        self._defaults = dict(defaults or {})

    def emit(self, level: str, message: str, step: str = "", **extra: Any) -> None:
        """
        level: "info" | "success" | "error" | "warn"
        step:  可选的流程阶段标识，如 "check_proxy" / "create_email" 等
        """
        ts = datetime.now().strftime("%H:%M:%S")
        event = {
            "ts": ts,
            "level": level,
            "message": message,
            "step": step,
        }
        if self._defaults:
            event.update(self._defaults)
        if extra:
            event.update({k: v for k, v in extra.items() if v is not None})
        if self._cli_mode:
            prefix_map = {
                "info": "[*]",
                "success": "[+]",
                "error": "[Error]",
                "warn": "[!]",
            }
            prefix = prefix_map.get(level, "[*]")
            print(f"{prefix} {message}")
        if self._q is not None:
            try:
                self._q.put_nowait(event)
            except queue.Full:
                pass

    def bind(self, **defaults: Any) -> "EventEmitter":
        merged = dict(self._defaults)
        merged.update({k: v for k, v in defaults.items() if v is not None})
        return EventEmitter(q=self._q, cli_mode=self._cli_mode, defaults=merged)

    def info(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("info", msg, step, **extra)

    def success(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("success", msg, step, **extra)

    def error(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("error", msg, step, **extra)

    def warn(self, msg: str, step: str = "", **extra: Any) -> None:
        self.emit("warn", msg, step, **extra)


# 默认 CLI 发射器（兼容直接运行）
_cli_emitter = EventEmitter(cli_mode=True)


# ==========================================
# Mail.tm 临时邮箱 API
# ==========================================

MAILTM_BASE = "https://api.mail.tm"
DEFAULT_PROXY_POOL_URL = ""
DEFAULT_PROXY_POOL_AUTH_MODE = "query"
DEFAULT_PROXY_POOL_API_KEY = ""
DEFAULT_PROXY_POOL_COUNT = 1
DEFAULT_PROXY_POOL_COUNTRY = "US"
DEFAULT_HTTP_VERSION = "v2"
H3_PROXY_ERROR_HINT = "HTTP/3 is not supported over an HTTP proxy"
TRANSIENT_TLS_ERROR_HINTS = (
    "curl: (35)",
    "curl: (28)",
    "Timeout was reached",
    "Operation timed out after",
    "TLS connect error",
    "OPENSSL_internal:invalid library",
    "SSL_ERROR_SYSCALL",
)
TRANSIENT_TLS_RETRY_COUNT = 2
POOL_RELAY_RETRIES = 2
POOL_PROXY_FETCH_RETRIES = 3
POOL_RELAY_REQUEST_RETRIES = 2
OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS = 30
OTP_RESEND_TRIGGER_SECONDS = (8, 16)
OTP_WRONG_CODE_RETRY_TIMEOUT_SECONDS = 20
OTP_WRONG_CODE_MAX_RETRIES = 2
PHONE_GATE_RECYCLE_MAX_ATTEMPTS = 1
AUTHORIZE_CONTINUE_RATE_LIMIT_RETRY_DELAYS_SECONDS = (4, 8)
CURRENT_SESSION_PHONE_GATE_RECYCLE_COOLDOWN_SECONDS = 4
CURRENT_SESSION_OAUTH_PHONE_GATE_RECYCLE_MARKER = "__CURRENT_SESSION_OAUTH_PHONE_GATE_RECYCLE__"


class SignupRateLimitError(RuntimeError):
    pass


class SignupInvalidStateError(RuntimeError):
    pass


POST_SIGNUP_CALLBACK_OAUTH_DELAY_SECONDS = 0
OTP_POLL_INTERVAL_MIN_SECONDS = 1.0
OTP_POLL_INTERVAL_MAX_SECONDS = 1.5
DEACTIVATED_MARKERS = (
    "account_deactivated",
    "has been deactivated",
    "account has been deactivated",
    "openai account has been deactivated",
    "deleted or deactivated",
    "has been deleted or deactivated",
    "do not have an account because it has been deleted or deactivated",
)
PHONE_GATE_MARKERS = (
    "add_phone",
    "add-phone",
    "phone_verification",
    "phone-verification",
    "phone/verify",
    "/add-phone",
)
ABOUT_YOU_PAGE_TYPES = ("about_you", "about-you")
DEFAULT_BROWSER_SENTINEL_PAGE_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"
DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS = 60
DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY = 16
MAX_BROWSER_SENTINEL_CONCURRENCY = 64
DEFAULT_BROWSER_SENTINEL_FALLBACK_HEADED = False
DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE = "auto_desktop"
DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE = "browserforge"
_BROWSER_SENTINEL_SEMAPHORE_LOCK = threading.Lock()
_BROWSER_SENTINEL_SEMAPHORES: Dict[int, threading.BoundedSemaphore] = {}


def _otp_poll_wait(stop_event: Optional[threading.Event] = None) -> None:
    delay = random.uniform(OTP_POLL_INTERVAL_MIN_SECONDS, OTP_POLL_INTERVAL_MAX_SECONDS)
    if stop_event is not None:
        stop_event.wait(delay)
        return
    time.sleep(delay)


def _sleep_with_stop_event(seconds: float, stop_event: Optional[threading.Event] = None) -> bool:
    delay = max(0.0, float(seconds or 0))
    if delay <= 0:
        return True
    if stop_event is not None:
        return not stop_event.wait(delay)
    time.sleep(delay)
    return True


def _build_otp_latency_message(
    sent_at_ts: Optional[float],
    label: str = "send_otp -> 首封命中延迟",
) -> str:
    if not sent_at_ts:
        return ""
    try:
        delta = max(0.0, time.time() - float(sent_at_ts))
    except (TypeError, ValueError):
        return ""
    return f"{label}: {delta:.1f}s"


def _emit_otp_latency(
    emitter: EventEmitter,
    sent_at_ts: Optional[float],
    step: str = "wait_otp",
    label: str = "send_otp -> 首封命中延迟",
    direct_print: bool = False,
) -> None:
    message = _build_otp_latency_message(sent_at_ts, label=label)
    if not message:
        return
    if direct_print and not getattr(emitter, "_cli_mode", False):
        print(message, flush=True)
    emitter.info(message, step=step)


def _wait_for_signup_otp_with_resend(
    *,
    fetch_otp: Callable[[int, Optional[float]], str],
    resend_otp: Callable[[int], Optional[float]],
    initial_sent_at: Optional[float],
    emitter: EventEmitter,
    stop_event: Optional[threading.Event] = None,
    total_timeout_seconds: int = OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS,
    resend_after_seconds: tuple[int, ...] = OTP_RESEND_TRIGGER_SECONDS,
    time_source: Callable[[], float] = time.time,
) -> str:
    total_timeout = max(1, int(total_timeout_seconds or OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS))
    resend_points = sorted(
        {
            max(1, int(point))
            for point in resend_after_seconds
            if int(point or 0) < total_timeout
        }
    )
    started_at = time_source()
    current_sent_at = initial_sent_at

    for attempt_index, trigger_after in enumerate(resend_points, start=1):
        if stop_event is not None and stop_event.is_set():
            return ""
        elapsed = max(0.0, time_source() - started_at)
        segment_timeout = int(math.ceil(trigger_after - elapsed))
        if segment_timeout <= 0:
            continue
        code = fetch_otp(segment_timeout, current_sent_at)
        if code:
            return code
        if stop_event is not None and stop_event.is_set():
            return ""
        elapsed = max(0.0, time_source() - started_at)
        if elapsed >= total_timeout:
            return ""
        emitter.warn(
            f"{trigger_after}s 内未收到验证码，正在重发邮箱验证码（第 {attempt_index} 次）...",
            step="send_otp",
        )
        resent_at = resend_otp(attempt_index)
        if not resent_at:
            return ""
        current_sent_at = resent_at

    if stop_event is not None and stop_event.is_set():
        return ""
    remaining_timeout = int(math.ceil(total_timeout - max(0.0, time_source() - started_at)))
    if remaining_timeout <= 0:
        return ""
    return fetch_otp(remaining_timeout, current_sent_at)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _normalize_browser_sentinel_config(raw_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    config = raw_config if isinstance(raw_config, dict) else {}
    try:
        timeout_seconds = int(config.get("timeout_seconds", DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        timeout_seconds = DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS
    timeout_seconds = max(3, min(timeout_seconds, 120))
    try:
        max_concurrency = int(
            config.get("max_concurrency", config.get("browser_sentinel_max_concurrency", DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY))
        )
    except (TypeError, ValueError):
        max_concurrency = DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY
    max_concurrency = max(1, min(max_concurrency, MAX_BROWSER_SENTINEL_CONCURRENCY))
    page_url = str(config.get("page_url") or DEFAULT_BROWSER_SENTINEL_PAGE_URL).strip() or DEFAULT_BROWSER_SENTINEL_PAGE_URL
    fingerprint_engine = DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE
    return {
        "enabled": _coerce_bool(config.get("enabled", False), default=False),
        "headless": _coerce_bool(config.get("headless", True), default=True),
        "fallback_headed": _coerce_bool(
            config.get(
                "fallback_headed",
                config.get("browser_sentinel_fallback_headed", DEFAULT_BROWSER_SENTINEL_FALLBACK_HEADED),
            ),
            default=DEFAULT_BROWSER_SENTINEL_FALLBACK_HEADED,
        ),
        "timeout_seconds": timeout_seconds,
        "max_concurrency": max_concurrency,
        "page_url": page_url,
        "fingerprint_scope": normalize_profile_scope(
            config.get(
                "fingerprint_scope",
                config.get("browser_sentinel_fingerprint_scope", DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
            )
        ),
        "fingerprint_engine": fingerprint_engine,
    }


def _browser_sentinel_semaphore(max_concurrency: int) -> threading.BoundedSemaphore:
    limit = max(1, min(int(max_concurrency or DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY), MAX_BROWSER_SENTINEL_CONCURRENCY))
    with _BROWSER_SENTINEL_SEMAPHORE_LOCK:
        semaphore = _BROWSER_SENTINEL_SEMAPHORES.get(limit)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(limit)
            _BROWSER_SENTINEL_SEMAPHORES[limit] = semaphore
        return semaphore


def _normalize_browser_entry_config(raw_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    config = raw_config if isinstance(raw_config, dict) else {}
    try:
        timeout_seconds = int(config.get("browser_entry_timeout_seconds", config.get("timeout_seconds", 180)))
    except (TypeError, ValueError):
        timeout_seconds = 180
    timeout_seconds = max(15, min(timeout_seconds, 300))
    return {
        "enabled": _coerce_bool(config.get("browser_entry_enabled", config.get("enabled", True)), default=True),
        "headless": _coerce_bool(config.get("browser_entry_headless", config.get("headless", False)), default=False),
        "timeout_seconds": timeout_seconds,
    }


def _response_header_value(response: Any, key: str) -> str:
    headers = getattr(response, "headers", {}) or {}
    if hasattr(headers, "get"):
        value = headers.get(key)
        if value is None:
            value = headers.get(key.lower())
        if value is None:
            value = headers.get(key.title())
        return str(value or "").strip()
    try:
        for header_key, header_value in dict(headers).items():
            if str(header_key or "").strip().lower() == str(key or "").strip().lower():
                return str(header_value or "").strip()
    except Exception:
        pass
    return ""


def _looks_like_cloudflare_challenge_response(response: Any) -> bool:
    status_code = int(getattr(response, "status_code", 0) or 0)
    body_text = str(getattr(response, "text", "") or "").strip().lower()
    title_markers = (
        "just a moment",
        "performing security verification",
    )
    body_markers = (
        "cf-turnstile",
        "cf_chl",
        "challenge-platform",
        "/cdn-cgi/challenge-platform",
        "security verification",
    )
    server = _response_header_value(response, "server").lower()
    mitigated = _response_header_value(response, "cf-mitigated").lower()
    if "cloudflare" in server and mitigated == "challenge":
        return True
    if status_code == 403 and "cloudflare" in server:
        return any(marker in body_text for marker in (*title_markers, *body_markers))
    return False


def _merge_browser_cookies_into_session(session: Any, cookies: Any) -> None:
    try:
        iterable = list(cookies or [])
    except Exception:
        iterable = []
    for cookie in iterable:
        if not isinstance(cookie, dict):
            continue
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        value = str(cookie.get("value") or "").strip()
        domain = str(cookie.get("domain") or "").strip() or None
        path = str(cookie.get("path") or "").strip() or "/"
        try:
            session.cookies.set(name, value, domain=domain, path=path)  # type: ignore[attr-defined]
        except Exception:
            try:
                session.cookies.set(name, value)  # type: ignore[attr-defined]
            except Exception:
                pass


def _resolve_session_profile(
    *,
    session_profile: Optional[SessionProfile],
    user_agent: str = "",
    scope: str = "auto_desktop",
) -> SessionProfile:
    supplied_user_agent = str(user_agent or "").strip()
    if session_profile is None:
        return create_session_profile(scope=scope, user_agent=supplied_user_agent)

    session_profile.validate()
    if supplied_user_agent and supplied_user_agent != session_profile.user_agent:
        raise ValueError("user_agent does not match the supplied SessionProfile")
    return session_profile


def _sentinel_local_timestamp(
    session_profile: SessionProfile,
    *,
    instant: Optional[datetime] = None,
) -> str:
    return chromium_local_timestamp(
        locale=session_profile.locale,
        timezone_id=session_profile.timezone_id,
        instant=instant,
    )


def _build_sentinel_identity_config(
    session_profile: SessionProfile,
    *,
    session_id: str,
) -> list[Any]:
    session_profile.validate()
    perf = random.uniform(1000, 50000)
    screen = session_profile.screen
    languages = session_profile.navigator.get("languages") or (session_profile.locale,)
    language_text = ",".join(str(language) for language in languages if str(language))
    return [
        f"{int(screen['width'])}x{int(screen['height'])}",
        _sentinel_local_timestamp(session_profile),
        4294705152,
        random.random(),
        session_profile.user_agent,
        "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
        None,
        None,
        session_profile.locale,
        language_text,
        random.random(),
        random.choice(["vendorSub", "productSub", "cookieEnabled"]) + "-undefined",
        random.choice(["location", "URL", "compatMode"]),
        random.choice(["Object", "Function", "Array", "Number"]),
        perf,
        session_id,
        "",
        int(session_profile.navigator["hardware_concurrency"]),
        time.time() * 1000 - perf,
    ]


def _warmup_auth_entry_with_browser(
    *,
    target_url: str,
    session: Any,
    emitter: EventEmitter,
    step: str,
    browser_entry_config: Optional[Dict[str, Any]],
    proxy: Optional[str],
    user_agent: str,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    config = _normalize_browser_entry_config(browser_entry_config)
    if not config["enabled"]:
        emitter.error(
            f"检测到 Cloudflare challenge（{step}），请开启浏览器入口验证模式后重试",
            step=step,
        )
        return None

    emitter.warn("检测到 Cloudflare challenge，切换浏览器入口验证...", step=step)
    try:
        from .browser_entry_warmup import warmup_auth_entry_in_browser
    except Exception as exc:
        emitter.error(f"浏览器入口验证模块不可用: {exc}", step=step)
        return None

    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
    )
    result = warmup_auth_entry_in_browser(
        start_url=target_url,
        cookies=getattr(session, "cookies", None),
        headless=bool(config["headless"]),
        timeout_seconds=int(config["timeout_seconds"]),
        proxy=proxy,
        user_agent=profile.user_agent,
        session_profile=profile,
    )
    if not result.get("ok") or not result.get("challenge_cleared"):
        error_text = str(result.get("error") or "browser entry verification failed").strip()
        body_excerpt = str(result.get("body_excerpt") or "").strip()
        if body_excerpt:
            error_text = f"{error_text}: {body_excerpt[:180]}"
        emitter.error(f"浏览器入口验证失败: {error_text}", step=step)
        return None

    _merge_browser_cookies_into_session(session, result.get("cookies"))
    final_url = str(result.get("final_url") or target_url).strip() or str(target_url or "").strip()
    emitter.success(f"浏览器入口验证通过: {final_url[:140]}", step=step)
    return final_url


def _load_browser_register_flow_class():
    try:
        from .browser_register_flow import PlaywrightBrowserFlow  # type: ignore
        return PlaywrightBrowserFlow
    except Exception:
        pass

    try:
        from importlib.machinery import SourcelessFileLoader
        from importlib.util import module_from_spec, spec_from_loader
        pyc_path = PACKAGE_DIR / "__pycache__" / f"browser_register_flow.cpython-{sys.version_info.major}{sys.version_info.minor}.pyc"
        if not pyc_path.exists():
            pyc_candidates = sorted((PACKAGE_DIR / "__pycache__").glob("browser_register_flow.cpython-*.pyc"))
            pyc_path = pyc_candidates[-1] if pyc_candidates else pyc_path
        if not pyc_path.exists():
            raise FileNotFoundError("browser_register_flow pyc not found")
        cached_module_name = f"{__package__}.browser_register_flow_cached"
        loader = SourcelessFileLoader(cached_module_name, str(pyc_path))
        spec = spec_from_loader(cached_module_name, loader)
        if spec is None:
            raise RuntimeError("failed to build browser register flow spec")
        module = module_from_spec(spec)
        loader.exec_module(module)
        cls = getattr(module, "PlaywrightBrowserFlow", None)
        if cls is None:
            raise RuntimeError("PlaywrightBrowserFlow missing in cached module")
        return cls
    except Exception as exc:
        raise RuntimeError(f"failed to load browser register flow: {exc}") from exc


def _run_browser_full_registration_flow(
    *,
    email: str,
    account_password: str,
    mail_provider: Any,
    mail_auth_credential: str,
    emitter: EventEmitter,
    stop_event: Any,
    proxy: Optional[str],
    user_agent: str,
    browser_entry_config: Optional[Dict[str, Any]],
    browser_sentinel_config: Optional[Dict[str, Any]],
    mail_provider_name: str,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    browser_entry_cfg = _normalize_browser_entry_config(browser_entry_config)
    if not browser_entry_cfg["enabled"]:
        return None

    sentinel_cfg = _normalize_browser_sentinel_config(browser_sentinel_config)
    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        scope=str(sentinel_cfg.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
    )
    FlowClass = _load_browser_register_flow_class()
    flow_kwargs = {
        "config": {
            "headless": bool(browser_entry_cfg["headless"]),
            "timeout_seconds": int(browser_entry_cfg["timeout_seconds"]),
            "sentinel_page_url": str(
                sentinel_cfg.get("page_url") or DEFAULT_BROWSER_SENTINEL_PAGE_URL
            ),
        },
        "proxy": proxy,
        "user_agent": profile.user_agent,
        "emitter": emitter,
    }
    try:
        flow = FlowClass(**flow_kwargs, session_profile=profile)
    except TypeError as exc:
        if "session_profile" not in str(exc):
            raise
        raise RuntimeError(
            "browser registration flow does not support SessionProfile; "
            "remove stale __pycache__ artifacts and retry"
        ) from exc
    codex_oauth = generate_oauth_url()
    browser_result = flow.run_registration_and_oauth(
        email=email,
        account_password=account_password,
        mail_provider=mail_provider,
        mail_auth_credential=mail_auth_credential,
        codex_auth_url=codex_oauth.auth_url,
        random_profile=_generate_random_profile(),
        stop_event=stop_event,
        signup_flow_candidates=AUTHORIZE_CONTINUE_SENTINEL_FLOWS,
        register_flow_candidates=REGISTER_SENTINEL_FLOWS,
        email_verification_flow_candidates=EMAIL_VERIFICATION_SENTINEL_FLOWS,
        create_account_flow_candidates=CREATE_ACCOUNT_SENTINEL_FLOWS,
        password_verify_flow_candidates=PASSWORD_VERIFY_SENTINEL_FLOWS,
    )
    if not isinstance(browser_result, dict) or not browser_result:
        return None

    callback_url = str(browser_result.get("callback_url") or "").strip()
    consent_url = str(browser_result.get("consent_url") or "").strip()
    cookies = browser_result.get("cookies")
    session_token_data = (
        browser_result.get("session_token_data")
        if isinstance(browser_result.get("session_token_data"), dict)
        else None
    )
    mailbox_context = _build_mailbox_context(email=email, auth_credential=mail_auth_credential)

    if callback_url:
        try:
            return submit_callback_url(
                callback_url=callback_url,
                expected_state=codex_oauth.state,
                code_verifier=codex_oauth.code_verifier,
                redirect_uri=codex_oauth.redirect_uri,
                proxy=str(proxy or "").strip(),
            )
        except Exception as exc:
            emitter.warn(f"浏览器全流程 callback exchange 失败，尝试 consent cookie exchange: {exc}", step="get_token")

    browser_session = requests.Session(
        impersonate=profile.impersonate,
        proxy=(str(proxy or "").strip() or None),
    )
    browser_session.headers.update(dict(profile.http_headers))
    try:
        _merge_browser_cookies_into_session(browser_session, cookies)
        if consent_url:
            token_data = exchange_codex_tokens_from_session(
                browser_session,
                consent_url=consent_url,
                oauth_issuer="https://auth.openai.com",
                oauth_client_id=codex_oauth.client_id,
                oauth_redirect_uri=codex_oauth.redirect_uri,
                code_verifier=codex_oauth.code_verifier,
                account_password=account_password,
                mail_provider=mail_provider_name,
                mailbox=mailbox_context,
                device_id=str(browser_result.get("device_id") or "").strip(),
            )
            if isinstance(token_data, dict) and token_data:
                return json.dumps(token_data, ensure_ascii=False, separators=(",", ":"))
    finally:
        try:
            browser_session.close()
        except Exception:
            pass

    if isinstance(session_token_data, dict) and session_token_data:
        fallback_data = _mark_token_payload_session_only(
            dict(session_token_data),
            reason="browser_full_flow_session_only",
            token_source=str(session_token_data.get("token_source") or "chatgpt_session"),
        )
        fallback_data["account_password"] = account_password
        fallback_data["password"] = account_password
        fallback_data["mail_provider"] = mail_provider_name
        if mailbox_context:
            fallback_data["mailbox"] = mailbox_context
        return json.dumps(fallback_data, ensure_ascii=False, separators=(",", ":"))
    return None


def _fallback_on_chatgpt_csrf_failure(
    *,
    csrf_response: Any,
    email: str,
    account_password: str,
    mail_provider: Any,
    mail_auth_credential: str,
    emitter: EventEmitter,
    stop_event: Any,
    proxy: Optional[str],
    user_agent: str,
    browser_entry_config: Optional[Dict[str, Any]],
    browser_sentinel_config: Optional[Dict[str, Any]],
    mail_provider_name: str,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    if _looks_like_cloudflare_challenge_response(csrf_response):
        emitter.warn("ChatGPT CSRF 命中 Cloudflare challenge，切换浏览器全流程注册...", step="oauth_init")
    else:
        emitter.warn("ChatGPT CSRF Token 缺失，切换浏览器全流程注册...", step="oauth_init")
    return _run_browser_full_registration_flow(
        email=email,
        account_password=account_password,
        mail_provider=mail_provider,
        mail_auth_credential=mail_auth_credential,
        emitter=emitter,
        stop_event=stop_event,
        proxy=proxy,
        user_agent=user_agent,
        browser_entry_config=browser_entry_config,
        browser_sentinel_config=browser_sentinel_config,
        mail_provider_name=mail_provider_name,
        session_profile=session_profile,
    )


def _get_browser_sentinel_token_for_create_account(
    *,
    browser_sentinel_config: Optional[Dict[str, Any]],
    proxy: Optional[str],
    user_agent: str,
    session_profile: Optional[SessionProfile] = None,
) -> str:
    config = _normalize_browser_sentinel_config(browser_sentinel_config)
    if not config["enabled"]:
        return ""
    try:
        from .sentinel_browser import get_browser_sentinel_token_for_create_account
    except Exception as exc:
        raise RuntimeError(f"failed to import browser sentinel helper: {exc}") from exc

    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
    )
    semaphore = _browser_sentinel_semaphore(int(config.get("max_concurrency") or DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY))
    semaphore.acquire()
    try:
        token = get_browser_sentinel_token_for_create_account(
            page_url=str(config["page_url"]),
            headless=bool(config["headless"]),
            timeout_seconds=int(config["timeout_seconds"]),
            proxy=proxy,
            user_agent=profile.user_agent,
            fingerprint_scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
            fingerprint_engine=str(config.get("fingerprint_engine") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE),
            session_profile=profile,
        )
    finally:
        semaphore.release()
    normalized_token = str(token or "").strip()
    if not normalized_token:
        raise RuntimeError("empty browser sentinel token")
    return normalized_token


def _get_browser_sentinel_bundle_for_create_account(
    *,
    browser_sentinel_config: Optional[Dict[str, Any]],
    proxy: Optional[str],
    user_agent: str,
    session_profile: Optional[SessionProfile] = None,
) -> Dict[str, Any]:
    config = _normalize_browser_sentinel_config(browser_sentinel_config)
    if not config["enabled"]:
        return {}
    try:
        from .sentinel_browser import get_browser_sentinel_bundle_for_create_account
    except Exception as exc:
        raise RuntimeError(f"failed to import browser sentinel helper: {exc}") from exc

    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
    )
    semaphore = _browser_sentinel_semaphore(int(config.get("max_concurrency") or DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY))
    semaphore.acquire()
    try:
        bundle = get_browser_sentinel_bundle_for_create_account(
            page_url=str(config["page_url"]),
            headless=bool(config["headless"]),
            timeout_seconds=int(config["timeout_seconds"]),
            proxy=proxy,
            user_agent=profile.user_agent,
            fingerprint_scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
            fingerprint_engine=str(config.get("fingerprint_engine") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE),
            session_profile=profile,
        )
    finally:
        semaphore.release()
    return bundle if isinstance(bundle, dict) else {}


def _get_browser_sentinel_token_for_signup(
    *,
    browser_sentinel_config: Optional[Dict[str, Any]],
    proxy: Optional[str],
    user_agent: str,
    session_profile: Optional[SessionProfile] = None,
) -> str:
    config = _normalize_browser_sentinel_config(browser_sentinel_config)
    if not config["enabled"]:
        return ""
    try:
        from .sentinel_browser import get_browser_sentinel_token_for_create_account
    except Exception as exc:
        raise RuntimeError(f"failed to import browser sentinel helper: {exc}") from exc

    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
    )
    semaphore = _browser_sentinel_semaphore(int(config.get("max_concurrency") or DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY))
    semaphore.acquire()
    try:
        token = get_browser_sentinel_token_for_create_account(
            page_url=str(config["page_url"]),
            headless=bool(config["headless"]),
            timeout_seconds=int(config["timeout_seconds"]),
            proxy=proxy,
            user_agent=profile.user_agent,
            flow_candidates=REGISTER_SENTINEL_FLOWS,
            fingerprint_scope=str(config.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
            fingerprint_engine=str(config.get("fingerprint_engine") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE),
            session_profile=profile,
        )
    finally:
        semaphore.release()
    normalized_token = str(token or "").strip()
    if not normalized_token:
        raise RuntimeError("empty browser sentinel token")
    return normalized_token


def _looks_deactivated_error(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in DEACTIVATED_MARKERS)


def _looks_wrong_otp_error(status_code: int, text: Any) -> bool:
    if int(status_code or 0) not in (400, 401, 422):
        return False
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    return any(
        marker in lowered
        for marker in (
            "wrong_email_otp_code",
            "wrong code",
            "incorrect code",
            "invalid code",
            "验证码错误",
            "验证码不正确",
        )
    )


def _is_transient_tls_error(exc: Exception | str) -> bool:
    message = str(exc or "").lower()
    return any(str(hint or "").lower() in message for hint in TRANSIENT_TLS_ERROR_HINTS)


def _copy_session_cookies(source_session: Any, target_session: Any) -> None:
    source_cookies = getattr(source_session, "cookies", None)
    target_cookies = getattr(target_session, "cookies", None)
    if source_cookies is None or target_cookies is None:
        return
    try:
        for cookie in source_cookies:
            try:
                target_cookies.set(
                    cookie.name,
                    cookie.value,
                    domain=getattr(cookie, "domain", None),
                    path=getattr(cookie, "path", None),
                )
            except Exception:
                target_cookies.set(cookie.name, cookie.value)
    except Exception:
        try:
            for name, value in dict(source_cookies).items():
                target_cookies.set(name, value)
        except Exception:
            return


def _choose_tls_recovery_impersonate(current_impersonate: str) -> str:
    return str(current_impersonate or "").strip().lower() or "chrome145"


def _call_with_http_fallback(
    request_func,
    url: str,
    *,
    recover_request_func_factory: Optional[Callable[[], Callable[..., Any]]] = None,
    **kwargs: Any,
):
    """
    curl_cffi 在某些站点可能优先尝试 H3，遇到 HTTP 代理不支持时自动降级到 HTTP/1.1 重试。
    对 curl TLS 握手异常（如 curl: (35)）也进行有限重试，并优先降级到 HTTP/1.1。
    """
    try:
        return request_func(url, **kwargs)
    except Exception as exc:
        message = str(exc)
        if H3_PROXY_ERROR_HINT in message:
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            return request_func(url, **retry_kwargs)
        if not _is_transient_tls_error(message):
            raise

        last_exc: Exception = exc
        candidate_kwargs_list = [dict(kwargs)]
        if str(kwargs.get("http_version") or "").strip().lower() != "v1":
            retry_kwargs = dict(kwargs)
            retry_kwargs["http_version"] = "v1"
            candidate_kwargs_list.append(retry_kwargs)

        for candidate_kwargs in candidate_kwargs_list:
            for attempt in range(TRANSIENT_TLS_RETRY_COUNT):
                time.sleep(min(0.175 * (attempt + 1), 0.5))
                try:
                    return request_func(url, **candidate_kwargs)
                except Exception as retry_exc:
                    last_exc = retry_exc
                    retry_message = str(retry_exc)
                    if H3_PROXY_ERROR_HINT in retry_message and str(candidate_kwargs.get("http_version") or "").strip().lower() != "v1":
                        candidate_kwargs = dict(candidate_kwargs)
                        candidate_kwargs["http_version"] = "v1"
                        continue
                    if not _is_transient_tls_error(retry_message):
                        raise

        if recover_request_func_factory is not None:
            recovered_request_func = recover_request_func_factory()
            for candidate_kwargs in candidate_kwargs_list:
                try:
                    return recovered_request_func(url, **candidate_kwargs)
                except Exception as recovery_exc:
                    last_exc = recovery_exc
                    recovery_message = str(recovery_exc)
                    if H3_PROXY_ERROR_HINT in recovery_message and str(candidate_kwargs.get("http_version") or "").strip().lower() != "v1":
                        continue
                    if not _is_transient_tls_error(recovery_message):
                        raise
        raise last_exc

def _normalize_proxy_value(proxy_value: Any) -> str:
    value = str(proxy_value or "").strip().strip('"').strip("'")
    if not value:
        return ""
    if value.startswith("{") or value.startswith("[") or value.startswith("<"):
        return ""
    if "://" in value:
        return value
    if ":" not in value:
        return ""
    return f"http://{value}"


def _to_proxies_dict(proxy_value: str) -> Optional[Dict[str, str]]:
    normalized = _normalize_proxy_value(proxy_value)
    if not normalized:
        return None
    return {"http": normalized, "https": normalized}


def _build_proxy_from_host_port(host: Any, port: Any, proxy_type: Any = "") -> str:
    host_value = str(host or "").strip()
    port_value = str(port or "").strip()
    if not host_value or not port_value:
        return ""
    proxy_type_value = str(proxy_type or "").strip().lower()
    if proxy_type_value in ("socks5", "socks", "shadowsocks"):
        return _normalize_proxy_value(f"socks5://{host_value}:{port_value}")
    return _normalize_proxy_value(f"http://{host_value}:{port_value}")


def _pool_host_from_api_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        return str(parsed.hostname or "").strip()
    except Exception:
        return ""


def _pool_relay_url_from_fetch_url(api_url: str) -> str:
    raw = str(api_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        if not netloc:
            return ""
        return f"{scheme}://{netloc}/api/relay"
    except Exception:
        return ""


def _trace_via_pool_relay(pool_cfg: Dict[str, Any]) -> str:
    relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    if not relay_url:
        raise RuntimeError("代理池 relay 地址解析失败")

    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(8, min(timeout, 30))

    params = {
        "api_key": api_key,
        "url": "https://cloudflare.com/cdn-cgi/trace",
        "country": country,
    }
    retry_count = max(1, int(pool_cfg.get("relay_retries") or POOL_RELAY_RETRIES))
    last_error = ""
    for i in range(retry_count):
        try:
            resp = _call_with_http_fallback(
                requests.get,
                relay_url,
                params=params,
                impersonate="chrome145",
                timeout=timeout,
            )
            if resp.status_code == 200:
                return str(resp.text or "")
            last_error = f"HTTP {resp.status_code}"
        except Exception as exc:
            last_error = str(exc)
        if i < retry_count - 1:
            time.sleep(min(0.15 * (i + 1), 0.5))
    raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")
def _extract_proxy_from_obj(obj: Any, relay_host: str = "") -> str:
    if isinstance(obj, str):
        return _normalize_proxy_value(obj)
    if isinstance(obj, (list, tuple)):
        for item in obj:
            proxy = _extract_proxy_from_obj(item, relay_host)
            if proxy:
                return proxy
        return ""
    if isinstance(obj, dict):
        local_port = obj.get("local_port")
        if local_port in (None, ""):
            local_port = obj.get("localPort")
        if local_port not in (None, ""):
            # ZenProxy 文档中的 local_port 是代理绑定端口，优先使用 api_url 主机名。
            if relay_host:
                proxy = _normalize_proxy_value(f"http://{relay_host}:{local_port}")
                if proxy:
                    return proxy
            proxy = _normalize_proxy_value(f"http://127.0.0.1:{local_port}")
            if proxy:
                return proxy

        host = str(obj.get("ip") or obj.get("host") or obj.get("server") or "").strip()
        port = str(obj.get("port") or "").strip()
        proxy_type = obj.get("type") or obj.get("protocol") or obj.get("scheme") or ""
        if host and port:
            proxy = _build_proxy_from_host_port(host, port, proxy_type)
            if proxy:
                return proxy

        for key in ("proxy", "proxy_url", "url", "value", "result", "data", "proxy_list", "list", "proxies"):
            if key in obj:
                proxy = _extract_proxy_from_obj(obj.get(key), relay_host)
                if proxy:
                    return proxy

        for value in obj.values():
            proxy = _extract_proxy_from_obj(value, relay_host)
            if proxy:
                return proxy
    return ""


def _looks_rate_limited_text(body_text: Any) -> bool:
    text = str(body_text or "").strip().lower()
    return "rate limit exceeded" in text or "please try again later" in text


def _looks_invalid_state_text(body_text: Any) -> bool:
    text = str(body_text or "").strip().lower()
    if not text:
        return False
    markers = (
        "invalid_state",
        "invalid client. please start over.",
        "invalid session. please start over.",
    )
    return any(marker in text for marker in markers)


def _looks_expired_signin_session_text(body_text: Any) -> bool:
    text = str(body_text or "").strip().lower()
    if not text:
        return False
    markers = (
        "your sign-in session is no longer valid",
        "please start over to continue",
        "sign-in session is no longer valid",
    )
    return any(marker in text for marker in markers)


def _is_expired_signin_session_response(status_code: int, body_text: Any) -> bool:
    status = int(status_code or 0)
    return status >= 400 and _looks_expired_signin_session_text(body_text)


def _proxy_tcp_reachable(proxy_url: str, timeout_seconds: float = 1.2) -> bool:
    value = str(proxy_url or "").strip()
    if not value:
        return False
    if "://" not in value:
        value = "http://" + value
    try:
        parsed = urlparse(value)
        host = str(parsed.hostname or "").strip()
        port = int(parsed.port or 0)
    except Exception:
        return False
    if not host or port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def _fetch_proxy_from_pool(pool_cfg: Dict[str, Any]) -> str:
    enabled = bool(pool_cfg.get("enabled"))
    if not enabled:
        return ""

    api_url = str(pool_cfg.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL
    auth_mode = str(pool_cfg.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower()
    if auth_mode not in ("header", "query"):
        auth_mode = DEFAULT_PROXY_POOL_AUTH_MODE
    api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    relay_host = str(pool_cfg.get("relay_host") or "").strip()
    if not relay_host:
        relay_host = _pool_host_from_api_url(api_url)
    try:
        count = int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT)
    except (TypeError, ValueError):
        count = DEFAULT_PROXY_POOL_COUNT
    count = max(1, min(count, 20))
    country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    timeout = int(pool_cfg.get("timeout_seconds") or 10)
    timeout = max(3, min(timeout, 30))

    headers: Dict[str, str] = {}
    params: Dict[str, str] = {"count": str(count), "country": country}
    if auth_mode == "query":
        params["api_key"] = api_key
    else:
        headers["Authorization"] = f"Bearer {api_key}"

    resp = _call_with_http_fallback(
        requests.get,
        api_url,
        headers=headers or None,
        params=params or None,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate="chrome145",
        timeout=timeout,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"代理池请求失败: HTTP {resp.status_code}")

    proxy = ""
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            proxies = payload.get("proxies")
            if isinstance(proxies, list):
                for item in proxies:
                    proxy = _extract_proxy_from_obj(item, relay_host)
                    if proxy:
                        break
        if not proxy:
            proxy = _extract_proxy_from_obj(payload, relay_host)
    except Exception:
        proxy = ""

    if not proxy:
        proxy = _normalize_proxy_value(resp.text)
    if not proxy:
        raise RuntimeError("代理池响应中未找到可用代理")
    return proxy


def _resolve_request_proxies(
    default_proxies: Any = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> Any:
    if not proxy_selector:
        return default_proxies
    try:
        selected = proxy_selector()
        if selected is not None:
            return selected
    except Exception:
        pass
    return default_proxies


def _mailtm_headers(*, token: str = "", use_json: bool = False) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if use_json:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mailtm_domains(proxies: Any = None) -> list[str]:
    resp = _call_with_http_fallback(
        requests.get,
        f"{MAILTM_BASE}/domains",
        headers=_mailtm_headers(),
        proxies=proxies,
        http_version=DEFAULT_HTTP_VERSION,
        impersonate="chrome145",
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"获取 Mail.tm 域名失败，状态码: {resp.status_code}")

    data = resp.json()
    domains = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("hydra:member") or data.get("items") or []
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        domain = str(item.get("domain") or "").strip()
        is_active = item.get("isActive", True)
        is_private = item.get("isPrivate", False)
        if domain and is_active and not is_private:
            domains.append(domain)

    return domains


def get_email_and_token(
    proxies: Any = None,
    emitter: EventEmitter = _cli_emitter,
    proxy_selector: Optional[Callable[[], Any]] = None,
) -> tuple[str, str]:
    """创建 Mail.tm 邮箱并获取 Bearer Token"""
    try:
        domains = _mailtm_domains(_resolve_request_proxies(proxies, proxy_selector))
        if not domains:
            emitter.error("Mail.tm 没有可用域名", step="create_email")
            return "", ""
        domain = random.choice(domains)

        for _ in range(5):
            local = f"oc{secrets.token_hex(5)}"
            email = f"{local}@{domain}"
            password = secrets.token_urlsafe(18)

            create_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/accounts",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome145",
                timeout=15,
            )

            if create_resp.status_code not in (200, 201):
                continue

            token_resp = _call_with_http_fallback(
                requests.post,
                f"{MAILTM_BASE}/token",
                headers=_mailtm_headers(use_json=True),
                json={"address": email, "password": password},
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome145",
                timeout=15,
            )

            if token_resp.status_code == 200:
                token = str(token_resp.json().get("token") or "").strip()
                if token:
                    return email, token

        emitter.error("Mail.tm 邮箱创建成功但获取 Token 失败", step="create_email")
        return "", ""
    except Exception as e:
        emitter.error(f"请求 Mail.tm API 出错: {e}", step="create_email")
        return "", ""


def _mailtm_message_timestamp_seconds(message: Any) -> Optional[float]:
    if not isinstance(message, dict):
        return None
    for key in (
        "createdAt",
        "created_at",
        "updatedAt",
        "updated_at",
        "receivedAt",
        "received_at",
        "date",
        "timestamp",
    ):
        value = message.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)):
            numeric = float(value)
            return numeric / 1000.0 if numeric > 10_000_000_000 else numeric
        parsed = _parse_rfc3339_timestamp(value)
        if parsed:
            return float(parsed)
    return None


def get_oai_code(
    token: str, email: str, proxies: Any = None, emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    proxy_selector: Optional[Callable[[], Any]] = None,
    timeout: int = OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS,
    sent_at_ts: Optional[float] = None,
    exclude_codes: Optional[set[str]] = None,
) -> str:
    """使用 Mail.tm Token 轮询获取 OpenAI 验证码"""
    url_list = f"{MAILTM_BASE}/messages"
    regex = r"(?<!\d)(\d{6})(?!\d)"
    seen_ids: set[str] = set()
    excluded = {str(code or "").strip() for code in (exclude_codes or set()) if str(code or "").strip()}
    wait_started_at = time.time()
    deadline = wait_started_at + max(1, int(timeout or OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS))
    lower_bound = max(0.0, float(sent_at_ts or 0.0) - 2.0) if sent_at_ts else 0.0
    progress_bucket = 0

    emitter.info(f"正在等待邮箱 {email} 的验证码...", step="wait_otp")

    while time.time() < deadline:
        if stop_event and stop_event.is_set():
            return ""
        try:
            resp = _call_with_http_fallback(
                requests.get,
                url_list,
                headers=_mailtm_headers(token=token),
                proxies=_resolve_request_proxies(proxies, proxy_selector),
                http_version=DEFAULT_HTTP_VERSION,
                impersonate="chrome145",
                timeout=15,
            )
            if resp.status_code != 200:
                _otp_poll_wait(stop_event)
                continue

            data = resp.json()
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("hydra:member") or data.get("messages") or []
            else:
                messages = []

            messages = sorted(
                messages,
                key=lambda item: _mailtm_message_timestamp_seconds(item) or 0.0,
                reverse=True,
            )
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "").strip()
                if not msg_id or msg_id in seen_ids:
                    continue
                summary_ts = _mailtm_message_timestamp_seconds(msg)
                if lower_bound and summary_ts is not None and summary_ts < lower_bound:
                    seen_ids.add(msg_id)
                    continue

                read_resp = _call_with_http_fallback(
                    requests.get,
                    f"{MAILTM_BASE}/messages/{msg_id}",
                    headers=_mailtm_headers(token=token),
                    proxies=_resolve_request_proxies(proxies, proxy_selector),
                    http_version=DEFAULT_HTTP_VERSION,
                    impersonate="chrome145",
                    timeout=15,
                )
                if read_resp.status_code != 200:
                    continue
                seen_ids.add(msg_id)

                mail_data = read_resp.json()
                mail_ts = _mailtm_message_timestamp_seconds(mail_data)
                effective_ts = mail_ts if mail_ts is not None else summary_ts
                if lower_bound and effective_ts is not None and effective_ts < lower_bound:
                    continue
                sender = str(
                    ((mail_data.get("from") or {}).get("address") or "")
                ).lower()
                subject = str(mail_data.get("subject") or "")
                intro = str(mail_data.get("intro") or "")
                text = str(mail_data.get("text") or "")
                html = mail_data.get("html") or ""
                if isinstance(html, list):
                    html = "\n".join(str(x) for x in html)
                content = "\n".join([subject, intro, text, str(html)])

                if "openai" not in sender and "openai" not in content.lower():
                    continue

                m = re.search(regex, content)
                if m:
                    code = m.group(1)
                    if code in excluded:
                        break
                    emitter.success(f"验证码已到达: {code}", step="wait_otp")
                    return code
        except Exception:
            pass

        waited_seconds = int(max(0, time.time() - wait_started_at))
        next_bucket = waited_seconds // 5
        if next_bucket > progress_bucket:
            progress_bucket = next_bucket
            emitter.info(f"已等待 {waited_seconds} 秒，继续轮询...", step="wait_otp")
        _otp_poll_wait(stop_event)

    return ""


# ==========================================
# OAuth 授权与辅助函数
# ==========================================

AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    return secrets.token_urlsafe(64)


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _post_form(
    url: str,
    data: Dict[str, str],
    timeout: int = 30,
    proxy: str = "",
) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    handlers = []
    normalized_proxy = _normalize_proxy_value(proxy)
    if normalized_proxy:
        handlers.append(urllib.request.ProxyHandler({"http": normalized_proxy, "https": normalized_proxy}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


def _infer_mail_provider_name(mail_provider: Any) -> str:
    if mail_provider is None:
        return "mailtm"
    class_name = type(mail_provider).__name__.strip().lower()
    if "mailtm" in class_name:
        return "mailtm"
    if "moemail" in class_name:
        return "moemail"
    if "duckmail" in class_name:
        return "duckmail"
    if "cloudflare" in class_name:
        return "cloudflare_temp_email"
    return ""


def _sanitize_mailbox_context(mailbox: Any) -> Optional[Dict[str, str]]:
    if not isinstance(mailbox, dict):
        return None
    email = str(mailbox.get("email") or "").strip()
    auth_credential = str(mailbox.get("auth_credential") or "").strip()
    if not email or not auth_credential:
        return None
    return {
        "email": email,
        "auth_credential": auth_credential,
    }


def _build_mailbox_context(email: str, auth_credential: str) -> Optional[Dict[str, str]]:
    email_value = str(email or "").strip()
    credential_value = str(auth_credential or "").strip()
    if not email_value or not credential_value:
        return None
    return {
        "email": email_value,
        "auth_credential": credential_value,
    }


def _extract_response_url_candidate(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("continue_url", "url", "redirect_url", "callback_url"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return ""


def _looks_like_chatgpt_callback_path(target_url: Any) -> bool:
    path = str(urlparse(str(target_url or "")).path or "").strip().lower()
    return path.startswith("/callback") or path.startswith("/api/auth/")


def _normalize_post_create_url(target_url: Any, chatgpt_base: str) -> str:
    text = str(target_url or "").strip()
    if not text:
        return ""
    if not text.startswith("/"):
        return text
    if _looks_like_chatgpt_callback_path(text):
        return urllib.parse.urljoin(str(chatgpt_base or "https://chatgpt.com").rstrip("/") + "/", text)
    return urllib.parse.urljoin("https://auth.openai.com", text)


def _extract_post_create_url(payload: Any, chatgpt_base: str) -> str:
    return _normalize_post_create_url(_extract_response_url_candidate(payload), chatgpt_base)


def _extract_page_type(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    page = payload.get("page") or {}
    if not isinstance(page, dict):
        return ""
    return str(page.get("type") or "").strip().lower()


def _requires_phone_verification(
    payload: Any = None,
    response_text: Any = "",
    target_url: Any = "",
) -> bool:
    page_type = _extract_page_type(payload)
    candidate_url = str(
        _extract_response_url_candidate(payload) or target_url or ""
    ).strip().lower()
    body_text = str(response_text or "").strip().lower()
    if any(marker == page_type for marker in PHONE_GATE_MARKERS):
        return True
    haystacks = (candidate_url, body_text)
    return any(marker in haystack for marker in PHONE_GATE_MARKERS for haystack in haystacks if haystack)


def _is_about_you_step(payload: Any = None, target_url: Any = "") -> bool:
    page_type = _extract_page_type(payload)
    if page_type in ABOUT_YOU_PAGE_TYPES:
        return True
    candidate_url = str(
        _extract_response_url_candidate(payload) or target_url or ""
    ).strip().lower()
    return "about-you" in candidate_url


def _phone_gate_error_message(prefix: str = "") -> str:
    base = "命中手机验证 / add-phone，按策略终止"
    return f"{prefix}{base}" if prefix else base


def _create_account_error_code(response: Any) -> str:
    try:
        payload = response.json()
    except Exception:
        payload = {}
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("code") or "").strip()
        return str(payload.get("code") or "").strip()
    return ""


def _notify_mail_provider_skip_primary(
    mail_provider: Any,
    *,
    auth_credential: str,
    email: str,
    reason: str,
) -> int:
    for method_name in ("skip_primary", "skip_primary_email", "mark_primary_skipped"):
        method = getattr(mail_provider, method_name, None)
        if not callable(method):
            continue
        try:
            removed = method(auth_credential=auth_credential, email=email, reason=reason)
        except TypeError:
            try:
                removed = method(email)
            except Exception:
                return 0
        except Exception:
            return 0
        try:
            return int(removed or 0)
        except Exception:
            return 0
    return 0


def _generate_random_profile() -> Dict[str, str]:
    first_name = random.choice([
        "James", "Emma", "Liam", "Olivia", "Noah", "Ava", "Ethan", "Sophia",
        "Lucas", "Mia", "Mason", "Isabella", "Logan", "Charlotte", "Alexander",
        "Amelia", "Benjamin", "Harper", "William", "Evelyn", "Henry", "Abigail",
    ])
    last_name = random.choice([
        "Smith", "Johnson", "Brown", "Davis", "Wilson", "Moore", "Taylor",
        "Clark", "Hall", "Young", "Anderson", "Thomas", "Jackson", "White",
    ])
    return {
        "name": f"{first_name} {last_name}",
        "birthdate": f"{random.randint(1985, 2002)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
    }


def _try_extract_chatgpt_session_token(
    *,
    continue_url: str,
    chatgpt_base: str,
    session_get: Callable[..., Any],
    emitter: EventEmitter,
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    normalized_continue_url = _normalize_post_create_url(continue_url, chatgpt_base)
    if normalized_continue_url:
        emitter.info("尝试复用当前注册会话读取 session...", step="create_account")
        try:
            session_get(
                normalized_continue_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                },
                timeout=20,
            )
        except Exception as exc:
            emitter.warn(f"预热 post-create 会话失败: {exc}", step="create_account")

    try:
        session_resp = session_get(
            f"{str(chatgpt_base or 'https://chatgpt.com').rstrip('/')}/api/auth/session",
            headers={
                "Accept": "application/json",
                "Referer": f"{str(chatgpt_base or 'https://chatgpt.com').rstrip('/')}/",
            },
            timeout=20,
        )
    except Exception as exc:
        emitter.warn(f"读取 ChatGPT session 失败: {exc}", step="create_account")
        return None

    if int(getattr(session_resp, "status_code", 0) or 0) != 200:
        return None

    try:
        session_payload = session_resp.json()
    except Exception:
        session_payload = {}
    if not isinstance(session_payload, dict):
        return None

    access_token = str(_extract_chatgpt_session_tokens(session_payload).get("access_token") or "").strip()
    if not access_token:
        return None

    try:
        token_json = _build_token_result_from_chatgpt_session(
            session_payload,
            account_password=account_password,
            mail_provider=mail_provider,
            mailbox=mailbox,
        )
    except Exception as exc:
        emitter.warn(f"构建 ChatGPT session 失败: {exc}", step="create_account")
        return None

    emitter.success("当前注册会话 session 读取成功！", step="export_session")
    return token_json


def _complete_signup_callback_before_oauth(
    *,
    callback_url: str,
    chatgpt_base: str,
    session_get: Callable[..., Any],
    emitter: EventEmitter,
    stop_event: Optional[threading.Event] = None,
    delay_seconds: int = POST_SIGNUP_CALLBACK_OAUTH_DELAY_SECONDS,
) -> bool:
    normalized_callback_url = str(callback_url or "").strip()
    if not normalized_callback_url:
        return True

    emitter.info("正在完成注册回调...", step="create_account")
    normalized_callback_url = _normalize_post_create_url(normalized_callback_url, chatgpt_base)

    callback_resp = session_get(
        normalized_callback_url,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        },
        timeout=20,
    )
    callback_final_url = str(callback_resp.url) if hasattr(callback_resp, "url") else ""
    emitter.info(
        f"注册回调结果: {(callback_final_url or normalized_callback_url or '-')[:140]}",
        step="create_account",
    )

    if stop_event is not None and stop_event.is_set():
        return False

    wait_seconds = max(0, int(delay_seconds or 0))
    if wait_seconds > 0:
        emitter.info(f"注册回调完成，等待 {wait_seconds}s 后进入 OAuth...", step="get_token")
        if stop_event is not None:
            if stop_event.wait(wait_seconds):
                return False
        else:
            time.sleep(wait_seconds)
    return True


def _finish_signup_with_fresh_oauth_login(
    *,
    email: str,
    account_password: str,
    proxy: Optional[str] = None,
    mail_provider=None,
    mail_provider_name: str = "",
    mail_auth_credential: str = "",
    emitter: Optional[EventEmitter] = None,
    stop_event: Optional[threading.Event] = None,
    session_fallback_token_data: Optional[Dict[str, Any]] = None,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    emitter = emitter or EventEmitter(cli_mode=False)
    emitter.info("正在通过独立 OAuth 登录获取 Token...", step="get_token")
    login_result = login_existing_account_for_token(
        email=email,
        account_password=account_password,
        proxy=proxy,
        mail_provider=mail_provider,
        mail_provider_name=mail_provider_name,
        mail_auth_credential=mail_auth_credential,
        emitter=emitter,
        stop_event=stop_event,
        session_profile=session_profile,
    )
    if not login_result.get("ok"):
        if isinstance(session_fallback_token_data, dict) and session_fallback_token_data:
            failure_reason = str(login_result.get("error") or "oauth_exchange_failed").strip() or "oauth_exchange_failed"
            session_only_data = _mark_token_payload_session_only(
                session_fallback_token_data,
                reason=failure_reason,
            )
            emitter.warn(
                f"OAuth 登录失败，已降级为 session-only token: {failure_reason[:180]}",
                step="get_token",
            )
            return json.dumps(session_only_data, ensure_ascii=False, separators=(",", ":"))
        emitter.error(str(login_result.get("error") or "OAuth 登录失败"), step="get_token")
        return None

    token_data = login_result.get("token_data")
    if not isinstance(token_data, dict) or not token_data:
        emitter.error("OAuth 登录成功但未返回 token_data", step="get_token")
        return None

    if bool(login_result.get("session_only")) or bool(token_data.get("session_only")):
        token_data = _mark_token_payload_session_only(
            token_data,
            reason=str(token_data.get("session_only_reason") or "missing_refresh_token"),
            token_source=str(token_data.get("token_source") or "chatgpt_session"),
        )
        emitter.warn("未获取到 refresh_token，已保存为 session-only token", step="get_token")
    else:
        emitter.success("Token 获取成功！", step="get_token")
    return json.dumps(token_data, ensure_ascii=False, separators=(",", ":"))


def _finish_signup_with_current_session_oauth_login(
    *,
    session: requests.Session,
    email: str,
    account_password: str,
    chatgpt_base: str,
    device_id: str,
    mail_provider=None,
    mail_provider_name: str = "",
    mail_auth_credential: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
    emitter: Optional[EventEmitter] = None,
    stop_event: Optional[threading.Event] = None,
    proxy: Optional[str] = None,
    session_get: Optional[Callable[..., Any]] = None,
    session_post: Optional[Callable[..., Any]] = None,
    oauth_headers_factory: Optional[Callable[[str], Dict[str, str]]] = None,
    prepare_auth_session: Optional[Callable[[], None]] = None,
    sentinel_builder: Optional[Callable[..., Optional[str]]] = None,
) -> Optional[str]:
    emitter = emitter or EventEmitter(cli_mode=False)
    get_func = session_get or getattr(session, "get", None)
    post_func = session_post or getattr(session, "post", None)
    if get_func is None or post_func is None or oauth_headers_factory is None or sentinel_builder is None:
        return None

    def _stopped() -> bool:
        return bool(stop_event is not None and stop_event.is_set())

    resolved_mail_provider_name = str(mail_provider_name or "").strip().lower()
    static_proxy = _normalize_proxy_value(proxy)
    auth_root = "https://auth.openai.com"
    default_consent_url = f"{auth_root}/sign-in-with-chatgpt/codex/consent"

    emitter.info("优先尝试复用当前注册会话换取 refresh_token...", step="get_token")

    current_session_fast_token_json = _try_extract_chatgpt_session_token(
        continue_url="",
        chatgpt_base=chatgpt_base,
        session_get=get_func,
        emitter=emitter,
        account_password=account_password,
        mail_provider=resolved_mail_provider_name,
        mailbox=mailbox,
    )
    current_session_fast_token_data: Optional[Dict[str, Any]] = None
    if current_session_fast_token_json:
        try:
            current_session_fast_token_data = json.loads(current_session_fast_token_json)
        except Exception:
            current_session_fast_token_data = None

    if prepare_auth_session is not None:
        try:
            prepare_auth_session()
        except Exception as exc:
            emitter.warn(f"当前注册会话预热失败，回退独立 OAuth: {exc}", step="get_token")
            return None

    codex_oauth = generate_oauth_url()
    try:
        get_func(codex_oauth.auth_url, timeout=30)
    except Exception as exc:
        emitter.warn(f"当前注册会话初始化 Codex OAuth 失败，回退独立 OAuth: {exc}", step="get_token")
        return None

    if _stopped():
        return None

    if _stopped():
        return None
    sentinel_token = sentinel_builder(*AUTHORIZE_CONTINUE_SENTINEL_FLOWS)
    if not sentinel_token:
        emitter.warn("当前注册会话 authorize_continue Sentinel 获取失败，回退独立 OAuth", step="get_token")
        return None
    ac_headers = oauth_headers_factory("https://auth.openai.com/log-in")
    ac_headers["openai-sentinel-token"] = sentinel_token
    ac_resp = post_func(
        "https://auth.openai.com/api/accounts/authorize/continue",
        headers=ac_headers,
        json={"username": {"kind": "email", "value": email}, "screen_hint": "login"},
    )
    if ac_resp is None:
        emitter.warn("当前注册会话 authorize_continue Sentinel 获取失败，回退独立 OAuth", step="get_token")
        return None
    if ac_resp.status_code != 200:
        emitter.warn(
            f"当前注册会话 authorize/continue 失败（{ac_resp.status_code}），回退独立 OAuth: {str(ac_resp.text or '')[:180]}",
            step="get_token",
        )
        return None

    sen_pw = sentinel_builder(*PASSWORD_VERIFY_SENTINEL_FLOWS)
    if not sen_pw:
        emitter.warn("当前注册会话 password_verify Sentinel 获取失败，回退独立 OAuth", step="get_token")
        return None
    pw_headers = oauth_headers_factory("https://auth.openai.com/log-in/password")
    pw_headers["openai-sentinel-token"] = sen_pw
    try:
        pw_resp = post_func(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=pw_headers,
            json={"password": account_password},
        )
    except Exception as exc:
        emitter.warn(f"当前注册会话 password/verify 请求失败，回退独立 OAuth: {exc}", step="get_token")
        return None
    if pw_resp.status_code != 200:
        if _is_expired_signin_session_response(pw_resp.status_code, pw_resp.text):
            if isinstance(current_session_fast_token_data, dict) and current_session_fast_token_data:
                emitter.warn(
                    "当前注册会话 password/verify 返回 409（登录会话已失效），保留当前 session-only token，避免 fresh OAuth 触发限流",
                    step="get_token",
                )
                return json.dumps(
                    _mark_token_payload_session_only(
                        current_session_fast_token_data,
                        reason="current_session_password_verify_expired",
                    ),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
        emitter.warn(
            f"当前注册会话 password/verify 失败（{pw_resp.status_code}），回退独立 OAuth: {str(pw_resp.text or '')[:180]}",
            step="get_token",
        )
        return None

    try:
        pw_data = pw_resp.json()
    except Exception:
        pw_data = {}
    consent_url = _extract_post_create_url(pw_data, chatgpt_base)
    page_type = str((pw_data.get("page") or {}).get("type", "")).strip()
    if _requires_phone_verification(pw_data, getattr(pw_resp, "text", ""), consent_url):
        emitter.warn("当前注册会话 OAuth 命中手机验证 / add-phone，标记改走全新授权链", step="get_token")
        return CURRENT_SESSION_OAUTH_PHONE_GATE_RECYCLE_MARKER

    need_oauth_otp = (
        page_type == "email_otp_verification"
        or "email-verification" in consent_url
        or "email-otp" in consent_url
    )
    if need_oauth_otp:
        if mail_provider is None or not str(mail_auth_credential or "").strip():
            emitter.warn("当前注册会话 OAuth 需要邮箱 OTP，但邮箱凭据不可用，回退独立 OAuth", step="get_token")
            return None
        otp_deadline = time.time() + OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS
        otp_wait_started_at = time.time()
        tried_codes: set[str] = set()
        while time.time() < otp_deadline:
            if _stopped():
                return None
            remaining_timeout = max(1, int(math.ceil(otp_deadline - time.time())))
            try:
                otp_code = mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=static_proxy,
                    timeout=remaining_timeout,
                    stop_event=stop_event,
                    sent_at_ts=otp_wait_started_at,
                )
            except TypeError:
                otp_code = mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=static_proxy,
                    timeout=remaining_timeout,
                    stop_event=stop_event,
                )
            if not otp_code:
                emitter.warn("当前注册会话 OAuth 未收到 OTP，回退独立 OAuth", step="get_token")
                return None
            if otp_code in tried_codes:
                _otp_poll_wait(stop_event)
                continue
            tried_codes.add(otp_code)
            otp_headers = oauth_headers_factory("https://auth.openai.com/email-verification")
            sen_otp = sentinel_builder(*EMAIL_VERIFICATION_SENTINEL_FLOWS)
            if sen_otp:
                otp_headers["openai-sentinel-token"] = sen_otp
            try:
                otp_resp = post_func(
                    "https://auth.openai.com/api/accounts/email-otp/validate",
                    headers=otp_headers,
                    json={"code": otp_code},
                )
            except Exception as exc:
                emitter.warn(f"当前注册会话 OAuth OTP 提交失败，回退独立 OAuth: {exc}", step="get_token")
                return None
            if otp_resp.status_code == 200:
                try:
                    otp_data = otp_resp.json()
                except Exception:
                    otp_data = {}
                consent_url = _extract_post_create_url(otp_data, chatgpt_base) or consent_url
                page_type = str((otp_data.get("page") or {}).get("type", "")).strip() or page_type
                if _requires_phone_verification(otp_data, getattr(otp_resp, "text", ""), consent_url):
                    emitter.warn("当前注册会话 OAuth OTP 后命中手机验证 / add-phone，标记改走全新授权链", step="get_token")
                    return CURRENT_SESSION_OAUTH_PHONE_GATE_RECYCLE_MARKER
                break
            _otp_poll_wait(stop_event)
        else:
            emitter.warn("当前注册会话 OAuth OTP 验证失败，回退独立 OAuth", step="get_token")
            return None

    normalized_consent_url = str(consent_url or "").strip()
    if normalized_consent_url.startswith("/"):
        normalized_consent_url = _normalize_post_create_url(normalized_consent_url, chatgpt_base)
    if not normalized_consent_url and "consent" in page_type:
        normalized_consent_url = default_consent_url

    code = ""
    exchange_consent_url = normalized_consent_url or default_consent_url
    prefer_codex_consent = _is_chatgpt_auth_callback_url(normalized_consent_url, chatgpt_base)
    if prefer_codex_consent:
        code = (
            extract_auth_code_from_consent_session(
                session=session,
                consent_url=default_consent_url,
                oauth_issuer=auth_root,
                device_id=device_id,
                header_factory=oauth_headers_factory,
                session_get=get_func,
                session_post=post_func,
            )
            or ""
        )
        if code:
            exchange_consent_url = default_consent_url

    if not code:
        code = (
            extract_auth_code_from_consent_session(
                session=session,
                consent_url=normalized_consent_url or default_consent_url,
                oauth_issuer=auth_root,
                device_id=device_id,
                header_factory=oauth_headers_factory,
                session_get=get_func,
                session_post=post_func,
            )
            or ""
        )
        if code:
            exchange_consent_url = normalized_consent_url or default_consent_url

    if not code and normalized_consent_url and normalized_consent_url != default_consent_url:
        code = (
            extract_auth_code_from_consent_session(
                session=session,
                consent_url=default_consent_url,
                oauth_issuer=auth_root,
                device_id=device_id,
                header_factory=oauth_headers_factory,
                session_get=get_func,
                session_post=post_func,
            )
            or ""
        )
        if code:
            exchange_consent_url = default_consent_url

    if not code:
        emitter.warn("当前注册会话未能获取 OAuth authorization code，回退独立 OAuth", step="get_token")
        return None

    token_data = exchange_codex_tokens_from_session(
        session=session,
        consent_url=exchange_consent_url,
        oauth_issuer=auth_root,
        oauth_client_id=codex_oauth.client_id,
        oauth_redirect_uri=codex_oauth.redirect_uri,
        code_verifier=codex_oauth.code_verifier,
        auth_code=code,
        account_password=account_password,
        mail_provider=resolved_mail_provider_name,
        mailbox=mailbox,
        device_id=device_id,
        header_factory=oauth_headers_factory,
        session_get=get_func,
        session_post=post_func,
    )
    refresh_token = str((token_data or {}).get("refresh_token") or "").strip()
    if isinstance(token_data, dict) and refresh_token:
        emitter.success("当前注册会话获取 refresh_token 成功！", step="get_token")
        return json.dumps(token_data, ensure_ascii=False, separators=(",", ":"))

    emitter.warn("当前注册会话未拿到 refresh_token，回退独立 OAuth", step="get_token")
    return None


def _build_token_result(
    token_payload: Dict[str, Any],
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
) -> str:
    access_token = str(token_payload.get("access_token") or "").strip()
    refresh_token = str(token_payload.get("refresh_token") or "").strip()
    id_token = str(token_payload.get("id_token") or "").strip()
    expires_in = _to_int(token_payload.get("expires_in"))

    missing_fields = [
        name for name, value in (
            ("access_token", access_token),
            ("refresh_token", refresh_token),
            ("id_token", id_token),
        ) if not value
    ]
    if missing_fields:
        raise ValueError(f"token exchange missing fields: {', '.join(missing_fields)}")

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
    if not email or not account_id:
        raise ValueError("token exchange missing email/account_id in id_token")

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "expires_at": expired_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }
    resolved_password = str(account_password or "").strip()
    if resolved_password:
        config["account_password"] = resolved_password
        config["password"] = resolved_password
    resolved_mail_provider = str(mail_provider or "").strip().lower()
    if resolved_mail_provider:
        config["mail_provider"] = resolved_mail_provider
    mailbox_context = _sanitize_mailbox_context(mailbox)
    if mailbox_context:
        config["mailbox"] = mailbox_context
    return json.dumps(
        _normalize_token_payload_for_compat(config),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _encode_unverified_jwt(payload: Dict[str, Any]) -> str:
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{header_b64}.{payload_b64}.sig"


def _extract_token_identity(token: str) -> Dict[str, Any]:
    claims = _jwt_claims_no_verify(token)
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    profile_claims = claims.get("https://api.openai.com/profile") or {}
    return {
        "claims": claims,
        "email": str(
            claims.get("email")
            or profile_claims.get("email")
            or ""
        ).strip(),
        "account_id": str(auth_claims.get("chatgpt_account_id") or "").strip(),
        "user_id": str(
            auth_claims.get("chatgpt_user_id")
            or auth_claims.get("user_id")
            or ""
        ).strip(),
        "plan_type": str(
            auth_claims.get("plan_type")
            or auth_claims.get("chatgpt_plan_type")
            or ""
        ).strip(),
        "exp": _to_int(claims.get("exp")),
    }


def _build_compat_id_token(
    *,
    email: str,
    exp_ts: int,
    account_id: str,
    user_id: str = "",
    plan_type: str = "",
) -> str:
    if not email or not account_id:
        return ""
    now_ts = int(time.time())
    safe_exp_ts = max(exp_ts or 0, now_ts + 3600)
    auth_claims: Dict[str, Any] = {
        "chatgpt_account_id": account_id,
        "plan_type": plan_type or "free",
        "chatgpt_plan_type": plan_type or "free",
    }
    if user_id:
        auth_claims["chatgpt_user_id"] = user_id
        auth_claims["user_id"] = user_id
    payload = {
        "email": email,
        "email_verified": True,
        "iat": now_ts,
        "exp": safe_exp_ts,
        "iss": "https://auth.openai.com",
        "https://api.openai.com/auth": auth_claims,
    }
    return _encode_unverified_jwt(payload)


def _normalize_token_payload_for_compat(token_payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = dict(token_payload or {})
    credentials = payload.get("credentials")
    credentials = dict(credentials) if isinstance(credentials, dict) else {}

    def _first_text(*values: Any) -> str:
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    access_token = _first_text(payload.get("access_token"), credentials.get("access_token"))
    refresh_token = _first_text(payload.get("refresh_token"), credentials.get("refresh_token"))
    existing_id_token = _first_text(payload.get("id_token"), credentials.get("id_token"))
    session_token = _first_text(
        payload.get("session_token"),
        payload.get("sessionToken"),
        credentials.get("session_token"),
        credentials.get("sessionToken"),
    )

    access_identity = _extract_token_identity(access_token)
    id_identity = _extract_token_identity(existing_id_token)

    email = _first_text(
        payload.get("email"),
        credentials.get("email"),
        access_identity.get("email"),
        id_identity.get("email"),
    )
    account_id = _first_text(
        payload.get("account_id"),
        payload.get("chatgpt_account_id"),
        credentials.get("chatgpt_account_id"),
        credentials.get("account_id"),
        access_identity.get("account_id"),
        id_identity.get("account_id"),
    )
    user_id = _first_text(
        payload.get("chatgpt_user_id"),
        credentials.get("chatgpt_user_id"),
        access_identity.get("user_id"),
        id_identity.get("user_id"),
    )
    plan_type = _first_text(
        payload.get("plan_type"),
        payload.get("chatgpt_plan_type"),
        credentials.get("plan_type"),
        credentials.get("chatgpt_plan_type"),
        access_identity.get("plan_type"),
        id_identity.get("plan_type"),
    )

    exp_ts = max(
        _to_int(access_identity.get("exp")),
        _to_int(id_identity.get("exp")),
        _parse_rfc3339_timestamp(payload.get("expires_at")),
        _parse_rfc3339_timestamp(payload.get("expired")),
        _parse_rfc3339_timestamp(credentials.get("expires_at")),
    )
    if exp_ts <= 0:
        exp_ts = int(time.time()) + 3600
    expires_at = _first_text(
        payload.get("expires_at"),
        payload.get("expired"),
        credentials.get("expires_at"),
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_ts)),
    )

    # Preserve an explicit id_token from upstream session payloads. When session fast-path
    # does not provide one, synthesize a minimal unsigned JWT for compatibility.
    compat_id_token = existing_id_token if existing_id_token else _build_compat_id_token(
        email=email,
        exp_ts=exp_ts,
        account_id=account_id,
        user_id=user_id,
        plan_type=plan_type,
    )

    if access_token:
        payload["access_token"] = access_token
    if refresh_token:
        payload["refresh_token"] = refresh_token
    if compat_id_token:
        payload["id_token"] = compat_id_token
    if email:
        payload["email"] = email
    if account_id:
        payload["account_id"] = account_id
        payload["chatgpt_account_id"] = account_id
    if user_id:
        payload["chatgpt_user_id"] = user_id
    if plan_type:
        payload["plan_type"] = plan_type
        payload["chatgpt_plan_type"] = plan_type
    if session_token:
        payload["session_token"] = session_token
    if expires_at:
        payload["expires_at"] = expires_at
        payload["expired"] = _first_text(payload.get("expired"), expires_at)

    if access_token:
        credentials["access_token"] = access_token
    if refresh_token:
        credentials["refresh_token"] = refresh_token
    if compat_id_token:
        credentials["id_token"] = compat_id_token
    if account_id:
        credentials["chatgpt_account_id"] = account_id
    if user_id:
        credentials["chatgpt_user_id"] = user_id
    if session_token:
        credentials["session_token"] = session_token
    if expires_at:
        credentials["expires_at"] = expires_at
    if plan_type:
        credentials["plan_type"] = plan_type
        credentials["chatgpt_plan_type"] = plan_type
    if credentials:
        payload["credentials"] = credentials

    return payload


def _mark_token_payload_session_only(
    token_payload: Dict[str, Any],
    *,
    reason: str = "missing_refresh_token",
    token_source: str = "chatgpt_session",
) -> Dict[str, Any]:
    payload = _normalize_token_payload_for_compat(token_payload or {})
    payload["session_only"] = True
    payload["refreshable"] = False
    reason_text = str(reason or "").strip()
    if reason_text:
        payload["session_only_reason"] = reason_text
    source_text = str(payload.get("token_source") or token_source or "").strip()
    if source_text:
        payload["token_source"] = source_text
    return payload


def _extract_chatgpt_session_tokens(session_payload: Any) -> Dict[str, str]:
    payload = session_payload if isinstance(session_payload, dict) else {}
    containers: list[Dict[str, Any]] = []
    for candidate in (
        payload,
        payload.get("data"),
        payload.get("session"),
    ):
        if isinstance(candidate, dict):
            containers.append(candidate)
            nested_user = candidate.get("user")
            if isinstance(nested_user, dict):
                containers.append(nested_user)

    def _pick(*keys: str) -> str:
        for container in containers:
            for key in keys:
                value = container.get(key)
                text = str(value or "").strip()
                if text:
                    return text
        return ""

    return {
        "access_token": _pick("accessToken", "access_token", "token"),
        "refresh_token": _pick("refreshToken", "refresh_token"),
        "id_token": _pick("idToken", "id_token"),
        "email": _pick("email"),
        "expires": _pick("expires", "expires_at", "expired"),
        "session_token": _pick("sessionToken", "session_token"),
    }


def _parse_rfc3339_timestamp(value: Any) -> int:
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _build_token_result_from_chatgpt_session(
    session_payload: Dict[str, Any],
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
) -> str:
    extracted = _extract_chatgpt_session_tokens(session_payload)
    access_token = str(extracted.get("access_token") or "").strip()
    if not access_token:
        raise ValueError("chatgpt session missing access_token")

    claims = _jwt_claims_no_verify(access_token)
    profile_claims = claims.get("https://api.openai.com/profile") or {}
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    email = str(
        profile_claims.get("email")
        or claims.get("email")
        or extracted.get("email")
        or ""
    ).strip()
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()
    if not email or not account_id:
        raise ValueError("chatgpt session missing email/account_id")

    now = int(time.time())
    exp_ts = _to_int(claims.get("exp"))
    if exp_ts <= 0:
        exp_ts = _parse_rfc3339_timestamp(extracted.get("expires"))
    if exp_ts <= 0:
        exp_ts = now + 3600

    expired_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp_ts))
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": str(extracted.get("id_token") or "").strip(),
        "access_token": access_token,
        "refresh_token": str(extracted.get("refresh_token") or "").strip(),
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "expires_at": expired_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }
    resolved_password = str(account_password or "").strip()
    if resolved_password:
        config["account_password"] = resolved_password
        config["password"] = resolved_password
    resolved_mail_provider = str(mail_provider or "").strip().lower()
    if resolved_mail_provider:
        config["mail_provider"] = resolved_mail_provider
    resolved_session_token = str(extracted.get("session_token") or "").strip()
    if resolved_session_token:
        config["session_token"] = resolved_session_token
    mailbox_context = _sanitize_mailbox_context(mailbox)
    if mailbox_context:
        config["mailbox"] = mailbox_context
    return json.dumps(
        _normalize_token_payload_for_compat(config),
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _write_text_atomic(file_path: str, content: str) -> None:
    directory = os.path.dirname(file_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, file_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str
    client_id: str = CLIENT_ID


def _build_chatgpt_signin_params(*, email: str, device_id: str, auth_session_id: str) -> Dict[str, str]:
    return {
        "prompt": "login",
        "ext-oai-did": device_id,
        "auth_session_logging_id": auth_session_id,
        "ext-passkey-client-capabilities": "0111",
        "screen_hint": "login_or_signup",
        "login_hint": email,
    }


def _resolve_oauth_start_from_authorize_url(
    authorize_url: str,
    fallback: OAuthStart,
) -> OAuthStart:
    candidate = str(authorize_url or "").strip()
    if not candidate:
        return fallback

    try:
        parsed = urllib.parse.urlparse(candidate)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return fallback

    def _get_first(name: str) -> str:
        values = query.get(name, [])
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    resolved_state = _get_first("state") or fallback.state
    resolved_redirect_uri = _get_first("redirect_uri") or fallback.redirect_uri
    resolved_client_id = _get_first("client_id") or fallback.client_id or CLIENT_ID
    explicit_code_verifier = _get_first("code_verifier")

    if explicit_code_verifier:
        resolved_code_verifier = explicit_code_verifier
    elif _get_first("client_id") or _get_first("redirect_uri"):
        # signin/openai 返回的是它自己的 OAuth client 链路时，不能再混用本地生成的 PKCE verifier
        resolved_code_verifier = ""
    else:
        resolved_code_verifier = fallback.code_verifier

    return OAuthStart(
        auth_url=candidate,
        state=resolved_state,
        code_verifier=resolved_code_verifier,
        redirect_uri=resolved_redirect_uri,
        client_id=resolved_client_id,
    )


def _select_exchange_oauth_start(
    *,
    callback_params: Optional[Dict[str, str]],
    signin_oauth: OAuthStart,
    codex_oauth: OAuthStart,
) -> OAuthStart:
    params = callback_params if isinstance(callback_params, dict) else {}
    callback_state = str(params.get("state") or "").strip()
    if callback_state and callback_state == str(signin_oauth.state or "").strip():
        return signin_oauth
    if callback_state and callback_state == str(codex_oauth.state or "").strip():
        return codex_oauth
    return codex_oauth


def _exchange_captured_oauth_callback_to_token_data(
    *,
    callback_params: Dict[str, str],
    signin_oauth: OAuthStart,
    codex_oauth: OAuthStart,
    proxy: str = "",
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    params = callback_params if isinstance(callback_params, dict) else {}
    code = str(params.get("code") or "").strip()
    if not code:
        return None

    selected_oauth = _select_exchange_oauth_start(
        callback_params=params,
        signin_oauth=signin_oauth,
        codex_oauth=codex_oauth,
    )
    form_payload = {
        "grant_type": "authorization_code",
        "client_id": str(selected_oauth.client_id or CLIENT_ID),
        "code": code,
        "redirect_uri": str(selected_oauth.redirect_uri or DEFAULT_REDIRECT_URI),
    }
    selected_code_verifier = str(selected_oauth.code_verifier or "").strip()
    if selected_code_verifier:
        form_payload["code_verifier"] = selected_code_verifier

    try:
        token_payload = _post_form(TOKEN_URL, form_payload, proxy=proxy)
    except Exception:
        return None

    try:
        return json.loads(
            _build_token_result(
                token_payload,
                account_password=account_password,
                mail_provider=mail_provider,
                mailbox=mailbox,
            )
        )
    except Exception:
        return None


def _try_browser_oauth_capture_for_token(
    *,
    start_url: str,
    session: requests.Session,
    signin_oauth: OAuthStart,
    codex_oauth: OAuthStart,
    proxy: str = "",
    user_agent: str = "",
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
    emitter: Optional[EventEmitter] = None,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[Dict[str, Any]]:
    emitter = emitter or EventEmitter(cli_mode=False)
    target_url = str(start_url or "").strip()
    if not target_url:
        return None

    try:
        from .browser_oauth_flow import get_browser_oauth_capture_bundle
    except Exception as exc:
        emitter.warn(f"浏览器 OAuth 模块不可用，跳过 browser fallback: {exc}", step="get_token")
        return None

    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
    )
    emitter.info("本地 OAuth 未拿到 refresh_token，尝试浏览器 callback 捕获...", step="get_token")
    try:
        bundle = get_browser_oauth_capture_bundle(
            start_url=target_url,
            cookies=getattr(session, "cookies", None),
            proxy=proxy,
            user_agent=profile.user_agent,
            session_profile=profile,
        )
    except Exception as exc:
        emitter.warn(f"浏览器 OAuth callback 捕获失败: {exc}", step="get_token")
        return None

    token_payload = bundle.get("token_payload") if isinstance(bundle, dict) else {}
    if isinstance(token_payload, dict) and str(token_payload.get("refresh_token") or "").strip():
        try:
            token_data = json.loads(
                _build_token_result(
                    token_payload,
                    account_password=account_password,
                    mail_provider=mail_provider,
                    mailbox=mailbox,
                )
            )
        except Exception as exc:
            emitter.warn(f"浏览器 OAuth token_payload 构建失败: {exc}", step="get_token")
        else:
            emitter.success("浏览器 OAuth 直接捕获 refresh_token 成功！", step="get_token")
            return token_data

    callback_params = {}
    if isinstance(bundle, dict):
        raw_callback_params = bundle.get("callback_params")
        if isinstance(raw_callback_params, dict):
            callback_params = {
                "code": str(raw_callback_params.get("code") or "").strip(),
                "state": str(raw_callback_params.get("state") or "").strip(),
                "error": str(raw_callback_params.get("error") or "").strip(),
                "error_description": str(raw_callback_params.get("error_description") or "").strip(),
            }
        if not any(callback_params.values()):
            callback_params = _parse_callback_url(str(bundle.get("callback_url") or ""))

    if str(callback_params.get("error") or "").strip():
        emitter.warn(
            f"浏览器 OAuth callback 返回错误: {str(callback_params.get('error') or '')[:80]}",
            step="get_token",
        )
        return None

    token_data = _exchange_captured_oauth_callback_to_token_data(
        callback_params=callback_params,
        signin_oauth=signin_oauth,
        codex_oauth=codex_oauth,
        proxy=proxy,
        account_password=account_password,
        mail_provider=mail_provider,
        mailbox=mailbox,
    )
    refresh_token = str((token_data or {}).get("refresh_token") or "").strip()
    if refresh_token:
        emitter.success("浏览器 OAuth callback 换取 refresh_token 成功！", step="get_token")
        return token_data
    return None


def _is_chatgpt_auth_callback_url(target_url: str, chatgpt_base: str = "") -> bool:
    candidate = str(target_url or "").strip()
    if not candidate:
        return False
    try:
        parsed = urllib.parse.urlparse(candidate)
    except Exception:
        return False
    host = str(parsed.netloc or "").strip().lower()
    path = str(parsed.path or "").rstrip("/")
    if not host or path != "/api/auth/callback/openai":
        return False

    allowed_hosts = {"chatgpt.com", "www.chatgpt.com"}
    try:
        base_host = str(urllib.parse.urlparse(str(chatgpt_base or "").strip()).netloc or "").strip().lower()
    except Exception:
        base_host = ""
    if base_host:
        allowed_hosts.add(base_host)
    return host in allowed_hosts


SIGNUP_PASSWORD_URL = "https://auth.openai.com/create-account/password"
EMAIL_VERIFICATION_URL = "https://auth.openai.com/email-verification"
SIGNUP_REGISTER_URL = "https://auth.openai.com/api/accounts/user/register"
AUTHORIZE_CONTINUE_SENTINEL_FLOWS = ("authorize-continue", "authorize_continue")
REGISTER_SENTINEL_FLOWS = (
    "username-password-create",
    "username_password_create",
    "register",
    *AUTHORIZE_CONTINUE_SENTINEL_FLOWS,
)
PASSWORD_VERIFY_SENTINEL_FLOWS = ("password-verify", "password_verify")
EMAIL_VERIFICATION_SENTINEL_FLOWS = (
    "email-verification",
    "email_verification",
    *AUTHORIZE_CONTINUE_SENTINEL_FLOWS,
)
CREATE_ACCOUNT_SENTINEL_FLOWS = (
    "oauth-create-account",
    "oauth_create_account",
    "create-account",
    "create_account",
    *AUTHORIZE_CONTINUE_SENTINEL_FLOWS,
)


def _is_signup_entry_url(target_url: str) -> bool:
    parsed = urlparse(str(target_url or ""))
    path = str(parsed.path or "").lower()
    if "/api/accounts/authorize" in path:
        return False
    if "email-verification" in path:
        return False
    return any(fragment in path for fragment in ("create-account", "/u/signup", "/signup"))


def _can_continue_signup_after_authorize(target_url: str) -> bool:
    normalized = _normalize_auth_url(target_url)
    if _is_signup_entry_url(normalized):
        return True
    path = str(urlparse(normalized).path or "").lower()
    return any(fragment in path for fragment in ("email-verification", "email-otp"))


def _normalize_auth_url(target_url: Any) -> str:
    text = str(target_url or "").strip()
    if not text:
        return ""
    if text.startswith("/"):
        return urllib.parse.urljoin("https://auth.openai.com", text)
    return text


def _extract_next_auth_url(payload: Any) -> str:
    return _normalize_auth_url(_extract_response_url_candidate(payload))


def _iter_sentinel_flows(*flows: str):
    seen: set[str] = set()
    for flow in flows:
        flow_name = str(flow or "").strip()
        if not flow_name or flow_name in seen:
            continue
        seen.add(flow_name)
        yield flow_name


def _looks_like_retryable_sentinel_failure(status_code: int, response_text: Any) -> bool:
    if int(status_code or 0) != 400:
        return False
    body_text = str(response_text or "").strip().lower()
    if not body_text:
        return False
    markers = (
        "invalid_request_error",
        "failed to create account",
        "sentinel",
    )
    return any(marker in body_text for marker in markers)


def _build_sentinel_token_for_flows(
    *,
    flow_candidates: tuple[str, ...],
    sentinel_builder: Callable[[str], Optional[str]],
) -> Optional[str]:
    for flow_name in _iter_sentinel_flows(*flow_candidates):
        token = sentinel_builder(flow_name)
        if token:
            return token
    return None


def _post_json_with_sentinel_flow_fallbacks(
    *,
    url: str,
    base_headers: Dict[str, str],
    payload: Dict[str, Any],
    flow_candidates: tuple[str, ...],
    sentinel_builder: Callable[[str], Optional[str]],
    session_post: Callable[..., Any],
    emitter: EventEmitter,
    step: str,
    action_label: str,
    allow_missing_sentinel: bool = False,
):
    last_response = None
    attempted_flow = ""
    attempted_any = False
    flow_names = list(_iter_sentinel_flows(*flow_candidates))
    for index, flow_name in enumerate(flow_names, start=1):
        sentinel_token = sentinel_builder(flow_name)
        if not sentinel_token:
            continue
        attempted_any = True
        attempted_flow = flow_name
        request_headers = dict(base_headers)
        request_headers["openai-sentinel-token"] = sentinel_token
        emitter.info(
            f"{action_label} 使用 Sentinel flow={flow_name}（尝试 {index}/{len(flow_names)}）",
            step=step,
        )
        response = session_post(url, headers=request_headers, json=payload)
        if response.status_code == 200:
            return response, flow_name
        last_response = response
        if index >= len(flow_names) or not _looks_like_retryable_sentinel_failure(response.status_code, response.text):
            break
        emitter.warn(
            f"{action_label} 使用 Sentinel flow={flow_name} 返回 {response.status_code}，尝试下一个 flow",
            step=step,
        )

    if attempted_any or not allow_missing_sentinel:
        return last_response, attempted_flow

    emitter.warn(f"{action_label} 未获取到 Sentinel token，按兼容模式继续请求", step=step)
    return session_post(url, headers=dict(base_headers), json=payload), attempted_flow


def _submit_signup_register_form(
    *,
    email: str,
    account_password: str,
    base_headers: Dict[str, str],
    initial_sentinel_token: str = "",
    initial_sentinel_label: str = "",
    flow_candidates: tuple[str, ...],
    sentinel_builder: Callable[[str], Optional[str]],
    session_post: Callable[..., Any],
    emitter: EventEmitter,
    step: str = "signup",
):
    payload = {"username": email, "password": account_password}
    initial_response = None
    initial_token = str(initial_sentinel_token or "").strip()
    initial_label = str(initial_sentinel_label or "initial").strip()

    if initial_token:
        request_headers = dict(base_headers)
        request_headers["openai-sentinel-token"] = initial_token
        emitter.info(f"注册表单使用{initial_label} Sentinel token", step=step)
        initial_response = session_post(
            SIGNUP_REGISTER_URL,
            headers=request_headers,
            json=payload,
        )
        if initial_response.status_code == 200:
            return initial_response, initial_label
        if not _looks_like_retryable_sentinel_failure(initial_response.status_code, initial_response.text):
            return initial_response, initial_label
        emitter.warn(
            f"注册表单{initial_label} Sentinel token 被拒绝，切换 challenge Sentinel flow 重试",
            step=step,
        )

    fallback_response, attempted_flow = _post_json_with_sentinel_flow_fallbacks(
        url=SIGNUP_REGISTER_URL,
        base_headers=base_headers,
        payload=payload,
        flow_candidates=flow_candidates,
        sentinel_builder=sentinel_builder,
        session_post=session_post,
        emitter=emitter,
        step=step,
        action_label="注册表单",
        allow_missing_sentinel=initial_response is None,
    )
    if fallback_response is not None:
        return fallback_response, attempted_flow
    return initial_response, initial_label


def _extract_query_param(target_url: str, key: str) -> str:
    parsed = urlparse(str(target_url or ""))
    values = parse_qs(parsed.query).get(key, [])
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _build_signup_prompt_candidates(authorize_like_url: str) -> list[str]:
    state = _extract_query_param(authorize_like_url, "state")
    if not state:
        return []
    return [
        f"https://auth.openai.com/u/signup/password?{urlencode({'state': state})}",
        f"https://auth.openai.com/u/signup/identifier?{urlencode({'state': state})}",
    ]


def _build_signup_headers(device_id: str, referer: str = "https://auth.openai.com/create-account/password") -> Dict[str, str]:
    headers = {
        "referer": referer,
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "origin": "https://auth.openai.com",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    if device_id:
        headers["oai-device-id"] = device_id
    return headers


def _resolve_send_otp_referer(
    signup_entry_url: str,
    *,
    signup_response_payload: Optional[Dict[str, Any]] = None,
) -> str:
    payload = signup_response_payload if isinstance(signup_response_payload, dict) else {}
    continue_url = _extract_next_auth_url(payload)
    page_type = _extract_page_type(payload)
    if continue_url and "email-verification" in continue_url:
        return continue_url
    if page_type == "email_otp_verification":
        return EMAIL_VERIFICATION_URL
    normalized_signup_entry = _normalize_auth_url(signup_entry_url)
    if "email-verification" in normalized_signup_entry:
        return EMAIL_VERIFICATION_URL
    return EMAIL_VERIFICATION_URL


def _submit_signup_authorize_continue(
    *,
    email: str,
    device_id: str,
    session_post: Callable[..., Any],
    trace_headers_factory: Callable[[], Dict[str, str]],
    sentinel_builder: Callable[[str], Optional[str]],
    emitter: EventEmitter,
    session: Any = None,
    authorize_like_url: str = "",
    browser_entry_config: Optional[Dict[str, Any]] = None,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    headers = {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "origin": "https://auth.openai.com",
        "referer": "https://auth.openai.com/log-in-or-create-account",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    if device_id:
        headers["oai-device-id"] = device_id
    headers.update(trace_headers_factory())

    sentinel = _build_sentinel_token_for_flows(
        flow_candidates=AUTHORIZE_CONTINUE_SENTINEL_FLOWS,
        sentinel_builder=sentinel_builder,
    )
    if sentinel:
        headers["openai-sentinel-token"] = sentinel

    response = session_post(
        "https://auth.openai.com/api/accounts/authorize/continue",
        headers=headers,
        json={"username": {"kind": "email", "value": email}, "screen_hint": "login_or_signup"},
    )
    emitter.info(f"Signup authorize 状态: {response.status_code}", step="oauth_init")
    if response.status_code != 200:
        body_preview = str(response.text or "")[:220]
        if _looks_like_cloudflare_challenge_response(response) and session is not None:
            browser_target_url = ""
            for candidate_url in _build_signup_prompt_candidates(authorize_like_url):
                browser_target_url = candidate_url
                break
            if not browser_target_url:
                browser_target_url = str(authorize_like_url or SIGNUP_PASSWORD_URL).strip() or SIGNUP_PASSWORD_URL
            warmed_url = _warmup_auth_entry_with_browser(
                target_url=browser_target_url,
                session=session,
                emitter=emitter,
                step="oauth_init",
                browser_entry_config=browser_entry_config,
                proxy=proxy,
                user_agent=user_agent,
                session_profile=session_profile,
            )
            if warmed_url:
                return warmed_url
        emitter.error(
            f"Signup authorize 失败（状态码 {response.status_code}）: {body_preview}",
            step="oauth_init",
        )
        if response.status_code == 429 or _looks_rate_limited_text(body_preview):
            raise SignupRateLimitError(body_preview or "rate limit exceeded")
        if _looks_invalid_state_text(body_preview):
            raise SignupInvalidStateError(body_preview or "invalid state")
        return None
    try:
        payload = response.json() if response.text else {}
    except Exception:
        payload = {}
    return _extract_next_auth_url(payload)


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        client_id=CLIENT_ID,
    )


def _bootstrap_reauth_oauth_session(
    *,
    session_get: Callable[..., Any],
    authorize_url: str,
    codex_oauth: OAuthStart,
    navigate_headers_factory: Callable[[str], Dict[str, str]],
    chatgpt_base: str,
    emitter: EventEmitter,
) -> None:
    referer = f"{str(chatgpt_base or 'https://chatgpt.com').rstrip('/')}/"
    normalized_authorize_url = str(authorize_url or "").strip()
    if normalized_authorize_url:
        emitter.info("先跟随 signin/openai 返回的 authorize_url 建立会话...", step="get_token")
        try:
            session_get(
                normalized_authorize_url,
                headers=navigate_headers_factory(referer),
                timeout=30,
            )
            return
        except Exception as exc:
            emitter.warn(
                f"跟随 signin/openai 返回的 authorize_url 失败，继续初始化 Codex OAuth: {exc}",
                step="get_token",
            )

    session_get(
        codex_oauth.auth_url,
        headers=navigate_headers_factory(referer),
        timeout=30,
    )


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    proxy: str = "",
) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        proxy=proxy,
    )

    return _build_token_result(token_resp)


def extract_oauth_callback_params_from_url(target_url: str) -> Optional[Dict[str, str]]:
    params = _parse_callback_url(str(target_url or ""))
    if any(str(params.get(key) or "").strip() for key in ("code", "state", "error", "error_description")):
        return params
    return None


def _read_auth_session_cookie_payload(session: requests.Session) -> Optional[Dict[str, Any]]:
    try:
        cookie_value = str(session.cookies.get("oai-client-auth-session") or "").strip()  # type: ignore[attr-defined]
    except Exception:
        cookie_value = ""
    if not cookie_value:
        try:
            for cookie in session.cookies:  # type: ignore[attr-defined]
                if str(getattr(cookie, "name", "")).strip() == "oai-client-auth-session":
                    cookie_value = str(getattr(cookie, "value", "")).strip()
                    if cookie_value:
                        break
        except Exception:
            cookie_value = ""
    if not cookie_value:
        return None
    first_segment = cookie_value.split(".")[0]
    payload = _decode_jwt_segment(first_segment)
    return payload if isinstance(payload, dict) and payload else None


def extract_oauth_callback_params_from_consent_session(
    session: requests.Session,
    consent_url: str,
    oauth_issuer: str,
    device_id: str = "",
    header_factory: Optional[Callable[[str], Dict[str, str]]] = None,
    session_get: Optional[Callable[..., Any]] = None,
    session_post: Optional[Callable[..., Any]] = None,
) -> Optional[Dict[str, str]]:
    normalized_issuer = str(oauth_issuer or "https://auth.openai.com").rstrip("/")
    normalized_consent_url = str(consent_url or "").strip()
    if not normalized_consent_url:
        return None
    if normalized_consent_url.startswith("/"):
        normalized_consent_url = f"{normalized_issuer}{normalized_consent_url}"
    direct_callback_params = extract_oauth_callback_params_from_url(normalized_consent_url)
    if direct_callback_params:
        return direct_callback_params

    get_func = session_get or getattr(session, "get", None)
    post_func = session_post or getattr(session, "post", None)
    if get_func is None:
        return None

    def _navigate_headers() -> Dict[str, str]:
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }

    def _action_headers(referer: str) -> Dict[str, str]:
        if header_factory is not None:
            return dict(header_factory(referer) or {})
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": normalized_issuer,
            "referer": str(referer or normalized_consent_url),
        }
        if device_id:
            headers["oai-device-id"] = str(device_id)
        return headers

    def _follow_and_extract_callback_params(start_url: str, max_depth: int = 10) -> Optional[Dict[str, str]]:
        current_url = str(start_url or "").strip()
        if not current_url or max_depth <= 0:
            return None
        try:
            response = get_func(
                current_url,
                headers=_navigate_headers(),
                verify=False,
                timeout=15,
                allow_redirects=False,
            )
        except requests.exceptions.ConnectionError as exc:
            match = re.search(r'(https?://localhost[^\s\'"]+)', str(exc))
            if match:
                return extract_oauth_callback_params_from_url(match.group(1))
            return None
        except Exception:
            return None

        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = str(response.headers.get("Location") or "").strip()
            if not redirect_url:
                return None
            callback_params = extract_oauth_callback_params_from_url(redirect_url)
            if callback_params:
                return callback_params
            return _follow_and_extract_callback_params(
                urllib.parse.urljoin(current_url, redirect_url),
                max_depth=max_depth - 1,
            )
        return extract_oauth_callback_params_from_url(str(getattr(response, "url", "") or ""))

    callback_params: Optional[Dict[str, str]] = None
    try:
        consent_response = get_func(
            normalized_consent_url,
            headers=_navigate_headers(),
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
    except requests.exceptions.ConnectionError as exc:
        match = re.search(r'(https?://localhost[^\s\'"]+)', str(exc))
        if match:
            callback_params = extract_oauth_callback_params_from_url(match.group(1))
    except Exception:
        consent_response = None
    else:
        if consent_response.status_code in (301, 302, 303, 307, 308):
            redirect_url = str(consent_response.headers.get("Location") or "").strip()
            callback_params = extract_oauth_callback_params_from_url(redirect_url)
            if not callback_params and redirect_url:
                callback_params = _follow_and_extract_callback_params(
                    urllib.parse.urljoin(normalized_consent_url, redirect_url)
                )
        elif consent_response.status_code == 200:
            callback_params = extract_oauth_callback_params_from_url(
                str(getattr(consent_response, "url", "") or "")
            )

    if callback_params:
        return callback_params

    auth_session_payload = _read_auth_session_cookie_payload(session)
    workspaces = auth_session_payload.get("workspaces") if isinstance(auth_session_payload, dict) else []
    workspace_id = ""
    if isinstance(workspaces, list) and workspaces:
        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()

    if workspace_id and post_func is not None:
        try:
            workspace_response = post_func(
                f"{normalized_issuer}/api/accounts/workspace/select",
                json={"workspace_id": workspace_id},
                headers=_action_headers(normalized_consent_url),
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
        except Exception:
            workspace_response = None
        if workspace_response is not None:
            if workspace_response.status_code in (301, 302, 303, 307, 308):
                redirect_url = str(workspace_response.headers.get("Location") or "").strip()
                callback_params = extract_oauth_callback_params_from_url(redirect_url)
                if not callback_params and redirect_url:
                    callback_params = _follow_and_extract_callback_params(
                        urllib.parse.urljoin(normalized_issuer + "/", redirect_url)
                    )
            elif workspace_response.status_code == 200:
                try:
                    workspace_payload = workspace_response.json()
                except Exception:
                    workspace_payload = {}
                if isinstance(workspace_payload, dict):
                    workspace_next = str(workspace_payload.get("continue_url") or "").strip()
                    orgs = (workspace_payload.get("data") or {}).get("orgs") or []
                    if isinstance(orgs, list) and orgs:
                        org_id = str((orgs[0] or {}).get("id") or "").strip()
                        projects = (orgs[0] or {}).get("projects") or []
                        project_id = str((projects[0] or {}).get("id") or "").strip() if projects else ""
                        if org_id:
                            organization_body = {"org_id": org_id}
                            if project_id:
                                organization_body["project_id"] = project_id
                            organization_referer = (
                                urllib.parse.urljoin(normalized_issuer + "/", workspace_next)
                                if workspace_next
                                else normalized_consent_url
                            )
                            try:
                                organization_response = post_func(
                                    f"{normalized_issuer}/api/accounts/organization/select",
                                    json=organization_body,
                                    headers=_action_headers(organization_referer),
                                    verify=False,
                                    timeout=30,
                                    allow_redirects=False,
                                )
                            except Exception:
                                organization_response = None
                            if organization_response is not None:
                                if organization_response.status_code in (301, 302, 303, 307, 308):
                                    redirect_url = str(organization_response.headers.get("Location") or "").strip()
                                    callback_params = extract_oauth_callback_params_from_url(redirect_url)
                                    if not callback_params and redirect_url:
                                        callback_params = _follow_and_extract_callback_params(
                                            urllib.parse.urljoin(normalized_issuer + "/", redirect_url)
                                        )
                                elif organization_response.status_code == 200:
                                    try:
                                        organization_payload = organization_response.json()
                                    except Exception:
                                        organization_payload = {}
                                    organization_next = str(
                                        (organization_payload or {}).get("continue_url") or ""
                                    ).strip()
                                    if organization_next:
                                        callback_params = extract_oauth_callback_params_from_url(organization_next)
                                        if not callback_params:
                                            callback_params = _follow_and_extract_callback_params(
                                                urllib.parse.urljoin(normalized_issuer + "/", organization_next)
                                            )
                    if not callback_params and workspace_next:
                        callback_params = extract_oauth_callback_params_from_url(workspace_next)
                        if not callback_params:
                            callback_params = _follow_and_extract_callback_params(
                                urllib.parse.urljoin(normalized_issuer + "/", workspace_next)
                            )

    if callback_params:
        return callback_params

    try:
        fallback_response = get_func(
            normalized_consent_url,
            headers=_navigate_headers(),
            verify=False,
            timeout=30,
            allow_redirects=True,
        )
    except requests.exceptions.ConnectionError as exc:
        match = re.search(r'(https?://localhost[^\s\'"]+)', str(exc))
        if match:
            return extract_oauth_callback_params_from_url(match.group(1))
        return None
    except Exception:
        return None

    callback_params = extract_oauth_callback_params_from_url(str(getattr(fallback_response, "url", "") or ""))
    if callback_params:
        return callback_params
    for history_item in getattr(fallback_response, "history", []) or []:
        callback_params = extract_oauth_callback_params_from_url(
            str(getattr(history_item, "headers", {}).get("Location") or "")
        )
        if callback_params:
            return callback_params
    return None


def extract_auth_code_from_consent_session(
    session: requests.Session,
    consent_url: str,
    oauth_issuer: str,
    device_id: str = "",
    header_factory: Optional[Callable[[str], Dict[str, str]]] = None,
    session_get: Optional[Callable[..., Any]] = None,
    session_post: Optional[Callable[..., Any]] = None,
) -> Optional[str]:
    callback_params = extract_oauth_callback_params_from_consent_session(
        session=session,
        consent_url=consent_url,
        oauth_issuer=oauth_issuer,
        device_id=device_id,
        header_factory=header_factory,
        session_get=session_get,
        session_post=session_post,
    )
    auth_code = str((callback_params or {}).get("code") or "").strip()
    return auth_code or None


def exchange_codex_tokens_from_session(
    session: requests.Session,
    consent_url: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    code_verifier: str,
    *,
    auth_code: str = "",
    account_password: str = "",
    mail_provider: str = "",
    mailbox: Optional[Dict[str, Any]] = None,
    device_id: str = "",
    header_factory: Optional[Callable[[str], Dict[str, str]]] = None,
    session_get: Optional[Callable[..., Any]] = None,
    session_post: Optional[Callable[..., Any]] = None,
) -> Optional[Dict[str, Any]]:
    post_func = session_post or getattr(session, "post", None)
    if post_func is None:
        return None

    resolved_auth_code = str(auth_code or "").strip()
    if not resolved_auth_code:
        resolved_auth_code = str(
            extract_auth_code_from_consent_session(
                session=session,
                consent_url=consent_url,
                oauth_issuer=oauth_issuer,
                device_id=device_id,
                header_factory=header_factory,
                session_get=session_get,
                session_post=session_post,
            )
            or ""
        ).strip()
    if not resolved_auth_code:
        return None

    try:
        form_payload = {
            "grant_type": "authorization_code",
            "code": resolved_auth_code,
            "redirect_uri": str(oauth_redirect_uri or DEFAULT_REDIRECT_URI),
            "client_id": str(oauth_client_id or CLIENT_ID),
        }
        resolved_code_verifier = str(code_verifier or "").strip()
        if resolved_code_verifier:
            form_payload["code_verifier"] = resolved_code_verifier
        token_response = post_func(
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urllib.parse.urlencode(form_payload),
            timeout=30,
        )
    except Exception:
        return None

    if int(getattr(token_response, "status_code", 0) or 0) != 200:
        return None

    try:
        token_payload = token_response.json()
    except Exception:
        try:
            token_payload = json.loads(str(getattr(token_response, "text", "") or "{}"))
        except Exception:
            return None

    try:
        return json.loads(
            _build_token_result(
                token_payload,
                account_password=account_password,
                mail_provider=mail_provider,
                mailbox=mailbox,
            )
        )
    except Exception:
        return None


def login_existing_account_for_token(
    *,
    email: str,
    account_password: str,
    proxy: Optional[str] = None,
    mail_provider=None,
    mail_provider_name: str = "",
    mail_auth_credential: str = "",
    emitter: Optional[EventEmitter] = None,
    stop_event: Optional[threading.Event] = None,
    session_profile: Optional[SessionProfile] = None,
    _phone_gate_recycle_left: int = PHONE_GATE_RECYCLE_MAX_ATTEMPTS,
    _authorize_continue_retry_delays: tuple[int, ...] = AUTHORIZE_CONTINUE_RATE_LIMIT_RETRY_DELAYS_SECONDS,
    _signin_session_recycle_left: int = 2,
) -> Dict[str, Any]:
    email = str(email or "").strip()
    account_password = str(account_password or "").strip()
    resolved_mail_provider_name = str(
        mail_provider_name or _infer_mail_provider_name(mail_provider)
    ).strip().lower()
    mailbox_context = _build_mailbox_context(email=email, auth_credential=mail_auth_credential)
    emitter = emitter or EventEmitter(cli_mode=False)

    if not email or not account_password:
        return {"ok": False, "error": "账号文件 email 或 password 缺失", "fatal_deactivated": False}

    static_proxy = _normalize_proxy_value(proxy)
    static_proxies: Any = _to_proxies_dict(static_proxy)

    fingerprint_profile = _resolve_session_profile(session_profile=session_profile)
    chrome_ua = fingerprint_profile.user_agent
    session_headers = dict(fingerprint_profile.http_headers)
    session = requests.Session(impersonate=fingerprint_profile.impersonate)
    session.headers.update(session_headers)

    did = ""
    sentinel = None

    def _trace_headers() -> Dict[str, str]:
        trace_id = random.randint(10**17, 10**18 - 1)
        parent_id = random.randint(10**17, 10**18 - 1)
        tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
        return {
            "traceparent": tp,
            "tracestate": "dd=s:1;o:rum",
            "x-datadog-origin": "rum",
            "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": str(trace_id),
            "x-datadog-parent-id": str(parent_id),
        }

    def _session_get(url: str, **kwargs: Any):
        def _recover_request_func():
            nonlocal session
            old_session = session
            recovery_impersonate = _choose_tls_recovery_impersonate(fingerprint_profile.impersonate)
            new_session = requests.Session(impersonate=recovery_impersonate)
            new_session.headers.update(session_headers)
            _copy_session_cookies(old_session, new_session)
            try:
                old_session.close()
            except Exception:
                pass
            session = new_session
            emitter.warn("检测到瞬时 TLS 握手异常，已重建 OAuth 会话后重试", step="runtime")
            return session.get

        kwargs["proxies"] = static_proxies
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(
            session.get,
            url,
            recover_request_func_factory=_recover_request_func,
            **kwargs,
        )

    def _session_post(url: str, **kwargs: Any):
        def _recover_request_func():
            nonlocal session
            old_session = session
            recovery_impersonate = _choose_tls_recovery_impersonate(fingerprint_profile.impersonate)
            new_session = requests.Session(impersonate=recovery_impersonate)
            new_session.headers.update(session_headers)
            _copy_session_cookies(old_session, new_session)
            try:
                old_session.close()
            except Exception:
                pass
            session = new_session
            emitter.warn("检测到瞬时 TLS 握手异常，已重建 OAuth 会话后重试", step="runtime")
            return session.post

        kwargs["proxies"] = static_proxies
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(
            session.post,
            url,
            recover_request_func_factory=_recover_request_func,
            **kwargs,
        )

    def _sync_oai_device_cookie(device_id: str) -> None:
        if not device_id:
            return
        for domain in ("chatgpt.com", ".chatgpt.com", "auth.openai.com", ".auth.openai.com"):
            try:
                session.cookies.set("oai-did", device_id, domain=domain)
            except Exception:
                pass
        try:
            session.cookies.set("oai-did", device_id)
        except Exception:
            pass

    class _SentinelGen:
        MAX_ATTEMPTS = 500000
        ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

        def __init__(self, dev_id, session_profile):
            self.dev_id = dev_id
            self.session_profile = session_profile.validate()
            self.ua = self.session_profile.user_agent
            self.req_seed = str(random.random())
            self.sid = str(uuid.uuid4())

        @staticmethod
        def _fnv1a(text):
            h = 2166136261
            for ch in text:
                h ^= ord(ch)
                h = (h * 16777619) & 0xFFFFFFFF
            h ^= (h >> 16)
            h = (h * 2246822507) & 0xFFFFFFFF
            h ^= (h >> 13)
            h = (h * 3266489909) & 0xFFFFFFFF
            h ^= (h >> 16)
            return format(h & 0xFFFFFFFF, "08x")

        def _cfg(self):
            return _build_sentinel_identity_config(
                self.session_profile,
                session_id=self.sid,
            )

        @staticmethod
        def _b64(data):
            return base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()

        def _solve(self, seed, diff, cfg, nonce):
            cfg[3] = nonce
            cfg[9] = round((time.time() - self._t0) * 1000)
            data = self._b64(cfg)
            digest = self._fnv1a(seed + data)
            return (data + "~S") if digest[:len(diff)] <= diff else None

        def gen_token(self, seed=None, diff="0"):
            seed = seed or self.req_seed
            self._t0 = time.time()
            cfg = self._cfg()
            for i in range(self.MAX_ATTEMPTS):
                result = self._solve(seed, str(diff), cfg, i)
                if result:
                    return "gAAAAAB" + result
            return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))

        def gen_req_token(self):
            cfg = self._cfg()
            cfg[3] = 1
            cfg[9] = round(random.uniform(5, 50))
            return "gAAAAAC" + self._b64(cfg)

    def _build_sentinel(flow: str) -> Optional[str]:
        nonlocal sentinel
        if not did:
            return None
        if sentinel is None or str(getattr(sentinel, "dev_id", "") or "") != did:
            sentinel = _SentinelGen(did, fingerprint_profile)
        req_body = json.dumps({"p": sentinel.gen_req_token(), "id": did, "flow": flow})
        sen_resp = _session_post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": "https://sentinel.openai.com",
                "Referer": DEFAULT_BROWSER_SENTINEL_PAGE_URL,
            },
            data=req_body,
        )
        if sen_resp.status_code != 200:
            return None
        try:
            challenge = sen_resp.json()
        except Exception:
            return None
        challenge_token = challenge.get("token", "")
        if not challenge_token:
            return None
        pow_data = challenge.get("proofofwork") or {}
        if pow_data.get("required") and pow_data.get("seed"):
            proof_token = sentinel.gen_token(seed=pow_data["seed"], diff=pow_data.get("difficulty", "0"))
        else:
            proof_token = sentinel.gen_req_token()
        return json.dumps(
            {"p": proof_token, "t": "", "c": challenge_token, "id": did, "flow": flow},
            separators=(",", ":"),
        )

    def _build_sentinel_any(*flows: str) -> Optional[str]:
        seen: set[str] = set()
        for flow in flows:
            flow_name = str(flow or "").strip()
            if not flow_name or flow_name in seen:
                continue
            seen.add(flow_name)
            token = _build_sentinel(flow_name)
            if token:
                return token
        return None

    def _failure(message: str, *, fatal_deactivated: bool = False) -> Dict[str, Any]:
        is_deactivated = fatal_deactivated or _looks_deactivated_error(message)
        return {
            "ok": False,
            "error": message,
            "fatal_deactivated": is_deactivated,
            "identity_error_code": "alias_disabled" if is_deactivated else "",
        }

    def _retry_after_phone_gate(stage: str) -> Dict[str, Any]:
        if _phone_gate_recycle_left <= 0:
            return _failure(_phone_gate_error_message("OAuth "))
        emitter.warn(
            f"OAuth 在 {stage} 命中 add-phone，按 A 方案丢弃当前授权会话并重新生成授权地址重试...",
            step="get_token",
        )
        return login_existing_account_for_token(
            email=email,
            account_password=account_password,
            proxy=proxy,
            mail_provider=mail_provider,
            mail_provider_name=mail_provider_name,
            mail_auth_credential=mail_auth_credential,
            emitter=emitter,
            stop_event=stop_event,
            session_profile=fingerprint_profile,
            _phone_gate_recycle_left=_phone_gate_recycle_left - 1,
            _signin_session_recycle_left=_signin_session_recycle_left,
        )

    def _retry_after_expired_signin_session(stage: str, body_text: Any = "") -> Dict[str, Any]:
        if _signin_session_recycle_left <= 0:
            return _failure(f"{stage} 登录会话持续失效，已重试仍失败: {str(body_text or '')[:180]}")
        emitter.warn(
            f"{stage} 返回登录会话已失效，丢弃当前授权链并重新开始（剩余重试 {_signin_session_recycle_left}）...",
            step="get_token",
        )
        return login_existing_account_for_token(
            email=email,
            account_password=account_password,
            proxy=proxy,
            mail_provider=mail_provider,
            mail_provider_name=mail_provider_name,
            mail_auth_credential=mail_auth_credential,
            emitter=emitter,
            stop_event=stop_event,
            session_profile=fingerprint_profile,
            _phone_gate_recycle_left=_phone_gate_recycle_left,
            _authorize_continue_retry_delays=_authorize_continue_retry_delays,
            _signin_session_recycle_left=_signin_session_recycle_left - 1,
        )

    try:
        chatgpt_base = "https://chatgpt.com"
        codex_oauth = generate_oauth_url()
        signin_oauth = codex_oauth

        def _navigate_headers(referer: str = "") -> Dict[str, str]:
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": session_headers["Accept-Language"],
                "User-Agent": chrome_ua,
                "sec-ch-ua": session_headers["sec-ch-ua"],
                "sec-ch-ua-mobile": session_headers["sec-ch-ua-mobile"],
                "sec-ch-ua-platform": session_headers["sec-ch-ua-platform"],
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "same-origin",
                "sec-fetch-user": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
            if referer:
                headers["Referer"] = referer
            return headers

        def _oauth_headers(referer: str) -> Dict[str, str]:
            headers = {
                "Accept": "application/json",
                "Accept-Language": session_headers["Accept-Language"],
                "Content-Type": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": referer,
                "User-Agent": chrome_ua,
                "sec-ch-ua": session_headers["sec-ch-ua"],
                "sec-ch-ua-mobile": session_headers["sec-ch-ua-mobile"],
                "sec-ch-ua-platform": session_headers["sec-ch-ua-platform"],
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "oai-device-id": did,
            }
            headers.update(_trace_headers())
            return headers

        _session_get(f"{chatgpt_base}/", timeout=20)
        csrf_resp = _session_get(
            f"{chatgpt_base}/api/auth/csrf",
            headers={"Accept": "application/json", "Referer": f"{chatgpt_base}/"},
            timeout=15,
        )
        try:
            csrf_token = str((csrf_resp.json() or {}).get("csrfToken") or "").strip()
        except Exception:
            csrf_token = ""
        if not csrf_token:
            return _failure("获取 ChatGPT CSRF Token 失败")

        try:
            did = str(session.cookies.get("oai-did") or "").strip()  # type: ignore[attr-defined]
        except Exception:
            did = ""
        if not did:
            did = str(uuid.uuid4())
        _sync_oai_device_cookie(did)
        if stop_event is not None and stop_event.is_set():
            return _failure("重认证已取消")

        auth_session_id = str(uuid.uuid4())
        signin_params = urllib.parse.urlencode(
            _build_chatgpt_signin_params(
                email=email,
                device_id=did,
                auth_session_id=auth_session_id,
            )
        )
        signin_resp = _session_post(
            f"{chatgpt_base}/api/auth/signin/openai?{signin_params}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Referer": f"{chatgpt_base}/",
                "Origin": chatgpt_base,
            },
            data=urllib.parse.urlencode(
                {
                    "callbackUrl": f"{chatgpt_base}/",
                    "csrfToken": csrf_token,
                    "json": "true",
                }
            ),
            timeout=20,
        )
        try:
            authorize_url = str((signin_resp.json() or {}).get("url") or "").strip()
        except Exception:
            authorize_url = ""
        if not authorize_url:
            return _failure(f"signin/openai 失败: {str(signin_resp.text or '')[:220]}")

        signin_oauth = _resolve_oauth_start_from_authorize_url(authorize_url, codex_oauth)
        emitter.info("已拿到 signin/openai 返回的 authorize_url；仅请求首跳写入 auth 会话 cookie，不跟随跳转。", step="get_token")
        try:
            auth_entry_resp = _session_get(
                authorize_url,
                headers=_navigate_headers(f"{chatgpt_base}/"),
                timeout=20,
                allow_redirects=False,
            )
            if int(getattr(auth_entry_resp, "status_code", 0) or 0) >= 400:
                return _failure(f"authorize_url 首跳失败: HTTP {auth_entry_resp.status_code} {str(auth_entry_resp.text or '')[:180]}")
        except Exception as exc:
            return _failure(f"authorize_url 首跳建会话失败: {exc}")
        try:
            refreshed_did = str(session.cookies.get("oai-did") or "").strip()  # type: ignore[attr-defined]
        except Exception:
            refreshed_did = ""
        if refreshed_did:
            did = refreshed_did
            _sync_oai_device_cookie(did)
        if stop_event is not None and stop_event.is_set():
            return _failure("重认证已取消")

        sen_ac = _build_sentinel_any(*AUTHORIZE_CONTINUE_SENTINEL_FLOWS)
        if not sen_ac:
            return _failure("Sentinel token (authorize_continue) 获取失败")
        ac_headers = _oauth_headers("https://auth.openai.com/log-in-or-create-account")
        ac_headers["openai-sentinel-token"] = sen_ac
        ac_resp = _session_post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers=ac_headers,
            json={
                "username": {"kind": "email", "value": email},
                "screen_hint": "login_or_signup",
            },
        )
        if ac_resp is None:
            return _failure("Sentinel token (authorize_continue) 获取失败")
        if ac_resp.status_code != 200:
            body_preview = str(ac_resp.text or "")[:200]
            if _looks_rate_limited_text(body_preview) and _authorize_continue_retry_delays:
                retry_delay = max(1, int(_authorize_continue_retry_delays[0]))
                emitter.warn(
                    f"authorize/continue 命中限流，{retry_delay}s 后重建授权链重试...",
                    step="get_token",
                )
                if not _sleep_with_stop_event(retry_delay, stop_event):
                    return _failure("重认证已取消")
                return login_existing_account_for_token(
                    email=email,
                    account_password=account_password,
                    proxy=proxy,
                    mail_provider=mail_provider,
                    mail_provider_name=mail_provider_name,
                    mail_auth_credential=mail_auth_credential,
                    emitter=emitter,
                    stop_event=stop_event,
                    session_profile=fingerprint_profile,
                    _phone_gate_recycle_left=_phone_gate_recycle_left,
                    _authorize_continue_retry_delays=_authorize_continue_retry_delays[1:],
                    _signin_session_recycle_left=_signin_session_recycle_left,
                )
            return _failure(f"authorize/continue 失败: {body_preview}")

        try:
            ac_data = ac_resp.json() if ac_resp.text else {}
        except Exception:
            ac_data = {}
        consent_url = _extract_post_create_url(ac_data, chatgpt_base)
        page_type = str((ac_data.get("page") or {}).get("type", "")).strip() if isinstance(ac_data, dict) else ""
        next_path = str(urlparse(str(consent_url or "")).path or "").strip()
        emitter.info(
            f"authorize/continue next page={page_type or '<empty>'} path={next_path or '<empty>'}",
            step="get_token",
        )
        if _requires_phone_verification(ac_data, ac_resp.text, consent_url):
            return _retry_after_phone_gate("authorize_continue")

        if mail_provider is None or not str(mail_auth_credential or "").strip():
            return _failure("验证码登录必须可读取邮箱 OTP，但邮箱 provider/凭据不可用")

        otp_wait_started_at = time.time()
        otp_already_requested = (
            page_type == "email_otp_verification"
            or "email-verification" in str(consent_url or "")
            or "email-otp" in str(consent_url or "")
        )
        if otp_already_requested:
            emitter.info("authorize/continue 已进入邮箱验证码阶段，跳过 password/verify，等待 OTP。", step="send_otp")
        else:
            otp_send_headers = _oauth_headers("https://auth.openai.com/log-in")
            sen_otp_send = _build_sentinel_any(*EMAIL_VERIFICATION_SENTINEL_FLOWS, *AUTHORIZE_CONTINUE_SENTINEL_FLOWS)
            if sen_otp_send:
                otp_send_headers["openai-sentinel-token"] = sen_otp_send
            send_payloads = (
                {"email": email},
                {"username": {"kind": "email", "value": email}},
                {"email": {"kind": "email", "value": email}},
                {},
            )
            last_send_error = ""
            send_ok = False
            for payload in send_payloads:
                otp_send_resp = _session_post(
                    "https://auth.openai.com/api/accounts/email-otp/send",
                    headers=otp_send_headers,
                    json=payload,
                )
                status_code = int(getattr(otp_send_resp, "status_code", 0) or 0)
                body_text = str(getattr(otp_send_resp, "text", "") or "")[:240]
                if status_code in (200, 202, 204):
                    send_ok = True
                    try:
                        send_data = otp_send_resp.json() if getattr(otp_send_resp, "text", "") else {}
                    except Exception:
                        send_data = {}
                    consent_url = _extract_post_create_url(send_data, chatgpt_base) or consent_url
                    page_type = str((send_data.get("page") or {}).get("type", "")).strip() or page_type if isinstance(send_data, dict) else page_type
                    if _requires_phone_verification(send_data, body_text, consent_url):
                        return _retry_after_phone_gate("email_otp_send")
                    break
                last_send_error = f"HTTP {status_code} {body_text}"
                if _looks_rate_limited_text(body_text):
                    return _failure(f"email-otp/send 命中限流: {body_text}")
                if _looks_deactivated_error(body_text):
                    return _failure(body_text, fatal_deactivated=True)
                if status_code not in (400, 404, 422):
                    break
            if not send_ok:
                return _failure(f"email-otp/send 失败: {last_send_error}")
            otp_wait_started_at = time.time()
            emitter.info("已触发邮箱验证码发送，跳过 password/verify。", step="send_otp")

        otp_deadline = time.time() + OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS
        tried_codes: set[str] = set()
        while time.time() < otp_deadline:
            if stop_event is not None and stop_event.is_set():
                return _failure("重认证已取消")
            remaining_timeout = max(1, int(math.ceil(otp_deadline - time.time())))
            try:
                otp_code = mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=static_proxy,
                    timeout=remaining_timeout,
                    stop_event=stop_event,
                    sent_at_ts=otp_wait_started_at,
                    exclude_codes=tried_codes,
                )
            except TypeError:
                try:
                    otp_code = mail_provider.wait_for_otp(
                        mail_auth_credential,
                        email,
                        proxy=static_proxy,
                        timeout=remaining_timeout,
                        stop_event=stop_event,
                        sent_at_ts=otp_wait_started_at,
                    )
                except TypeError:
                    otp_code = mail_provider.wait_for_otp(
                        mail_auth_credential,
                        email,
                        proxy=static_proxy,
                        timeout=remaining_timeout,
                        stop_event=stop_event,
                    )
            if not otp_code:
                return _failure("验证码登录失败：未收到邮箱 OTP")
            if otp_code in tried_codes:
                _otp_poll_wait(stop_event)
                continue
            tried_codes.add(otp_code)
            otp_headers = _oauth_headers("https://auth.openai.com/email-verification")
            sen_otp = _build_sentinel_any(*EMAIL_VERIFICATION_SENTINEL_FLOWS)
            if sen_otp:
                otp_headers["openai-sentinel-token"] = sen_otp
            otp_resp = _session_post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=otp_headers,
                json={"code": otp_code},
            )
            if otp_resp.status_code == 200:
                try:
                    otp_data = otp_resp.json()
                except Exception:
                    otp_data = {}
                consent_url = _extract_post_create_url(otp_data, chatgpt_base) or consent_url
                page_type = str((otp_data.get("page") or {}).get("type", "")).strip() or page_type
                if _requires_phone_verification(otp_data, otp_resp.text, consent_url):
                    return _retry_after_phone_gate("email_otp_validate")
                break
            body_text = str(otp_resp.text or "")[:220]
            if _looks_deactivated_error(body_text):
                return _failure(body_text, fatal_deactivated=True)
            if _looks_wrong_otp_error(otp_resp.status_code, body_text):
                emitter.warn("OTP 被拒绝，已排除当前验证码，继续等待新验证码。", step="verify_otp")
                _otp_poll_wait(stop_event)
                continue
            if _is_expired_signin_session_response(otp_resp.status_code, body_text):
                return _retry_after_expired_signin_session("email-otp/validate", body_text)
            return _failure(f"email-otp/validate 失败: {body_text}")
        else:
            return _failure(f"验证码登录失败，已尝试 {len(tried_codes)} 个验证码")

        auth_root = "https://auth.openai.com"
        default_consent_url = f"{auth_root}/sign-in-with-chatgpt/codex/consent"
        if _is_about_you_step({"page": {"type": page_type}, "continue_url": consent_url}):
            emitter.info("OAuth 进入 about-you 阶段，继续补全资料...", step="get_token")
            about_you_resp = _session_get(
                f"{auth_root}/about-you",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://auth.openai.com/email-verification",
                    "Upgrade-Insecure-Requests": "1",
                },
                timeout=20,
            )
            about_you_final_url = str(getattr(about_you_resp, "url", "") or "").strip()
            if _requires_phone_verification(
                None,
                getattr(about_you_resp, "text", ""),
                about_you_final_url,
            ):
                return _retry_after_phone_gate("about_you_page")
            if "consent" in about_you_final_url or "organization" in about_you_final_url:
                consent_url = about_you_final_url
                page_type = "consent"
            else:
                profile = _generate_random_profile()
                sen_create_account = ""
                sen_create_account_so = ""
                try:
                    sen_create_account_bundle = _get_browser_sentinel_bundle_for_create_account(
                        browser_sentinel_config={
                            "enabled": True,
                            "headless": True,
                            "timeout_seconds": DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS,
                            "page_url": DEFAULT_BROWSER_SENTINEL_PAGE_URL,
                        },
                        proxy=proxy,
                        user_agent=chrome_ua,
                        session_profile=fingerprint_profile,
                    )
                    sen_create_account = str((sen_create_account_bundle or {}).get("token") or "").strip()
                    sen_create_account_so = str((sen_create_account_bundle or {}).get("so_token") or "").strip()
                except Exception:
                    sen_create_account = ""
                    sen_create_account_so = ""
                if not sen_create_account:
                    sen_create_account = _build_sentinel_any(*CREATE_ACCOUNT_SENTINEL_FLOWS)
                if not sen_create_account:
                    return _failure("Sentinel token (create_account) 获取失败")
                create_headers = _oauth_headers("https://auth.openai.com/about-you")
                create_headers["openai-sentinel-token"] = sen_create_account
                if sen_create_account_so:
                    create_headers["openai-sentinel-so-token"] = sen_create_account_so
                about_create_resp = _session_post(
                    "https://auth.openai.com/api/accounts/create_account",
                    headers=create_headers,
                    json=profile,
                )
                if about_create_resp.status_code != 200:
                    body_text = str(about_create_resp.text or "")[:220]
                    if _looks_deactivated_error(body_text):
                        return _failure(body_text, fatal_deactivated=True)
                    return _failure(f"OAuth about-you 提交失败: {body_text}")
                try:
                    about_data = about_create_resp.json()
                except Exception:
                    about_data = {}
                consent_url = _extract_post_create_url(about_data, chatgpt_base) or consent_url
                page_type = str((about_data.get("page") or {}).get("type", "")).strip() or page_type
                if _requires_phone_verification(about_data, about_create_resp.text, consent_url):
                    return _retry_after_phone_gate("about_you_submit")

        normalized_consent_url = str(consent_url or "").strip()
        if normalized_consent_url.startswith("/"):
            normalized_consent_url = _normalize_post_create_url(
                normalized_consent_url,
                chatgpt_base,
            )
        if not normalized_consent_url and "consent" in page_type:
            normalized_consent_url = default_consent_url

        session_token_data: Optional[Dict[str, Any]] = None
        session_token_json = _try_extract_chatgpt_session_token(
            continue_url=normalized_consent_url or default_consent_url,
            chatgpt_base=chatgpt_base,
            session_get=_session_get,
            emitter=emitter,
            account_password=account_password,
            mail_provider=resolved_mail_provider_name,
            mailbox=mailbox_context,
        )
        if session_token_json:
            try:
                session_token_data = json.loads(session_token_json)
            except Exception:
                session_token_data = None
            if isinstance(session_token_data, dict) and session_token_data:
                session_only_data = dict(session_token_data)
                session_only_data.pop("refresh_token", None)
                credentials = session_only_data.get("credentials")
                if isinstance(credentials, dict):
                    credentials.pop("refresh_token", None)
                session_only_data = _mark_token_payload_session_only(
                    session_only_data,
                    reason="relogin_session_only_no_refresh_token",
                    token_source=str(session_only_data.get("token_source") or "chatgpt_session"),
                )
                session_only_data.pop("refresh_token", None)
                credentials = session_only_data.get("credentials")
                if isinstance(credentials, dict):
                    credentials.pop("refresh_token", None)
                emitter.success(
                    "重登已获取 ChatGPT session/access_token；按配置保存 session-only，不进行 authorization code 交换/refresh_token 获取。",
                    step="get_token",
                )
                return {
                    "ok": True,
                    "token_data": session_only_data,
                    "fatal_deactivated": False,
                    "error": "",
                    "session_only": True,
                }

        return _failure("验证码登录完成但未获取到 ChatGPT session/access_token；已按要求停止，不进行 authorization code 交换")
    except Exception as exc:
        return _failure(f"运行时发生错误: {exc}")
    finally:
        try:
            session.close()
        except Exception:
            pass


# ==========================================
# 核心注册逻辑
# ==========================================

from . import CONFIG_FILE as _PKG_CONFIG_FILE, TOKENS_DIR as _PKG_TOKENS_DIR, PACKAGE_DIR as _PKG_PACKAGE_DIR

TOKENS_DIR = str(_PKG_TOKENS_DIR)
CONFIG_FILE = str(_PKG_CONFIG_FILE)
PACKAGE_DIR = _PKG_PACKAGE_DIR


def run(
    proxy: Optional[str],
    emitter: EventEmitter = _cli_emitter,
    stop_event: Optional[threading.Event] = None,
    mail_provider=None,
    mail_provider_name: str = "",
    proxy_pool_config: Optional[Dict[str, Any]] = None,
    browser_sentinel_config: Optional[Dict[str, Any]] = None,
    session_profile: Optional[SessionProfile] = None,
) -> Optional[str]:
    static_proxy = _normalize_proxy_value(proxy)
    static_proxies: Any = _to_proxies_dict(static_proxy)

    pool_cfg_raw = proxy_pool_config or {}
    pool_cfg = {
        "enabled": bool(pool_cfg_raw.get("enabled", False)),
        "api_url": str(pool_cfg_raw.get("api_url") or DEFAULT_PROXY_POOL_URL).strip() or DEFAULT_PROXY_POOL_URL,
        "auth_mode": str(pool_cfg_raw.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower() or DEFAULT_PROXY_POOL_AUTH_MODE,
        "api_key": str(pool_cfg_raw.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY,
        "count": pool_cfg_raw.get("count", DEFAULT_PROXY_POOL_COUNT),
        "country": str(pool_cfg_raw.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY,
        "timeout_seconds": int(pool_cfg_raw.get("timeout_seconds") or 10),
    }
    if pool_cfg["auth_mode"] not in ("header", "query"):
        pool_cfg["auth_mode"] = DEFAULT_PROXY_POOL_AUTH_MODE
    try:
        pool_cfg["count"] = max(1, min(int(pool_cfg.get("count") or DEFAULT_PROXY_POOL_COUNT), 20))
    except (TypeError, ValueError):
        pool_cfg["count"] = DEFAULT_PROXY_POOL_COUNT

    last_pool_proxy = ""
    pool_fail_streak = 0
    warned_fallback = False
    browser_sentinel_cfg = _normalize_browser_sentinel_config(browser_sentinel_config)
    browser_entry_cfg = _normalize_browser_entry_config(browser_sentinel_config)
    resolved_mail_provider_name = str(
        mail_provider_name or _infer_mail_provider_name(mail_provider)
    ).strip().lower()

    def _next_proxy_value() -> str:
        nonlocal last_pool_proxy, pool_fail_streak, warned_fallback
        if pool_cfg["enabled"]:
            max_fetch_retries = max(1, int(pool_cfg.get("fetch_retries") or POOL_PROXY_FETCH_RETRIES))
            last_error = ""
            for _ in range(max_fetch_retries):
                try:
                    fetched = _fetch_proxy_from_pool(pool_cfg)
                    if fetched and not _proxy_tcp_reachable(fetched):
                        last_error = f"代理池代理不可达: {fetched}"
                        continue
                    last_pool_proxy = fetched
                    pool_fail_streak = 0
                    warned_fallback = False
                    return fetched
                except Exception as e:
                    last_error = str(e)

            pool_fail_streak += 1
            if static_proxy:
                if not warned_fallback:
                    emitter.warn(f"代理池不可用，回退固定代理: {last_error or 'unknown error'}", step="check_proxy")
                    warned_fallback = True
                return static_proxy
            if pool_fail_streak <= 3:
                emitter.warn(f"代理池不可用: {last_error or 'unknown error'}", step="check_proxy")
            return ""
        return static_proxy
    def _next_proxies() -> Any:
        proxy_value = _next_proxy_value()
        return _to_proxies_dict(proxy_value)

    # HTTP、浏览器预热、OAuth 和 Sentinel 在一次任务内共享同一个不可变身份。
    session_profile = _resolve_session_profile(
        session_profile=session_profile,
        scope=str(browser_sentinel_cfg.get("fingerprint_scope") or DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE),
    )
    _chrome_ua = session_profile.user_agent
    session_headers = dict(session_profile.http_headers)
    s = requests.Session(impersonate=session_profile.impersonate)
    s.headers.update(session_headers)

    def _trace_headers() -> Dict[str, str]:
        """生成 DataDog trace headers，模拟真实浏览器监控"""
        trace_id = random.randint(10**17, 10**18 - 1)
        parent_id = random.randint(10**17, 10**18 - 1)
        tp = f"00-{uuid.uuid4().hex}-{format(parent_id, '016x')}-01"
        return {
            "traceparent": tp, "tracestate": "dd=s:1;o:rum",
            "x-datadog-origin": "rum", "x-datadog-sampling-priority": "1",
            "x-datadog-trace-id": str(trace_id), "x-datadog-parent-id": str(parent_id),
        }

    def _auth_api_headers(referer: str, *, include_device_id: bool = False) -> Dict[str, str]:
        headers = {
            "accept": "application/json",
            "accept-language": session_headers["Accept-Language"],
            "content-type": "application/json",
            "origin": "https://auth.openai.com",
            "referer": referer,
            "user-agent": _chrome_ua,
            "sec-ch-ua": session_headers["sec-ch-ua"],
            "sec-ch-ua-mobile": session_headers["sec-ch-ua-mobile"],
            "sec-ch-ua-platform": session_headers["sec-ch-ua-platform"],
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if include_device_id and did:
            headers["oai-device-id"] = did
        return headers

    def _navigate_headers(referer: str = "") -> Dict[str, str]:
        headers = {
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": session_headers["Accept-Language"],
            "user-agent": _chrome_ua,
            "sec-ch-ua": session_headers["sec-ch-ua"],
            "sec-ch-ua-mobile": session_headers["sec-ch-ua-mobile"],
            "sec-ch-ua-platform": session_headers["sec-ch-ua-platform"],
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        }
        if referer:
            headers["referer"] = referer
        return headers
    pool_relay_url = _pool_relay_url_from_fetch_url(str(pool_cfg.get("api_url") or ""))
    pool_relay_enabled = bool(
        pool_cfg["enabled"]
        and pool_relay_url
        and str(pool_cfg.get("auth_mode") or DEFAULT_PROXY_POOL_AUTH_MODE).strip().lower() == "query"
    )
    relay_cookie_jar: Dict[str, str] = {}
    pool_relay_api_key = str(pool_cfg.get("api_key") or DEFAULT_PROXY_POOL_API_KEY).strip() or DEFAULT_PROXY_POOL_API_KEY
    pool_relay_country = str(pool_cfg.get("country") or DEFAULT_PROXY_POOL_COUNTRY).strip().upper() or DEFAULT_PROXY_POOL_COUNTRY
    relay_fallback_warned = False
    relay_bypass_openai_hosts = False
    openai_relay_probe_done = False
    mail_proxy_selector = None if pool_relay_enabled else _next_proxy_value
    mail_proxies_selector = None if pool_relay_enabled else _next_proxies

    def _fallback_proxies_for_relay_failure() -> Any:
        if static_proxy:
            return _to_proxies_dict(static_proxy)
        return None

    def _target_host(target_url: str) -> str:
        return str(urlparse(str(target_url or "")).hostname or "").strip().lower()

    def _is_openai_like_host(host: str) -> bool:
        return bool(host) and (host.endswith("openai.com") or host.endswith("chatgpt.com"))

    def _should_bypass_relay_for_target(target_url: str) -> bool:
        host = _target_host(target_url)
        return relay_bypass_openai_hosts and _is_openai_like_host(host)

    def _warn_relay_fallback(reason: str, target_url: str) -> None:
        nonlocal relay_fallback_warned, relay_bypass_openai_hosts
        host = _target_host(target_url) or str(target_url or "?")
        if _is_openai_like_host(host):
            relay_bypass_openai_hosts = True
        if relay_fallback_warned:
            return
        if static_proxy:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退固定代理: {reason}", step="check_proxy")
        else:
            emitter.warn(f"代理池 relay 对 {host} 不可用，回退直连: {reason}", step="check_proxy")
        relay_fallback_warned = True

    def _update_relay_cookie_jar(resp: Any) -> None:
        try:
            for k, v in (resp.cookies or {}).items():
                key = str(k or "").strip()
                if key:
                    relay_cookie_jar[key] = str(v or "")
        except Exception:
            pass
        set_cookie_values: list[str] = []
        try:
            values = resp.headers.get_list("set-cookie")  # type: ignore[attr-defined]
            if values:
                set_cookie_values.extend(str(v or "") for v in values if str(v or "").strip())
        except Exception:
            pass
        if not set_cookie_values:
            try:
                set_cookie_raw = str(resp.headers.get("set-cookie") or "")
                if set_cookie_raw.strip():
                    set_cookie_values.append(set_cookie_raw)
            except Exception:
                pass
        for set_cookie_raw in set_cookie_values:
            try:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(set_cookie_raw)
                for k, morsel in parsed_cookie.items():
                    key = str(k or "").strip()
                    if key:
                        relay_cookie_jar[key] = str(morsel.value or "")
            except Exception:
                pass
        try:
            for k, v in relay_cookie_jar.items():
                s.cookies.set(k, v)
        except Exception:
            pass

    def _request_via_pool_relay(method: str, target_url: str, **kwargs: Any):
        if not pool_relay_enabled:
            raise RuntimeError("代理池 relay 未启用")
        relay_retries_override = kwargs.pop("_relay_retries", None)
        relay_params = {
            "api_key": pool_relay_api_key,
            "url": str(target_url),
            "method": str(method or "GET").upper(),
            "country": pool_relay_country,
        }
        target_params = kwargs.pop("params", None)
        if target_params:
            query_text = urlencode(target_params, doseq=True)
            if query_text:
                separator = "&" if "?" in relay_params["url"] else "?"
                relay_params["url"] = f"{relay_params['url']}{separator}{query_text}"

        headers = dict(kwargs.pop("headers", {}) or {})
        if relay_cookie_jar and not any(str(k).lower() == "cookie" for k in headers.keys()):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in relay_cookie_jar.items())
        kwargs.pop("proxies", None)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 20)

        method_upper = relay_params["method"]
        retry_count = max(
            1,
            int(
                relay_retries_override
                if relay_retries_override is not None
                else (pool_cfg.get("relay_request_retries") or POOL_RELAY_REQUEST_RETRIES)
            ),
        )
        last_error = ""
        for i in range(retry_count):
            try:
                resp = _call_with_http_fallback(
                    lambda relay_endpoint, **call_kwargs: requests.request(method_upper, relay_endpoint, **call_kwargs),
                    pool_relay_url,
                    params=relay_params,
                    headers=headers or None,
                    **kwargs,
                )
                _update_relay_cookie_jar(resp)
                if resp.status_code >= 500 or resp.status_code == 429:
                    last_error = f"HTTP {resp.status_code}"
                    if i < retry_count - 1:
                        time.sleep(min(0.2 * (i + 1), 0.6))
                        continue
                return resp
            except Exception as exc:
                last_error = str(exc)
                if i < retry_count - 1:
                    time.sleep(min(0.2 * (i + 1), 0.6))
        raise RuntimeError(f"代理池 relay 请求失败: {last_error or 'unknown error'}")

    def _ensure_openai_relay_ready() -> None:
        nonlocal openai_relay_probe_done
        if not pool_relay_enabled or relay_bypass_openai_hosts or openai_relay_probe_done:
            return
        openai_relay_probe_done = True
        probe_url = "https://auth.openai.com/"
        try:
            probe_resp = _request_via_pool_relay(
                "GET",
                probe_url,
                timeout=5,
                allow_redirects=False,
                _relay_retries=1,
            )
            status = int(probe_resp.status_code or 0)
            if status < 200 or status >= 400:
                raise RuntimeError(f"HTTP {status}")
            emitter.info("代理池 relay OpenAI 预检通过", step="check_proxy")
        except Exception as exc:
            _warn_relay_fallback(f"{exc} (OpenAI 预检)", probe_url)

    def _session_get(url: str, **kwargs: Any):
        def _recover_request_func():
            nonlocal s
            old_session = s
            new_session = requests.Session(impersonate=session_profile.impersonate)
            new_session.headers.update(session_headers)
            _copy_session_cookies(old_session, new_session)
            try:
                old_session.close()
            except Exception:
                pass
            s = new_session
            emitter.warn("检测到瞬时 TLS 握手异常，已重建注册会话后重试", step="runtime")
            return s.get

        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(
                    s.get,
                    url,
                    recover_request_func_factory=_recover_request_func,
                    **kwargs,
                )
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(
                s.get,
                url,
                recover_request_func_factory=_recover_request_func,
                **kwargs,
            )
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(
            s.get,
            url,
            recover_request_func_factory=_recover_request_func,
            **kwargs,
        )

    def _session_post(url: str, **kwargs: Any):
        def _recover_request_func():
            nonlocal s
            old_session = s
            new_session = requests.Session(impersonate=session_profile.impersonate)
            new_session.headers.update(session_headers)
            _copy_session_cookies(old_session, new_session)
            try:
                old_session.close()
            except Exception:
                pass
            s = new_session
            emitter.warn("检测到瞬时 TLS 握手异常，已重建注册会话后重试", step="runtime")
            return s.post

        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(
                    s.post,
                    url,
                    recover_request_func_factory=_recover_request_func,
                    **kwargs,
                )
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(
                s.post,
                url,
                recover_request_func_factory=_recover_request_func,
                **kwargs,
            )
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(
            s.post,
            url,
            recover_request_func_factory=_recover_request_func,
            **kwargs,
        )

    def _raw_get(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("GET", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", "chrome")
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.get, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", "chrome")
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.get, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.get, url, **kwargs)

    def _raw_post(url: str, **kwargs: Any):
        if pool_relay_enabled and not _should_bypass_relay_for_target(url):
            try:
                relay_resp = _request_via_pool_relay("POST", url, **kwargs)
                if relay_resp.status_code < 500 and relay_resp.status_code != 429:
                    return relay_resp
                raise RuntimeError(f"HTTP {relay_resp.status_code}")
            except Exception as exc:
                _warn_relay_fallback(str(exc), url)
                kwargs["proxies"] = _fallback_proxies_for_relay_failure()
                kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
                kwargs.setdefault("impersonate", "chrome")
                kwargs.setdefault("timeout", 20)
                return _call_with_http_fallback(requests.post, url, **kwargs)
        if pool_relay_enabled and _should_bypass_relay_for_target(url):
            kwargs["proxies"] = _fallback_proxies_for_relay_failure()
            kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
            kwargs.setdefault("impersonate", "chrome")
            kwargs.setdefault("timeout", 20)
            return _call_with_http_fallback(requests.post, url, **kwargs)
        kwargs["proxies"] = _next_proxies()
        kwargs.setdefault("http_version", DEFAULT_HTTP_VERSION)
        kwargs.setdefault("impersonate", "chrome")
        kwargs.setdefault("timeout", 15)
        return _call_with_http_fallback(requests.post, url, **kwargs)

    def _submit_callback_url_via_pool_relay(
        *,
        callback_url: str,
        expected_state: str,
        code_verifier: str,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
    ) -> str:
        cb = _parse_callback_url(callback_url)
        if cb["error"]:
            desc = cb["error_description"]
            raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())
        if not cb["code"]:
            raise ValueError("callback url missing ?code=")
        if not cb["state"]:
            raise ValueError("callback url missing ?state=")
        if cb["state"] != expected_state:
            raise ValueError("state mismatch")

        token_resp = _request_via_pool_relay(
            "POST",
            TOKEN_URL,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urllib.parse.urlencode(
                {
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "code": cb["code"],
                    "redirect_uri": redirect_uri,
                    "code_verifier": code_verifier,
                }
            ),
            timeout=30,
        )
        if token_resp.status_code != 200:
            raise RuntimeError(
                f"token exchange failed: {token_resp.status_code}: {str(token_resp.text or '')[:240]}"
            )
        try:
            token_json = token_resp.json()
        except Exception:
            token_json = json.loads(str(token_resp.text or "{}"))

        return _build_token_result(token_json, account_password=account_password)

    did = ""
    _sentinel = None

    def _sync_oai_device_cookie(device_id: str) -> None:
        if not device_id:
            return
        relay_cookie_jar["oai-did"] = device_id
        for domain in ("chatgpt.com", ".chatgpt.com", "auth.openai.com", ".auth.openai.com"):
            try:
                s.cookies.set("oai-did", device_id, domain=domain)
            except Exception:
                pass
        try:
            s.cookies.set("oai-did", device_id)
        except Exception:
            pass

    class _SentinelGen:
        MAX_ATTEMPTS = 500000
        ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

        def __init__(self, dev_id, session_profile):
            self.dev_id = dev_id
            self.session_profile = session_profile.validate()
            self.ua = self.session_profile.user_agent
            self.req_seed = str(random.random())
            self.sid = str(uuid.uuid4())

        @staticmethod
        def _fnv1a(text):
            h = 2166136261
            for ch in text:
                h ^= ord(ch)
                h = (h * 16777619) & 0xFFFFFFFF
            h ^= (h >> 16)
            h = (h * 2246822507) & 0xFFFFFFFF
            h ^= (h >> 13)
            h = (h * 3266489909) & 0xFFFFFFFF
            h ^= (h >> 16)
            return format(h & 0xFFFFFFFF, "08x")

        def _cfg(self):
            return _build_sentinel_identity_config(
                self.session_profile,
                session_id=self.sid,
            )

        @staticmethod
        def _b64(data):
            return base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()

        def _solve(self, seed, diff, cfg, nonce):
            cfg[3] = nonce
            cfg[9] = round((time.time() - self._t0) * 1000)
            data = self._b64(cfg)
            digest = self._fnv1a(seed + data)
            return (data + "~S") if digest[:len(diff)] <= diff else None

        def gen_token(self, seed=None, diff="0"):
            seed = seed or self.req_seed
            self._t0 = time.time()
            cfg = self._cfg()
            for i in range(self.MAX_ATTEMPTS):
                result = self._solve(seed, str(diff), cfg, i)
                if result:
                    return "gAAAAAB" + result
            return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))

        def gen_req_token(self):
            cfg = self._cfg()
            cfg[3] = 1
            cfg[9] = round(random.uniform(5, 50))
            return "gAAAAAC" + self._b64(cfg)

    def _build_sentinel(flow: str) -> Optional[str]:
        nonlocal _sentinel
        if not did:
            return None
        if _sentinel is None or str(getattr(_sentinel, "dev_id", "") or "") != did:
            _sentinel = _SentinelGen(did, session_profile)
        req_body = json.dumps({"p": _sentinel.gen_req_token(), "id": did, "flow": flow})
        sen_resp = _session_post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": "https://sentinel.openai.com",
                "Referer": DEFAULT_BROWSER_SENTINEL_PAGE_URL,
            },
            data=req_body,
        )
        if sen_resp.status_code != 200:
            return None
        try:
            challenge = sen_resp.json()
        except Exception:
            return None
        challenge_token = challenge.get("token", "")
        if not challenge_token:
            return None
        pow_data = challenge.get("proofofwork") or {}
        if pow_data.get("required") and pow_data.get("seed"):
            proof_token = _sentinel.gen_token(seed=pow_data["seed"], diff=pow_data.get("difficulty", "0"))
        else:
            proof_token = _sentinel.gen_req_token()
        return json.dumps(
            {"p": proof_token, "t": "", "c": challenge_token, "id": did, "flow": flow},
            separators=(",", ":"),
        )

    def _build_sentinel_any(*flows: str) -> Optional[str]:
        seen: set[str] = set()
        for flow in flows:
            flow_name = str(flow or "").strip()
            if not flow_name or flow_name in seen:
                continue
            seen.add(flow_name)
            token = _build_sentinel(flow_name)
            if token:
                return token
        return None

    def _create_account_browser_sentinel_config(*, force_headless: Optional[bool] = None) -> Dict[str, Any]:
        cfg = dict(browser_sentinel_cfg)
        if not bool(cfg.get("enabled")):
            # 兼容旧 GUI 配置：create_account 阶段始终按 gmailreg-v2 无头浏览器协议取 token。
            cfg["enabled"] = True
            cfg["headless"] = True
        if force_headless is not None:
            cfg["headless"] = bool(force_headless)
        return cfg

    _sentinel_prefetch_lock = threading.Lock()
    _sentinel_prefetch_started = False
    _sentinel_prefetch_started_at = 0.0
    _sentinel_prefetch_done = threading.Event()
    _sentinel_prefetch_bundle: Dict[str, Any] = {}
    _sentinel_prefetch_error = ""

    def _fetch_create_account_browser_sentinel(cfg: Dict[str, Any]) -> Dict[str, Any]:
        return _get_browser_sentinel_bundle_for_create_account(
            browser_sentinel_config=cfg,
            proxy=static_proxy,
            user_agent=_chrome_ua,
            session_profile=session_profile,
        )

    def _start_create_account_sentinel_prefetch(step: str = "wait_otp") -> None:
        nonlocal _sentinel_prefetch_started, _sentinel_prefetch_started_at
        nonlocal _sentinel_prefetch_bundle, _sentinel_prefetch_error
        with _sentinel_prefetch_lock:
            if _sentinel_prefetch_started:
                return
            _sentinel_prefetch_started = True
            _sentinel_prefetch_started_at = time.time()
            prefetch_cfg = _create_account_browser_sentinel_config(force_headless=True)

        def _worker() -> None:
            nonlocal _sentinel_prefetch_bundle, _sentinel_prefetch_error
            try:
                _sentinel_prefetch_bundle = _fetch_create_account_browser_sentinel(prefetch_cfg)
            except Exception as exc:
                _sentinel_prefetch_error = str(exc)
            finally:
                _sentinel_prefetch_done.set()

        threading.Thread(target=_worker, name="create-account-sentinel-prefetch", daemon=True).start()
        emitter.info("已开始后台预取 create_account 浏览器 Sentinel（与邮箱 OTP 等待并行）", step=step)

    def _get_create_account_browser_sentinel_bundle(cfg: Dict[str, Any]) -> Dict[str, Any]:
        if _sentinel_prefetch_started:
            elapsed = max(0.0, time.time() - _sentinel_prefetch_started_at)
            if not _sentinel_prefetch_done.is_set():
                emitter.info(
                    f"等待后台 Sentinel 预取结果（已并行 {elapsed:.1f}s）...",
                    step="create_account",
                )
            wait_timeout = max(3, int(cfg.get("timeout_seconds") or DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS) + 5)
            if _sentinel_prefetch_done.wait(timeout=wait_timeout):
                if _sentinel_prefetch_bundle:
                    total_elapsed = max(0.0, time.time() - _sentinel_prefetch_started_at)
                    emitter.info(
                        f"后台 Sentinel 预取命中，总耗时 {total_elapsed:.1f}s",
                        step="create_account",
                    )
                    return dict(_sentinel_prefetch_bundle)
                if _sentinel_prefetch_error:
                    emitter.warn(f"后台 Sentinel 预取失败，改为同步获取: {_sentinel_prefetch_error}", step="create_account")
            else:
                emitter.warn("后台 Sentinel 预取超时，改为同步获取一次", step="create_account")
        return _fetch_create_account_browser_sentinel(cfg)

    def _stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        # ------- 步骤1：网络环境检查 -------
        emitter.info("正在检查网络环境...", step="check_proxy")
        try:
            trace_text = ""
            relay_error = ""
            relay_used = False
            if pool_relay_enabled:
                try:
                    trace_text = _trace_via_pool_relay(pool_cfg)
                    relay_used = True
                except Exception as e:
                    relay_error = str(e)
                    if static_proxy:
                        emitter.warn(f"代理池 relay 检查失败，回退固定代理: {relay_error}", step="check_proxy")
                    else:
                        emitter.warn(f"代理池 relay 检查失败，尝试直连代理: {relay_error}", step="check_proxy")
            if not trace_text:
                trace_errors = []
                for probe_url in (
                    "https://cloudflare.com/cdn-cgi/trace",
                    "https://ipinfo.io/json",
                    "https://api.myip.com",
                ):
                    try:
                        trace_resp = _session_get(probe_url, timeout=10)
                        if "cdn-cgi/trace" in probe_url:
                            trace_text = str(trace_resp.text or "")
                        else:
                            try:
                                payload = trace_resp.json()
                            except Exception:
                                payload = {}
                            if isinstance(payload, dict):
                                ip_value = str(payload.get("ip") or "").strip()
                                loc_value = str(payload.get("country") or payload.get("countryCode") or "").strip()
                                if ip_value or loc_value:
                                    trace_text = f"ip={ip_value}\nloc={loc_value}\n"
                        if trace_text:
                            break
                    except Exception as probe_exc:
                        trace_errors.append(f"{probe_url}: {probe_exc}")
                if not trace_text:
                    raise RuntimeError("出口 IP 探测失败: " + " | ".join(trace_errors[-2:]))
            trace = trace_text
            loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
            loc = loc_re.group(1) if loc_re else None
            ip_re = re.search(r"^ip=(.+)$", trace, re.MULTILINE)
            current_ip = ip_re.group(1).strip() if ip_re else ""
            if relay_used:
                emitter.info("代理池 relay 连通检查成功", step="check_proxy")
            emitter.info(f"当前 IP 所在地: {loc}", step="check_proxy")
            if current_ip:
                emitter.info(f"当前出口 IP: {current_ip}", step="check_proxy")
            if loc == "CN" or loc == "HK":
                emitter.error("检查代理哦 — 所在地不支持 (CN/HK)", step="check_proxy")
                return None
            emitter.success("网络环境检查通过", step="check_proxy")
            _ensure_openai_relay_ready()
            _start_create_account_sentinel_prefetch(step="check_proxy")
        except Exception as e:
            emitter.error(f"网络连接检查失败: {e}", step="check_proxy")
            return None

        if _stopped():
            return None

        # ------- 步骤2：准备邮箱 -------
        if mail_provider is not None:
            if resolved_mail_provider_name == "appleemail_hotmail":
                mailbox_action_label = "Outlook/Hotmail 邮箱 alias"
                emitter.info("正在准备 Outlook/Hotmail 邮箱 alias...", step="create_email")
            else:
                mailbox_action_label = "邮箱"
                emitter.info("正在准备邮箱...", step="create_email")
            try:
                email, dev_token = mail_provider.create_mailbox(
                    proxy=static_proxy,
                    proxy_selector=mail_proxy_selector,
                )
            except TypeError:
                email, dev_token = mail_provider.create_mailbox(proxy=static_proxy)
        else:
            mailbox_action_label = "Mail.tm 临时邮箱"
            emitter.info("正在创建 Mail.tm 临时邮箱...", step="create_email")
            email, dev_token = get_email_and_token(
                static_proxies,
                emitter,
                proxy_selector=mail_proxies_selector,
            )
        if not email or not dev_token:
            emitter.error(f"{mailbox_action_label}准备失败", step="create_email")
            return None
        emitter.success(f"{mailbox_action_label}准备成功: {email}", step="create_email")
        mailbox_context = _build_mailbox_context(email=email, auth_credential=dev_token)

        # 生成随机密码（密码注册流程需要）
        _pw_chars = string.ascii_letters + string.digits + "!@#$%&*"
        account_password = "".join(secrets.choice(_pw_chars) for _ in range(16))

        if _stopped():
            return None

        # ------- 步骤3：通过 chatgpt.com 建立注册会话 -------
        emitter.info("正在访问 ChatGPT 首页...", step="oauth_init")
        _chatgpt_base = "https://chatgpt.com"

        # 3a: 访问首页，获取 cookies
        _session_get(f"{_chatgpt_base}/", timeout=20)

        # 3b: 获取 CSRF Token
        csrf_resp = _session_get(
            f"{_chatgpt_base}/api/auth/csrf",
            headers={"Accept": "application/json", "Referer": f"{_chatgpt_base}/"},
            timeout=15,
        )
        try:
            csrf_token = csrf_resp.json().get("csrfToken", "")
        except Exception:
            csrf_token = ""
        if not csrf_token:
            try:
                browser_token_json = _fallback_on_chatgpt_csrf_failure(
                    csrf_response=csrf_resp,
                    email=email,
                    account_password=account_password,
                    mail_provider=mail_provider,
                    mail_auth_credential=dev_token,
                    emitter=emitter,
                    stop_event=stop_event,
                    proxy=static_proxy,
                    user_agent=_chrome_ua,
                    session_profile=session_profile,
                    browser_entry_config=browser_entry_cfg,
                    browser_sentinel_config=browser_sentinel_cfg,
                    mail_provider_name=resolved_mail_provider_name,
                )
            except Exception as exc:
                emitter.error(f"获取 CSRF Token 失败，浏览器全流程回退异常: {exc}", step="oauth_init")
                return None
            if browser_token_json:
                emitter.success("ChatGPT CSRF 回退到浏览器全流程成功", step="get_token")
                try:
                    s.close()
                except Exception:
                    pass
                return browser_token_json
            emitter.error("获取 CSRF Token 失败", step="oauth_init")
            return None

        # 3c: 生成 Device ID
        did = s.cookies.get("oai-did") or relay_cookie_jar.get("oai-did") or ""
        if not did:
            did = str(uuid.uuid4())
        _sync_oai_device_cookie(did)

        # 3d: Signin 请求，获取 authorize URL
        auth_session_id = str(uuid.uuid4())
        signin_params = urllib.parse.urlencode(
            _build_chatgpt_signin_params(
                email=email,
                device_id=did,
                auth_session_id=auth_session_id,
            )
        )
        signin_resp = _session_post(
            f"{_chatgpt_base}/api/auth/signin/openai?{signin_params}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Referer": f"{_chatgpt_base}/",
                "Origin": _chatgpt_base,
            },
            data=urllib.parse.urlencode({
                "callbackUrl": f"{_chatgpt_base}/",
                "csrfToken": csrf_token,
                "json": "true",
            }),
            timeout=20,
        )
        try:
            authorize_url = signin_resp.json().get("url", "")
        except Exception:
            authorize_url = ""
        if not authorize_url:
            emitter.error(
                f"Signin 获取授权链接失败（{signin_resp.status_code}）: {str(signin_resp.text or '')[:220]}",
                step="oauth_init",
            )
            return None
        emitter.info(f"OAuth 初始化状态: {signin_resp.status_code}", step="oauth_init")

        # 3e: 跟随 authorize 重定向，建立 auth.openai.com 会话
        auth_resp = _session_get(
            authorize_url,
            headers=_navigate_headers(referer=f"{_chatgpt_base}/"),
            timeout=20,
        )
        final_url = str(auth_resp.url) if hasattr(auth_resp, "url") else ""
        emitter.info(f"Authorize 重定向完成: {final_url[:120]}", step="oauth_init")
        emitter.info(f"Device ID: {did}", step="oauth_init")
        signup_entry_url = final_url or authorize_url
        if not _can_continue_signup_after_authorize(signup_entry_url):
            emitter.error(
                f"Authorize 未进入注册页，当前 URL: {(signup_entry_url or final_url or '-')[:220]}",
                step="oauth_init",
            )
            return None
        if not _is_signup_entry_url(signup_entry_url):
            emitter.warn(
                f"Authorize 直接进入注册续流程页，按抓包链路继续 OTP/资料提交: {(signup_entry_url or final_url or '-')[:140]}",
                step="oauth_init",
            )
        else:
            try:
                bootstrap_resp = _session_get(
                    signup_entry_url,
                    headers=_navigate_headers(referer="https://auth.openai.com/log-in-or-create-account"),
                    timeout=20,
                )
            except Exception as exc:
                emitter.error(f"注册页预热失败: {exc}", step="oauth_init")
                return None
            if bootstrap_resp.status_code >= 400:
                if _looks_like_cloudflare_challenge_response(bootstrap_resp):
                    warmed_signup_url = _warmup_auth_entry_with_browser(
                        target_url=signup_entry_url,
                        session=s,
                        emitter=emitter,
                        step="oauth_init",
                        browser_entry_config=browser_entry_cfg,
                        proxy=static_proxy,
                        user_agent=_chrome_ua,
                        session_profile=session_profile,
                    )
                    if not warmed_signup_url:
                        return None
                    signup_entry_url = warmed_signup_url
                    emitter.info(f"注册页预热完成: {signup_entry_url[:120]}", step="oauth_init")
                    if _stopped():
                        return None
                    # 浏览器已成功完成入口验证，继续后续注册请求
                    pass
                else:
                    emitter.error(
                        f"注册页预热失败（状态码 {bootstrap_resp.status_code}）: {(str(bootstrap_resp.text or '')[:220])}",
                        step="oauth_init",
                    )
                    return None
            else:
                signup_entry_url = str(getattr(bootstrap_resp, "url", "") or signup_entry_url)
                emitter.info(f"注册页预热完成: {signup_entry_url[:120]}", step="oauth_init")

        if _stopped():
            return None

        # ------- 步骤4：轮询邮箱拿验证码（抓包未见独立 send_otp 请求） -------
        def _fetch_signup_otp(
            timeout_seconds: int,
            sent_at_ts: Optional[float],
            exclude_codes: Optional[set[str]] = None,
        ) -> str:
            excluded_codes = {
                str(candidate or "").strip()
                for candidate in (exclude_codes or set())
                if str(candidate or "").strip()
            }
            if mail_provider is not None:
                try:
                    return mail_provider.wait_for_otp(
                        dev_token,
                        email,
                        proxy=static_proxy,
                        proxy_selector=mail_proxy_selector,
                        timeout=timeout_seconds,
                        stop_event=stop_event,
                        sent_at_ts=sent_at_ts,
                        exclude_codes=excluded_codes,
                    )
                except TypeError:
                    if excluded_codes:
                        emitter.warn(
                            "当前邮箱 provider 不支持排除旧验证码，可能重复命中同一 OTP",
                            step="wait_otp",
                        )
                    return mail_provider.wait_for_otp(
                        dev_token,
                        email,
                        proxy=static_proxy,
                        timeout=timeout_seconds,
                        stop_event=stop_event,
                    )
            return get_oai_code(
                dev_token,
                email,
                static_proxies,
                emitter,
                stop_event,
                proxy_selector=mail_proxies_selector,
                timeout=timeout_seconds,
                sent_at_ts=sent_at_ts,
                exclude_codes=excluded_codes,
            )

        _start_create_account_sentinel_prefetch(step="wait_otp")
        emitter.info("等待邮箱 OTP（按抓包链路跳过独立 send_otp 请求）...", step="wait_otp")
        otp_wait_started_at = time.time()
        tried_otp_codes: set[str] = set()
        otp_latency_emitted = False
        otp_resp_data: Dict[str, Any] = {}

        # ------- 步骤5：提交验证码 -------
        for otp_candidate_index in range(1, OTP_WRONG_CODE_MAX_RETRIES + 2):
            fetch_timeout = (
                OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS
                if otp_candidate_index == 1
                else OTP_WRONG_CODE_RETRY_TIMEOUT_SECONDS
            )
            code = _fetch_signup_otp(
                fetch_timeout,
                otp_wait_started_at,
                exclude_codes=tried_otp_codes,
            )
            if not code:
                if tried_otp_codes:
                    emitter.warn(
                        f"已排除 {len(tried_otp_codes)} 个被拒绝验证码，"
                        f"{fetch_timeout}s 内未等到新的验证码，放弃当前邮箱并切换下一个 provider",
                        step="wait_otp",
                    )
                else:
                    emitter.warn(
                        f"{OTP_PROVIDER_SWITCH_TIMEOUT_SECONDS}s 内未收到验证码，放弃当前邮箱并切换下一个 provider",
                        step="wait_otp",
                    )
                return None
            if code in tried_otp_codes:
                emitter.warn("邮箱 provider 重复返回已拒绝验证码，继续等待新 OTP", step="wait_otp")
                _otp_poll_wait(stop_event)
                continue
            tried_otp_codes.add(code)
            if not otp_latency_emitted:
                _emit_otp_latency(
                    emitter,
                    otp_wait_started_at,
                    step="wait_otp",
                    direct_print=mail_provider is None,
                )
                otp_latency_emitted = True

            if _stopped():
                return None

            time.sleep(random.uniform(0.15, 0.4))
            emitter.info(
                "正在验证 OTP..." if otp_candidate_index == 1 else f"正在验证新的 OTP（第 {otp_candidate_index} 个）...",
                step="verify_otp",
            )
            _otp_headers = {
                **_auth_api_headers("https://auth.openai.com/email-verification", include_device_id=False),
            }
            _otp_headers.update(_trace_headers())
            code_resp = _session_post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers=_otp_headers,
                json={"code": code},
            )
            emitter.info(f"验证码校验状态: {code_resp.status_code}", step="verify_otp")
            if code_resp.status_code == 200:
                try:
                    otp_resp_data = code_resp.json() if code_resp.text else {}
                except Exception:
                    otp_resp_data = {}
                break

            verify_error_text = str(code_resp.text or "")
            if _looks_deactivated_error(verify_error_text):
                removed_aliases = _notify_mail_provider_skip_primary(
                    mail_provider,
                    auth_credential=dev_token,
                    email=email,
                    reason="account_deactivated",
                )
                emitter.warn(
                    f"主邮箱不可用/已停用，跳过该主邮箱剩余 alias（移除 {removed_aliases} 个待注册邮箱）",
                    step="verify_otp",
                )
                emitter.error(
                    f"验证码校验失败（状态码 {code_resp.status_code}）: {verify_error_text[:220]}",
                    step="verify_otp",
                )
                return None

            can_retry_wrong_code = (
                otp_candidate_index <= OTP_WRONG_CODE_MAX_RETRIES
                and _looks_wrong_otp_error(code_resp.status_code, verify_error_text)
                and not _stopped()
            )
            if can_retry_wrong_code:
                emitter.warn(
                    "OTP 被 OpenAI 拒绝，疑似旧验证码或错 alias 验证码；"
                    f"已排除当前验证码，继续等待新的邮件（{OTP_WRONG_CODE_RETRY_TIMEOUT_SECONDS}s）",
                    step="verify_otp",
                )
                continue

            emitter.error(
                f"验证码校验失败（状态码 {code_resp.status_code}）: {verify_error_text[:220]}",
                step="verify_otp",
            )
            return None
        else:
            return None
        otp_continue_url = _extract_next_auth_url(otp_resp_data)
        if otp_continue_url:
            signup_entry_url = otp_continue_url
            emitter.info(f"OTP 校验返回 next={otp_continue_url[:140]}", step="verify_otp")

        if _stopped():
            return None

        # ------- 步骤6：创建账户 -------
        time.sleep(random.uniform(0.25, 0.75))
        emitter.info("正在创建账户信息...", step="create_account")
        profile = _generate_random_profile()
        _ca_headers = _auth_api_headers("https://auth.openai.com/about-you", include_device_id=False)
        _ca_headers.update(_trace_headers())
        _browser_create_account_sentinel = ""
        _browser_create_account_so_token = ""
        create_account_sentinel_cfg = _create_account_browser_sentinel_config()
        try:
            emitter.info(
                "读取浏览器 Sentinel token"
                f"（无头={bool(create_account_sentinel_cfg.get('headless'))}，"
                f"并发上限 {create_account_sentinel_cfg.get('max_concurrency', DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY)}，"
                f"指纹={create_account_sentinel_cfg.get('fingerprint_scope', DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE)}/"
                f"{create_account_sentinel_cfg.get('fingerprint_engine', DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE)}，"
                "协议=gmailreg-v2，优先使用后台预取）...",
                step="create_account",
            )
            _browser_sentinel_bundle = _get_create_account_browser_sentinel_bundle(create_account_sentinel_cfg)
            _browser_create_account_sentinel = str((_browser_sentinel_bundle or {}).get("token") or "").strip()
            _browser_create_account_so_token = str((_browser_sentinel_bundle or {}).get("so_token") or "").strip()
        except Exception as exc:
            emitter.warn(f"浏览器 Sentinel 获取失败，已禁用 challenge Sentinel fallback: {exc}", step="create_account")
        if _browser_create_account_sentinel:
            _ca_headers["openai-sentinel-token"] = _browser_create_account_sentinel
            if _browser_create_account_so_token:
                _ca_headers["openai-sentinel-so-token"] = _browser_create_account_so_token
            emitter.info("账户创建使用浏览器 Sentinel token", step="create_account")
        else:
            emitter.error("浏览器 Sentinel 未返回 token；create_account 不再回退 challenge Sentinel，跳过当前邮箱", step="create_account")
            return None
        create_account_resp = _session_post(
            "https://auth.openai.com/api/accounts/create_account",
            headers=_ca_headers,
            json=profile,
        )
        create_account_status = create_account_resp.status_code
        emitter.info(f"账户创建状态: {create_account_status}", step="create_account")

        if create_account_status != 200 and _create_account_error_code(create_account_resp) == "invalid_auth_step":
            emitter.warn(
                "create_account 返回 invalid_auth_step；按 gmailreg-v2 协议重新获取无头浏览器 Sentinel 后重试一次...",
                step="create_account",
            )
            try:
                retry_sentinel_cfg = dict(create_account_sentinel_cfg)
                retry_sentinel_cfg["enabled"] = True
                retry_sentinel_cfg["headless"] = True
                retry_bundle = _get_browser_sentinel_bundle_for_create_account(
                    browser_sentinel_config=retry_sentinel_cfg,
                    proxy=static_proxy,
                    user_agent=_chrome_ua,
                    session_profile=session_profile,
                )
                retry_sentinel = str((retry_bundle or {}).get("token") or "").strip()
                retry_so_token = str((retry_bundle or {}).get("so_token") or "").strip()
                if retry_sentinel:
                    retry_headers = dict(_ca_headers)
                    retry_headers["openai-sentinel-token"] = retry_sentinel
                    retry_headers.pop("openai-sentinel-so-token", None)
                    if retry_so_token:
                        retry_headers["openai-sentinel-so-token"] = retry_so_token
                    create_account_resp = _session_post(
                        "https://auth.openai.com/api/accounts/create_account",
                        headers=retry_headers,
                        json=profile,
                    )
                    create_account_status = create_account_resp.status_code
                    emitter.info(
                        f"gmailreg-v2 Sentinel 重试账户创建状态: {create_account_status}",
                        step="create_account",
                    )
                else:
                    emitter.warn("gmailreg-v2 Sentinel 未返回 token，无法重试 create_account", step="create_account")
            except Exception as exc:
                emitter.warn(f"gmailreg-v2 Sentinel 重试失败: {exc}", step="create_account")

        if (
            create_account_status != 200
            and browser_sentinel_cfg["enabled"]
            and browser_sentinel_cfg["headless"]
            and bool(browser_sentinel_cfg.get("fallback_headed"))
        ):
            create_account_error_text = str(create_account_resp.text or "")
            lower_error_text = create_account_error_text.lower()
            if create_account_status == 400 and (
                "registration_disallowed" in lower_error_text
                or "cannot create your account" in lower_error_text
            ):
                emitter.warn(
                    "无头 Sentinel 返回 create_account 400，按配置切换可视浏览器 Sentinel 重试一次...",
                    step="create_account",
                )
                try:
                    headed_sentinel_cfg = dict(browser_sentinel_cfg)
                    headed_sentinel_cfg["headless"] = False
                    retry_bundle = _get_browser_sentinel_bundle_for_create_account(
                        browser_sentinel_config=headed_sentinel_cfg,
                        proxy=static_proxy,
                        user_agent=_chrome_ua,
                        session_profile=session_profile,
                    )
                    retry_sentinel = str((retry_bundle or {}).get("token") or "").strip()
                    retry_so_token = str((retry_bundle or {}).get("so_token") or "").strip()
                    if retry_sentinel:
                        retry_headers = dict(_ca_headers)
                        retry_headers["openai-sentinel-token"] = retry_sentinel
                        if retry_so_token:
                            retry_headers["openai-sentinel-so-token"] = retry_so_token
                        create_account_resp = _session_post(
                            "https://auth.openai.com/api/accounts/create_account",
                            headers=retry_headers,
                            json=profile,
                        )
                        create_account_status = create_account_resp.status_code
                        emitter.info(
                            f"可视 Sentinel 重试账户创建状态: {create_account_status}",
                            step="create_account",
                        )
                    else:
                        emitter.warn("可视 Sentinel 未返回 token，无法重试 create_account", step="create_account")
                except Exception as exc:
                    emitter.warn(f"可视 Sentinel 重试失败: {exc}", step="create_account")

        if create_account_status != 200:
            error_code = _create_account_error_code(create_account_resp)
            if error_code == "user_already_exists":
                removed_aliases = _notify_mail_provider_skip_primary(
                    mail_provider,
                    auth_credential=dev_token,
                    email=email,
                    reason=error_code,
                )
                emitter.warn(
                    f"邮箱已存在，跳过该主邮箱剩余 alias（移除 {removed_aliases} 个待注册邮箱）",
                    step="create_account",
                )
            elif error_code == "invalid_auth_step":
                removed_aliases = _notify_mail_provider_skip_primary(
                    mail_provider,
                    auth_credential=dev_token,
                    email=email,
                    reason=error_code,
                )
                emitter.warn(
                    f"invalid_auth_step：按 gmailreg-v2 处理为该主邮箱/alias额度异常，跳过该主邮箱剩余 alias（移除 {removed_aliases} 个待注册邮箱）",
                    step="create_account",
                )
            emitter.error(create_account_resp.text, step="create_account")
            return None

        emitter.success("账户创建成功！", step="create_account")

        # 账户已创建成功：只读取当前 ChatGPT session 并立即返回。
        # 不再继续尝试 refresh_token / 当前会话 OAuth / fresh OAuth，避免触发额外限流。
        try:
            _ca_data = create_account_resp.json() if create_account_resp.text else {}
        except Exception:
            _ca_data = {}
        post_create_url = _extract_post_create_url(_ca_data, _chatgpt_base)
        mailbox_context = _build_mailbox_context(email=email, auth_credential=dev_token)

        if _requires_phone_verification(_ca_data, create_account_resp.text, post_create_url):
            emitter.warn(_phone_gate_error_message("create_account 后 "), step="create_account")

        token_json = _try_extract_chatgpt_session_token(
            continue_url=post_create_url,
            chatgpt_base=_chatgpt_base,
            session_get=_session_get,
            emitter=emitter,
            account_password=account_password,
            mail_provider=resolved_mail_provider_name,
            mailbox=mailbox_context,
        )
        try:
            s.close()
        except Exception:
            pass
        if token_json:
            emitter.success("账户创建完成，已按配置导出当前注册会话 session。", step="create_account")
            return token_json

        emitter.error(
            "账户已创建，但未能读取当前 ChatGPT session；已按要求停止，不再执行 refresh_token/OAuth。",
            step="export_session",
        )
        return None

    except Exception as e:
        emitter.error(f"运行时发生错误: {e}", step="runtime")
        try: s.close()
        except: pass
        return None

# ==========================================
# CLI 入口（兼容直接运行）
# ==========================================


def main() -> None:
    parser = argparse.ArgumentParser(description="注册账号并获取 session/token 的精简 CLI")
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7897"
    )
    parser.add_argument("--once", action="store_true", help="只运行一次")
    parser.add_argument("--sleep-min", type=int, default=5, help="循环模式最短等待秒数")
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="循环模式最长等待秒数"
    )
    args = parser.parse_args()

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)

    os.makedirs(TOKENS_DIR, exist_ok=True)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            sync_cfg = json.load(f)
    except Exception:
        sync_cfg = {}

    browser_sentinel_config = {
        "enabled": bool(sync_cfg.get("browser_sentinel_enabled", False)),
        "headless": bool(sync_cfg.get("browser_sentinel_headless", True)),
        "max_concurrency": sync_cfg.get(
            "browser_sentinel_max_concurrency",
            DEFAULT_BROWSER_SENTINEL_MAX_CONCURRENCY,
        ),
        "fingerprint_scope": sync_cfg.get(
            "browser_sentinel_fingerprint_scope",
            DEFAULT_BROWSER_SENTINEL_FINGERPRINT_SCOPE,
        ),
        "fingerprint_engine": sync_cfg.get(
            "browser_sentinel_fingerprint_engine",
            DEFAULT_BROWSER_SENTINEL_FINGERPRINT_ENGINE,
        ),
        "fallback_headed": bool(
            sync_cfg.get(
                "browser_sentinel_fallback_headed",
                DEFAULT_BROWSER_SENTINEL_FALLBACK_HEADED,
            )
        ),
        "timeout_seconds": sync_cfg.get("browser_sentinel_timeout_seconds", DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS),
        "page_url": str(
            sync_cfg.get("browser_sentinel_page_url") or DEFAULT_BROWSER_SENTINEL_PAGE_URL
        ).strip()
        or DEFAULT_BROWSER_SENTINEL_PAGE_URL,
        "browser_entry_enabled": bool(sync_cfg.get("browser_entry_enabled", True)),
        "browser_entry_headless": bool(sync_cfg.get("browser_entry_headless", False)),
        "browser_entry_timeout_seconds": sync_cfg.get("browser_entry_timeout_seconds", 180),
    }

    count = 0
    print("[Info] 注册 -> 获取 session/token - CLI 模式")

    while True:
        count += 1
        print(
            f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> 开始第 {count} 次注册流程 <<<"
        )

        try:
            token_json = run(
                args.proxy,
                browser_sentinel_config=browser_sentinel_config,
            )

            if token_json:
                try:
                    t_data = json.loads(token_json)
                    fname_email = t_data.get("email", "unknown").replace("@", "_")
                except Exception:
                    fname_email = "unknown"
                    t_data = {}

                file_name = f"token_{fname_email}_{time.time_ns()}.json"
                file_path = os.path.join(TOKENS_DIR, file_name)

                _write_text_atomic(file_path, token_json)

                print(f"[*] 成功! session/token 已保存至: {file_path}")
            else:
                print("[-] 本次注册失败。")

        except Exception as e:
            print(f"[Error] 发生未捕获异常: {e}")

        if args.once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        print(f"[*] 休息 {wait_time} 秒...")
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
