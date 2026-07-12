from __future__ import annotations

import json
import os
import queue
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, Optional, Sequence
from urllib.parse import quote as urllib_parse_quote

from .fingerprint_profiles import SessionProfile, context_options_for_profile, create_session_profile
from .sentinel_browser import fingerprint_init_script_for_profile


CHATGPT_BASE = "https://chatgpt.com"
AUTH_BASE = "https://auth.openai.com"
DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_CHATGPT_WARMUP_WAIT_MS = 2500
DEFAULT_SENTINEL_PAGE_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"
DEFAULT_CHATGPT_READY_TIMEOUT_SECONDS = 30
DEFAULT_CHATGPT_READY_POLL_INTERVAL_MS = 1000

_CHALLENGE_MARKERS = (
    "just a moment",
    "performing security verification",
    "cf-turnstile",
    "challenge-platform",
    "cf_chl",
)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _normalize_url(*values: Any) -> str:
    raw = _first_text(*values)
    if not raw:
        return ""
    if raw.startswith("/"):
        return f"{AUTH_BASE}{raw}"
    return raw


def _safe_json_loads(raw: Any) -> Dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _looks_phone_gate(*values: Any) -> bool:
    haystack = "\n".join(str(v or "").strip().lower() for v in values if str(v or "").strip())
    if not haystack:
        return False
    markers = ("add-phone", "phone verification", "phone_verification", "phone-required")
    return any(marker in haystack for marker in markers)


def _looks_like_challenge_page(title: str, body_text: str) -> bool:
    haystack = f"{str(title or '').strip().lower()}\n{str(body_text or '').strip().lower()}"
    return any(marker in haystack for marker in _CHALLENGE_MARKERS)


class PlaywrightBrowserFlow:
    def __init__(
        self,
        *,
        config: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
        user_agent: str = "",
        session_profile: Optional[SessionProfile] = None,
        emitter: Any = None,
    ) -> None:
        self.config = dict(config or {})
        self.proxy = str(proxy or "").strip()
        supplied_user_agent = str(user_agent or "").strip()
        self.session_profile = session_profile or create_session_profile(user_agent=supplied_user_agent)
        if supplied_user_agent and supplied_user_agent != self.session_profile.user_agent:
            raise ValueError("user_agent conflicts with the supplied SessionProfile")
        self.user_agent = self.session_profile.user_agent
        self.emitter = emitter
        self._profile_dir = str(self.config.get("profile_dir") or "").strip()
        self._cleanup_profile_dir = False
        self._playwright_cm = None
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._sentinel_page = None

    def _log(self, level: str, message: str, step: str = "browser_flow") -> None:
        emitter = self.emitter
        if emitter is None:
            return
        try:
            getattr(emitter, level)(message, step=step)
        except Exception:
            try:
                emitter.emit(level, message, step=step)
            except Exception:
                pass

    def _resolve_profile_dir(self) -> Optional[str]:
        if self._profile_dir:
            return self._profile_dir
        return None

    def open(self) -> None:
        if self._context is not None and self._page is not None:
            return
        from playwright.sync_api import sync_playwright

        self._playwright_cm = sync_playwright()
        self._playwright = self._playwright_cm.start()
        launch_options: Dict[str, Any] = {"headless": _coerce_bool(self.config.get("headless", False), default=False)}
        if self.proxy:
            launch_options["proxy"] = {"server": self.proxy}
        self._browser = self._playwright.chromium.launch(**launch_options)
        self._context = self._browser.new_context(**context_options_for_profile(self.session_profile))
        self._context.add_init_script(fingerprint_init_script_for_profile(self.session_profile))
        self._page = self._context.new_page()

    def close(self) -> None:
        for resource_name in ("_sentinel_page", "_page", "_context", "_browser"):
            resource = getattr(self, resource_name, None)
            if resource is None:
                continue
            try:
                resource.close()
            except Exception:
                pass
            setattr(self, resource_name, None)
        if self._playwright_cm is not None:
            try:
                self._playwright_cm.stop()
            except Exception:
                pass
        self._playwright_cm = None
        self._playwright = None

    def _ensure_page_origin(self, origin: str):
        self.open()
        if self._page is None:
            raise RuntimeError("browser page unavailable")
        page = self._page
        target_base = CHATGPT_BASE if str(origin or "").strip().lower() == "chatgpt" else AUTH_BASE
        current_url = str(getattr(page, "url", "") or "").strip()
        if not current_url.startswith(target_base):
            page.goto(f"{target_base}/", wait_until="domcontentloaded", timeout=max(30000, int(self.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)) * 1000))
        return page

    def _ensure_sentinel_page(self):
        self.open()
        if self._context is None:
            raise RuntimeError("browser context unavailable")
        if self._sentinel_page is None:
            self._sentinel_page = self._context.new_page()
            self._sentinel_page.goto(
                str(self.config.get("sentinel_page_url") or DEFAULT_SENTINEL_PAGE_URL),
                wait_until="load",
                timeout=max(30000, int(self.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)) * 1000),
            )
            self._sentinel_page.wait_for_timeout(4000)
            self._sentinel_page.wait_for_function("() => !!window.SentinelSDK", timeout=30000)
        return self._sentinel_page

    def _page_title(self, page: Any) -> str:
        try:
            return str(page.title() or "").strip()
        except Exception:
            return ""

    def _page_text_excerpt(self, page: Any) -> str:
        try:
            return str(page.locator("body").inner_text(timeout=5000) or "").strip()[:300]
        except Exception:
            return ""

    def _wait_until_page_ready(self, page: Any, *, label: str) -> Any:
        timeout_seconds = max(
            1,
            int(self.config.get("chatgpt_ready_timeout_seconds", self.config.get("timeout_seconds", DEFAULT_CHATGPT_READY_TIMEOUT_SECONDS))),
        )
        poll_interval_ms = max(
            1,
            int(self.config.get("chatgpt_ready_poll_interval_ms", DEFAULT_CHATGPT_READY_POLL_INTERVAL_MS)),
        )
        deadline = time.time() + timeout_seconds
        last_title = ""
        last_excerpt = ""
        while time.time() < deadline:
            last_title = self._page_title(page)
            last_excerpt = self._page_text_excerpt(page)
            if not _looks_like_challenge_page(last_title, last_excerpt):
                return page
            page.wait_for_timeout(poll_interval_ms)
        raise RuntimeError(f"{label} challenge not cleared: {last_title} {last_excerpt}".strip())

    def _csrf_error_message(self, csrf_response: Dict[str, Any], page: Any) -> str:
        status = int(csrf_response.get("status") or 0)
        text = _first_text(csrf_response.get("text"))
        if text:
            return f"browser flow csrf failed ({status}): {text[:160]}"
        title = self._page_title(page)
        excerpt = self._page_text_excerpt(page)
        return f"browser flow csrf failed ({status}): {title} {excerpt}".strip()

    def _warm_chatgpt_page(self):
        page = self._ensure_page_origin("chatgpt")
        page.goto(
            f"{CHATGPT_BASE}/auth/login?screen_hint=signup",
            wait_until="domcontentloaded",
            timeout=max(30000, int(self.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)) * 1000),
        )
        page.wait_for_timeout(int(self.config.get("chatgpt_warmup_wait_ms", DEFAULT_CHATGPT_WARMUP_WAIT_MS)))
        return self._wait_until_page_ready(page, label="chatgpt")

    def _fetch_json(
        self,
        *,
        origin: str,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, Any]] = None,
        json_body: Any = None,
        data_body: Optional[str] = None,
    ) -> Dict[str, Any]:
        page = self._ensure_page_origin(origin)
        return page.evaluate(
            """async ({ url, method, headers, jsonBody, dataBody }) => {
                const opts = {
                    method,
                    headers: { ...(headers || {}) },
                    credentials: 'include',
                };
                if (jsonBody !== null && jsonBody !== undefined) {
                    opts.body = JSON.stringify(jsonBody);
                } else if (dataBody !== null && dataBody !== undefined) {
                    opts.body = dataBody;
                }
                const resp = await fetch(url, opts);
                const text = await resp.text();
                let data = null;
                try {
                    data = text ? JSON.parse(text) : null;
                } catch (error) {
                    data = null;
                }
                return {
                    status: resp.status,
                    url: resp.url,
                    text,
                    json: data,
                };
            }""",
            {
                "url": url,
                "method": str(method or "GET").upper(),
                "headers": headers or {},
                "jsonBody": json_body,
                "dataBody": data_body,
            },
        )

    def _cookies(self) -> list[dict]:
        self.open()
        if self._context is None:
            return []
        try:
            cookies = self._context.cookies()
        except Exception:
            cookies = []
        return cookies if isinstance(cookies, list) else []

    def _device_id(self) -> str:
        for cookie in self._cookies():
            if str(cookie.get("name") or "").strip() == "oai-did":
                return str(cookie.get("value") or "").strip()
        return str(uuid.uuid4())

    def _generate_sentinel_token(self, flow_candidates: Sequence[str]) -> str:
        sentinel_page = self._ensure_sentinel_page()
        result = sentinel_page.evaluate(
            """async (flows) => {
                if (!window.SentinelSDK) throw new Error('SentinelSDK missing');
                let lastError = '';
                for (const flow of flows) {
                    try {
                        await window.SentinelSDK.init(flow);
                        const token = await window.SentinelSDK.token(flow);
                        if (typeof token === 'string' && token.trim()) {
                            return token.trim();
                        }
                    } catch (error) {
                        lastError = String(error || '');
                    }
                }
                if (lastError) throw new Error(lastError);
                return '';
            }""",
            list(flow_candidates or []),
        )
        return str(result or "").strip()

    def _wait_for_otp(self, *, mail_provider: Any, mail_auth_credential: str, email: str, stop_event: Any = None, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> str:
        if mail_provider is None:
            raise RuntimeError("browser flow otp wait requires mail provider")
        try:
            return str(
                mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=self.proxy,
                    timeout=int(timeout_seconds or DEFAULT_TIMEOUT_SECONDS),
                    stop_event=stop_event,
                )
                or ""
            ).strip()
        except TypeError:
            return str(
                mail_provider.wait_for_otp(
                    mail_auth_credential,
                    email,
                    proxy=self.proxy,
                    stop_event=stop_event,
                )
                or ""
            ).strip()

    def _try_get_chatgpt_session(self) -> Optional[Dict[str, Any]]:
        try:
            page = self._ensure_page_origin("chatgpt")
            result = page.evaluate(
                """async () => {
                    const resp = await fetch('/api/auth/session', { credentials: 'include' });
                    const text = await resp.text();
                    let data = null;
                    try {
                        data = text ? JSON.parse(text) : null;
                    } catch (error) {
                        data = null;
                    }
                    return { status: resp.status, json: data, text };
                }"""
            )
            if int(result.get("status") or 0) != 200:
                return None
            payload = result.get("json") if isinstance(result.get("json"), dict) else {}
            access_token = _first_text(payload.get("accessToken"))
            if not access_token:
                return None
            session_token = _first_text(payload.get("sessionToken"))
            email = _first_text((payload.get("user") or {}).get("email") if isinstance(payload.get("user"), dict) else "")
            return {
                "access_token": access_token,
                "refresh_token": "",
                "session_token": session_token,
                "email": email,
                "token_source": "chatgpt_session",
                "type": "codex",
            }
        except Exception:
            return None

    def _run_registration_and_oauth_sync(
        self,
        *,
        email: str,
        account_password: str,
        mail_provider: Any,
        mail_auth_credential: str,
        codex_auth_url: str,
        random_profile: Optional[Dict[str, Any]] = None,
        stop_event: Any = None,
        signup_flow_candidates: Sequence[str],
        register_flow_candidates: Sequence[str],
        email_verification_flow_candidates: Sequence[str],
        create_account_flow_candidates: Sequence[str],
        password_verify_flow_candidates: Sequence[str],
    ) -> Dict[str, Any]:
        try:
            self.open()
            device_id = self._device_id()
            self._log("info", "浏览器全流程：初始化 ChatGPT 会话")
            page = self._warm_chatgpt_page()

            csrf_response: Dict[str, Any] = {}
            csrf_token = ""
            for attempt in range(2):
                csrf_response = self._fetch_json(
                    origin="chatgpt",
                    url=f"{CHATGPT_BASE}/api/auth/csrf?ts={int(time.time() * 1000)}",
                    headers={"Accept": "application/json", "Referer": f"{CHATGPT_BASE}/"},
                )
                csrf_token = _first_text((csrf_response.get("json") or {}).get("csrfToken"))
                if csrf_token:
                    break
                message = self._csrf_error_message(csrf_response, page)
                if attempt == 0:
                    self._log("warn", f"{message}，准备重试一次")
                    page = self._warm_chatgpt_page()
                    continue
                raise RuntimeError(message)

            signin_params = (
                "prompt=login"
                f"&ext-oai-did={urllib_parse_quote(device_id)}"
                f"&auth_session_logging_id={uuid.uuid4()}"
                "&ext-passkey-client-capabilities=0111"
                "&screen_hint=login_or_signup"
                f"&login_hint={urllib_parse_quote(email)}"
            )
            signin_response = self._fetch_json(
                origin="chatgpt",
                url=f"{CHATGPT_BASE}/api/auth/signin/openai?{signin_params}",
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Referer": f"{CHATGPT_BASE}/",
                    "Origin": CHATGPT_BASE,
                },
                data_body=f"callbackUrl={urllib_parse_quote(f'{CHATGPT_BASE}/')}&csrfToken={urllib_parse_quote(csrf_token)}&json=true",
            )
            authorize_url = _first_text((signin_response.get("json") or {}).get("url"))
            if not authorize_url:
                raise RuntimeError(f"browser flow signin/openai failed: {str(signin_response.get('text') or '')[:180]}")

            page = self._ensure_page_origin(authorize_url)
            page.goto(authorize_url, wait_until="domcontentloaded")
            device_id = self._device_id()

            signup_entry_url = _normalize_url(page.url)
            if signup_entry_url:
                page.goto(signup_entry_url, wait_until="domcontentloaded")

            self._log("info", "浏览器全流程：等待邮箱 OTP")
            otp_code = self._wait_for_otp(
                mail_provider=mail_provider,
                mail_auth_credential=mail_auth_credential,
                email=email,
                stop_event=stop_event,
                timeout_seconds=int(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS),
            )
            if not otp_code:
                raise RuntimeError("browser flow otp missing")

            otp_validate_response = self._fetch_json(
                origin="auth",
                url=f"{AUTH_BASE}/api/accounts/email-otp/validate",
                method="POST",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": AUTH_BASE,
                    "Referer": f"{AUTH_BASE}/email-verification",
                },
                json_body={"code": otp_code},
            )
            if int(otp_validate_response.get("status") or 0) != 200:
                raise RuntimeError(f"browser flow otp validate failed: {str(otp_validate_response.get('text') or '')[:180]}")
            if _looks_phone_gate(otp_validate_response.get("text"), otp_validate_response.get("json")):
                raise RuntimeError("browser flow hit add-phone gate after otp")
            payload = otp_validate_response.get("json") if isinstance(otp_validate_response.get("json"), dict) else {}
            page_type = _first_text((payload.get("page") or {}).get("type") if isinstance(payload.get("page"), dict) else "").lower()
            next_url = _normalize_url(payload.get("continue_url"), payload.get("url"), payload.get("redirect_url"))

            consent_url = next_url
            if not consent_url or ("consent" not in page_type and "code=" not in consent_url and "state=" not in consent_url):
                profile = dict(random_profile or {"name": "Alex Wilson", "birthdate": "1994-05-17"})
                create_bundle = self._ensure_sentinel_page().evaluate(
                    """async (flows) => {
                        if (!window.SentinelSDK) throw new Error('SentinelSDK missing');
                        let lastError = '';
                        for (const flow of flows) {
                            try {
                                await window.SentinelSDK.init(flow);
                                const tokenResult = await window.SentinelSDK.token(flow);
                                let soToken = '';
                                try {
                                    soToken = await window.SentinelSDK.sessionObserverToken(flow) || '';
                                } catch (error) {}
                                const token =
                                    typeof tokenResult === 'string'
                                        ? tokenResult.trim()
                                        : (tokenResult && typeof tokenResult.token === 'string' ? tokenResult.token.trim() : '');
                                if (token) {
                                    return { token, so_token: typeof soToken === 'string' ? soToken.trim() : '', flow };
                                }
                            } catch (error) {
                                lastError = String(error || '');
                            }
                        }
                        return { token: '', so_token: '', flow: '', error: lastError };
                    }""",
                    list(create_account_flow_candidates or []),
                )
                create_token = _first_text((create_bundle or {}).get("token"))
                create_so_token = _first_text((create_bundle or {}).get("so_token"))
                if not create_token:
                    raise RuntimeError(f"browser flow create_account sentinel missing: {_first_text((create_bundle or {}).get('error'))}")
                create_response = self._fetch_json(
                    origin="auth",
                    url=f"{AUTH_BASE}/api/accounts/create_account",
                    method="POST",
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Origin": AUTH_BASE,
                        "Referer": f"{AUTH_BASE}/about-you",
                        "openai-sentinel-token": create_token,
                        "openai-sentinel-so-token": create_so_token,
                    },
                    json_body=profile,
                )
                if int(create_response.get("status") or 0) != 200:
                    raise RuntimeError(f"browser flow create_account failed: {str(create_response.get('text') or '')[:180]}")
                create_payload = create_response.get("json") if isinstance(create_response.get("json"), dict) else {}
                consent_url = _normalize_url(create_payload.get("continue_url"), create_payload.get("url"), create_payload.get("redirect_url"), consent_url)
                if _looks_phone_gate(consent_url, create_response.get("text"), create_payload):
                    raise RuntimeError("browser flow hit add-phone gate during create_account")

            callback_url = ""
            if "code=" in consent_url and "state=" in consent_url:
                callback_url = consent_url

            session_token_data = self._try_get_chatgpt_session()
            self._log("success", "浏览器全流程：注册成功，等待外层 token exchange")
            return {
                "device_id": device_id,
                "consent_url": consent_url,
                "callback_url": callback_url,
                "cookies": self._cookies(),
                "session_token_data": session_token_data,
            }
        finally:
            self.close()

    def run_registration_and_oauth(
        self,
        *,
        email: str,
        account_password: str,
        mail_provider: Any,
        mail_auth_credential: str,
        codex_auth_url: str,
        random_profile: Optional[Dict[str, Any]] = None,
        stop_event: Any = None,
        signup_flow_candidates: Sequence[str],
        register_flow_candidates: Sequence[str],
        email_verification_flow_candidates: Sequence[str],
        create_account_flow_candidates: Sequence[str],
        password_verify_flow_candidates: Sequence[str],
    ) -> Dict[str, Any]:
        result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)

        def _runner() -> None:
            try:
                result = self._run_registration_and_oauth_sync(
                    email=email,
                    account_password=account_password,
                    mail_provider=mail_provider,
                    mail_auth_credential=mail_auth_credential,
                    codex_auth_url=codex_auth_url,
                    random_profile=random_profile,
                    stop_event=stop_event,
                    signup_flow_candidates=signup_flow_candidates,
                    register_flow_candidates=register_flow_candidates,
                    email_verification_flow_candidates=email_verification_flow_candidates,
                    create_account_flow_candidates=create_account_flow_candidates,
                    password_verify_flow_candidates=password_verify_flow_candidates,
                )
                result_queue.put({"ok": True, "result": result})
            except Exception as exc:
                result_queue.put({"ok": False, "error": str(exc)})

        thread = threading.Thread(target=_runner, name="browser-register-flow", daemon=True)
        thread.start()
        timeout_seconds = max(60.0, float(self.config.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS) + 60.0)
        thread.join(timeout=timeout_seconds)
        if thread.is_alive():
            raise RuntimeError("browser flow thread timeout")
        item = result_queue.get_nowait()
        if not item.get("ok"):
            raise RuntimeError(str(item.get("error") or "browser flow failed"))
        return item["result"]
