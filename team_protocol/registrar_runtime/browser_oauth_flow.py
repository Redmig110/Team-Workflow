from __future__ import annotations

import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional

from .fingerprint_profiles import SessionProfile, context_options_for_profile, create_session_profile
from .sentinel_browser import fingerprint_init_script_for_profile


TOKEN_URL = "https://auth.openai.com/oauth/token"
DEFAULT_BROWSER_OAUTH_TIMEOUT_SECONDS = 45
DEFAULT_BROWSER_OAUTH_POLL_INTERVAL_MS = 500


def _close_quietly(resource: Any) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        pass


def _build_launch_options(proxy: Optional[str], headless: bool) -> Dict[str, Any]:
    launch_options: Dict[str, Any] = {"headless": bool(headless)}
    proxy_value = str(proxy or "").strip()
    if proxy_value:
        launch_options["proxy"] = {"server": proxy_value}
    return launch_options


def _parse_callback_params(url: Any) -> Dict[str, str]:
    candidate = str(url or "").strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}
    try:
        parsed = urllib.parse.urlparse(candidate)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    except Exception:
        return {"code": "", "state": "", "error": "", "error_description": ""}
    return {
        "code": str((params.get("code") or [""])[0] or "").strip(),
        "state": str((params.get("state") or [""])[0] or "").strip(),
        "error": str((params.get("error") or [""])[0] or "").strip(),
        "error_description": str((params.get("error_description") or [""])[0] or "").strip(),
    }


def _looks_like_callback_url(url: Any) -> bool:
    params = _parse_callback_params(url)
    return bool(params["code"] or params["error"])


def _normalize_cookie(cookie: Any) -> Optional[Dict[str, Any]]:
    if isinstance(cookie, dict):
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "").strip()
        if not name:
            return None
        normalized = {
            "name": name,
            "value": value,
            "domain": str(cookie.get("domain") or ".openai.com").strip() or ".openai.com",
            "path": str(cookie.get("path") or "/").strip() or "/",
            "secure": bool(cookie.get("secure", True)),
            "httpOnly": bool(cookie.get("httpOnly", False)),
        }
        same_site = str(cookie.get("sameSite") or "").strip()
        if same_site:
            normalized["sameSite"] = same_site
        return normalized

    name = str(getattr(cookie, "name", "") or "").strip()
    if not name:
        return None
    value = str(getattr(cookie, "value", "") or "").strip()
    domain = str(getattr(cookie, "domain", "") or ".openai.com").strip() or ".openai.com"
    path = str(getattr(cookie, "path", "") or "/").strip() or "/"
    secure_attr = getattr(cookie, "secure", None)
    http_only_attr = getattr(cookie, "rest", None)
    http_only = False
    if isinstance(http_only_attr, dict):
        http_only = bool(http_only_attr.get("HttpOnly"))
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "secure": bool(True if secure_attr is None else secure_attr),
        "httpOnly": http_only,
    }


def _normalize_cookies(cookies: Any) -> List[Dict[str, Any]]:
    if cookies is None:
        return []
    normalized: List[Dict[str, Any]] = []
    if isinstance(cookies, dict):
        iterable: Iterable[Any] = cookies.values()
    else:
        iterable = cookies
    try:
        for cookie in iterable:
            normalized_cookie = _normalize_cookie(cookie)
            if normalized_cookie:
                normalized.append(normalized_cookie)
    except Exception:
        return []
    return normalized


def get_browser_oauth_capture_bundle(
    *,
    start_url: str,
    cookies: Any = None,
    headless: bool = True,
    timeout_seconds: int = DEFAULT_BROWSER_OAUTH_TIMEOUT_SECONDS,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
) -> Dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"Playwright unavailable: {exc}") from exc

    target_url = str(start_url or "").strip()
    if not target_url:
        raise ValueError("start_url is required")

    timeout_ms = max(3000, int(float(timeout_seconds or DEFAULT_BROWSER_OAUTH_TIMEOUT_SECONDS) * 1000))
    browser = None
    context = None
    page = None
    bundle: Dict[str, Any] = {
        "callback_url": "",
        "callback_params": {"code": "", "state": "", "error": "", "error_description": ""},
        "token_response_url": "",
        "token_payload": {},
        "error": "",
    }

    def _capture_url(url: Any) -> None:
        if not _looks_like_callback_url(url):
            return
        bundle["callback_url"] = str(url or "").strip()
        bundle["callback_params"] = _parse_callback_params(url)

    def _capture_token_response(response: Any) -> None:
        try:
            url = str(getattr(response, "url", "") or "").strip()
        except Exception:
            url = ""
        if not url or "/oauth/token" not in url:
            _capture_url(url)
            return
        bundle["token_response_url"] = url
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if isinstance(payload, dict):
            bundle["token_payload"] = payload

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**_build_launch_options(proxy, headless))
            profile = session_profile or create_session_profile(user_agent=user_agent)
            if user_agent and user_agent.strip() != profile.user_agent:
                raise ValueError("user_agent conflicts with the supplied SessionProfile")
            context = browser.new_context(**context_options_for_profile(profile))
            context.add_init_script(fingerprint_init_script_for_profile(profile))
            normalized_cookies = _normalize_cookies(cookies)
            if normalized_cookies:
                context.add_cookies(normalized_cookies)
            page = context.new_page()
            page.on("response", _capture_token_response)
            page.on("framenavigated", lambda frame: _capture_url(getattr(frame, "url", "")))
            page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)

            deadline = time.time() + max(3.0, timeout_ms / 1000.0)
            while time.time() < deadline:
                _capture_url(getattr(page, "url", ""))
                token_payload = bundle.get("token_payload")
                if isinstance(token_payload, dict) and str(token_payload.get("refresh_token") or "").strip():
                    break
                callback_params = bundle.get("callback_params") or {}
                if str(callback_params.get("code") or "").strip():
                    break
                page.wait_for_timeout(DEFAULT_BROWSER_OAUTH_POLL_INTERVAL_MS)
            return bundle
    except PlaywrightTimeoutError as exc:
        raise RuntimeError(f"browser oauth timeout: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"browser oauth failed: {exc}") from exc
    finally:
        _close_quietly(page)
        _close_quietly(context)
        _close_quietly(browser)
