from __future__ import annotations

import queue
import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from .fingerprint_profiles import SessionProfile, context_options_for_profile, create_session_profile
from .sentinel_browser import fingerprint_init_script_for_profile


DEFAULT_BROWSER_ENTRY_TIMEOUT_SECONDS = 180
DEFAULT_BROWSER_ENTRY_POLL_INTERVAL_MS = 1000

_CHALLENGE_MARKERS = (
    "just a moment",
    "performing security verification",
    "cf-turnstile",
    "challenge-platform",
    "cf_chl",
)


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


def _normalize_cookie(cookie: Any) -> Optional[Dict[str, Any]]:
    if isinstance(cookie, dict):
        name = str(cookie.get("name") or "").strip()
        if not name:
            return None
        return {
            "name": name,
            "value": str(cookie.get("value") or "").strip(),
            "domain": str(cookie.get("domain") or ".openai.com").strip() or ".openai.com",
            "path": str(cookie.get("path") or "/").strip() or "/",
            "secure": bool(cookie.get("secure", True)),
            "httpOnly": bool(cookie.get("httpOnly", False)),
        }

    name = str(getattr(cookie, "name", "") or "").strip()
    if not name:
        return None
    return {
        "name": name,
        "value": str(getattr(cookie, "value", "") or "").strip(),
        "domain": str(getattr(cookie, "domain", "") or ".openai.com").strip() or ".openai.com",
        "path": str(getattr(cookie, "path", "") or "/").strip() or "/",
        "secure": bool(getattr(cookie, "secure", True)),
        "httpOnly": False,
    }


def _normalize_cookies(cookies: Any) -> List[Dict[str, Any]]:
    if cookies is None:
        return []
    if isinstance(cookies, dict):
        iterable: Iterable[Any] = cookies.values()
    else:
        iterable = cookies
    normalized: List[Dict[str, Any]] = []
    try:
        for cookie in iterable:
            normalized_cookie = _normalize_cookie(cookie)
            if normalized_cookie:
                normalized.append(normalized_cookie)
    except Exception:
        return []
    return normalized


def _looks_like_challenge(title: str, body_text: str) -> bool:
    haystack = f"{str(title or '').strip().lower()}\n{str(body_text or '').strip().lower()}"
    return any(marker in haystack for marker in _CHALLENGE_MARKERS)


def _warmup_auth_entry_in_browser_sync(
    *,
    start_url: str,
    cookies: Any = None,
    headless: bool = False,
    timeout_seconds: int = DEFAULT_BROWSER_ENTRY_TIMEOUT_SECONDS,
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

    timeout_ms = max(15000, int(float(timeout_seconds or DEFAULT_BROWSER_ENTRY_TIMEOUT_SECONDS) * 1000))
    browser = None
    context = None
    page = None

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
            page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)

            deadline = time.time() + max(15.0, timeout_ms / 1000.0)
            last_title = ""
            last_body = ""
            while time.time() < deadline:
                try:
                    last_title = page.title()
                except Exception:
                    last_title = ""
                try:
                    last_body = page.locator("body").inner_text(timeout=3000)
                except Exception:
                    last_body = ""
                if not _looks_like_challenge(last_title, last_body):
                    return {
                        "ok": True,
                        "challenge_cleared": True,
                        "final_url": str(page.url or "").strip(),
                        "title": str(last_title or "").strip(),
                        "body_excerpt": str(last_body or "").strip()[:500],
                        "cookies": context.cookies(),
                        "error": "",
                    }
                page.wait_for_timeout(DEFAULT_BROWSER_ENTRY_POLL_INTERVAL_MS)

            return {
                "ok": False,
                "challenge_cleared": False,
                "final_url": str(page.url or "").strip(),
                "title": str(last_title or "").strip(),
                "body_excerpt": str(last_body or "").strip()[:500],
                "cookies": context.cookies(),
                "error": "browser challenge wait timed out",
            }
    except PlaywrightTimeoutError as exc:
        return {
            "ok": False,
            "challenge_cleared": False,
            "final_url": "",
            "title": "",
            "body_excerpt": "",
            "cookies": [],
            "error": f"browser entry timeout: {exc}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "challenge_cleared": False,
            "final_url": "",
            "title": "",
            "body_excerpt": "",
            "cookies": [],
            "error": f"browser entry failed: {exc}",
        }
    finally:
        _close_quietly(page)
        _close_quietly(context)
        _close_quietly(browser)


def warmup_auth_entry_in_browser(
    *,
    start_url: str,
    cookies: Any = None,
    headless: bool = False,
    timeout_seconds: int = DEFAULT_BROWSER_ENTRY_TIMEOUT_SECONDS,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
) -> Dict[str, Any]:
    result_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1)

    def _runner() -> None:
        try:
            result = _warmup_auth_entry_in_browser_sync(
                start_url=start_url,
                cookies=cookies,
                headless=headless,
                timeout_seconds=timeout_seconds,
                proxy=proxy,
                user_agent=user_agent,
                session_profile=session_profile,
            )
        except Exception as exc:
            result = {
                "ok": False,
                "challenge_cleared": False,
                "final_url": "",
                "title": "",
                "body_excerpt": "",
                "cookies": [],
                "error": f"browser entry thread failed: {exc}",
            }
        result_queue.put(result)

    thread = threading.Thread(target=_runner, name="browser-entry-warmup", daemon=True)
    thread.start()
    thread.join(timeout=max(30.0, float(timeout_seconds or DEFAULT_BROWSER_ENTRY_TIMEOUT_SECONDS) + 15.0))
    if thread.is_alive():
        return {
            "ok": False,
            "challenge_cleared": False,
            "final_url": "",
            "title": "",
            "body_excerpt": "",
            "cookies": [],
            "error": "browser entry thread timeout",
        }
    try:
        return result_queue.get_nowait()
    except queue.Empty:
        return {
            "ok": False,
            "challenge_cleared": False,
            "final_url": "",
            "title": "",
            "body_excerpt": "",
            "cookies": [],
            "error": "browser entry thread returned no result",
        }
