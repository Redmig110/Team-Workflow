from __future__ import annotations

import copy
import hashlib
import json
import random
import secrets
import threading
import uuid
from collections import OrderedDict
from typing import Any, Dict, Optional, Sequence
from urllib.parse import quote

from .fingerprint_profiles import (
    FingerprintEngineMetadata,
    SessionProfile,
    browserforge_options_for_scope,
    context_options_for_profile,
    create_session_profile,
    resolve_fingerprint_engine,
    user_agent_data_for_profile,
)


DEFAULT_BROWSER_SENTINEL_PAGE_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6"
DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS = 60
DEFAULT_BROWSER_SENTINEL_WARMUP_MS = 1000
_BROWSERFORGE_CACHE_MAX_SIZE = 64
_BROWSERFORGE_CACHE_LOCK = threading.Lock()
_BROWSERFORGE_CACHE: "OrderedDict[str, tuple[bool, Any]]" = OrderedDict()
CHATGPT_WEB_CLIENT_ID = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
DEFAULT_CREATE_ACCOUNT_FLOW_CANDIDATES = (
    "oauth_create_account",
    "oauth-create-account",
    "create_account",
    "create-account",
)
def _close_quietly(resource: Any) -> None:
    if resource is None:
        return
    try:
        resource.close()
    except Exception:
        pass


def _resolve_session_profile(
    *,
    session_profile: Optional[SessionProfile],
    user_agent: str,
    fingerprint_scope: str,
) -> SessionProfile:
    if session_profile is not None:
        if user_agent and user_agent.strip() != session_profile.user_agent:
            raise ValueError("user_agent conflicts with the supplied SessionProfile")
        return session_profile.validate()
    return create_session_profile(scope=fingerprint_scope, user_agent=user_agent)


def _build_fingerprint(
    user_agent: str = "",
    fingerprint_scope: str = "auto_desktop",
    *,
    session_profile: Optional[SessionProfile] = None,
) -> Dict[str, Any]:
    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        fingerprint_scope=fingerprint_scope,
    )
    init_payload = profile.init_script_payload()
    return {
        "webdriver": False,
        "profile_id": profile.profile_id,
        "user_agent": profile.user_agent,
        "viewport": dict(profile.viewport),
        "screen": dict(profile.screen),
        "locale": profile.locale,
        "timezone_id": profile.timezone_id,
        "device_scale_factor": profile.device_scale_factor,
        "is_mobile": profile.is_mobile,
        "has_touch": profile.has_touch,
        "color_scheme": profile.color_scheme,
        "reduced_motion": profile.reduced_motion,
        "navigator": init_payload["navigator"],
        "webgl": dict(profile.webgl),
        "fonts": {**profile.fonts, "families": list(profile.fonts.get("families", ()))},
        "canvas": dict(profile.canvas),
        "audio": dict(profile.audio),
        "extra_http_headers": dict(profile.extra_http_headers),
    }


def _build_context_options(
    user_agent: str = "",
    fingerprint_scope: str = "auto_desktop",
    *,
    session_profile: Optional[SessionProfile] = None,
) -> Dict[str, Any]:
    profile = _resolve_session_profile(
        session_profile=session_profile,
        user_agent=user_agent,
        fingerprint_scope=fingerprint_scope,
    )
    context_kwargs = context_options_for_profile(profile)
    context_kwargs["_fingerprint"] = _build_fingerprint(session_profile=profile)
    return context_kwargs


def _build_fingerprint_init_script(fingerprint: Dict[str, Any]) -> str:
    nav = fingerprint.get("navigator") if isinstance(fingerprint.get("navigator"), dict) else {}
    webgl = fingerprint.get("webgl") if isinstance(fingerprint.get("webgl"), dict) else {}
    fonts = fingerprint.get("fonts") if isinstance(fingerprint.get("fonts"), dict) else {}
    canvas = fingerprint.get("canvas") if isinstance(fingerprint.get("canvas"), dict) else {}
    audio = fingerprint.get("audio") if isinstance(fingerprint.get("audio"), dict) else {}
    payload = {
        "webdriver": fingerprint.get("webdriver"),
        "navigator": nav,
        "webgl": webgl,
        "fonts": fonts,
        "canvas": canvas,
        "audio": audio,
    }
    return f"""
(() => {{
  const fp = {json.dumps(payload, ensure_ascii=False)};
  const defineGetter = (proto, prop, value) => {{
    try {{
      Object.defineProperty(proto, prop, {{
        get: () => value,
        configurable: true
      }});
    }} catch (_) {{}}
  }};

  try {{
    window.chrome = window.chrome || {{ runtime: {{}} }};
  }} catch (_) {{}}

  if (fp.webdriver === false) {{
    defineGetter(Navigator.prototype, "webdriver", undefined);
  }}

  const navMap = {{
    platform: "platform",
    vendor: "vendor",
    languages: "languages",
    hardware_concurrency: "hardwareConcurrency",
    device_memory: "deviceMemory",
    max_touch_points: "maxTouchPoints"
  }};
  for (const [cfgKey, navProp] of Object.entries(navMap)) {{
    if (Object.prototype.hasOwnProperty.call(fp.navigator || {{}}, cfgKey)) {{
      defineGetter(Navigator.prototype, navProp, fp.navigator[cfgKey]);
    }}
  }}

  const uaDataConfig = fp.navigator && fp.navigator.userAgentData;
  if (uaDataConfig && typeof uaDataConfig === "object") {{
    const cloneEntries = (entries) => (
      Array.isArray(entries)
        ? entries.map(entry => Object.freeze({{ ...entry }}))
        : []
    );
    const brands = Object.freeze(cloneEntries(uaDataConfig.brands));
    const highEntropyValues = uaDataConfig.highEntropyValues || {{}};
    const cloneValue = (value) => (
      Array.isArray(value)
        ? cloneEntries(value)
        : (value && typeof value === "object" ? {{ ...value }} : value)
    );
    const uaData = {{
      brands,
      mobile: Boolean(uaDataConfig.mobile),
      platform: String(uaDataConfig.platform || ""),
      getHighEntropyValues: async (hints = []) => {{
        const result = {{
          brands: cloneEntries(brands),
          mobile: Boolean(uaDataConfig.mobile),
          platform: String(uaDataConfig.platform || "")
        }};
        for (const hint of Array.isArray(hints) ? hints : []) {{
          if (Object.prototype.hasOwnProperty.call(highEntropyValues, hint)) {{
            result[hint] = cloneValue(highEntropyValues[hint]);
          }}
        }}
        return result;
      }},
      toJSON: () => ({{
        brands: cloneEntries(brands),
        mobile: Boolean(uaDataConfig.mobile),
        platform: String(uaDataConfig.platform || "")
      }})
    }};
    defineGetter(Navigator.prototype, "userAgentData", Object.freeze(uaData));
  }}

  defineGetter(Navigator.prototype, "plugins", [1, 2, 3, 4, 5]);

  try {{
    const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
    window.navigator.permissions.query = (parameters) => (
      parameters && parameters.name === "notifications"
        ? Promise.resolve({{ state: Notification.permission }})
        : originalQuery(parameters)
    );
  }} catch (_) {{}}

  const patchWebGL = (ctor) => {{
    if (!ctor || !ctor.prototype || !ctor.prototype.getParameter) return;
    const original = ctor.prototype.getParameter;
    ctor.prototype.getParameter = function(parameter) {{
      if (parameter === 37445 && fp.webgl && fp.webgl.vendor) return fp.webgl.vendor;
      if (parameter === 37446 && fp.webgl && fp.webgl.renderer) return fp.webgl.renderer;
      return original.apply(this, arguments);
    }};
  }};
  patchWebGL(window.WebGLRenderingContext);
  patchWebGL(window.WebGL2RenderingContext);

  const fontConfig = fp.fonts || {{}};
  if (fontConfig.enabled !== false) {{
    const fontFamilies = Array.isArray(fontConfig.families) ? fontConfig.families : [];
    const fontNoise = Number(fontConfig.noise || 0);
    if (document.fonts && document.fonts.check) {{
      const originalFontCheck = document.fonts.check.bind(document.fonts);
      document.fonts.check = function(font, text) {{
        const normalized = String(font || "").toLowerCase();
        if (fontFamilies.some(f => normalized.includes(String(f).toLowerCase()))) {{
          return true;
        }}
        return originalFontCheck(font, text);
      }};
    }}
    if (window.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype.measureText) {{
      const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
      CanvasRenderingContext2D.prototype.measureText = function(text) {{
        const metrics = originalMeasureText.apply(this, arguments);
        if (fontNoise) {{
          try {{
            Object.defineProperty(metrics, "width", {{
              value: metrics.width + fontNoise,
              configurable: true
            }});
          }} catch (_) {{}}
        }}
        return metrics;
      }};
    }}
  }}

  const canvasConfig = fp.canvas || {{}};
  if (canvasConfig.enabled !== false && window.CanvasRenderingContext2D) {{
    const canvasNoise = Number(canvasConfig.noise || 0);
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {{
      const imageData = originalGetImageData.apply(this, arguments);
      if (canvasNoise && imageData && imageData.data) {{
        const stride = Math.max(4, Math.floor(imageData.data.length / 64));
        for (let i = 0; i < imageData.data.length; i += stride) {{
          imageData.data[i] = (imageData.data[i] + canvasNoise) & 255;
        }}
      }}
      return imageData;
    }};
  }}

  const audioConfig = fp.audio || {{}};
  if (audioConfig.enabled !== false && window.AudioBuffer && AudioBuffer.prototype.getChannelData) {{
    const audioNoise = Number(audioConfig.noise || 0);
    const originalGetChannelData = AudioBuffer.prototype.getChannelData;
    const patchedAudioChannels = new WeakMap();
    AudioBuffer.prototype.getChannelData = function(channel) {{
      const data = originalGetChannelData.apply(this, arguments);
      let patchedChannels = patchedAudioChannels.get(this);
      if (!patchedChannels) {{
        patchedChannels = new Set();
        patchedAudioChannels.set(this, patchedChannels);
      }}
      const channelIndex = Number(channel || 0);
      if (
        audioNoise
        && data
        && typeof data.length === "number"
        && !patchedChannels.has(channelIndex)
      ) {{
        const stride = Math.max(1, Math.floor(data.length / 64));
        for (let i = 0; i < data.length; i += stride) {{
          data[i] = data[i] + audioNoise;
        }}
        patchedChannels.add(channelIndex);
      }}
      return data;
    }};
  }}
}})();
"""


def fingerprint_init_script_for_profile(profile: SessionProfile) -> str:
    return _build_fingerprint_init_script(_build_fingerprint(session_profile=profile))


def _browserforge_cache_key(profile: SessionProfile) -> str:
    serialized = json.dumps(
        profile.to_legacy_dict(),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _canonicalize_browserforge_fingerprint(
    fingerprint: Any,
    profile: SessionProfile,
) -> Any:
    profile.validate()
    fingerprint.headers = dict(profile.http_headers)

    navigator = fingerprint.navigator
    navigator.userAgent = profile.user_agent
    navigator.language = profile.locale
    navigator.languages = list(profile.navigator.get("languages") or ())
    navigator.platform = str(profile.navigator["platform"])
    navigator.deviceMemory = int(profile.navigator["device_memory"])
    navigator.hardwareConcurrency = int(
        profile.navigator["hardware_concurrency"]
    )
    navigator.maxTouchPoints = int(profile.navigator["max_touch_points"])
    ua_data = user_agent_data_for_profile(profile)
    navigator.userAgentData = {
        "brands": copy.deepcopy(ua_data["brands"]),
        "mobile": bool(ua_data["mobile"]),
        "platform": str(ua_data["platform"]),
        **copy.deepcopy(ua_data["highEntropyValues"]),
    }

    screen = fingerprint.screen
    screen_width = int(profile.screen["width"])
    screen_height = int(profile.screen["height"])
    viewport_width = int(profile.viewport["width"])
    viewport_height = int(profile.viewport["height"])
    for attribute in ("width", "availWidth", "outerWidth"):
        setattr(screen, attribute, screen_width)
    for attribute in ("height", "availHeight", "outerHeight"):
        setattr(screen, attribute, screen_height)
    for attribute in ("innerWidth", "clientWidth"):
        setattr(screen, attribute, viewport_width)
    for attribute in ("innerHeight", "clientHeight"):
        setattr(screen, attribute, viewport_height)
    screen.devicePixelRatio = float(profile.device_scale_factor)

    try:
        from browserforge.fingerprints.generator import VideoCard  # type: ignore

        fingerprint.videoCard = VideoCard(
            renderer=str(profile.webgl["renderer"]),
            vendor=str(profile.webgl["vendor"]),
        )
    except Exception:
        video_card = getattr(fingerprint, "videoCard", None)
        if video_card is None:
            raise RuntimeError("BrowserForge fingerprint has no mutable video card")
        video_card.renderer = str(profile.webgl["renderer"])
        video_card.vendor = str(profile.webgl["vendor"])
    fingerprint.fonts = list(profile.fonts.get("families") or ())
    return fingerprint


def _browserforge_fingerprint_for_profile(
    profile: SessionProfile,
    *,
    fingerprint_scope: str,
) -> Any:
    cache_key = _browserforge_cache_key(profile)
    # BrowserForge owns global generators internally; serializing the bounded
    # first-fill path also guarantees one sampled payload per session profile.
    with _BROWSERFORGE_CACHE_LOCK:
        cached = _BROWSERFORGE_CACHE.get(cache_key)
        if cached is not None:
            _BROWSERFORGE_CACHE.move_to_end(cache_key)
            success, value = cached
            if not success:
                raise RuntimeError(str(value))
            return copy.deepcopy(value)

        try:
            from browserforge.fingerprints import FingerprintGenerator, Screen  # type: ignore

            generator_options = browserforge_options_for_scope(fingerprint_scope)
            generator_options.update(
                {
                    "browser": profile.browser,
                    "os": profile.os,
                    "device": "mobile" if profile.is_mobile else "desktop",
                    "locale": profile.locale,
                }
            )
            generator = FingerprintGenerator(**generator_options)
            screen = Screen(
                min_width=int(profile.screen["width"]),
                max_width=int(profile.screen["width"]),
                min_height=int(profile.screen["height"]),
                max_height=int(profile.screen["height"]),
            )
            fingerprint = generator.generate(
                strict=True,
                screen=screen,
                user_agent=profile.user_agent,
            )
            generated_headers = getattr(fingerprint, "headers", {}) or {}
            generated_ua = str(
                generated_headers.get("User-Agent")
                or generated_headers.get("user-agent")
                or ""
            ).strip()
            if generated_ua != profile.user_agent:
                raise RuntimeError(
                    "BrowserForge generated a different User-Agent"
                )
            fingerprint = _canonicalize_browserforge_fingerprint(
                fingerprint,
                profile,
            )
        except Exception as exc:
            failure = f"{type(exc).__name__}: {exc}"
            _BROWSERFORGE_CACHE[cache_key] = (False, failure)
            _BROWSERFORGE_CACHE.move_to_end(cache_key)
            while len(_BROWSERFORGE_CACHE) > _BROWSERFORGE_CACHE_MAX_SIZE:
                _BROWSERFORGE_CACHE.popitem(last=False)
            raise RuntimeError(failure) from exc

        _BROWSERFORGE_CACHE[cache_key] = (
            True,
            copy.deepcopy(fingerprint),
        )
        _BROWSERFORGE_CACHE.move_to_end(cache_key)
        while len(_BROWSERFORGE_CACHE) > _BROWSERFORGE_CACHE_MAX_SIZE:
            _BROWSERFORGE_CACHE.popitem(last=False)
        return copy.deepcopy(fingerprint)

def _new_browserforge_context(
    browser: Any,
    *,
    fingerprint_scope: str,
    session_profile: Optional[SessionProfile] = None,
) -> Any:
    if session_profile is None:
        raise RuntimeError("BrowserForge requires an immutable SessionProfile")

    from browserforge.injectors.playwright import NewContext  # type: ignore

    fingerprint = _browserforge_fingerprint_for_profile(
        session_profile,
        fingerprint_scope=fingerprint_scope,
    )
    context = NewContext(
        browser,
        fingerprint=fingerprint,
        **context_options_for_profile(session_profile),
    )
    context.add_init_script(
        fingerprint_init_script_for_profile(session_profile)
    )

    def _restore_media(page: Any) -> None:
        try:
            page.emulate_media(
                color_scheme=session_profile.color_scheme,
                reduced_motion=session_profile.reduced_motion,
            )
        except Exception:
            pass

    context.on("page", _restore_media)
    return context

def _build_launch_options(proxy: Optional[str], headless: bool) -> Dict[str, Any]:
    launch_options: Dict[str, Any] = {
        "headless": bool(headless),
        "args": [
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--disable-infobars",
            "--disable-search-engine-choice-screen",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-size=1920,1080",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ],
        "ignore_default_args": ["--enable-automation"],
    }
    proxy_value = str(proxy or "").strip()
    if proxy_value:
        launch_options["proxy"] = {"server": proxy_value}
    return launch_options


def _normalize_flow_candidates(flow_candidates: Optional[Sequence[str]]) -> list[str]:
    if flow_candidates is None:
        # None means "use the gmailreg-v2 create-account protocol":
        # load the auth authorize surface, call SentinelSDK without a flow,
        # then stamp the returned browser token with username_password_create
        # and build the oauth_create_account session-observer wrapper.
        return []
    candidates = flow_candidates or DEFAULT_CREATE_ACCOUNT_FLOW_CANDIDATES
    normalized: list[str] = []
    seen: set[str] = set()
    for flow in candidates:
        flow_name = str(flow or "").strip()
        if not flow_name or flow_name in seen:
            continue
        seen.add(flow_name)
        normalized.append(flow_name)
    if normalized:
        return normalized
    return list(DEFAULT_CREATE_ACCOUNT_FLOW_CANDIDATES)


def _build_gmailreg_style_authorize_url() -> str:
    scope = "openid email profile offline_access model.request model.read organization.read organization.write"
    device_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    return (
        "https://auth.openai.com/api/accounts/authorize"
        f"?client_id={CHATGPT_WEB_CLIENT_ID}"
        f"&scope={quote(scope)}"
        "&response_type=code"
        f"&redirect_uri={quote('https://chatgpt.com/api/auth/callback/openai')}"
        f"&audience={quote('https://api.openai.com/v1')}"
        f"&device_id={device_id}"
        "&prompt=login"
        "&screen_hint=signup"
        f"&state={state}"
    )


def _extract_token_from_result(result: Any) -> str:
    if isinstance(result, str):
        return result.strip()
    if isinstance(result, dict):
        token = result.get("token")
        if isinstance(token, str):
            return token.strip()
    return ""


def _normalize_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _normalize_capture_bundle(result: Any) -> Dict[str, Any]:
    if isinstance(result, str):
        return {
            "flow": "",
            "token": result.strip(),
            "so_token": "",
            "challenge_request": {},
            "challenge_response": {},
            "req_p": "",
            "challenge_token": "",
            "pow_required": False,
            "pow_seed": "",
            "pow_difficulty": "",
            "error": "",
        }

    source = result if isinstance(result, dict) else {}
    challenge_request = source.get("challenge_request")
    if not isinstance(challenge_request, dict):
        challenge_request = {}
    challenge_response = source.get("challenge_response")
    if not isinstance(challenge_response, dict):
        challenge_response = {}
    proof_of_work = challenge_response.get("proofofwork")
    if not isinstance(proof_of_work, dict):
        proof_of_work = {}

    bundle = {
        "flow": _normalize_string(source.get("flow")),
        "token": _extract_token_from_result(source),
        "so_token": _normalize_string(source.get("so_token")),
        "challenge_request": challenge_request,
        "challenge_response": challenge_response,
        "req_p": _normalize_string(source.get("req_p")) or _normalize_string(challenge_request.get("p")),
        "challenge_token": _normalize_string(source.get("challenge_token"))
        or _normalize_string(challenge_response.get("token")),
        "pow_required": bool(source.get("pow_required"))
        if "pow_required" in source
        else bool(proof_of_work.get("required")),
        "pow_seed": _normalize_string(source.get("pow_seed")) or _normalize_string(proof_of_work.get("seed")),
        "pow_difficulty": _normalize_string(source.get("pow_difficulty"))
        or _normalize_string(proof_of_work.get("difficulty")),
        "error": _normalize_string(source.get("error")),
    }
    return bundle


def _run_browser_sentinel_capture(
    *,
    page_url: str = DEFAULT_BROWSER_SENTINEL_PAGE_URL,
    headless: bool = True,
    timeout_seconds: int = DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
    flow_candidates: Optional[Sequence[str]] = None,
    fingerprint_scope: str = "auto_desktop",
    fingerprint_engine: str = "internal",
) -> Dict[str, Any]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise RuntimeError(f"Playwright unavailable: {exc}") from exc

    timeout_ms = max(3000, int(float(timeout_seconds or DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS) * 1000))
    flows = _normalize_flow_candidates(flow_candidates)
    use_gmailreg_create_account_protocol = not flows
    target_url = (
        _build_gmailreg_style_authorize_url()
        if use_gmailreg_create_account_protocol
        else (str(page_url or DEFAULT_BROWSER_SENTINEL_PAGE_URL).strip() or DEFAULT_BROWSER_SENTINEL_PAGE_URL)
    )
    browser = None
    context = None
    page = None

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**_build_launch_options(proxy, headless))
            profile = _resolve_session_profile(
                session_profile=session_profile,
                user_agent=user_agent,
                fingerprint_scope=fingerprint_scope,
            )
            context_kwargs = _build_context_options(session_profile=profile)
            fingerprint = context_kwargs.pop("_fingerprint", {})
            requested_engine = str(fingerprint_engine or "internal").strip().lower()
            engine_metadata: FingerprintEngineMetadata
            if requested_engine in {"browserforge", "auto"}:
                try:
                    context = _new_browserforge_context(
                        browser,
                        fingerprint_scope=fingerprint_scope,
                        session_profile=profile,
                    )
                except Exception as exc:
                    context = None
                    engine_metadata = resolve_fingerprint_engine(
                        requested_engine,
                        browserforge_available=False,
                        fallback_reason=f"{type(exc).__name__}: {exc}",
                    )
                else:
                    engine_metadata = resolve_fingerprint_engine(requested_engine, browserforge_available=True)
            else:
                engine_metadata = resolve_fingerprint_engine("internal", browserforge_available=False)
            if context is None:
                context = browser.new_context(**context_kwargs)
                context.add_init_script(_build_fingerprint_init_script(fingerprint))
            page = context.new_page()
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception:
                page.goto(target_url, wait_until="commit", timeout=timeout_ms)
            page.wait_for_timeout(min(DEFAULT_BROWSER_SENTINEL_WARMUP_MS, timeout_ms))
            page.wait_for_function("() => !!window.SentinelSDK", timeout=min(30000, timeout_ms))
            result = page.evaluate(
                """async (flows) => {
                    if (!window.SentinelSDK) throw new Error('SentinelSDK missing');

                    const sentinelPath = '/backend-api/sentinel/req';
                    const capture = {
                        flow: '',
                        token: '',
                        so_token: '',
                        challenge_request: {},
                        challenge_response: {},
                        req_p: '',
                        challenge_token: '',
                        pow_required: false,
                        pow_seed: '',
                        pow_difficulty: '',
                        error: '',
                    };

                    const toText = async (value) => {
                        if (typeof value === 'string') return value;
                        if (value == null) return '';
                        if (typeof Blob !== 'undefined' && value instanceof Blob) {
                            try { return await value.text(); } catch (error) { return ''; }
                        }
                        if (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams) {
                            return value.toString();
                        }
                        if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
                            try { return new TextDecoder().decode(value); } catch (error) { return ''; }
                        }
                        if (typeof value === 'object' && typeof value.toString === 'function' && value.toString !== Object.prototype.toString) {
                            try { return String(value.toString()); } catch (error) { return ''; }
                        }
                        return '';
                    };

                    const deviceId = () => {
                        try {
                            const match = document.cookie.match(/(?:^|;\\s*)oai-did=([^;]+)/);
                            if (match && match[1]) return decodeURIComponent(match[1]);
                        } catch (error) {}
                        try {
                            if (crypto && crypto.randomUUID) return crypto.randomUUID();
                        } catch (error) {}
                        return '';
                    };

                    const normalizeSentinelToken = (value, flow, did) => {
                        const raw = typeof value === 'string'
                            ? value.trim()
                            : (value && typeof value.token === 'string' ? value.token.trim() : '');
                        if (!raw) return '';
                        try {
                            const parsed = JSON.parse(raw);
                            if (parsed && typeof parsed === 'object') {
                                if (did && !parsed.id) parsed.id = did;
                                if (flow && !parsed.flow) parsed.flow = flow;
                                return JSON.stringify(parsed);
                            }
                        } catch (error) {}
                        return raw;
                    };

                    const parseMaybeJson = (value) => {
                        if (!value) return {};
                        if (typeof value === 'object') return value;
                        if (typeof value !== 'string') return {};
                        try {
                            const parsed = JSON.parse(value);
                            return parsed && typeof parsed === 'object' ? parsed : {};
                        } catch (error) {
                            return {};
                        }
                    };

                    const assignRequest = (payload) => {
                        if (!payload || typeof payload !== 'object') return;
                        capture.challenge_request = payload;
                        if (typeof payload.p === 'string' && payload.p.trim()) capture.req_p = payload.p.trim();
                        if (typeof payload.flow === 'string' && payload.flow.trim() && !capture.flow) capture.flow = payload.flow.trim();
                    };

                    const assignResponse = (payload) => {
                        if (!payload || typeof payload !== 'object') return;
                        capture.challenge_response = payload;
                        if (typeof payload.token === 'string' && payload.token.trim()) capture.challenge_token = payload.token.trim();
                        const proof = payload.proofofwork;
                        if (proof && typeof proof === 'object') {
                            capture.pow_required = !!proof.required;
                            if (typeof proof.seed === 'string' && proof.seed.trim()) capture.pow_seed = proof.seed.trim();
                            if (typeof proof.difficulty === 'string' && proof.difficulty.trim()) capture.pow_difficulty = proof.difficulty.trim();
                        }
                    };

                    const isTargetUrl = (value) => typeof value === 'string' && value.includes(sentinelPath);

                    if (!window.__sentinelCaptureInstalled) {
                        const originalFetch = window.fetch.bind(window);
                        window.fetch = async (...args) => {
                            let url = '';
                            let requestBody = '';
                            const input = args[0];
                            const init = args[1] || {};
                            try {
                                if (typeof input === 'string') {
                                    url = input;
                                } else if (input && typeof input.url === 'string') {
                                    url = input.url;
                                }
                                if (init && init.body !== undefined) {
                                    requestBody = await toText(init.body);
                                } else if (input && typeof input.clone === 'function') {
                                    try {
                                        requestBody = await input.clone().text();
                                    } catch (error) {
                                        requestBody = '';
                                    }
                                }
                            } catch (error) {
                                requestBody = '';
                            }

                            if (isTargetUrl(url)) {
                                assignRequest(parseMaybeJson(requestBody));
                            }

                            const response = await originalFetch(...args);
                            if (isTargetUrl(url) && response && typeof response.clone === 'function') {
                                try {
                                    const responseText = await response.clone().text();
                                    assignResponse(parseMaybeJson(responseText));
                                } catch (error) {
                                    // ignore capture failures
                                }
                            }
                            return response;
                        };

                        const originalXhrOpen = XMLHttpRequest.prototype.open;
                        const originalXhrSend = XMLHttpRequest.prototype.send;
                        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                            this.__sentinelUrl = typeof url === 'string' ? url : String(url || '');
                            return originalXhrOpen.call(this, method, url, ...rest);
                        };
                        XMLHttpRequest.prototype.send = function(body) {
                            const requestUrl = this.__sentinelUrl || '';
                            if (isTargetUrl(requestUrl)) {
                                Promise.resolve(toText(body))
                                    .then((requestBody) => assignRequest(parseMaybeJson(requestBody)))
                                    .catch(() => {});
                                this.addEventListener('load', () => {
                                    try {
                                        assignResponse(parseMaybeJson(this.responseText || ''));
                                    } catch (error) {
                                        // ignore capture failures
                                    }
                                }, { once: true });
                            }
                            return originalXhrSend.call(this, body);
                        };
                        window.__sentinelCaptureInstalled = true;
                    }

                    let lastError = '';
                    const did = deviceId();
                    if (!Array.isArray(flows) || flows.length === 0) {
                        try {
                            // gmailreg-v2 compatible create_account protocol:
                            // do not ask SentinelSDK for an oauth_create_account token directly.
                            // OpenAI accepts the normal username_password_create browser token
                            // plus a separate oauth_create_account session-observer wrapper.
                            await window.SentinelSDK.init();
                            const rawToken = await window.SentinelSDK.token();
                            const parsedToken = parseMaybeJson(rawToken);
                            let finalBrowserToken = typeof rawToken === 'string' ? rawToken.trim() : '';
                            if (parsedToken && typeof parsedToken === 'object' && Object.keys(parsedToken).length > 0) {
                                parsedToken.id = did;
                                parsedToken.flow = 'username_password_create';
                                finalBrowserToken = JSON.stringify(parsedToken);
                            }
                            const rawSo = await window.SentinelSDK.token();
                            const parsedSo = parseMaybeJson(rawSo);
                            const soPayload = {
                                so: rawSo,
                                c: parsedSo && typeof parsedSo.c === 'string' ? parsedSo.c : '',
                                id: did,
                                flow: 'oauth_create_account',
                            };
                            capture.flow = 'username_password_create';
                            capture.token = finalBrowserToken;
                            capture.so_token = JSON.stringify(soPayload);
                            return capture;
                        } catch (error) {
                            capture.error = String(error || '');
                            return capture;
                        }
                    }
                    for (const flow of flows) {
                        try {
                            await window.SentinelSDK.init(flow);
                            const tokenResult = await window.SentinelSDK.token(flow);
                            let soToken = null;
                            try {
                                soToken = await window.SentinelSDK.sessionObserverToken(flow);
                            } catch (error) {
                                soToken = null;
                            }

                            const finalToken = normalizeSentinelToken(tokenResult, flow, did);

                            if (typeof flow === 'string' && flow.trim()) {
                                capture.flow = flow.trim();
                            }
                            capture.so_token = typeof soToken === 'string' ? soToken.trim() : '';

                            if (finalToken) {
                                capture.token = finalToken;
                                return capture;
                            }
                        } catch (error) {
                            lastError = String(error || '');
                        }
                    }

                    capture.error = lastError;
                    return capture;
                }""",
                flows,
            )
            bundle = _normalize_capture_bundle(result)
            bundle["fingerprint_metadata"] = {
                "profile_id": profile.profile_id,
                "scope": profile.scope,
                "browser": profile.browser,
                "major": profile.major,
                "version_policy": profile.version_policy,
                "version_fallback_reason": profile.version_fallback_reason,
                "engine": {
                    "requested": engine_metadata.requested,
                    "effective": engine_metadata.effective,
                    "fallback_reason": engine_metadata.fallback_reason,
                },
            }
            return bundle
    except PlaywrightTimeoutError as exc:
        raise RuntimeError(f"browser sentinel timeout: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"browser sentinel failed: {exc}") from exc
    finally:
        _close_quietly(page)
        _close_quietly(context)
        _close_quietly(browser)


def get_browser_sentinel_bundle_for_create_account(
    *,
    page_url: str = DEFAULT_BROWSER_SENTINEL_PAGE_URL,
    headless: bool = True,
    timeout_seconds: int = DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
    flow_candidates: Optional[Sequence[str]] = None,
    fingerprint_scope: str = "auto_desktop",
    fingerprint_engine: str = "internal",
) -> Dict[str, Any]:
    return _run_browser_sentinel_capture(
        page_url=page_url,
        headless=headless,
        timeout_seconds=timeout_seconds,
        proxy=proxy,
        user_agent=user_agent,
        session_profile=session_profile,
        flow_candidates=flow_candidates,
        fingerprint_scope=fingerprint_scope,
        fingerprint_engine=fingerprint_engine,
    )


def get_browser_sentinel_token_for_create_account(
    *,
    page_url: str = DEFAULT_BROWSER_SENTINEL_PAGE_URL,
    headless: bool = True,
    timeout_seconds: int = DEFAULT_BROWSER_SENTINEL_TIMEOUT_SECONDS,
    proxy: Optional[str] = None,
    user_agent: str = "",
    session_profile: Optional[SessionProfile] = None,
    flow_candidates: Optional[Sequence[str]] = None,
    fingerprint_scope: str = "auto_desktop",
    fingerprint_engine: str = "internal",
) -> Optional[str]:
    bundle = get_browser_sentinel_bundle_for_create_account(
        page_url=page_url,
        headless=headless,
        timeout_seconds=timeout_seconds,
        proxy=proxy,
        user_agent=user_agent,
        session_profile=session_profile,
        flow_candidates=flow_candidates,
        fingerprint_scope=fingerprint_scope,
        fingerprint_engine=fingerprint_engine,
    )
    token = _extract_token_from_result(bundle)
    if token:
        return token
    raise RuntimeError("browser page did not expose a sentinel token")
