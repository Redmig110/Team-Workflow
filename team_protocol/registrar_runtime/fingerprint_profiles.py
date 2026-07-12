from __future__ import annotations

import random
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Iterable, Optional, get_args


@dataclass(frozen=True, slots=True)
class HttpChromeVersion:
    major: int
    impersonate: str
    version_prefix: str
    patch_range: tuple[int, int]
    generated: bool = True
    mobile_impersonate: str = ""
    edge_impersonate: str = ""
    edge_generated: bool = False
    sec_ch_ua: str = ""
    edge_sec_ch_ua: str = ""
    edge_version_prefix: str = ""
    edge_patch_range: tuple[int, int] = (0, 0)

    def impersonate_for(self, *, mobile: bool = False, browser: str = "chrome") -> str:
        if browser == "edge":
            return self.edge_impersonate
        return self.mobile_impersonate if mobile else self.impersonate

    def generated_for(self, *, browser: str = "chrome") -> bool:
        return self.edge_generated if browser == "edge" else self.generated

    def sec_ch_ua_for(self, *, browser: str = "chrome") -> str:
        return self.edge_sec_ch_ua if browser == "edge" else self.sec_ch_ua


@dataclass(frozen=True, slots=True)
class FingerprintEngineMetadata:
    requested: str
    effective: str
    fallback_reason: str = ""


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class SessionProfile(Mapping[str, Any]):
    profile_id: str
    scope: str
    browser: str
    os: str
    major: int
    requested_major: int
    version: str
    chromium_version: str
    version_policy: str
    version_fallback_reason: str
    impersonate: str
    user_agent: str
    accept_language: str
    locale: str
    timezone_id: str
    viewport: Mapping[str, Any]
    screen: Mapping[str, Any]
    device_scale_factor: float
    is_mobile: bool
    has_touch: bool
    color_scheme: str
    reduced_motion: str
    navigator: Mapping[str, Any]
    webgl: Mapping[str, Any]
    fonts: Mapping[str, Any]
    canvas: Mapping[str, Any]
    audio: Mapping[str, Any]
    extra_http_headers: Mapping[str, str]
    http_headers: Mapping[str, str]

    def to_legacy_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "scope": self.scope,
            "browser": self.browser,
            "os": self.os,
            "major": self.major,
            "requested_major": self.requested_major,
            "version": self.version,
            "chromium_version": self.chromium_version,
            "version_policy": self.version_policy,
            "version_fallback_reason": self.version_fallback_reason,
            "impersonate": self.impersonate,
            "user_agent": self.user_agent,
            "accept_language": self.accept_language,
            "locale": self.locale,
            "timezone_id": self.timezone_id,
            "viewport": _deep_thaw(self.viewport),
            "screen": _deep_thaw(self.screen),
            "device_scale_factor": self.device_scale_factor,
            "is_mobile": self.is_mobile,
            "has_touch": self.has_touch,
            "color_scheme": self.color_scheme,
            "reduced_motion": self.reduced_motion,
            "navigator": _deep_thaw(self.navigator),
            "webgl": _deep_thaw(self.webgl),
            "fonts": _deep_thaw(self.fonts),
            "canvas": _deep_thaw(self.canvas),
            "audio": _deep_thaw(self.audio),
            "extra_http_headers": dict(self.extra_http_headers),
            "http_headers": dict(self.http_headers),
        }

    def playwright_context_options(self) -> Dict[str, Any]:
        return context_options_for_profile(self)

    def init_script_payload(self) -> Dict[str, Any]:
        navigator = _deep_thaw(self.navigator)
        navigator["userAgentData"] = user_agent_data_for_profile(self)
        return {
            "webdriver": False,
            "navigator": navigator,
            "webgl": _deep_thaw(self.webgl),
            "fonts": _deep_thaw(self.fonts),
            "canvas": _deep_thaw(self.canvas),
            "audio": _deep_thaw(self.audio),
        }

    def validate(self) -> "SessionProfile":
        validate_session_profile(self)
        return self

    def __getitem__(self, key: str) -> Any:
        return self.to_legacy_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_legacy_dict())

    def __len__(self) -> int:
        return len(self.to_legacy_dict())


SUPPORTED_HTTP_CHROME_VERSIONS: dict[int, HttpChromeVersion] = {
    101: HttpChromeVersion(
        101,
        "",
        "101.0.4951",
        (64, 64),
        generated=False,
        edge_impersonate="edge101",
        edge_generated=True,
        sec_ch_ua='" Not A;Brand";v="99", "Chromium";v="101", "Google Chrome";v="101"',
        edge_sec_ch_ua='" Not A;Brand";v="99", "Chromium";v="101", "Microsoft Edge";v="101"',
        edge_version_prefix="101.0.1210",
        edge_patch_range=(47, 47),
    ),
    119: HttpChromeVersion(
        119,
        "chrome119",
        "119.0.6045",
        (123, 200),
        generated=False,
        sec_ch_ua='"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
    ),
    120: HttpChromeVersion(
        120,
        "chrome120",
        "120.0.6099",
        (62, 200),
        generated=False,
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    ),
    123: HttpChromeVersion(
        123,
        "chrome123",
        "123.0.6312",
        (46, 170),
        generated=False,
        sec_ch_ua='"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
    ),
    124: HttpChromeVersion(
        124,
        "chrome124",
        "124.0.6367",
        (60, 180),
        sec_ch_ua='"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    ),
    131: HttpChromeVersion(
        131,
        "chrome131",
        "131.0.6778",
        (85, 265),
        mobile_impersonate="chrome131_android",
        sec_ch_ua='"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    ),
    133: HttpChromeVersion(
        133,
        "chrome133a",
        "133.0.6943",
        (53, 141),
        sec_ch_ua='"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    ),
    136: HttpChromeVersion(
        136,
        "chrome136",
        "136.0.7103",
        (48, 114),
        sec_ch_ua='"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    ),
    142: HttpChromeVersion(
        142,
        "chrome142",
        "142.0.7444",
        (59, 175),
        sec_ch_ua='"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    ),
}

_CHROME_UA_RE = re.compile(r"Chrome/(\d+)(?:\.([0-9.]+))?", re.IGNORECASE)
_EDGE_UA_RE = re.compile(r"Edg/(\d+)(?:\.([0-9.]+))?", re.IGNORECASE)
_UA_CH_BRAND_RE = re.compile(r'"([^"]+)";v="([^"]+)"')


PROFILE_SCOPE_OPTIONS = (
    "auto_desktop",
    "all_desktop",
    "windows",
    "macos",
    "linux",
    "edge",
    "mobile",
    "all",
)


_COMMON_FONTS = (
    "Arial",
    "Calibri",
    "Cambria",
    "Candara",
    "Consolas",
    "Courier New",
    "Georgia",
    "Segoe UI",
    "Tahoma",
    "Times New Roman",
    "Verdana",
)

_PROFILE_CATALOG: tuple[Dict[str, Any], ...] = (
    {
        "id": "win10_chrome_intel_us",
        "scope": ("auto_desktop", "all_desktop", "windows", "all"),
        "browser": "chrome",
        "os": "windows",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "sec_ch_platform": '"Windows"',
        "navigator_platform": "Win32",
        "platform_version": lambda rng: f'"{rng.randint(10, 15)}.0.0"',
        "viewports": (
            {"width": 1366, "height": 768},
            {"width": 1440, "height": 900},
            {"width": 1536, "height": 864},
            {"width": 1920, "height": 1080},
        ),
        "hardware": (
            {"hardware_concurrency": 4, "device_memory": 8},
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 12, "device_memory": 16},
        ),
        "webgl": (
            {
                "vendor": "Google Inc. (Intel)",
                "renderer": "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            {
                "vendor": "Google Inc. (Intel)",
                "renderer": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
        ),
        "fonts": _COMMON_FONTS + ("Microsoft Sans Serif", "Trebuchet MS"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Chicago", "America/Los_Angeles")),),
    },
    {
        "id": "win11_chrome_nvidia_us",
        "scope": ("auto_desktop", "all_desktop", "windows", "all"),
        "browser": "chrome",
        "os": "windows",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "sec_ch_platform": '"Windows"',
        "navigator_platform": "Win32",
        "platform_version": lambda rng: f'"{rng.randint(13, 15)}.0.0"',
        "viewports": (
            {"width": 1440, "height": 900},
            {"width": 1600, "height": 900},
            {"width": 1920, "height": 1080},
            {"width": 2560, "height": 1440},
        ),
        "hardware": (
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 12, "device_memory": 16},
            {"hardware_concurrency": 16, "device_memory": 16},
        ),
        "webgl": (
            {
                "vendor": "Google Inc. (NVIDIA)",
                "renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
            {
                "vendor": "Google Inc. (NVIDIA)",
                "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
        ),
        "fonts": _COMMON_FONTS + ("Bahnschrift", "Segoe UI Variable"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Denver", "America/Los_Angeles")),),
    },
    {
        "id": "macos_chrome_apple_us",
        "scope": ("auto_desktop", "all_desktop", "macos", "all"),
        "browser": "chrome",
        "os": "macos",
        "ua_os": "Macintosh; Intel Mac OS X 10_15_7",
        "sec_ch_platform": '"macOS"',
        "navigator_platform": "MacIntel",
        "arch": '"arm"',
        "platform_version": lambda rng: f'"{rng.randint(12, 14)}.{rng.randint(0, 7)}.{rng.randint(0, 9)}"',
        "viewports": (
            {"width": 1440, "height": 900},
            {"width": 1512, "height": 982},
            {"width": 1728, "height": 1117},
        ),
        "hardware": (
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 10, "device_memory": 16},
        ),
        "webgl": (
            {"vendor": "Google Inc. (Apple)", "renderer": "ANGLE (Apple, Apple M1, OpenGL 4.1)"},
            {"vendor": "Google Inc. (Apple)", "renderer": "ANGLE (Apple, Apple M2, OpenGL 4.1)"},
        ),
        "fonts": (
            "Arial",
            "Arial Hebrew",
            "Avenir",
            "Courier",
            "Courier New",
            "Georgia",
            "Helvetica",
            "Helvetica Neue",
            "Menlo",
            "Monaco",
            "San Francisco",
            "Times",
            "Times New Roman",
            "Verdana",
        ),
        "locales": (
            ("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")),
            ("en-GB", "en-GB,en;q=0.9", ("Europe/London",)),
        ),
    },
    {
        "id": "linux_chrome_intel_us",
        "scope": ("auto_desktop", "all_desktop", "linux", "all"),
        "browser": "chrome",
        "os": "linux",
        "ua_os": "X11; Linux x86_64",
        "sec_ch_platform": '"Linux"',
        "navigator_platform": "Linux x86_64",
        "platform_version": lambda rng: '""',
        "viewports": (
            {"width": 1366, "height": 768},
            {"width": 1440, "height": 900},
            {"width": 1920, "height": 1080},
        ),
        "hardware": (
            {"hardware_concurrency": 4, "device_memory": 8},
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 16, "device_memory": 16},
        ),
        "webgl": (
            {"vendor": "Google Inc. (Intel)", "renderer": "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620, OpenGL)"},
            {"vendor": "Google Inc. (AMD)", "renderer": "ANGLE (AMD, AMD Radeon Graphics, OpenGL)"},
        ),
        "fonts": _COMMON_FONTS + ("Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans"),
        "locales": (
            ("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Chicago")),
            ("en-GB", "en-GB,en;q=0.9", ("Europe/London",)),
        ),
    },
    {
        "id": "win_edge_intel_us",
        "scope": ("edge", "all"),
        "browser": "edge",
        "os": "windows",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "sec_ch_platform": '"Windows"',
        "navigator_platform": "Win32",
        "platform_version": lambda rng: f'"{rng.randint(13, 15)}.0.0"',
        "viewports": (
            {"width": 1366, "height": 768},
            {"width": 1536, "height": 864},
            {"width": 1920, "height": 1080},
        ),
        "hardware": (
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 12, "device_memory": 16},
        ),
        "webgl": (
            {
                "vendor": "Google Inc. (Intel)",
                "renderer": "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
            },
        ),
        "fonts": _COMMON_FONTS + ("Bahnschrift", "Segoe UI Variable"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")),),
    },
    {
        "id": "android_chrome_pixel_us",
        "scope": ("mobile", "all"),
        "browser": "chrome",
        "os": "android",
        "ua_os": "Linux; Android 14; Pixel 7",
        "sec_ch_platform": '"Android"',
        "navigator_platform": "Linux armv81",
        "platform_version": lambda _rng: '"14.0.0"',
        "viewports": (
            {"width": 393, "height": 873},
            {"width": 412, "height": 915},
        ),
        "hardware": (
            {"hardware_concurrency": 8, "device_memory": 8},
            {"hardware_concurrency": 8, "device_memory": 6},
        ),
        "webgl": (
            {"vendor": "Google Inc. (Qualcomm)", "renderer": "ANGLE (Qualcomm, Adreno (TM) 730, OpenGL ES)"},
            {"vendor": "Google Inc. (ARM)", "renderer": "ANGLE (ARM, Mali-G710, OpenGL ES)"},
        ),
        "fonts": ("Roboto", "Noto Sans", "Arial", "Droid Sans"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")),),
        "device_scale_factor": 2.75,
        "mobile": True,
    },
    {
        "id": "win11_chrome_amd_global",
        "scope": ("auto_desktop", "all_desktop", "windows", "all"),
        "browser": "chrome",
        "os": "windows",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "sec_ch_platform": '"Windows"',
        "navigator_platform": "Win32",
        "platform_version": lambda rng: f'"{rng.randint(14, 19)}.0.0"',
        "viewports": ({"width": 1536, "height": 864}, {"width": 1920, "height": 1080}, {"width": 2560, "height": 1440}),
        "hardware": ({"hardware_concurrency": 8, "device_memory": 16}, {"hardware_concurrency": 16, "device_memory": 16}),
        "webgl": ({"vendor": "Google Inc. (AMD)", "renderer": "ANGLE (AMD, AMD Radeon RX 6600 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"},),
        "fonts": _COMMON_FONTS + ("Bahnschrift", "Segoe UI Variable"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Chicago", "America/Los_Angeles")),),
    },
    {
        "id": "macos_chrome_apple_m3_global",
        "scope": ("auto_desktop", "all_desktop", "macos", "all"),
        "browser": "chrome",
        "os": "macos",
        "ua_os": "Macintosh; Intel Mac OS X 10_15_7",
        "sec_ch_platform": '"macOS"',
        "navigator_platform": "MacIntel",
        "arch": '"arm"',
        "platform_version": lambda rng: f'"{rng.randint(13, 15)}.{rng.randint(0, 7)}.{rng.randint(0, 9)}"',
        "viewports": ({"width": 1512, "height": 982}, {"width": 1728, "height": 1117}, {"width": 1800, "height": 1169}),
        "hardware": ({"hardware_concurrency": 8, "device_memory": 8}, {"hardware_concurrency": 12, "device_memory": 16}),
        "webgl": ({"vendor": "Google Inc. (Apple)", "renderer": "ANGLE (Apple, Apple M3, OpenGL 4.1)"},),
        "fonts": ("Arial", "Avenir", "Courier", "Georgia", "Helvetica", "Helvetica Neue", "Menlo", "Monaco", "San Francisco", "Times New Roman", "Verdana"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")), ("en-GB", "en-GB,en;q=0.9", ("Europe/London",))),
    },
    {
        "id": "linux_chrome_nvidia_eu",
        "scope": ("auto_desktop", "all_desktop", "linux", "all"),
        "browser": "chrome",
        "os": "linux",
        "ua_os": "X11; Linux x86_64",
        "sec_ch_platform": '"Linux"',
        "navigator_platform": "Linux x86_64",
        "platform_version": lambda _rng: '""',
        "viewports": ({"width": 1440, "height": 900}, {"width": 1920, "height": 1080}, {"width": 2560, "height": 1440}),
        "hardware": ({"hardware_concurrency": 8, "device_memory": 8}, {"hardware_concurrency": 16, "device_memory": 16}),
        "webgl": ({"vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL)"},),
        "fonts": _COMMON_FONTS + ("Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans"),
        "locales": (("en-GB", "en-GB,en;q=0.9", ("Europe/London",)), ("de-DE", "de-DE,de;q=0.9,en;q=0.8", ("Europe/Berlin",))),
    },
    {
        "id": "win_edge_nvidia_global",
        "scope": ("edge", "all"),
        "browser": "edge",
        "os": "windows",
        "ua_os": "Windows NT 10.0; Win64; x64",
        "sec_ch_platform": '"Windows"',
        "navigator_platform": "Win32",
        "platform_version": lambda rng: f'"{rng.randint(14, 19)}.0.0"',
        "viewports": ({"width": 1536, "height": 864}, {"width": 1920, "height": 1080}),
        "hardware": ({"hardware_concurrency": 8, "device_memory": 8}, {"hardware_concurrency": 16, "device_memory": 16}),
        "webgl": ({"vendor": "Google Inc. (NVIDIA)", "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"},),
        "fonts": _COMMON_FONTS + ("Bahnschrift", "Segoe UI Variable"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")),),
    },
    {
        "id": "android_chrome_samsung_global",
        "scope": ("mobile", "all"),
        "browser": "chrome",
        "os": "android",
        "ua_os": "Linux; Android 14; SM-S918B",
        "sec_ch_platform": '"Android"',
        "navigator_platform": "Linux armv81",
        "platform_version": lambda _rng: '"14.0.0"',
        "viewports": ({"width": 360, "height": 800}, {"width": 384, "height": 854}, {"width": 412, "height": 915}),
        "hardware": ({"hardware_concurrency": 8, "device_memory": 8}, {"hardware_concurrency": 8, "device_memory": 12}),
        "webgl": ({"vendor": "Google Inc. (Qualcomm)", "renderer": "ANGLE (Qualcomm, Adreno (TM) 740, OpenGL ES)"},),
        "fonts": ("Roboto", "Noto Sans", "Arial", "Droid Sans"),
        "locales": (("en-US", "en-US,en;q=0.9", ("America/New_York", "America/Los_Angeles")),),
        "device_scale_factor": 3.0,
        "mobile": True,
    },
)


def normalize_profile_scope(scope: str | None) -> str:
    value = str(scope or "auto_desktop").strip().lower().replace("-", "_")
    aliases = {
        "auto": "auto_desktop",
        "desktop": "auto_desktop",
        "desktop_all": "all_desktop",
        "all_desktop_chrome": "all_desktop",
        "win": "windows",
        "mac": "macos",
        "osx": "macos",
        "android": "mobile",
    }
    value = aliases.get(value, value)
    if value not in PROFILE_SCOPE_OPTIONS:
        return "auto_desktop"
    return value


def _templates_for_scope(scope: str) -> list[Dict[str, Any]]:
    normalized = normalize_profile_scope(scope)
    matches = [template for template in _PROFILE_CATALOG if normalized in template.get("scope", ())]
    if matches:
        return matches
    return [template for template in _PROFILE_CATALOG if "auto_desktop" in template.get("scope", ())]


def _browser_from_user_agent(user_agent: str) -> str:
    return "edge" if _EDGE_UA_RE.search(str(user_agent or "")) else "chrome"


def _template_for_user_agent(user_agent: str, scope: str, rng: random.Random) -> Dict[str, Any]:
    text = str(user_agent or "")
    browser = _browser_from_user_agent(text)
    if "Android" in text:
        wanted_os = "android"
    elif "Macintosh" in text or "Mac OS X" in text:
        wanted_os = "macos"
    elif "Linux" in text or "X11" in text:
        wanted_os = "linux"
    else:
        wanted_os = "windows"

    candidates = [
        template
        for template in _templates_for_scope(scope)
        if template.get("os") == wanted_os and template.get("browser") == browser
    ]
    if not candidates:
        candidates = [
            template
            for template in _PROFILE_CATALOG
            if template.get("os") == wanted_os and template.get("browser") == browser
        ]
    if not candidates:
        raise ValueError(f"no fingerprint template for browser={browser!r}, os={wanted_os!r}")
    return rng.choice(candidates)


def _available_http_impersonations() -> set[str]:
    try:
        from curl_cffi.requests.impersonate import BrowserTypeLiteral

        available = {str(value) for value in get_args(BrowserTypeLiteral)}
        if available:
            return available
    except Exception:
        pass

    try:
        from curl_cffi.requests.impersonate import BrowserType

        available = {
            str(getattr(member, "value", member))
            for member in BrowserType
        }
        if available:
            return available
    except Exception:
        pass

    try:
        from curl_cffi.requests.impersonate import REAL_TARGET_MAP

        return {
            str(value)
            for value in dict(REAL_TARGET_MAP).values()
            if str(value)
        }
    except Exception:
        return set()


def _available_version_specs(
    *,
    generated_only: bool = False,
    mobile: bool = False,
    browser: str = "chrome",
) -> list[HttpChromeVersion]:
    available = _available_http_impersonations()
    specs = [
        spec
        for spec in SUPPORTED_HTTP_CHROME_VERSIONS.values()
        if spec.impersonate_for(mobile=mobile, browser=browser) in available
        and (spec.generated_for(browser=browser) or not generated_only)
    ]
    if generated_only and not specs:
        return _available_version_specs(
            generated_only=False,
            mobile=mobile,
            browser=browser,
        )
    if not specs:
        device = "Android" if mobile else browser.title()
        raise ValueError(f"curl-cffi does not expose a supported {device} impersonation profile")
    return specs


def _normalize_version_policy(value: str) -> str:
    policy = str(value or "strict").strip().lower()
    if policy not in {"strict", "nearest"}:
        raise ValueError(f"unsupported fingerprint version policy: {value!r}")
    return policy


def _version_pair_for_spec(
    spec: HttpChromeVersion,
    rng: random.Random,
    *,
    browser: str,
) -> tuple[str, str]:
    chromium_version = f"{spec.version_prefix}.{rng.randint(*spec.patch_range)}"
    if browser != "edge":
        return chromium_version, chromium_version
    if not spec.edge_version_prefix or spec.edge_patch_range == (0, 0):
        raise ValueError(f"Edge version metadata is unavailable for major {spec.major}")
    edge_version = f"{spec.edge_version_prefix}.{rng.randint(*spec.edge_patch_range)}"
    return chromium_version, edge_version


def _rewrite_user_agent_version(
    user_agent: str,
    chromium_version: str,
    browser_version: str = "",
) -> str:
    rewritten = re.sub(
        r"Chrome/[0-9.]+",
        f"Chrome/{chromium_version}",
        str(user_agent or ""),
        count=1,
    )
    if _EDGE_UA_RE.search(rewritten):
        rewritten = re.sub(
            r"Edg/[0-9.]+",
            f"Edg/{browser_version or chromium_version}",
            rewritten,
            count=1,
        )
    return rewritten


def _select_chrome_version(
    rng: random.Random,
    user_agent: str = "",
    *,
    version_policy: str = "strict",
    mobile: bool = False,
    browser: str = "chrome",
) -> tuple[int, int, str, str, HttpChromeVersion, str, str]:
    policy = _normalize_version_policy(version_policy)
    supplied_user_agent = str(user_agent or "").strip()
    chrome_match = _CHROME_UA_RE.search(supplied_user_agent)
    edge_match = _EDGE_UA_RE.search(supplied_user_agent)
    if supplied_user_agent and chrome_match is None:
        raise ValueError("user_agent must contain a Chrome/<major> version")
    if supplied_user_agent and browser == "edge" and edge_match is None:
        raise ValueError("Edge user_agent must contain an Edg/<major> version")
    if chrome_match:
        requested_major = int(chrome_match.group(1))
        if edge_match is not None and int(edge_match.group(1)) != requested_major:
            raise ValueError("Chrome and Edg major versions must match")
        spec = SUPPORTED_HTTP_CHROME_VERSIONS.get(requested_major)
        available = _available_http_impersonations()
        if (
            spec is not None
            and spec.impersonate_for(mobile=mobile, browser=browser) in available
        ):
            chrome_tail = str(chrome_match.group(2) or "").strip()
            chromium_version = (
                f"{requested_major}.{chrome_tail}"
                if chrome_tail
                else f"{spec.version_prefix}.{rng.randint(*spec.patch_range)}"
            )
            if browser == "edge":
                edge_tail = str(edge_match.group(2) or "").strip() if edge_match else ""
                browser_version = (
                    f"{requested_major}.{edge_tail}"
                    if edge_tail
                    else _version_pair_for_spec(spec, rng, browser=browser)[1]
                )
            else:
                browser_version = chromium_version
            return (
                requested_major,
                requested_major,
                chromium_version,
                browser_version,
                spec,
                "",
                supplied_user_agent,
            )
        if policy == "strict":
            supported = sorted(
                candidate.major
                for candidate in _available_version_specs(
                    mobile=mobile,
                    browser=browser,
                )
            )
            raise ValueError(
                f"unsupported {browser.title()} major {requested_major}; "
                f"supported majors: {supported}"
            )
        spec = min(
            _available_version_specs(mobile=mobile, browser=browser),
            key=lambda candidate: (abs(candidate.major - requested_major), -candidate.major),
        )
        chromium_version, browser_version = _version_pair_for_spec(
            spec,
            rng,
            browser=browser,
        )
        reason = (
            f"requested {browser.title()} {requested_major} is unavailable; "
            f"using nearest supported {browser.title()} {spec.major}"
        )
        return (
            requested_major,
            spec.major,
            chromium_version,
            browser_version,
            spec,
            reason,
            _rewrite_user_agent_version(
                supplied_user_agent,
                chromium_version,
                browser_version,
            ),
        )

    spec = rng.choice(
        _available_version_specs(
            generated_only=True,
            mobile=mobile,
            browser=browser,
        )
    )
    chromium_version, browser_version = _version_pair_for_spec(
        spec,
        rng,
        browser=browser,
    )
    return (
        spec.major,
        spec.major,
        chromium_version,
        browser_version,
        spec,
        "",
        "",
    )


def _sec_ch_ua(browser: str, spec: HttpChromeVersion) -> str:
    value = spec.sec_ch_ua_for(browser=browser)
    if not value:
        raise ValueError(
            f"Client Hints metadata is unavailable for {browser} {spec.major}"
        )
    return value

def resolve_fingerprint_engine(
    requested: str,
    *,
    browserforge_available: bool,
    fallback_reason: str = "",
) -> FingerprintEngineMetadata:
    normalized = str(requested or "internal").strip().lower()
    if normalized not in {"internal", "browserforge", "auto"}:
        normalized = "internal"
    if normalized == "internal":
        return FingerprintEngineMetadata(requested=normalized, effective="internal")
    if browserforge_available:
        return FingerprintEngineMetadata(requested=normalized, effective="browserforge")
    reason = str(fallback_reason or "browserforge is unavailable").strip()
    return FingerprintEngineMetadata(requested=normalized, effective="internal", fallback_reason=reason)


def create_session_profile(
    *,
    scope: str = "auto_desktop",
    user_agent: str = "",
    rng: Optional[random.Random] = None,
    version_policy: str = "strict",
) -> SessionProfile:
    rng = rng or random.SystemRandom()
    normalized_scope = normalize_profile_scope(scope)
    template = _template_for_user_agent(user_agent, normalized_scope, rng) if user_agent else rng.choice(_templates_for_scope(normalized_scope))
    mobile = bool(template.get("mobile"))
    browser = _browser_from_user_agent(user_agent) if user_agent else str(template.get("browser") or "chrome")
    requested_major, major, chromium_full, browser_full, spec, fallback_reason, resolved_user_agent = _select_chrome_version(
        rng,
        user_agent,
        version_policy=version_policy,
        mobile=mobile,
        browser=browser,
    )
    locale, accept_language, timezones = rng.choice(tuple(template["locales"]))
    viewport = dict(rng.choice(tuple(template["viewports"])))
    hardware = dict(rng.choice(tuple(template["hardware"])))
    webgl = dict(rng.choice(tuple(template["webgl"])))

    if resolved_user_agent:
        ua = resolved_user_agent
    elif browser == "edge":
        ua = (
            f"Mozilla/5.0 ({template['ua_os']}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chromium_full} Safari/537.36 Edg/{browser_full}"
        )
    elif mobile:
        ua = (
            f"Mozilla/5.0 ({template['ua_os']}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chromium_full} Mobile Safari/537.36"
        )
    else:
        ua = (
            f"Mozilla/5.0 ({template['ua_os']}) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{chromium_full} Safari/537.36"
        )

    platform_version_factory = template.get("platform_version")
    platform_version = platform_version_factory(rng) if callable(platform_version_factory) else str(platform_version_factory or '""')
    sec_headers = {
        "sec-ch-ua": _sec_ch_ua(browser, spec),
        "sec-ch-ua-mobile": "?1" if mobile else "?0",
        "sec-ch-ua-platform": str(template["sec_ch_platform"]),
        "sec-ch-ua-arch": str(template.get("arch") or ('"arm"' if mobile else '"x86"')),
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version": f'"{browser_full}"',
        "sec-ch-ua-platform-version": platform_version,
    }
    navigator = {
        "platform": str(template["navigator_platform"]),
        "vendor": "Google Inc.",
        "languages": [locale, "en"] if locale != "en" else ["en"],
        "hardware_concurrency": hardware["hardware_concurrency"],
        "device_memory": hardware["device_memory"],
        "max_touch_points": 5 if mobile else 0,
    }
    profile = SessionProfile(
        profile_id=f"{template['id']}:v{major}:{rng.getrandbits(64):016x}",
        scope=normalized_scope,
        browser=browser,
        os=str(template["os"]),
        major=major,
        requested_major=requested_major,
        version=browser_full,
        chromium_version=chromium_full,
        version_policy=_normalize_version_policy(version_policy),
        version_fallback_reason=fallback_reason,
        impersonate=spec.impersonate_for(mobile=mobile, browser=browser),
        user_agent=ua,
        accept_language=accept_language,
        locale=locale,
        timezone_id=rng.choice(tuple(timezones)),
        viewport=_deep_freeze(viewport),
        screen=_deep_freeze(viewport),
        device_scale_factor=float(template.get("device_scale_factor") or 1),
        is_mobile=mobile,
        has_touch=mobile,
        color_scheme="light",
        reduced_motion="no-preference",
        navigator=_deep_freeze(navigator),
        webgl=_deep_freeze(webgl),
        fonts=_deep_freeze({"enabled": True, "families": list(template["fonts"]), "noise": rng.choice((0.002, 0.003, 0.005))}),
        canvas=_deep_freeze({"enabled": True, "noise": rng.choice((2, 3, 4))}),
        audio=_deep_freeze({"enabled": True, "noise": rng.choice((0.000002, 0.000003, 0.000004))}),
        extra_http_headers=_deep_freeze({"Accept-Language": accept_language, **sec_headers}),
        http_headers=_deep_freeze({"User-Agent": ua, "Accept-Language": accept_language, **sec_headers}),
    )
    return profile.validate()


def validate_session_profile(profile: SessionProfile) -> None:
    problems: list[str] = []
    chrome_match = _CHROME_UA_RE.search(profile.user_agent)
    edge_match = _EDGE_UA_RE.search(profile.user_agent)
    if chrome_match is None or int(chrome_match.group(1)) != profile.major:
        problems.append("UA Chrome major does not match profile major")
    else:
        chrome_tail = str(chrome_match.group(2) or "").strip()
        chrome_full_version = (
            f"{chrome_match.group(1)}.{chrome_tail}"
            if chrome_tail
            else str(chrome_match.group(1))
        )
        if chrome_full_version != profile.chromium_version:
            problems.append("UA Chrome full version does not match Chromium version")
    if profile.browser != "edge" and profile.version != profile.chromium_version:
        problems.append("Chrome profile has different browser and Chromium versions")

    http_headers = profile.http_headers
    if http_headers.get("User-Agent") != profile.user_agent:
        problems.append("HTTP User-Agent does not match profile")
    if http_headers.get("Accept-Language") != profile.accept_language:
        problems.append("HTTP Accept-Language does not match profile")
    if profile.browser == "edge":
        if edge_match is None or int(edge_match.group(1)) != profile.major:
            problems.append("Edge profile is missing a matching Edg/ version")
        else:
            edge_tail = str(edge_match.group(2) or "").strip()
            edge_full_version = (
                f"{edge_match.group(1)}.{edge_tail}"
                if edge_tail
                else str(edge_match.group(1))
            )
            if edge_full_version != profile.version:
                problems.append("UA Edge full version does not match profile version")
        if "Microsoft Edge" not in http_headers.get("sec-ch-ua", ""):
            problems.append("Edge profile has non-Edge Client Hints")
    elif edge_match is not None or "Google Chrome" not in http_headers.get("sec-ch-ua", ""):
        problems.append("Chrome profile has inconsistent browser family metadata")
    if f'v="{profile.major}"' not in http_headers.get("sec-ch-ua", ""):
        problems.append("Client Hints major does not match profile major")
    if http_headers.get("sec-ch-ua-full-version") != f'"{profile.version}"':
        problems.append("Client Hints full version does not match profile version")

    expected_platform = {
        "windows": '"Windows"',
        "macos": '"macOS"',
        "linux": '"Linux"',
        "android": '"Android"',
    }.get(profile.os)
    if expected_platform is None:
        problems.append("unsupported profile OS")
    elif http_headers.get("sec-ch-ua-platform") != expected_platform:
        problems.append("Client Hints platform does not match profile OS")

    expected_ua_markers = {
        "windows": ("Windows NT", "Win64"),
        "macos": ("Macintosh", "Mac OS X"),
        "linux": ("X11", "Linux"),
        "android": ("Android", "Mobile"),
    }.get(profile.os, ())
    if any(marker not in profile.user_agent for marker in expected_ua_markers):
        problems.append("User-Agent platform does not match profile OS")

    expected_mobile = profile.os == "android"
    if profile.is_mobile != expected_mobile:
        problems.append("mobile flag does not match profile OS")
    if profile.has_touch != profile.is_mobile:
        problems.append("touch capability does not match mobile profile")
    navigator_has_touch = int(profile.navigator.get("max_touch_points", 0)) > 0
    if navigator_has_touch != profile.is_mobile:
        problems.append("navigator touch points do not match mobile profile")
    if http_headers.get("sec-ch-ua-mobile") != ("?1" if profile.is_mobile else "?0"):
        problems.append("mobile Client Hint does not match profile")
    if profile.is_mobile and profile.device_scale_factor <= 1:
        problems.append("mobile device scale factor is not credible")
    if not profile.is_mobile and profile.device_scale_factor != 1:
        problems.append("desktop device scale factor is inconsistent")

    expected_arch = '"arm"' if profile.os in {"android", "macos"} else '"x86"'
    if http_headers.get("sec-ch-ua-arch") != expected_arch:
        problems.append("Client Hints architecture does not match profile")
    if not profile.accept_language.lower().startswith(profile.locale.lower()):
        problems.append("Accept-Language does not match locale")
    if int(profile.viewport["width"]) > int(profile.screen["width"]) or int(profile.viewport["height"]) > int(profile.screen["height"]):
        problems.append("viewport exceeds screen")

    spec = SUPPORTED_HTTP_CHROME_VERSIONS.get(profile.major)
    expected_impersonate = spec.impersonate_for(mobile=profile.is_mobile, browser=profile.browser) if spec is not None else ""
    if not expected_impersonate or expected_impersonate != profile.impersonate:
        problems.append("HTTP impersonation does not match profile major and device")
    expected_sec_ch_ua = spec.sec_ch_ua_for(browser=profile.browser) if spec is not None else ""
    if not expected_sec_ch_ua or http_headers.get("sec-ch-ua") != expected_sec_ch_ua:
        problems.append("Client Hints brand order does not match HTTP impersonation")
    if profile.version_policy == "strict" and (
        profile.requested_major != profile.major or profile.version_fallback_reason
    ):
        problems.append("strict version policy contains a fallback")
    if profile.requested_major != profile.major and not profile.version_fallback_reason:
        problems.append("version fallback is missing a reason")
    if profile.scope == "edge" and profile.browser != "edge":
        problems.append("edge scope selected a non-Edge browser")
    if profile.scope == "mobile" and not profile.is_mobile:
        problems.append("mobile scope selected a desktop profile")
    scoped_os = {"windows": "windows", "macos": "macos", "linux": "linux"}.get(profile.scope)
    if scoped_os and profile.os != scoped_os:
        problems.append(f"{profile.scope} scope selected a different OS")
    if problems:
        raise ValueError("invalid SessionProfile: " + "; ".join(problems))


def user_agent_data_for_profile(profile: SessionProfile) -> Dict[str, Any]:
    profile.validate()
    headers = profile.http_headers
    brands = [
        {"brand": brand, "version": version}
        for brand, version in _UA_CH_BRAND_RE.findall(
            str(headers.get("sec-ch-ua") or "")
        )
    ]
    full_version_list = []
    browser_brand = "Microsoft Edge" if profile.browser == "edge" else "Google Chrome"
    for brand in brands:
        name = str(brand["brand"])
        if name == "Chromium":
            full_version = profile.chromium_version
        elif name == browser_brand:
            full_version = profile.version
        else:
            full_version = str(brand["version"])
        full_version_list.append({"brand": name, "version": full_version})

    model = ""
    if profile.is_mobile:
        model_match = re.search(r"Android [^;]+;\s*([^)]+)\)", profile.user_agent)
        if model_match:
            model = model_match.group(1).split(" Build/", 1)[0].strip()

    def _unquote(value: Any) -> str:
        return str(value or "").strip().strip('"')

    return {
        "brands": brands,
        "mobile": profile.is_mobile,
        "platform": _unquote(headers.get("sec-ch-ua-platform")),
        "highEntropyValues": {
            "architecture": _unquote(headers.get("sec-ch-ua-arch")),
            "bitness": _unquote(headers.get("sec-ch-ua-bitness")),
            "model": model,
            "platformVersion": _unquote(
                headers.get("sec-ch-ua-platform-version")
            ),
            "uaFullVersion": profile.version,
            "fullVersionList": full_version_list,
            "wow64": False,
            "mobile": profile.is_mobile,
        },
    }


def context_options_for_profile(profile: SessionProfile) -> Dict[str, Any]:
    profile.validate()
    return {
        "locale": profile.locale,
        "viewport": _deep_thaw(profile.viewport),
        "screen": _deep_thaw(profile.screen),
        "device_scale_factor": profile.device_scale_factor,
        "is_mobile": profile.is_mobile,
        "has_touch": profile.has_touch,
        "timezone_id": profile.timezone_id,
        "color_scheme": profile.color_scheme,
        "reduced_motion": profile.reduced_motion,
        "extra_http_headers": dict(profile.extra_http_headers),
        "user_agent": profile.user_agent,
    }


def select_fingerprint_profile(
    *,
    scope: str = "auto_desktop",
    user_agent: str = "",
    rng: Optional[random.Random] = None,
    version_policy: str = "strict",
) -> Dict[str, Any]:
    return create_session_profile(
        scope=scope,
        user_agent=user_agent,
        rng=rng,
        version_policy=version_policy,
    ).to_legacy_dict()


def browserforge_options_for_scope(scope: str) -> Dict[str, Any]:
    normalized = normalize_profile_scope(scope)
    if normalized == "windows":
        return {"browser": "chrome", "os": "windows", "device": "desktop", "locale": "en-US"}
    if normalized == "macos":
        return {"browser": "chrome", "os": "macos", "device": "desktop", "locale": "en-US"}
    if normalized == "linux":
        return {"browser": "chrome", "os": "linux", "device": "desktop", "locale": "en-US"}
    if normalized == "edge":
        return {"browser": "edge", "os": "windows", "device": "desktop", "locale": "en-US"}
    if normalized == "mobile":
        return {"browser": "chrome", "os": "android", "device": "mobile", "locale": "en-US"}
    if normalized == "all":
        return {
            "browser": ("chrome", "edge"),
            "os": ("windows", "macos", "linux", "android"),
            "device": ("desktop", "mobile"),
            "locale": "en-US",
        }
    return {
        "browser": "chrome",
        "os": ("windows", "macos", "linux"),
        "device": "desktop",
        "locale": "en-US",
    }


def profile_scope_labels() -> Iterable[str]:
    return PROFILE_SCOPE_OPTIONS
