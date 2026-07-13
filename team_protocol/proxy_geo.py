from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


_IPWHO_URL = "https://ipwho.is/"
_CLOUDFLARE_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
_DEFAULT_TIMEOUT_SECONDS = 8.0
_DEFAULT_PRIMARY_ATTEMPTS = 2

# Country defaults are used only when the primary provider cannot return an
# exact timezone. The profile language still comes from the resolved country.
_COUNTRY_DEFAULTS: dict[str, tuple[str, str, str]] = {
    "AE": ("ar-AE", "Asia/Dubai", "AS"),
    "AR": ("es-AR", "America/Argentina/Buenos_Aires", "SA"),
    "AT": ("de-AT", "Europe/Vienna", "EU"),
    "AU": ("en-AU", "Australia/Sydney", "OC"),
    "BD": ("bn-BD", "Asia/Dhaka", "AS"),
    "BE": ("nl-BE", "Europe/Brussels", "EU"),
    "BG": ("bg-BG", "Europe/Sofia", "EU"),
    "BR": ("pt-BR", "America/Sao_Paulo", "SA"),
    "CA": ("en-CA", "America/Toronto", "NA"),
    "CH": ("de-CH", "Europe/Zurich", "EU"),
    "CL": ("es-CL", "America/Santiago", "SA"),
    "CN": ("zh-CN", "Asia/Shanghai", "AS"),
    "CO": ("es-CO", "America/Bogota", "SA"),
    "CZ": ("cs-CZ", "Europe/Prague", "EU"),
    "DE": ("de-DE", "Europe/Berlin", "EU"),
    "DK": ("da-DK", "Europe/Copenhagen", "EU"),
    "EE": ("et-EE", "Europe/Tallinn", "EU"),
    "EG": ("ar-EG", "Africa/Cairo", "AF"),
    "ES": ("es-ES", "Europe/Madrid", "EU"),
    "FI": ("fi-FI", "Europe/Helsinki", "EU"),
    "FR": ("fr-FR", "Europe/Paris", "EU"),
    "GB": ("en-GB", "Europe/London", "EU"),
    "GR": ("el-GR", "Europe/Athens", "EU"),
    "HK": ("zh-HK", "Asia/Hong_Kong", "AS"),
    "HU": ("hu-HU", "Europe/Budapest", "EU"),
    "ID": ("id-ID", "Asia/Jakarta", "AS"),
    "IE": ("en-IE", "Europe/Dublin", "EU"),
    "IL": ("he-IL", "Asia/Jerusalem", "AS"),
    "IN": ("en-IN", "Asia/Kolkata", "AS"),
    "IS": ("is-IS", "Atlantic/Reykjavik", "EU"),
    "IT": ("it-IT", "Europe/Rome", "EU"),
    "JP": ("ja-JP", "Asia/Tokyo", "AS"),
    "KE": ("en-KE", "Africa/Nairobi", "AF"),
    "KR": ("ko-KR", "Asia/Seoul", "AS"),
    "LT": ("lt-LT", "Europe/Vilnius", "EU"),
    "LU": ("fr-LU", "Europe/Luxembourg", "EU"),
    "LV": ("lv-LV", "Europe/Riga", "EU"),
    "MA": ("ar-MA", "Africa/Casablanca", "AF"),
    "MX": ("es-MX", "America/Mexico_City", "NA"),
    "MY": ("ms-MY", "Asia/Kuala_Lumpur", "AS"),
    "NG": ("en-NG", "Africa/Lagos", "AF"),
    "NL": ("nl-NL", "Europe/Amsterdam", "EU"),
    "NO": ("nb-NO", "Europe/Oslo", "EU"),
    "NZ": ("en-NZ", "Pacific/Auckland", "OC"),
    "PE": ("es-PE", "America/Lima", "SA"),
    "PH": ("en-PH", "Asia/Manila", "AS"),
    "PK": ("en-PK", "Asia/Karachi", "AS"),
    "PL": ("pl-PL", "Europe/Warsaw", "EU"),
    "PT": ("pt-PT", "Europe/Lisbon", "EU"),
    "RO": ("ro-RO", "Europe/Bucharest", "EU"),
    "RU": ("ru-RU", "Europe/Moscow", "EU"),
    "SA": ("ar-SA", "Asia/Riyadh", "AS"),
    "SE": ("sv-SE", "Europe/Stockholm", "EU"),
    "SG": ("en-SG", "Asia/Singapore", "AS"),
    "SK": ("sk-SK", "Europe/Bratislava", "EU"),
    "TH": ("th-TH", "Asia/Bangkok", "AS"),
    "TR": ("tr-TR", "Europe/Istanbul", "AS"),
    "TW": ("zh-TW", "Asia/Taipei", "AS"),
    "UA": ("uk-UA", "Europe/Kyiv", "EU"),
    "US": ("en-US", "America/New_York", "NA"),
    "UY": ("es-UY", "America/Montevideo", "SA"),
    "VN": ("vi-VN", "Asia/Ho_Chi_Minh", "AS"),
    "ZA": ("en-ZA", "Africa/Johannesburg", "AF"),
}

_CONTINENT_DEFAULTS: dict[str, tuple[str, str]] = {
    "AF": ("en-US", "Africa/Johannesburg"),
    "AS": ("en-US", "Asia/Singapore"),
    "EU": ("en-GB", "Europe/London"),
    "NA": ("en-US", "America/New_York"),
    "OC": ("en-AU", "Australia/Sydney"),
    "SA": ("es-419", "America/Sao_Paulo"),
}


def _default_request_get(url: str, *, proxy: str, timeout: float) -> Any:
    from curl_cffi import requests as curl_requests

    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "impersonate": "chrome145",
    }
    if proxy:
        kwargs["proxy"] = proxy
    return curl_requests.get(url, **kwargs)


def _country_code(value: Any) -> str:
    code = str(value or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else ""


def _continent_code(value: Any) -> str:
    code = str(value or "").strip().upper()
    return code if code in _CONTINENT_DEFAULTS else ""


def _valid_timezone(value: Any) -> str:
    timezone_id = str(value or "").strip()
    if not timezone_id:
        return ""
    try:
        ZoneInfo(timezone_id)
    except (ValueError, ZoneInfoNotFoundError):
        return ""
    return timezone_id


def _accept_language(locale: str) -> str:
    language = locale.split("-", 1)[0].lower()
    if language == "en":
        return f"{locale},en;q=0.9"
    return f"{locale},{language};q=0.9,en;q=0.8"


def _build_hint(
    *,
    country_code: str,
    continent_code: str = "",
    timezone_id: str = "",
    timezone_exact: bool = False,
    source: str,
) -> dict[str, Any]:
    country = _country_code(country_code)
    country_defaults = _COUNTRY_DEFAULTS.get(country)
    continent = _continent_code(continent_code)
    if not continent and country_defaults is not None:
        continent = country_defaults[2]

    if country_defaults is not None:
        locale = country_defaults[0]
        fallback_timezone = country_defaults[1]
    else:
        locale, fallback_timezone = _CONTINENT_DEFAULTS.get(
            continent, ("en-US", "UTC")
        )
    resolved_timezone = _valid_timezone(timezone_id) or fallback_timezone

    return {
        "resolved": bool(country),
        "source": source,
        "country_code": country,
        "continent_code": continent,
        "timezone_id": resolved_timezone,
        "timezone_exact": bool(timezone_exact),
        "clock_checked": False,
        "clock_skew_seconds": None,
        "locale": locale,
        "accept_language": _accept_language(locale),
        # IP geolocation cannot reveal a client OS. Pinning a common desktop
        # baseline is more coherent than inventing a country-to-OS inference.
        "profile_scope": "windows",
    }


def _response_clock_hint(response: Any) -> tuple[bool, float | None]:
    headers = getattr(response, "headers", None)
    if not hasattr(headers, "get"):
        return False, None
    date_value = str(headers.get("date") or headers.get("Date") or "").strip()
    if not date_value:
        return False, None
    try:
        server_time = parsedate_to_datetime(date_value)
    except (TypeError, ValueError, OverflowError):
        return False, None
    if server_time.tzinfo is None:
        server_time = server_time.replace(tzinfo=timezone.utc)
    skew_seconds = (
        server_time.astimezone(timezone.utc) - datetime.now(timezone.utc)
    ).total_seconds()
    return True, round(skew_seconds, 3)


def _parse_ipwho(response: Any) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 0) or 0)
    if not 200 <= status_code < 300:
        raise RuntimeError("primary geo provider returned a non-success status")
    payload = response.json()
    if not isinstance(payload, Mapping) or payload.get("success") is False:
        raise RuntimeError("primary geo provider returned an invalid payload")
    timezone_data = payload.get("timezone")
    timezone_id = (
        timezone_data.get("id") if isinstance(timezone_data, Mapping) else timezone_data
    )
    hint = _build_hint(
        country_code=str(payload.get("country_code") or ""),
        continent_code=str(payload.get("continent_code") or ""),
        timezone_id=str(timezone_id or ""),
        timezone_exact=bool(_valid_timezone(timezone_id)),
        source="ipwho.is",
    )
    if not hint["resolved"]:
        raise RuntimeError("primary geo provider omitted the country")
    clock_checked, clock_skew_seconds = _response_clock_hint(response)
    hint["clock_checked"] = clock_checked
    hint["clock_skew_seconds"] = clock_skew_seconds
    return hint


def _parse_cloudflare(response: Any) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 0) or 0)
    if not 200 <= status_code < 300:
        raise RuntimeError("fallback geo provider returned a non-success status")
    fields: dict[str, str] = {}
    for line in str(getattr(response, "text", "") or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key.strip()] = value.strip()
    hint = _build_hint(
        country_code=fields.get("loc", ""),
        timezone_exact=False,
        source="cloudflare",
    )
    if not hint["resolved"]:
        raise RuntimeError("fallback geo provider omitted the country")
    return hint


def resolve_proxy_geo(
    proxy: str | None,
    *,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    primary_attempts: int = _DEFAULT_PRIMARY_ATTEMPTS,
    request_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    getter = request_get or _default_request_get
    clean_proxy = str(proxy or "").strip()
    bounded_timeout = max(1.0, min(float(timeout), 15.0))
    bounded_primary_attempts = max(1, min(int(primary_attempts), 3))

    for _ in range(bounded_primary_attempts):
        try:
            response = getter(
                _IPWHO_URL,
                proxy=clean_proxy,
                timeout=bounded_timeout,
            )
            return _parse_ipwho(response)
        except Exception:
            pass

    try:
        response = getter(
            _CLOUDFLARE_TRACE_URL,
            proxy=clean_proxy,
            timeout=bounded_timeout,
        )
        return _parse_cloudflare(response)
    except Exception:
        return _build_hint(
            country_code="",
            timezone_id="UTC",
            timezone_exact=False,
            source="fallback",
        )
