from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock


_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
_DISPLAY_NAME_CACHE: dict[tuple[str, str, int, int, bool], str] = {}
_DISPLAY_NAME_LOCK = RLock()


def _extract_timezone_display_name(date_text: str) -> str:
    marker = date_text.find(" (")
    if marker < 0 or not date_text.endswith(")"):
        raise RuntimeError("Chromium did not expose a localized timezone display name")
    display_name = date_text[marker + 2 : -1].strip()
    if not display_name:
        raise RuntimeError("Chromium returned an empty timezone display name")
    return display_name


def _load_chromium_timezone_display_name(
    locale: str,
    timezone_id: str,
    epoch_ms: int,
) -> str:
    from playwright.sync_api import sync_playwright

    from .fingerprint_profiles import ACTIVE_DESKTOP_CHROME_MAJOR

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            actual_major = int(str(browser.version).split(".", 1)[0])
            if actual_major != ACTIVE_DESKTOP_CHROME_MAJOR:
                raise RuntimeError(
                    f"Chromium major {actual_major} does not match required "
                    f"Chrome {ACTIVE_DESKTOP_CHROME_MAJOR}"
                )
            context = browser.new_context(locale=locale, timezone_id=timezone_id)
            try:
                page = context.new_page()
                date_text = page.evaluate(
                    "timestamp => new Date(timestamp).toString()",
                    epoch_ms,
                )
            finally:
                context.close()
        finally:
            browser.close()
    return _extract_timezone_display_name(str(date_text or ""))


def chromium_local_timestamp(
    *,
    locale: str,
    timezone_id: str,
    instant: datetime | None = None,
) -> str:
    aware_instant = instant or datetime.now(timezone.utc)
    if aware_instant.tzinfo is None or aware_instant.utcoffset() is None:
        raise ValueError("instant must be timezone-aware")

    from zoneinfo import ZoneInfo

    local_time = aware_instant.astimezone(ZoneInfo(timezone_id))
    offset = local_time.utcoffset()
    if offset is None:
        raise RuntimeError("timezone did not provide a UTC offset")
    offset_minutes = int(offset.total_seconds() // 60)
    is_dst = bool(local_time.dst() and local_time.dst().total_seconds())
    cache_key = (
        locale,
        timezone_id,
        local_time.year,
        offset_minutes,
        is_dst,
    )
    with _DISPLAY_NAME_LOCK:
        display_name = _DISPLAY_NAME_CACHE.get(cache_key)
        if display_name is None:
            display_name = _load_chromium_timezone_display_name(
                locale,
                timezone_id,
                int(aware_instant.timestamp() * 1000),
            )
            _DISPLAY_NAME_CACHE[cache_key] = display_name

    sign = "+" if offset_minutes >= 0 else "-"
    absolute_offset = abs(offset_minutes)
    offset_text = f"{sign}{absolute_offset // 60:02d}{absolute_offset % 60:02d}"
    return (
        f"{_WEEKDAYS[local_time.weekday()]} "
        f"{_MONTHS[local_time.month - 1]} {local_time.day:02d} "
        f"{local_time.year:04d} {local_time:%H:%M:%S} "
        f"GMT{offset_text} ({display_name})"
    )
