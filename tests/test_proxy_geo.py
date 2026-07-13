import random
import unittest
from datetime import datetime, timezone
from email.utils import format_datetime

from team_protocol.proxy_geo import resolve_proxy_geo
from team_protocol.registrar_runtime.fingerprint_profiles import (
    SessionProfile,
    create_session_profile,
)


class FakeResponse:
    def __init__(self, *, payload=None, text="", status_code=200, headers=None):
        self._payload = payload
        self.text = text
        self.status_code = status_code
        self.headers = dict(headers or {})

    def json(self):
        if self._payload is None:
            raise ValueError("response is not JSON")
        return self._payload


class ProxyGeoTests(unittest.TestCase):
    def test_primary_lookup_uses_proxy_and_returns_exact_timezone(self):
        calls = []

        def request_get(url, *, proxy, timeout):
            calls.append((url, proxy, timeout))
            return FakeResponse(
                headers={"Date": format_datetime(datetime.now(timezone.utc), usegmt=True)},
                payload={
                    "success": True,
                    "ip": "203.0.113.9",
                    "country_code": "DE",
                    "continent_code": "EU",
                    "timezone": {"id": "Europe/Berlin"},
                }
            )

        hint = resolve_proxy_geo(
            "socks5h://user:secret@proxy.example:1080",
            timeout=4.0,
            request_get=request_get,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], "socks5h://user:secret@proxy.example:1080")
        self.assertEqual(calls[0][2], 4.0)
        self.assertEqual(hint["source"], "ipwho.is")
        self.assertTrue(hint["resolved"])
        self.assertEqual(hint["country_code"], "DE")
        self.assertEqual(hint["timezone_id"], "Europe/Berlin")
        self.assertTrue(hint["timezone_exact"])
        self.assertTrue(hint["clock_checked"])
        self.assertLess(abs(hint["clock_skew_seconds"]), 2.0)
        self.assertEqual(hint["locale"], "de-DE")
        self.assertEqual(hint["accept_language"], "de-DE,de;q=0.9,en;q=0.8")
        self.assertEqual(hint["profile_scope"], "windows")
        self.assertNotIn("exit_ip", hint)
        self.assertNotIn("203.0.113.9", str(hint))

    def test_cloudflare_country_fallback_uses_regional_defaults(self):
        calls = []

        def request_get(url, *, proxy, timeout):
            del proxy, timeout
            calls.append(url)
            if "ipwho.is" in url:
                raise TimeoutError("primary geo lookup timed out")
            return FakeResponse(text="ip=203.0.113.10\nloc=JP\n")

        hint = resolve_proxy_geo("http://proxy.example:8080", request_get=request_get)

        self.assertEqual(len(calls), 3)
        self.assertEqual(hint["source"], "cloudflare")
        self.assertTrue(hint["resolved"])
        self.assertEqual(hint["country_code"], "JP")
        self.assertEqual(hint["continent_code"], "AS")
        self.assertEqual(hint["timezone_id"], "Asia/Tokyo")
        self.assertFalse(hint["timezone_exact"])
        self.assertFalse(hint["clock_checked"])
        self.assertIsNone(hint["clock_skew_seconds"])
        self.assertEqual(hint["locale"], "ja-JP")

    def test_primary_lookup_retries_once_with_the_same_proxy(self):
        calls = []

        def request_get(url, *, proxy, timeout):
            calls.append((url, proxy, timeout))
            if len(calls) == 1:
                raise TimeoutError("proxy cold start")
            return FakeResponse(
                headers={"Date": format_datetime(datetime.now(timezone.utc), usegmt=True)},
                payload={
                    "success": True,
                    "country_code": "BR",
                    "continent_code": "SA",
                    "timezone": {"id": "America/Sao_Paulo"},
                },
            )

        hint = resolve_proxy_geo(
            "socks5h://user:secret@proxy.example:1080",
            request_get=request_get,
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertEqual(calls[0][2], 8.0)
        self.assertEqual(hint["source"], "ipwho.is")
        self.assertTrue(hint["timezone_exact"])

    def test_lookup_failure_returns_explicit_conservative_fallback(self):
        def request_get(_url, *, proxy, timeout):
            del proxy, timeout
            raise OSError("offline")

        hint = resolve_proxy_geo("", request_get=request_get)

        self.assertFalse(hint["resolved"])
        self.assertEqual(hint["source"], "fallback")
        self.assertEqual(hint["timezone_id"], "UTC")
        self.assertFalse(hint["timezone_exact"])
        self.assertEqual(hint["locale"], "en-US")
        self.assertEqual(hint["profile_scope"], "windows")

    def test_geo_hint_localizes_one_coherent_windows_profile(self):
        hint = {
            "resolved": True,
            "source": "ipwho.is",
            "country_code": "DE",
            "continent_code": "EU",
            "timezone_id": "Europe/Berlin",
            "locale": "de-DE",
            "accept_language": "de-DE,de;q=0.9,en;q=0.8",
            "profile_scope": "windows",
        }

        profile = create_session_profile(
            scope="auto_desktop",
            geo_hint=hint,
            rng=random.Random(7),
        )
        serialized = profile.to_legacy_dict()
        restored = SessionProfile(**serialized).validate()

        self.assertEqual(profile.os, "windows")
        self.assertEqual(profile.scope, "windows")
        self.assertEqual(profile.locale, "de-DE")
        self.assertEqual(profile.timezone_id, "Europe/Berlin")
        self.assertEqual(
            profile.http_headers["Accept-Language"],
            "de-DE,de;q=0.9,en;q=0.8",
        )
        self.assertEqual(profile.navigator["languages"], ("de-DE", "de", "en"))
        self.assertEqual(profile.geo_country_code, "DE")
        self.assertEqual(profile.geo_source, "ipwho.is")
        self.assertEqual(restored.to_legacy_dict(), serialized)


if __name__ == "__main__":
    unittest.main()
