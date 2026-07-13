import random
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from team_protocol.registrar_runtime.fingerprint_profiles import (
    create_session_profile,
    normalize_profile_scope,
)
from team_protocol.registrar_runtime.sentinel_browser import (
    _BROWSERFORGE_CACHE,
    _browserforge_fingerprint_for_profile,
    _create_required_browser_context,
    create_browserforge_context,
    restore_browserforge_fingerprint,
    serialize_browserforge_fingerprint,
)


class FingerprintProfileTests(unittest.TestCase):
    def test_new_desktop_profiles_use_only_latest_shared_chrome(self):
        profiles = [
            create_session_profile(scope="windows", rng=random.Random(seed))
            for seed in range(20)
        ]

        self.assertEqual({profile.major for profile in profiles}, {145})
        self.assertEqual({profile.impersonate for profile in profiles}, {"chrome145"})

    def test_unsupported_mobile_and_edge_scopes_normalize_to_active_chrome(self):
        self.assertEqual(normalize_profile_scope("mobile"), "auto_desktop")
        self.assertEqual(normalize_profile_scope("edge"), "auto_desktop")
        self.assertEqual(normalize_profile_scope("all"), "all_desktop")
        for scope in ("mobile", "edge", "all"):
            profile = create_session_profile(scope=scope, rng=random.Random(3))
            self.assertEqual(profile.major, 145)
            self.assertEqual(profile.browser, "chrome")
            self.assertFalse(profile.is_mobile)

    def test_new_mobile_or_edge_user_agent_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "desktop Chrome"):
            create_session_profile(
                user_agent=(
                    "Mozilla/5.0 (Linux; Android 14; Pixel 7) "
                    "AppleWebKit/537.36 Chrome/145.0.0.0 Mobile Safari/537.36"
                )
            )
        with self.assertRaisesRegex(ValueError, "desktop Chrome"):
            create_session_profile(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"
                )
            )

    def test_browserforge_generates_and_canonicalizes_the_locked_profile(self):
        profile = create_session_profile(scope="windows", rng=random.Random(7))

        fingerprint = _browserforge_fingerprint_for_profile(
            profile,
            fingerprint_scope="windows",
        )

        self.assertEqual(fingerprint.navigator.userAgent, profile.user_agent)
        self.assertEqual(fingerprint.navigator.language, profile.locale)
        self.assertEqual(fingerprint.headers, dict(profile.http_headers))
        self.assertEqual(fingerprint.screen.width, profile.screen["width"])
        self.assertEqual(fingerprint.screen.height, profile.screen["height"])

        payload = serialize_browserforge_fingerprint(fingerprint)
        _BROWSERFORGE_CACHE.clear()
        restored = restore_browserforge_fingerprint(profile, payload)
        self.assertEqual(serialize_browserforge_fingerprint(restored), payload)

    def test_actual_chromium_major_must_match_the_locked_profile(self):
        profile = create_session_profile(scope="windows", rng=random.Random(11))

        with self.assertRaisesRegex(RuntimeError, "Chromium major 146"):
            create_browserforge_context(
                SimpleNamespace(version="146.0.0.0"),
                fingerprint_scope="windows",
                session_profile=profile,
            )

    def test_required_browserforge_context_never_falls_back(self):
        with patch(
            "team_protocol.registrar_runtime.sentinel_browser._new_browserforge_context",
            side_effect=ImportError("browserforge missing"),
        ):
            with self.assertRaisesRegex(RuntimeError, "BrowserForge context creation failed"):
                _create_required_browser_context(
                    object(),
                    requested_engine="browserforge",
                    fingerprint_scope="windows",
                    session_profile=object(),
                )

        with self.assertRaisesRegex(ValueError, "BrowserForge is mandatory"):
            _create_required_browser_context(
                object(),
                requested_engine="internal",
                fingerprint_scope="windows",
                session_profile=object(),
            )


if __name__ == "__main__":
    unittest.main()
