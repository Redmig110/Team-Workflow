from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from team_protocol.registrar_runtime.chromium_time import (
    _DISPLAY_NAME_CACHE,
    chromium_local_timestamp,
)


class ChromiumTimeTests(unittest.TestCase):
    def setUp(self):
        _DISPLAY_NAME_CACHE.clear()

    def test_formats_chromium_date_with_localized_timezone_name(self):
        instant = datetime(2026, 7, 15, 3, 34, 56, tzinfo=timezone.utc)

        with patch(
            "team_protocol.registrar_runtime.chromium_time._load_chromium_timezone_display_name",
            return_value="日本標準時",
        ) as loader:
            first = chromium_local_timestamp(
                locale="ja-JP",
                timezone_id="Asia/Tokyo",
                instant=instant,
            )
            second = chromium_local_timestamp(
                locale="ja-JP",
                timezone_id="Asia/Tokyo",
                instant=instant,
            )

        self.assertEqual(
            first,
            "Wed Jul 15 2026 12:34:56 GMT+0900 (日本標準時)",
        )
        self.assertEqual(second, first)
        loader.assert_called_once()

    def test_real_chromium_uses_the_same_japanese_timestamp(self):
        instant = datetime(2026, 1, 15, 3, 34, 56, tzinfo=timezone.utc)

        actual = chromium_local_timestamp(
            locale="ja-JP",
            timezone_id="Asia/Tokyo",
            instant=instant,
        )

        self.assertEqual(
            actual,
            "Thu Jan 15 2026 12:34:56 GMT+0900 (日本標準時)",
        )


if __name__ == "__main__":
    unittest.main()
