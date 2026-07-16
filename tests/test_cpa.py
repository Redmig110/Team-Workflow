import base64
import json
import unittest
from datetime import datetime, timezone

from team_protocol.cpa import (
    OPENAI_AUTH_CLAIM,
    OPENAI_PROFILE_CLAIM,
    build_cpa,
    build_cpa_filename,
    decode_jwt_payload,
    semantic_cpa_payload,
)


def encode_part(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_jwt(payload):
    return f"{encode_part({'alg': 'RS256', 'typ': 'JWT'})}.{encode_part(payload)}.signature"


class CpaTests(unittest.TestCase):
    def setUp(self):
        self.account_id = "00000000-0000-4000-9000-000000000000"
        self.user_id = "user-test"
        self.email = "Example+3@Example.com"
        self.exp = 1_786_000_000
        self.access_token = make_jwt(
            {
                "iat": 1_785_000_000,
                "exp": self.exp,
                OPENAI_AUTH_CLAIM: {
                    "chatgpt_account_id": self.account_id,
                    "chatgpt_plan_type": "team",
                    "chatgpt_user_id": self.user_id,
                    "user_id": self.user_id,
                },
                OPENAI_PROFILE_CLAIM: {"email": self.email},
            }
        )

    def test_build_cpa_matches_shop_shape(self):
        now = datetime(2026, 7, 12, 6, 42, 32, 699000, tzinfo=timezone.utc)
        session = {
            "user": {"id": self.user_id, "email": self.email},
            "account": {"id": self.account_id, "planType": "team"},
            "accessToken": self.access_token,
            "sessionToken": "session-token",
        }
        result = build_cpa(session, personal_access_token="at-personal", now=now)

        self.assertEqual(
            list(result),
            [
                "type",
                "account_id",
                "chatgpt_account_id",
                "email",
                "name",
                "plan_type",
                "chatgpt_plan_type",
                "id_token",
                "id_token_synthetic",
                "access_token",
                "refresh_token",
                "last_refresh",
            ],
        )
        self.assertEqual(result["account_id"], self.account_id)
        self.assertEqual(result["chatgpt_account_id"], self.account_id)
        self.assertEqual(result["email"], self.email)
        self.assertEqual(result["plan_type"], "team")
        self.assertEqual(result["access_token"], "at-personal")
        self.assertEqual(result["refresh_token"], "")
        self.assertEqual(result["last_refresh"], "2026-07-12T06:42:32.699Z")
        self.assertTrue(result["id_token_synthetic"])
        self.assertNotIn("session_token", result)
        self.assertNotIn("expired", result)
        self.assertNotIn("headers", result)

        id_payload = decode_jwt_payload(result["id_token"])
        self.assertEqual(id_payload["iat"], int(now.timestamp()))
        self.assertEqual(id_payload["exp"], self.exp)
        self.assertEqual(id_payload["email"], self.email)
        self.assertEqual(id_payload[OPENAI_AUTH_CLAIM]["chatgpt_account_id"], self.account_id)

    def test_build_cpa_does_not_require_session_tokens(self):
        now = datetime(2026, 7, 16, 8, 30, 21, 350000, tzinfo=timezone.utc)
        result = build_cpa(
            {
                "user": {"id": self.user_id, "email": self.email},
                "account": {"id": self.account_id, "planType": "team"},
            },
            personal_access_token="Bearer at-personal",
            now=now,
        )

        self.assertEqual(result["access_token"], "at-personal")
        self.assertEqual(result["refresh_token"], "")
        self.assertEqual(result["last_refresh"], "2026-07-16T08:30:21.350Z")
        self.assertTrue(result["id_token_synthetic"])
        self.assertNotIn("session_token", result)
        self.assertNotIn("expired", result)
        self.assertNotIn("headers", result)
        id_payload = decode_jwt_payload(result["id_token"])
        self.assertEqual(id_payload["email"], self.email)
        self.assertEqual(id_payload[OPENAI_AUTH_CLAIM]["chatgpt_account_id"], self.account_id)

    def test_real_id_token_is_preserved(self):
        session = {
            "account_id": self.account_id,
            "access_token": self.access_token,
            "id_token": "real.header.signature",
        }
        result = build_cpa(session, now=datetime(2026, 7, 12, tzinfo=timezone.utc))
        self.assertEqual(result["id_token"], "real.header.signature")
        self.assertNotIn("id_token_synthetic", result)

    def test_filename_matches_converter_behavior(self):
        local_time = datetime(2026, 7, 12, 14, 42, 43)
        self.assertEqual(
            build_cpa_filename("ExampleUser+3@example.com", local_time=local_time),
            "exampleuser+3@example.cpa.2026-07-12_14-42-43.json",
        )

    def test_semantic_payload_defaults_disabled_false(self):
        self.assertEqual(
            semantic_cpa_payload({"type": "codex", "email": "a@example.com"}),
            {"type": "codex", "email": "a@example.com", "disabled": False},
        )


if __name__ == "__main__":
    unittest.main()
