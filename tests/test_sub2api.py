import base64
import json
import unittest
from datetime import datetime, timezone

from team_protocol.cpa import OPENAI_AUTH_CLAIM, OPENAI_PROFILE_CLAIM
from team_protocol.sub2api import (
    Sub2APIClient,
    Sub2APIError,
    build_sub2api_account,
)


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def access_token():
    payload = {
        "exp": 1_900_000_000,
        OPENAI_AUTH_CLAIM: {
            "chatgpt_account_id": "workspace-1",
            "chatgpt_plan_type": "team",
            "chatgpt_user_id": "user-1",
        },
        OPENAI_PROFILE_CLAIM: {"email": "user@example.com"},
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.signature"


def account_payload(token="at-test"):
    return build_sub2api_account(
        {
            "accessToken": access_token(),
            "sessionToken": "session-token",
            "user": {"id": "user-1", "email": "user@example.com"},
            "account": {"id": "workspace-1", "planType": "team"},
        },
        personal_access_token=token,
        concurrency=10,
        priority=1,
        now=datetime(2026, 7, 12, 9, 0, tzinfo=timezone.utc),
    )


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.reason = "OK"

    def json(self):
        return self.payload


class QueueSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def wrapped(data):
    return FakeResponse({"code": 0, "data": data})


class Sub2APIAccountTests(unittest.TestCase):
    def test_builds_codex_pat_account(self):
        account = account_payload()

        self.assertEqual(account["platform"], "openai")
        self.assertEqual(account["type"], "oauth")
        self.assertEqual(account["name"], "user@example.com")
        self.assertEqual(account["credentials"]["access_token"], "at-test")
        self.assertEqual(account["credentials"]["auth_mode"], "personalAccessToken")
        self.assertEqual(account["credentials"]["openai_auth_mode"], "personal_access_token")
        self.assertEqual(account["credentials"]["chatgpt_account_id"], "workspace-1")
        self.assertEqual(account["credentials"]["email"], "user@example.com")
        self.assertEqual(account["concurrency"], 10)
        self.assertEqual(account["priority"], 1)

    def test_push_creates_and_verifies_new_account(self):
        account = account_payload()
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": []}),
                wrapped({"id": 42, "name": account["name"]}),
                wrapped(
                    {
                        "exported_at": "2026-07-12T09:00:01Z",
                        "proxies": [],
                        "accounts": [account],
                    }
                ),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        result = client.push_account(account)

        self.assertEqual(result.action, "created")
        self.assertTrue(result.verified)
        create_call = session.calls[2]
        self.assertTrue(create_call[1].endswith("/admin/openai/create-from-codex-pat"))
        self.assertEqual(create_call[2]["json"]["access_token"], "at-test")
        self.assertEqual(
            create_call[2]["json"]["credential_extras"]["chatgpt_account_id"],
            "workspace-1",
        )

    def test_push_skips_exact_remote_account(self):
        account = account_payload()
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": [account]}),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        result = client.push_account(account)

        self.assertEqual(result.action, "skipped")
        self.assertTrue(result.verified)
        self.assertEqual(len(session.calls), 2)

    def test_push_rejects_same_identity_with_different_token(self):
        account = account_payload()
        remote = account_payload(token="at-other")
        session = QueueSession(
            [
                wrapped({"access_token": "admin-token"}),
                wrapped({"exported_at": "2026-07-12T09:00:00Z", "proxies": [], "accounts": [remote]}),
            ]
        )
        client = Sub2APIClient(
            "https://sub2api.example",
            "admin@example.com",
            "secret",
            session=session,
        )

        with self.assertRaisesRegex(Sub2APIError, "different token"):
            client.push_account(account)

        self.assertEqual(len(session.calls), 2)


if __name__ == "__main__":
    unittest.main()
