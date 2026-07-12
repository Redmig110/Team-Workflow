import base64
import json
import unittest
from types import SimpleNamespace

from team_protocol.chatgpt import AuthContext, ChatGPTClient
from team_protocol.cpa import OPENAI_AUTH_CLAIM


def encode(value):
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class AuthContextTests(unittest.TestCase):
    def test_context_falls_back_to_access_token_claims(self):
        token = (
            f"{encode({'alg': 'none'})}."
            f"{encode({OPENAI_AUTH_CLAIM: {'chatgpt_account_id': 'account-1', 'chatgpt_user_id': 'user-1'}})}."
            "signature"
        )
        context = AuthContext.from_mapping(
            {
                "access_token": token,
                "session_token": "session",
                "email": "user@example.com",
            }
        )
        self.assertEqual(context.account_id, "account-1")
        self.assertEqual(context.user_id, "user-1")
        self.assertEqual(context.session_token, "session")


class CapturingSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return SimpleNamespace(status_code=200, json=lambda: {"ok": True}, text="")

    def close(self):
        pass


class ChatGPTClientFingerprintTests(unittest.TestCase):
    def test_session_profile_controls_impersonation_and_headers(self):
        profile = SimpleNamespace(
            impersonate="chrome131",
            http_headers={
                "User-Agent": "profile-user-agent",
                "Accept-Language": "en-US,en;q=0.8",
                "sec-ch-ua": '"Chromium";v="131"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
        )
        client = ChatGPTClient(session_profile=profile, proxy="socks5h://proxy.example:1000")
        client._session.close()
        session = CapturingSession()
        client._session = session

        result = client._request(
            "GET",
            "https://chatgpt.com/backend-api/test",
            headers={"Accept": "application/json"},
        )

        self.assertEqual(result, {"ok": True})
        _, _, kwargs = session.calls[0]
        self.assertEqual(kwargs["impersonate"], profile.impersonate)
        self.assertEqual(kwargs["proxy"], "socks5h://proxy.example:1000")
        self.assertEqual(kwargs["headers"]["User-Agent"], profile.http_headers["User-Agent"])
        self.assertEqual(kwargs["headers"]["sec-ch-ua"], profile.http_headers["sec-ch-ua"])
        self.assertEqual(kwargs["headers"]["Accept"], "application/json")


if __name__ == "__main__":
    unittest.main()
