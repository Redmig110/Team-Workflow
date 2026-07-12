import json
import unittest

from team_protocol.har import analyze_har, select_pat_credential, select_session_snapshot


def entry(index, method, url, status=200, request_body=None, response_body=None):
    del index
    request = {"method": method, "url": url}
    if request_body is not None:
        request["postData"] = {"text": json.dumps(request_body)}
    response = {"status": status, "content": {}}
    if response_body is not None:
        response["content"]["text"] = json.dumps(response_body)
    return {
        "startedDateTime": "2026-07-12T06:41:00.000Z",
        "request": request,
        "response": response,
    }


class HarTests(unittest.TestCase):
    def setUp(self):
        account_id = "account-1"
        self.har = {
            "log": {
                "entries": [
                    entry(
                        0,
                        "POST",
                        "https://chatgpt.com/api/auth/signin/openai?login_hint=old%2B2%40example.com",
                    ),
                    entry(
                        1,
                        "POST",
                        f"https://chatgpt.com/backend-api/accounts/{account_id}/invites",
                    ),
                    entry(
                        2,
                        "DELETE",
                        f"https://chatgpt.com/backend-api/accounts/{account_id}/users/user-old",
                    ),
                    entry(
                        3,
                        "POST",
                        "https://chatgpt.com/api/auth/signin/openai?login_hint=new%2B3%40example.com",
                    ),
                    entry(
                        4,
                        "POST",
                        "https://auth.openai.com/api/accounts/workspace/select",
                        request_body={"workspace_id": account_id},
                    ),
                    entry(
                        5,
                        "GET",
                        "https://chatgpt.com/api/auth/session",
                        response_body={
                            "user": {"email": "new+3@example.com"},
                            "account": {"id": account_id, "planType": "team"},
                            "accessToken": "a.b.c",
                            "sessionToken": "session-one",
                        },
                    ),
                    entry(
                        6,
                        "POST",
                        "https://chatgpt.com/backend-api/wham/auth-credentials",
                        request_body={"name": "new", "scopes": ["one"], "ttl": 5_184_000},
                        response_body={
                            "access_token": "at-test",
                            "creator_user_email": "new+3@example.com",
                            "workspace_id": account_id,
                        },
                    ),
                    entry(
                        7,
                        "GET",
                        "https://chatgpt.com/api/auth/session",
                        response_body={
                            "user": {"email": "new+3@example.com"},
                            "account": {"id": account_id, "planType": "team"},
                            "accessToken": "d.e.f",
                            "sessionToken": "session-two",
                        },
                    ),
                ]
            }
        }

    def test_analysis_extracts_protocol(self):
        report = analyze_har(self.har)
        self.assertEqual([item["login_hint"] for item in report["signins"]], ["old+2@example.com", "new+3@example.com"])
        self.assertEqual(report["invites"][0]["account_id"], "account-1")
        self.assertEqual(report["member_deletes"][0]["user_id"], "user-old")
        self.assertEqual(report["workspace_selections"][0]["workspace_id"], "account-1")
        self.assertEqual(report["token_creations"][0]["ttl"], 5_184_000)
        self.assertEqual(report["session_snapshots"], 2)
        self.assertEqual(report["inferences"]["invitee_email"], "new+3@example.com")

    def test_latest_session_and_pat_selection(self):
        session = select_session_snapshot(self.har, email="NEW+3@example.com")
        self.assertEqual(session.index, 7)
        self.assertEqual(session.data["sessionToken"], "session-two")
        pat = select_pat_credential(self.har, email="new+3@example.com")
        self.assertIsNotNone(pat)
        self.assertEqual(pat.token, "at-test")


if __name__ == "__main__":
    unittest.main()
