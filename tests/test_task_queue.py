import json
import tempfile
import threading
import time
import unittest
from collections import deque
from pathlib import Path

from team_protocol.database import Database
from team_protocol.task_queue import DatabaseCheckpointStore, TaskQueue, redact_text
from team_protocol.workflow import WorkflowCancelled, WorkflowIdentityError


class MemorySecretStore:
    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        body = bytes(plaintext)
        key = purpose.encode("utf-8") or b"x"
        return b"test:" + bytes(
            value ^ key[index % len(key)] for index, value in enumerate(body)
        )

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        payload = bytes(ciphertext)
        if not payload.startswith(b"test:"):
            raise ValueError("invalid ciphertext")
        body = payload[5:]
        key = purpose.encode("utf-8") or b"x"
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(body))


def wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


class RunnerHarness:
    def __init__(self, *behaviors):
        self.behaviors = deque(behaviors)
        self.lock = threading.Lock()
        self.calls = []
        self.active = 0
        self.max_active = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, config, **kwargs):
        with self.lock:
            behavior = self.behaviors.popleft() if self.behaviors else "success"
            call = {
                "behavior": behavior,
                "config": config,
                "old_mailbox": kwargs["old_mailbox"],
                "new_mailbox": kwargs["new_mailbox"],
                "proxy": kwargs["expanded_proxy"],
                "old_network": kwargs["old_network"],
                "new_network": kwargs["new_network"],
                "checkpoint_before": kwargs["checkpoint_store"].snapshot(),
            }
            self.calls.append(call)
        return FakeRunner(self, behavior, config, kwargs)


class FakeRunner:
    def __init__(self, harness, behavior, config, kwargs):
        self.harness = harness
        self.behavior = behavior
        self.config = config
        self.kwargs = kwargs

    def run(self):
        with self.harness.lock:
            self.harness.active += 1
            self.harness.max_active = max(self.harness.max_active, self.harness.active)
        try:
            callback = self.kwargs["event_callback"]
            logger = self.kwargs["logger"]
            checkpoint = self.kwargs["checkpoint_store"]
            stop_event = self.kwargs["stop_event"]
            callback({"type": "step", "step": "old_login", "state": "active"})
            checkpoint.set(
                "old_login",
                {"attempt": len(self.harness.calls), "session": "session-checkpoint-canary"},
            )
            logger(
                "using "
                + self.config.proxy
                + " refresh="
                + self.kwargs["old_mailbox"].refresh_token
            )
            if isinstance(self.behavior, BaseException):
                raise self.behavior
            if self.behavior == "fail":
                raise RuntimeError(
                    "failed with "
                    + self.kwargs["old_mailbox"].refresh_token
                    + " at "
                    + self.config.proxy
                )
            if self.behavior == "block":
                self.harness.started.set()
                while not self.harness.release.is_set():
                    if stop_event.wait(0.01):
                        raise WorkflowCancelled("cancelled")
            elif self.behavior == "ignore-stop":
                self.harness.started.set()
                self.harness.release.wait(3.0)
            callback({"type": "step", "step": "old_login", "state": "done"})
            return {
                "status": "ok",
                "authenticated_url": self.config.proxy,
                "session": "session-checkpoint-canary",
            }
        finally:
            with self.harness.lock:
                self.harness.active -= 1


class TaskQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.database = Database(
            self.root / "console.db", secret_store=MemorySecretStore()
        )
        self.database.set_text_setting("output_dir", str(self.root / "output"))
        self.database.set_text_setting("management_push", "0")
        self.database.set_text_setting("sub2api_push", "0")
        self.database.set_secret_setting(
            "proxy",
            "http://proxy-user-region-BR-sid-seed-t-60:"
            "proxy-password@proxy.invalid:9000/{rand}",
        )
        self.queues = []

    def tearDown(self):
        for queue in self.queues:
            queue.shutdown(timeout=1.0)

    def make_workspace(self, suffix):
        current = self.database.create_account(
            account_id=f"account-{suffix}-current",
            email=f"person+{suffix}-current@example.com",
            primary_email=f"person-{suffix}@example.com",
            credentials={
                "mailbox_password": f"mailbox-password-{suffix}-current",
                "client_id": f"client-{suffix}-current",
                "refresh_token": f"refresh-{suffix}-current",
                "account_password": f"account-password-{suffix}-current",
            },
            source="test",
        )
        next_account = self.database.create_account(
            account_id=f"account-{suffix}-next",
            email=f"person+{suffix}-next@example.com",
            primary_email=f"person-{suffix}@example.com",
            credentials={
                "mailbox_password": f"mailbox-password-{suffix}-next",
                "client_id": f"client-{suffix}-next",
                "refresh_token": f"refresh-{suffix}-next",
                "account_password": f"account-password-{suffix}-next",
            },
            source="test",
        )
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    def make_queue(self, harness, *, shutdown_timeout=1.0):
        queue = TaskQueue(
            self.database,
            runner_factory=harness,
            shutdown_timeout=shutdown_timeout,
        )
        self.queues.append(queue)
        return queue

    def test_database_checkpoint_store_persists_the_full_encrypted_document(self):
        workspace, _, _ = self.make_workspace("checkpoint")
        run = self.database.enqueue_workspace(workspace["id"])
        checkpoint = DatabaseCheckpointStore(self.database, run["id"])

        checkpoint.set("old_login", {"session": "checkpoint-secret-one"})
        checkpoint.set("invite", {"token": "checkpoint-secret-two"})

        self.assertEqual(
            self.database.get_run_checkpoint(run["id"]),
            {
                "old_login": {"session": "checkpoint-secret-one"},
                "invite": {"token": "checkpoint-secret-two"},
            },
        )
        self.assertEqual(self.database.get_run(run["id"])["current_step"], "invite")
        raw = b"".join(
            path.read_bytes() for path in self.root.glob("console.db*") if path.is_file()
        )
        self.assertNotIn(b"checkpoint-secret-one", raw)
        self.assertNotIn(b"checkpoint-secret-two", raw)

    def test_fifo_single_active_failure_continues_and_redacts(self):
        first, _, _ = self.make_workspace("first")
        second, _, second_next = self.make_workspace("second")
        harness = RunnerHarness("fail", "success")
        queue = self.make_queue(harness)
        runs = queue.enqueue([first["id"], second["id"]])

        queue.start()

        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(runs[0]["id"])["state"] == "failed"
                and self.database.get_run(runs[1]["id"])["state"] == "succeeded"
            )
        )
        self.assertEqual(
            [call["config"].old_account.email for call in harness.calls],
            [runs[0]["current_email_snapshot"], runs[1]["current_email_snapshot"]],
        )
        self.assertEqual(harness.max_active, 1)
        self.assertEqual(
            self.database.get_workspace(second["id"])["current_account_id"],
            second_next["id"],
        )
        error = self.database.get_run(runs[0]["id"])["redacted_error"]
        self.assertNotIn("refresh-first-current", error)
        self.assertNotIn("proxy-password", error)
        self.assertIn("***", error)
        self.assertTrue(
            wait_until(
                lambda: any(
                    event["message"] == "run succeeded"
                    for event in self.database.list_run_events(run_id=runs[1]["id"])
                )
            )
        )
        serialized_events = json.dumps(
            self.database.list_run_events(), ensure_ascii=False
        )
        self.assertNotIn("refresh-first-current", serialized_events)
        self.assertNotIn("proxy-password", serialized_events)
        self.assertNotIn("proxy-user:", serialized_events)

    def test_pause_blocks_claim_until_resume(self):
        workspace, _, _ = self.make_workspace("paused")
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)
        queue.pause()
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        time.sleep(0.08)

        self.assertEqual(harness.calls, [])
        self.assertEqual(self.database.get_run(run["id"])["state"], "queued")
        queue.resume()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )

    def test_active_and_queued_stop_never_start_the_cancelled_item(self):
        first, _, _ = self.make_workspace("stop-active")
        second, _, _ = self.make_workspace("stop-pending")
        harness = RunnerHarness("block", "success")
        queue = self.make_queue(harness)
        runs = queue.enqueue([first["id"], second["id"]])
        queue.start()
        self.assertTrue(harness.started.wait(2.0))

        self.assertEqual(queue.stop(runs[1]["id"]), "cancelled")
        self.assertEqual(queue.stop(runs[0]["id"]), "stopping")

        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(runs[0]["id"])["state"] == "cancelled"
            )
        )
        self.assertEqual(self.database.get_run(runs[1]["id"])["state"], "cancelled")
        self.assertEqual(len(harness.calls), 1)

    def test_retry_reuses_run_checkpoint_and_expanded_proxy(self):
        workspace, _, next_account = self.make_workspace("retry")
        harness = RunnerHarness("fail", "success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        first_proxy = self.database.get_run_proxy(run["id"])

        retried = queue.retry(run["id"])

        self.assertEqual(retried["id"], run["id"])
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )
        self.assertEqual([call["proxy"] for call in harness.calls], [first_proxy, first_proxy])
        self.assertNotEqual(
            harness.calls[0]["old_network"].proxy,
            harness.calls[0]["new_network"].proxy,
        )
        self.assertEqual(
            [call["old_network"].proxy for call in harness.calls],
            [harness.calls[0]["old_network"].proxy] * 2,
        )
        self.assertEqual(
            [call["new_network"].proxy for call in harness.calls],
            [harness.calls[0]["new_network"].proxy] * 2,
        )
        current_identity = self.database.get_account_network_identity(
            workspace["current_account_id"]
        )
        next_identity = self.database.get_account_network_identity(next_account["id"])
        self.assertNotEqual(current_identity["proxy_sid"], next_identity["proxy_sid"])
        self.assertIn("old_login", harness.calls[1]["checkpoint_before"])
        self.assertEqual(
            self.database.get_workspace(workspace["id"])["current_account_id"],
            next_account["id"],
        )
        messages = [
            event["message"]
            for event in self.database.list_run_events(run_id=run["id"])
        ]
        self.assertIn("failed run queued for retry", messages)

    def test_only_structured_identity_error_uses_atomic_replacement(self):
        workspace, _, _ = self.make_workspace("identity")
        identity_calls = []

        def fail_and_replace(run_id, *, role, failure_code, redacted_error):
            identity_calls.append((run_id, role, failure_code, redacted_error))
            return self.database.fail_run(run_id, redacted_error)

        self.database.fail_run_and_replace_account = fail_and_replace
        harness = RunnerHarness(
            WorkflowIdentityError("alias_disabled", "next"),
            "fail",
        )
        queue = self.make_queue(harness)
        identity_run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(
            wait_until(
                lambda: self.database.get_run(identity_run["id"])["state"] == "failed"
            )
        )

        self.assertEqual(len(identity_calls), 1)
        self.assertEqual(identity_calls[0][0:3], (identity_run["id"], "next", "alias_disabled"))
        self.assertNotIn("refresh-identity", identity_calls[0][3])

    def test_transient_failure_never_calls_identity_replacement(self):
        workspace, _, _ = self.make_workspace("transient-identity")
        replacement_calls = []

        def unexpected_replacement(*args, **kwargs):
            replacement_calls.append((args, kwargs))
            raise AssertionError("transient failure attempted identity replacement")

        self.database.fail_run_and_replace_account = unexpected_replacement
        queue = self.make_queue(RunnerHarness("fail"))
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        self.assertEqual(replacement_calls, [])

    def test_structured_identity_failure_atomically_replaces_next_account(self):
        workspace, current, failed_next = self.make_workspace("identity-atomic")
        self.database.import_mailbox_inventory(
            [
                {
                    "primary_email": "replacement@example.com",
                    "client_id": "replacement-client",
                    "refresh_token": "replacement-refresh-secret",
                    "password": "replacement-mail-secret",
                    "source_order": 0,
                }
            ]
        )
        queue = self.make_queue(
            RunnerHarness(
                WorkflowIdentityError("alias_disabled", "next")
            )
        )
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        updated = self.database.get_workspace(workspace["id"])
        replacement = self.database.get_account(updated["next_account_id"])
        self.assertEqual(updated["current_account_id"], current["id"])
        self.assertNotEqual(updated["next_account_id"], failed_next["id"])
        self.assertEqual(replacement["email"], "replacement+1@example.com")
        self.assertEqual(replacement["status"], "bound_next")
        self.assertEqual(
            self.database.get_account(failed_next["id"])["status"], "disabled"
        )

    def test_identity_replacement_conflict_does_not_leave_run_running(self):
        primary = "same-primary@example.com"
        current = self.database.create_account(
            email="same-primary+1@example.com",
            primary_email=primary,
            credentials={
                "mailbox_password": "current-mail",
                "client_id": "current-client",
                "refresh_token": "current-refresh",
                "account_password": "current-account",
            },
            source="test",
        )
        next_account = self.database.create_account(
            email="same-primary+2@example.com",
            primary_email=primary,
            credentials={
                "mailbox_password": "next-mail",
                "client_id": "next-client",
                "refresh_token": "next-refresh",
                "account_password": "next-account",
            },
            source="test",
        )
        workspace = self.database.create_workspace(
            name="No replacement",
            workspace_uid="no-replacement",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        queue = self.make_queue(
            RunnerHarness(
                WorkflowIdentityError("mailbox_credentials_invalid", "current")
            )
        )
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()

        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "failed")
        )
        unresolved = self.database.get_workspace(workspace["id"])
        self.assertEqual(unresolved["current_account_id"], current["id"])
        self.assertIsNone(unresolved["next_account_id"])
        self.assertEqual(unresolved["status"], "needs_account")
        self.assertEqual(self.database.get_account(current["id"])["status"], "disabled")
        self.assertEqual(
            self.database.get_account(next_account["id"])["status"], "disabled"
        )
        self.assertEqual(
            self.database.list_queue(include_terminal=True)[0]["state"], "failed"
        )

    def test_startup_recovers_the_same_interrupted_run(self):
        workspace, _, _ = self.make_workspace("recovery")
        run = self.database.enqueue_workspace(workspace["id"])
        legacy_profile = {"profile_id": "legacy-shared-profile", "major": 142}
        legacy_geo = {
            "resolved": True,
            "country_code": "BR",
            "timezone_id": "America/Sao_Paulo",
            "locale": "pt-BR",
        }
        self.database.set_run_checkpoint(
            run["id"],
            {
                "new_login": {"done": True},
                "invite": {"done": True},
                "_fingerprint_profile": legacy_profile,
                "_proxy_geo": legacy_geo,
            },
        )
        self.database.set_run_proxy(
            run["id"], "http://fixed-user:fixed-password@proxy.invalid:9000"
        )
        self.database.claim_next_queue_item()
        self.database.request_stop(run["id"])
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)

        recovered = queue.start()

        self.assertEqual(recovered, (run["id"],))
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )
        self.assertEqual(harness.calls[0]["proxy"], self.database.get_run_proxy(run["id"]))
        self.assertEqual(harness.calls[0]["checkpoint_before"]["invite"], {"done": True})
        self.assertTrue(harness.calls[0]["old_network"].legacy_recovery)
        self.assertTrue(harness.calls[0]["new_network"].legacy_recovery)
        self.assertEqual(
            harness.calls[0]["old_network"].fingerprint_profile,
            legacy_profile,
        )
        self.assertEqual(
            harness.calls[0]["old_network"].proxy,
            self.database.get_run_proxy(run["id"]),
        )
        self.assertNotIn(
            "fingerprint_profile",
            self.database.get_account_network_identity(
                workspace["current_account_id"]
            ),
        )
        self.assertIn(
            "interrupted run recovered and requeued",
            [
                event["message"]
                for event in self.database.list_run_events(run_id=run["id"])
            ],
        )

    def test_shutdown_is_bounded_and_requests_cooperative_stop(self):
        workspace, _, _ = self.make_workspace("shutdown")
        harness = RunnerHarness("ignore-stop")
        queue = self.make_queue(harness, shutdown_timeout=0.05)
        run = queue.enqueue([workspace["id"]])[0]
        queue.start()
        self.assertTrue(harness.started.wait(2.0))

        started = time.monotonic()
        stopped = queue.shutdown()
        elapsed = time.monotonic() - started

        self.assertFalse(stopped)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(self.database.get_run(run["id"])["state"], "stopping")
        harness.release.set()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "cancelled")
        )
        self.assertTrue(queue.shutdown(timeout=1.0))

    def test_wait_for_change_uses_monotonic_revision(self):
        harness = RunnerHarness()
        queue = self.make_queue(harness)
        before = queue.revision
        observed = []

        waiter = threading.Thread(
            target=lambda: observed.append(queue.wait_for_change(before, timeout=1.0))
        )
        waiter.start()
        time.sleep(0.02)
        changed = queue.notify_change()
        waiter.join(1.0)

        self.assertEqual(observed, [changed])
        self.assertGreater(changed, before)

    def test_default_runner_inputs_use_snapshot_credentials_and_settings(self):
        workspace, current, next_account = self.make_workspace("inputs")
        self.database.set_text_setting("pat_name", "database-pat")
        self.database.set_text_setting("pat_ttl", "600")
        self.database.set_text_setting("invite_settle_seconds", "4.5")
        self.database.set_text_setting("sub2api_group_id", "3")
        self.database.set_secret_setting("management_api_key", "management-secret")
        harness = RunnerHarness("success")
        queue = self.make_queue(harness)
        run = queue.enqueue([workspace["id"]])[0]

        queue.start()
        self.assertTrue(
            wait_until(lambda: self.database.get_run(run["id"])["state"] == "succeeded")
        )

        call = harness.calls[0]
        self.assertEqual(call["config"].workspace_id, workspace["workspace_uid"])
        self.assertEqual(call["config"].pat_name, "database-pat")
        self.assertEqual(call["config"].pat_ttl, 600)
        self.assertEqual(call["config"].invite_settle_seconds, 4.5)
        self.assertEqual(call["config"].management_key, "management-secret")
        self.assertFalse(call["config"].push)
        self.assertFalse(call["config"].sub2api_push)
        self.assertEqual(call["config"].sub2api_group_id, 3)
        self.assertEqual(call["old_mailbox"].registration_email, current["email"])
        self.assertEqual(call["new_mailbox"].registration_email, next_account["email"])
        self.assertEqual(call["old_mailbox"].refresh_token, "refresh-inputs-current")

    def test_redact_text_removes_known_secrets_and_url_userinfo(self):
        value = "token=canary https://name:password@example.invalid/path"
        self.assertEqual(
            redact_text(value, ("canary",)),
            "token=*** https://***@example.invalid/path",
        )


if __name__ == "__main__":
    unittest.main()
