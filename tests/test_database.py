import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from team_protocol.database import (
    BindingConflictError,
    ConflictError,
    Database,
    RestoreValidationError,
    StaleVersionError,
    StateConflictError,
    ValidationError,
    WorkspaceActiveError,
)
import team_protocol.database as database_module
from team_protocol.migration import (
    LegacyAccountBinding,
    LegacyConfig,
    LegacyImportModel,
    LegacyMailboxRow,
    LegacyManagementSettings,
    LegacySub2APISettings,
    VerifiedBackup,
)


class TestSecretStore:
    def __init__(self) -> None:
        self.key = hashlib.sha256(b"database-test-key").digest()

    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        nonce = os.urandom(16)
        seed = hashlib.sha256(self.key + purpose.encode("utf-8") + nonce).digest()
        body = bytes(value ^ seed[index % len(seed)] for index, value in enumerate(plaintext))
        tag = hmac.new(
            self.key, purpose.encode("utf-8") + nonce + body, hashlib.sha256
        ).digest()
        return b"TEST1" + nonce + tag + body

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        if not ciphertext.startswith(b"TEST1"):
            raise ValueError("invalid ciphertext")
        nonce = ciphertext[5:21]
        tag = ciphertext[21:53]
        body = ciphertext[53:]
        expected = hmac.new(
            self.key, purpose.encode("utf-8") + nonce + body, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("invalid ciphertext")
        seed = hashlib.sha256(self.key + purpose.encode("utf-8") + nonce).digest()
        return bytes(value ^ seed[index % len(seed)] for index, value in enumerate(body))


class FailingRotationDatabase(Database):
    fail_before_commit = False

    def _before_rotation_commit(self, connection, run_id):
        del connection, run_id
        if self.fail_before_commit:
            raise RuntimeError("injected rotation failure")


class FailingImportDatabase(Database):
    fail_import = False

    def _before_legacy_import_commit(self, connection, migration_id):
        del connection, migration_id
        if self.fail_import:
            raise RuntimeError("injected import failure")


class FailingSchemaUpgradeDatabase(Database):
    fail_upgrade = False

    def _before_schema_migration_commit(self, connection, from_version, to_version):
        del connection, from_version, to_version
        if self.fail_upgrade:
            raise RuntimeError("injected schema upgrade failure")


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.path = Path(self.temporary_directory.name) / "nested" / "console.db"
        self.database = Database(self.path, secret_store=TestSecretStore())

    def create_account(self, suffix: str) -> dict:
        return self.database.create_account(
            account_id=f"account-{suffix}",
            email=f"person+{suffix}@example.com",
            primary_email="person@example.com",
            credentials={
                "password": f"password-{suffix}",
                "client_id": f"client-{suffix}",
                "refresh_token": f"refresh-{suffix}",
            },
            source="test",
        )

    def create_workspace(self, suffix: str) -> tuple[dict, dict, dict]:
        current = self.create_account(f"{suffix}-current")
        next_account = self.create_account(f"{suffix}-next")
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    @staticmethod
    def inventory_record(primary_email: str, source_order: int = 0) -> dict:
        local = primary_email.split("@", 1)[0].casefold()
        return {
            "primary_email": primary_email,
            "password": f"mailbox-{local}",
            "client_id": f"client-{local}",
            "refresh_token": f"refresh-{local}",
            "source_order": source_order,
        }

    def assert_secret_absent_from_database_files(self, secret: str) -> None:
        encoded = secret.encode("utf-8")
        for path in self.path.parent.glob(f"{self.path.name}*"):
            if path.is_file():
                self.assertNotIn(encoded, path.read_bytes(), str(path))

    def legacy_model(self, *, with_state: bool = True) -> LegacyImportModel:
        root = Path(self.temporary_directory.name) / "legacy"
        root.mkdir(parents=True, exist_ok=True)
        main = LegacyMailboxRow(
            primary_email="main@example.com",
            password="mailbox-secret-main",
            client_id="client-secret-main",
            refresh_token="refresh-secret-main",
        )
        other = LegacyMailboxRow(
            primary_email="other@example.com",
            password="mailbox-secret-other",
            client_id="client-secret-other",
            refresh_token="refresh-secret-other",
        )
        old = LegacyAccountBinding(
            registration_email="main+3@example.com",
            primary_email=main.primary_email,
            account_password="account-secret-old",
            mailbox=main,
        )
        new = LegacyAccountBinding(
            registration_email="main+4@example.com",
            primary_email=main.primary_email,
            account_password="account-secret-new",
            mailbox=main,
        )
        config = LegacyConfig(
            config_path=root / "workflow.json",
            mail_account_file=root / "hotmail.txt",
            workspace_id="legacy-workspace-uid",
            old_email=old.registration_email,
            new_email=new.registration_email,
            old_password=old.account_password,
            new_password=new.account_password,
            proxy="socks5h://user:proxy-secret@proxy.invalid:9000",
            pat_name="migration-pat",
            pat_ttl=3600,
            output_dir=root / "output",
            state_path=root / "output" / ".state" / "legacy.json",
            state_is_app_owned=True,
            invite_settle_seconds=3.5,
            management=LegacyManagementSettings(
                base_url="https://management.invalid",
                api_key="management-secret",
                push=False,
                replace=True,
                remote_name="remote.json",
            ),
            sub2api=LegacySub2APISettings(
                base_url="https://sub2api.invalid",
                email="admin@example.com",
                password="sub2-secret",
                api_key="sub2-api-key",
                totp_secret="sub2-totp-secret",
                push=True,
                concurrency=30,
                priority=2,
            ),
        )
        state = (
            {
                "version": 1,
                "steps": {
                    "_fingerprint_profile": {"profile_id": "fingerprint-secret"},
                    "old_login": {"session": "state-secret"},
                    "complete": {"workspace_id": config.workspace_id},
                },
            }
            if with_state
            else None
        )
        return LegacyImportModel(
            config=config,
            mailboxes=(main, other),
            old_binding=old,
            new_binding=new,
            state=state,
            migration_id=hashlib.sha256(b"database-legacy-fixture").hexdigest(),
        )

    def backup_candidate(self, database: Database, model: LegacyImportModel) -> VerifiedBackup:
        return VerifiedBackup(
            schema_version=int(database.get_meta("schema_version") or 0),
            instance_id=str(database.get_meta("instance_id")),
            created_at="2026-07-12T12:00:00Z",
            migration_id=model.migration_id,
            identity={
                "workspace_id": model.config.workspace_id,
                "old_email": model.config.old_email,
                "new_email": model.config.new_email,
            },
            sources=(),
            sqlite_snapshot=database.create_snapshot_bytes(),
            payload_sha256="fixture",
        )

    def test_schema_initialization_is_idempotent_and_uses_required_pragmas(self):
        instance_id = self.database.get_meta("instance_id")
        self.database.initialize()
        diagnostics = self.database.diagnostics()

        self.assertEqual(diagnostics["schema_version"], 3)
        self.assertEqual(diagnostics["journal_mode"], "wal")
        self.assertTrue(diagnostics["foreign_keys"])
        self.assertEqual(diagnostics["busy_timeout_ms"], 5000)
        self.assertEqual(self.database.get_meta("instance_id"), instance_id)

    def test_text_and_encrypted_settings_never_share_storage_columns(self):
        canary = "setting-secret-canary-923847"
        self.database.set_text_setting("output_dir", "output")
        self.database.set_secret_setting("proxy", canary)

        self.assertEqual(self.database.get_text_setting("output_dir"), "output")
        self.assertEqual(self.database.get_secret_setting("proxy"), canary.encode())
        self.assertEqual(
            self.database.list_settings(),
            [
                {
                    "key": "output_dir",
                    "value": "output",
                    "encrypted": False,
                    "configured": False,
                    "updated_at": self.database.list_settings()[0]["updated_at"],
                },
                {
                    "key": "proxy",
                    "value": None,
                    "encrypted": True,
                    "configured": True,
                    "updated_at": self.database.list_settings()[1]["updated_at"],
                },
            ],
        )
        self.assertNotIn(canary.encode(), self.path.read_bytes())
        with self.assertRaises(StateConflictError):
            self.database.get_text_setting("proxy")
        self.assertTrue(self.database.delete_setting("proxy"))
        self.assertFalse(self.database.delete_setting("proxy"))
        self.assertNotIn("proxy", {row["key"] for row in self.database.list_settings()})

    def test_account_credentials_are_encrypted_and_email_is_case_insensitive_unique(self):
        account = self.create_account("one")
        credentials = self.database.get_account_credentials(account["id"])

        self.assertEqual(credentials["refresh_token"], "refresh-one")
        self.assertNotIn(b"refresh-one", self.path.read_bytes())
        with self.assertRaises(ConflictError):
            self.database.create_account(
                email="PERSON+ONE@EXAMPLE.COM",
                primary_email="person@example.com",
                credentials={"password": "other"},
                source="test",
            )

    def test_account_network_identity_is_encrypted_stable_and_write_once(self):
        account = self.create_account("network")
        first = self.database.ensure_account_network_identity(
            account["id"],
            proxy_sid="Account90",
        )
        second = self.database.ensure_account_network_identity(
            account["id"],
            proxy_sid="Ignored99",
        )
        geo = {
            "resolved": True,
            "country_code": "BR",
            "timezone_id": "America/Sao_Paulo",
            "locale": "pt-BR",
        }
        profile = {
            "profile_id": "account-fingerprint-90",
            "major": 145,
            "timezone_id": "America/Sao_Paulo",
        }

        updated = self.database.merge_account_network_identity(
            account["id"],
            {"proxy_geo": geo, "fingerprint_profile": profile},
        )
        repeated = self.database.merge_account_network_identity(
            account["id"],
            {"proxy_geo": geo, "fingerprint_profile": profile},
        )

        self.assertEqual(first["proxy_sid"], "Account90")
        self.assertEqual(second["proxy_sid"], "Account90")
        self.assertEqual(updated, repeated)
        self.assertEqual(updated["version"], 1)
        self.assertEqual(updated["proxy_geo"], geo)
        self.assertEqual(updated["fingerprint_profile"], profile)
        self.assertEqual(
            self.database.get_account_network_identity(account["id"]),
            updated,
        )
        self.database.replace_account_credentials(
            account["id"],
            {"refresh_token": "replacement-refresh"},
        )
        self.assertEqual(
            self.database.get_account_network_identity(account["id"]),
            updated,
        )
        raw = b"".join(
            path.read_bytes() for path in self.path.parent.glob("console.db*")
            if path.is_file()
        )
        self.assertNotIn(b"Account90", raw)
        self.assertNotIn(b"account-fingerprint-90", raw)

        with self.assertRaises(StateConflictError):
            self.database.merge_account_network_identity(
                account["id"],
                {"proxy_sid": "Different90"},
            )

    def test_account_manual_lifecycle_blocks_bound_accounts(self):
        current = self.create_account("current")
        next_account = self.create_account("next")
        self.database.create_workspace(
            name="Space",
            workspace_uid="workspace-uid",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )

        with self.assertRaises(StateConflictError):
            self.database.transition_account_status(current["id"], "retired")
        spare = self.create_account("spare")
        self.database.transition_account_status(spare["id"], "disabled")
        self.assertEqual(
            self.database.transition_account_status(spare["id"], "available")["status"],
            "available",
        )

    def test_workspace_creation_assigns_roles_and_derives_readiness(self):
        current = self.create_account("current")
        next_account = self.create_account("next")
        workspace = self.database.create_workspace(
            workspace_id="workspace-1",
            name="Primary space",
            workspace_uid="workspace-uid",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )

        self.assertEqual(workspace["status"], "ready")
        self.assertEqual(workspace["version"], 1)
        self.assertEqual(self.database.get_account(current["id"])["status"], "bound_current")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_next")

    def test_every_cross_role_binding_conflict_is_rejected(self):
        first_current = self.create_account("first-current")
        first_next = self.create_account("first-next")
        second_current = self.create_account("second-current")
        second_next = self.create_account("second-next")
        self.database.create_workspace(
            name="First",
            workspace_uid="first-uid",
            current_account_id=first_current["id"],
            next_account_id=first_next["id"],
        )

        for current_id, next_id in (
            (first_current["id"], second_next["id"]),
            (first_next["id"], second_next["id"]),
            (second_current["id"], first_current["id"]),
            (second_current["id"], first_next["id"]),
        ):
            with self.subTest(current=current_id, next=next_id):
                with self.assertRaises(BindingConflictError):
                    self.database.create_workspace(
                        name="Conflicting",
                        workspace_uid=f"conflict-{current_id}-{next_id}",
                        current_account_id=current_id,
                        next_account_id=next_id,
                    )

    def test_binding_update_is_optimistic_and_releases_replaced_accounts(self):
        old_current = self.create_account("old-current")
        old_next = self.create_account("old-next")
        new_current = self.create_account("new-current")
        workspace = self.database.create_workspace(
            name="Space",
            workspace_uid="workspace-uid",
            current_account_id=old_current["id"],
            next_account_id=old_next["id"],
        )

        updated = self.database.update_workspace_bindings(
            workspace["id"],
            current_account_id=new_current["id"],
            next_account_id=None,
            expected_version=workspace["version"],
        )

        self.assertEqual(updated["version"], 2)
        self.assertEqual(updated["status"], "needs_account")
        self.assertEqual(self.database.get_account(old_current["id"])["status"], "available")
        self.assertEqual(self.database.get_account(old_next["id"])["status"], "available")
        self.assertEqual(self.database.get_account(new_current["id"])["status"], "bound_current")
        with self.assertRaises(StaleVersionError):
            self.database.update_workspace_bindings(
                workspace["id"],
                current_account_id=new_current["id"],
                next_account_id=None,
                expected_version=workspace["version"],
            )

    def test_unified_workspace_update_preserves_uid_and_supports_explicit_next_clear(self):
        workspace, current, next_account = self.create_workspace("unified")

        renamed = self.database.update_workspace(
            workspace["id"],
            expected_version=workspace["version"],
            name="Renamed space",
        )
        self.assertEqual(renamed["name"], "Renamed space")
        self.assertEqual(renamed["workspace_uid"], workspace["workspace_uid"])
        self.assertEqual(renamed["status"], "ready")
        self.assertEqual(renamed["next_account_id"], next_account["id"])

        cleared = self.database.update_workspace(
            workspace["id"],
            expected_version=renamed["version"],
            next_account_id=None,
        )
        self.assertEqual(cleared["current_account_id"], current["id"])
        self.assertIsNone(cleared["next_account_id"])
        self.assertEqual(cleared["status"], "needs_account")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "available")

    def test_batch_enqueue_is_atomic_and_snapshots_identity(self):
        first, first_current, first_next = self.create_workspace("first")
        second, _, _ = self.create_workspace("second")

        runs = self.database.enqueue_workspaces([first["id"], second["id"]])

        self.assertEqual([run["position"] for run in runs], [0, 1])
        self.assertEqual(runs[0]["current_account_id"], first_current["id"])
        self.assertEqual(runs[0]["next_account_id"], first_next["id"])
        self.assertEqual(runs[0]["workspace_uid_snapshot"], first["workspace_uid"])
        self.assertEqual(self.database.get_workspace(first["id"])["status"], "queued")
        self.assertEqual(self.database.get_workspace(second["id"])["status"], "queued")

        valid, _, _ = self.create_workspace("valid")
        current = self.create_account("not-ready-current")
        not_ready = self.database.create_workspace(
            name="Not ready",
            workspace_uid="not-ready-uid",
            current_account_id=current["id"],
        )
        before = len(self.database.list_runs())
        with self.assertRaises(StateConflictError):
            self.database.enqueue_workspaces([valid["id"], not_ready["id"]])
        self.assertEqual(len(self.database.list_runs()), before)
        self.assertEqual(self.database.get_workspace(valid["id"])["status"], "ready")

    def test_run_checkpoint_and_proxy_are_encrypted_and_proxy_is_immutable(self):
        workspace, _, _ = self.create_workspace("encrypted-run")
        run = self.database.enqueue_workspace(workspace["id"])
        checkpoint_secret = "checkpoint-canary-712"
        proxy = "http://user:proxy-canary-931@proxy.example:9000"

        self.database.set_run_checkpoint(
            run["id"], {"session": checkpoint_secret, "completed": ["invite"]}, current_step="invite"
        )
        self.database.set_run_proxy(run["id"], proxy)
        self.database.set_run_proxy(run["id"], proxy)

        self.assertEqual(self.database.get_run_checkpoint(run["id"])["session"], checkpoint_secret)
        self.assertEqual(self.database.get_run_proxy(run["id"]), proxy)
        self.assertEqual(self.database.get_run(run["id"])["current_step"], "invite")
        self.assert_secret_absent_from_database_files(checkpoint_secret)
        self.assert_secret_absent_from_database_files(proxy)
        with self.assertRaises(StateConflictError):
            self.database.set_run_proxy(run["id"], "http://different.example:9000")

    def test_queue_pause_fifo_claim_and_single_running(self):
        first, _, _ = self.create_workspace("fifo-first")
        second, _, _ = self.create_workspace("fifo-second")
        runs = self.database.enqueue_workspaces([first["id"], second["id"]])

        self.database.set_queue_paused(True)
        self.assertTrue(self.database.is_queue_paused())
        self.assertIsNone(self.database.claim_next_queue_item())
        self.database.set_queue_paused(False)
        claimed = self.database.claim_next_queue_item()

        self.assertEqual(claimed["run_id"], runs[0]["id"])
        self.assertEqual(claimed["state"], "running")
        self.assertIsNone(self.database.claim_next_queue_item())
        self.assertEqual(self.database.get_workspace(first["id"])["status"], "running")

    def test_concurrent_claims_cannot_create_two_running_items(self):
        workspaces = [self.create_workspace(f"race-{index}")[0] for index in range(2)]
        self.database.enqueue_workspaces([workspace["id"] for workspace in workspaces])
        barrier = threading.Barrier(3)
        results = []
        errors = []

        def claim():
            try:
                barrier.wait()
                results.append(self.database.claim_next_queue_item())
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=claim) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(sum(item["state"] == "running" for item in self.database.list_queue()), 1)

    def test_queue_reorder_is_transactional(self):
        workspaces = [self.create_workspace(f"order-{index}")[0] for index in range(3)]
        runs = self.database.enqueue_workspaces([workspace["id"] for workspace in workspaces])
        original = self.database.list_queue()
        reversed_ids = [item["id"] for item in reversed(original)]

        reordered = self.database.reorder_queue(reversed_ids)

        self.assertEqual([item["id"] for item in reordered], reversed_ids)
        with self.assertRaises(StateConflictError):
            self.database.reorder_queue(reversed_ids[:-1])
        self.assertEqual([item["id"] for item in self.database.list_queue()], reversed_ids)
        self.assertEqual({item["run_id"] for item in reordered}, {run["id"] for run in runs})

    def test_pending_stop_cancels_and_active_failure_releases_next_item(self):
        first, _, _ = self.create_workspace("stop-first")
        second, _, _ = self.create_workspace("stop-second")
        runs = self.database.enqueue_workspaces([first["id"], second["id"]])
        claimed = self.database.claim_next_queue_item()

        self.assertEqual(self.database.request_stop(claimed["run_id"]), "stopping")
        failed = self.database.fail_run(claimed["run_id"], "safe failure")
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(self.database.claim_next_queue_item()["run_id"], runs[1]["id"])

        third, _, _ = self.create_workspace("stop-pending")
        pending = self.database.enqueue_workspace(third["id"])
        self.assertEqual(self.database.request_stop(pending["id"]), "cancelled")
        self.assertEqual(self.database.get_run(pending["id"])["state"], "cancelled")
        self.assertEqual(self.database.get_workspace(third["id"])["status"], "ready")

    def test_recover_interrupted_run_preserves_identity_and_checkpoint(self):
        workspace, _, _ = self.create_workspace("recover")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.set_run_checkpoint(run["id"], {"step": "login"})
        self.database.claim_next_queue_item()
        self.database.request_stop(run["id"])

        recovered = self.database.recover_interrupted_runs()

        self.assertEqual(recovered, [run["id"]])
        self.assertEqual(self.database.get_run(run["id"])["state"], "queued")
        self.assertEqual(self.database.get_run_checkpoint(run["id"]), {"step": "login"})
        self.assertEqual(self.database.list_queue()[0]["state"], "pending")

    def test_retry_reuses_failed_run_only_while_bindings_match(self):
        workspace, _, _ = self.create_workspace("retry")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.set_run_checkpoint(run["id"], {"completed": ["login"]})
        self.database.claim_next_queue_item()
        self.database.fail_run(run["id"], "redacted")

        retried = self.database.retry_run(run["id"])

        self.assertEqual(retried["id"], run["id"])
        self.assertEqual(retried["state"], "queued")
        self.assertEqual(self.database.get_run_checkpoint(run["id"]), {"completed": ["login"]})
        self.database.claim_next_queue_item()
        self.database.fail_run(run["id"], "redacted again")
        replacement = self.create_account("retry-replacement")
        latest = self.database.get_workspace(workspace["id"])
        self.database.update_workspace_bindings(
            workspace["id"],
            current_account_id=replacement["id"],
            next_account_id=latest["next_account_id"],
            expected_version=latest["version"],
        )
        with self.assertRaises(StateConflictError):
            self.database.retry_run(run["id"])

    def test_success_rotation_is_atomic_and_idempotent(self):
        workspace, current, next_account = self.create_workspace("success")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()

        succeeded = self.database.complete_run_and_rotate(run["id"], {"file": "result.json"})
        first_rotation = self.database.get_workspace(workspace["id"])
        repeated = self.database.complete_run_and_rotate(run["id"], {"ignored": True})

        self.assertEqual(succeeded["state"], "succeeded")
        self.assertEqual(repeated["id"], run["id"])
        self.assertEqual(first_rotation["current_account_id"], next_account["id"])
        self.assertIsNone(first_rotation["next_account_id"])
        self.assertEqual(first_rotation["rotation_count"], 1)
        self.assertEqual(self.database.get_workspace(workspace["id"])["rotation_count"], 1)
        self.assertEqual(self.database.get_account(current["id"])["status"], "exited_pending")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_current")
        self.assertEqual(self.database.list_queue(), [])
        self.assertEqual(
            self.database.transition_account_status(current["id"], "available")["status"],
            "available",
        )

    def test_success_rotation_rolls_back_every_mutation_on_failure(self):
        self.database = FailingRotationDatabase(self.path, secret_store=TestSecretStore())
        workspace, current, next_account = self.create_workspace("rollback")
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()
        self.database.fail_before_commit = True

        with self.assertRaisesRegex(RuntimeError, "injected rotation failure"):
            self.database.complete_run_and_rotate(run["id"])

        unchanged = self.database.get_workspace(workspace["id"])
        self.assertEqual(self.database.get_run(run["id"])["state"], "running")
        self.assertEqual(unchanged["current_account_id"], current["id"])
        self.assertEqual(unchanged["next_account_id"], next_account["id"])
        self.assertEqual(unchanged["rotation_count"], 0)
        self.assertEqual(self.database.get_account(current["id"])["status"], "bound_current")
        self.assertEqual(self.database.get_account(next_account["id"])["status"], "bound_next")

    def test_run_events_are_ordered_and_support_replay(self):
        workspace, _, _ = self.create_workspace("events")
        run = self.database.enqueue_workspace(workspace["id"])
        first = self.database.append_run_event(
            run["id"], step="login", level="info", message="started"
        )
        second = self.database.append_run_event(
            run["id"], step="login", level="debug", message="routine", routine=True
        )

        replay = self.database.list_run_events(run_id=run["id"], after_seq=first["seq"])

        self.assertEqual([event["seq"] for event in replay], [second["seq"]])
        self.assertTrue(replay[0]["routine"])

    def test_legacy_import_is_idempotent_and_encrypts_all_sensitive_state(self):
        model = self.legacy_model(with_state=True)

        first = self.database.apply_legacy_import(model)
        second = self.database.apply_legacy_import(model)

        self.assertEqual(first, second)
        self.assertEqual(first["counts"]["accounts"], 3)
        self.assertEqual(first["counts"]["workspaces"], 1)
        self.assertEqual(first["counts"]["runs"], 1)
        self.assertEqual(first["counts"]["queue_items"], 1)
        self.assertEqual(len(self.database.list_accounts()), 3)
        accounts = {account["email"]: account for account in self.database.list_accounts()}
        self.assertIn("main@example.com", accounts)
        self.assertNotIn("other@example.com", accounts)
        self.assertIn("main+3@example.com", accounts)
        self.assertIn("main+4@example.com", accounts)
        old_credentials = self.database.get_account_credentials(
            accounts["main+3@example.com"]["id"]
        )
        self.assertEqual(old_credentials["account_password"], "account-secret-old")
        self.assertEqual(old_credentials["refresh_token"], "refresh-secret-main")
        workspace = self.database.list_workspaces()[0]
        run = self.database.list_runs()[0]
        self.assertEqual(workspace["status"], "failed")
        self.assertEqual(run["state"], "failed")
        checkpoint = self.database.get_run_checkpoint(run["id"])
        self.assertIn("old_login", checkpoint)
        self.assertNotIn("steps", checkpoint)
        self.assertEqual(run["current_step"], "old_login")
        self.assertEqual(self.database.list_queue(include_terminal=True)[0]["state"], "failed")
        self.assertEqual(self.database.get_text_setting("pat_ttl"), "3600")
        self.assertEqual(self.database.get_secret_setting("proxy"), model.config.proxy.encode())
        self.assertEqual(
            self.database.get_secret_setting("management_api_key"), b"management-secret"
        )
        self.assertEqual(self.database.get_secret_setting("sub2api_password"), b"sub2-secret")
        self.assertEqual(self.database.get_secret_setting("sub2api_api_key"), b"sub2-api-key")
        self.assertEqual(
            self.database.get_secret_setting("sub2api_totp_secret"),
            b"sub2-totp-secret",
        )
        for secret in (
            "mailbox-secret-main",
            "client-secret-main",
            "refresh-secret-main",
            "account-secret-old",
            "account-secret-new",
            "proxy-secret",
            "management-secret",
            "sub2-secret",
            "sub2-api-key",
            "sub2-totp-secret",
            "state-secret",
        ):
            self.assert_secret_absent_from_database_files(secret)

    def test_prune_unreferenced_legacy_inventory_preserves_related_and_manual_accounts(self):
        model = self.legacy_model(with_state=False)
        self.database.apply_legacy_import(model)
        orphan = self.database.create_account(
            email="orphan@example.com",
            primary_email="orphan@example.com",
            credentials={
                "mailbox_password": "orphan-mail",
                "client_id": "orphan-client",
                "refresh_token": "orphan-refresh",
                "account_password": "",
            },
            source="legacy_txt",
        )
        manual = self.database.create_account(
            email="manual@example.com",
            primary_email="manual@example.com",
            credentials={
                "mailbox_password": "manual-mail",
                "client_id": "manual-client",
                "refresh_token": "manual-refresh",
                "account_password": "",
            },
            source="txt_import",
        )

        removed = self.database.prune_unreferenced_legacy_accounts()
        second = self.database.prune_unreferenced_legacy_accounts()

        remaining = {account["email"] for account in self.database.list_accounts()}
        self.assertEqual(removed, 1)
        self.assertEqual(second, 0)
        self.assertNotIn(orphan["email"], remaining)
        self.assertIn(manual["email"], remaining)
        self.assertIn("main@example.com", remaining)
        self.assertIn("main+3@example.com", remaining)
        self.assertIn("main+4@example.com", remaining)
        self.assertEqual(self.database.get_meta("legacy_account_scope_version"), "1")

    def test_legacy_import_disables_push_targets_without_required_secrets(self):
        model = self.legacy_model(with_state=False)
        config = replace(
            model.config,
            management=replace(model.config.management, api_key="", push=True),
            sub2api=replace(
                model.config.sub2api,
                password="",
                api_key="",
                totp_secret="",
                push=True,
            ),
        )

        self.database.apply_legacy_import(replace(model, config=config))

        self.assertEqual(self.database.get_text_setting("management_push"), "0")
        self.assertEqual(self.database.get_text_setting("sub2api_push"), "0")
        self.assertIsNone(self.database.get_secret_setting("management_api_key"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_password"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_api_key"))
        self.assertIsNone(self.database.get_secret_setting("sub2api_totp_secret"))

    def test_legacy_import_without_checkpoint_creates_ready_workspace(self):
        model = self.legacy_model(with_state=False)

        result = self.database.apply_legacy_import(model)

        self.assertEqual(result["counts"]["runs"], 0)
        self.assertEqual(result["counts"]["queue_items"], 0)
        self.assertEqual(self.database.list_workspaces()[0]["status"], "ready")

    def test_legacy_import_rolls_back_every_row_and_marker_on_failure(self):
        self.database = FailingImportDatabase(self.path, secret_store=TestSecretStore())
        self.database.fail_import = True
        model = self.legacy_model()

        with self.assertRaisesRegex(RuntimeError, "injected import failure"):
            self.database.apply_legacy_import(model)

        self.assertEqual(self.database.list_accounts(), [])
        self.assertEqual(self.database.list_workspaces(), [])
        self.assertEqual(self.database.list_runs(), [])
        self.assertEqual(self.database.list_queue(include_terminal=True), [])
        self.assertIsNone(self.database.get_meta("migration_id"))

    def test_legacy_import_rejects_nonfresh_or_different_migration(self):
        self.create_account("existing")
        with self.assertRaises(StateConflictError):
            self.database.apply_legacy_import(self.legacy_model())

        other_path = Path(self.temporary_directory.name) / "other.db"
        other = Database(other_path, secret_store=TestSecretStore())
        model = self.legacy_model()
        other.apply_legacy_import(model)
        different = LegacyImportModel(
            config=model.config,
            mailboxes=model.mailboxes,
            old_binding=model.old_binding,
            new_binding=model.new_binding,
            state=model.state,
            migration_id="f" * 64,
        )
        with self.assertRaises(ConflictError):
            other.apply_legacy_import(different)

    def test_snapshot_uses_live_wal_content_and_restore_replaces_database(self):
        model = self.legacy_model()
        self.database.apply_legacy_import(model)
        candidate = self.backup_candidate(self.database, model)
        self.assertTrue(candidate.sqlite_snapshot.startswith(b"SQLite format 3\x00"))

        target_path = Path(self.temporary_directory.name) / "restore" / "console.db"
        target = Database(target_path, secret_store=TestSecretStore())
        target.create_account(
            email="target-only@example.com",
            primary_email="target-only@example.com",
            credentials={"password": "target-only-secret"},
            source="test",
        )
        validation = target.validate_restore_candidate(candidate)
        with self.assertRaises(StateConflictError):
            target.restore_verified_backup(candidate, validation)
        target.set_queue_paused(True)

        result = target.restore_verified_backup(candidate, validation)

        self.assertEqual(result["status"], "restored")
        self.assertTrue(target.is_queue_paused())
        self.assertEqual(target.get_meta("migration_id"), model.migration_id)
        self.assertEqual(len(target.list_accounts()), 3)
        self.assertNotIn("target-only@example.com", {row["email"] for row in target.list_accounts()})
        self.assertEqual(result["row_counts"]["accounts"], 3)

    def test_restore_candidate_rejects_tampering_and_wrong_secret_purpose(self):
        model = self.legacy_model()
        self.database.apply_legacy_import(model)
        candidate = self.backup_candidate(self.database, model)
        truncated = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=b"X" + candidate.sqlite_snapshot[1:],
        )
        with self.assertRaises(RestoreValidationError):
            self.database.validate_restore_candidate(truncated)

        altered_path = Path(self.temporary_directory.name) / "wrong-purpose.db"
        altered_path.write_bytes(candidate.sqlite_snapshot)
        connection = sqlite3.connect(altered_path)
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            wrong_blob = self.database.secret_store.encrypt(
                b"management-secret", "setting:not-management-api-key"
            )
            connection.execute(
                "UPDATE settings SET value_blob = ? WHERE key = 'management_api_key'",
                (wrong_blob,),
            )
            connection.commit()
        finally:
            connection.close()
        wrong_purpose = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=altered_path.read_bytes(),
        )
        with self.assertRaises(RestoreValidationError):
            self.database.validate_restore_candidate(wrong_purpose)

    def test_restore_rejects_candidate_changed_after_validation_and_running_queue(self):
        source_path = Path(self.temporary_directory.name) / "source.db"
        source = Database(source_path, secret_store=TestSecretStore())
        model = self.legacy_model(with_state=False)
        source.apply_legacy_import(model)
        candidate = self.backup_candidate(source, model)

        validation = self.database.validate_restore_candidate(candidate)
        changed = VerifiedBackup(
            schema_version=candidate.schema_version,
            instance_id=candidate.instance_id,
            created_at=candidate.created_at,
            migration_id=candidate.migration_id,
            identity=candidate.identity,
            sources=(),
            sqlite_snapshot=candidate.sqlite_snapshot + b"changed",
        )
        self.database.set_queue_paused(True)
        with self.assertRaises(RestoreValidationError):
            self.database.restore_verified_backup(changed, validation)

        workspace, _, _ = self.create_workspace("restore-running")
        self.database.enqueue_workspace(workspace["id"])
        self.database.set_queue_paused(False)
        self.database.claim_next_queue_item()
        self.database.set_queue_paused(True)
        with self.assertRaises(StateConflictError):
            self.database.restore_verified_backup(candidate, validation)

    def test_v1_schema_upgrades_in_order_and_rolls_back_as_one_transaction(self):
        legacy_path = Path(self.temporary_directory.name) / "v1" / "console.db"
        legacy_path.parent.mkdir(parents=True)
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                "CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            for statement in database_module._SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO app_meta(key, value) VALUES(?, ?)",
                (("schema_version", "1"), ("instance_id", "legacy-instance")),
            )
            connection.commit()
        finally:
            connection.close()

        FailingSchemaUpgradeDatabase.fail_upgrade = True
        try:
            with self.assertRaisesRegex(RuntimeError, "injected schema upgrade failure"):
                FailingSchemaUpgradeDatabase(
                    legacy_path, secret_store=TestSecretStore()
                )
        finally:
            FailingSchemaUpgradeDatabase.fail_upgrade = False

        connection = sqlite3.connect(legacy_path)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM app_meta WHERE key = 'schema_version'"
                ).fetchone()[0],
                "1",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='mailbox_inventory'"
                ).fetchone()
            )
        finally:
            connection.close()

        upgraded = Database(legacy_path, secret_store=TestSecretStore())
        self.assertEqual(upgraded.diagnostics()["schema_version"], 3)
        self.assertEqual(upgraded.get_meta("instance_id"), "legacy-instance")
        upgraded.initialize()
        self.assertEqual(upgraded.diagnostics()["schema_version"], 3)

    def test_inventory_import_search_and_credentials_are_encrypted(self):
        records = [
            self.inventory_record(f"user{index:02d}@example.com", index)
            for index in range(25)
        ]
        records.append({"primary_email": "broken", "client_id": "x"})

        imported = self.database.import_mailbox_inventory(records)
        repeated = self.database.import_mailbox_inventory(
            [self.inventory_record("USER00@EXAMPLE.COM", 999)]
        )
        results = self.database.search_mailbox_inventory(
            query="user", status="available", limit=999
        )

        self.assertEqual(
            imported,
            {"total": 26, "imported": 25, "existing": 0, "invalid": 1},
        )
        self.assertEqual(repeated["existing"], 1)
        self.assertEqual(len(results), 20)
        self.assertNotIn("credential_blob", results[0])
        self.assertNotIn("refresh_token", results[0])
        first = self.database.get_mailbox_inventory(results[0]["id"])
        credentials = self.database.get_mailbox_inventory_credentials(first["id"])
        self.assertEqual(credentials["refresh_token"], "refresh-user00")
        self.assertEqual(
            self.database.get_mailbox_inventory_summary(),
            {"total": 25, "available": 25, "disabled": 0, "exhausted": 0},
        )
        with self.assertRaises(ValidationError):
            self.database.search_mailbox_inventory(status="unknown")
        for secret in ("mailbox-user00", "client-user00", "refresh-user00"):
            self.assert_secret_absent_from_database_files(secret)

    def test_alias_allocator_is_sequential_and_switches_inventory_after_plus_five(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("first@example.com", 1),
                self.inventory_record("second@example.com", 2),
            ]
        )
        inventories = self.database.search_mailbox_inventory(limit=20)
        first = next(row for row in inventories if row["primary_email"] == "first@example.com")

        allocated = [
            self.database.allocate_mailbox_alias(first["id"])["email"]
            for _ in range(5)
        ]
        switched = self.database.allocate_mailbox_alias()

        self.assertEqual(
            allocated,
            [f"first+{number}@example.com" for number in range(1, 6)],
        )
        self.assertEqual(switched["email"], "second+1@example.com")
        exhausted = self.database.get_mailbox_inventory(first["id"])
        self.assertEqual(exhausted["status"], "exhausted")
        self.assertEqual(exhausted["next_alias_number"], 6)
        with self.assertRaises(ConflictError):
            self.database.allocate_mailbox_alias(first["id"])

    def test_concurrent_alias_allocation_never_duplicates_or_moves_cursor_backwards(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("concurrent@example.com")]
        )
        inventory = self.database.search_mailbox_inventory(query="concurrent")[0]
        other = Database(self.path, secret_store=TestSecretStore())
        barrier = threading.Barrier(2)
        results = []
        failures = []

        def allocate(database):
            try:
                barrier.wait(timeout=2)
                results.append(database.allocate_mailbox_alias(inventory["id"])["email"])
            except BaseException as exc:
                failures.append(exc)

        threads = [
            threading.Thread(target=allocate, args=(database,))
            for database in (self.database, other)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(3)

        self.assertEqual(failures, [])
        self.assertEqual(set(results), {"concurrent+1@example.com", "concurrent+2@example.com"})
        self.assertEqual(
            self.database.get_mailbox_inventory(inventory["id"])["next_alias_number"],
            3,
        )

    def test_disabled_inventory_is_skipped_and_constraints_reject_plus_six(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("disabled@example.com", 0),
                self.inventory_record("active@example.com", 1),
            ]
        )
        inventory = self.database.search_mailbox_inventory(query="disabled")[0]
        self.database.set_mailbox_inventory_status(
            inventory["id"],
            "disabled",
            failure_code="mailbox_credentials_invalid",
            failure_message="safe message",
        )
        self.assertEqual(
            self.database.allocate_mailbox_alias()["email"],
            "active+1@example.com",
        )
        with self.assertRaises(ConflictError):
            with self.database._write_transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO mailbox_alias_allocations(
                        inventory_id, alias_number, account_id, state, created_at, updated_at
                    ) VALUES(?, 6, NULL, 'allocated', 'now', 'now')
                    """,
                    (inventory["id"],),
                )

    def test_workspace_inventory_selection_allocates_only_after_version_check(self):
        current = self.create_account("inventory-current")
        self.database.import_mailbox_inventory(
            [self.inventory_record("workspace-stock@example.com")]
        )
        inventory = self.database.search_mailbox_inventory(query="workspace-stock")[0]
        workspace = self.database.create_workspace(
            name="Inventory space",
            workspace_uid="inventory-space-uid",
            current_account_id=current["id"],
            next_inventory_id=inventory["id"],
        )
        next_account = self.database.get_account(workspace["next_account_id"])
        self.assertEqual(next_account["email"], "workspace-stock+1@example.com")
        before = len(self.database.list_accounts())

        with self.assertRaises(StaleVersionError):
            self.database.update_workspace_bindings(
                workspace["id"],
                current_account_id=current["id"],
                next_account_id=None,
                next_inventory_id=inventory["id"],
                expected_version=workspace["version"] - 1,
            )
        self.assertEqual(len(self.database.list_accounts()), before)

    def test_success_rotation_promotes_and_allocates_next_alias_atomically(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("rotate@example.com")]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Rotate",
            workspace_uid="rotate-uid",
            current_account_id=aliases[2]["id"],
            next_account_id=aliases[3]["id"],
        )
        run = self.database.enqueue_workspace(workspace["id"])
        self.database.claim_next_queue_item()

        self.database.complete_run_and_rotate(run["id"])
        rotated = self.database.get_workspace(workspace["id"])

        self.assertEqual(
            self.database.get_account(rotated["current_account_id"])["email"],
            "rotate+4@example.com",
        )
        self.assertEqual(
            self.database.get_account(rotated["next_account_id"])["email"],
            "rotate+5@example.com",
        )
        self.assertEqual(rotated["status"], "ready")
        self.assertEqual(self.database.get_account(aliases[2]["id"])["status"], "exited_pending")
        count = len(self.database.list_accounts())
        self.database.complete_run_and_rotate(run["id"])
        self.assertEqual(len(self.database.list_accounts()), count)

    def test_manual_workspace_advance_promotes_plus_five_and_switches_primary(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("first-primary@example.com", 0),
                self.inventory_record("second-primary@example.com", 1),
            ]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Manual rotation",
            workspace_uid="manual-rotation-uid",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )

        result = self.database.advance_workspace_accounts(
            workspace["id"], expected_version=workspace["version"]
        )
        advanced = result["workspace"]
        replacement = result["replacement"]

        self.assertEqual(
            self.database.get_account(advanced["current_account_id"])["email"],
            "first-primary+5@example.com",
        )
        self.assertEqual(replacement["email"], "second-primary+1@example.com")
        self.assertEqual(advanced["next_account_id"], replacement["id"])
        self.assertEqual(advanced["rotation_count"], 1)
        self.assertEqual(advanced["version"], 2)
        self.assertEqual(advanced["status"], "ready")
        self.assertEqual(
            self.database.get_account(aliases[3]["id"])["status"],
            "exited_pending",
        )
        allocation = next(
            row
            for row in self.database.list_mailbox_alias_allocations()
            if row["account_id"] == aliases[3]["id"]
        )
        self.assertEqual(allocation["state"], "retired")

        with self.assertRaises(StaleVersionError):
            self.database.advance_workspace_accounts(
                workspace["id"], expected_version=workspace["version"]
            )
        self.assertEqual(len(self.database.list_accounts()), 6)

    def test_manual_and_failed_run_replacement_share_atomic_rotation_rules(self):
        self.database.import_mailbox_inventory(
            [self.inventory_record("replace@example.com")]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(2)]
        workspace = self.database.create_workspace(
            name="Replace",
            workspace_uid="replace-uid",
            current_account_id=aliases[0]["id"],
            next_account_id=aliases[1]["id"],
        )

        manual = self.database.replace_workspace_account(
            workspace["id"],
            role="next",
            failure_code="alias_disabled",
            expected_version=workspace["version"],
        )
        self.assertEqual(
            self.database.get_account(manual["workspace"]["next_account_id"])["email"],
            "replace+3@example.com",
        )
        self.assertEqual(self.database.get_account(aliases[1]["id"])["status"], "disabled")

        active_workspace = manual["workspace"]
        subsequent_workspace, _, _ = self.create_workspace("after-identity-failure")
        runs = self.database.enqueue_workspaces(
            [active_workspace["id"], subsequent_workspace["id"]]
        )
        run = runs[0]
        queued_workspace = self.database.get_workspace(active_workspace["id"])
        with self.assertRaises(WorkspaceActiveError):
            self.database.replace_workspace_account(
                active_workspace["id"],
                role="next",
                failure_code="alias_disabled",
                expected_version=queued_workspace["version"],
            )
        self.database.claim_next_queue_item()
        automated = self.database.fail_run_and_replace_account(
            run["id"],
            role="current",
            failure_code="mailbox_credentials_invalid",
            redacted_error="mailbox credentials rejected",
        )

        self.assertEqual(automated["run"]["state"], "failed")
        self.assertEqual(automated["workspace"]["status"], "needs_account")
        self.assertEqual(
            automated["workspace"]["current_account_id"],
            active_workspace["current_account_id"],
        )
        self.assertIsNone(automated["workspace"]["next_account_id"])
        self.assertIsNone(automated["replacement"])
        self.assertEqual(
            self.database.claim_next_queue_item()["run_id"], runs[1]["id"]
        )
        inventory = self.database.search_mailbox_inventory(query="replace")[0]
        self.assertEqual(inventory["status"], "disabled")

    def test_backfill_inventory_repairs_legacy_rotation_once(self):
        records = [
            self.inventory_record("main@example.com", 0),
            self.inventory_record("other@example.com", 1),
        ]
        primary = self.database.create_account(
            email="main@example.com",
            primary_email="main@example.com",
            credentials={"refresh_token": "legacy-primary"},
            source="legacy_txt",
        )
        self.database.transition_account_status(primary["id"], "disabled")
        manual = self.database.create_account(
            email="manual-disabled@example.com",
            primary_email="manual-disabled@example.com",
            credentials={"refresh_token": "manual"},
            source="txt_import",
        )
        self.database.transition_account_status(manual["id"], "disabled")
        aliases = {}
        for number in (3, 4, 5):
            aliases[number] = self.database.create_account(
                email=f"main+{number}@example.com",
                primary_email="main@example.com",
                credentials={"refresh_token": f"legacy-{number}"},
                source="legacy_txt",
            )
        workspace = self.database.create_workspace(
            name="Legacy",
            workspace_uid="legacy-backfill-uid",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )

        first = self.database.backfill_mailbox_inventory(
            records,
            migration_id="a" * 64,
            expected_count=2,
            legacy_old_email="main+3@example.com",
            legacy_new_email="main+4@example.com",
        )
        second = self.database.backfill_mailbox_inventory(
            records,
            migration_id="a" * 64,
            expected_count=2,
            legacy_old_email="main+3@example.com",
            legacy_new_email="main+4@example.com",
        )

        repaired = self.database.get_workspace(workspace["id"])
        self.assertEqual(first["repair_status"], "repaired")
        self.assertEqual(second["repair_status"], "already_completed")
        self.assertEqual(first["marker"], "1")
        self.assertEqual(repaired["current_account_id"], aliases[4]["id"])
        self.assertEqual(repaired["next_account_id"], aliases[5]["id"])
        self.assertEqual(repaired["rotation_count"], 1)
        self.assertEqual(repaired["version"], 2)
        self.assertEqual(self.database.get_account(aliases[3]["id"])["status"], "exited_pending")
        self.assertNotIn(primary["id"], {row["id"] for row in self.database.list_accounts()})
        self.assertIn(manual["id"], {row["id"] for row in self.database.list_accounts()})
        inventory = self.database.search_mailbox_inventory(query="main")[0]
        self.assertEqual(inventory["next_alias_number"], 6)
        self.assertEqual(inventory["status"], "exhausted")

    def test_backfill_handles_full_inventory_scale_without_creating_accounts(self):
        records = [
            self.inventory_record(f"bulk{index:05d}@example.com", index)
            for index in range(7_211)
        ]

        result = self.database.backfill_mailbox_inventory(
            records,
            migration_id="c" * 64,
            expected_count=7_211,
        )

        self.assertEqual(result["counts"]["inventory_total"], 7_211)
        self.assertEqual(result["counts"]["imported"], 7_211)
        self.assertEqual(self.database.list_accounts(), [])
        self.assertEqual(self.database.get_mailbox_inventory_summary()["total"], 7_211)
        self.assertEqual(len(self.database.search_mailbox_inventory(query="bulk", limit=100)), 20)
        self.assert_secret_absent_from_database_files("refresh-bulk07210")

    def test_v1_snapshot_validates_and_restores_with_v2_upgrade(self):
        source_path = Path(self.temporary_directory.name) / "snapshot-v1.db"
        connection = sqlite3.connect(source_path)
        try:
            connection.execute(
                "CREATE TABLE app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            for statement in database_module._SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO app_meta(key, value) VALUES(?, ?)",
                (
                    ("schema_version", "1"),
                    ("instance_id", "snapshot-v1-instance"),
                    ("migration_id", "b" * 64),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        candidate = VerifiedBackup(
            schema_version=1,
            instance_id="snapshot-v1-instance",
            created_at="2026-07-13T00:00:00Z",
            migration_id="b" * 64,
            identity={
                "workspace_id": "legacy",
                "old_email": "old@example.com",
                "new_email": "new@example.com",
            },
            sources=(),
            sqlite_snapshot=source_path.read_bytes(),
        )

        validation = self.database.validate_restore_candidate(candidate)
        self.database.set_queue_paused(True)
        restored = self.database.restore_verified_backup(candidate, validation)

        self.assertEqual(validation.schema_version, 1)
        self.assertEqual(restored["schema_version"], 3)
        self.assertEqual(self.database.get_meta("instance_id"), "snapshot-v1-instance")
        self.assertEqual(self.database.diagnostics()["schema_version"], 3)


if __name__ == "__main__":
    unittest.main()
