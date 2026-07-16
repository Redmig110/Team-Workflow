from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from team_protocol.migration import (
    MigrationBackupError,
    MigrationValidationError,
    apply_import,
    cleanup_plaintext,
    create_backup,
    discover_legacy,
    legacy_state_filename,
    mailbox_inventory_records_from_backup,
    parse_mailbox_inventory_import,
    parse_legacy_mailboxes,
    restore_backup,
    validate_legacy,
    verify_backup,
)
from team_protocol.secret_store import SecretStore


class AuthenticatedMemoryBackend:
    @staticmethod
    def _key(entropy: bytes) -> bytes:
        return hashlib.sha256(b"test-key\x00" + entropy).digest()

    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        key = self._key(entropy)
        ciphertext = bytes(
            value ^ key[index % len(key)] for index, value in enumerate(plaintext)
        )
        tag = hashlib.sha256(entropy + ciphertext).digest()
        return tag + ciphertext

    def unprotect(self, ciphertext: bytes, entropy: bytes) -> bytes:
        tag, body = ciphertext[:32], ciphertext[32:]
        if tag != hashlib.sha256(entropy + body).digest():
            raise OSError("authentication failed")
        key = self._key(entropy)
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(body))


class FailingBackend:
    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        del plaintext, entropy
        raise OSError("injected failure")

    def unprotect(self, ciphertext: bytes, entropy: bytes) -> bytes:
        del ciphertext, entropy
        raise OSError("injected failure")


class MigrationFixture:
    def __init__(self, root: Path, *, explicit_external_state: bool = False):
        self.root = root
        self.config_path = root / "workflow.json"
        self.mail_path = root / "hotmail.txt"
        self.output_dir = root / "output"
        self.workspace_id = "workspace-123"
        self.old_email = "main+3@example.com"
        self.new_email = "main+4@example.com"
        self.state_path = (
            root / "external-state.json"
            if explicit_external_state
            else self.output_dir
            / ".state"
            / legacy_state_filename(
                self.old_email,
                self.new_email,
                self.workspace_id,
            )
        )
        self.mail_path.write_text(
            "main@example.com----mail-pass----client-main----refresh-main\n"
            "other@example.com----client-other----refresh-other\n",
            encoding="utf-8",
        )
        payload = {
            "mail_account_file": "hotmail.txt",
            "workspace_id": self.workspace_id,
            "old_account": {"email": "Main+3@Example.com", "password": "old-pass"},
            "new_account": {"email": self.new_email, "password": ""},
            "proxy": "socks5h://user:proxy-secret@proxy.invalid:9000",
            "invite_settle_seconds": 3.5,
            "pat": {"name": "migration-pat", "ttl": 3600},
            "output_dir": "output",
            "management": {
                "base_url": "https://management.invalid",
                "api_key": "${CPA_KEY}",
                "push": False,
                "replace": True,
                "remote_name": "remote.json",
            },
            "sub2api": {
                "base_url": "https://sub2api.invalid",
                "email": "admin@example.com",
                "password": "%SUB2_PASSWORD%",
                "api_key": "%SUB2_API_KEY%",
                "totp_secret": "%SUB2_TOTP_SECRET%",
                "push": True,
                "concurrency": 30,
                "priority": 2,
            },
        }
        if explicit_external_state:
            payload["state_path"] = "external-state.json"
        self.config_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "steps": {
                        "invite": {"action": "invited"},
                        "complete": {
                            "old_email": self.old_email,
                            "new_email": self.new_email,
                            "workspace_id": self.workspace_id,
                            "state_path": str(self.state_path.resolve()),
                        },
                    },
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def model(self):
        discovery = discover_legacy(
            self.config_path,
            env={
                "CPA_KEY": "management-secret",
                "SUB2_PASSWORD": "sub2-secret",
                "SUB2_API_KEY": "sub2-api-key",
                "SUB2_TOTP_SECRET": "sub2-totp-secret",
            },
        )
        return discovery, validate_legacy(discovery)


class MigrationParsingTests(unittest.TestCase):
    def test_inventory_import_parser_keeps_valid_rows_and_counts_invalid_rows(self):
        valid, invalid = parse_mailbox_inventory_import(
            "\n".join(
                (
                    "first@example.com----mail-one----client-one----refresh-one",
                    "broken-row",
                    "alias+1@example.com----mail----client----refresh",
                    "second@example.com----client-two----refresh-two",
                )
            )
        )

        self.assertEqual(invalid, 2)
        self.assertEqual(
            valid,
            (
                {
                    "primary_email": "first@example.com",
                    "password": "mail-one",
                    "client_id": "client-one",
                    "refresh_token": "refresh-one",
                    "source_order": 0,
                },
                {
                    "primary_email": "second@example.com",
                    "password": "",
                    "client_id": "client-two",
                    "refresh_token": "refresh-two",
                    "source_order": 3,
                },
            ),
        )
        with self.assertRaises(MigrationValidationError):
            parse_mailbox_inventory_import("bad\nalso-bad")

    def test_discovers_and_validates_frozen_legacy_format(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            discovery, model = fixture.model()

        self.assertEqual(
            [source.role for source in discovery.sources],
            ["workflow_config", "mail_accounts", "workflow_state"],
        )
        self.assertEqual(
            [source.ownership for source in discovery.sources],
            ["app_owned", "external", "app_owned"],
        )
        for item in discovery.manifest:
            self.assertEqual(len(item["sha256"]), 64)
            self.assertGreater(item["size"], 0)
            self.assertTrue(Path(item["path"]).is_absolute())
        self.assertEqual(len(model.mailboxes), 2)
        self.assertEqual(model.old_binding.registration_email, fixture.old_email)
        self.assertEqual(model.old_binding.primary_email, "main@example.com")
        self.assertEqual(model.old_binding.account_password, "old-pass")
        self.assertEqual(model.new_binding.registration_email, fixture.new_email)
        self.assertEqual(model.new_binding.account_password, "mail-pass")
        self.assertEqual(model.config.proxy, "socks5h://user:proxy-secret@proxy.invalid:9000")
        self.assertEqual(model.config.pat_name, "migration-pat")
        self.assertEqual(model.config.pat_ttl, 3600)
        self.assertEqual(model.config.management.api_key, "management-secret")
        self.assertFalse(model.config.management.push)
        self.assertTrue(model.config.management.replace)
        self.assertEqual(model.config.sub2api.password, "sub2-secret")
        self.assertEqual(model.config.sub2api.api_key, "sub2-api-key")
        self.assertEqual(model.config.sub2api.totp_secret, "sub2-totp-secret")
        self.assertTrue(model.config.sub2api.push)
        self.assertEqual(model.config.sub2api.concurrency, 30)
        self.assertRegex(model.migration_id, r"^[0-9a-f]{64}$")

    def test_parses_three_and_four_part_rows_and_preserves_secrets(self):
        rows = parse_legacy_mailboxes(
            "three@example.com----client-three----refresh-three\n"
            "four@example.com----password-four----client-four----refresh-four\n"
        )

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].password, "")
        self.assertEqual(rows[0].client_id, "client-three")
        self.assertEqual(rows[1].password, "password-four")
        self.assertEqual(rows[1].refresh_token, "refresh-four")

    def test_flat_aliases_are_supported_but_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            mail = root / "mail.txt"
            mail.write_text(
                "main@example.com----client----refresh\n",
                encoding="utf-8",
            )
            flat = root / "flat.json"
            flat.write_text(
                json.dumps(
                    {
                        "mail_account_file": "mail.txt",
                        "workspace_id": "space",
                        "old_email": "main+1@example.com",
                        "new_email": "main+2@example.com",
                    }
                ),
                encoding="utf-8",
            )
            flat_model = validate_legacy(discover_legacy(flat, env={}))
            self.assertEqual(flat_model.old_binding.registration_email, "main+1@example.com")

            conflicting = root / "conflicting.json"
            conflicting.write_text(
                json.dumps(
                    {
                        "mail_account_file": "mail.txt",
                        "workspace_id": "space",
                        "old_account": {"email": "main+1@example.com"},
                        "old_email": "main+9@example.com",
                        "new_email": "main+2@example.com",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MigrationValidationError, "conflicting"):
                discover_legacy(conflicting, env={})

    def test_state_identity_mismatch_is_rejected_without_modifying_sources(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            before = {
                path: path.read_bytes()
                for path in (fixture.config_path, fixture.mail_path, fixture.state_path)
            }
            state = json.loads(fixture.state_path.read_text(encoding="utf-8"))
            state["steps"]["complete"]["workspace_id"] = "wrong-space"
            fixture.state_path.write_text(json.dumps(state), encoding="utf-8")
            before[fixture.state_path] = fixture.state_path.read_bytes()

            discovery = discover_legacy(fixture.config_path, env={})
            with self.assertRaisesRegex(MigrationValidationError, "workspace_id"):
                validate_legacy(discovery)

            self.assertEqual(
                {path: path.read_bytes() for path in before},
                before,
            )

    def test_parse_failure_and_discovery_change_leave_sources_untouched(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            discovery = discover_legacy(fixture.config_path, env={})
            fixture.mail_path.write_text("not-a-valid-row\n", encoding="utf-8")
            current = fixture.mail_path.read_bytes()

            with self.assertRaisesRegex(MigrationValidationError, "changed after discovery"):
                validate_legacy(discovery)
            self.assertEqual(fixture.mail_path.read_bytes(), current)

    def test_external_explicit_state_is_validated_but_not_owned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir), explicit_external_state=True)
            discovery, _ = fixture.model()

        state_source = next(
            source for source in discovery.sources if source.role == "workflow_state"
        )
        self.assertEqual(state_source.ownership, "external")

    def test_custom_state_inside_state_directory_is_preserved_as_external(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root)
            custom_state = fixture.output_dir / ".state" / "custom.json"
            custom_state.write_bytes(fixture.state_path.read_bytes())
            fixture.state_path.unlink()
            payload = json.loads(fixture.config_path.read_text(encoding="utf-8"))
            payload["state_path"] = "output/.state/custom.json"
            fixture.config_path.write_text(json.dumps(payload), encoding="utf-8")
            state = json.loads(custom_state.read_text(encoding="utf-8"))
            state["steps"]["complete"]["state_path"] = str(custom_state.resolve())
            custom_state.write_text(json.dumps(state), encoding="utf-8")

            discovery = discover_legacy(fixture.config_path, env={})
            validate_legacy(discovery)

        state_source = next(
            source for source in discovery.sources if source.role == "workflow_state"
        )
        self.assertEqual(state_source.path, custom_state.resolve())
        self.assertEqual(state_source.ownership, "external")

    def test_custom_state_without_identity_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root, explicit_external_state=True)
            fixture.state_path.write_text(
                json.dumps({"version": 1, "steps": {"pat": {"name": "old"}}}),
                encoding="utf-8",
            )

            discovery = discover_legacy(fixture.config_path, env={})
            with self.assertRaisesRegex(MigrationValidationError, "does not prove"):
                validate_legacy(discovery)


class MigrationBackupTests(unittest.TestCase):
    def setUp(self):
        self.store = SecretStore(_backend=AuthenticatedMemoryBackend())

    def test_encrypted_backup_roundtrip_and_hash_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            backup_path = Path(temp_dir) / "backups" / "migration.twbackup"
            snapshot = b"SQLite format 3\x00database-snapshot"

            created = create_backup(
                model,
                backup_path,
                self.store,
                schema_version=3,
                instance_id="instance-1",
                sqlite_snapshot=snapshot,
                created_at="2026-07-12T12:00:00Z",
            )
            verified = verify_backup(backup_path, self.store)
            inventory_records = mailbox_inventory_records_from_backup(verified)
            encrypted_bytes = backup_path.read_bytes()

        self.assertEqual(created.payload_sha256, verified.payload_sha256)
        self.assertEqual(verified.schema_version, 3)
        self.assertEqual(verified.instance_id, "instance-1")
        self.assertEqual(verified.migration_id, model.migration_id)
        self.assertEqual(verified.sqlite_snapshot, snapshot)
        self.assertEqual(len(verified.sources), 3)
        self.assertEqual(len(inventory_records), 2)
        self.assertEqual(inventory_records[0]["primary_email"], "main@example.com")
        self.assertEqual(inventory_records[0]["source_order"], 0)
        for secret in (
            b"management-secret",
            b"sub2-secret",
            b"refresh-main",
            b"database-snapshot",
        ):
            self.assertNotIn(secret, encrypted_bytes)

    def test_tampered_backup_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            backup_path = Path(temp_dir) / "migration.twbackup"
            create_backup(
                model,
                backup_path,
                self.store,
                schema_version=1,
                instance_id="instance-1",
            )
            payload = bytearray(backup_path.read_bytes())
            payload[-1] ^= 0x01
            backup_path.write_bytes(bytes(payload))

            with self.assertRaises(MigrationBackupError):
                verify_backup(backup_path, self.store)

    def test_dpapi_failure_does_not_create_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            backup_path = Path(temp_dir) / "migration.twbackup"
            failing_store = SecretStore(_backend=FailingBackend())

            with self.assertRaisesRegex(MigrationBackupError, "creation failed"):
                create_backup(
                    model,
                    backup_path,
                    failing_store,
                    schema_version=1,
                    instance_id="instance-1",
                )
            self.assertFalse(backup_path.exists())
            self.assertTrue(fixture.config_path.exists())
            self.assertTrue(fixture.mail_path.exists())
            self.assertTrue(fixture.state_path.exists())

    def test_restore_repository_is_validated_before_apply(self):
        class Repository:
            def __init__(self):
                self.calls = []

            def validate_restore_candidate(self, candidate):
                self.calls.append(("validate", candidate.sqlite_snapshot))
                return {"rows": 4}

            def restore_verified_backup(self, candidate, validation):
                self.calls.append(("restore", candidate.sqlite_snapshot, validation))
                return "restored"

        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            backup_path = Path(temp_dir) / "migration.twbackup"
            create_backup(
                model,
                backup_path,
                self.store,
                schema_version=1,
                instance_id="instance-1",
                sqlite_snapshot=b"snapshot",
            )
            repository = Repository()
            result = restore_backup(backup_path, self.store, repository)

        self.assertEqual(result, "restored")
        self.assertEqual(
            repository.calls,
            [
                ("validate", b"snapshot"),
                ("restore", b"snapshot", {"rows": 4}),
            ],
        )


class MigrationApplyAndCleanupTests(unittest.TestCase):
    def setUp(self):
        self.store = SecretStore(_backend=AuthenticatedMemoryBackend())

    def _backup(self, model, root: Path):
        path = root / "migration.twbackup"
        return create_backup(
            model,
            path,
            self.store,
            schema_version=1,
            instance_id="instance-1",
        )

    def test_apply_import_has_an_idempotent_repository_boundary(self):
        class Repository:
            def __init__(self):
                self.imported = {}

            def apply_legacy_import(self, model):
                return self.imported.setdefault(
                    model.migration_id,
                    {"migration_id": model.migration_id, "accounts": len(model.mailboxes)},
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            repository = Repository()
            first = apply_import(model, repository)
            second = apply_import(model, repository)

        self.assertIs(first, second)
        self.assertEqual(first["accounts"], 2)
        self.assertEqual(len(repository.imported), 1)

    def test_apply_failure_leaves_every_source_untouched(self):
        class FailingRepository:
            def apply_legacy_import(self, model):
                del model
                raise RuntimeError("injected rollback")

        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = MigrationFixture(Path(temp_dir))
            _, model = fixture.model()
            before = {source.record.path: source.content for source in model.sources}

            with self.assertRaisesRegex(RuntimeError, "injected rollback"):
                apply_import(model, FailingRepository())

            self.assertEqual(
                {path: path.read_bytes() for path in before},
                before,
            )

    def test_cleanup_removes_only_verified_app_owned_json_and_never_txt(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root)
            _, model = fixture.model()
            verified = self._backup(model, root)

            result = cleanup_plaintext(model, verified)

            self.assertEqual(result.status, "cleanup_complete")
            self.assertFalse(fixture.config_path.exists())
            self.assertFalse(fixture.state_path.exists())
            self.assertTrue(fixture.mail_path.exists())
            self.assertEqual(result.preserved, (fixture.mail_path.resolve(),))

    def test_cleanup_failure_returns_blocked_and_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root)
            _, model = fixture.model()
            verified = self._backup(model, root)

            def fail_for_state(path: Path) -> None:
                if path == fixture.state_path.resolve():
                    raise OSError("injected lock")
                path.unlink()

            first = cleanup_plaintext(model, verified, remove_file=fail_for_state)
            self.assertEqual(first.status, "cleanup_blocked")
            self.assertEqual(first.failures[0].code, "remove_failed")
            self.assertFalse(fixture.config_path.exists())
            self.assertTrue(fixture.state_path.exists())
            self.assertTrue(fixture.mail_path.exists())

            second = cleanup_plaintext(model, verified)
            self.assertEqual(second.status, "cleanup_complete")
            self.assertIn(fixture.config_path.resolve(), second.missing)
            self.assertFalse(fixture.state_path.exists())
            self.assertTrue(fixture.mail_path.exists())

    def test_cleanup_refuses_changed_plaintext(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root)
            _, model = fixture.model()
            verified = self._backup(model, root)
            fixture.config_path.write_text("{}", encoding="utf-8")

            result = cleanup_plaintext(model, verified)

            self.assertEqual(result.status, "cleanup_blocked")
            self.assertEqual(result.failures[0].code, "source_changed")
            self.assertTrue(fixture.config_path.exists())
            self.assertTrue(fixture.mail_path.exists())

    def test_external_state_and_txt_are_always_preserved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = MigrationFixture(root, explicit_external_state=True)
            _, model = fixture.model()
            verified = self._backup(model, root)

            result = cleanup_plaintext(model, verified)

            self.assertEqual(result.status, "cleanup_complete")
            self.assertFalse(fixture.config_path.exists())
            self.assertTrue(fixture.mail_path.exists())
            self.assertTrue(fixture.state_path.exists())
            self.assertIn(fixture.mail_path.resolve(), result.preserved)
            self.assertIn(fixture.state_path.resolve(), result.preserved)


if __name__ == "__main__":
    unittest.main()
