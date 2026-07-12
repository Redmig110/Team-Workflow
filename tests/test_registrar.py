import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from team_protocol.registrar import (
    MailboxCredentials,
    RegistrarAdapter,
    RegistrarIdentityError,
    RegistrarProxyLease,
    primary_email_for_alias,
)
from team_protocol.registrar_runtime.appleemail_provider import (
    AppleEmailHotmailProvider,
    AppleEmailMailbox,
    MailboxCredentialsInvalidError,
    _is_explicit_mailbox_auth_rejection,
)


class FakeSessionProfile:
    def __init__(self, profile_id, impersonate="chrome131"):
        self.profile_id = profile_id
        self.impersonate = impersonate

    def validate(self):
        return self

    def to_legacy_dict(self):
        return {
            "profile_id": self.profile_id,
            "impersonate": self.impersonate,
        }


class RegistrarTests(unittest.TestCase):
    @staticmethod
    def _adapter_for_login(result_or_error):
        adapter = RegistrarAdapter.__new__(RegistrarAdapter)
        adapter.state_dir = Path(".").resolve()
        adapter._provider_class = lambda **_kwargs: object()
        adapter._event_emitter = lambda **_kwargs: SimpleNamespace()
        adapter._register_module = SimpleNamespace(
            _try_extract_chatgpt_session_token=lambda **_kwargs: None,
        )
        adapter._mailbox_identity_error_class = MailboxCredentialsInvalidError

        def fake_login(**_kwargs):
            if isinstance(result_or_error, BaseException):
                raise result_or_error
            return result_or_error

        adapter._login = fake_login
        return adapter

    @staticmethod
    def _mailbox():
        return MailboxCredentials(
            primary_email="main@example.com",
            registration_email="main+1@example.com",
            client_id="client-id",
            refresh_token="refresh-token",
        )

    def test_primary_email_for_alias(self):
        self.assertEqual(
            primary_email_for_alias("ExampleUser+3@Example.com"),
            "exampleuser@example.com",
        )

    def test_proxy_lease_expands_the_workflow_proxy_template(self):
        with RegistrarProxyLease(
            explicit_proxy="http://user:pass@proxy-{worker}-{rand}.example:9000",
            index=7,
        ) as lease:
            self.assertRegex(
                lease.proxy or "",
                r"^http://user:pass@proxy-7-[0-9a-f]{8}\.example:9000$",
            )
            self.assertEqual(lease.source, "workflow")
            self.assertNotIn("pass", lease.description)

    def test_proxy_lease_uses_direct_connection_when_proxy_is_empty(self):
        with RegistrarProxyLease() as lease:
            self.assertIsNone(lease.proxy)
            self.assertEqual(lease.source, "direct")

    def test_adapter_loads_the_bundled_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            adapter = RegistrarAdapter(state_dir=directory)
            profile = adapter.resolve_session_profile()
            serialized = adapter.serialize_session_profile(profile)
            restored = adapter.resolve_session_profile(serialized)

        self.assertEqual(
            adapter._register_module.__name__,
            "team_protocol.registrar_runtime.register",
        )
        self.assertEqual(
            adapter._provider_class.__module__,
            "team_protocol.registrar_runtime.appleemail_provider",
        )
        self.assertEqual(
            adapter._session_profile_class.__module__,
            "team_protocol.registrar_runtime.fingerprint_profiles",
        )
        self.assertEqual(restored.profile_id, profile.profile_id)
        self.assertEqual(restored.impersonate, profile.impersonate)

    def test_offline_cli_import_does_not_load_registrar_network_dependencies(self):
        script = """
import builtins
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name.split('.', 1)[0] in {'curl_cffi', 'requests', 'playwright'}:
        raise RuntimeError(f'unexpected network dependency import: {name}')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
import team_protocol.cli
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_session_profile_can_be_serialized_and_restored(self):
        adapter = RegistrarAdapter.__new__(RegistrarAdapter)
        adapter._session_profile_class = FakeSessionProfile
        adapter._create_session_profile = lambda **_kwargs: FakeSessionProfile("generated")

        generated = adapter.resolve_session_profile()
        serialized = adapter.serialize_session_profile(generated)
        restored = adapter.resolve_session_profile(serialized)

        self.assertEqual(generated.profile_id, "generated")
        self.assertEqual(serialized["profile_id"], "generated")
        self.assertEqual(restored.profile_id, generated.profile_id)
        self.assertEqual(restored.impersonate, generated.impersonate)

    def test_login_forwards_the_supplied_session_profile(self):
        captured = {}
        adapter = RegistrarAdapter.__new__(RegistrarAdapter)
        adapter.state_dir = Path(".").resolve()
        adapter._provider_class = lambda **_kwargs: object()
        adapter._event_emitter = lambda **_kwargs: SimpleNamespace()
        adapter._register_module = SimpleNamespace(
            _try_extract_chatgpt_session_token=lambda **_kwargs: None,
        )

        def fake_login(**kwargs):
            captured.update(kwargs)
            return {"ok": True, "token_data": {"access_token": "token"}}

        adapter._login = fake_login
        profile = FakeSessionProfile("shared")
        mailbox = MailboxCredentials(
            primary_email="main@example.com",
            registration_email="main+1@example.com",
            client_id="client-id",
            refresh_token="refresh-token",
        )

        adapter.login(
            email="main+1@example.com",
            account_password="",
            mailbox=mailbox,
            session_profile=profile,
            verbose=False,
        )

        self.assertIs(captured["session_profile"], profile)

    def test_adapter_maps_only_structured_identity_failures(self):
        fatal_adapter = self._adapter_for_login(
            {
                "ok": False,
                "error": "account unavailable",
                "fatal_deactivated": True,
                "identity_error_code": "alias_disabled",
            }
        )
        with self.assertRaises(RegistrarIdentityError) as fatal:
            fatal_adapter.login(
                email="main+1@example.com",
                account_password="",
                mailbox=self._mailbox(),
                verbose=False,
            )
        self.assertEqual(fatal.exception.code, "alias_disabled")

        mailbox_adapter = self._adapter_for_login(
            MailboxCredentialsInvalidError("provider rejected refresh credentials")
        )
        with self.assertRaises(RegistrarIdentityError) as mailbox:
            mailbox_adapter.login(
                email="main+1@example.com",
                account_password="",
                mailbox=self._mailbox(),
                verbose=False,
            )
        self.assertEqual(mailbox.exception.code, "mailbox_credentials_invalid")

        transient = self._adapter_for_login(RuntimeError("temporary timeout"))
        with self.assertRaisesRegex(RuntimeError, "temporary timeout"):
            transient.login(
                email="main+1@example.com",
                account_password="",
                mailbox=self._mailbox(),
                verbose=False,
            )

    def test_mailbox_auth_rejection_requires_known_error_code(self):
        explicit = SimpleNamespace(
            status_code=401,
            text='{"error":"invalid_grant","error_description":"token revoked"}',
        )
        bare_unauthorized = SimpleNamespace(status_code=401, text="Unauthorized")
        rate_limited = SimpleNamespace(
            status_code=429,
            text='{"error":"invalid_grant"}',
        )
        server_error = SimpleNamespace(
            status_code=503,
            text='{"error":"invalid_grant"}',
        )

        self.assertTrue(_is_explicit_mailbox_auth_rejection(explicit))
        self.assertFalse(_is_explicit_mailbox_auth_rejection(bare_unauthorized))
        self.assertFalse(_is_explicit_mailbox_auth_rejection(rate_limited))
        self.assertFalse(_is_explicit_mailbox_auth_rejection(server_error))

    def test_provider_propagates_only_explicit_mailbox_auth_rejection(self):
        provider = AppleEmailHotmailProvider(accounts=[])
        mailbox = AppleEmailMailbox(
            primary_email="main@example.com",
            registration_email="main+1@example.com",
            client_id="client-id",
            refresh_token="refresh-token",
        )
        explicit = SimpleNamespace(
            status_code=400,
            text='{"error":"invalid_grant"}',
            raise_for_status=lambda: None,
        )
        with patch(
            "team_protocol.registrar_runtime.appleemail_provider.requests.post",
            return_value=explicit,
        ):
            with self.assertRaises(MailboxCredentialsInvalidError):
                provider._fetch_messages(mailbox, "INBOX")

    def test_provider_can_publish_detached_state_without_writing_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "appleemail_state.json"
            snapshots = []
            provider = AppleEmailHotmailProvider(
                accounts=[],
                initial_state={
                    "version": 1,
                    "completed_aliases": {},
                    "ignored_secret": "must-not-be-published",
                },
                state_callback=snapshots.append,
            )

            self.assertTrue(
                provider.mark_email_completed(
                    email="main+1@example.com",
                    status="success",
                )
            )
            snapshot = provider.snapshot_state()
            snapshot["completed_aliases"].clear()

            self.assertFalse(state_path.exists())
            self.assertNotIn("ignored_secret", snapshots[-1])
            self.assertIn("main+1@example.com", snapshots[-1]["completed_aliases"])
            self.assertIn(
                "main+1@example.com",
                provider.snapshot_state()["completed_aliases"],
            )

    def test_adapter_provider_checkpoint_mode_does_not_create_registrar_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter = RegistrarAdapter.__new__(RegistrarAdapter)
            adapter.state_dir = root / ".registrar"
            adapter._provider_class = AppleEmailHotmailProvider
            adapter._event_emitter = lambda **_kwargs: SimpleNamespace()
            adapter._register_module = SimpleNamespace(
                _try_extract_chatgpt_session_token=lambda **_kwargs: None,
            )
            snapshots = []

            def fake_login(**kwargs):
                provider = kwargs["mail_provider"]
                provider.mark_email_completed(
                    auth_credential=kwargs["mail_auth_credential"],
                    email=kwargs["email"],
                )
                return {"ok": True, "token_data": {"access_token": "token"}}

            adapter._login = fake_login
            mailbox = MailboxCredentials(
                primary_email="main@example.com",
                registration_email="main+1@example.com",
                client_id="client-id",
                refresh_token="refresh-token",
            )
            before = list(root.rglob("*"))

            result = adapter.login(
                email=mailbox.registration_email,
                account_password="",
                mailbox=mailbox,
                provider_initial_state={},
                provider_state_callback=snapshots.append,
                verbose=False,
            )

            self.assertEqual(result, {"access_token": "token"})
            self.assertEqual(before, list(root.rglob("*")))
            self.assertIn(
                mailbox.registration_email,
                snapshots[-1]["completed_aliases"],
            )


if __name__ == "__main__":
    unittest.main()
