import os
import unittest
from unittest import mock

from team_protocol import secret_store
from team_protocol.secret_store import SecretStore, SecretStoreError


class _FailingBackend:
    def __init__(self, leaked_value: bytes):
        self.leaked_value = leaked_value

    def protect(self, _plaintext: bytes, _entropy: bytes) -> bytes:
        raise OSError(f"native failure for {self.leaked_value!r}")

    def unprotect(self, _ciphertext: bytes, _entropy: bytes) -> bytes:
        raise OSError(f"native failure for {self.leaked_value!r}")


@unittest.skipUnless(os.name == "nt", "Windows DPAPI is required")
class WindowsSecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = SecretStore()

    def test_roundtrip(self):
        plaintext = b"roundtrip-secret-4fbffcb0e250"
        ciphertext = self.store.encrypt(plaintext, "account.credentials")

        self.assertEqual(
            self.store.decrypt(ciphertext, "account.credentials"),
            plaintext,
        )
        self.assertNotEqual(ciphertext, plaintext)

    def test_roundtrip_empty_and_binary_payloads(self):
        payloads = (
            b"",
            bytes(range(256)),
            b"\x00\xff\x80binary\x00payload",
        )
        for payload in payloads:
            with self.subTest(payload_size=len(payload)):
                ciphertext = self.store.encrypt(payload, "checkpoint")
                self.assertEqual(
                    self.store.decrypt(ciphertext, "checkpoint"),
                    payload,
                )

    def test_purpose_mismatch_is_rejected(self):
        ciphertext = self.store.encrypt(b"purpose-bound", "account.credentials")

        with self.assertRaisesRegex(
            SecretStoreError,
            r"^Secret decryption failed\.$",
        ):
            self.store.decrypt(ciphertext, "checkpoint")

    def test_tampered_ciphertext_is_rejected(self):
        ciphertext = bytearray(self.store.encrypt(b"tamper-canary", "proxy"))
        ciphertext[-1] ^= 0x01

        with self.assertRaisesRegex(
            SecretStoreError,
            r"^Secret decryption failed\.$",
        ):
            self.store.decrypt(bytes(ciphertext), "proxy")

    def test_unsupported_envelope_version_is_rejected_before_dpapi(self):
        ciphertext = bytearray(self.store.encrypt(b"version-canary", "settings"))
        ciphertext[len(secret_store._MAGIC)] = secret_store._VERSION + 1

        with mock.patch.object(
            self.store._backend,
            "unprotect",
            wraps=self.store._backend.unprotect,
        ) as unprotect:
            with self.assertRaisesRegex(
                SecretStoreError,
                r"^Secret decryption failed\.$",
            ):
                self.store.decrypt(bytes(ciphertext), "settings")

        unprotect.assert_not_called()

    def test_ciphertext_does_not_contain_plaintext(self):
        plaintext = b"plaintext-scan-canary-724337fa3bf3483bb94596dfa752b8c4"
        ciphertext = self.store.encrypt(plaintext, "backup")

        self.assertNotIn(plaintext, ciphertext)


class SecretStoreFailureTests(unittest.TestCase):
    def test_mocked_native_failures_are_stable_and_do_not_leak_input(self):
        canary = b"failure-canary-824cb171"
        store = SecretStore(_backend=_FailingBackend(canary))

        with self.assertRaises(SecretStoreError) as encrypt_error:
            store.encrypt(canary, "account.credentials")
        with self.assertRaises(SecretStoreError) as decrypt_error:
            store.decrypt(
                secret_store._HEADER.pack(
                    secret_store._MAGIC,
                    secret_store._VERSION,
                )
                + b"ciphertext",
                "account.credentials",
            )

        self.assertEqual(str(encrypt_error.exception), "Secret encryption failed.")
        self.assertEqual(str(decrypt_error.exception), "Secret decryption failed.")
        self.assertNotIn(canary.decode("ascii"), str(encrypt_error.exception))
        self.assertNotIn(canary.decode("ascii"), str(decrypt_error.exception))


if __name__ == "__main__":
    unittest.main()
