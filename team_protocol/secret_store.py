from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from ctypes import wintypes


_MAGIC = b"TWSCSECR"
_VERSION = 1
_HEADER = struct.Struct(">8sB")
_APPLICATION_ENTROPY = b"TeamWorkflowConsole.SecretStore"
_PAYLOAD_MARKER = b"TWSC-DATA\x00"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01
_MAX_BLOB_SIZE = (1 << 32) - 1


class SecretStoreError(RuntimeError):
    """Raised when a secret cannot be protected or recovered safely."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _as_blob(data: bytes) -> tuple[_DATA_BLOB, object | None]:
    if len(data) > _MAX_BLOB_SIZE:
        raise ValueError("DPAPI payload is too large")
    if not data:
        return _DATA_BLOB(0, None), None

    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    return _DATA_BLOB(len(data), pointer), buffer


class _WindowsDpapi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise SecretStoreError("Windows DPAPI is unavailable.")

        try:
            self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._configure_functions()
        except SecretStoreError:
            raise
        except Exception:
            raise SecretStoreError("Windows DPAPI is unavailable.") from None

    def _configure_functions(self) -> None:
        self._protect = self._crypt32.CryptProtectData
        self._protect.argtypes = [
            ctypes.POINTER(_DATA_BLOB),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DATA_BLOB),
        ]
        self._protect.restype = wintypes.BOOL

        self._unprotect = self._crypt32.CryptUnprotectData
        self._unprotect.argtypes = [
            ctypes.POINTER(_DATA_BLOB),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DATA_BLOB),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DATA_BLOB),
        ]
        self._unprotect.restype = wintypes.BOOL

        self._local_free = self._kernel32.LocalFree
        self._local_free.argtypes = [ctypes.c_void_p]
        self._local_free.restype = ctypes.c_void_p

    def protect(self, plaintext: bytes, entropy: bytes) -> bytes:
        return self._transform(plaintext, entropy, decrypt=False)

    def unprotect(self, ciphertext: bytes, entropy: bytes) -> bytes:
        return self._transform(ciphertext, entropy, decrypt=True)

    def _transform(self, payload: bytes, entropy: bytes, *, decrypt: bool) -> bytes:
        input_blob, input_buffer = _as_blob(payload)
        entropy_blob, entropy_buffer = _as_blob(entropy)
        output_blob = _DATA_BLOB()

        # Retain Python-owned input buffers for the duration of the native call.
        _ = input_buffer, entropy_buffer
        try:
            if decrypt:
                succeeded = self._unprotect(
                    ctypes.byref(input_blob),
                    None,
                    ctypes.byref(entropy_blob),
                    None,
                    None,
                    _CRYPTPROTECT_UI_FORBIDDEN,
                    ctypes.byref(output_blob),
                )
            else:
                succeeded = self._protect(
                    ctypes.byref(input_blob),
                    "Team Workflow Console",
                    ctypes.byref(entropy_blob),
                    None,
                    None,
                    _CRYPTPROTECT_UI_FORBIDDEN,
                    ctypes.byref(output_blob),
                )

            if not succeeded:
                raise OSError("DPAPI operation failed")
            if output_blob.cbData and not output_blob.pbData:
                raise OSError("DPAPI returned an invalid buffer")
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            if output_blob.pbData:
                if self._local_free(ctypes.cast(output_blob.pbData, ctypes.c_void_p)):
                    raise OSError("DPAPI buffer release failed")


class SecretStore:
    """Purpose-bound Windows DPAPI storage for byte-oriented secrets."""

    def __init__(self, *, _backend: object | None = None) -> None:
        self._backend = _backend if _backend is not None else _WindowsDpapi()

    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        payload = self._require_bytes(plaintext, "plaintext")
        entropy = self._purpose_entropy(purpose)
        try:
            protected = self._backend.protect(_PAYLOAD_MARKER + payload, entropy)
            if not isinstance(protected, bytes) or not protected:
                raise OSError("DPAPI returned invalid ciphertext")
        except Exception:
            raise SecretStoreError("Secret encryption failed.") from None
        return _HEADER.pack(_MAGIC, _VERSION) + protected

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        envelope = self._require_bytes(ciphertext, "ciphertext")
        entropy = self._purpose_entropy(purpose)
        try:
            if len(envelope) <= _HEADER.size:
                raise ValueError("invalid envelope")
            magic, version = _HEADER.unpack_from(envelope)
            if magic != _MAGIC or version != _VERSION:
                raise ValueError("unsupported envelope")
            protected_payload = self._backend.unprotect(envelope[_HEADER.size :], entropy)
            if not isinstance(protected_payload, bytes):
                raise OSError("DPAPI returned invalid plaintext")
            if not protected_payload.startswith(_PAYLOAD_MARKER):
                raise OSError("DPAPI returned invalid plaintext")
            return protected_payload[len(_PAYLOAD_MARKER) :]
        except Exception:
            raise SecretStoreError("Secret decryption failed.") from None

    @staticmethod
    def _require_bytes(value: bytes, name: str) -> bytes:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")
        return value

    @staticmethod
    def _purpose_entropy(purpose: str) -> bytes:
        if not isinstance(purpose, str) or not purpose:
            raise ValueError("purpose must be a non-empty string")
        purpose_bytes = purpose.encode("utf-8")
        material = _APPLICATION_ENTROPY + bytes([_VERSION]) + b"\x00" + purpose_bytes
        return hashlib.sha256(material).digest()


__all__ = ["SecretStore", "SecretStoreError"]
