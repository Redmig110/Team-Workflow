from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Protocol


SCHEMA_VERSION = 3
ACCOUNT_STATUSES = frozenset(
    {
        "available",
        "bound_current",
        "bound_next",
        "exited_pending",
        "retired",
        "disabled",
    }
)
WORKSPACE_STATUSES = frozenset(
    {"needs_account", "ready", "queued", "running", "failed", "paused"}
)
RUN_STATES = frozenset(
    {"queued", "running", "stopping", "succeeded", "failed", "cancelled"}
)
QUEUE_STATES = frozenset({"pending", "running", "completed", "failed", "cancelled"})
MAILBOX_INVENTORY_STATUSES = frozenset({"available", "disabled", "exhausted"})
MAILBOX_ALLOCATION_STATES = frozenset({"allocated", "retired", "disabled"})
IDENTITY_FAILURE_CODES = frozenset({"alias_disabled", "mailbox_credentials_invalid"})
WORKFLOW_STEPS = (
    "old_login",
    "new_login",
    "invite",
    "old_leave",
    "pat",
    "cpa",
    "push",
    "push_sub2api",
)
_UNSET = object()
_ACCOUNT_RUNTIME_IDENTITY_VERSION = 1
_ACCOUNT_RUNTIME_IDENTITY_KEYS = frozenset(
    {
        "version",
        "proxy_sid",
        "proxy_geo",
        "fingerprint_profile",
        "browserforge_fingerprint",
        "toolchain",
    }
)


class SecretStoreLike(Protocol):
    def encrypt(self, plaintext: bytes, purpose: str) -> bytes: ...

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes: ...


class DatabaseError(RuntimeError):
    code = "database_error"


class DatabaseConfigurationError(DatabaseError):
    code = "database_configuration"


class NotFoundError(DatabaseError):
    code = "not_found"


class ConflictError(DatabaseError):
    code = "conflict"


class BindingConflictError(ConflictError):
    code = "account_binding_conflict"


class StaleVersionError(ConflictError):
    code = "stale_workspace_version"


class StateConflictError(ConflictError):
    code = "state_conflict"


class WorkspaceActiveError(StateConflictError):
    code = "workspace_active"


class InventoryExhaustedError(ConflictError):
    code = "inventory_exhausted"


class InventoryDisabledError(ConflictError):
    code = "inventory_disabled"


class NoReplacementAccountError(ConflictError):
    code = "no_replacement_account"


class ValidationError(DatabaseError):
    code = "validation_error"


class RestoreValidationError(DatabaseError):
    code = "restore_validation"


@dataclass(frozen=True)
class RestoreValidation:
    snapshot_sha256: str
    schema_version: int
    instance_id: str
    migration_id: str
    row_counts: Mapping[str, int]


def default_app_dir() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise DatabaseConfigurationError("LOCALAPPDATA is not configured")
    return Path(local_app_data) / "TeamWorkflowConsole"


def default_database_path() -> Path:
    return default_app_dir() / "console.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _identifier(value: str | None) -> str:
    return str(value or uuid.uuid4())


def _migration_identifier(migration_id: str, kind: str, value: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"twsc:{migration_id}:{kind}:{value.casefold()}"))


def _required_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValidationError(f"{field} is required")
    return text


def _normalize_primary_email(value: Any) -> str:
    email = _required_text(value, "primary_email").casefold()
    if email.count("@") != 1:
        raise ValidationError("primary_email is invalid")
    local, domain = email.split("@", 1)
    if not local or not domain or "." not in domain or re.search(r"\+\d+$", local):
        raise ValidationError("primary_email is invalid")
    return email


def _alias_email(primary_email: str, alias_number: int) -> str:
    local, domain = primary_email.rsplit("@", 1)
    return f"{local}+{alias_number}@{domain}"


def _alias_number(email: str, primary_email: str) -> int | None:
    primary_local, primary_domain = primary_email.casefold().rsplit("@", 1)
    match = re.fullmatch(
        rf"{re.escape(primary_local)}\+([1-5])@{re.escape(primary_domain)}",
        email.casefold(),
    )
    return None if match is None else int(match.group(1))


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _validate_account_runtime_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise DatabaseError("account runtime identity is invalid")
    identity = dict(value)
    if set(identity) - _ACCOUNT_RUNTIME_IDENTITY_KEYS:
        raise DatabaseError("account runtime identity contains unsupported fields")
    if int(identity.get("version") or 0) != _ACCOUNT_RUNTIME_IDENTITY_VERSION:
        raise DatabaseError("account runtime identity version is unsupported")
    sid = str(identity.get("proxy_sid") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{8,32}", sid):
        raise DatabaseError("account runtime identity has an invalid proxy SID")
    identity["proxy_sid"] = sid
    for key in (
        "proxy_geo",
        "fingerprint_profile",
        "browserforge_fingerprint",
        "toolchain",
    ):
        item = identity.get(key)
        if item is not None and not isinstance(item, Mapping):
            raise DatabaseError(f"account runtime identity {key} is invalid")
        if isinstance(item, Mapping):
            identity[key] = dict(item)
    try:
        _json_bytes(identity)
    except (TypeError, ValueError) as exc:
        raise DatabaseError("account runtime identity is not JSON serializable") from exc
    return identity


_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value_text TEXT,
        value_blob BLOB,
        encrypted INTEGER NOT NULL CHECK (encrypted IN (0, 1)),
        updated_at TEXT NOT NULL,
        CHECK (
            (encrypted = 0 AND value_text IS NOT NULL AND value_blob IS NULL)
            OR
            (encrypted = 1 AND value_text IS NULL AND value_blob IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        primary_email TEXT NOT NULL COLLATE NOCASE,
        credential_blob BLOB NOT NULL,
        status TEXT NOT NULL CHECK (
            status IN (
                'available', 'bound_current', 'bound_next',
                'exited_pending', 'retired', 'disabled'
            )
        ),
        source TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE workspaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        workspace_uid TEXT NOT NULL UNIQUE,
        current_account_id TEXT NOT NULL REFERENCES accounts(id),
        next_account_id TEXT REFERENCES accounts(id),
        status TEXT NOT NULL CHECK (
            status IN (
                'needs_account', 'ready', 'queued', 'running', 'failed', 'paused'
            )
        ),
        last_run_id TEXT,
        rotation_count INTEGER NOT NULL DEFAULT 0 CHECK (rotation_count >= 0),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        CHECK (next_account_id IS NULL OR current_account_id <> next_account_id)
    )
    """,
    """
    CREATE TABLE runs (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL REFERENCES workspaces(id),
        current_account_id TEXT NOT NULL REFERENCES accounts(id),
        next_account_id TEXT NOT NULL REFERENCES accounts(id),
        current_email_snapshot TEXT NOT NULL,
        next_email_snapshot TEXT NOT NULL,
        workspace_uid_snapshot TEXT NOT NULL,
        state TEXT NOT NULL CHECK (
            state IN ('queued', 'running', 'stopping', 'succeeded', 'failed', 'cancelled')
        ),
        current_step TEXT,
        checkpoint_blob BLOB,
        proxy_blob BLOB,
        result_json TEXT,
        redacted_error TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    )
    """,
    """
    CREATE TABLE queue_items (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL UNIQUE REFERENCES runs(id),
        position INTEGER NOT NULL CHECK (position >= 0),
        state TEXT NOT NULL CHECK (
            state IN ('pending', 'running', 'completed', 'failed', 'cancelled')
        ),
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    )
    """,
    """
    CREATE TABLE run_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL REFERENCES runs(id),
        step TEXT,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        routine INTEGER NOT NULL DEFAULT 0 CHECK (routine IN (0, 1)),
        created_at TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX ux_workspaces_current_account ON workspaces(current_account_id)",
    "CREATE UNIQUE INDEX ux_workspaces_next_account ON workspaces(next_account_id) WHERE next_account_id IS NOT NULL",
    "CREATE UNIQUE INDEX ux_queue_single_running ON queue_items((1)) WHERE state = 'running'",
    "CREATE UNIQUE INDEX ux_queue_active_position ON queue_items(position) WHERE state IN ('pending', 'running')",
    "CREATE INDEX ix_runs_workspace_created ON runs(workspace_id, created_at DESC)",
    "CREATE INDEX ix_run_events_run_seq ON run_events(run_id, seq)",
    """
    CREATE TRIGGER workspaces_binding_conflict_insert
    BEFORE INSERT ON workspaces
    BEGIN
        SELECT RAISE(ABORT, 'account_active_binding_conflict')
        WHERE EXISTS (
            SELECT 1 FROM workspaces AS other
            WHERE other.current_account_id = NEW.current_account_id
               OR other.next_account_id = NEW.current_account_id
               OR (NEW.next_account_id IS NOT NULL AND (
                    other.current_account_id = NEW.next_account_id
                    OR other.next_account_id = NEW.next_account_id
               ))
        );
    END
    """,
    """
    CREATE TRIGGER workspaces_binding_conflict_update
    BEFORE UPDATE OF current_account_id, next_account_id ON workspaces
    BEGIN
        SELECT RAISE(ABORT, 'account_active_binding_conflict')
        WHERE EXISTS (
            SELECT 1 FROM workspaces AS other
            WHERE other.id <> OLD.id
              AND (
                   other.current_account_id = NEW.current_account_id
                   OR other.next_account_id = NEW.current_account_id
                   OR (NEW.next_account_id IS NOT NULL AND (
                        other.current_account_id = NEW.next_account_id
                        OR other.next_account_id = NEW.next_account_id
                   ))
              )
        );
    END
    """,
)

_SCHEMA_V2_STATEMENTS = (
    """
    CREATE TABLE mailbox_inventory (
        id TEXT PRIMARY KEY,
        primary_email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        credential_blob BLOB NOT NULL,
        credential_purpose TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('available', 'disabled', 'exhausted')),
        next_alias_number INTEGER NOT NULL DEFAULT 1 CHECK (next_alias_number BETWEEN 1 AND 6),
        source_order INTEGER NOT NULL CHECK (source_order >= 0),
        failure_code TEXT,
        failure_message TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE mailbox_alias_allocations (
        inventory_id TEXT NOT NULL REFERENCES mailbox_inventory(id) ON DELETE CASCADE,
        alias_number INTEGER NOT NULL CHECK (alias_number BETWEEN 1 AND 5),
        account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        state TEXT NOT NULL CHECK (state IN ('allocated', 'retired', 'disabled')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (inventory_id, alias_number)
    )
    """,
    "CREATE INDEX ix_mailbox_inventory_selection ON mailbox_inventory(status, source_order, created_at, id)",
    "CREATE INDEX ix_mailbox_inventory_email ON mailbox_inventory(primary_email COLLATE NOCASE)",
    "CREATE INDEX ix_mailbox_alias_account ON mailbox_alias_allocations(account_id)",
    "CREATE UNIQUE INDEX ux_mailbox_alias_account ON mailbox_alias_allocations(account_id) WHERE account_id IS NOT NULL",
)

_SCHEMA_V3_STATEMENTS = (
    "ALTER TABLE accounts ADD COLUMN runtime_identity_blob BLOB",
)

_SCHEMA_MIGRATIONS = {
    1: _SCHEMA_STATEMENTS,
    2: _SCHEMA_V2_STATEMENTS,
    3: _SCHEMA_V3_STATEMENTS,
}


class Database:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        secret_store: SecretStoreLike | None = None,
        busy_timeout_ms: int = 5_000,
    ) -> None:
        self.path = Path(path) if path is not None else default_database_path()
        self.path = self.path.expanduser().resolve()
        self.secret_store = secret_store
        self.busy_timeout_ms = max(1, int(busy_timeout_ms))
        self._maintenance_lock = threading.RLock()
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        return connection

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        with self._maintenance_lock:
            connection = self._connect()
            try:
                yield connection
            finally:
                connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._maintenance_lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except sqlite3.IntegrityError as exc:
                connection.rollback()
                self._raise_integrity_error(exc)
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    @staticmethod
    def _raise_integrity_error(exc: sqlite3.IntegrityError) -> None:
        message = str(exc)
        if (
            "account_active_binding_conflict" in message
            or "workspaces.current_account_id" in message
            or "workspaces.next_account_id" in message
        ):
            raise BindingConflictError("account is already actively bound") from exc
        if "accounts.email" in message:
            raise ConflictError("account email already exists") from exc
        if "mailbox_inventory.primary_email" in message:
            raise ConflictError("mailbox inventory email already exists") from exc
        if "mailbox_alias_allocations" in message:
            raise ConflictError("mailbox alias is already allocated") from exc
        if "workspaces.workspace_uid" in message:
            raise ConflictError("workspace UID already exists") from exc
        if "FOREIGN KEY constraint failed" in message:
            raise ConflictError("referenced entity does not exist") from exc
        raise ConflictError("database constraint rejected the operation") from exc

    def initialize(self) -> None:
        with self._maintenance_lock:
            self._initialize_locked()

    def _before_schema_migration_commit(
        self,
        connection: sqlite3.Connection,
        from_version: int,
        to_version: int,
    ) -> None:
        del connection, from_version, to_version

    def _initialize_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            journal_mode = str(
                connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            ).lower()
            if journal_mode != "wal":
                raise DatabaseConfigurationError("SQLite WAL mode is unavailable")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT value FROM app_meta WHERE key = 'schema_version'"
            ).fetchone()
            current_version = int(row[0]) if row else 0
            if current_version > SCHEMA_VERSION:
                raise DatabaseConfigurationError(
                    f"database schema {current_version} is newer than supported {SCHEMA_VERSION}"
                )
            while current_version < SCHEMA_VERSION:
                next_version = current_version + 1
                statements = _SCHEMA_MIGRATIONS.get(next_version)
                if statements is None:
                    raise DatabaseConfigurationError(
                        f"database schema migration {next_version} is unavailable"
                    )
                for statement in statements:
                    connection.execute(statement)
                self._before_schema_migration_commit(
                    connection, current_version, next_version
                )
                connection.execute(
                    """
                    INSERT INTO app_meta(key, value) VALUES('schema_version', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (str(next_version),),
                )
                current_version = next_version
            connection.execute(
                "INSERT OR IGNORE INTO app_meta(key, value) VALUES('instance_id', ?)",
                (str(uuid.uuid4()),),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def diagnostics(self) -> dict[str, Any]:
        with self._read_connection() as connection:
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            busy_timeout = int(
                connection.execute("PRAGMA busy_timeout").fetchone()[0]
            )
        return {
            "path": str(self.path),
            "schema_version": int(self.get_meta("schema_version") or 0),
            "journal_mode": journal_mode.lower(),
            "foreign_keys": bool(foreign_keys),
            "busy_timeout_ms": busy_timeout,
        }

    def get_meta(self, key: str) -> str | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT value FROM app_meta WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else str(row[0])

    def set_meta(self, key: str, value: str) -> None:
        key = _required_text(key, "key")
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO app_meta(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, str(value)),
            )

    def _require_secret_store(self) -> SecretStoreLike:
        if self.secret_store is None:
            raise DatabaseConfigurationError("secret store is required")
        return self.secret_store

    def set_text_setting(self, key: str, value: str) -> None:
        key = _required_text(key, "key")
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value_text, value_blob, encrypted, updated_at)
                VALUES(?, ?, NULL, 0, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_text = excluded.value_text,
                    value_blob = NULL,
                    encrypted = 0,
                    updated_at = excluded.updated_at
                """,
                (key, str(value), _now()),
            )

    def get_text_setting(self, key: str, default: str | None = None) -> str | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT value_text, encrypted FROM settings WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        if row["encrypted"]:
            raise StateConflictError("setting is encrypted")
        return str(row["value_text"])

    def set_secret_setting(self, key: str, value: str | bytes) -> None:
        key = _required_text(key, "key")
        plaintext = value if isinstance(value, bytes) else str(value).encode("utf-8")
        ciphertext = self._require_secret_store().encrypt(plaintext, f"setting:{key}")
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value_text, value_blob, encrypted, updated_at)
                VALUES(?, NULL, ?, 1, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_text = NULL,
                    value_blob = excluded.value_blob,
                    encrypted = 1,
                    updated_at = excluded.updated_at
                """,
                (key, sqlite3.Binary(ciphertext), _now()),
            )

    def get_secret_setting(self, key: str, default: bytes | None = None) -> bytes | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT value_blob, encrypted FROM settings WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        if not row["encrypted"]:
            raise StateConflictError("setting is not encrypted")
        return self._require_secret_store().decrypt(
            bytes(row["value_blob"]), f"setting:{key}"
        )

    def list_settings(self) -> list[dict[str, Any]]:
        with self._read_connection() as connection:
            rows = connection.execute(
                "SELECT key, value_text, encrypted, updated_at FROM settings ORDER BY key"
            ).fetchall()
        return [
            {
                "key": str(row["key"]),
                "value": None if row["encrypted"] else str(row["value_text"]),
                "encrypted": bool(row["encrypted"]),
                "configured": bool(row["encrypted"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def delete_setting(self, key: str) -> bool:
        key = _required_text(key, "key")
        with self._write_transaction() as connection:
            cursor = connection.execute("DELETE FROM settings WHERE key = ?", (key,))
        return cursor.rowcount == 1

    @staticmethod
    def _mailbox_inventory_view(row: sqlite3.Row) -> dict[str, Any]:
        status = str(row["status"])
        return {
            "id": str(row["id"]),
            "primary_email": str(row["primary_email"]),
            "status": status,
            "next_alias_number": int(row["next_alias_number"]),
            "exhausted": status == "exhausted",
            "failure_code": (
                None if row["failure_code"] is None else str(row["failure_code"])
            ),
            "failure_message": (
                None if row["failure_message"] is None else str(row["failure_message"])
            ),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    @staticmethod
    def _coerce_inventory_record(
        value: Any, default_source_order: int
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise ValidationError("mailbox inventory record is invalid")
        primary_email = _normalize_primary_email(value.get("primary_email"))
        client_id = _required_text(value.get("client_id"), "client_id")
        refresh_token = _required_text(value.get("refresh_token"), "refresh_token")
        password = str(value.get("password") or value.get("mailbox_password") or "").strip()
        try:
            source_order = int(value.get("source_order", default_source_order))
        except (TypeError, ValueError) as exc:
            raise ValidationError("source_order is invalid") from exc
        if source_order < 0:
            raise ValidationError("source_order is invalid")
        return {
            "primary_email": primary_email,
            "credentials": {
                "mailbox_password": password,
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
            "source_order": source_order,
        }

    def _import_mailbox_inventory_tx(
        self,
        connection: sqlite3.Connection,
        records: tuple[Any, ...],
        *,
        reject_invalid: bool = False,
    ) -> dict[str, int]:
        timestamp = _now()
        counts = {"total": len(records), "imported": 0, "existing": 0, "invalid": 0}
        for index, value in enumerate(records):
            try:
                record = self._coerce_inventory_record(value, index)
            except ValidationError:
                counts["invalid"] += 1
                if reject_invalid:
                    raise
                continue
            existing = connection.execute(
                "SELECT * FROM mailbox_inventory WHERE primary_email = ? COLLATE NOCASE",
                (record["primary_email"],),
            ).fetchone()
            inventory_id = str(existing["id"]) if existing is not None else _identifier(None)
            purpose = (
                str(existing["credential_purpose"])
                if existing is not None
                else f"mailbox-inventory:{inventory_id}:credentials"
            )
            ciphertext = self._require_secret_store().encrypt(
                _json_bytes(record["credentials"]), purpose
            )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO mailbox_inventory(
                        id, primary_email, credential_blob, credential_purpose,
                        status, next_alias_number, source_order,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, ?, 'available', 1, ?, ?, ?)
                    """,
                    (
                        inventory_id,
                        record["primary_email"],
                        sqlite3.Binary(ciphertext),
                        purpose,
                        record["source_order"],
                        timestamp,
                        timestamp,
                    ),
                )
                counts["imported"] += 1
            else:
                connection.execute(
                    """
                    UPDATE mailbox_inventory
                    SET credential_blob = ?, credential_purpose = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (sqlite3.Binary(ciphertext), purpose, timestamp, inventory_id),
                )
                counts["existing"] += 1
        return counts

    def import_mailbox_inventory(
        self, records: Iterable[Mapping[str, Any]]
    ) -> dict[str, int]:
        values = tuple(records)
        with self._write_transaction() as connection:
            return self._import_mailbox_inventory_tx(connection, values)

    def get_mailbox_inventory(self, inventory_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM mailbox_inventory WHERE id = ?", (inventory_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("mailbox inventory not found")
        return self._mailbox_inventory_view(row)

    def get_mailbox_inventory_credentials(self, inventory_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT credential_blob, credential_purpose
                FROM mailbox_inventory WHERE id = ?
                """,
                (inventory_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("mailbox inventory not found")
        try:
            plaintext = self._require_secret_store().decrypt(
                bytes(row["credential_blob"]), str(row["credential_purpose"])
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise DatabaseError("mailbox inventory credentials are invalid") from exc
        if not isinstance(value, dict):
            raise DatabaseError("mailbox inventory credentials are invalid")
        return value

    def search_mailbox_inventory(
        self,
        *,
        query: str = "",
        status: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        if status is not None and status not in MAILBOX_INVENTORY_STATUSES:
            raise ValidationError("mailbox inventory status is invalid")
        bounded_limit = min(max(int(limit), 1), 20)
        clauses: list[str] = []
        parameters: list[Any] = []
        query = str(query or "").strip()
        if query:
            escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("primary_email LIKE ? ESCAPE '\\' COLLATE NOCASE")
            parameters.append(f"%{escaped}%")
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status)
        where = "" if not clauses else "WHERE " + " AND ".join(clauses)
        parameters.append(bounded_limit)
        with self._read_connection() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM mailbox_inventory
                {where}
                ORDER BY source_order, created_at, id
                LIMIT ?
                """,
                tuple(parameters),
            ).fetchall()
        return [self._mailbox_inventory_view(row) for row in rows]

    def get_mailbox_inventory_summary(self) -> dict[str, int]:
        with self._read_connection() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM mailbox_inventory GROUP BY status"
            ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        return {
            "total": sum(counts.values()),
            "available": counts.get("available", 0),
            "disabled": counts.get("disabled", 0),
            "exhausted": counts.get("exhausted", 0),
        }

    def set_mailbox_inventory_status(
        self,
        inventory_id: str,
        status: str,
        *,
        failure_code: str | None = None,
        failure_message: str | None = None,
    ) -> dict[str, Any]:
        if status not in MAILBOX_INVENTORY_STATUSES:
            raise ValidationError("mailbox inventory status is invalid")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT next_alias_number FROM mailbox_inventory WHERE id = ?",
                (inventory_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("mailbox inventory not found")
            if status == "available" and int(row["next_alias_number"]) > 5:
                raise InventoryExhaustedError("mailbox inventory is exhausted")
            connection.execute(
                """
                UPDATE mailbox_inventory
                SET status = ?, failure_code = ?, failure_message = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    str(failure_code).strip() if failure_code else None,
                    str(failure_message).strip() if failure_message else None,
                    _now(),
                    inventory_id,
                ),
            )
        return self.get_mailbox_inventory(inventory_id)

    def _inventory_credentials_tx(
        self, connection: sqlite3.Connection, inventory: sqlite3.Row
    ) -> dict[str, Any]:
        try:
            plaintext = self._require_secret_store().decrypt(
                bytes(inventory["credential_blob"]),
                str(inventory["credential_purpose"]),
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise DatabaseError("mailbox inventory credentials are invalid") from exc
        if not isinstance(value, dict):
            raise DatabaseError("mailbox inventory credentials are invalid")
        return value

    def _allocate_alias_tx(
        self,
        connection: sqlite3.Connection,
        inventory_id: str | None = None,
        preferred_primary_email: str | None = None,
    ) -> dict[str, Any] | None:
        if inventory_id and preferred_primary_email:
            raise ValidationError(
                "inventory_id and preferred_primary_email are mutually exclusive"
            )
        explicit_inventory_id = str(inventory_id).strip() if inventory_id else None
        preferred = (
            _normalize_primary_email(preferred_primary_email)
            if preferred_primary_email
            else None
        )
        preferred_checked = False
        exhausted_ids: set[str] = set()
        timestamp = _now()

        while True:
            inventory: sqlite3.Row | None
            if explicit_inventory_id:
                inventory = connection.execute(
                    "SELECT * FROM mailbox_inventory WHERE id = ?",
                    (explicit_inventory_id,),
                ).fetchone()
                if inventory is None:
                    raise NotFoundError("mailbox inventory not found")
                status = str(inventory["status"])
                if status == "disabled":
                    raise InventoryDisabledError("mailbox inventory is disabled")
                if status == "exhausted":
                    raise InventoryExhaustedError("mailbox inventory is exhausted")
            elif preferred and not preferred_checked:
                inventory = connection.execute(
                    """
                    SELECT * FROM mailbox_inventory
                    WHERE primary_email = ? COLLATE NOCASE AND status = 'available'
                    """,
                    (preferred,),
                ).fetchone()
                preferred_checked = True
            else:
                exclusion = ""
                parameters: list[Any] = []
                if exhausted_ids:
                    placeholders = ",".join("?" for _ in exhausted_ids)
                    exclusion = f"AND id NOT IN ({placeholders})"
                    parameters.extend(sorted(exhausted_ids))
                inventory = connection.execute(
                    f"""
                    SELECT * FROM mailbox_inventory
                    WHERE status = 'available' {exclusion}
                    ORDER BY source_order, created_at, id
                    LIMIT 1
                    """,
                    tuple(parameters),
                ).fetchone()
            if inventory is None:
                if preferred and preferred_checked:
                    preferred = None
                    continue
                return None

            inventory_key = str(inventory["id"])
            start = max(1, int(inventory["next_alias_number"]))
            allocated = {
                int(row["alias_number"])
                for row in connection.execute(
                    """
                    SELECT alias_number FROM mailbox_alias_allocations
                    WHERE inventory_id = ?
                    """,
                    (inventory_key,),
                )
            }
            alias_number = next(
                (number for number in range(start, 6) if number not in allocated),
                None,
            )
            if alias_number is None:
                connection.execute(
                    """
                    UPDATE mailbox_inventory
                    SET status = 'exhausted', next_alias_number = 6, updated_at = ?
                    WHERE id = ?
                    """,
                    (timestamp, inventory_key),
                )
                if explicit_inventory_id:
                    raise InventoryExhaustedError("mailbox inventory is exhausted")
                exhausted_ids.add(inventory_key)
                preferred = None
                continue

            email = _alias_email(str(inventory["primary_email"]), alias_number)
            account = connection.execute(
                "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE", (email,)
            ).fetchone()
            if account is None:
                account_id = _identifier(None)
                credentials = self._inventory_credentials_tx(connection, inventory)
                credentials["account_password"] = ""
                credential_blob = self._require_secret_store().encrypt(
                    _json_bytes(credentials), f"account:{account_id}:credentials"
                )
                connection.execute(
                    """
                    INSERT INTO accounts(
                        id, email, primary_email, credential_blob, status, source,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, ?, 'available', 'mailbox_inventory', ?, ?)
                    """,
                    (
                        account_id,
                        email,
                        inventory["primary_email"],
                        sqlite3.Binary(credential_blob),
                        timestamp,
                        timestamp,
                    ),
                )
            else:
                account_id = str(account["id"])
                if str(account["primary_email"]).casefold() != str(
                    inventory["primary_email"]
                ).casefold():
                    raise ConflictError("existing alias belongs to another mailbox")

            account_status = str(account["status"]) if account is not None else "available"
            allocation_state = (
                "disabled"
                if account_status == "disabled"
                else "retired"
                if account_status in {"retired", "exited_pending"}
                else "allocated"
            )
            connection.execute(
                """
                INSERT INTO mailbox_alias_allocations(
                    inventory_id, alias_number, account_id, state,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    inventory_key,
                    alias_number,
                    account_id,
                    allocation_state,
                    timestamp,
                    timestamp,
                ),
            )
            allocated.add(alias_number)
            next_alias = next(
                (number for number in range(alias_number + 1, 6) if number not in allocated),
                6,
            )
            connection.execute(
                """
                UPDATE mailbox_inventory
                SET next_alias_number = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    next_alias,
                    "exhausted" if next_alias == 6 else "available",
                    timestamp,
                    inventory_key,
                ),
            )
            row = connection.execute(
                "SELECT * FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if row is None:
                raise StateConflictError("allocated account is missing")
            return self._account_view(row)

    def allocate_mailbox_alias(
        self,
        inventory_id: str | None = None,
        *,
        preferred_primary_email: str | None = None,
    ) -> dict[str, Any]:
        with self._write_transaction() as connection:
            account = self._allocate_alias_tx(
                connection,
                inventory_id=inventory_id,
                preferred_primary_email=preferred_primary_email,
            )
            if account is None:
                raise InventoryExhaustedError("no available mailbox inventory")
            return account

    def _claim_replacement_account_tx(
        self,
        connection: sqlite3.Connection,
        *,
        preferred_primary_email: str | None = None,
        after_alias_number: int | None = None,
    ) -> dict[str, Any] | None:
        preferred = (
            _normalize_primary_email(preferred_primary_email)
            if preferred_primary_email
            else None
        )
        if preferred:
            parameters: list[Any] = [preferred]
            alias_clause = ""
            if after_alias_number is not None:
                alias_clause = "AND allocation.alias_number > ?"
                parameters.append(int(after_alias_number))
            row = connection.execute(
                f"""
                SELECT account.*
                FROM accounts AS account
                JOIN mailbox_alias_allocations AS allocation
                  ON allocation.account_id = account.id
                JOIN mailbox_inventory AS inventory
                  ON inventory.id = allocation.inventory_id
                WHERE account.status = 'available'
                  AND inventory.status <> 'disabled'
                  AND inventory.primary_email = ? COLLATE NOCASE
                  {alias_clause}
                ORDER BY allocation.alias_number, account.created_at, account.id
                LIMIT 1
                """,
                tuple(parameters),
            ).fetchone()
            if row is not None:
                return self._account_view(row)

        clauses = ["account.status = 'available'"]
        parameters = []
        if preferred:
            clauses.append("account.primary_email <> ? COLLATE NOCASE")
            parameters.append(preferred)
        row = connection.execute(
            f"""
            SELECT account.*
            FROM accounts AS account
            LEFT JOIN mailbox_alias_allocations AS allocation
              ON allocation.account_id = account.id
            LEFT JOIN mailbox_inventory AS inventory
              ON inventory.id = allocation.inventory_id
            WHERE {' AND '.join(clauses)}
              AND (inventory.id IS NULL OR inventory.status <> 'disabled')
            ORDER BY
                CASE WHEN inventory.source_order IS NULL THEN 1 ELSE 0 END,
                inventory.source_order,
                allocation.alias_number,
                account.created_at,
                account.id
            LIMIT 1
            """,
            tuple(parameters),
        ).fetchone()
        if row is not None:
            return self._account_view(row)
        return self._allocate_alias_tx(
            connection, preferred_primary_email=preferred
        )

    def list_mailbox_alias_allocations(
        self, inventory_id: str | None = None
    ) -> list[dict[str, Any]]:
        parameters: tuple[Any, ...] = () if inventory_id is None else (inventory_id,)
        where = "" if inventory_id is None else "WHERE inventory_id = ?"
        with self._read_connection() as connection:
            rows = connection.execute(
                f"""
                SELECT inventory_id, alias_number, account_id, state,
                       created_at, updated_at
                FROM mailbox_alias_allocations {where}
                ORDER BY inventory_id, alias_number
                """,
                parameters,
            ).fetchall()
        return [
            {
                "inventory_id": str(row["inventory_id"]),
                "alias_number": int(row["alias_number"]),
                "account_id": (
                    None if row["account_id"] is None else str(row["account_id"])
                ),
                "state": str(row["state"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    def _backfill_alias_allocations_tx(
        self, connection: sqlite3.Connection, timestamp: str
    ) -> int:
        linked = 0
        rows = connection.execute(
            """
            SELECT account.*, inventory.id AS inventory_id
            FROM accounts AS account
            JOIN mailbox_inventory AS inventory
              ON inventory.primary_email = account.primary_email COLLATE NOCASE
            ORDER BY account.created_at, account.id
            """
        ).fetchall()
        for account in rows:
            number = _alias_number(
                str(account["email"]), str(account["primary_email"])
            )
            if number is None:
                continue
            state = (
                "disabled"
                if account["status"] == "disabled"
                else "retired"
                if account["status"] in {"retired", "exited_pending"}
                else "allocated"
            )
            existing = connection.execute(
                """
                SELECT account_id FROM mailbox_alias_allocations
                WHERE inventory_id = ? AND alias_number = ?
                """,
                (account["inventory_id"], number),
            ).fetchone()
            if existing is not None and existing["account_id"] not in {
                None,
                account["id"],
            }:
                raise ConflictError("mailbox alias allocation history conflicts")
            connection.execute(
                """
                INSERT INTO mailbox_alias_allocations(
                    inventory_id, alias_number, account_id, state,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(inventory_id, alias_number) DO UPDATE SET
                    account_id = excluded.account_id,
                    state = excluded.state,
                    updated_at = excluded.updated_at
                """,
                (
                    account["inventory_id"],
                    number,
                    account["id"],
                    state,
                    timestamp,
                    timestamp,
                ),
            )
            linked += 1

        inventories = connection.execute(
            "SELECT id, status FROM mailbox_inventory"
        ).fetchall()
        for inventory in inventories:
            row = connection.execute(
                """
                SELECT MAX(alias_number) AS maximum
                FROM mailbox_alias_allocations WHERE inventory_id = ?
                """,
                (inventory["id"],),
            ).fetchone()
            maximum = 0 if row is None or row["maximum"] is None else int(row["maximum"])
            next_alias = min(maximum + 1, 6)
            status = str(inventory["status"])
            if status != "disabled":
                status = "exhausted" if next_alias == 6 else "available"
            connection.execute(
                """
                UPDATE mailbox_inventory
                SET next_alias_number = ?, status = ?, updated_at = ?
                WHERE id = ?
                """,
                (next_alias, status, timestamp, inventory["id"]),
            )
        return linked

    @staticmethod
    def _prune_migrated_legacy_accounts_tx(
        connection: sqlite3.Connection,
    ) -> int:
        cursor = connection.execute(
            """
            DELETE FROM accounts
            WHERE source = 'legacy_txt'
              AND email = primary_email COLLATE NOCASE
              AND EXISTS (
                  SELECT 1 FROM mailbox_inventory AS inventory
                  WHERE inventory.primary_email = accounts.primary_email COLLATE NOCASE
              )
              AND NOT EXISTS (
                  SELECT 1 FROM workspaces AS workspace
                  WHERE workspace.current_account_id = accounts.id
                     OR workspace.next_account_id = accounts.id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM runs
                  WHERE runs.current_account_id = accounts.id
                     OR runs.next_account_id = accounts.id
              )
            """
        )
        return int(cursor.rowcount)

    def backfill_mailbox_inventory(
        self,
        records: Iterable[Mapping[str, Any]],
        *,
        migration_id: str,
        expected_count: int | None = None,
        legacy_old_email: str | None = None,
        legacy_new_email: str | None = None,
    ) -> dict[str, Any]:
        values = tuple(records)
        migration_id = _required_text(migration_id, "migration_id")
        if not re.fullmatch(r"[0-9a-f]{64}", migration_id):
            raise ValidationError("migration_id is invalid")
        if (legacy_old_email is None) != (legacy_new_email is None):
            raise ValidationError("legacy repair identity is incomplete")
        timestamp = _now()
        with self._write_transaction() as connection:
            marker = connection.execute(
                """
                SELECT value FROM app_meta
                WHERE key = 'mailbox_inventory_migration_version'
                """
            ).fetchone()
            if marker is not None:
                stored_id = connection.execute(
                    """
                    SELECT value FROM app_meta
                    WHERE key = 'mailbox_inventory_migration_id'
                    """
                ).fetchone()
                if stored_id is None or str(stored_id["value"]) != migration_id:
                    raise ConflictError("mailbox inventory migration identity conflicts")
                stored_counts = connection.execute(
                    """
                    SELECT value FROM app_meta
                    WHERE key = 'mailbox_inventory_migration_counts'
                    """
                ).fetchone()
                counts = (
                    json.loads(str(stored_counts["value"]))
                    if stored_counts is not None
                    else self.get_mailbox_inventory_summary()
                )
                return {
                    "counts": counts,
                    "repair_status": "already_completed",
                    "marker": str(marker["value"]),
                }

            normalized = [
                self._coerce_inventory_record(value, index)
                for index, value in enumerate(values)
            ]
            unique = {record["primary_email"] for record in normalized}
            if expected_count is not None and (
                len(values) != int(expected_count)
                or len(unique) != int(expected_count)
            ):
                raise ValidationError("mailbox inventory source count mismatch")
            import_counts = self._import_mailbox_inventory_tx(
                connection, values, reject_invalid=True
            )
            linked = self._backfill_alias_allocations_tx(connection, timestamp)
            repair_status = "not_requested"

            if legacy_old_email is not None and legacy_new_email is not None:
                old_email = _required_text(legacy_old_email, "legacy_old_email").casefold()
                new_email = _required_text(legacy_new_email, "legacy_new_email").casefold()
                old_account = connection.execute(
                    "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE", (old_email,)
                ).fetchone()
                new_account = connection.execute(
                    "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE", (new_email,)
                ).fetchone()
                if old_account is None or new_account is None:
                    raise StateConflictError("legacy repair accounts are missing")
                old_number = _alias_number(old_email, str(old_account["primary_email"]))
                new_number = _alias_number(new_email, str(new_account["primary_email"]))
                if (
                    old_number is None
                    or new_number is None
                    or new_number != old_number + 1
                    or new_number >= 5
                    or str(old_account["primary_email"]).casefold()
                    != str(new_account["primary_email"]).casefold()
                ):
                    raise StateConflictError("legacy repair identity is invalid")
                desired_email = _alias_email(
                    str(new_account["primary_email"]), new_number + 1
                )
                desired = connection.execute(
                    "SELECT * FROM accounts WHERE email = ? COLLATE NOCASE",
                    (desired_email,),
                ).fetchone()
                if desired is None:
                    inventory = connection.execute(
                        """
                        SELECT id FROM mailbox_inventory
                        WHERE primary_email = ? COLLATE NOCASE
                        """,
                        (new_account["primary_email"],),
                    ).fetchone()
                    if inventory is None:
                        raise StateConflictError("legacy repair inventory is missing")
                    allocated = self._allocate_alias_tx(
                        connection, inventory_id=str(inventory["id"])
                    )
                    if allocated is None or allocated["email"].casefold() != desired_email:
                        raise StateConflictError("legacy repair successor is unavailable")
                    desired = connection.execute(
                        "SELECT * FROM accounts WHERE id = ?", (allocated["id"],)
                    ).fetchone()
                workspace = connection.execute(
                    """
                    SELECT * FROM workspaces
                    WHERE current_account_id IN (?, ?)
                    ORDER BY created_at, id LIMIT 1
                    """,
                    (old_account["id"], new_account["id"]),
                ).fetchone()
                if workspace is None:
                    raise StateConflictError("legacy repair workspace is missing")
                if (
                    workspace["current_account_id"] == new_account["id"]
                    and workspace["next_account_id"] == desired["id"]
                ):
                    repair_status = "already_repaired"
                elif (
                    workspace["current_account_id"] == old_account["id"]
                    and workspace["next_account_id"] == new_account["id"]
                    and workspace["status"] not in {"queued", "running"}
                ):
                    connection.execute(
                        "UPDATE accounts SET status = 'exited_pending', updated_at = ? WHERE id = ?",
                        (timestamp, old_account["id"]),
                    )
                    self._set_allocation_state_tx(
                        connection, str(old_account["id"]), "retired", timestamp
                    )
                    connection.execute(
                        "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                        (timestamp, new_account["id"]),
                    )
                    connection.execute(
                        "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                        (timestamp, desired["id"]),
                    )
                    connection.execute(
                        """
                        UPDATE workspaces
                        SET current_account_id = ?, next_account_id = ?, status = 'ready',
                            rotation_count = rotation_count + 1,
                            version = version + 1, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            new_account["id"],
                            desired["id"],
                            timestamp,
                            workspace["id"],
                        ),
                    )
                    repair_status = "repaired"
                else:
                    raise StateConflictError("legacy workspace state is not repairable")

            removed = self._prune_migrated_legacy_accounts_tx(connection)
            summary_rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM mailbox_inventory GROUP BY status"
            ).fetchall()
            summary_map = {
                str(row["status"]): int(row["count"]) for row in summary_rows
            }
            counts: dict[str, Any] = {
                **import_counts,
                "inventory_total": sum(summary_map.values()),
                "allocations_linked": linked,
                "legacy_accounts_removed": removed,
            }
            metadata = {
                "mailbox_inventory_migration_version": "1",
                "mailbox_inventory_migration_id": migration_id,
                "mailbox_inventory_migration_counts": json.dumps(
                    counts, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                ),
            }
            for key, value in metadata.items():
                connection.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?)", (key, value)
                )
            return {
                "counts": counts,
                "repair_status": repair_status,
                "marker": "1",
            }

    def create_account(
        self,
        *,
        email: str,
        primary_email: str,
        credentials: Mapping[str, Any],
        source: str,
        account_id: str | None = None,
    ) -> dict[str, Any]:
        account_id = _identifier(account_id)
        email = _required_text(email, "email")
        primary_email = _required_text(primary_email, "primary_email")
        source = _required_text(source, "source")
        ciphertext = self._require_secret_store().encrypt(
            _json_bytes(credentials), f"account:{account_id}:credentials"
        )
        timestamp = _now()
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO accounts(
                    id, email, primary_email, credential_blob, status, source,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, 'available', ?, ?, ?)
                """,
                (
                    account_id,
                    email,
                    primary_email,
                    sqlite3.Binary(ciphertext),
                    source,
                    timestamp,
                    timestamp,
                ),
            )
        return self.get_account(account_id)

    @staticmethod
    def _account_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "email": str(row["email"]),
            "primary_email": str(row["primary_email"]),
            "status": str(row["status"]),
            "source": str(row["source"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "credentials_configured": True,
        }

    def get_account(self, account_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                """
                SELECT id, email, primary_email, status, source, created_at, updated_at
                FROM accounts WHERE id = ?
                """,
                (account_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("account not found")
        return self._account_view(row)

    def list_accounts(self) -> list[dict[str, Any]]:
        with self._read_connection() as connection:
            rows = connection.execute(
                """
                SELECT id, email, primary_email, status, source, created_at, updated_at
                FROM accounts ORDER BY email COLLATE NOCASE
                """
            ).fetchall()
        return [self._account_view(row) for row in rows]

    def prune_unreferenced_legacy_accounts(self) -> int:
        """Remove only over-imported legacy inventory unrelated to a workspace."""

        with self._write_transaction() as connection:
            version = connection.execute(
                "SELECT value FROM app_meta WHERE key = 'legacy_account_scope_version'"
            ).fetchone()
            if version is not None and str(version["value"]) == "1":
                return 0

            if connection.execute(
                "SELECT 1 FROM mailbox_inventory LIMIT 1"
            ).fetchone() is not None:
                removed = self._prune_migrated_legacy_accounts_tx(connection)
                connection.execute(
                    """
                    INSERT INTO app_meta(key, value)
                    VALUES('legacy_account_scope_version', '1')
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """
                )
                return removed

            rows = connection.execute(
                """
                SELECT DISTINCT LOWER(account.primary_email) AS primary_email
                FROM workspaces AS workspace
                JOIN accounts AS account
                  ON account.id = workspace.current_account_id
                  OR account.id = workspace.next_account_id
                WHERE account.primary_email <> ''
                """
            ).fetchall()
            referenced_primaries = tuple(
                str(row["primary_email"]).casefold()
                for row in rows
                if str(row["primary_email"] or "").strip()
            )
            if not referenced_primaries:
                return 0

            placeholders = ",".join("?" for _ in referenced_primaries)
            cursor = connection.execute(
                f"""
                DELETE FROM accounts
                WHERE source = 'legacy_txt'
                  AND status = 'available'
                  AND LOWER(email) NOT IN ({placeholders})
                """,
                referenced_primaries,
            )
            connection.execute(
                """
                INSERT INTO app_meta(key, value) VALUES('legacy_account_scope_version', '1')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """
            )
            return int(cursor.rowcount)

    def get_account_credentials(self, account_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT credential_blob FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("account not found")
        plaintext = self._require_secret_store().decrypt(
            bytes(row["credential_blob"]), f"account:{account_id}:credentials"
        )
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise DatabaseError("account credentials are invalid")
        return value

    def replace_account_credentials(
        self, account_id: str, credentials: Mapping[str, Any]
    ) -> None:
        ciphertext = self._require_secret_store().encrypt(
            _json_bytes(credentials), f"account:{account_id}:credentials"
        )
        with self._write_transaction() as connection:
            cursor = connection.execute(
                "UPDATE accounts SET credential_blob = ?, updated_at = ? WHERE id = ?",
                (sqlite3.Binary(ciphertext), _now(), account_id),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("account not found")

    def _decode_account_network_identity(
        self,
        account_id: str,
        blob: Any,
    ) -> dict[str, Any]:
        if blob is None:
            return {}
        try:
            plaintext = self._require_secret_store().decrypt(
                bytes(blob),
                f"account:{account_id}:runtime-identity:v1",
            )
            value = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise DatabaseError("account runtime identity is invalid") from exc
        return _validate_account_runtime_identity(value)

    def get_account_network_identity(self, account_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT runtime_identity_blob FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("account not found")
        return self._decode_account_network_identity(
            account_id,
            row["runtime_identity_blob"],
        )

    def ensure_account_network_identity(
        self,
        account_id: str,
        *,
        proxy_sid: str,
    ) -> dict[str, Any]:
        candidate = _validate_account_runtime_identity(
            {
                "version": _ACCOUNT_RUNTIME_IDENTITY_VERSION,
                "proxy_sid": proxy_sid,
            }
        )
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT runtime_identity_blob FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("account not found")
            existing = self._decode_account_network_identity(
                account_id,
                row["runtime_identity_blob"],
            )
            if existing:
                return existing
            ciphertext = self._require_secret_store().encrypt(
                _json_bytes(candidate),
                f"account:{account_id}:runtime-identity:v1",
            )
            connection.execute(
                """
                UPDATE accounts
                SET runtime_identity_blob = ?, updated_at = ?
                WHERE id = ?
                """,
                (sqlite3.Binary(ciphertext), _now(), account_id),
            )
            return candidate

    def merge_account_network_identity(
        self,
        account_id: str,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(updates, Mapping):
            raise ValidationError("account runtime identity update is invalid")
        update_values = dict(updates)
        if set(update_values) - _ACCOUNT_RUNTIME_IDENTITY_KEYS:
            raise ValidationError("account runtime identity update contains unsupported fields")
        update_values.pop("version", None)
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT runtime_identity_blob FROM accounts WHERE id = ?",
                (account_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("account not found")
            identity = self._decode_account_network_identity(
                account_id,
                row["runtime_identity_blob"],
            )
            if not identity:
                raise StateConflictError("account runtime identity has not been initialized")
            for key, value in update_values.items():
                existing = identity.get(key, _UNSET)
                if existing is not _UNSET and existing != value:
                    raise StateConflictError(
                        f"account runtime identity {key} is immutable"
                    )
                identity[key] = value
            validated = _validate_account_runtime_identity(identity)
            ciphertext = self._require_secret_store().encrypt(
                _json_bytes(validated),
                f"account:{account_id}:runtime-identity:v1",
            )
            connection.execute(
                """
                UPDATE accounts
                SET runtime_identity_blob = ?, updated_at = ?
                WHERE id = ?
                """,
                (sqlite3.Binary(ciphertext), _now(), account_id),
            )
            return validated

    def transition_account_status(self, account_id: str, new_status: str) -> dict[str, Any]:
        if new_status not in {"available", "disabled", "retired"}:
            raise ValidationError("manual account status is invalid")
        allowed = {
            "available": {"disabled", "retired"},
            "disabled": {"available", "retired"},
            "exited_pending": {"available", "retired"},
        }
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT status FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("account not found")
            current = str(row["status"])
            if current == new_status:
                return self.get_account(account_id)
            if new_status not in allowed.get(current, set()):
                raise StateConflictError(
                    f"account cannot transition from {current} to {new_status}"
                )
            connection.execute(
                "UPDATE accounts SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, _now(), account_id),
            )
        return self.get_account(account_id)

    @staticmethod
    def _workspace_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "name": str(row["name"]),
            "workspace_uid": str(row["workspace_uid"]),
            "current_account_id": str(row["current_account_id"]),
            "next_account_id": (
                None if row["next_account_id"] is None else str(row["next_account_id"])
            ),
            "status": str(row["status"]),
            "last_run_id": None if row["last_run_id"] is None else str(row["last_run_id"]),
            "rotation_count": int(row["rotation_count"]),
            "version": int(row["version"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def _account_statuses(
        self, connection: sqlite3.Connection, account_ids: set[str]
    ) -> dict[str, str]:
        if not account_ids:
            return {}
        placeholders = ",".join("?" for _ in account_ids)
        rows = connection.execute(
            f"SELECT id, status FROM accounts WHERE id IN ({placeholders})",
            tuple(account_ids),
        ).fetchall()
        statuses = {str(row["id"]): str(row["status"]) for row in rows}
        if len(statuses) != len(account_ids):
            raise NotFoundError("account not found")
        return statuses

    def _resolve_account_selection_tx(
        self,
        connection: sqlite3.Connection,
        *,
        account_id: str | None,
        inventory_id: str | None,
        required: bool,
        role: str,
    ) -> str | None:
        clean_account_id = str(account_id).strip() if account_id else None
        clean_inventory_id = str(inventory_id).strip() if inventory_id else None
        if clean_account_id and clean_inventory_id:
            raise ValidationError(
                f"{role}_account_id and {role}_inventory_id are mutually exclusive"
            )
        if clean_inventory_id:
            account = self._allocate_alias_tx(
                connection, inventory_id=clean_inventory_id
            )
            if account is None:
                raise InventoryExhaustedError("mailbox inventory is exhausted")
            return str(account["id"])
        if clean_account_id:
            return clean_account_id
        if required:
            raise ValidationError(
                f"{role}_account_id or {role}_inventory_id is required"
            )
        return None

    def create_workspace(
        self,
        *,
        name: str,
        workspace_uid: str,
        current_account_id: str | None = None,
        next_account_id: str | None = None,
        current_inventory_id: str | None = None,
        next_inventory_id: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, Any]:
        workspace_id = _identifier(workspace_id)
        name = _required_text(name, "name")
        workspace_uid = _required_text(workspace_uid, "workspace_uid")
        timestamp = _now()
        with self._write_transaction() as connection:
            current_account_id = self._resolve_account_selection_tx(
                connection,
                account_id=current_account_id,
                inventory_id=current_inventory_id,
                required=True,
                role="current",
            )
            next_account_id = self._resolve_account_selection_tx(
                connection,
                account_id=next_account_id,
                inventory_id=next_inventory_id,
                required=False,
                role="next",
            )
            if next_account_id == current_account_id:
                raise BindingConflictError("current and next account must differ")
            account_ids = {str(current_account_id)}
            if next_account_id:
                account_ids.add(next_account_id)
            statuses = self._account_statuses(connection, account_ids)
            unavailable = [key for key, value in statuses.items() if value != "available"]
            if unavailable:
                raise BindingConflictError("account is not available")
            connection.execute(
                """
                INSERT INTO workspaces(
                    id, name, workspace_uid, current_account_id, next_account_id,
                    status, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id,
                    name,
                    workspace_uid,
                    current_account_id,
                    next_account_id,
                    "ready" if next_account_id else "needs_account",
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                (timestamp, current_account_id),
            )
            if next_account_id:
                connection.execute(
                    "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                    (timestamp, next_account_id),
                )
        return self.get_workspace(workspace_id)

    def get_workspace(self, workspace_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("workspace not found")
        return self._workspace_view(row)

    def list_workspaces(self) -> list[dict[str, Any]]:
        with self._read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM workspaces ORDER BY name COLLATE NOCASE, id"
            ).fetchall()
        return [self._workspace_view(row) for row in rows]

    def update_workspace_bindings(
        self,
        workspace_id: str,
        *,
        current_account_id: str | None = None,
        next_account_id: str | None = None,
        current_inventory_id: str | None = None,
        next_inventory_id: str | None = None,
        expected_version: int,
        name: str | None = None,
    ) -> dict[str, Any]:
        timestamp = _now()
        with self._write_transaction() as connection:
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise NotFoundError("workspace not found")
            if int(workspace["version"]) != int(expected_version):
                raise StaleVersionError("workspace version is stale")
            if workspace["status"] in {"queued", "running"}:
                raise WorkspaceActiveError(
                    "active workspace bindings cannot be changed"
                )

            current_account_id = self._resolve_account_selection_tx(
                connection,
                account_id=current_account_id,
                inventory_id=current_inventory_id,
                required=True,
                role="current",
            )
            next_account_id = self._resolve_account_selection_tx(
                connection,
                account_id=next_account_id,
                inventory_id=next_inventory_id,
                required=False,
                role="next",
            )
            if current_account_id == next_account_id:
                raise BindingConflictError("current and next account must differ")

            old_ids = {
                str(workspace["current_account_id"]),
                *(
                    []
                    if workspace["next_account_id"] is None
                    else [str(workspace["next_account_id"])]
                ),
            }
            new_ids = {current_account_id}
            if next_account_id:
                new_ids.add(next_account_id)
            statuses = self._account_statuses(connection, new_ids)
            for account_id in new_ids - old_ids:
                if statuses[account_id] != "available":
                    raise BindingConflictError("account is not available")

            cursor = connection.execute(
                """
                UPDATE workspaces SET
                    name = ?, current_account_id = ?, next_account_id = ?, status = ?,
                    version = version + 1, updated_at = ?
                WHERE id = ? AND version = ?
                """,
                (
                    _required_text(name, "name") if name is not None else workspace["name"],
                    current_account_id,
                    next_account_id,
                    "ready" if next_account_id else "needs_account",
                    timestamp,
                    workspace_id,
                    int(expected_version),
                ),
            )
            if cursor.rowcount != 1:
                raise StaleVersionError("workspace version is stale")

            for account_id in old_ids - new_ids:
                connection.execute(
                    """
                    UPDATE accounts SET status = 'available', updated_at = ?
                    WHERE id = ? AND status IN ('bound_current', 'bound_next')
                    """,
                    (timestamp, account_id),
                )
            connection.execute(
                "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                (timestamp, current_account_id),
            )
            if next_account_id:
                connection.execute(
                    "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                    (timestamp, next_account_id),
                )
        return self.get_workspace(workspace_id)

    def update_workspace(
        self,
        workspace_id: str,
        *,
        expected_version: int,
        name: str | None = None,
        current_account_id: str | None = None,
        next_account_id: str | None | object = _UNSET,
        current_inventory_id: str | None = None,
        next_inventory_id: str | None = None,
    ) -> dict[str, Any]:
        workspace = self.get_workspace(workspace_id)
        if int(workspace["version"]) != int(expected_version):
            raise StaleVersionError("workspace version is stale")

        effective_name = workspace["name"] if name is None else _required_text(name, "name")
        effective_current = (
            None
            if current_inventory_id
            else current_account_id or workspace["current_account_id"]
        )
        effective_next = (
            None
            if next_inventory_id
            else workspace["next_account_id"]
            if next_account_id is _UNSET
            else next_account_id
        )
        bindings_changed = (
            current_inventory_id is not None
            or next_inventory_id is not None
            or effective_current != workspace["current_account_id"]
            or effective_next != workspace["next_account_id"]
        )
        if bindings_changed:
            return self.update_workspace_bindings(
                workspace_id,
                current_account_id=(
                    None if effective_current is None else str(effective_current)
                ),
                next_account_id=(None if effective_next is None else str(effective_next)),
                current_inventory_id=current_inventory_id,
                next_inventory_id=next_inventory_id,
                expected_version=expected_version,
                name=effective_name,
            )
        if effective_name == workspace["name"]:
            return workspace

        with self._write_transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE workspaces SET name = ?, version = version + 1, updated_at = ?
                WHERE id = ? AND version = ?
                """,
                (effective_name, _now(), workspace_id, int(expected_version)),
            )
            if cursor.rowcount != 1:
                raise StaleVersionError("workspace version is stale")
        return self.get_workspace(workspace_id)

    @staticmethod
    def _run_view(row: sqlite3.Row) -> dict[str, Any]:
        result = None
        if row["result_json"] is not None:
            result = json.loads(str(row["result_json"]))
        return {
            "id": str(row["id"]),
            "workspace_id": str(row["workspace_id"]),
            "current_account_id": str(row["current_account_id"]),
            "next_account_id": str(row["next_account_id"]),
            "current_email_snapshot": str(row["current_email_snapshot"]),
            "next_email_snapshot": str(row["next_email_snapshot"]),
            "workspace_uid_snapshot": str(row["workspace_uid_snapshot"]),
            "state": str(row["state"]),
            "current_step": None if row["current_step"] is None else str(row["current_step"]),
            "checkpoint_configured": row["checkpoint_blob"] is not None,
            "proxy_configured": row["proxy_blob"] is not None,
            "result": result,
            "redacted_error": (
                None if row["redacted_error"] is None else str(row["redacted_error"])
            ),
            "created_at": str(row["created_at"]),
            "started_at": None if row["started_at"] is None else str(row["started_at"]),
            "finished_at": None if row["finished_at"] is None else str(row["finished_at"]),
        }

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._read_connection() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise NotFoundError("run not found")
        return self._run_view(row)

    def list_runs(
        self,
        *,
        workspace_id: str | None = None,
        state: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if state is not None and state not in RUN_STATES:
            raise ValidationError("run state is invalid")
        clauses: list[str] = []
        values: list[Any] = []
        if workspace_id is not None:
            clauses.append("workspace_id = ?")
            values.append(workspace_id)
        if state is not None:
            clauses.append("state = ?")
            values.append(state)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(max(1, min(int(limit), 1000)))
        with self._read_connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM runs{where} ORDER BY created_at DESC, id DESC LIMIT ?",
                values,
            ).fetchall()
        return [self._run_view(row) for row in rows]

    def enqueue_workspaces(self, workspace_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        ordered_ids = [_required_text(value, "workspace_id") for value in workspace_ids]
        if not ordered_ids:
            raise ValidationError("at least one workspace is required")
        if len(set(ordered_ids)) != len(ordered_ids):
            raise ValidationError("workspace IDs must be unique")
        created: list[tuple[str, str, int]] = []
        timestamp = _now()
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(position), -1) AS position FROM queue_items WHERE state IN ('pending', 'running')"
            ).fetchone()
            position = int(row["position"]) + 1
            for workspace_id in ordered_ids:
                workspace = connection.execute(
                    "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
                ).fetchone()
                if workspace is None:
                    raise NotFoundError("workspace not found")
                if workspace["status"] != "ready" or workspace["next_account_id"] is None:
                    raise StateConflictError("workspace is not ready")
                current = connection.execute(
                    "SELECT email, status FROM accounts WHERE id = ?",
                    (workspace["current_account_id"],),
                ).fetchone()
                next_account = connection.execute(
                    "SELECT email, status FROM accounts WHERE id = ?",
                    (workspace["next_account_id"],),
                ).fetchone()
                if (
                    current is None
                    or next_account is None
                    or current["status"] != "bound_current"
                    or next_account["status"] != "bound_next"
                ):
                    raise StateConflictError("workspace account roles are inconsistent")
                run_id = str(uuid.uuid4())
                queue_item_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO runs(
                        id, workspace_id, current_account_id, next_account_id,
                        current_email_snapshot, next_email_snapshot,
                        workspace_uid_snapshot, state, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, 'queued', ?)
                    """,
                    (
                        run_id,
                        workspace_id,
                        workspace["current_account_id"],
                        workspace["next_account_id"],
                        current["email"],
                        next_account["email"],
                        workspace["workspace_uid"],
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO queue_items(id, run_id, position, state, created_at)
                    VALUES(?, ?, ?, 'pending', ?)
                    """,
                    (queue_item_id, run_id, position, timestamp),
                )
                connection.execute(
                    """
                    UPDATE workspaces SET status = 'queued', last_run_id = ?,
                        version = version + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (run_id, timestamp, workspace_id),
                )
                created.append((run_id, queue_item_id, position))
                position += 1
        results: list[dict[str, Any]] = []
        for run_id, queue_item_id, item_position in created:
            run = self.get_run(run_id)
            run["queue_item_id"] = queue_item_id
            run["position"] = item_position
            results.append(run)
        return results

    def enqueue_workspace(self, workspace_id: str) -> dict[str, Any]:
        return self.enqueue_workspaces([workspace_id])[0]

    def set_run_checkpoint(
        self, run_id: str, checkpoint: Mapping[str, Any], *, current_step: str | None = None
    ) -> None:
        ciphertext = self._require_secret_store().encrypt(
            _json_bytes(checkpoint), f"run:{run_id}:checkpoint"
        )
        with self._write_transaction() as connection:
            row = connection.execute("SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise NotFoundError("run not found")
            if row["state"] not in {"queued", "running", "stopping"}:
                raise StateConflictError("terminal run checkpoint cannot be changed")
            connection.execute(
                "UPDATE runs SET checkpoint_blob = ?, current_step = COALESCE(?, current_step) WHERE id = ?",
                (sqlite3.Binary(ciphertext), current_step, run_id),
            )

    def get_run_checkpoint(self, run_id: str) -> dict[str, Any] | None:
        with self._read_connection() as connection:
            row = connection.execute(
                "SELECT checkpoint_blob FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("run not found")
        if row["checkpoint_blob"] is None:
            return None
        plaintext = self._require_secret_store().decrypt(
            bytes(row["checkpoint_blob"]), f"run:{run_id}:checkpoint"
        )
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise DatabaseError("run checkpoint is invalid")
        return value

    def set_run_proxy(self, run_id: str, proxy: str) -> None:
        plaintext = str(proxy).encode("utf-8")
        purpose = f"run:{run_id}:proxy"
        ciphertext = self._require_secret_store().encrypt(plaintext, purpose)
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT state, proxy_blob FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("run not found")
            if row["proxy_blob"] is not None:
                existing = self._require_secret_store().decrypt(bytes(row["proxy_blob"]), purpose)
                if existing != plaintext:
                    raise StateConflictError("run proxy is immutable")
                return
            if row["state"] not in {"queued", "running", "stopping"}:
                raise StateConflictError("terminal run proxy cannot be changed")
            connection.execute(
                "UPDATE runs SET proxy_blob = ? WHERE id = ?",
                (sqlite3.Binary(ciphertext), run_id),
            )

    def get_run_proxy(self, run_id: str) -> str | None:
        with self._read_connection() as connection:
            row = connection.execute("SELECT proxy_blob FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise NotFoundError("run not found")
        if row["proxy_blob"] is None:
            return None
        plaintext = self._require_secret_store().decrypt(
            bytes(row["proxy_blob"]), f"run:{run_id}:proxy"
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def _queue_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "run_id": str(row["run_id"]),
            "workspace_id": str(row["workspace_id"]),
            "position": int(row["position"]),
            "state": str(row["state"]),
            "run_state": str(row["run_state"]),
            "created_at": str(row["created_at"]),
            "started_at": None if row["started_at"] is None else str(row["started_at"]),
            "finished_at": None if row["finished_at"] is None else str(row["finished_at"]),
        }

    @staticmethod
    def _queue_select() -> str:
        return """
            SELECT q.id, q.run_id, q.position, q.state, q.created_at,
                   q.started_at, q.finished_at, r.workspace_id, r.state AS run_state
            FROM queue_items AS q JOIN runs AS r ON r.id = q.run_id
        """

    def list_queue(self, *, include_terminal: bool = False) -> list[dict[str, Any]]:
        where = "" if include_terminal else " WHERE q.state IN ('pending', 'running')"
        with self._read_connection() as connection:
            rows = connection.execute(
                self._queue_select()
                + where
                + " ORDER BY CASE q.state WHEN 'running' THEN 0 ELSE 1 END, q.position, q.created_at"
            ).fetchall()
        return [self._queue_view(row) for row in rows]

    def is_queue_paused(self) -> bool:
        return self.get_meta("queue_paused") == "1"

    def set_queue_paused(self, paused: bool) -> bool:
        self.set_meta("queue_paused", "1" if paused else "0")
        return bool(paused)

    def claim_next_queue_item(self) -> dict[str, Any] | None:
        claimed_id: str | None = None
        timestamp = _now()
        with self._write_transaction() as connection:
            paused = connection.execute(
                "SELECT value FROM app_meta WHERE key = 'queue_paused'"
            ).fetchone()
            if paused is not None and paused["value"] == "1":
                return None
            if connection.execute(
                "SELECT 1 FROM queue_items WHERE state = 'running'"
            ).fetchone() is not None:
                return None
            row = connection.execute(
                """
                SELECT q.id, q.run_id, r.workspace_id
                FROM queue_items AS q
                JOIN runs AS r ON r.id = q.run_id
                JOIN workspaces AS w ON w.id = r.workspace_id
                WHERE q.state = 'pending' AND r.state = 'queued' AND w.status = 'queued'
                ORDER BY q.position, q.created_at, q.id LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None
            claimed_id = str(row["id"])
            connection.execute(
                "UPDATE queue_items SET state = 'running', started_at = ? WHERE id = ?",
                (timestamp, claimed_id),
            )
            connection.execute(
                "UPDATE runs SET state = 'running', started_at = COALESCE(started_at, ?) WHERE id = ?",
                (timestamp, row["run_id"]),
            )
            connection.execute(
                "UPDATE workspaces SET status = 'running', version = version + 1, updated_at = ? WHERE id = ?",
                (timestamp, row["workspace_id"]),
            )
        with self._read_connection() as connection:
            row = connection.execute(
                self._queue_select() + " WHERE q.id = ?", (claimed_id,)
            ).fetchone()
        return None if row is None else self._queue_view(row)

    def reorder_queue(self, queue_item_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        ordered = [str(value) for value in queue_item_ids]
        if len(set(ordered)) != len(ordered):
            raise ValidationError("queue item IDs must be unique")
        with self._write_transaction() as connection:
            rows = connection.execute(
                "SELECT id FROM queue_items WHERE state = 'pending' ORDER BY position"
            ).fetchall()
            pending = [str(row["id"]) for row in rows]
            if set(ordered) != set(pending) or len(ordered) != len(pending):
                raise StateConflictError("queue order must contain every pending item")
            if ordered:
                maximum = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(position), 0) FROM queue_items"
                    ).fetchone()[0]
                )
                temporary_base = maximum + len(ordered) + 1
                for index, item_id in enumerate(ordered):
                    connection.execute(
                        "UPDATE queue_items SET position = ? WHERE id = ?",
                        (temporary_base + index, item_id),
                    )
                running = connection.execute(
                    "SELECT position FROM queue_items WHERE state = 'running'"
                ).fetchone()
                start = int(running["position"]) + 1 if running is not None else 0
                for index, item_id in enumerate(ordered):
                    connection.execute(
                        "UPDATE queue_items SET position = ? WHERE id = ?",
                        (start + index, item_id),
                    )
        return self.list_queue()

    def request_stop(self, run_id: str) -> str:
        timestamp = _now()
        with self._write_transaction() as connection:
            run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            state = str(run["state"])
            if state == "queued":
                queue = connection.execute(
                    "SELECT state FROM queue_items WHERE run_id = ?", (run_id,)
                ).fetchone()
                if queue is None or queue["state"] != "pending":
                    raise StateConflictError("queued run has no pending queue item")
                connection.execute(
                    "UPDATE runs SET state = 'cancelled', finished_at = ? WHERE id = ?",
                    (timestamp, run_id),
                )
                connection.execute(
                    "UPDATE queue_items SET state = 'cancelled', finished_at = ? WHERE run_id = ?",
                    (timestamp, run_id),
                )
                connection.execute(
                    "UPDATE workspaces SET status = 'ready', version = version + 1, updated_at = ? WHERE id = ?",
                    (timestamp, run["workspace_id"]),
                )
                return "cancelled"
            if state == "running":
                connection.execute("UPDATE runs SET state = 'stopping' WHERE id = ?", (run_id,))
                return "stopping"
            if state == "stopping":
                return "stopping"
            return state

    def mark_run_cancelled(self, run_id: str) -> dict[str, Any]:
        timestamp = _now()
        with self._write_transaction() as connection:
            run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            if run["state"] == "cancelled":
                return self.get_run(run_id)
            if run["state"] not in {"running", "stopping"}:
                raise StateConflictError("run cannot be cancelled")
            connection.execute(
                "UPDATE runs SET state = 'cancelled', finished_at = ? WHERE id = ?",
                (timestamp, run_id),
            )
            connection.execute(
                "UPDATE queue_items SET state = 'cancelled', finished_at = ? WHERE run_id = ? AND state = 'running'",
                (timestamp, run_id),
            )
            connection.execute(
                "UPDATE workspaces SET status = 'ready', version = version + 1, updated_at = ? WHERE id = ?",
                (timestamp, run["workspace_id"]),
            )
        return self.get_run(run_id)

    def fail_run(self, run_id: str, redacted_error: str) -> dict[str, Any]:
        timestamp = _now()
        safe_error = str(redacted_error)[:4000]
        with self._write_transaction() as connection:
            run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            if run["state"] == "failed":
                return self.get_run(run_id)
            if run["state"] not in {"running", "stopping"}:
                raise StateConflictError("run cannot fail from its current state")
            connection.execute(
                "UPDATE runs SET state = 'failed', redacted_error = ?, finished_at = ? WHERE id = ?",
                (safe_error, timestamp, run_id),
            )
            connection.execute(
                "UPDATE queue_items SET state = 'failed', finished_at = ? WHERE run_id = ? AND state = 'running'",
                (timestamp, run_id),
            )
            connection.execute(
                "UPDATE workspaces SET status = 'failed', version = version + 1, updated_at = ? WHERE id = ?",
                (timestamp, run["workspace_id"]),
            )
        return self.get_run(run_id)

    def recover_interrupted_runs(self) -> list[str]:
        recovered: list[str] = []
        timestamp = _now()
        with self._write_transaction() as connection:
            rows = connection.execute(
                """
                SELECT r.id, r.workspace_id FROM runs AS r
                JOIN queue_items AS q ON q.run_id = r.id
                WHERE r.state IN ('running', 'stopping') AND q.state = 'running'
                ORDER BY q.position
                """
            ).fetchall()
            for row in rows:
                run_id = str(row["id"])
                connection.execute(
                    "UPDATE runs SET state = 'queued', started_at = NULL WHERE id = ?",
                    (run_id,),
                )
                connection.execute(
                    "UPDATE queue_items SET state = 'pending', started_at = NULL WHERE run_id = ?",
                    (run_id,),
                )
                connection.execute(
                    "UPDATE workspaces SET status = 'queued', version = version + 1, updated_at = ? WHERE id = ?",
                    (timestamp, row["workspace_id"]),
                )
                recovered.append(run_id)
        return recovered

    def retry_run(self, run_id: str) -> dict[str, Any]:
        timestamp = _now()
        with self._write_transaction() as connection:
            run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            if run["state"] != "failed":
                raise StateConflictError("only failed runs can be retried")
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (run["workspace_id"],)
            ).fetchone()
            if (
                workspace is None
                or workspace["current_account_id"] != run["current_account_id"]
                or workspace["next_account_id"] != run["next_account_id"]
            ):
                raise StateConflictError("workspace bindings no longer match the run snapshot")
            if connection.execute(
                """
                SELECT 1 FROM queue_items AS q JOIN runs AS active ON active.id = q.run_id
                WHERE active.workspace_id = ? AND q.state IN ('pending', 'running')
                """,
                (run["workspace_id"],),
            ).fetchone() is not None:
                raise StateConflictError("workspace already has an active queue item")
            position = int(
                connection.execute(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM queue_items WHERE state IN ('pending', 'running')"
                ).fetchone()[0]
            )
            connection.execute(
                """
                UPDATE runs SET state = 'queued', started_at = NULL, finished_at = NULL,
                    redacted_error = NULL WHERE id = ?
                """,
                (run_id,),
            )
            cursor = connection.execute(
                """
                UPDATE queue_items SET state = 'pending', position = ?, started_at = NULL,
                    finished_at = NULL WHERE run_id = ? AND state = 'failed'
                """,
                (position, run_id),
            )
            if cursor.rowcount != 1:
                raise StateConflictError("failed queue item is missing")
            connection.execute(
                "UPDATE workspaces SET status = 'queued', version = version + 1, updated_at = ? WHERE id = ?",
                (timestamp, run["workspace_id"]),
            )
        return self.get_run(run_id)

    def _before_rotation_commit(self, connection: sqlite3.Connection, run_id: str) -> None:
        del connection, run_id

    @staticmethod
    def _set_allocation_state_tx(
        connection: sqlite3.Connection,
        account_id: str,
        state: str,
        timestamp: str,
    ) -> None:
        if state not in MAILBOX_ALLOCATION_STATES:
            raise ValidationError("mailbox allocation state is invalid")
        connection.execute(
            """
            UPDATE mailbox_alias_allocations
            SET state = ?, updated_at = ? WHERE account_id = ?
            """,
            (state, timestamp, account_id),
        )

    def complete_run_and_rotate(
        self, run_id: str, result: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        timestamp = _now()
        result_json = (
            None
            if result is None
            else json.dumps(dict(result), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        )
        with self._write_transaction() as connection:
            run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (run["workspace_id"],)
            ).fetchone()
            queue = connection.execute(
                "SELECT * FROM queue_items WHERE run_id = ?", (run_id,)
            ).fetchone()
            if workspace is None or queue is None:
                raise StateConflictError("run ownership is incomplete")
            if run["state"] == "succeeded":
                if not (
                    queue["state"] == "completed"
                    and workspace["current_account_id"] == run["next_account_id"]
                    and workspace["last_run_id"] == run_id
                ):
                    raise StateConflictError("successful run rotation is inconsistent")
                return self.get_run(run_id)
            if run["state"] not in {"running", "stopping"} or queue["state"] != "running":
                raise StateConflictError("run is not active")
            if (
                workspace["current_account_id"] != run["current_account_id"]
                or workspace["next_account_id"] != run["next_account_id"]
            ):
                raise StateConflictError("workspace bindings no longer match the run snapshot")
            accounts = self._account_statuses(
                connection, {str(run["current_account_id"]), str(run["next_account_id"])}
            )
            if (
                accounts[str(run["current_account_id"])] != "bound_current"
                or accounts[str(run["next_account_id"])] != "bound_next"
            ):
                raise StateConflictError("account roles no longer match the run snapshot")
            connection.execute(
                "UPDATE accounts SET status = 'exited_pending', updated_at = ? WHERE id = ?",
                (timestamp, run["current_account_id"]),
            )
            self._set_allocation_state_tx(
                connection, str(run["current_account_id"]), "retired", timestamp
            )
            connection.execute(
                "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                (timestamp, run["next_account_id"]),
            )
            promoted = connection.execute(
                "SELECT email, primary_email FROM accounts WHERE id = ?",
                (run["next_account_id"],),
            ).fetchone()
            if promoted is None:
                raise StateConflictError("promoted account is missing")
            promoted_alias_number = _alias_number(
                str(promoted["email"]), str(promoted["primary_email"])
            )
            replacement = self._claim_replacement_account_tx(
                connection,
                preferred_primary_email=str(promoted["primary_email"]),
                after_alias_number=promoted_alias_number,
            )
            replacement_id = None if replacement is None else str(replacement["id"])
            if replacement_id is not None:
                if replacement["status"] != "available":
                    raise StateConflictError("replacement account is not available")
                connection.execute(
                    "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                    (timestamp, replacement_id),
                )
            connection.execute(
                """
                UPDATE workspaces SET current_account_id = ?, next_account_id = ?,
                    status = ?, last_run_id = ?,
                    rotation_count = rotation_count + 1, version = version + 1,
                    updated_at = ? WHERE id = ?
                """,
                (
                    run["next_account_id"],
                    replacement_id,
                    "ready" if replacement_id is not None else "needs_account",
                    run_id,
                    timestamp,
                    run["workspace_id"],
                ),
            )
            connection.execute(
                "UPDATE runs SET state = 'succeeded', result_json = ?, finished_at = ? WHERE id = ?",
                (result_json, timestamp, run_id),
            )
            connection.execute(
                "UPDATE queue_items SET state = 'completed', finished_at = ? WHERE run_id = ?",
                (timestamp, run_id),
            )
            self._before_rotation_commit(connection, run_id)
        return self.get_run(run_id)

    def advance_workspace_accounts(
        self,
        workspace_id: str,
        *,
        expected_version: int,
    ) -> dict[str, Any]:
        """Record an account switch completed outside the managed workflow."""
        timestamp = _now()
        previous_id: str
        current_id: str
        replacement_id: str | None
        with self._write_transaction() as connection:
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise NotFoundError("workspace not found")
            if workspace["status"] in {"queued", "running"}:
                raise WorkspaceActiveError(
                    "active workspace bindings cannot be changed"
                )
            if int(workspace["version"]) != int(expected_version):
                raise StaleVersionError("workspace version is stale")
            if workspace["next_account_id"] is None:
                raise NoReplacementAccountError(
                    "workspace has no next account to promote"
                )

            previous_id = str(workspace["current_account_id"])
            current_id = str(workspace["next_account_id"])
            statuses = self._account_statuses(
                connection, {previous_id, current_id}
            )
            if (
                statuses.get(previous_id) != "bound_current"
                or statuses.get(current_id) != "bound_next"
            ):
                raise StateConflictError("workspace account roles are inconsistent")

            connection.execute(
                "UPDATE accounts SET status = 'exited_pending', updated_at = ? WHERE id = ?",
                (timestamp, previous_id),
            )
            self._set_allocation_state_tx(
                connection, previous_id, "retired", timestamp
            )
            connection.execute(
                "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                (timestamp, current_id),
            )
            promoted = connection.execute(
                "SELECT email, primary_email FROM accounts WHERE id = ?",
                (current_id,),
            ).fetchone()
            if promoted is None:
                raise StateConflictError("promoted account is missing")
            replacement = self._claim_replacement_account_tx(
                connection,
                preferred_primary_email=str(promoted["primary_email"]),
                after_alias_number=_alias_number(
                    str(promoted["email"]), str(promoted["primary_email"])
                ),
            )
            replacement_id = (
                None if replacement is None else str(replacement["id"])
            )
            if replacement_id is not None:
                if replacement["status"] != "available":
                    raise StateConflictError("replacement account is not available")
                connection.execute(
                    "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                    (timestamp, replacement_id),
                )
            connection.execute(
                """
                UPDATE workspaces
                SET current_account_id = ?, next_account_id = ?, status = ?,
                    rotation_count = rotation_count + 1,
                    version = version + 1, updated_at = ?
                WHERE id = ?
                """,
                (
                    current_id,
                    replacement_id,
                    "ready" if replacement_id is not None else "needs_account",
                    timestamp,
                    workspace_id,
                ),
            )

        return {
            "workspace": self.get_workspace(workspace_id),
            "previous": self.get_account(previous_id),
            "current": self.get_account(current_id),
            "replacement": (
                None if replacement_id is None else self.get_account(replacement_id)
            ),
        }

    def _replace_workspace_account_tx(
        self,
        connection: sqlite3.Connection,
        workspace: sqlite3.Row,
        *,
        role: str,
        failure_code: str,
        timestamp: str,
        allow_missing_current: bool = False,
    ) -> str | None:
        if role not in {"current", "next"}:
            raise ValidationError("workspace account role is invalid")
        if failure_code not in IDENTITY_FAILURE_CODES:
            raise ValidationError("identity failure code is invalid")
        target_id = (
            str(workspace["current_account_id"])
            if role == "current"
            else None
            if workspace["next_account_id"] is None
            else str(workspace["next_account_id"])
        )
        if target_id is None:
            raise StateConflictError("workspace role has no account")
        target = connection.execute(
            "SELECT * FROM accounts WHERE id = ?", (target_id,)
        ).fetchone()
        if target is None:
            raise StateConflictError("workspace account is missing")
        inventory = connection.execute(
            """
            SELECT * FROM mailbox_inventory
            WHERE primary_email = ? COLLATE NOCASE
            """,
            (target["primary_email"],),
        ).fetchone()

        connection.execute(
            "UPDATE accounts SET status = 'disabled', updated_at = ? WHERE id = ?",
            (timestamp, target_id),
        )
        self._set_allocation_state_tx(
            connection, target_id, "disabled", timestamp
        )
        if failure_code == "mailbox_credentials_invalid" and inventory is not None:
            connection.execute(
                """
                UPDATE mailbox_inventory
                SET status = 'disabled', failure_code = ?,
                    failure_message = NULL, updated_at = ?
                WHERE id = ?
                """,
                (failure_code, timestamp, inventory["id"]),
            )

        if role == "current":
            promoted_id = (
                None
                if workspace["next_account_id"] is None
                else str(workspace["next_account_id"])
            )
            if promoted_id is not None and failure_code == "mailbox_credentials_invalid":
                promoted = connection.execute(
                    "SELECT primary_email FROM accounts WHERE id = ?", (promoted_id,)
                ).fetchone()
                if (
                    promoted is not None
                    and str(promoted["primary_email"]).casefold()
                    == str(target["primary_email"]).casefold()
                ):
                    connection.execute(
                        "UPDATE accounts SET status = 'disabled', updated_at = ? WHERE id = ?",
                        (timestamp, promoted_id),
                    )
                    self._set_allocation_state_tx(
                        connection, promoted_id, "disabled", timestamp
                    )
                    promoted_id = None
            if promoted_id is None:
                promoted_account = self._claim_replacement_account_tx(connection)
                if promoted_account is None:
                    if not allow_missing_current:
                        raise NoReplacementAccountError(
                            "no replacement account is available"
                        )
                    current_id = target_id
                    replacement = None
                else:
                    promoted_id = str(promoted_account["id"])
            if promoted_id is not None:
                connection.execute(
                    "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                    (timestamp, promoted_id),
                )
                promoted = connection.execute(
                    "SELECT email, primary_email FROM accounts WHERE id = ?",
                    (promoted_id,),
                ).fetchone()
                if promoted is None:
                    raise StateConflictError("promoted account is missing")
                replacement = self._claim_replacement_account_tx(
                    connection,
                    preferred_primary_email=str(promoted["primary_email"]),
                    after_alias_number=_alias_number(
                        str(promoted["email"]), str(promoted["primary_email"])
                    ),
                )
                current_id = promoted_id
        else:
            current_id = str(workspace["current_account_id"])
            current = connection.execute(
                "SELECT email, primary_email FROM accounts WHERE id = ?", (current_id,)
            ).fetchone()
            if current is None:
                raise StateConflictError("current account is missing")
            replacement = self._claim_replacement_account_tx(
                connection,
                preferred_primary_email=str(current["primary_email"]),
                after_alias_number=_alias_number(
                    str(current["email"]), str(current["primary_email"])
                ),
            )

        replacement_id = None if replacement is None else str(replacement["id"])
        if replacement_id is not None:
            if replacement["status"] != "available":
                raise StateConflictError("replacement account is not available")
            connection.execute(
                "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                (timestamp, replacement_id),
            )
        connection.execute(
            """
            UPDATE workspaces
            SET current_account_id = ?, next_account_id = ?, status = ?,
                version = version + 1, updated_at = ?
            WHERE id = ?
            """,
            (
                current_id,
                replacement_id,
                "ready" if replacement_id is not None else "needs_account",
                timestamp,
                workspace["id"],
            ),
        )
        return replacement_id

    def replace_workspace_account(
        self,
        workspace_id: str,
        *,
        role: str,
        failure_code: str,
        expected_version: int,
    ) -> dict[str, Any]:
        timestamp = _now()
        with self._write_transaction() as connection:
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise NotFoundError("workspace not found")
            if workspace["status"] in {"queued", "running"}:
                raise WorkspaceActiveError(
                    "active workspace bindings cannot be changed"
                )
            if int(workspace["version"]) != int(expected_version):
                raise StaleVersionError("workspace version is stale")
            replacement_id = self._replace_workspace_account_tx(
                connection,
                workspace,
                role=role,
                failure_code=failure_code,
                timestamp=timestamp,
            )
        return {
            "workspace": self.get_workspace(workspace_id),
            "replacement": (
                None if replacement_id is None else self.get_account(replacement_id)
            ),
            "role": role,
            "failure_code": failure_code,
        }

    def fail_run_and_replace_account(
        self,
        run_id: str,
        *,
        role: str,
        failure_code: str,
        redacted_error: str,
    ) -> dict[str, Any]:
        timestamp = _now()
        with self._write_transaction() as connection:
            run = connection.execute(
                "SELECT * FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise NotFoundError("run not found")
            queue = connection.execute(
                "SELECT * FROM queue_items WHERE run_id = ?", (run_id,)
            ).fetchone()
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id = ?", (run["workspace_id"],)
            ).fetchone()
            if queue is None or workspace is None:
                raise StateConflictError("run ownership is incomplete")
            if run["state"] not in {"running", "stopping"} or queue["state"] != "running":
                raise StateConflictError("run is not active")
            if (
                workspace["current_account_id"] != run["current_account_id"]
                or workspace["next_account_id"] != run["next_account_id"]
            ):
                raise StateConflictError(
                    "workspace bindings no longer match the run snapshot"
                )
            replacement_id = self._replace_workspace_account_tx(
                connection,
                workspace,
                role=role,
                failure_code=failure_code,
                timestamp=timestamp,
                allow_missing_current=True,
            )
            connection.execute(
                """
                UPDATE runs SET state = 'failed', redacted_error = ?, finished_at = ?
                WHERE id = ?
                """,
                (_required_text(redacted_error, "redacted_error"), timestamp, run_id),
            )
            connection.execute(
                """
                UPDATE queue_items SET state = 'failed', finished_at = ?
                WHERE run_id = ?
                """,
                (timestamp, run_id),
            )
        return {
            "run": self.get_run(run_id),
            "workspace": self.get_workspace(str(run["workspace_id"])),
            "replacement": (
                None if replacement_id is None else self.get_account(replacement_id)
            ),
        }

    def append_run_event(
        self,
        run_id: str,
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
    ) -> dict[str, Any]:
        level = _required_text(level, "level")
        message = _required_text(message, "message")
        timestamp = _now()
        with self._write_transaction() as connection:
            if connection.execute("SELECT 1 FROM runs WHERE id = ?", (run_id,)).fetchone() is None:
                raise NotFoundError("run not found")
            cursor = connection.execute(
                """
                INSERT INTO run_events(run_id, step, level, message, routine, created_at)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (run_id, step, level, message, int(routine), timestamp),
            )
            sequence = int(cursor.lastrowid)
        return {
            "seq": sequence,
            "run_id": run_id,
            "step": step,
            "level": level,
            "message": message,
            "routine": bool(routine),
            "created_at": timestamp,
        }

    def list_run_events(
        self,
        *,
        run_id: str | None = None,
        after_seq: int = 0,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses = ["seq > ?"]
        values: list[Any] = [max(0, int(after_seq))]
        if run_id is not None:
            clauses.append("run_id = ?")
            values.append(run_id)
        values.append(max(1, min(int(limit), 2000)))
        with self._read_connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM run_events WHERE {' AND '.join(clauses)} ORDER BY seq LIMIT ?",
                values,
            ).fetchall()
        return [
            {
                "seq": int(row["seq"]),
                "run_id": str(row["run_id"]),
                "step": None if row["step"] is None else str(row["step"]),
                "level": str(row["level"]),
                "message": str(row["message"]),
                "routine": bool(row["routine"]),
                "created_at": str(row["created_at"]),
            }
            for row in rows
        ]

    @staticmethod
    def _upsert_text_setting_row(
        connection: sqlite3.Connection,
        key: str,
        value: Any,
        timestamp: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO settings(key, value_text, value_blob, encrypted, updated_at)
            VALUES(?, ?, NULL, 0, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_text = excluded.value_text,
                value_blob = NULL,
                encrypted = 0,
                updated_at = excluded.updated_at
            """,
            (key, str(value), timestamp),
        )

    def _upsert_secret_setting_row(
        self,
        connection: sqlite3.Connection,
        key: str,
        value: str,
        timestamp: str,
    ) -> None:
        ciphertext = self._require_secret_store().encrypt(
            value.encode("utf-8"), f"setting:{key}"
        )
        connection.execute(
            """
            INSERT INTO settings(key, value_text, value_blob, encrypted, updated_at)
            VALUES(?, NULL, ?, 1, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_text = NULL,
                value_blob = excluded.value_blob,
                encrypted = 1,
                updated_at = excluded.updated_at
            """,
            (key, sqlite3.Binary(ciphertext), timestamp),
        )

    @staticmethod
    def _migration_result(
        connection: sqlite3.Connection, migration_id: str
    ) -> dict[str, Any]:
        rows = connection.execute(
            "SELECT key, value FROM app_meta WHERE key IN ('migration_status', 'migration_counts')"
        ).fetchall()
        metadata = {str(row["key"]): str(row["value"]) for row in rows}
        try:
            counts = json.loads(metadata.get("migration_counts", "{}"))
        except json.JSONDecodeError as exc:
            raise DatabaseError("migration metadata is invalid") from exc
        if not isinstance(counts, dict):
            raise DatabaseError("migration metadata is invalid")
        return {
            "migration_id": migration_id,
            "status": metadata.get("migration_status", "imported"),
            "counts": {str(key): int(value) for key, value in counts.items()},
        }

    def _before_legacy_import_commit(
        self, connection: sqlite3.Connection, migration_id: str
    ) -> None:
        del connection, migration_id

    def apply_legacy_import(self, model: Any) -> dict[str, Any]:
        migration_id = _required_text(getattr(model, "migration_id", ""), "migration_id")
        timestamp = _now()
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT value FROM app_meta WHERE key = 'migration_id'"
            ).fetchone()
            if existing is not None:
                if str(existing["value"]) != migration_id:
                    raise ConflictError("a different migration was already imported")
                return self._migration_result(connection, migration_id)

            table_names = (
                "settings",
                "accounts",
                "workspaces",
                "runs",
                "queue_items",
                "run_events",
                "mailbox_inventory",
                "mailbox_alias_allocations",
            )
            existing_counts = {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in table_names
            }
            if any(existing_counts.values()):
                raise StateConflictError("legacy import requires a fresh database")

            bindings = (
                getattr(model, "old_binding", None),
                getattr(model, "new_binding", None),
            )
            if any(binding is None for binding in bindings):
                raise ValidationError("legacy account bindings are required")
            account_specs: dict[str, dict[str, Any]] = {}
            for binding in bindings:
                primary = _required_text(
                    binding.primary_email, "mailbox primary email"
                ).casefold()
                alias = _required_text(
                    binding.registration_email, "registration email"
                ).casefold()
                mailbox = binding.mailbox
                account_specs.setdefault(
                    primary,
                    {
                        "email": primary,
                        "primary_email": primary,
                        "mailbox_password": str(mailbox.password or ""),
                        "client_id": str(mailbox.client_id or ""),
                        "refresh_token": str(mailbox.refresh_token or ""),
                        "account_password": "",
                        "source": "legacy_txt",
                    },
                )
                account_specs[alias] = {
                    "email": alias,
                    "primary_email": primary,
                    "mailbox_password": str(mailbox.password or ""),
                    "client_id": str(mailbox.client_id or ""),
                    "refresh_token": str(mailbox.refresh_token or ""),
                    "account_password": str(binding.account_password or ""),
                    "source": "legacy_binding",
                }

            account_ids: dict[str, str] = {}
            for email, spec in account_specs.items():
                account_id = _migration_identifier(migration_id, "account", email)
                account_ids[email] = account_id
                credential_payload = {
                    "mailbox_password": spec["mailbox_password"],
                    "client_id": spec["client_id"],
                    "refresh_token": spec["refresh_token"],
                    "account_password": spec["account_password"],
                }
                credential_blob = self._require_secret_store().encrypt(
                    _json_bytes(credential_payload),
                    f"account:{account_id}:credentials",
                )
                connection.execute(
                    """
                    INSERT INTO accounts(
                        id, email, primary_email, credential_blob, status, source,
                        created_at, updated_at
                    ) VALUES(?, ?, ?, ?, 'available', ?, ?, ?)
                    """,
                    (
                        account_id,
                        spec["email"],
                        spec["primary_email"],
                        sqlite3.Binary(credential_blob),
                        spec["source"],
                        timestamp,
                        timestamp,
                    ),
                )

            config = getattr(model, "config", None)
            if config is None:
                raise ValidationError("legacy configuration is required")
            old_email = str(model.old_binding.registration_email).casefold()
            new_email = str(model.new_binding.registration_email).casefold()
            current_account_id = account_ids[old_email]
            next_account_id = account_ids[new_email]
            workspace_id = _migration_identifier(
                migration_id, "workspace", str(config.workspace_id)
            )

            state = getattr(model, "state", None)
            steps = state.get("steps") if isinstance(state, Mapping) else None
            has_checkpoint = isinstance(steps, Mapping) and bool(steps)
            run_id = (
                _migration_identifier(migration_id, "run", str(config.workspace_id))
                if has_checkpoint
                else None
            )
            connection.execute(
                """
                INSERT INTO workspaces(
                    id, name, workspace_uid, current_account_id, next_account_id,
                    status, last_run_id, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id,
                    str(config.workspace_id),
                    str(config.workspace_id),
                    current_account_id,
                    next_account_id,
                    "failed" if has_checkpoint else "ready",
                    run_id,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                "UPDATE accounts SET status = 'bound_current', updated_at = ? WHERE id = ?",
                (timestamp, current_account_id),
            )
            connection.execute(
                "UPDATE accounts SET status = 'bound_next', updated_at = ? WHERE id = ?",
                (timestamp, next_account_id),
            )

            management_secret = str(config.management.api_key or "")
            sub2api_secret = str(config.sub2api.password or "")
            sub2api_api_key = str(config.sub2api.api_key or "")
            sub2api_totp_secret = str(config.sub2api.totp_secret or "")
            text_settings = {
                "output_dir": str(config.output_dir),
                "invite_settle_seconds": config.invite_settle_seconds,
                "pat_name": config.pat_name,
                "pat_ttl": config.pat_ttl,
                "management_base_url": config.management.base_url,
                "management_push": int(config.management.push and bool(management_secret)),
                "management_replace": int(config.management.replace),
                "management_remote_name": config.management.remote_name,
                "sub2api_base_url": config.sub2api.base_url,
                "sub2api_email": config.sub2api.email,
                "sub2api_push": int(
                    config.sub2api.push
                    and bool(config.sub2api.email)
                    and bool(sub2api_secret)
                    and bool(sub2api_totp_secret)
                ),
                "sub2api_concurrency": config.sub2api.concurrency,
                "sub2api_priority": config.sub2api.priority,
            }
            for key, value in text_settings.items():
                self._upsert_text_setting_row(connection, key, value, timestamp)
            secret_settings = {
                "proxy": str(config.proxy or ""),
                "management_api_key": management_secret,
                "sub2api_password": sub2api_secret,
                "sub2api_api_key": sub2api_api_key,
                "sub2api_totp_secret": sub2api_totp_secret,
            }
            for key, value in secret_settings.items():
                if value:
                    self._upsert_secret_setting_row(connection, key, value, timestamp)

            if has_checkpoint and run_id is not None:
                checkpoint_blob = self._require_secret_store().encrypt(
                    _json_bytes(steps), f"run:{run_id}:checkpoint"
                )
                completed_visible_steps = [step for step in WORKFLOW_STEPS if step in steps]
                current_step = (
                    completed_visible_steps[-1] if completed_visible_steps else None
                )
                queue_item_id = _migration_identifier(
                    migration_id, "queue", str(config.workspace_id)
                )
                connection.execute(
                    """
                    INSERT INTO runs(
                        id, workspace_id, current_account_id, next_account_id,
                        current_email_snapshot, next_email_snapshot,
                        workspace_uid_snapshot, state, current_step, checkpoint_blob,
                        redacted_error, created_at, finished_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, 'failed', ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        workspace_id,
                        current_account_id,
                        next_account_id,
                        old_email,
                        new_email,
                        str(config.workspace_id),
                        current_step,
                        sqlite3.Binary(checkpoint_blob),
                        "Migrated interrupted legacy workflow",
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO queue_items(
                        id, run_id, position, state, created_at, finished_at
                    ) VALUES(?, ?, 0, 'failed', ?, ?)
                    """,
                    (queue_item_id, run_id, timestamp, timestamp),
                )

            counts = {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in table_names
            }
            metadata = {
                "migration_id": migration_id,
                "migration_status": "imported",
                "migration_counts": json.dumps(
                    counts, ensure_ascii=True, separators=(",", ":"), sort_keys=True
                ),
            }
            for key, value in metadata.items():
                connection.execute(
                    "INSERT INTO app_meta(key, value) VALUES(?, ?)", (key, value)
                )
            self._before_legacy_import_commit(connection, migration_id)
            return {
                "migration_id": migration_id,
                "status": "imported",
                "counts": counts,
            }

    @contextmanager
    def _temporary_snapshot_file(self, payload: bytes | None = None) -> Iterator[Path]:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".snapshot", dir=self.path.parent
        )
        path = Path(name)
        try:
            if payload is None:
                os.close(descriptor)
            else:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            yield path
        finally:
            path.unlink(missing_ok=True)
            Path(f"{path}-wal").unlink(missing_ok=True)
            Path(f"{path}-shm").unlink(missing_ok=True)

    def create_snapshot_bytes(self) -> bytes:
        with self._maintenance_lock:
            with self._temporary_snapshot_file() as snapshot_path:
                source = self._connect()
                destination = sqlite3.connect(snapshot_path)
                try:
                    source.backup(destination)
                    destination.commit()
                finally:
                    destination.close()
                    source.close()
                return snapshot_path.read_bytes()

    @staticmethod
    def _restore_candidate_metadata(candidate: Any) -> tuple[bytes, int, str, str]:
        snapshot = getattr(candidate, "sqlite_snapshot", None)
        if not isinstance(snapshot, bytes) or not snapshot:
            raise RestoreValidationError("restore candidate has no database snapshot")
        try:
            schema_version = int(candidate.schema_version)
        except (AttributeError, TypeError, ValueError) as exc:
            raise RestoreValidationError("restore candidate metadata is invalid") from exc
        instance_id = str(getattr(candidate, "instance_id", "") or "").strip()
        migration_id = str(getattr(candidate, "migration_id", "") or "").strip()
        if (
            schema_version < 1
            or schema_version > SCHEMA_VERSION
            or not instance_id
            or not migration_id
        ):
            raise RestoreValidationError("restore candidate metadata is incompatible")
        return snapshot, schema_version, instance_id, migration_id

    def validate_restore_candidate(self, candidate: Any) -> RestoreValidation:
        snapshot, schema_version, instance_id, migration_id = self._restore_candidate_metadata(
            candidate
        )
        digest = hashlib.sha256(snapshot).hexdigest()
        expected_tables = {
            "app_meta",
            "settings",
            "accounts",
            "workspaces",
            "runs",
            "queue_items",
            "run_events",
        }
        if schema_version >= 2:
            expected_tables.update(
                {"mailbox_inventory", "mailbox_alias_allocations"}
            )
        try:
            with self._temporary_snapshot_file(snapshot) as snapshot_path:
                connection = sqlite3.connect(
                    snapshot_path.resolve().as_uri() + "?mode=ro",
                    uri=True,
                    isolation_level=None,
                )
                connection.row_factory = sqlite3.Row
                try:
                    integrity = [
                        str(row[0]) for row in connection.execute("PRAGMA integrity_check")
                    ]
                    if integrity != ["ok"]:
                        raise RestoreValidationError(
                            "restore candidate database integrity check failed"
                        )
                    connection.execute("PRAGMA foreign_keys = ON")
                    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise RestoreValidationError(
                            "restore candidate contains invalid references"
                        )
                    tables = {
                        str(row[0])
                        for row in connection.execute(
                            "SELECT name FROM sqlite_master WHERE type = 'table'"
                        )
                    }
                    if not expected_tables.issubset(tables):
                        raise RestoreValidationError(
                            "restore candidate schema is incomplete"
                        )
                    metadata = {
                        str(row["key"]): str(row["value"])
                        for row in connection.execute(
                            "SELECT key, value FROM app_meta WHERE key IN ('schema_version', 'instance_id', 'migration_id')"
                        )
                    }
                    if (
                        int(metadata.get("schema_version", "0")) != schema_version
                        or metadata.get("instance_id") != instance_id
                        or metadata.get("migration_id") != migration_id
                    ):
                        raise RestoreValidationError(
                            "restore candidate identity does not match its manifest"
                        )

                    for row in connection.execute(
                        "SELECT key, value_blob FROM settings WHERE encrypted = 1"
                    ):
                        self._require_secret_store().decrypt(
                            bytes(row["value_blob"]), f"setting:{row['key']}"
                        )
                    account_query = (
                        "SELECT id, credential_blob, runtime_identity_blob FROM accounts"
                        if schema_version >= 3
                        else "SELECT id, credential_blob, NULL AS runtime_identity_blob FROM accounts"
                    )
                    for row in connection.execute(account_query):
                        plaintext = self._require_secret_store().decrypt(
                            bytes(row["credential_blob"]),
                            f"account:{row['id']}:credentials",
                        )
                        if not isinstance(json.loads(plaintext.decode("utf-8")), dict):
                            raise RestoreValidationError(
                                "restore candidate account credentials are invalid"
                            )
                        if schema_version >= 3 and row["runtime_identity_blob"] is not None:
                            runtime_plaintext = self._require_secret_store().decrypt(
                                bytes(row["runtime_identity_blob"]),
                                f"account:{row['id']}:runtime-identity:v1",
                            )
                            _validate_account_runtime_identity(
                                json.loads(runtime_plaintext.decode("utf-8"))
                            )
                    if schema_version >= 2:
                        for row in connection.execute(
                            """
                            SELECT credential_blob, credential_purpose
                            FROM mailbox_inventory
                            """
                        ):
                            plaintext = self._require_secret_store().decrypt(
                                bytes(row["credential_blob"]),
                                str(row["credential_purpose"]),
                            )
                            if not isinstance(json.loads(plaintext.decode("utf-8")), dict):
                                raise RestoreValidationError(
                                    "restore candidate mailbox credentials are invalid"
                                )
                    for row in connection.execute(
                        "SELECT id, checkpoint_blob, proxy_blob FROM runs"
                    ):
                        if row["checkpoint_blob"] is not None:
                            plaintext = self._require_secret_store().decrypt(
                                bytes(row["checkpoint_blob"]),
                                f"run:{row['id']}:checkpoint",
                            )
                            if not isinstance(json.loads(plaintext.decode("utf-8")), dict):
                                raise RestoreValidationError(
                                    "restore candidate checkpoint is invalid"
                                )
                        if row["proxy_blob"] is not None:
                            self._require_secret_store().decrypt(
                                bytes(row["proxy_blob"]), f"run:{row['id']}:proxy"
                            ).decode("utf-8")
                    row_counts = {
                        table: int(
                            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                        )
                        for table in expected_tables - {"app_meta"}
                    }
                finally:
                    connection.close()
        except RestoreValidationError:
            raise
        except Exception as exc:
            raise RestoreValidationError("restore candidate validation failed") from exc
        return RestoreValidation(
            snapshot_sha256=digest,
            schema_version=schema_version,
            instance_id=instance_id,
            migration_id=migration_id,
            row_counts=row_counts,
        )

    @staticmethod
    def _remove_database_sidecars(path: Path) -> None:
        Path(f"{path}-wal").unlink(missing_ok=True)
        Path(f"{path}-shm").unlink(missing_ok=True)

    def restore_verified_backup(
        self, candidate: Any, validation: Any
    ) -> dict[str, Any]:
        snapshot, schema_version, instance_id, migration_id = self._restore_candidate_metadata(
            candidate
        )
        if not isinstance(validation, RestoreValidation):
            raise RestoreValidationError("restore validation token is invalid")
        if (
            validation.snapshot_sha256 != hashlib.sha256(snapshot).hexdigest()
            or validation.schema_version != schema_version
            or validation.instance_id != instance_id
            or validation.migration_id != migration_id
        ):
            raise RestoreValidationError("restore candidate changed after validation")

        with self._maintenance_lock:
            connection = self._connect()
            try:
                paused = connection.execute(
                    "SELECT value FROM app_meta WHERE key = 'queue_paused'"
                ).fetchone()
                if paused is None or paused["value"] != "1":
                    raise StateConflictError("queue must be paused before restore")
                if connection.execute(
                    "SELECT 1 FROM queue_items WHERE state = 'running'"
                ).fetchone() is not None:
                    raise StateConflictError("running queue item blocks restore")
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()

            previous = self.create_snapshot_bytes()
            replaced = False
            try:
                with self._temporary_snapshot_file(snapshot) as replacement:
                    self._remove_database_sidecars(self.path)
                    os.replace(replacement, self.path)
                    replaced = True
                self._initialize_locked()
                self.set_queue_paused(True)
            except BaseException:
                if replaced:
                    with self._temporary_snapshot_file(previous) as rollback:
                        self._remove_database_sidecars(self.path)
                        os.replace(rollback, self.path)
                    self._initialize_locked()
                raise
        return {
            "status": "restored",
            "schema_version": SCHEMA_VERSION,
            "source_schema_version": schema_version,
            "instance_id": instance_id,
            "migration_id": migration_id,
            "row_counts": dict(validation.row_counts),
            "queue_paused": True,
        }
