from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import socket
import threading
import webbrowser
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Mapping

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .database import (
    BindingConflictError,
    ConflictError,
    Database,
    DatabaseConfigurationError,
    DatabaseError,
    NotFoundError,
    RestoreValidationError,
    StaleVersionError,
    StateConflictError,
    ValidationError,
    default_app_dir,
)
from .migration import (
    CleanupResult,
    MigrationBackupError,
    MigrationError,
    SourcePayload,
    SourceRecord,
    apply_import,
    cleanup_plaintext,
    create_backup,
    discover_legacy,
    mailbox_inventory_records_from_backup,
    parse_legacy_mailboxes,
    restore_backup,
    validate_legacy,
    verify_backup,
)
from .secret_store import SecretStore, SecretStoreError
from .task_queue import TaskQueue, redact_value


STATIC_DIR = Path(__file__).resolve().parent / "web_static"
PROJECT_DIR = Path(__file__).resolve().parents[1]
_SECRET_SETTING_KEYS = frozenset({"proxy", "management_api_key", "sub2api_password"})
_TEXT_SETTING_KEYS = frozenset(
    {
        "output_dir",
        "pat_name",
        "pat_ttl",
        "invite_settle_seconds",
        "management_base_url",
        "management_push",
        "management_replace",
        "management_remote_name",
        "sub2api_base_url",
        "sub2api_email",
        "sub2api_push",
        "sub2api_concurrency",
        "sub2api_priority",
    }
)
_VISIBLE_TEXT_SETTING_KEYS = _TEXT_SETTING_KEYS | {
    "last_backup_path",
    "last_backup_at",
}
_SENSITIVE_RESPONSE_KEYS = frozenset(
    {
        "credential_blob",
        "checkpoint_blob",
        "proxy_blob",
        "value_blob",
        "password",
        "mailbox_password",
        "account_password",
        "refresh_token",
        "client_id",
        "credential_purpose",
        "management_api_key",
        "sub2api_password",
        "proxy",
    }
)
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkspaceCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    workspace_uid: str = Field(min_length=1, max_length=500)
    current_account_id: str | None = None
    current_inventory_id: str | None = None
    next_account_id: str | None = None
    next_inventory_id: str | None = None


class WorkspaceUpdateRequest(StrictModel):
    version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=160)
    current_account_id: str | None = None
    current_inventory_id: str | None = None
    next_account_id: str | None = None
    next_inventory_id: str | None = None
    clear_next_account: bool = False


class AccountImportRequest(StrictModel):
    path: str = Field(min_length=1)


class AccountAliasRequest(StrictModel):
    inventory_id: str = Field(min_length=1)


class WorkspaceReplaceAccountRequest(StrictModel):
    version: int = Field(ge=1)
    role: Literal["current", "next"]
    failure_code: Literal["alias_disabled", "mailbox_credentials_invalid"]


class WorkspaceAdvanceRequest(StrictModel):
    version: int = Field(ge=1)


class AccountStatusRequest(StrictModel):
    status: str


class QueueEnqueueRequest(StrictModel):
    workspace_ids: list[str] = Field(min_length=1, max_length=500)


class QueueOrderRequest(StrictModel):
    queue_item_ids: list[str] = Field(max_length=500)


class QueuePauseRequest(StrictModel):
    paused: bool


class SettingsUpdateRequest(StrictModel):
    values: dict[str, str | bool | int | float] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list)


class DialogRequest(StrictModel):
    kind: str
    current: str = ""


class BackupCreateRequest(StrictModel):
    path: str | None = None


class BackupRestoreRequest(StrictModel):
    path: str = Field(min_length=1)


class FieldInputError(ValueError):
    def __init__(self, fields: Mapping[str, str]) -> None:
        self.fields = {str(key): str(value) for key, value in fields.items()}
        super().__init__("invalid request fields")


@dataclass(frozen=True)
class _BackupModel:
    config: Any
    sources: tuple[SourcePayload, ...]
    migration_id: str

    @property
    def source_records(self) -> tuple[SourceRecord, ...]:
        return tuple(source.record for source in self.sources)


class WebConsoleController:
    """Map local HTTP operations to the persisted workspace domain."""

    def __init__(
        self,
        *,
        database: Database | None = None,
        secret_store: SecretStore | None = None,
        task_queue: TaskQueue | None = None,
        app_dir: str | Path | None = None,
        backup_dir: str | Path | None = None,
        legacy_config_path: str | Path | None = None,
        inventory_expected_count: int | None = None,
    ) -> None:
        self.app_dir = (
            Path(app_dir).expanduser().resolve()
            if app_dir is not None
            else default_app_dir().expanduser().resolve()
        )
        self.backup_dir = (
            Path(backup_dir).expanduser().resolve()
            if backup_dir is not None
            else self.app_dir / "backups"
        )
        self.secret_store = secret_store or SecretStore()
        self.database = database or Database(
            self.app_dir / "console.db", secret_store=self.secret_store
        )
        self.task_queue = task_queue or TaskQueue(self.database)
        self.legacy_config_path = (
            None
            if legacy_config_path is None
            else Path(legacy_config_path).expanduser().resolve()
        )
        self.inventory_expected_count = (
            None
            if inventory_expected_count is None
            else max(1, int(inventory_expected_count))
        )
        self.request_token = secrets.token_urlsafe(32)
        self._dialog_lock = threading.Lock()
        self._lifecycle_lock = threading.RLock()
        self._started = False
        self._migration_status = "initializing"
        self._migration_error: str | None = None

    def startup(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._started:
                return self.health()
            self.database.initialize()
            self._prepare_migration()
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
            if self._migration_status == "ready":
                self.database.prune_unreferenced_legacy_accounts()
                self.task_queue.start()
            self._started = True
            return self.health()

    def shutdown(self) -> bool:
        with self._lifecycle_lock:
            stopped = self.task_queue.shutdown()
            self._started = False
            return bool(stopped)

    def health(self) -> dict[str, Any]:
        return {
            "ready": self._migration_status == "ready",
            "started": self._started,
            "migration": self.migration_status(),
        }

    def migration_status(self) -> dict[str, Any]:
        backup_path = self.database.get_meta("migration_backup_path")
        preserved = self.database.get_meta("migration_preserved_paths")
        try:
            preserved_paths = json.loads(preserved) if preserved else []
        except json.JSONDecodeError:
            preserved_paths = []
        return {
            "status": self._migration_status,
            "error": self._migration_error,
            "legacy_source_configured": self.legacy_config_path is not None,
            "backup": {"configured": bool(backup_path), "path": backup_path},
            "preserved_external_paths": preserved_paths,
        }

    def _prepare_migration(self) -> None:
        persisted = self.database.get_meta("migration_status")
        if persisted in {"ready", "complete"}:
            self._migration_status = "ready"
            self._migration_error = None
            return
        if persisted == "cleanup_blocked":
            self._migration_status = "cleanup_blocked"
            self._migration_error = self.database.get_meta("migration_error")
            return
        if self.legacy_config_path is None or not self.legacy_config_path.is_file():
            if self.database.get_meta("migration_id"):
                self._migration_status = "migration_error"
                self._migration_error = "legacy migration is incomplete and its source is unavailable"
                return
            self.database.set_meta("migration_status", "ready")
            self.database.set_meta("migration_completed", "1")
            self._migration_status = "ready"
            self._migration_error = None
            return
        self._run_legacy_migration()

    def _run_legacy_migration(self) -> None:
        try:
            discovery = discover_legacy(self.legacy_config_path)
            model = validate_legacy(discovery)
            apply_import(model, self.database)
            snapshot = self.database.create_snapshot_bytes()
            backup_path = self.app_dir / "backups" / f"migration-{model.migration_id[:16]}.twbackup"
            if backup_path.exists():
                verified = verify_backup(backup_path, self.secret_store)
                if verified.migration_id != model.migration_id:
                    raise MigrationBackupError("existing migration backup does not match")
            else:
                verified = create_backup(
                    model,
                    backup_path,
                    self.secret_store,
                    schema_version=int(self.database.get_meta("schema_version") or 0),
                    instance_id=str(self.database.get_meta("instance_id") or ""),
                    sqlite_snapshot=snapshot,
                )
            self.database.set_meta("migration_backup_path", str(backup_path))
            self.database.set_meta("migration_status", "backup_verified")
            result = cleanup_plaintext(model, verified)
            self._finish_cleanup(result)
        except Exception as exc:
            self._migration_status = "migration_error"
            self._migration_error = str(redact_value(str(exc)))
            self.database.set_meta("migration_status", "migration_error")
            self.database.set_meta("migration_error", self._migration_error)

    def _finish_cleanup(self, result: CleanupResult) -> None:
        preserved = [str(path) for path in result.preserved]
        self.database.set_meta(
            "migration_preserved_paths",
            json.dumps(preserved, ensure_ascii=False, separators=(",", ":")),
        )
        if result.status == "cleanup_blocked":
            codes = ", ".join(sorted({failure.code for failure in result.failures}))
            self._migration_status = "cleanup_blocked"
            self._migration_error = f"legacy plaintext cleanup is blocked: {codes}"
            self.database.set_meta("migration_status", "cleanup_blocked")
            self.database.set_meta("migration_error", self._migration_error)
            return
        self.database.set_meta("migration_status", "complete")
        self.database.set_meta("migration_completed", "1")
        self.database.set_meta("migration_error", "")
        self._migration_status = "ready"
        self._migration_error = None

    def retry_migration_cleanup(self) -> dict[str, Any]:
        with self._lifecycle_lock:
            if self._migration_status == "ready":
                return self.migration_status()
            if self._migration_status == "inventory_migration_error":
                self._migration_status = "ready"
                self._migration_error = None
                self._prepare_inventory_backfill()
                if self._migration_status == "ready":
                    self.database.prune_unreferenced_legacy_accounts()
                    self.task_queue.start()
                    self.task_queue.notify_change()
                return self.migration_status()
            backup_path = self.database.get_meta("migration_backup_path")
            if self._migration_status == "cleanup_blocked" and backup_path:
                verified = verify_backup(backup_path, self.secret_store)
                model = _BackupModel(
                    config=SimpleNamespace(**verified.identity),
                    sources=verified.sources,
                    migration_id=verified.migration_id,
                )
                self._finish_cleanup(cleanup_plaintext(model, verified))
            elif self.legacy_config_path is not None and self.legacy_config_path.is_file():
                self._run_legacy_migration()
            else:
                raise MigrationBackupError("migration recovery source is unavailable")
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
                if self._migration_status == "ready":
                    self.task_queue.start()
                    self.task_queue.notify_change()
            return self.migration_status()

    def _prepare_inventory_backfill(self) -> None:
        if self.database.get_meta("mailbox_inventory_migration_version") == "1":
            return
        backup_path = self.database.get_meta("migration_backup_path")
        if not backup_path:
            self.database.set_meta("mailbox_inventory_migration_version", "1")
            return
        try:
            verified = verify_backup(backup_path, self.secret_store)
            database_migration_id = str(self.database.get_meta("migration_id") or "")
            database_instance_id = str(self.database.get_meta("instance_id") or "")
            if verified.migration_id != database_migration_id:
                raise MigrationBackupError("inventory source migration identity does not match")
            if verified.instance_id != database_instance_id:
                raise MigrationBackupError("inventory source instance identity does not match")
            records = mailbox_inventory_records_from_backup(verified)
            prechange = self.create_encrypted_backup()
            result = self.database.backfill_mailbox_inventory(
                records,
                migration_id=verified.migration_id,
                expected_count=self.inventory_expected_count,
                legacy_old_email=verified.identity.get("old_email"),
                legacy_new_email=verified.identity.get("new_email"),
            )
            if self.database.get_meta("mailbox_inventory_migration_version") != "1":
                raise StateConflictError("mailbox inventory backfill did not commit its marker")
            self.database.set_meta(
                "mailbox_inventory_prechange_backup_path", str(prechange["path"])
            )
            self.database.set_meta(
                "mailbox_inventory_migration_result",
                json.dumps(_safe_payload(result), ensure_ascii=False, separators=(",", ":")),
            )
        except Exception as exc:
            self._migration_status = "inventory_migration_error"
            self._migration_error = str(redact_value(str(exc)))
            self.database.set_meta("mailbox_inventory_migration_error", self._migration_error)

    def bootstrap(self) -> dict[str, Any]:
        return {
            "request_token": self.request_token,
            "health": self.health(),
            "workspaces": self.list_workspaces(),
            "accounts": self.list_accounts(),
            "queue": self.queue_snapshot(),
            "runs": self.list_runs(limit=100),
            "settings": self.get_settings(),
        }

    def event_reset(self) -> dict[str, Any]:
        return {
            "workspaces": self.list_workspaces(),
            "accounts": self.list_accounts(),
            "queue": self.queue_snapshot(),
            "runs": self.list_runs(limit=100),
            "settings": self.get_settings(),
            "migration": self.migration_status(),
        }

    def list_workspaces(self) -> list[dict[str, Any]]:
        return _safe_payload(self.database.list_workspaces())

    def create_workspace(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        current_account_id, current_inventory_id = _selection(
            payload, "current", required=True
        )
        next_account_id, next_inventory_id = _selection(
            payload, "next", required=False
        )
        workspace = self.database.create_workspace(
            name=str(payload["name"]).strip(),
            workspace_uid=str(payload["workspace_uid"]).strip(),
            current_account_id=current_account_id,
            current_inventory_id=current_inventory_id,
            next_account_id=next_account_id,
            next_inventory_id=next_inventory_id,
        )
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def update_workspace(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "expected_version": int(payload["version"]),
            "name": _optional_text(payload.get("name")),
        }
        if "current_account_id" in payload or "current_inventory_id" in payload:
            current_account_id, current_inventory_id = _selection(
                payload, "current", required=True
            )
            kwargs["current_account_id"] = current_account_id
            kwargs["current_inventory_id"] = current_inventory_id
        if bool(payload.get("clear_next_account")):
            if payload.get("next_account_id") or payload.get("next_inventory_id"):
                raise FieldInputError(
                    {"clear_next_account": "cannot clear and select next account together"}
                )
            kwargs["next_account_id"] = None
            kwargs["next_inventory_id"] = None
        elif "next_account_id" in payload or "next_inventory_id" in payload:
            next_account_id, next_inventory_id = _selection(
                payload, "next", required=False
            )
            kwargs["next_account_id"] = next_account_id
            kwargs["next_inventory_id"] = next_inventory_id
        workspace = self.database.update_workspace(str(workspace_id), **kwargs)
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def enqueue_workspace(self, workspace_id: str) -> dict[str, Any]:
        return _safe_payload(self.task_queue.enqueue([str(workspace_id)])[0])

    def retry_workspace(self, workspace_id: str) -> dict[str, Any]:
        workspace = self.database.get_workspace(str(workspace_id))
        run_id = workspace.get("last_run_id")
        if not run_id:
            raise StateConflictError("workspace has no run to retry")
        return _safe_payload(self.task_queue.retry(str(run_id)))

    def list_accounts(self) -> list[dict[str, Any]]:
        return _safe_payload(self.database.list_accounts())

    def import_accounts(self, path: str | Path) -> dict[str, Any]:
        from .migration import parse_mailbox_inventory_import

        source = Path(path).expanduser().resolve()
        rows, invalid_count = parse_mailbox_inventory_import(source.read_bytes())
        if not rows:
            raise FieldInputError({"path": "TXT contains no valid mailbox records"})
        result = dict(self.database.import_mailbox_inventory(rows))
        result["total"] = int(result.get("total", len(rows))) + int(invalid_count)
        result["invalid"] = int(result.get("invalid", 0)) + int(invalid_count)
        self.task_queue.notify_change()
        return _safe_payload(result)

    def create_account_alias(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        account = self.database.allocate_mailbox_alias(
            str(payload["inventory_id"])
        )
        self.task_queue.notify_change()
        return _safe_payload(account)

    def search_mailbox_inventory(
        self,
        *,
        query: str = "",
        status: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        return _safe_payload(
            self.database.search_mailbox_inventory(
                query=str(query or "").strip(),
                status=status,
                limit=max(1, min(int(limit), 20)),
            )
        )

    def allocate_mailbox_inventory(self, inventory_id: str) -> dict[str, Any]:
        account = self.database.allocate_mailbox_alias(str(inventory_id))
        self.task_queue.notify_change()
        return _safe_payload(account)

    def replace_workspace_account(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        workspace = self.database.replace_workspace_account(
            str(workspace_id),
            role=str(payload["role"]),
            failure_code=str(payload["failure_code"]),
            expected_version=int(payload["version"]),
        )
        self.task_queue.notify_change()
        return _safe_payload(workspace)

    def advance_workspace_accounts(
        self, workspace_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        result = self.database.advance_workspace_accounts(
            str(workspace_id), expected_version=int(payload["version"])
        )
        self.task_queue.notify_change()
        return _safe_payload(result)

    def update_account_status(self, account_id: str, new_status: str) -> dict[str, Any]:
        account = self.database.transition_account_status(account_id, str(new_status))
        self.task_queue.notify_change()
        return _safe_payload(account)

    def queue_snapshot(self) -> dict[str, Any]:
        return _safe_payload(self.task_queue.snapshot())

    def enqueue(self, workspace_ids: list[str]) -> list[dict[str, Any]]:
        return _safe_payload(self.task_queue.enqueue(workspace_ids))

    def reorder_queue(self, queue_item_ids: list[str]) -> list[dict[str, Any]]:
        return _safe_payload(self.task_queue.reorder(queue_item_ids))

    def pause_queue(self, paused: bool) -> dict[str, Any]:
        return {"paused": bool(self.task_queue.set_paused(bool(paused)))}

    def list_runs(
        self,
        *,
        workspace_id: str | None = None,
        state: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        return _safe_payload(
            self.database.list_runs(
                workspace_id=workspace_id,
                state=state,
                limit=limit,
            )
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        run = self.database.get_run(run_id)
        run["events"] = self.database.list_run_events(run_id=run_id, limit=2000)
        return _safe_payload(run)

    def stop_run(self, run_id: str) -> dict[str, Any]:
        return {"run_id": str(run_id), "state": self.task_queue.stop(str(run_id))}

    def get_settings(self) -> dict[str, Any]:
        rows = self.database.list_settings()
        values = {
            str(item["key"]): item["value"]
            for item in rows
            if not item["encrypted"] and item["key"] in _VISIBLE_TEXT_SETTING_KEYS
        }
        configured = {
            key: any(
                item["key"] == key and item["encrypted"] and item["configured"]
                for item in rows
            )
            for key in sorted(_SECRET_SETTING_KEYS)
        }
        return {"values": values, "secrets": configured}

    def update_settings(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        values = dict(payload.get("values") or {})
        secret_updates = dict(payload.get("secrets") or {})
        clear_secrets = [str(value) for value in payload.get("clear_secrets") or []]
        invalid_values = sorted(set(values) - _TEXT_SETTING_KEYS)
        invalid_secrets = sorted((set(secret_updates) | set(clear_secrets)) - _SECRET_SETTING_KEYS)
        fields = {}
        if invalid_values:
            fields["values"] = f"unsupported settings: {', '.join(invalid_values)}"
        if invalid_secrets:
            fields["secrets"] = f"unsupported secrets: {', '.join(invalid_secrets)}"
        if set(secret_updates) & set(clear_secrets):
            fields["clear_secrets"] = "a secret cannot be updated and cleared together"
        if fields:
            raise FieldInputError(fields)
        for key, value in values.items():
            self.database.set_text_setting(key, _setting_text(value))
        for key, value in secret_updates.items():
            if value:
                self.database.set_secret_setting(key, value)
        for key in clear_secrets:
            self.database.delete_setting(key)
        self.task_queue.notify_change()
        return self.get_settings()

    def create_encrypted_backup(self, path: str | None = None) -> dict[str, Any]:
        destination = (
            Path(path).expanduser().resolve()
            if path
            else self.backup_dir
            / (
                "console-"
                + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
                + ".twbackup"
            )
        )
        model = self._current_backup_model()
        stored_migration_id = self.database.get_meta("migration_id")
        if stored_migration_id is None:
            self.database.set_meta("migration_id", model.migration_id)
        elif stored_migration_id != model.migration_id:
            raise MigrationBackupError("database migration identity does not match backup sources")
        verified = create_backup(
            model,
            destination,
            self.secret_store,
            schema_version=int(self.database.get_meta("schema_version") or 0),
            instance_id=str(self.database.get_meta("instance_id") or ""),
            sqlite_snapshot=self.database.create_snapshot_bytes(),
        )
        self.database.set_text_setting("last_backup_path", str(destination))
        self.database.set_text_setting("last_backup_at", verified.created_at)
        self.task_queue.notify_change()
        return {
            "status": "created",
            "path": str(destination),
            "created_at": verified.created_at,
            "schema_version": verified.schema_version,
        }

    def _current_backup_model(self) -> _BackupModel:
        migration_backup_path = self.database.get_meta("migration_backup_path")
        if migration_backup_path and Path(migration_backup_path).is_file():
            verified = verify_backup(migration_backup_path, self.secret_store)
            return _BackupModel(
                config=SimpleNamespace(**verified.identity),
                sources=verified.sources,
                migration_id=verified.migration_id,
            )
        identity = {
            "workspace_id": "console",
            "old_email": "current@console.invalid",
            "new_email": "next@console.invalid",
        }
        workspaces = self.database.list_workspaces()
        accounts = {item["id"]: item for item in self.database.list_accounts()}
        if workspaces:
            workspace = workspaces[0]
            identity["workspace_id"] = workspace["workspace_uid"]
            current = accounts.get(workspace["current_account_id"])
            next_account = accounts.get(workspace.get("next_account_id"))
            if current:
                identity["old_email"] = current["email"]
            if next_account:
                identity["new_email"] = next_account["email"]
        sources: list[SourcePayload] = []
        source_specs = (
            (
                "workflow_config",
                self.app_dir / ".backup-manifest" / "console.json",
                json.dumps(
                    {"instance_id": self.database.get_meta("instance_id")},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            ),
            (
                "mail_accounts",
                self.app_dir / ".backup-manifest" / "accounts.txt",
                b"database-owned encrypted account library",
            ),
        )
        for role, path, content in source_specs:
            record = SourceRecord(
                role=role,
                path=path.resolve(),
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
                ownership="external",
            )
            sources.append(SourcePayload(record=record, content=content))
        manifest = [source.record.as_manifest() for source in sources]
        migration_id = hashlib.sha256(
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return _BackupModel(
            config=SimpleNamespace(**identity),
            sources=tuple(sources),
            migration_id=migration_id,
        )

    def restore_encrypted_backup(self, path: str | Path) -> dict[str, Any]:
        snapshot = self.task_queue.snapshot()
        if not snapshot.get("paused"):
            raise StateConflictError("queue must be paused before restore")
        if snapshot.get("active_run_id"):
            raise StateConflictError("active run blocks restore")
        self.task_queue.shutdown()
        try:
            result = restore_backup(path, self.secret_store, self.database)
            self.database.initialize()
            persisted = self.database.get_meta("migration_status")
            if persisted in {"imported", "backup_verified"}:
                self.database.set_meta("migration_status", "complete")
                self.database.set_meta("migration_completed", "1")
                self.database.set_meta("migration_backup_path", str(Path(path).resolve()))
                persisted = "complete"
            self._migration_status = (
                "ready" if persisted in {"ready", "complete"} else str(persisted or "ready")
            )
            self._migration_error = None
            if self._migration_status == "ready":
                self._prepare_inventory_backfill()
            if self._migration_status == "ready":
                self.database.prune_unreferenced_legacy_accounts()
        finally:
            if self._migration_status == "ready":
                self.task_queue.start()
                self.task_queue.notify_change()
        return _safe_payload(result)

    def choose_path(self, kind: str, current: str = "") -> dict[str, str]:
        if kind not in {"txt", "directory", "backup"}:
            raise FieldInputError({"kind": "supported values are txt, directory, backup"})
        with self._dialog_lock:
            selected = _choose_path(kind, current)
        return {"path": selected}


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    clean = str(value).strip()
    return clean or None


def _selection(
    payload: Mapping[str, Any], role: str, *, required: bool
) -> tuple[str | None, str | None]:
    account_id = _optional_text(payload.get(f"{role}_account_id"))
    inventory_id = _optional_text(payload.get(f"{role}_inventory_id"))
    selected = int(account_id is not None) + int(inventory_id is not None)
    if selected > 1 or (required and selected != 1):
        message = "select exactly one account or mailbox inventory item"
        raise FieldInputError({role: message})
    return account_id, inventory_id


def _setting_text(value: str | bool | int | float) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def _safe_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned = {
            str(key): _safe_payload(item)
            for key, item in value.items()
            if str(key).casefold() not in _SENSITIVE_RESPONSE_KEYS
            and not str(key).casefold().endswith("_blob")
        }
        return redact_value(cleaned)
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_safe_payload(item) for item in value]
    return redact_value(value)


def _choose_path(kind: str, current: str) -> str:
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    current_path = Path(current).expanduser() if current else None
    initial_dir = ""
    if current_path is not None:
        initial_dir = str(current_path if current_path.is_dir() else current_path.parent)
    try:
        if kind == "directory":
            return str(
                filedialog.askdirectory(
                    parent=root,
                    title="选择目录",
                    initialdir=initial_dir or None,
                )
                or ""
            )
        filetypes = (
            (("加密备份", "*.twbackup"), ("全部文件", "*.*"))
            if kind == "backup"
            else (("文本文件", "*.txt"), ("全部文件", "*.*"))
        )
        return str(
            filedialog.askopenfilename(
                parent=root,
                title="选择文件",
                initialdir=initial_dir or None,
                filetypes=filetypes,
            )
            or ""
        )
    finally:
        root.destroy()


def create_app(
    controller: WebConsoleController | None = None,
    *,
    testing: bool = False,
) -> FastAPI:
    controller = controller or WebConsoleController()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await asyncio.to_thread(controller.startup)
        try:
            yield
        finally:
            await asyncio.to_thread(controller.shutdown)

    app = FastAPI(
        title="Team Workflow Console",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    allowed_hosts = ["127.0.0.1", "localhost"]
    if testing:
        allowed_hosts.append("testserver")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: Request, exc: RequestValidationError):
        fields: dict[str, str] = {}
        for error in exc.errors():
            location = [str(part) for part in error.get("loc", ()) if part != "body"]
            field = ".".join(location) or "body"
            fields[field] = str(error.get("msg") or "invalid value")
        return JSONResponse(
            {"detail": {"code": "validation_error", "fields": fields}},
            status_code=422,
        )

    @app.middleware("http")
    async def secure_local_requests(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path != "/api/bootstrap":
            token = request.headers.get("X-Workflow-Token") or request.query_params.get("token")
            if not secrets.compare_digest(token or "", controller.request_token):
                return _error_response(403, "invalid_request_token", "invalid request token")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                origin = request.headers.get("Origin", "")
                expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
                if origin != expected:
                    return _error_response(403, "invalid_origin", "invalid origin")
        if (
            path.startswith("/api/")
            and controller._migration_status != "ready"
            and path
            not in {
                "/api/bootstrap",
                "/api/events",
                "/api/migration/status",
                "/api/migration/retry-cleanup",
                "/api/migration/cleanup",
                "/api/migration/cleanup/retry",
                "/api/backups/restore",
                "/api/dialog",
            }
        ):
            return _error_response(
                503,
                "migration_blocked",
                "migration recovery must complete before normal operations",
            )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "script-src 'self'; style-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/bootstrap")
    async def bootstrap():
        return await _call_controller(controller.bootstrap)

    @app.get("/api/workspaces")
    async def list_workspaces():
        return await _call_controller(controller.list_workspaces)

    @app.post("/api/workspaces", status_code=status.HTTP_201_CREATED)
    async def create_workspace(request: WorkspaceCreateRequest):
        return await _call_controller(controller.create_workspace, request.model_dump())

    @app.patch("/api/workspaces/{workspace_id}")
    async def update_workspace(workspace_id: str, request: WorkspaceUpdateRequest):
        return await _call_controller(
            controller.update_workspace,
            workspace_id,
            request.model_dump(exclude_unset=True),
        )

    @app.post("/api/workspaces/{workspace_id}/enqueue", status_code=202)
    async def enqueue_workspace(workspace_id: str):
        return await _call_controller(controller.enqueue_workspace, workspace_id)

    @app.post("/api/workspaces/{workspace_id}/retry", status_code=202)
    async def retry_workspace(workspace_id: str):
        return await _call_controller(controller.retry_workspace, workspace_id)

    @app.get("/api/accounts")
    async def list_accounts():
        return await _call_controller(controller.list_accounts)

    @app.post("/api/accounts/import", status_code=status.HTTP_201_CREATED)
    async def import_accounts(request: AccountImportRequest):
        return await _call_controller(controller.import_accounts, request.path)

    @app.post("/api/accounts/alias", status_code=status.HTTP_201_CREATED)
    async def create_account_alias(request: AccountAliasRequest):
        return await _call_controller(controller.create_account_alias, request.model_dump())

    @app.get("/api/mailbox-inventory")
    async def search_mailbox_inventory(
        query: str = Query("", max_length=320),
        inventory_status: Literal["available", "disabled", "exhausted"] | None = Query(
            None, alias="status"
        ),
        limit: int = Query(20, ge=1, le=20),
    ):
        return await _call_controller(
            controller.search_mailbox_inventory,
            query=query,
            status=inventory_status,
            limit=limit,
        )

    @app.post(
        "/api/mailbox-inventory/{inventory_id}/allocate",
        status_code=status.HTTP_201_CREATED,
    )
    async def allocate_mailbox_inventory(inventory_id: str):
        return await _call_controller(
            controller.allocate_mailbox_inventory, inventory_id
        )

    @app.post("/api/workspaces/{workspace_id}/replace-account")
    async def replace_workspace_account(
        workspace_id: str, request: WorkspaceReplaceAccountRequest
    ):
        return await _call_controller(
            controller.replace_workspace_account,
            workspace_id,
            request.model_dump(),
        )

    @app.post("/api/workspaces/{workspace_id}/advance")
    async def advance_workspace_accounts(
        workspace_id: str, request: WorkspaceAdvanceRequest
    ):
        return await _call_controller(
            controller.advance_workspace_accounts,
            workspace_id,
            request.model_dump(),
        )

    @app.patch("/api/accounts/{account_id}/status")
    async def update_account_status(account_id: str, request: AccountStatusRequest):
        return await _call_controller(
            controller.update_account_status, account_id, request.status
        )

    @app.get("/api/queue")
    async def queue_snapshot():
        return await _call_controller(controller.queue_snapshot)

    @app.post("/api/queue", status_code=202)
    async def enqueue(request: QueueEnqueueRequest):
        return await _call_controller(controller.enqueue, request.workspace_ids)

    @app.patch("/api/queue/order")
    async def reorder_queue(request: QueueOrderRequest):
        return await _call_controller(controller.reorder_queue, request.queue_item_ids)

    @app.post("/api/queue/pause")
    async def pause_queue(request: QueuePauseRequest):
        return await _call_controller(controller.pause_queue, request.paused)

    @app.get("/api/runs")
    async def list_runs(
        workspace_id: str | None = None,
        state: str | None = None,
        limit: int = Query(200, ge=1, le=1000),
    ):
        return await _call_controller(
            controller.list_runs,
            workspace_id=workspace_id,
            state=state,
            limit=limit,
        )

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str):
        return await _call_controller(controller.get_run, run_id)

    @app.post("/api/runs/{run_id}/stop")
    async def stop_run(run_id: str):
        return await _call_controller(controller.stop_run, run_id)

    @app.get("/api/settings")
    async def get_settings():
        return await _call_controller(controller.get_settings)

    @app.put("/api/settings")
    async def update_settings(request: SettingsUpdateRequest):
        return await _call_controller(controller.update_settings, request.model_dump())

    @app.get("/api/migration/status")
    async def migration_status():
        return await _call_controller(controller.migration_status)

    @app.post("/api/migration/retry-cleanup")
    async def retry_migration_cleanup():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/migration/cleanup")
    async def cleanup_migration():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/migration/cleanup/retry")
    async def retry_cleanup_migration():
        return await _call_controller(controller.retry_migration_cleanup)

    @app.post("/api/backups", status_code=status.HTTP_201_CREATED)
    async def create_encrypted_backup(request: BackupCreateRequest | None = None):
        return await _call_controller(
            controller.create_encrypted_backup,
            None if request is None else request.path,
        )

    @app.post("/api/backups/restore")
    async def restore_encrypted_backup(request: BackupRestoreRequest):
        return await _call_controller(controller.restore_encrypted_backup, request.path)

    @app.post("/api/dialog")
    async def choose_dialog(request: DialogRequest):
        return await _call_controller(controller.choose_path, request.kind, request.current)

    @app.get("/api/events")
    async def events(request: Request):
        return StreamingResponse(
            _event_stream(controller, request), media_type="text/event-stream"
        )

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


async def _call_controller(function, *args, **kwargs):
    try:
        return await asyncio.to_thread(function, *args, **kwargs)
    except FieldInputError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "fields": exc.fields},
        ) from exc
    except NotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (BindingConflictError, StaleVersionError, StateConflictError, ConflictError) as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "file_not_found", "message": "selected file was not found"},
        ) from exc
    except (MigrationError, RestoreValidationError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": getattr(exc, "code", "migration_error"), "message": str(exc)},
        ) from exc
    except (SecretStoreError, DatabaseConfigurationError) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": getattr(exc, "code", "storage_unavailable"), "message": str(exc)},
        ) from exc
    except DatabaseError as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


async def _event_stream(controller: WebConsoleController, request: Request):
    revision = controller.task_queue.revision
    existing = controller.database.list_run_events(after_seq=0, limit=2000)
    current_seq = int(existing[-1]["seq"]) if existing else 0
    yield _sse("reset", controller.event_reset(), current_seq)
    while not await request.is_disconnected():
        found = await asyncio.to_thread(
            controller.database.list_run_events,
            after_seq=current_seq,
            limit=2000,
        )
        for event in found:
            current_seq = int(event["seq"])
            yield _sse("message", _safe_payload(event), current_seq)
        next_revision = await asyncio.to_thread(
            controller.task_queue.wait_for_change,
            revision,
            1.0,
        )
        if next_revision != revision:
            revision = next_revision
            yield _sse("reset", controller.event_reset(), current_seq)
        elif not found:
            yield ": keepalive\n\n"


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"detail": {"code": code, "message": message}},
        status_code=status_code,
    )


def _sse(event_type: str, payload: Mapping[str, Any], event_id: int) -> str:
    data = json.dumps(_safe_payload(payload), ensure_ascii=False, separators=(",", ":"))
    return f"id: {event_id}\nevent: {event_type}\ndata: {data}\n\n"


def _available_port(preferred: int) -> int:
    for port in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no available loopback port found")


def serve_web_console(
    *,
    port: int = 8765,
    open_browser: bool = True,
    app_dir: str | Path | None = None,
    legacy_config_path: str | Path | None = None,
) -> int:
    selected_port = _available_port(port)
    internal_legacy_path = (
        Path(legacy_config_path).expanduser().resolve()
        if legacy_config_path is not None
        else (Path.cwd() / "workflow.example.json").resolve()
    )
    controller = WebConsoleController(
        app_dir=app_dir,
        backup_dir=PROJECT_DIR / "backups",
        legacy_config_path=internal_legacy_path,
        inventory_expected_count=7_211,
    )
    app = create_app(controller)
    url = f"http://127.0.0.1:{selected_port}"
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    print(f"Team Workflow Console: {url}")
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=selected_port,
            workers=1,
            log_level="warning",
            access_log=False,
        )
    )
    server.run()
    return 0


def main() -> int:
    return serve_web_console()


if __name__ == "__main__":
    raise SystemExit(main())
