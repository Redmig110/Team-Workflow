from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .secret_store import SecretStore, SecretStoreError


_BACKUP_MAGIC = b"TWSCBKUP"
_BACKUP_VERSION = 1
_BACKUP_HEADER = struct.Struct(">8sB")
_BACKUP_FORMAT = "team-workflow-console-backup"
_BACKUP_PURPOSE = "backup"
_SOURCE_ROLES = frozenset({"workflow_config", "mail_accounts", "workflow_state"})
_OWNERSHIP_VALUES = frozenset({"app_owned", "external"})
_CLEANUP_ROLES = frozenset({"workflow_config", "workflow_state"})


class MigrationError(RuntimeError):
    """Base class for stable migration failures."""


class MigrationValidationError(MigrationError):
    """Raised when legacy input is incomplete, ambiguous, or inconsistent."""


class MigrationBackupError(MigrationError):
    """Raised when an encrypted backup cannot be created or verified."""


@dataclass(frozen=True)
class SourceRecord:
    role: str
    path: Path
    sha256: str
    size: int
    ownership: str

    def as_manifest(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "ownership": self.ownership,
        }


@dataclass(frozen=True)
class SourcePayload:
    record: SourceRecord
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class LegacyMailboxRow:
    primary_email: str
    client_id: str = field(repr=False)
    refresh_token: str = field(repr=False)
    password: str = field(default="", repr=False)


@dataclass(frozen=True)
class LegacyAccountBinding:
    registration_email: str
    primary_email: str
    account_password: str = field(repr=False)
    mailbox: LegacyMailboxRow = field(repr=False)


@dataclass(frozen=True)
class LegacyManagementSettings:
    base_url: str
    api_key: str = field(repr=False)
    push: bool = True
    replace: bool = False
    remote_name: str = ""


@dataclass(frozen=True)
class LegacySub2APISettings:
    base_url: str
    email: str
    password: str = field(repr=False)
    push: bool = False
    concurrency: int = 10
    priority: int = 1


@dataclass(frozen=True)
class LegacyConfig:
    config_path: Path
    mail_account_file: Path
    workspace_id: str
    old_email: str
    new_email: str
    old_password: str = field(repr=False)
    new_password: str = field(repr=False)
    proxy: str = field(repr=False)
    pat_name: str
    pat_ttl: int
    output_dir: Path
    state_path: Path
    state_is_app_owned: bool
    invite_settle_seconds: float
    management: LegacyManagementSettings = field(repr=False)
    sub2api: LegacySub2APISettings = field(repr=False)


@dataclass(frozen=True)
class LegacyDiscovery:
    config: LegacyConfig = field(repr=False)
    sources: tuple[SourceRecord, ...]

    @property
    def manifest(self) -> tuple[dict[str, Any], ...]:
        return tuple(source.as_manifest() for source in self.sources)


@dataclass(frozen=True)
class LegacyImportModel:
    config: LegacyConfig = field(repr=False)
    mailboxes: tuple[LegacyMailboxRow, ...] = field(repr=False)
    old_binding: LegacyAccountBinding = field(repr=False)
    new_binding: LegacyAccountBinding = field(repr=False)
    state: Mapping[str, Any] | None = field(default=None, repr=False)
    sources: tuple[SourcePayload, ...] = field(default=(), repr=False)
    migration_id: str = ""

    @property
    def source_records(self) -> tuple[SourceRecord, ...]:
        return tuple(source.record for source in self.sources)


@dataclass(frozen=True)
class VerifiedBackup:
    schema_version: int
    instance_id: str
    created_at: str
    migration_id: str
    identity: Mapping[str, str]
    sources: tuple[SourcePayload, ...] = field(repr=False)
    sqlite_snapshot: bytes | None = field(default=None, repr=False)
    payload_sha256: str = ""


@dataclass(frozen=True)
class CleanupFailure:
    path: Path
    code: str


@dataclass(frozen=True)
class CleanupResult:
    status: str
    removed: tuple[Path, ...]
    preserved: tuple[Path, ...]
    missing: tuple[Path, ...]
    failures: tuple[CleanupFailure, ...]


class ImportRepository(Protocol):
    def apply_legacy_import(self, model: LegacyImportModel) -> Any: ...


class RestoreRepository(Protocol):
    def validate_restore_candidate(self, candidate: VerifiedBackup) -> Any: ...

    def restore_verified_backup(
        self,
        candidate: VerifiedBackup,
        validation: Any,
    ) -> Any: ...


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationValidationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise MigrationValidationError(f"{label} must be a JSON object")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise MigrationValidationError(f"{label} must be a JSON object")
    return value


def _env_expand(value: Any, env: Mapping[str, str]) -> str:
    text = str(value or "").strip()

    def replace_braced(match: re.Match[str]) -> str:
        return str(env.get(match.group(1), ""))

    def replace_percent(match: re.Match[str]) -> str:
        return str(env.get(match.group(1), match.group(0)))

    text = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", replace_braced, text)
    return re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%", replace_percent, text).strip()


def _resolve_path(value: Any, base_dir: Path, env: Mapping[str, str]) -> Path:
    expanded = _env_expand(value, env)
    if not expanded:
        raise MigrationValidationError("legacy path value is empty")
    path = Path(expanded)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _selected_alias(
    nested: Mapping[str, Any],
    nested_key: str,
    raw: Mapping[str, Any],
    flat_key: str,
    *,
    label: str,
    case_insensitive: bool,
) -> str:
    candidates = [
        str(nested.get(nested_key) or "").strip(),
        str(raw.get(flat_key) or "").strip(),
    ]
    values = [value for value in candidates if value]
    if not values:
        return ""
    normalized = {value.casefold() if case_insensitive else value for value in values}
    if len(normalized) != 1:
        raise MigrationValidationError(f"conflicting legacy aliases for {label}")
    return values[0]


def _primary_email_for_alias(email: str) -> str:
    normalized = str(email or "").strip().casefold()
    if normalized.count("@") != 1:
        return ""
    local, domain = normalized.rsplit("@", 1)
    primary_local = local.split("+", 1)[0]
    if not primary_local or not domain:
        return ""
    return f"{primary_local}@{domain}"


def legacy_state_filename(old_email: str, new_email: str, workspace_id: str) -> str:
    identity = f"{old_email.casefold()}|{new_email.casefold()}|{workspace_id}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    local = re.sub(r"[^a-z0-9]+", "-", new_email.casefold()).strip("-")[:48]
    return f"team-flow-{local or 'account'}-{digest}.json"


def decode_legacy_config(
    config_path: str | Path,
    payload: bytes,
    *,
    env: Mapping[str, str] | None = None,
) -> LegacyConfig:
    resolved_config = Path(config_path).resolve()
    raw = _decode_json_object(payload, "legacy workflow config")
    environment = dict(os.environ if env is None else env)
    base_dir = resolved_config.parent

    old_account = _mapping(raw.get("old_account"), "old_account")
    new_account = _mapping(raw.get("new_account"), "new_account")
    old_email = _selected_alias(
        old_account,
        "email",
        raw,
        "old_email",
        label="old account email",
        case_insensitive=True,
    )
    new_email = _selected_alias(
        new_account,
        "email",
        raw,
        "new_email",
        label="new account email",
        case_insensitive=True,
    )
    old_password = _selected_alias(
        old_account,
        "password",
        raw,
        "old_password",
        label="old account password",
        case_insensitive=False,
    )
    new_password = _selected_alias(
        new_account,
        "password",
        raw,
        "new_password",
        label="new account password",
        case_insensitive=False,
    )
    workspace_id = str(raw.get("workspace_id") or "").strip()
    if not old_email or not new_email or not workspace_id:
        raise MigrationValidationError(
            "old account email, new account email, and workspace_id are required"
        )
    if not _primary_email_for_alias(old_email) or not _primary_email_for_alias(new_email):
        raise MigrationValidationError("legacy account email is invalid")
    if old_email.casefold() == new_email.casefold():
        raise MigrationValidationError("old and new account aliases must differ")

    mail_account_file = _resolve_path(raw.get("mail_account_file"), base_dir, environment)
    output_dir = _resolve_path(raw.get("output_dir") or "output", base_dir, environment)
    expected_state_path = (
        output_dir
        / ".state"
        / legacy_state_filename(old_email, new_email, workspace_id)
    ).resolve()
    configured_state = raw.get("state_path")
    state_path = (
        _resolve_path(configured_state, base_dir, environment)
        if configured_state
        else expected_state_path
    )
    state_is_app_owned = (
        str(state_path).casefold() == str(expected_state_path).casefold()
    )

    pat = _mapping(raw.get("pat"), "pat")
    management = _mapping(raw.get("management"), "management")
    sub2api = _mapping(raw.get("sub2api"), "sub2api")
    try:
        pat_ttl = max(60, int(pat.get("ttl") or 5_184_000))
        invite_settle_seconds = max(
            0.0,
            float(raw.get("invite_settle_seconds") or 2.0),
        )
        concurrency = max(0, int(sub2api.get("concurrency") or 10))
        priority = max(0, int(sub2api.get("priority") or 1))
    except (TypeError, ValueError) as exc:
        raise MigrationValidationError("legacy numeric setting is invalid") from exc

    management_key = _env_expand(
        management.get("api_key") or environment.get("CPA_MANAGEMENT_KEY", ""),
        environment,
    )
    sub2api_password = _env_expand(
        sub2api.get("password") or environment.get("SUB2API_PASSWORD", ""),
        environment,
    )
    return LegacyConfig(
        config_path=resolved_config,
        mail_account_file=mail_account_file,
        workspace_id=workspace_id,
        old_email=old_email.casefold(),
        new_email=new_email.casefold(),
        old_password=old_password,
        new_password=new_password,
        proxy=str(raw.get("proxy") or "").strip(),
        pat_name=str(pat.get("name") or new_email).strip(),
        pat_ttl=pat_ttl,
        output_dir=output_dir,
        state_path=state_path,
        state_is_app_owned=state_is_app_owned,
        invite_settle_seconds=invite_settle_seconds,
        management=LegacyManagementSettings(
            base_url=str(management.get("base_url") or "https://upic.cloud").strip(),
            api_key=management_key,
            push=bool(management.get("push", True)),
            replace=bool(management.get("replace", False)),
            remote_name=str(management.get("remote_name") or "").strip(),
        ),
        sub2api=LegacySub2APISettings(
            base_url=str(
                sub2api.get("base_url") or "https://sub2api.upic.cloud"
            ).strip(),
            email=str(sub2api.get("email") or "").strip(),
            password=sub2api_password,
            push=bool(sub2api.get("push", False)),
            concurrency=concurrency,
            priority=priority,
        ),
    )


def _split_account_line(line: str) -> list[str]:
    raw = str(line or "").strip()
    if not raw or raw.startswith("#"):
        return []
    if "----" in raw:
        return [part.strip() for part in raw.split("----")]
    for delimiter in ("\t", "|", ","):
        if delimiter in raw:
            return [part.strip() for part in raw.split(delimiter)]
    return [raw]


def parse_legacy_mailboxes(payload: bytes | str) -> tuple[LegacyMailboxRow, ...]:
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise MigrationValidationError("mail account file is not valid UTF-8") from exc
    elif isinstance(payload, str):
        text = payload.lstrip("\ufeff")
    else:
        raise TypeError("mail account payload must be bytes or str")

    rows: list[LegacyMailboxRow] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        parts = _split_account_line(raw_line)
        if not parts:
            continue
        if len(parts) not in (3, 4):
            raise MigrationValidationError(
                f"mail account line {line_number} must contain three or four fields"
            )
        primary_email = str(parts[0] or "").strip().casefold()
        if _primary_email_for_alias(primary_email) != primary_email:
            raise MigrationValidationError(
                f"mail account line {line_number} has an invalid primary email"
            )
        if len(parts) == 4:
            password, client_id, refresh_token = parts[1], parts[2], parts[3]
        else:
            password, client_id, refresh_token = "", parts[1], parts[2]
        if not client_id or not refresh_token:
            raise MigrationValidationError(
                f"mail account line {line_number} lacks client_id or refresh_token"
            )
        if primary_email in seen:
            raise MigrationValidationError(
                f"mail account line {line_number} duplicates a primary email"
            )
        seen.add(primary_email)
        rows.append(
            LegacyMailboxRow(
                primary_email=primary_email,
                client_id=client_id,
                refresh_token=refresh_token,
                password=password,
            )
        )
    if not rows:
        raise MigrationValidationError("mail account file contains no valid accounts")
    return tuple(rows)


def parse_mailbox_inventory_import(
    payload: bytes | str,
) -> tuple[tuple[dict[str, Any], ...], int]:
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise MigrationValidationError(
                "mail account file is not valid UTF-8"
            ) from exc
    elif isinstance(payload, str):
        text = payload.lstrip("\ufeff")
    else:
        raise TypeError("mail account payload must be bytes or str")

    records: list[dict[str, Any]] = []
    invalid = 0
    seen: set[str] = set()
    for source_order, raw_line in enumerate(text.splitlines()):
        parts = _split_account_line(raw_line)
        if not parts:
            continue
        if len(parts) not in (3, 4):
            invalid += 1
            continue
        primary_email = str(parts[0] or "").strip().casefold()
        if _primary_email_for_alias(primary_email) != primary_email:
            invalid += 1
            continue
        if len(parts) == 4:
            password, client_id, refresh_token = parts[1], parts[2], parts[3]
        else:
            password, client_id, refresh_token = "", parts[1], parts[2]
        if not client_id or not refresh_token or primary_email in seen:
            invalid += 1
            continue
        seen.add(primary_email)
        records.append(
            {
                "primary_email": primary_email,
                "password": password,
                "client_id": client_id,
                "refresh_token": refresh_token,
                "source_order": source_order,
            }
        )
    if not records:
        raise MigrationValidationError("mail account file contains no valid accounts")
    return tuple(records), invalid


def mailbox_inventory_records_from_backup(
    backup: VerifiedBackup,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(backup, VerifiedBackup):
        raise TypeError("backup must be a VerifiedBackup")
    sources = [
        source for source in backup.sources if source.record.role == "mail_accounts"
    ]
    if len(sources) != 1:
        raise MigrationBackupError(
            "verified backup does not contain one mail account source"
        )
    parse_legacy_mailboxes(sources[0].content)
    records, invalid = parse_mailbox_inventory_import(sources[0].content)
    if invalid:
        raise MigrationBackupError("verified backup mail account source is invalid")
    return records


def _source_record(role: str, path: Path, ownership: str, payload: bytes) -> SourceRecord:
    return SourceRecord(
        role=role,
        path=path.resolve(),
        sha256=_sha256(payload),
        size=len(payload),
        ownership=ownership,
    )


def _read_required_file(path: Path, label: str) -> bytes:
    try:
        if not path.is_file():
            raise OSError("not a file")
        return path.read_bytes()
    except OSError as exc:
        raise MigrationValidationError(f"{label} is not readable: {path}") from exc


def discover_legacy(
    config_path: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> LegacyDiscovery:
    resolved_config = Path(config_path).resolve()
    if resolved_config.suffix.casefold() != ".json":
        raise MigrationValidationError("legacy workflow config must be a JSON file")
    config_payload = _read_required_file(resolved_config, "legacy workflow config")
    config = decode_legacy_config(resolved_config, config_payload, env=env)
    mail_payload = _read_required_file(config.mail_account_file, "mail account file")

    sources = [
        _source_record("workflow_config", resolved_config, "app_owned", config_payload),
        _source_record("mail_accounts", config.mail_account_file, "external", mail_payload),
    ]
    if config.state_path.exists():
        state_payload = _read_required_file(config.state_path, "workflow state")
        sources.append(
            _source_record(
                "workflow_state",
                config.state_path,
                "app_owned" if config.state_is_app_owned else "external",
                state_payload,
            )
        )

    paths = [str(source.path).casefold() for source in sources]
    if len(paths) != len(set(paths)):
        raise MigrationValidationError("legacy source paths overlap")
    return LegacyDiscovery(config=config, sources=tuple(sources))


def _read_discovered_sources(discovery: LegacyDiscovery) -> tuple[SourcePayload, ...]:
    payloads: list[SourcePayload] = []
    for record in discovery.sources:
        payload = _read_required_file(record.path, record.role.replace("_", " "))
        if len(payload) != record.size or _sha256(payload) != record.sha256:
            raise MigrationValidationError(
                f"legacy source changed after discovery: {record.path}"
            )
        payloads.append(SourcePayload(record=record, content=payload))
    return tuple(payloads)


def _validate_state_identity(
    state: Mapping[str, Any],
    config: LegacyConfig,
) -> None:
    version = state.get("version", 1)
    if version != 1:
        raise MigrationValidationError("legacy workflow state version is unsupported")
    steps = state.get("steps", {})
    if not isinstance(steps, Mapping):
        raise MigrationValidationError("legacy workflow state steps must be an object")

    candidates: list[Mapping[str, Any]] = [state]
    identity = state.get("identity")
    if isinstance(identity, Mapping):
        candidates.append(identity)
    complete = steps.get("complete")
    if isinstance(complete, Mapping):
        candidates.append(complete)

    expected = {
        "old_email": config.old_email,
        "new_email": config.new_email,
        "workspace_id": config.workspace_id,
    }
    matched_identity_fields: set[str] = set()
    for candidate in candidates:
        for key, expected_value in expected.items():
            actual = str(candidate.get(key) or "").strip()
            if not actual:
                continue
            matches = (
                actual.casefold() == expected_value.casefold()
                if key.endswith("email")
                else actual == expected_value
            )
            if not matches:
                raise MigrationValidationError(
                    f"legacy workflow state identity does not match {key}"
                )
            matched_identity_fields.add(key)
        actual_state_path = str(candidate.get("state_path") or "").strip()
        if actual_state_path:
            try:
                matches_path = (
                    str(Path(actual_state_path).resolve()).casefold()
                    == str(config.state_path).casefold()
                )
            except OSError:
                matches_path = False
            if not matches_path:
                raise MigrationValidationError(
                    "legacy workflow state identity does not match state_path"
                )

    invite = steps.get("invite")
    if isinstance(invite, Mapping):
        invited_email = str(invite.get("email") or "").strip()
        if invited_email:
            if invited_email.casefold() != config.new_email.casefold():
                raise MigrationValidationError(
                    "legacy workflow state identity does not match invited account"
                )
            matched_identity_fields.add("new_email")
    old_leave = steps.get("old_leave")
    if isinstance(old_leave, Mapping):
        exited_email = str(old_leave.get("email") or "").strip()
        if exited_email:
            if exited_email.casefold() != config.old_email.casefold():
                raise MigrationValidationError(
                    "legacy workflow state identity does not match exited account"
                )
            matched_identity_fields.add("old_email")

    if not config.state_is_app_owned and not (
        "workspace_id" in matched_identity_fields
        and {"old_email", "new_email"} & matched_identity_fields
    ):
        raise MigrationValidationError(
            "custom legacy workflow state does not prove workspace/account identity"
        )


def _manifest_digest(records: tuple[SourceRecord, ...]) -> str:
    manifest = [record.as_manifest() for record in records]
    return _sha256(_canonical_json(manifest))


def validate_legacy(discovery: LegacyDiscovery) -> LegacyImportModel:
    payloads = _read_discovered_sources(discovery)
    by_role = {source.record.role: source for source in payloads}
    mail_source = by_role.get("mail_accounts")
    if mail_source is None:
        raise MigrationValidationError("mail account source is missing")
    mailboxes = parse_legacy_mailboxes(mail_source.content)
    mailbox_by_primary = {row.primary_email: row for row in mailboxes}

    def bind(registration_email: str, account_password: str) -> LegacyAccountBinding:
        primary = _primary_email_for_alias(registration_email)
        mailbox = mailbox_by_primary.get(primary)
        if mailbox is None:
            raise MigrationValidationError(
                f"primary mailbox for {registration_email} was not found"
            )
        return LegacyAccountBinding(
            registration_email=registration_email.casefold(),
            primary_email=primary,
            account_password=account_password or mailbox.password,
            mailbox=mailbox,
        )

    state: Mapping[str, Any] | None = None
    state_source = by_role.get("workflow_state")
    if state_source is not None:
        state = _decode_json_object(state_source.content, "legacy workflow state")
        _validate_state_identity(state, discovery.config)

    records = tuple(source.record for source in payloads)
    return LegacyImportModel(
        config=discovery.config,
        mailboxes=mailboxes,
        old_binding=bind(discovery.config.old_email, discovery.config.old_password),
        new_binding=bind(discovery.config.new_email, discovery.config.new_password),
        state=state,
        sources=payloads,
        migration_id=_manifest_digest(records),
    )


def apply_import(model: LegacyImportModel, repository: ImportRepository) -> Any:
    apply_method = getattr(repository, "apply_legacy_import", None)
    if not callable(apply_method):
        raise TypeError("repository must implement apply_legacy_import(model)")
    return apply_method(model)


def _build_backup_payload(
    model: LegacyImportModel,
    *,
    schema_version: int,
    instance_id: str,
    sqlite_snapshot: bytes | None,
    created_at: str,
) -> dict[str, Any]:
    source_records = model.source_records
    manifest = [record.as_manifest() for record in source_records]
    sources = [
        {
            "role": source.record.role,
            "path": str(source.record.path),
            "content": base64.b64encode(source.content).decode("ascii"),
        }
        for source in model.sources
    ]
    snapshot = None
    if sqlite_snapshot is not None:
        snapshot = {
            "sha256": _sha256(sqlite_snapshot),
            "size": len(sqlite_snapshot),
            "content": base64.b64encode(sqlite_snapshot).decode("ascii"),
        }
    return {
        "format": _BACKUP_FORMAT,
        "version": _BACKUP_VERSION,
        "created_at": created_at,
        "schema_version": schema_version,
        "instance_id": instance_id,
        "migration_id": model.migration_id,
        "identity": {
            "workspace_id": model.config.workspace_id,
            "old_email": model.config.old_email,
            "new_email": model.config.new_email,
        },
        "manifest": {
            "source_count": len(manifest),
            "sources": manifest,
        },
        "sources": sources,
        "sqlite_snapshot": snapshot,
    }


def _encrypt_backup_payload(payload: Mapping[str, Any], secret_store: SecretStore) -> bytes:
    core = dict(payload)
    core_bytes = _canonical_json(core)
    wrapper = {
        "payload": core,
        "payload_sha256": _sha256(core_bytes),
    }
    try:
        encrypted = secret_store.encrypt(_canonical_json(wrapper), _BACKUP_PURPOSE)
    except (SecretStoreError, TypeError, ValueError) as exc:
        raise MigrationBackupError("encrypted backup creation failed") from exc
    return _BACKUP_HEADER.pack(_BACKUP_MAGIC, _BACKUP_VERSION) + encrypted


def _decode_base64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise MigrationBackupError(f"{label} content is invalid")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise MigrationBackupError(f"{label} content is invalid") from exc


def _record_from_manifest(value: Any) -> SourceRecord:
    if not isinstance(value, Mapping):
        raise MigrationBackupError("backup source manifest is invalid")
    role = str(value.get("role") or "")
    ownership = str(value.get("ownership") or "")
    digest = str(value.get("sha256") or "")
    try:
        size = int(value.get("size"))
    except (TypeError, ValueError) as exc:
        raise MigrationBackupError("backup source manifest is invalid") from exc
    path_value = str(value.get("path") or "")
    if (
        role not in _SOURCE_ROLES
        or ownership not in _OWNERSHIP_VALUES
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or size < 0
        or not path_value
        or not Path(path_value).is_absolute()
    ):
        raise MigrationBackupError("backup source manifest is invalid")
    return SourceRecord(
        role=role,
        path=Path(path_value),
        sha256=digest,
        size=size,
        ownership=ownership,
    )


def verify_backup_bytes(payload: bytes, secret_store: SecretStore) -> VerifiedBackup:
    if not isinstance(payload, bytes):
        raise TypeError("backup payload must be bytes")
    try:
        if len(payload) <= _BACKUP_HEADER.size:
            raise MigrationBackupError("backup envelope is invalid")
        magic, envelope_version = _BACKUP_HEADER.unpack_from(payload)
        if magic != _BACKUP_MAGIC or envelope_version != _BACKUP_VERSION:
            raise MigrationBackupError("backup envelope version is unsupported")
        decrypted = secret_store.decrypt(payload[_BACKUP_HEADER.size :], _BACKUP_PURPOSE)
        wrapper = _decode_json_object(decrypted, "backup payload")
    except MigrationBackupError:
        raise
    except (SecretStoreError, MigrationValidationError, struct.error) as exc:
        raise MigrationBackupError("encrypted backup verification failed") from exc

    core = wrapper.get("payload")
    payload_sha256 = str(wrapper.get("payload_sha256") or "")
    if not isinstance(core, Mapping) or _sha256(_canonical_json(core)) != payload_sha256:
        raise MigrationBackupError("backup payload hash mismatch")
    if core.get("format") != _BACKUP_FORMAT or core.get("version") != _BACKUP_VERSION:
        raise MigrationBackupError("backup payload version is unsupported")
    try:
        schema_version = int(core.get("schema_version"))
    except (TypeError, ValueError) as exc:
        raise MigrationBackupError("backup schema version is invalid") from exc
    instance_id = str(core.get("instance_id") or "").strip()
    created_at = str(core.get("created_at") or "").strip()
    migration_id = str(core.get("migration_id") or "").strip()
    identity_value = core.get("identity")
    if (
        schema_version < 1
        or not instance_id
        or not created_at
        or not re.fullmatch(r"[0-9a-f]{64}", migration_id)
        or not isinstance(identity_value, Mapping)
    ):
        raise MigrationBackupError("backup metadata is invalid")
    identity = {
        "workspace_id": str(identity_value.get("workspace_id") or ""),
        "old_email": str(identity_value.get("old_email") or ""),
        "new_email": str(identity_value.get("new_email") or ""),
    }
    if not all(identity.values()):
        raise MigrationBackupError("backup identity is invalid")

    manifest_value = core.get("manifest")
    sources_value = core.get("sources")
    if not isinstance(manifest_value, Mapping) or not isinstance(sources_value, list):
        raise MigrationBackupError("backup source manifest is invalid")
    manifest_sources = manifest_value.get("sources")
    if not isinstance(manifest_sources, list):
        raise MigrationBackupError("backup source manifest is invalid")
    try:
        source_count = int(manifest_value.get("source_count"))
    except (TypeError, ValueError) as exc:
        raise MigrationBackupError("backup source manifest is invalid") from exc
    if source_count != len(manifest_sources) or source_count != len(sources_value):
        raise MigrationBackupError("backup source count mismatch")

    records = tuple(_record_from_manifest(item) for item in manifest_sources)
    roles = [record.role for record in records]
    if roles.count("workflow_config") != 1 or roles.count("mail_accounts") != 1:
        raise MigrationBackupError("backup does not contain required legacy sources")
    if roles.count("workflow_state") > 1:
        raise MigrationBackupError("backup contains duplicate workflow state")
    identities = [(record.role, str(record.path).casefold()) for record in records]
    if len(identities) != len(set(identities)):
        raise MigrationBackupError("backup contains duplicate sources")
    if _manifest_digest(records) != migration_id:
        raise MigrationBackupError("backup migration identity mismatch")

    record_by_key = {
        (record.role, str(record.path)): record
        for record in records
    }
    verified_sources: list[SourcePayload] = []
    consumed: set[tuple[str, str]] = set()
    for item in sources_value:
        if not isinstance(item, Mapping):
            raise MigrationBackupError("backup source payload is invalid")
        key = (str(item.get("role") or ""), str(item.get("path") or ""))
        record = record_by_key.get(key)
        if record is None or key in consumed:
            raise MigrationBackupError("backup source payload does not match manifest")
        content = _decode_base64(item.get("content"), "backup source")
        if len(content) != record.size or _sha256(content) != record.sha256:
            raise MigrationBackupError("backup source hash mismatch")
        consumed.add(key)
        verified_sources.append(SourcePayload(record=record, content=content))
    if len(consumed) != len(records):
        raise MigrationBackupError("backup source payload is incomplete")

    snapshot_value = core.get("sqlite_snapshot")
    sqlite_snapshot: bytes | None = None
    if snapshot_value is not None:
        if not isinstance(snapshot_value, Mapping):
            raise MigrationBackupError("backup database snapshot is invalid")
        sqlite_snapshot = _decode_base64(
            snapshot_value.get("content"),
            "backup database snapshot",
        )
        try:
            expected_size = int(snapshot_value.get("size"))
        except (TypeError, ValueError) as exc:
            raise MigrationBackupError("backup database snapshot is invalid") from exc
        expected_hash = str(snapshot_value.get("sha256") or "")
        if len(sqlite_snapshot) != expected_size or _sha256(sqlite_snapshot) != expected_hash:
            raise MigrationBackupError("backup database snapshot hash mismatch")

    return VerifiedBackup(
        schema_version=schema_version,
        instance_id=instance_id,
        created_at=created_at,
        migration_id=migration_id,
        identity=identity,
        sources=tuple(verified_sources),
        sqlite_snapshot=sqlite_snapshot,
        payload_sha256=payload_sha256,
    )


def verify_backup(path: str | Path, secret_store: SecretStore) -> VerifiedBackup:
    backup_path = Path(path)
    try:
        payload = backup_path.read_bytes()
    except OSError as exc:
        raise MigrationBackupError(f"backup is not readable: {backup_path}") from exc
    return verify_backup_bytes(payload, secret_store)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def create_backup(
    model: LegacyImportModel,
    destination: str | Path,
    secret_store: SecretStore,
    *,
    schema_version: int,
    instance_id: str,
    sqlite_snapshot: bytes | None = None,
    created_at: str | None = None,
) -> VerifiedBackup:
    backup_path = Path(destination)
    if backup_path.suffix.casefold() != ".twbackup":
        raise MigrationBackupError("backup filename must use the .twbackup extension")
    if backup_path.exists():
        raise MigrationBackupError("backup destination already exists")
    if not isinstance(schema_version, int) or schema_version < 1:
        raise MigrationBackupError("backup schema version is invalid")
    if not str(instance_id or "").strip():
        raise MigrationBackupError("backup instance identifier is required")
    if sqlite_snapshot is not None and not isinstance(sqlite_snapshot, bytes):
        raise TypeError("sqlite_snapshot must be bytes or None")
    timestamp = created_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    core = _build_backup_payload(
        model,
        schema_version=schema_version,
        instance_id=str(instance_id).strip(),
        sqlite_snapshot=sqlite_snapshot,
        created_at=timestamp,
    )
    encrypted = _encrypt_backup_payload(core, secret_store)
    verify_backup_bytes(encrypted, secret_store)
    _atomic_write(backup_path, encrypted)
    try:
        return verify_backup(backup_path, secret_store)
    except Exception:
        try:
            backup_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _source_signature(record: SourceRecord) -> tuple[str, str, str, int, str]:
    return (
        record.role,
        str(record.path).casefold(),
        record.sha256,
        record.size,
        record.ownership,
    )


def cleanup_plaintext(
    model: LegacyImportModel,
    verified_backup: VerifiedBackup,
    *,
    remove_file: Callable[[Path], None] | None = None,
) -> CleanupResult:
    if verified_backup.migration_id != model.migration_id:
        raise MigrationBackupError("verified backup does not match the migration")
    expected = {_source_signature(record) for record in model.source_records}
    actual = {_source_signature(source.record) for source in verified_backup.sources}
    if expected != actual:
        raise MigrationBackupError("verified backup sources do not match the migration")

    remover = remove_file or (lambda path: path.unlink())
    removed: list[Path] = []
    preserved: list[Path] = []
    missing: list[Path] = []
    failures: list[CleanupFailure] = []
    for record in model.source_records:
        path = record.path
        if record.role not in _CLEANUP_ROLES or record.ownership != "app_owned":
            preserved.append(path)
            continue
        if not path.exists():
            missing.append(path)
            continue
        try:
            current = path.read_bytes()
        except OSError:
            failures.append(CleanupFailure(path=path, code="read_failed"))
            continue
        if len(current) != record.size or _sha256(current) != record.sha256:
            failures.append(CleanupFailure(path=path, code="source_changed"))
            continue
        try:
            remover(path)
        except OSError:
            failures.append(CleanupFailure(path=path, code="remove_failed"))
            continue
        if path.exists():
            failures.append(CleanupFailure(path=path, code="remove_failed"))
            continue
        removed.append(path)
    return CleanupResult(
        status="cleanup_blocked" if failures else "cleanup_complete",
        removed=tuple(removed),
        preserved=tuple(preserved),
        missing=tuple(missing),
        failures=tuple(failures),
    )


def validate_restore(
    candidate: VerifiedBackup,
    repository: RestoreRepository,
) -> Any:
    if candidate.sqlite_snapshot is None:
        raise MigrationBackupError("backup does not contain a database snapshot")
    validate_method = getattr(repository, "validate_restore_candidate", None)
    if not callable(validate_method):
        raise TypeError(
            "repository must implement validate_restore_candidate(candidate)"
        )
    return validate_method(candidate)


def restore_backup(
    path: str | Path,
    secret_store: SecretStore,
    repository: RestoreRepository,
) -> Any:
    candidate = verify_backup(path, secret_store)
    validation = validate_restore(candidate, repository)
    restore_method = getattr(repository, "restore_verified_backup", None)
    if not callable(restore_method):
        raise TypeError(
            "repository must implement restore_verified_backup(candidate, validation)"
        )
    return restore_method(candidate, validation)


__all__ = [
    "CleanupFailure",
    "CleanupResult",
    "ImportRepository",
    "LegacyAccountBinding",
    "LegacyConfig",
    "LegacyDiscovery",
    "LegacyImportModel",
    "LegacyMailboxRow",
    "LegacyManagementSettings",
    "LegacySub2APISettings",
    "MigrationBackupError",
    "MigrationError",
    "MigrationValidationError",
    "RestoreRepository",
    "SourcePayload",
    "SourceRecord",
    "VerifiedBackup",
    "apply_import",
    "cleanup_plaintext",
    "create_backup",
    "decode_legacy_config",
    "discover_legacy",
    "legacy_state_filename",
    "mailbox_inventory_records_from_backup",
    "parse_mailbox_inventory_import",
    "parse_legacy_mailboxes",
    "restore_backup",
    "validate_legacy",
    "validate_restore",
    "verify_backup",
    "verify_backup_bytes",
]
