from __future__ import annotations

import copy
import re
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from .database import Database, StateConflictError
from .registrar import MailboxCredentials, RegistrarProxyLease
from .workflow import (
    AccountSpec,
    WorkflowCancelled,
    WorkflowConfig,
    WorkflowIdentityError,
    WorkflowRunner,
)
from .workflow_display import STEP_IDS, is_routine_log, log_level


_AUTHENTICATED_URL_RE = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^\s/@]+)@"
)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off", ""})


def redact_text(value: Any, secrets: tuple[str, ...] | list[str] = ()) -> str:
    clean = str(value)
    for secret in sorted({str(item) for item in secrets if str(item)}, key=len, reverse=True):
        clean = clean.replace(secret, "***")
    return _AUTHENTICATED_URL_RE.sub(r"\g<scheme>***@", clean)


def redact_value(value: Any, secrets: tuple[str, ...] | list[str] = ()) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        return {
            str(key): redact_value(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return "<bytes>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(value, secrets)


class DatabaseCheckpointStore:
    """Persist one encrypted, complete checkpoint document after every mutation."""

    def __init__(self, database: Database, run_id: str) -> None:
        self.database = database
        self.run_id = str(run_id)
        self._lock = threading.RLock()
        loaded = database.get_run_checkpoint(self.run_id)
        self._values: dict[str, Any] = copy.deepcopy(loaded or {})

    def get(self, name: str) -> Any:
        with self._lock:
            return copy.deepcopy(self._values.get(name))

    def set(self, name: str, value: Any) -> None:
        with self._lock:
            candidate = copy.deepcopy(self._values)
            candidate[str(name)] = copy.deepcopy(value)
            self.database.set_run_checkpoint(
                self.run_id,
                candidate,
                current_step=str(name) if str(name) in STEP_IDS else None,
            )
            self._values = candidate

    def mark_step(self, step: str) -> None:
        if step not in STEP_IDS:
            return
        with self._lock:
            self.database.set_run_checkpoint(
                self.run_id,
                copy.deepcopy(self._values),
                current_step=step,
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._values)


class TaskQueue:
    def __init__(
        self,
        database: Database,
        *,
        runner_factory: Callable[..., Any] = WorkflowRunner,
        shutdown_timeout: float = 5.0,
    ) -> None:
        self.database = database
        self.runner_factory = runner_factory
        self.shutdown_timeout = max(0.0, float(shutdown_timeout))
        self._condition = threading.Condition(threading.RLock())
        self._revision = 0
        self._thread: threading.Thread | None = None
        self._started = False
        self._closing = False
        self._active_run_id: str | None = None
        self._active_stop_event: threading.Event | None = None
        self._last_worker_error: str | None = None

    @property
    def revision(self) -> int:
        with self._condition:
            return self._revision

    @property
    def active_run_id(self) -> str | None:
        with self._condition:
            return self._active_run_id

    def _bump_locked(self) -> int:
        self._revision += 1
        self._condition.notify_all()
        return self._revision

    def notify_change(self) -> int:
        with self._condition:
            return self._bump_locked()

    def wait_for_change(self, after_revision: int, timeout: float | None = None) -> int:
        target = max(0, int(after_revision))
        with self._condition:
            self._condition.wait_for(
                lambda: self._revision > target or self._closing,
                timeout=timeout,
            )
            return self._revision

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            return {
                "paused": self.database.is_queue_paused(),
                "active_run_id": self._active_run_id,
                "items": self.database.list_queue(),
                "revision": self._revision,
                "started": self._started,
                "closing": self._closing,
                "last_worker_error": self._last_worker_error,
            }

    def start(self) -> tuple[str, ...]:
        with self._condition:
            if self._started:
                return ()
            recovered = tuple(self.database.recover_interrupted_runs())
            for run_id in recovered:
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="interrupted run recovered and requeued",
                )
            self._closing = False
            self._started = True
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="workflow-task-queue",
                daemon=True,
            )
            self._bump_locked()
            self._thread.start()
            return recovered

    def enqueue(self, workspace_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        with self._condition:
            runs = self.database.enqueue_workspaces(workspace_ids)
            for run in runs:
                self._append_event_locked(
                    run["id"], step=None, level="info", message="run queued"
                )
            self._bump_locked()
            return runs

    def set_paused(self, paused: bool) -> bool:
        with self._condition:
            result = self.database.set_queue_paused(bool(paused))
            self._bump_locked()
            return result

    def pause(self) -> bool:
        return self.set_paused(True)

    def resume(self) -> bool:
        return self.set_paused(False)

    def reorder(self, queue_item_ids: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
        with self._condition:
            queue = self.database.reorder_queue(queue_item_ids)
            self._bump_locked()
            return queue

    def stop(self, run_id: str) -> str:
        run_id = str(run_id)
        with self._condition:
            state = self.database.request_stop(run_id)
            if state == "stopping" and self._active_run_id == run_id:
                if self._active_stop_event is not None:
                    self._active_stop_event.set()
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="stop requested",
                )
            elif state == "cancelled":
                self._append_event_locked(
                    run_id,
                    step=None,
                    level="warning",
                    message="queued run cancelled",
                )
            self._bump_locked()
            return state

    def retry(self, run_id: str) -> dict[str, Any]:
        run_id = str(run_id)
        with self._condition:
            run = self.database.retry_run(run_id)
            self._append_event_locked(
                run_id,
                step=None,
                level="info",
                message="failed run queued for retry",
            )
            self._bump_locked()
            return run

    def shutdown(self, timeout: float | None = None) -> bool:
        wait_timeout = self.shutdown_timeout if timeout is None else max(0.0, float(timeout))
        with self._condition:
            thread = self._thread
            if thread is None:
                self._closing = True
                self._started = False
                self._bump_locked()
                return True
            self._closing = True
            if self._active_run_id is not None:
                try:
                    self.database.request_stop(self._active_run_id)
                except StateConflictError:
                    pass
                if self._active_stop_event is not None:
                    self._active_stop_event.set()
            self._bump_locked()
        thread.join(wait_timeout)
        stopped = not thread.is_alive()
        with self._condition:
            if stopped:
                self._thread = None
                self._started = False
            self._bump_locked()
        return stopped

    def _worker_loop(self) -> None:
        try:
            while True:
                with self._condition:
                    item = None
                    while item is None:
                        if self._closing:
                            return
                        try:
                            paused = self.database.is_queue_paused()
                            item = None if paused else self.database.claim_next_queue_item()
                        except Exception as exc:
                            self._last_worker_error = redact_text(exc)
                            self._condition.wait(timeout=0.25)
                            continue
                        if item is None:
                            self._condition.wait()
                    run_id = str(item["run_id"])
                    stop_event = threading.Event()
                    self._active_run_id = run_id
                    self._active_stop_event = stop_event
                    self._last_worker_error = None
                    self._bump_locked()
                self._execute_claimed(run_id, stop_event)
                with self._condition:
                    self._active_run_id = None
                    self._active_stop_event = None
                    self._bump_locked()
        finally:
            with self._condition:
                self._active_run_id = None
                self._active_stop_event = None
                self._started = False
                self._condition.notify_all()

    def _execute_claimed(self, run_id: str, stop_event: threading.Event) -> None:
        secrets: tuple[str, ...] = ()
        try:
            checkpoint = DatabaseCheckpointStore(self.database, run_id)
            config, old_mailbox, new_mailbox, proxy, secrets = self._build_run_inputs(run_id)
            current_step: list[str | None] = [None]

            def on_log(message: str) -> None:
                clean = redact_text(message, secrets)
                self._append_event(
                    run_id,
                    step=current_step[0],
                    level=log_level(clean),
                    message=clean,
                    routine=is_routine_log(clean),
                )

            def on_event(event: Mapping[str, Any]) -> None:
                if event.get("type") != "step":
                    return
                step = str(event.get("step") or "")
                state = str(event.get("state") or "")
                if step not in STEP_IDS or state not in {
                    "active",
                    "done",
                    "skipped",
                    "error",
                    "cancelled",
                }:
                    return
                if state == "active":
                    current_step[0] = step
                    checkpoint.mark_step(step)
                elif current_step[0] == step:
                    current_step[0] = None
                level = "error" if state == "error" else "warning" if state == "cancelled" else "info"
                self._append_event(
                    run_id,
                    step=step,
                    level=level,
                    message=f"stage {state}",
                )

            self._append_event(run_id, step=None, level="info", message="run started")
            runner = self.runner_factory(
                config,
                checkpoint_store=checkpoint,
                old_mailbox=old_mailbox,
                new_mailbox=new_mailbox,
                expanded_proxy=proxy,
                verbose=False,
                stop_event=stop_event,
                logger=on_log,
                event_callback=on_event,
            )
            result = runner.run()
            if stop_event.is_set() or self.database.get_run(run_id)["state"] == "stopping":
                self.database.mark_run_cancelled(run_id)
                self._append_event(
                    run_id, step=current_step[0], level="warning", message="run cancelled"
                )
            else:
                safe_result = redact_value(result, secrets)
                self.database.complete_run_and_rotate(
                    run_id,
                    safe_result if isinstance(safe_result, Mapping) else None,
                )
                self._append_event(run_id, step=None, level="info", message="run succeeded")
        except WorkflowIdentityError as exc:
            try:
                current_state = self.database.get_run(run_id)["state"]
                if current_state == "stopping" or stop_event.is_set():
                    self.database.mark_run_cancelled(run_id)
                    self._append_event(
                        run_id, step=None, level="warning", message="run cancelled"
                    )
                else:
                    safe_error = redact_text(exc, secrets)
                    self.database.fail_run_and_replace_account(
                        run_id,
                        role=exc.role,
                        failure_code=exc.code,
                        redacted_error=safe_error,
                    )
                    self._append_event(
                        run_id,
                        step=None,
                        level="error",
                        message=f"run failed: {safe_error}",
                    )
            except Exception as terminal_exc:
                try:
                    current_state = self.database.get_run(run_id)["state"]
                    if current_state in {"running", "stopping"}:
                        safe_error = redact_text(exc, secrets)
                        self.database.fail_run(run_id, safe_error)
                        self._append_event(
                            run_id,
                            step=None,
                            level="error",
                            message=f"run failed: {safe_error}",
                        )
                except Exception:
                    pass
                with self._condition:
                    self._last_worker_error = redact_text(terminal_exc, secrets)
        except WorkflowCancelled:
            self.database.mark_run_cancelled(run_id)
            self._append_event(run_id, step=None, level="warning", message="run cancelled")
        except Exception as exc:
            try:
                current_state = self.database.get_run(run_id)["state"]
                if current_state == "stopping" or stop_event.is_set():
                    self.database.mark_run_cancelled(run_id)
                    self._append_event(
                        run_id, step=None, level="warning", message="run cancelled"
                    )
                else:
                    safe_error = redact_text(exc, secrets)
                    self.database.fail_run(run_id, safe_error)
                    self._append_event(
                        run_id,
                        step=None,
                        level="error",
                        message=f"run failed: {safe_error}",
                    )
            except Exception as terminal_exc:
                with self._condition:
                    self._last_worker_error = redact_text(terminal_exc, secrets)
        finally:
            secrets = ()

    def _build_run_inputs(
        self, run_id: str
    ) -> tuple[
        WorkflowConfig,
        MailboxCredentials,
        MailboxCredentials,
        str,
        tuple[str, ...],
    ]:
        run = self.database.get_run(run_id)
        workspace = self.database.get_workspace(run["workspace_id"])
        if (
            workspace["current_account_id"] != run["current_account_id"]
            or workspace["next_account_id"] != run["next_account_id"]
            or workspace["workspace_uid"] != run["workspace_uid_snapshot"]
        ):
            raise StateConflictError("workspace no longer matches the run snapshot")

        old_account = self.database.get_account(run["current_account_id"])
        new_account = self.database.get_account(run["next_account_id"])
        if (
            old_account["email"].casefold() != run["current_email_snapshot"].casefold()
            or new_account["email"].casefold() != run["next_email_snapshot"].casefold()
        ):
            raise StateConflictError("account identity no longer matches the run snapshot")

        old_credentials = self.database.get_account_credentials(old_account["id"])
        new_credentials = self.database.get_account_credentials(new_account["id"])
        old_mailbox = self._mailbox(old_account, old_credentials)
        new_mailbox = self._mailbox(new_account, new_credentials)

        proxy_template = self._secret_setting("proxy")
        proxy = self.database.get_run_proxy(run_id) if run["proxy_configured"] else None
        if proxy is None:
            with RegistrarProxyLease(explicit_proxy=proxy_template) as lease:
                proxy = lease.proxy or ""
            self.database.set_run_proxy(run_id, proxy)

        management_key = self._secret_setting("management_api_key")
        sub2api_password = self._secret_setting("sub2api_password")
        output_dir = Path(self._text_setting("output_dir", "output")).expanduser().resolve()
        config = WorkflowConfig(
            old_account=AccountSpec(
                run["current_email_snapshot"],
                str(old_credentials.get("account_password") or ""),
            ),
            new_account=AccountSpec(
                run["next_email_snapshot"],
                str(new_credentials.get("account_password") or ""),
            ),
            workspace_id=run["workspace_uid_snapshot"],
            proxy=proxy,
            pat_name=self._text_setting("pat_name", run["next_email_snapshot"]),
            pat_ttl=self._int_setting("pat_ttl", 5_184_000, minimum=60),
            output_dir=output_dir,
            management_base_url=self._text_setting(
                "management_base_url", "https://upic.cloud"
            ),
            management_key=management_key,
            push=self._bool_setting("management_push", False),
            replace=self._bool_setting("management_replace", False),
            remote_name=self._text_setting("management_remote_name", ""),
            invite_settle_seconds=self._float_setting(
                "invite_settle_seconds", 2.0, minimum=0.0
            ),
            sub2api_base_url=self._text_setting(
                "sub2api_base_url", "https://sub2api.upic.cloud"
            ),
            sub2api_email=self._text_setting("sub2api_email", ""),
            sub2api_password=sub2api_password,
            sub2api_push=self._bool_setting("sub2api_push", False),
            sub2api_concurrency=self._int_setting(
                "sub2api_concurrency", 10, minimum=0
            ),
            sub2api_priority=self._int_setting("sub2api_priority", 1, minimum=0),
        )
        known_secrets = tuple(
            sorted(
                {
                    str(value)
                    for value in (
                        *old_credentials.values(),
                        *new_credentials.values(),
                        proxy_template,
                        proxy,
                        management_key,
                        sub2api_password,
                    )
                    if value
                },
                key=len,
                reverse=True,
            )
        )
        return config, old_mailbox, new_mailbox, proxy, known_secrets

    @staticmethod
    def _mailbox(
        account: Mapping[str, Any], credentials: Mapping[str, Any]
    ) -> MailboxCredentials:
        client_id = str(credentials.get("client_id") or "").strip()
        refresh_token = str(credentials.get("refresh_token") or "").strip()
        if not client_id or not refresh_token:
            raise StateConflictError("account mailbox credentials are incomplete")
        return MailboxCredentials(
            primary_email=str(account["primary_email"]),
            registration_email=str(account["email"]),
            client_id=client_id,
            refresh_token=refresh_token,
            password=str(credentials.get("mailbox_password") or ""),
        )

    def _text_setting(self, key: str, default: str) -> str:
        value = self.database.get_text_setting(key, default)
        return default if value is None else str(value)

    def _secret_setting(self, key: str) -> str:
        value = self.database.get_secret_setting(key)
        return "" if value is None else value.decode("utf-8")

    def _bool_setting(self, key: str, default: bool) -> bool:
        value = self._text_setting(key, "1" if default else "0").strip().casefold()
        if value in _TRUE_VALUES:
            return True
        if value in _FALSE_VALUES:
            return False
        raise StateConflictError(f"setting {key} is not a boolean")

    def _int_setting(self, key: str, default: int, *, minimum: int) -> int:
        try:
            value = int(self._text_setting(key, str(default)))
        except ValueError as exc:
            raise StateConflictError(f"setting {key} is not an integer") from exc
        return max(minimum, value)

    def _float_setting(self, key: str, default: float, *, minimum: float) -> float:
        try:
            value = float(self._text_setting(key, str(default)))
        except ValueError as exc:
            raise StateConflictError(f"setting {key} is not a number") from exc
        return max(minimum, value)

    def _append_event(
        self,
        run_id: str,
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
    ) -> dict[str, Any]:
        event = self.database.append_run_event(
            run_id,
            step=step,
            level=level,
            message=message,
            routine=routine,
        )
        self.notify_change()
        return event

    def _append_event_locked(
        self,
        run_id: str,
        *,
        step: str | None,
        level: str,
        message: str,
        routine: bool = False,
    ) -> dict[str, Any]:
        event = self.database.append_run_event(
            run_id,
            step=step,
            level=level,
            message=message,
            routine=routine,
        )
        self._bump_locked()
        return event
