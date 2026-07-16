from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from team_protocol.database import Database
from team_protocol.migration import CleanupFailure, CleanupResult, cleanup_plaintext
from team_protocol.web_console import (
    ConsoleAlreadyRunningError,
    WebConsoleController,
    _ConsoleInstanceLock,
    _event_stream,
    create_app,
    serve_web_console,
)


class MemorySecretStore:
    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        key = purpose.encode("utf-8") or b"x"
        return b"test:" + bytes(
            value ^ key[index % len(key)] for index, value in enumerate(plaintext)
        )

    def decrypt(self, ciphertext: bytes, purpose: str) -> bytes:
        payload = bytes(ciphertext)
        if not payload.startswith(b"test:"):
            raise ValueError("invalid ciphertext")
        key = purpose.encode("utf-8") or b"x"
        return bytes(
            value ^ key[index % len(key)]
            for index, value in enumerate(payload[5:])
        )


class FakeTaskQueue:
    def __init__(self, database: Database) -> None:
        self.database = database
        self._condition = threading.Condition()
        self._revision = 0
        self.started = 0
        self.shutdown_calls = 0

    @property
    def revision(self):
        with self._condition:
            return self._revision

    def notify_change(self):
        with self._condition:
            self._revision += 1
            self._condition.notify_all()
            return self._revision

    def wait_for_change(self, after_revision, timeout=None):
        with self._condition:
            self._condition.wait_for(
                lambda: self._revision > after_revision,
                timeout=timeout,
            )
            return self._revision

    def start(self):
        self.started += 1
        self.notify_change()
        return ()

    def shutdown(self, timeout=None):
        del timeout
        self.shutdown_calls += 1
        self.notify_change()
        return True

    def snapshot(self):
        return {
            "paused": self.database.is_queue_paused(),
            "active_run_id": None,
            "items": self.database.list_queue(),
            "revision": self.revision,
            "started": bool(self.started),
            "closing": False,
            "last_worker_error": None,
        }

    def enqueue(self, workspace_ids):
        result = self.database.enqueue_workspaces(workspace_ids)
        for run in result:
            self.database.append_run_event(
                run["id"], step=None, level="info", message="run queued"
            )
        self.notify_change()
        return result

    def reorder(self, queue_item_ids):
        result = self.database.reorder_queue(queue_item_ids)
        self.notify_change()
        return result

    def set_paused(self, paused):
        result = self.database.set_queue_paused(paused)
        self.notify_change()
        return result

    def stop(self, run_id):
        result = self.database.request_stop(run_id)
        self.notify_change()
        return result

    def retry(self, run_id):
        result = self.database.retry_run(run_id)
        self.notify_change()
        return result


class WebConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.root = Path(self.temp_directory.name)
        self.store = MemorySecretStore()
        self.database = Database(self.root / "console.db", secret_store=self.store)
        self.queue = FakeTaskQueue(self.database)
        self.controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
        )
        self.origin_headers = {
            "Origin": "http://testserver",
            "X-Workflow-Token": self.controller.request_token,
        }

    def account(self, suffix, *, primary=None):
        primary_email = primary or f"primary-{suffix}@example.com"
        return self.database.create_account(
            account_id=f"account-{suffix}",
            email=f"person+{suffix}@example.com",
            primary_email=primary_email,
            credentials={
                "mailbox_password": f"mail-secret-{suffix}",
                "client_id": f"client-{suffix}",
                "refresh_token": f"refresh-secret-{suffix}",
                "account_password": f"account-secret-{suffix}",
            },
            source="test",
        )

    def workspace(self, suffix="one"):
        current = self.account(f"{suffix}-current")
        next_account = self.account(f"{suffix}-next")
        workspace = self.database.create_workspace(
            workspace_id=f"workspace-{suffix}",
            name=f"Space {suffix}",
            workspace_uid=f"workspace-uid-{suffix}",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        return workspace, current, next_account

    @staticmethod
    def inventory_record(email, order=0):
        return {
            "primary_email": email,
            "client_id": f"client-{order}",
            "refresh_token": f"inventory-refresh-secret-{order}",
            "password": f"inventory-mail-secret-{order}",
            "source_order": order,
        }

    def legacy_fixture(self):
        config = self.root / "workflow.json"
        mail = self.root / "hotmail.txt"
        mail.write_text(
            "main@example.com----mail-pass----client-main----refresh-main\n",
            encoding="utf-8",
        )
        config.write_text(
            json.dumps(
                {
                    "mail_account_file": str(mail),
                    "workspace_id": "legacy-workspace",
                    "old_account": {"email": "main+1@example.com"},
                    "new_account": {"email": "main+2@example.com"},
                    "output_dir": str(self.root / "output"),
                    "management": {"push": False},
                    "sub2api": {"push": False},
                }
            ),
            encoding="utf-8",
        )
        return config, mail

    def test_console_instance_lock_rejects_second_owner_and_releases(self):
        first = _ConsoleInstanceLock(self.root)
        second = _ConsoleInstanceLock(self.root)
        first.acquire()
        try:
            first.set_owner_url("http://127.0.0.1:9012")
            with self.assertRaises(ConsoleAlreadyRunningError) as caught:
                second.acquire()
            self.assertEqual(caught.exception.url, "http://127.0.0.1:9012")
        finally:
            first.release()

        second.acquire()
        second.release()

    def test_console_instance_lock_is_released_when_owner_process_exits(self):
        script = (
            "import sys, time\n"
            "from team_protocol.web_console import _ConsoleInstanceLock\n"
            "lock = _ConsoleInstanceLock(sys.argv[1])\n"
            "lock.acquire()\n"
            "lock.set_owner_url('http://127.0.0.1:9014')\n"
            "print('locked', flush=True)\n"
            "time.sleep(30)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(self.root)],
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        contender = _ConsoleInstanceLock(self.root)
        try:
            self.assertEqual(process.stdout.readline().strip(), "locked")
            with self.assertRaises(ConsoleAlreadyRunningError) as caught:
                contender.acquire()
            self.assertEqual(caught.exception.url, "http://127.0.0.1:9014")
        finally:
            process.terminate()
            process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

        contender.acquire()
        contender.release()

    def test_second_server_uses_existing_instance_without_starting_controller(self):
        owner = _ConsoleInstanceLock(self.root)
        owner.acquire()
        owner.set_owner_url("http://127.0.0.1:9013")
        try:
            with (
                patch(
                    "team_protocol.web_console.WebConsoleController",
                    side_effect=AssertionError("second instance constructed a controller"),
                ),
                patch("team_protocol.web_console.webbrowser.open") as open_browser,
            ):
                result = serve_web_console(
                    port=9012,
                    open_browser=True,
                    app_dir=self.root,
                )
        finally:
            owner.release()

        self.assertEqual(result, 0)
        open_browser.assert_called_once_with("http://127.0.0.1:9013")

    def test_bootstrap_is_domain_shaped_and_redacts_all_secrets(self):
        self.workspace()
        self.database.set_secret_setting("proxy", "http://user:proxy-secret@proxy.invalid")
        self.database.set_secret_setting("management_api_key", "management-canary")

        payload = self.controller.bootstrap()
        serialized = json.dumps(payload)

        self.assertIn("workspaces", payload)
        self.assertIn("accounts", payload)
        self.assertIn("queue", payload)
        self.assertNotIn("config_path", serialized)
        self.assertNotIn("credential_blob", serialized)
        self.assertNotIn("mail-secret", serialized)
        self.assertNotIn("refresh-secret", serialized)
        self.assertNotIn("proxy-secret", serialized)
        self.assertNotIn("management-canary", serialized)
        self.assertTrue(payload["settings"]["secrets"]["proxy"])

    def test_large_inventory_is_absent_from_bootstrap_and_sse_reset(self):
        before = len(json.dumps(self.controller.bootstrap(), sort_keys=True))
        records = [
            self.inventory_record(f"inventory-{index}@example.com", index)
            for index in range(250)
        ]
        self.database.import_mailbox_inventory(records)

        bootstrap = self.controller.bootstrap()
        reset = self.controller.event_reset()
        after = len(json.dumps(bootstrap, sort_keys=True))
        serialized = json.dumps({"bootstrap": bootstrap, "reset": reset})

        self.assertLess(after - before, 256)
        self.assertNotIn("mailbox_inventory", serialized)
        self.assertNotIn("inventory-249@example.com", serialized)
        self.assertNotIn("inventory-refresh-secret", serialized)
        self.assertNotIn("inventory-mail-secret", serialized)
        self.assertNotIn("client-249", serialized)

    def test_startup_repairs_overbroad_legacy_account_inventory(self):
        primary_email = "main@example.com"
        current = self.account("current", primary=primary_email)
        next_account = self.account("next", primary=primary_email)
        self.database.create_workspace(
            name="Legacy Space",
            workspace_uid="legacy-space",
            current_account_id=current["id"],
            next_account_id=next_account["id"],
        )
        related_primary = self.database.create_account(
            email=primary_email,
            primary_email=primary_email,
            credentials={"client_id": "main-client", "refresh_token": "main-refresh"},
            source="legacy_txt",
        )
        orphan = self.database.create_account(
            email="orphan@example.com",
            primary_email="orphan@example.com",
            credentials={"client_id": "orphan-client", "refresh_token": "orphan-refresh"},
            source="legacy_txt",
        )
        manual = self.database.create_account(
            email="manual@example.com",
            primary_email="manual@example.com",
            credentials={"client_id": "manual-client", "refresh_token": "manual-refresh"},
            source="txt_import",
        )
        self.database.set_meta("migration_status", "complete")

        health = self.controller.startup()

        remaining = {account["id"] for account in self.database.list_accounts()}
        self.assertTrue(health["ready"])
        self.assertNotIn(orphan["id"], remaining)
        self.assertIn(related_primary["id"], remaining)
        self.assertIn(manual["id"], remaining)
        self.assertEqual(self.database.get_meta("legacy_account_scope_version"), "1")

    def test_security_middleware_requires_token_and_same_origin(self):
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            denied = client.post("/api/queue/pause", json={"paused": True})
            wrong_origin = client.post(
                "/api/queue/pause",
                json={"paused": True},
                headers={
                    "Origin": "https://evil.example",
                    "X-Workflow-Token": self.controller.request_token,
                },
            )
            allowed = client.post(
                "/api/queue/pause",
                json={"paused": True},
                headers=self.origin_headers,
            )
            bootstrap = client.get("/api/bootstrap")

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"]["code"], "invalid_request_token")
        self.assertEqual(wrong_origin.status_code, 403)
        self.assertEqual(allowed.status_code, 200)
        self.assertTrue(allowed.json()["paused"])
        self.assertEqual(bootstrap.status_code, 200)
        self.assertEqual(self.queue.started, 1)
        self.assertEqual(self.queue.shutdown_calls, 1)

    def test_workspace_crud_binding_and_stale_version_errors(self):
        current = self.account("create-current")
        next_account = self.account("create-next")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            created = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Created Space",
                    "workspace_uid": "uid-created",
                    "current_account_id": current["id"],
                    "next_account_id": next_account["id"],
                },
            )
            workspace = created.json()
            renamed = client.patch(
                f"/api/workspaces/{workspace['id']}",
                headers=self.origin_headers,
                json={"version": workspace["version"], "name": "Renamed Space"},
            )
            stale = client.patch(
                f"/api/workspaces/{workspace['id']}",
                headers=self.origin_headers,
                json={"version": workspace["version"], "name": "Stale"},
            )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.json()["name"], "Renamed Space")
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "stale_workspace_version")

    def test_account_import_populates_inventory_and_allocation_never_returns_credentials(self):
        txt = self.root / "hotmail.txt"
        txt.write_text(
            "primary@example.com----mail-password----client-id----refresh-token\n"
            "invalid-row-with-secret\n",
            encoding="utf-8",
        )
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            imported = client.post(
                "/api/accounts/import",
                headers=self.origin_headers,
                json={"path": str(txt)},
            )
            inventory = client.get(
                "/api/mailbox-inventory?query=PRIMARY&limit=20",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            inventory_item = inventory.json()[0]
            alias = client.post(
                "/api/accounts/alias",
                headers=self.origin_headers,
                json={"inventory_id": inventory_item["id"]},
            )
            disabled = client.patch(
                f"/api/accounts/{alias.json()['id']}/status",
                headers=self.origin_headers,
                json={"status": "disabled"},
            )

            too_large = client.get(
                "/api/mailbox-inventory?query=primary&limit=21",
                headers={"X-Workflow-Token": self.controller.request_token},
            )
            bootstrap = client.get("/api/bootstrap")

        body = imported.text + inventory.text + alias.text + disabled.text + bootstrap.text
        self.assertEqual(imported.status_code, 201)
        self.assertEqual(imported.json()["imported"], 1)
        self.assertEqual(imported.json()["invalid"], 1)
        self.assertEqual(inventory.status_code, 200)
        self.assertEqual(len(inventory.json()), 1)
        self.assertEqual(alias.status_code, 201)
        self.assertEqual(alias.json()["email"], "primary+1@example.com")
        self.assertEqual(alias.json()["primary_email"], "primary@example.com")
        self.assertEqual(disabled.json()["status"], "disabled")
        self.assertEqual(too_large.status_code, 422)
        self.assertNotIn("mailbox_inventory", bootstrap.json())
        self.assertNotIn("inventory", bootstrap.json())
        self.assertNotIn("mail-password", body)
        self.assertNotIn("refresh-token", body)
        self.assertNotIn("client-id", body)

    def test_workspace_inventory_selection_and_replace_api_are_transactional(self):
        imported = self.database.import_mailbox_inventory(
            [
                self.inventory_record("rotate@example.com", 0),
                self.inventory_record("fallback@example.com", 1),
            ]
        )
        self.assertEqual(imported["imported"], 2)
        rotate = self.database.search_mailbox_inventory(query="rotate", limit=20)[0]
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            created = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Inventory Space",
                    "workspace_uid": "inventory-space",
                    "current_inventory_id": rotate["id"],
                    "next_inventory_id": rotate["id"],
                },
            )
            workspace = created.json()
            before_accounts = len(self.database.list_accounts())
            invalid_selection = client.post(
                "/api/workspaces",
                headers=self.origin_headers,
                json={
                    "name": "Invalid Space",
                    "workspace_uid": "invalid-space",
                    "current_account_id": workspace["current_account_id"],
                    "current_inventory_id": rotate["id"],
                },
            )
            replaced = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": workspace["version"],
                    "role": "next",
                    "failure_code": "alias_disabled",
                },
            )
            invalid_role = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": workspace["version"],
                    "role": "other",
                    "failure_code": "alias_disabled",
                },
            )
            queued = client.post(
                f"/api/workspaces/{workspace['id']}/enqueue",
                headers=self.origin_headers,
                json={},
            )
            active_replace = client.post(
                f"/api/workspaces/{workspace['id']}/replace-account",
                headers=self.origin_headers,
                json={
                    "version": replaced.json()["workspace"]["version"],
                    "role": "next",
                    "failure_code": "alias_disabled",
                },
            )

        self.assertEqual(created.status_code, 201)
        self.assertEqual(invalid_selection.status_code, 422)
        self.assertEqual(len(self.database.list_accounts()), before_accounts + 1)
        self.assertEqual(replaced.status_code, 200)
        replaced_workspace = replaced.json()["workspace"]
        replacement = replaced.json()["replacement"]
        self.assertEqual(
            replaced_workspace["current_account_id"], workspace["current_account_id"]
        )
        self.assertEqual(replaced_workspace["next_account_id"], replacement["id"])
        self.assertEqual(replacement["email"], "rotate+3@example.com")
        self.assertEqual(invalid_role.status_code, 422)
        self.assertEqual(queued.status_code, 202)
        self.assertEqual(active_replace.status_code, 409)
        self.assertEqual(
            active_replace.json()["detail"]["code"], "workspace_active"
        )

    def test_workspace_advance_api_records_an_external_rotation(self):
        self.database.import_mailbox_inventory(
            [
                self.inventory_record("manual-first@example.com", 0),
                self.inventory_record("manual-second@example.com", 1),
            ]
        )
        aliases = [self.database.allocate_mailbox_alias() for _ in range(5)]
        workspace = self.database.create_workspace(
            name="Manual rotation",
            workspace_uid="manual-rotation-api",
            current_account_id=aliases[3]["id"],
            next_account_id=aliases[4]["id"],
        )
        app = create_app(self.controller, testing=True)

        with TestClient(app) as client:
            advanced = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": workspace["version"]},
            )
            stale = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": workspace["version"]},
            )
            queued = client.post(
                f"/api/workspaces/{workspace['id']}/enqueue",
                headers=self.origin_headers,
                json={},
            )
            active = client.post(
                f"/api/workspaces/{workspace['id']}/advance",
                headers=self.origin_headers,
                json={"version": advanced.json()["workspace"]["version"]},
            )

        self.assertEqual(advanced.status_code, 200)
        payload = advanced.json()
        self.assertEqual(payload["current"]["email"], "manual-first+5@example.com")
        self.assertEqual(payload["replacement"]["email"], "manual-second+1@example.com")
        self.assertEqual(payload["workspace"]["rotation_count"], 1)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.json()["detail"]["code"], "stale_workspace_version")
        self.assertEqual(queued.status_code, 202)
        self.assertEqual(active.status_code, 409)
        self.assertEqual(active.json()["detail"]["code"], "workspace_active")

    def test_queue_run_routes_and_sse_start_with_authoritative_reset(self):
        workspace, _, _ = self.workspace("queue")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            enqueued = client.post(
                "/api/queue",
                headers=self.origin_headers,
                json={"workspace_ids": [workspace["id"]]},
            )
            run = enqueued.json()[0]
            queue = client.get("/api/queue", headers={"X-Workflow-Token": self.controller.request_token})
            detail = client.get(
                f"/api/runs/{run['id']}",
                headers={"X-Workflow-Token": self.controller.request_token},
            )

        class DisconnectedRequest:
            async def is_disconnected(self):
                return True

        async def first_frame():
            stream = _event_stream(self.controller, DisconnectedRequest())
            try:
                return await anext(stream)
            finally:
                await stream.aclose()

        frame = asyncio.run(first_frame())

        self.assertEqual(enqueued.status_code, 202)
        self.assertEqual(queue.json()["items"][0]["run_id"], run["id"])
        self.assertEqual(detail.json()["events"][0]["message"], "run queued")
        self.assertIn("event: reset", frame)
        self.assertIn('"workspaces"', frame)

    def test_settings_empty_secret_preserves_and_explicit_clear_removes(self):
        self.database.set_secret_setting("sub2api_password", "secret-canary")
        self.database.set_secret_setting("sub2api_api_key", "api-key-canary")
        self.database.set_secret_setting("sub2api_totp_secret", "totp-canary")
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            preserved = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={
                    "values": {
                        "output_dir": str(self.root / "output"),
                        "sub2api_push": True,
                        "sub2api_group_id": 3,
                    },
                    "secrets": {
                        "sub2api_password": "",
                        "sub2api_api_key": "",
                        "sub2api_totp_secret": "",
                    },
                },
            )
            cleared = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={
                    "clear_secrets": [
                        "sub2api_password",
                        "sub2api_api_key",
                        "sub2api_totp_secret",
                    ]
                },
            )
            invalid = client.put(
                "/api/settings",
                headers=self.origin_headers,
                json={"values": {"unknown": "value"}},
            )

        self.assertTrue(preserved.json()["secrets"]["sub2api_password"])
        self.assertTrue(preserved.json()["secrets"]["sub2api_api_key"])
        self.assertTrue(preserved.json()["secrets"]["sub2api_totp_secret"])
        self.assertEqual(preserved.json()["values"]["sub2api_group_id"], "3")
        self.assertFalse(cleared.json()["secrets"]["sub2api_password"])
        self.assertFalse(cleared.json()["secrets"]["sub2api_api_key"])
        self.assertFalse(cleared.json()["secrets"]["sub2api_totp_secret"])
        self.assertNotIn("secret-canary", preserved.text + cleared.text)
        self.assertNotIn("api-key-canary", preserved.text + cleared.text)
        self.assertNotIn("totp-canary", preserved.text + cleared.text)
        self.assertEqual(invalid.status_code, 422)
        self.assertIn("values", invalid.json()["detail"]["fields"])

    def test_sub2api_groups_route_uses_saved_credentials_and_returns_safe_metadata(self):
        self.database.set_text_setting("sub2api_base_url", "https://sub2api.example")
        self.database.set_text_setting("sub2api_email", "admin@example.com")
        self.database.set_secret_setting("sub2api_password", "secret-canary")
        self.database.set_secret_setting("sub2api_totp_secret", "totp-canary")
        app = create_app(self.controller, testing=True)
        with patch("team_protocol.web_console.Sub2APIClient") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.list_groups.return_value = [
                {
                    "id": 3,
                    "name": "K12",
                    "platform": "openai",
                    "status": "active",
                    "is_exclusive": False,
                    "private_field": "not-returned",
                }
            ]
            with TestClient(app) as test_client:
                response = test_client.get(
                    "/api/sub2api/groups",
                    headers={"X-Workflow-Token": self.controller.request_token},
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "groups": [
                    {
                        "id": 3,
                        "name": "K12",
                        "platform": "openai",
                        "status": "active",
                        "is_exclusive": False,
                    }
                ]
            },
        )
        client_class.assert_called_once_with(
            "https://sub2api.example",
            "admin@example.com",
            "secret-canary",
            totp_secret="totp-canary",
        )
        client.list_groups.assert_called_once_with(include_inactive=True)

    def test_sub2api_groups_route_uses_saved_api_key_without_password(self):
        self.database.set_text_setting("sub2api_base_url", "https://sub2api.example")
        self.database.set_secret_setting("sub2api_api_key", "api-key-canary")
        app = create_app(self.controller, testing=True)
        with patch("team_protocol.web_console.Sub2APIClient") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.list_groups.return_value = []
            with TestClient(app) as test_client:
                response = test_client.get(
                    "/api/sub2api/groups",
                    headers={"X-Workflow-Token": self.controller.request_token},
                )

        self.assertEqual(response.status_code, 200)
        client_class.assert_called_once_with(
            "https://sub2api.example", "", "", api_key="api-key-canary"
        )
        self.assertNotIn("api-key-canary", response.text)

    def test_static_traversal_and_legacy_config_routes_are_absent(self):
        app = create_app(self.controller, testing=True)
        with TestClient(app) as client:
            index = client.get("/")
            script = client.get("/static/app.js")
            traversal = client.get("/static/../../workflow.example.json")
            old_load = client.post(
                "/api/config/load",
                headers=self.origin_headers,
                json={"path": "workflow.json"},
            )
            old_run = client.post(
                "/api/run",
                headers=self.origin_headers,
                json={"config_path": "workflow.json"},
            )

        self.assertEqual(index.status_code, 200)
        self.assertEqual(script.status_code, 200)
        self.assertIn("refreshRequestToken", script.text)
        self.assertIn("invalid_request_token", script.text)
        self.assertIn("Content-Security-Policy", index.headers)
        self.assertIn('id="account-page-summary"', index.text)
        self.assertIn('data-action="account-page-next"', index.text)
        self.assertIn('name="sub2api_group_id"', index.text)
        self.assertIn('name="sub2api_api_key"', index.text)
        self.assertIn('name="sub2api_totp_secret"', index.text)
        self.assertIn('<select name="sub2api_group_id">', index.text)
        self.assertIn('/api/sub2api/groups', script.text)
        self.assertIn("const ACCOUNT_PAGE_SIZE = 50", script.text)
        self.assertIn("const MOBILE_ACCOUNT_PAGE_SIZE = 20", script.text)
        self.assertIn(traversal.status_code, {400, 404})
        self.assertEqual(old_load.status_code, 404)
        self.assertEqual(old_run.status_code, 404)
        self.assertNotIn("config_path", self.controller.bootstrap())

    def test_startup_migration_verifies_backup_before_cleanup_and_never_deletes_txt(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )

        def assert_backup_exists(model, verified):
            backup_path = Path(controller.database.get_meta("migration_backup_path"))
            self.assertTrue(backup_path.is_file())
            return cleanup_plaintext(model, verified)

        with patch(
            "team_protocol.web_console.cleanup_plaintext",
            side_effect=assert_backup_exists,
        ):
            status = controller.startup()

        self.assertTrue(status["ready"])
        self.assertFalse(config.exists())
        self.assertTrue(mail.exists())
        self.assertTrue(Path(controller.database.get_meta("migration_backup_path")).is_file())
        self.assertTrue(
            Path(
                controller.database.get_meta(
                    "mailbox_inventory_prechange_backup_path"
                )
            ).is_file()
        )
        self.assertEqual(
            controller.database.get_meta("mailbox_inventory_migration_version"),
            "1",
        )
        self.assertEqual(controller.database.get_mailbox_inventory_summary()["total"], 1)
        self.assertEqual(self.queue.started, 1)

        second_database = Database(self.root / "console.db", secret_store=self.store)
        second_queue = FakeTaskQueue(second_database)
        second = WebConsoleController(
            database=second_database,
            secret_store=self.store,
            task_queue=second_queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        with (
            patch(
                "team_protocol.web_console.discover_legacy",
                side_effect=AssertionError("completed migration reread legacy source"),
            ),
            patch(
                "team_protocol.web_console.verify_backup",
                side_effect=AssertionError("completed inventory migration reread backup"),
            ),
        ):
            self.assertTrue(second.startup()["ready"])

    def test_inventory_backfill_count_mismatch_blocks_queue_without_marker(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
            inventory_expected_count=2,
        )

        health = controller.startup()

        self.assertFalse(health["ready"])
        self.assertEqual(
            controller.migration_status()["status"], "inventory_migration_error"
        )
        self.assertEqual(self.queue.started, 0)
        self.assertIsNone(
            self.database.get_meta("mailbox_inventory_migration_version")
        )
        self.assertEqual(self.database.get_mailbox_inventory_summary()["total"], 0)
        self.assertTrue(mail.exists())
        prechange = self.database.get_text_setting("last_backup_path")
        self.assertTrue(prechange and Path(prechange).is_file())

        controller.inventory_expected_count = 1
        recovered = controller.retry_migration_cleanup()
        self.assertEqual(recovered["status"], "ready")
        self.assertEqual(self.queue.started, 1)
        self.assertEqual(
            self.database.get_meta("mailbox_inventory_migration_version"), "1"
        )

    def test_cleanup_blocked_exposes_only_recovery_then_retries_from_backup(self):
        config, mail = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        blocked = CleanupResult(
            status="cleanup_blocked",
            removed=(),
            preserved=(mail,),
            missing=(),
            failures=(CleanupFailure(path=config, code="remove_failed"),),
        )
        with patch("team_protocol.web_console.cleanup_plaintext", return_value=blocked):
            controller.startup()

        self.assertEqual(controller.migration_status()["status"], "cleanup_blocked")
        self.assertEqual(self.queue.started, 0)
        self.assertTrue(config.exists())
        app = create_app(controller, testing=True)
        with TestClient(app) as client:
            blocked_route = client.get(
                "/api/workspaces",
                headers={"X-Workflow-Token": controller.request_token},
            )
            recovered = client.post(
                "/api/migration/retry-cleanup",
                headers={
                    "Origin": "http://testserver",
                    "X-Workflow-Token": controller.request_token,
                },
            )

        self.assertEqual(blocked_route.status_code, 503)
        self.assertEqual(blocked_route.json()["detail"]["code"], "migration_blocked")
        self.assertEqual(recovered.json()["status"], "ready")
        self.assertFalse(config.exists())
        self.assertTrue(mail.exists())

    def test_encrypted_backup_restore_requires_paused_queue_and_reinitializes(self):
        self.controller.startup()
        original = self.account("backup-original")
        with self.assertRaisesRegex(Exception, "paused"):
            self.controller.restore_encrypted_backup(self.root / "missing.twbackup")
        self.queue.set_paused(True)
        backup = self.controller.create_encrypted_backup()
        settings = self.controller.get_settings()["values"]
        extra = self.account("backup-extra")

        restored = self.controller.restore_encrypted_backup(backup["path"])

        self.assertEqual(restored["status"], "restored")
        account_ids = {item["id"] for item in self.database.list_accounts()}
        self.assertIn(original["id"], account_ids)
        self.assertNotIn(extra["id"], account_ids)
        self.assertTrue(self.database.is_queue_paused())
        self.assertGreaterEqual(self.queue.shutdown_calls, 1)
        self.assertEqual(settings["last_backup_path"], backup["path"])
        self.assertTrue(settings["last_backup_at"])

    def test_custom_backup_directory_controls_default_backup_destination(self):
        backup_directory = self.root / "project-backups"
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            backup_dir=backup_directory,
        )
        controller.startup()

        backup = controller.create_encrypted_backup()

        backup_path = Path(backup["path"])
        self.assertEqual(backup_path.parent, backup_directory.resolve())
        self.assertTrue(backup_path.is_file())

    def test_restore_keeps_blocked_database_stopped(self):
        self.controller.startup()
        self.database.set_meta("migration_status", "cleanup_blocked")
        self.queue.set_paused(True)
        backup = self.controller.create_encrypted_backup()
        self.database.set_meta("migration_status", "ready")
        started_before = self.queue.started

        self.controller.restore_encrypted_backup(backup["path"])

        self.assertEqual(self.controller.migration_status()["status"], "cleanup_blocked")
        self.assertEqual(self.queue.started, started_before)

    def test_restored_verified_migration_snapshot_becomes_complete_without_legacy_read(self):
        config, _ = self.legacy_fixture()
        controller = WebConsoleController(
            database=self.database,
            secret_store=self.store,
            task_queue=self.queue,
            app_dir=self.root,
            legacy_config_path=config,
        )
        controller.startup()
        backup_path = controller.database.get_meta("migration_backup_path")
        controller.task_queue.set_paused(True)

        with patch(
            "team_protocol.web_console.discover_legacy",
            side_effect=AssertionError("restore reread legacy source"),
        ):
            restored = controller.restore_encrypted_backup(backup_path)

        self.assertEqual(restored["status"], "restored")
        self.assertEqual(controller.database.get_meta("migration_status"), "complete")
        self.assertEqual(controller.database.get_meta("migration_completed"), "1")
        self.assertEqual(controller.migration_status()["status"], "ready")
        self.assertGreaterEqual(self.queue.started, 2)

    def test_server_uses_project_legacy_path_internally_without_cli_argument(self):
        expected = (Path.cwd() / "workflow.example.json").resolve()
        with (
            patch("team_protocol.web_console._available_port", return_value=8765),
            patch("team_protocol.web_console.WebConsoleController") as controller_type,
            patch("team_protocol.web_console.create_app", return_value=object()),
            patch("team_protocol.web_console.uvicorn.Server") as server_type,
        ):
            server_type.return_value.run.return_value = None
            result = serve_web_console(open_browser=False, app_dir=self.root)

        self.assertEqual(result, 0)
        self.assertEqual(
            controller_type.call_args.kwargs["legacy_config_path"],
            expected,
        )


if __name__ == "__main__":
    unittest.main()
