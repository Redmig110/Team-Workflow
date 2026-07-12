from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from .cpa import load_json_object, semantic_cpa_payload


class ManagementError(RuntimeError):
    pass


@dataclass(frozen=True)
class PushResult:
    action: str
    filename: str
    verified: bool
    message: str


class ManagementClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 20.0,
        impersonate: str = "chrome110",
    ):
        try:
            from curl_cffi import requests as curl_requests
        except ImportError as exc:
            raise RuntimeError("curl_cffi is required for management requests") from exc
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.timeout = timeout
        self.impersonate = impersonate
        self._session = curl_requests.Session()
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("management base URL must start with http:// or https://")
        if not self.api_key:
            raise ValueError("management API key is empty")

    @property
    def management_base_url(self) -> str:
        return f"{self.base_url}/v0/management"

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> bytes:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        if content_type:
            headers["Content-Type"] = content_type
        response = self._session.request(
            method,
            f"{self.management_base_url}{path}",
            data=body,
            headers=headers,
            impersonate=self.impersonate,
            timeout=self.timeout,
            verify=False,
        )
        if not 200 <= response.status_code < 300:
            detail = response.text.strip()
            raise ManagementError(f"HTTP {response.status_code}: {detail or response.reason}")
        return response.content

    def list_files(self) -> list[dict[str, Any]]:
        raw = self._request("GET", "/auth-files")
        data = json.loads(raw.decode("utf-8")) if raw else {}
        files = data.get("files") if isinstance(data, dict) else None
        return [item for item in (files or []) if isinstance(item, dict)]

    def download(self, filename: str) -> dict[str, Any]:
        raw = self._request("GET", f"/auth-files/download?name={quote(filename, safe='')}")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ManagementError("downloaded auth file is not a JSON object")
        return data

    def upload(self, filename: str, payload: Mapping[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._request(
            "POST",
            f"/auth-files?name={quote(filename, safe='')}",
            body=raw,
            content_type="application/json",
        )

    def delete(self, filename: str) -> None:
        self._request("DELETE", f"/auth-files?name={quote(filename, safe='')}")

    def push_payload(
        self,
        filename: str,
        payload: Mapping[str, Any],
        *,
        replace: bool = False,
        dry_run: bool = False,
    ) -> PushResult:
        remote_entry = next(
            (item for item in self.list_files() if str(item.get("name") or "") == filename),
            None,
        )
        local_semantic = semantic_cpa_payload(payload)

        if remote_entry is not None:
            if remote_entry.get("runtime_only"):
                raise ManagementError(f"remote credential is runtime_only and cannot be replaced: {filename}")
            remote_payload = self.download(filename)
            if semantic_cpa_payload(remote_payload) == local_semantic:
                return PushResult(
                    action="skipped",
                    filename=filename,
                    verified=True,
                    message="remote credential already matches local payload",
                )
            if not replace:
                raise ManagementError(
                    f"remote credential differs: {filename}; rerun with --replace to update it"
                )
            if dry_run:
                return PushResult(
                    action="would-update",
                    filename=filename,
                    verified=False,
                    message="dry run: remote credential would be replaced",
                )
            self.delete(filename)
            self.upload(filename, payload)
            action = "updated"
        else:
            if dry_run:
                return PushResult(
                    action="would-upload",
                    filename=filename,
                    verified=False,
                    message="dry run: new credential would be uploaded",
                )
            self.upload(filename, payload)
            action = "uploaded"

        verified = semantic_cpa_payload(self.download(filename)) == local_semantic
        if not verified:
            raise ManagementError(f"post-upload verification failed: {filename}")
        return PushResult(
            action=action,
            filename=filename,
            verified=True,
            message=f"credential {action} and verified",
        )

    def push_file(
        self,
        path: str | Path,
        *,
        remote_name: str | None = None,
        replace: bool = False,
        dry_run: bool = False,
    ) -> PushResult:
        file_path = Path(path)
        payload = load_json_object(file_path)
        return self.push_payload(
            remote_name or file_path.name,
            payload,
            replace=replace,
            dry_run=dry_run,
        )
