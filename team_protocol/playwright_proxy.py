from __future__ import annotations

import select
import socket
import socketserver
import threading
import urllib.parse
from typing import Any, Mapping


_MAX_CONNECT_HEADER_BYTES = 64 * 1024


def _proxy_parts(value: str) -> urllib.parse.SplitResult:
    text = str(value or "").strip()
    if not text:
        return urllib.parse.urlsplit("")
    return urllib.parse.urlsplit(text if "://" in text else f"http://{text}")


def _server_url(parts: urllib.parse.SplitResult) -> str:
    hostname = str(parts.hostname or "").strip()
    if not hostname:
        raise ValueError("proxy hostname is required")
    host = f"[{hostname}]" if ":" in hostname else hostname
    if parts.port is None:
        raise ValueError("proxy port is required")
    return f"{parts.scheme}://{host}:{parts.port}"


def _connect_target(value: str) -> tuple[str, int]:
    target = str(value or "").strip()
    if target.startswith("["):
        host, separator, port = target[1:].partition("]:")
    else:
        host, separator, port = target.rpartition(":")
    if not separator or not host:
        raise ValueError("CONNECT target is invalid")
    return host, int(port)


class _ThreadingProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], upstream: urllib.parse.SplitResult):
        self.upstream = upstream
        super().__init__(server_address, _ConnectProxyHandler)


class _ConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(15.0)
        header = bytearray()
        try:
            while b"\r\n\r\n" not in header:
                chunk = client.recv(4096)
                if not chunk:
                    return
                header.extend(chunk)
                if len(header) > _MAX_CONNECT_HEADER_BYTES:
                    raise ValueError("proxy request header is too large")
            request_line = bytes(header).split(b"\r\n", 1)[0].decode(
                "ascii",
                errors="strict",
            )
            method, target, _version = request_line.split(" ", 2)
            if method.upper() != "CONNECT":
                client.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n"
                )
                return
            target_host, target_port = _connect_target(target)
            upstream = self.server.upstream
            import socks

            remote = socks.socksocket()
            remote.set_proxy(
                proxy_type=socks.SOCKS5,
                addr=str(upstream.hostname or ""),
                port=int(upstream.port or 0),
                rdns=True,
                username=urllib.parse.unquote(upstream.username or "") or None,
                password=urllib.parse.unquote(upstream.password or "") or None,
            )
            remote.settimeout(20.0)
            remote.connect((target_host, target_port))
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client.settimeout(None)
            remote.settimeout(None)
            self._relay(client, remote)
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except Exception:
                pass
        finally:
            remote_socket = locals().get("remote")
            if remote_socket is not None:
                try:
                    remote_socket.close()
                except Exception:
                    pass

    @staticmethod
    def _relay(client: socket.socket, remote: socket.socket) -> None:
        sockets = (client, remote)
        while True:
            readable, _, exceptional = select.select(sockets, (), sockets, 30.0)
            if exceptional or not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                target = remote if source is client else client
                target.sendall(data)


class PlaywrightProxyLease:
    def __init__(self, proxy: str | None):
        self.proxy = str(proxy or "").strip()
        self.playwright_proxy: dict[str, str] | None = None
        self._server: _ThreadingProxyServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "PlaywrightProxyLease":
        if not self.proxy:
            return self
        parts = _proxy_parts(self.proxy)
        scheme = str(parts.scheme or "").strip().lower()
        username = urllib.parse.unquote(parts.username or "")
        password = urllib.parse.unquote(parts.password or "")
        if scheme in {"socks5", "socks5h"} and (username or password):
            server = _ThreadingProxyServer(("127.0.0.1", 0), parts)
            thread = threading.Thread(
                target=server.serve_forever,
                name="playwright-socks-adapter",
                daemon=True,
            )
            thread.start()
            self._server = server
            self._thread = thread
            self.playwright_proxy = {
                "server": f"http://127.0.0.1:{server.server_address[1]}"
            }
            return self

        config = {"server": _server_url(parts)}
        if username:
            config["username"] = username
        if password:
            config["password"] = password
        self.playwright_proxy = config
        return self

    def close(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        self.playwright_proxy = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5.0)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()


def apply_playwright_proxy(
    launch_options: Mapping[str, Any],
    lease: PlaywrightProxyLease,
) -> dict[str, Any]:
    options = dict(launch_options)
    if lease.playwright_proxy is not None:
        options["proxy"] = dict(lease.playwright_proxy)
    return options
