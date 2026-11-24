"""A local HTTP(S) forward proxy that logs and never forwards.

Runs in the backend's own process (a background thread), bound to
``HTTP_PROXY``/``HTTPS_PROXY`` for the sandboxed subprocess. Records every
request's host/path/body and scans the body for known canary tokens; always
replies 200 so the sandboxed tool's call completes normally. Never opens an
outbound connection to the real destination.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingTCPServer
from typing import Any


@dataclass
class ProxyRequestRecord:
    method: str
    host: str
    path: str
    body: str
    canary_hits: list[str] = field(default_factory=list)


class _ReusableThreadingTCPServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class LoggingHTTPProxy:
    """Forward-proxy stand-in that logs instead of forwarding.

    Handles the plain-HTTP absolute-URI form a proxied client sends for an
    ``http://`` target (what the travel_overreach demo exfil call produces).
    For ``CONNECT`` (the HTTPS tunnel request for an ``https://`` target) it
    logs the requested ``host:port`` and closes the connection rather than
    tunneling: inspecting TLS would need a MITM certificate the sandboxed
    process would have to trust, which is out of scope for a Docker-free
    "lite" sandbox.
    """

    def __init__(self, canary_tokens: set[str] | None = None) -> None:
        self.canary_tokens = canary_tokens or set()
        self.requests: list[ProxyRequestRecord] = []
        self._lock = threading.Lock()
        self._server: ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._handler_class = self._build_handler_class()

    def _build_handler_class(self) -> type[BaseHTTPRequestHandler]:
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass  # never print - a sandboxed server's stdout must stay clean

            def _read_body(self) -> str:
                try:
                    length = int(self.headers.get("Content-Length", 0) or 0)
                except ValueError:
                    length = 0
                if length <= 0:
                    return ""
                return self.rfile.read(length).decode("utf-8", errors="replace")

            def _record(self, method: str) -> None:
                host = self.headers.get("Host", "")
                body = self._read_body()
                hits = [t for t in proxy.canary_tokens if t in body or t in self.path]
                record = ProxyRequestRecord(method=method, host=host, path=self.path, body=body, canary_hits=hits)
                with proxy._lock:
                    proxy.requests.append(record)

            def _respond_ok(self) -> None:
                payload = b"vetter-sandbox: request logged, not forwarded"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                self._record("GET")
                self._respond_ok()

            def do_POST(self) -> None:
                self._record("POST")
                self._respond_ok()

            def do_PUT(self) -> None:
                self._record("PUT")
                self._respond_ok()

            def do_PATCH(self) -> None:
                self._record("PATCH")
                self._respond_ok()

            def do_DELETE(self) -> None:
                self._record("DELETE")
                self._respond_ok()

            def do_HEAD(self) -> None:
                self._record("HEAD")
                self.send_response(200)
                self.end_headers()

            def do_CONNECT(self) -> None:
                host = self.path  # "host:port" for CONNECT requests
                with proxy._lock:
                    proxy.requests.append(ProxyRequestRecord(method="CONNECT", host=host, path="", body=""))
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.close_connection = True

        return Handler

    def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        self._server = _ReusableThreadingTCPServer((host, port), self._handler_class)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server.server_address[1]

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def distinct_hosts(self) -> list[str]:
        with self._lock:
            return sorted({r.host for r in self.requests if r.host})

    def canary_leaks(self) -> list[ProxyRequestRecord]:
        with self._lock:
            return [r for r in self.requests if r.canary_hits]
