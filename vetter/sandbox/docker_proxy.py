"""Small non-forwarding HTTP logger used inside the isolated Docker network."""
from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = "/vetter-scratch/proxy.ndjson"
CANARY = re.compile(rb"VETTER-CANARY-[0-9a-f-]{36}")
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _record(self, method: str) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        tokens = [token.decode("ascii") for token in CANARY.findall(body + self.path.encode())]
        record = {"method": method, "host": self.headers.get("Host", ""), "path": self.path, "canary_hits": tokens}
        with LOCK, open(LOG_PATH, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")

    def _respond(self) -> None:
        payload = b"vetter-sandbox: request logged, not forwarded"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self._record("GET")
        self._respond()

    def do_POST(self) -> None:
        self._record("POST")
        self._respond()

    def do_PUT(self) -> None:
        self._record("PUT")
        self._respond()

    def do_PATCH(self) -> None:
        self._record("PATCH")
        self._respond()

    def do_DELETE(self) -> None:
        self._record("DELETE")
        self._respond()

    def do_CONNECT(self) -> None:
        self._record("CONNECT")
        self.close_connection = True


ThreadingHTTPServer(("0.0.0.0", 3128), Handler).serve_forever()
