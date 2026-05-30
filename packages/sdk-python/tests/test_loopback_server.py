"""Loopback test-HTTP-server helper for the W3.2 SDK lifecycle tests.

The SDK targets the local sidecar's HTTP surface; many W3.2 assertions
(VAL-W3-010, VAL-W3-013, VAL-W3-014, VAL-W3-015, VAL-W3-018, VAL-W3-019)
require asserting wire-format behaviour. Rather than spawning the full
sidecar (which the SDK can attach to via the W3.1 path) we run a small
:class:`http.server.HTTPServer` on 127.0.0.1 that records request bodies
and returns scripted responses. The server is purely a test fixture; it
ships nowhere outside ``tests/``.

The server's loopback binding is 127.0.0.1 only. No external network
exposure.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class RecordedRequest:
    """A single captured inbound HTTP request from the SDK."""

    def __init__(
        self,
        *,
        method: str,
        path: str,
        body_bytes: bytes,
        headers: dict[str, str],
    ) -> None:
        self.method = method
        self.path = path
        self.body_bytes = body_bytes
        self.headers = headers

    @property
    def body_json(self) -> dict[str, Any]:
        try:
            return json.loads(self.body_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}


# Type alias for a handler callable: takes a RecordedRequest, returns
# (status_code, response_body_dict, extra_headers).
HandlerFn = Callable[[RecordedRequest], tuple[int, dict[str, Any], dict[str, str]]]


class LoopbackServer:
    """A minimal scriptable HTTP server bound to 127.0.0.1.

    Usage:

        server = LoopbackServer()
        server.add_route("POST", "/v1/ingest/runs",
            lambda req: (200, {"accepted": True}, {}))
        server.start()
        try:
            # tests use server.base_url
            ...
        finally:
            server.stop()

    Routes are matched by (method, path). The first matching route wins.
    An unmatched request returns 404 + a synthetic error envelope.
    """

    def __init__(self) -> None:
        self._routes: list[tuple[str, str, HandlerFn]] = []
        self.requests: list[RecordedRequest] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None, "server not started"
        # ``server_address`` is typed as the union of the AF_INET (2-tuple)
        # and AF_INET6 (4-tuple) sockaddr forms. The loopback test server
        # binds AF_INET, so the host/port are always the first two members;
        # index them rather than unpacking to a fixed-arity 2-tuple.
        addr = self._server.server_address
        host, port = addr[0], addr[1]
        return f"http://{host}:{port}"

    def add_route(self, method: str, path: str, handler: HandlerFn) -> None:
        self._routes.append((method.upper(), path, handler))

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            # Silence the default stderr access-log spam.
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(length) if length > 0 else b""

            def _dispatch(self) -> None:
                body = self._read_body()
                req = RecordedRequest(
                    method=self.command,
                    path=self.path,
                    body_bytes=body,
                    headers={k: v for k, v in self.headers.items()},
                )
                with outer._lock:
                    outer.requests.append(req)
                for method, route_path, handler in outer._routes:
                    if method == self.command and route_path == self.path:
                        status, body_obj, extra = handler(req)
                        payload = json.dumps(body_obj).encode("utf-8")
                        self.send_response(status)
                        self.send_header("Content-Type", "application/json")
                        for k, v in extra.items():
                            self.send_header(k, v)
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                # No route matched.
                envelope = {
                    "schema_version": "relay.error.v1",
                    "code": "RELAY-ING-001",
                    "error_class": "TEST-SERVER-NOT-FOUND",
                    "message": f"No route registered for {self.command} {self.path}",
                    "retry_advice": {"mode": "no_retry"},
                    "details": {},
                }
                payload = json.dumps(envelope).encode("utf-8")
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:  # noqa: N802 - stdlib hook
                self._dispatch()

            def do_POST(self) -> None:  # noqa: N802 - stdlib hook
                self._dispatch()

            def do_PUT(self) -> None:  # noqa: N802 - stdlib hook
                self._dispatch()

            def do_DELETE(self) -> None:  # noqa: N802 - stdlib hook
                self._dispatch()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True, name="loopback-test-server"
        )
        self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._server = None
        self._thread = None
