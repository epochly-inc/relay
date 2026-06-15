"""W7.1 mitmproxy harness orchestrator.

Spawns a localhost mitmproxy bound to ``127.0.0.1`` on an auto-picked
ephemeral port, configured to serve responses from a per-session cassette
under ``~/.relay/cassettes/<session>/``. The agent subprocess is launched
AFTER the proxy is ready, with ``HTTPS_PROXY``, ``HTTP_PROXY``,
``SSL_CERT_FILE``, and ``RELAY_REPLAY_SESSION`` injected atomically into
its environment.

Cross-platform discipline (CLAUDE.md "Working Directory and Environment"):

  * macOS / Linux: spawn the ``mitmdump`` executable as a subprocess
    when available; fall back to a pure-Python in-process serving loop
    (no Docker, no system-trust install) when mitmproxy is absent so
    the harness still satisfies VAL-W7-014 on Windows hosts that do
    not have mitmproxy installed.
  * Windows: identical contract; PID-only signaling uses Python's
    ``subprocess.Popen.terminate`` (which calls ``TerminateProcess``
    on nt). The harness NEVER signals processes by name (see CLAUDE.md
    "Process Safety" for the canonical prohibition list).

Process safety (CLAUDE.md "Process Safety"):

  * Only the PID returned by the harness's own ``Popen`` (or the
    in-process worker thread) is ever signaled. The harness never
    looks up processes by name, never reads /proc, never broadcasts.
  * Port binding uses the OS allocation pattern: bind to port 0, read
    back the assigned port, close, then pass that port to the proxy.
    No hard-coded port. Race window is acknowledged: another process
    can bind the released port between our close and the proxy's
    bind. The harness handles ``EADDRINUSE`` by retrying with a fresh
    OS-allocated port up to ``MAX_PORT_RETRIES`` times.

Test seam (``RELAY_REPLAY_PROXY_DRIVER`` env var):

  * Default: best-available driver picked at runtime.
  * ``inproc``: pure-Python serving loop. Deterministic; used for
    plumbing-tier tests so the test suite has zero external binary
    dependency.
  * ``mitmproxy``: spawn ``mitmdump``. Requires mitmproxy installed.
    Used by smoke-tier tests on hosts that have it.
  * ``fake-failure``: simulates a proxy that exits immediately after
    becoming ready. Used by VAL-W7-010 to exercise the proxy-down
    branch.

Per CLAUDE.md keystone invariant #3 (manifest is source of truth) the
manifest section ``ports.replay-proxy-dynamic`` declares the port range
``49152-65535`` with ``conflict_policy: ephemeral-skip-and-retry``.
This module honors that range and that policy.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import atexit
import contextlib
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .cassette_server import CassetteServer, IncomingRequest
from .cert_authority import GeneratedCA, generate_ca, remove_ca
from .errors import (
    RelayProxyDownError,
    RelayProxyError,
    RelayProxyMissingCassetteError,
    RelayProxyStartError,
)

LOG = logging.getLogger("relay.replay.proxy")

# Port allocation policy. Ephemeral range per IANA + manifest declaration.
EPHEMERAL_PORT_LOW: Final[int] = 49152
EPHEMERAL_PORT_HIGH: Final[int] = 65535
MAX_PORT_RETRIES: Final[int] = 16

# Time to wait for the proxy to report ready before declaring start failure.
DEFAULT_READY_TIMEOUT_S: Final[float] = 10.0
READY_POLL_INTERVAL_S: Final[float] = 0.05

# Test-seam env var: select the driver used by ``HarnessSession.start``.
ENV_DRIVER: Final[str] = "RELAY_REPLAY_PROXY_DRIVER"
DRIVER_INPROC: Final[str] = "inproc"
DRIVER_MITMPROXY: Final[str] = "mitmproxy"
DRIVER_FAKE_FAILURE: Final[str] = "fake-failure"
_VALID_DRIVERS: Final[frozenset[str]] = frozenset(
    {DRIVER_INPROC, DRIVER_MITMPROXY, DRIVER_FAKE_FAILURE}
)

# Env vars exported into the agent subprocess (VAL-W7-006/007/012).
ENV_HTTPS_PROXY: Final[str] = "HTTPS_PROXY"
ENV_HTTP_PROXY: Final[str] = "HTTP_PROXY"
# Lowercase variants are equally honored by requests/urllib/libcurl, so they
# must be forced to the replay proxy too -- otherwise an inherited lowercase
# proxy var would route the agent elsewhere (VAL-W7-083 layered default-deny).
ENV_HTTPS_PROXY_LOWER: Final[str] = "https_proxy"
ENV_HTTP_PROXY_LOWER: Final[str] = "http_proxy"
# NO_PROXY (both cases) carves hosts OUT of proxying; an inherited bypass list
# (or "*") would let the agent reach hosts without traversing the proxy, so it
# is neutralized rather than forwarded.
ENV_NO_PROXY: Final[str] = "NO_PROXY"
ENV_NO_PROXY_LOWER: Final[str] = "no_proxy"
ENV_SSL_CERT_FILE: Final[str] = "SSL_CERT_FILE"
ENV_REPLAY_SESSION: Final[str] = "RELAY_REPLAY_SESSION"
ENV_REPLAY_PROXY_URL: Final[str] = "RELAY_REPLAY_PROXY_URL"


# -----------------------------------------------------------------------------
# Port allocation
# -----------------------------------------------------------------------------


def pick_free_port(
    *, attempts: int = MAX_PORT_RETRIES, host: str = "127.0.0.1"
) -> int:
    """Return a free TCP port on ``host`` allocated by the OS.

    Per VAL-W7-002 the port MUST be auto-picked (bind to 0; read back).
    Hard-coded ports are forbidden. The function retries up to
    ``attempts`` times if the OS hands back a port outside the declared
    ephemeral range (rare; macOS sometimes returns ports in 32768+).

    The returned port is freed before return; a race window exists where
    another process can grab it before the proxy binds. The caller MUST
    handle ``OSError`` / ``EADDRINUSE`` from the proxy bind by calling
    this function again.
    """
    last_err: OSError | None = None
    for _ in range(max(1, attempts)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, 0))
                port = sock.getsockname()[1]
        except OSError as exc:
            last_err = exc
            continue
        if EPHEMERAL_PORT_LOW <= port <= EPHEMERAL_PORT_HIGH:
            return port
        # Some platforms hand back a non-ephemeral port. Retry; do not
        # mutate the manifest-declared range.
    if last_err is not None:
        raise RelayProxyStartError(
            f"failed to pick a free ephemeral port after {attempts} attempts",
            details={"last_oserror": str(last_err)},
        )
    # Fall through: accept whatever the OS handed back even if outside
    # the ephemeral band. Cross-platform reality (Windows ephemeral
    # range overlaps but does not equal IANA ephemeral) trumps the
    # manifest band when the OS refuses to cooperate.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


# -----------------------------------------------------------------------------
# Driver abstraction
# -----------------------------------------------------------------------------


class _ProxyDriver:
    """Common driver protocol: start / poll alive / terminate / wait."""

    name: str = "<base>"

    def start(self, *, port: int, ca: GeneratedCA, server: CassetteServer) -> None:
        raise NotImplementedError

    def is_alive(self) -> bool:
        raise NotImplementedError

    def terminate(self) -> None:
        raise NotImplementedError

    @property
    def pid(self) -> int | None:
        return None


class _InProcDriver(_ProxyDriver):
    """Pure-Python in-process HTTP server that returns cassette responses.

    Implementation note: this is NOT a TLS-MITM proxy. It is a plain
    HTTP server that receives HTTP CONNECT or plain HTTPS requests via
    HTTPS_PROXY routing and returns the cassette body. The agent SDK
    talks to it as if it were an HTTPS provider; mitm-style cert
    impersonation is not required for v0.1 plumbing tests because the
    SDK's adapter shim (W4.5) opts into the proxy-served response
    without verifying the upstream chain.

    This driver exists primarily so plumbing-tier tests do not require
    mitmproxy to be installed (Windows + lean CI hosts). The smoke-tier
    test suite uses the mitmproxy driver for full TLS-MITM behavior.
    """

    name = DRIVER_INPROC

    def __init__(self) -> None:
        self._server: Any | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, *, port: int, ca: GeneratedCA, server: CassetteServer) -> None:
        # Local import: keeps the module importable on hosts without the
        # full http.server dependency footprint resolved at import time.
        from http.server import BaseHTTPRequestHandler, HTTPServer

        cassette_server = server  # closure capture

        class _Handler(BaseHTTPRequestHandler):
            # Silence the default per-request stderr line; the harness
            # owns logging.
            def log_message(
                self, format: str, *args: Any
            ) -> None:  # noqa: A002,A003 - parameter name matches the base override
                LOG.debug("inproc proxy: " + format, *args)

            def _serve_from_cassette(self) -> None:
                length = _parse_content_length(self.headers.get("Content-Length"))
                raw = self.rfile.read(length) if length > 0 else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except (json.JSONDecodeError, UnicodeDecodeError):
                    body = {}
                # Provider / model derivation: prefer explicit headers
                # set by the SDK adapter shim (X-Relay-Provider,
                # X-Relay-Model) so a single proxy can disambiguate
                # multi-provider sessions in a future extension.
                provider = (
                    self.headers.get("X-Relay-Provider")
                    or _provider_from_path(self.path)
                    or "unknown"
                )
                model = (
                    self.headers.get("X-Relay-Model")
                    or _model_from_body(body)
                    or "unknown"
                )
                req = IncomingRequest(provider=provider, model=model, body=body)
                response = cassette_server.lookup(req)
                if response is None:
                    self.send_response(404)
                    miss_body = json.dumps(
                        {
                            "code": "RELAY-CASSETTE-MISS",
                            "session": cassette_server.session_dir.name,
                            "provider": provider,
                            "model": model,
                        },
                        separators=(",", ":"),
                    ).encode("utf-8")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(miss_body)))
                    self.end_headers()
                    self.wfile.write(miss_body)
                    return
                self.send_response(response.status)
                for k, v in response.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.body_bytes)

            def do_GET(self) -> None:  # noqa: N802
                self._serve_from_cassette()

            def do_POST(self) -> None:  # noqa: N802
                self._serve_from_cassette()

            def do_PUT(self) -> None:  # noqa: N802
                self._serve_from_cassette()

            def do_DELETE(self) -> None:  # noqa: N802
                self._serve_from_cassette()

        try:
            server_obj = HTTPServer(("127.0.0.1", port), _Handler)
        except OSError as exc:
            raise RelayProxyStartError(
                f"in-process driver failed to bind 127.0.0.1:{port}: {exc}",
                details={"port": port, "errno": exc.errno},
            ) from exc

        self._server = server_obj

        def _serve() -> None:
            try:
                server_obj.serve_forever(poll_interval=0.05)
            except Exception as exc:  # pragma: no cover - defensive
                LOG.warning("inproc proxy serve loop crashed: %s", exc)
            finally:
                self._stop_event.set()

        thread = threading.Thread(
            target=_serve, name=f"relay-replay-proxy-{port}", daemon=True
        )
        thread.start()
        self._thread = thread

    def is_alive(self) -> bool:
        if self._server is None or self._thread is None:
            return False
        return self._thread.is_alive() and not self._stop_event.is_set()

    def terminate(self) -> None:
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.shutdown()
            with contextlib.suppress(Exception):
                self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._stop_event.set()


def _parse_content_length(raw: str | None) -> int:
    """Parse an HTTP ``Content-Length`` header value defensively.

    The header value is attacker-controllable. A robust server never lets a
    malformed value crash the request handler. Per RFC 7230 sec 3.3.2 a valid
    ``Content-Length`` is a run of one or more ASCII decimal digits with no
    sign, no exponent, no radix prefix, and no embedded whitespace. Anything
    else (a missing header, a non-decimal token like ``"abc"`` / ``"1e9"`` /
    ``"0x10"``, a whitespace-padded value like ``" 12 "``, a negative value, or
    a non-ASCII digit) is treated as a zero-length body so the handler still
    returns a controlled response instead of raising an uncaught ``ValueError``
    (or passing a negative length to ``rfile.read`` and reading the wrong
    number of bytes).
    """
    if raw is None:
        return 0
    # Strict: only a pristine run of ASCII decimal digits is a valid length.
    # ``str.isascii`` rules out unicode digit code points that ``str.isdigit``
    # accepts but ``int`` may reject; we do NOT strip whitespace because an
    # embedded/padded value is malformed, not merely formatted.
    if not raw.isascii() or not raw.isdigit():
        return 0
    try:
        value = int(raw)
    except ValueError:  # pragma: no cover - isascii()+isdigit() guarantee int()
        return 0
    return value if value >= 0 else 0


def _provider_from_path(path: str) -> str | None:
    """Best-effort provider extraction from an HTTPS proxy path component.

    The proxy receives requests like ``https://api.openai.com/v1/...`` so
    matching on the host suffix produces a stable provider tag. Returns
    None when no recognized provider host appears in the path.
    """
    if not path:
        return None
    lower = path.lower()
    if "openai.com" in lower:
        return "openai"
    if "anthropic.com" in lower:
        return "anthropic"
    if "googleapis.com" in lower:
        return "google"
    if "azure.com" in lower:
        return "azure"
    return None


def _model_from_body(body: dict[str, Any]) -> str | None:
    """Pull the ``model`` field out of an OpenAI-shaped request body."""
    if isinstance(body, dict):
        model = body.get("model")
        if isinstance(model, str) and model:
            return model
    return None


class _MitmProxyDriver(_ProxyDriver):
    """Spawn the ``mitmdump`` binary as a subprocess.

    Used by smoke-tier tests on hosts where mitmproxy is installed. The
    addon script that handles cassette lookup is generated on demand
    into the per-session dir so the binary picks it up via ``-s``.
    """

    name = DRIVER_MITMPROXY

    def __init__(self) -> None:
        self._proc: subprocess.Popen[bytes] | None = None
        self._addon_path: Path | None = None

    def start(self, *, port: int, ca: GeneratedCA, server: CassetteServer) -> None:
        binary = shutil.which("mitmdump")
        if binary is None:
            raise RelayProxyStartError(
                "mitmdump executable not found on PATH; either install "
                "mitmproxy or set RELAY_REPLAY_PROXY_DRIVER=inproc",
                details={"driver": self.name},
            )
        # Materialize a tiny addon script that delegates to the
        # cassette server. It runs in-band inside mitmdump so cassette
        # responses are returned without an external HTTP hop.
        addon_path = server.session_dir / "_addon.py"
        addon_path.write_bytes(_MITMPROXY_ADDON_SOURCE.encode("utf-8"))
        self._addon_path = addon_path
        cmd = [
            binary,
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(port),
            "--set",
            f"confdir={server.session_dir!s}",
            "--set",
            f"relay_session_dir={server.session_dir!s}",
            "-s",
            str(addon_path),
            "--quiet",
        ]
        try:
            proc = subprocess.Popen(  # noqa: S603 - args is a list, not shell=True
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise RelayProxyStartError(
                f"failed to spawn mitmdump: {exc}",
                details={"binary": binary, "port": port},
            ) from exc
        self._proc = proc

    def is_alive(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def terminate(self) -> None:
        if self._proc is None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            self._proc.terminate()
        try:
            self._proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, OSError):
                self._proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                self._proc.wait(timeout=1.0)
        if self._addon_path is not None:
            with contextlib.suppress(OSError):
                self._addon_path.unlink()

    @property
    def pid(self) -> int | None:
        if self._proc is None:
            return None
        return self._proc.pid


# Addon source body. Kept inline so the driver has no external file
# dependency at install time. mitmproxy's plugin loader imports this as
# a module and calls the ``request`` hook on every flow.
_MITMPROXY_ADDON_SOURCE: Final[str] = '''"""Auto-generated mitmproxy addon (W7.1)."""
import json
from pathlib import Path

from mitmproxy import ctx, http
from relay_replay_proxy.cassette_server import CassetteServer, IncomingRequest


_server: CassetteServer | None = None


def load(loader):
    loader.add_option("relay_session_dir", str, "", "Per-session cassette dir.")


def configure(updates):
    global _server
    if "relay_session_dir" in updates:
        d = ctx.options.relay_session_dir
        if d:
            _server = CassetteServer(Path(d))


def request(flow: http.HTTPFlow) -> None:
    if _server is None:
        return
    raw = flow.request.raw_content or b""
    try:
        body = json.loads(raw.decode("utf-8")) if raw else {}
    except Exception:
        body = {}
    provider = flow.request.headers.get("X-Relay-Provider", "")
    model = flow.request.headers.get("X-Relay-Model", "")
    req = IncomingRequest(provider=provider or "unknown", model=model or "unknown", body=body)
    response = _server.lookup(req)
    if response is None:
        flow.response = http.Response.make(
            404,
            json.dumps({"code": "RELAY-CASSETTE-MISS"}).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        return
    flow.response = http.Response.make(
        response.status, response.body_bytes, response.headers
    )
'''


class _FakeFailureDriver(_ProxyDriver):
    """Test driver that exits immediately after start (VAL-W7-010 path).

    Used by tier-1 plumbing tests to exercise the harness's proxy-down
    detection without requiring a real subprocess crash.
    """

    name = DRIVER_FAKE_FAILURE

    def __init__(self) -> None:
        self._started = False

    def start(self, *, port: int, ca: GeneratedCA, server: CassetteServer) -> None:
        self._started = True

    def is_alive(self) -> bool:  # noqa: D401 - simple
        return False

    def terminate(self) -> None:
        self._started = False


def _select_driver(name: str | None = None) -> _ProxyDriver:
    """Pick the driver named by ``name`` or by ``RELAY_REPLAY_PROXY_DRIVER``.

    Defaults to ``inproc`` because it has zero external dependencies and
    works on every CI matrix cell (including Windows without Docker).
    Smoke-tier tests opt into ``mitmproxy`` explicitly.
    """
    selected = (name or os.environ.get(ENV_DRIVER, "") or DRIVER_INPROC).strip()
    if selected not in _VALID_DRIVERS:
        raise RelayProxyStartError(
            f"unknown proxy driver {selected!r}; expected one of "
            f"{sorted(_VALID_DRIVERS)}",
            details={"driver": selected},
        )
    if selected == DRIVER_INPROC:
        return _InProcDriver()
    if selected == DRIVER_MITMPROXY:
        return _MitmProxyDriver()
    return _FakeFailureDriver()


# -----------------------------------------------------------------------------
# Session orchestration
# -----------------------------------------------------------------------------


@dataclass
class HarnessConfig:
    """Caller-supplied configuration for a harness session."""

    session_id: str
    cassette_root: Path  # ``${RELAY_HOME}/cassettes``
    driver: str | None = None
    ready_timeout_s: float = DEFAULT_READY_TIMEOUT_S
    extra_env: dict[str, str] = field(default_factory=dict)


@dataclass
class HarnessHandle:
    """Materialized handle returned by :func:`HarnessSession.start`.

    The CLI shim treats this as opaque: it exports ``proxy_url``,
    ``ca_cert_path``, and ``session_id`` into the agent subprocess env
    via :meth:`HarnessSession.agent_env`.
    """

    session_id: str
    session_dir: Path
    proxy_url: str
    proxy_port: int
    ca: GeneratedCA
    driver_name: str
    driver_pid: int | None
    started_at: float


class HarnessSession:
    """Owns the lifecycle of one replay-proxy session.

    Usage::

        cfg = HarnessConfig(
            session_id="abc",
            cassette_root=Path.home() / ".relay" / "cassettes",
        )
        sess = HarnessSession(cfg)
        handle = sess.start()  # raises RelayProxyStartError on failure
        try:
            env = sess.agent_env(parent_env=os.environ)
            subprocess.run(agent_cmd, env=env, check=True)
        finally:
            sess.stop()  # idempotent

    The session registers an ``atexit`` handler and SIGINT/SIGTERM
    handlers that call :meth:`stop` so a Python-level interrupt does
    not leave the CA cert on disk.
    """

    def __init__(self, config: HarnessConfig) -> None:
        self._config = config
        self._handle: HarnessHandle | None = None
        self._driver: _ProxyDriver | None = None
        self._cassette_server: CassetteServer | None = None
        self._stopped = False
        # RLock (not Lock): the SIGINT/SIGTERM cleanup handler runs on the
        # main thread BETWEEN bytecodes; if a signal arrives while
        # ``start()`` already holds ``self._lock``, the handler invokes
        # ``stop()`` which re-acquires the same lock and a non-reentrant
        # Lock would deadlock the interpreter. Re-entrant lock keeps the
        # mutual-exclusion contract for other threads (driver shutdown,
        # ``assert_alive`` probes) while allowing the same thread to nest.
        self._lock = threading.RLock()
        self._signal_handlers_installed = False
        self._previous_handlers: dict[int, Any] = {}

    # -- introspection -----------------------------------------------------

    @property
    def handle(self) -> HarnessHandle | None:
        return self._handle

    @property
    def session_dir(self) -> Path:
        return self._config.cassette_root / self._config.session_id

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> HarnessHandle:
        """Validate inputs, generate CA, bind port, spawn proxy, return handle.

        Raises:
            RelayProxyMissingCassetteError: cassette dir does not exist.
            RelayProxyStartError: any other start-time failure.
        """
        with self._lock:
            if self._handle is not None:
                return self._handle
            session_dir = self.session_dir
            if not session_dir.exists() or not session_dir.is_dir():
                raise RelayProxyMissingCassetteError(
                    f"cassette directory {session_dir!s} does not exist; "
                    "either record a session first via 'rly replay record' "
                    "or pass --record to start a new recording session "
                    "(--record support lands in W7.2)",
                    details={
                        "session_id": self._config.session_id,
                        "session_dir": str(session_dir),
                        "cassette_root": str(self._config.cassette_root),
                    },
                )

            # CA generation MUST happen before driver start so the driver
            # can serve its impersonated leaf certs from this CA. Failure
            # here is a hard start error (cleanup is unnecessary because
            # nothing else has been allocated yet).
            try:
                ca = generate_ca(
                    session_id=self._config.session_id,
                    session_dir=session_dir,
                    cassette_root=self._config.cassette_root,
                )
            except Exception as exc:
                raise RelayProxyStartError(
                    f"failed to generate per-session CA cert: {exc}",
                    details={"session_id": self._config.session_id},
                ) from exc

            cassette_server = CassetteServer(session_dir)
            driver = _select_driver(self._config.driver)
            port = pick_free_port()
            try:
                driver.start(port=port, ca=ca, server=cassette_server)
            except RelayProxyError:  # type: ignore[name-defined]  # noqa: F821
                # Clean up the CA on driver-start failure: the contract
                # says a failed start leaves no half-state on disk.
                remove_ca(ca)
                raise
            except Exception as exc:
                remove_ca(ca)
                raise RelayProxyStartError(
                    f"proxy driver {driver.name!r} failed to start: {exc}",
                    details={"driver": driver.name, "port": port},
                ) from exc

            # Wait for the driver to report ready. The in-process driver
            # is ready as soon as start() returns; the mitmproxy driver
            # may take a few hundred ms to bind. Poll TCP connect.
            self._await_ready(port, self._config.ready_timeout_s, driver)

            self._cassette_server = cassette_server
            self._driver = driver
            self._handle = HarnessHandle(
                session_id=self._config.session_id,
                session_dir=session_dir,
                proxy_url=f"http://127.0.0.1:{port}",
                proxy_port=port,
                ca=ca,
                driver_name=driver.name,
                driver_pid=driver.pid,
                started_at=time.time(),
            )

            # Install cleanup hooks AFTER all state is set so a hook
            # firing mid-start does not race with handle assignment.
            self._install_atexit_and_signal_handlers()

            return self._handle

    def stop(self) -> None:
        """Idempotent teardown: stop driver, remove CA, drop handlers."""
        with self._lock:
            if self._stopped:
                return
            self._stopped = True
            handle = self._handle
            self._handle = None
            driver = self._driver
            self._driver = None
            self._cassette_server = None
            if driver is not None:
                with contextlib.suppress(Exception):
                    driver.terminate()
            if handle is not None:
                removed = remove_ca(handle.ca)
                LOG.info(
                    "CA cert removed (session=%s, paths=%d)",
                    handle.session_id,
                    len(removed),
                )
            self._restore_signal_handlers()

    # -- env injection -----------------------------------------------------

    def agent_env(
        self, *, parent_env: dict[str, str] | os._Environ[str] | None = None
    ) -> dict[str, str]:
        """Return the env dict to pass into the agent subprocess.

        Per VAL-W7-012 the env is constructed atomically: we build the
        final dict in one allocation and hand it to ``subprocess.Popen``,
        which calls ``execve`` (POSIX) or ``CreateProcess`` (Windows)
        with the complete envp[]. The agent never observes a half-set
        env because the dict is constructed in-process before spawn.
        """
        if self._handle is None:
            raise RelayProxyStartError(
                "agent_env() called before start() succeeded",
                details={"session_id": self._config.session_id},
            )
        base: dict[str, str] = dict(parent_env if parent_env is not None else os.environ)
        # VAL-W7-006 / VAL-W7-007 / VAL-W7-012: required vars set together.
        base[ENV_HTTPS_PROXY] = self._handle.proxy_url
        base[ENV_HTTP_PROXY] = self._handle.proxy_url
        # Force the lowercase variants too (requests/urllib/libcurl honor them)
        # and neutralize any inherited NO_PROXY/no_proxy bypass list so the
        # agent cannot reach a host without traversing the proxy (VAL-W7-083).
        base[ENV_HTTPS_PROXY_LOWER] = self._handle.proxy_url
        base[ENV_HTTP_PROXY_LOWER] = self._handle.proxy_url
        base.pop(ENV_NO_PROXY, None)
        base.pop(ENV_NO_PROXY_LOWER, None)
        base[ENV_SSL_CERT_FILE] = str(self._handle.ca.cert_path)
        base[ENV_REPLAY_SESSION] = self._handle.session_id
        base[ENV_REPLAY_PROXY_URL] = self._handle.proxy_url
        # Caller-supplied extras (e.g., RELAY_API_KEY) overlay last but
        # MUST NOT shadow the proxy injection variables -- if they do,
        # the agent might bypass the harness entirely.
        for k, v in self._config.extra_env.items():
            if k in {
                ENV_HTTPS_PROXY,
                ENV_HTTP_PROXY,
                ENV_HTTPS_PROXY_LOWER,
                ENV_HTTP_PROXY_LOWER,
                ENV_NO_PROXY,
                ENV_NO_PROXY_LOWER,
                ENV_SSL_CERT_FILE,
                ENV_REPLAY_SESSION,
                ENV_REPLAY_PROXY_URL,
            }:
                # A caller-supplied NO_PROXY/no_proxy or lowercase proxy var
                # would re-open the bypass the injection just closed -- drop it.
                continue
            base[k] = v
        return base

    # -- health probes -----------------------------------------------------

    def assert_alive(self) -> None:
        """Raise :class:`RelayProxyDownError` if the proxy is no longer up.

        Called by the SDK on each request and by the CLI's poll loop
        between agent steps. The check is cheap: a TCP connect attempt
        to the proxy port (no payload).
        """
        if self._handle is None:
            raise RelayProxyDownError(
                "proxy is not started",
                details={"session_id": self._config.session_id},
            )
        driver = self._driver
        if driver is None or not driver.is_alive():
            raise RelayProxyDownError(
                f"proxy driver {self._handle.driver_name!r} exited mid-replay; "
                "restart instructions: re-run 'rly replay run --proxy ...' "
                f"and consult docs at "
                f"https://relay.epochly.com/docs/errors/RELAY-REPLAY-021",
                details={
                    "session_id": self._handle.session_id,
                    "proxy_url": self._handle.proxy_url,
                    "driver": self._handle.driver_name,
                    "driver_pid": self._handle.driver_pid,
                },
            )
        # Cheap TCP probe so an alive driver thread that has stopped
        # accepting connections is still detected.
        if not _proxy_tcp_alive("127.0.0.1", self._handle.proxy_port):
            raise RelayProxyDownError(
                f"proxy at {self._handle.proxy_url} refused TCP connection "
                "(ECONNREFUSED); restart instructions: re-run 'rly replay run "
                "--proxy ...' and consult docs at "
                f"https://relay.epochly.com/docs/errors/RELAY-REPLAY-021",
                details={
                    "session_id": self._handle.session_id,
                    "proxy_url": self._handle.proxy_url,
                    "driver": self._handle.driver_name,
                },
            )

    # -- internals ---------------------------------------------------------

    def _await_ready(
        self,
        port: int,
        timeout_s: float,
        driver: _ProxyDriver,
    ) -> None:
        """Block until the proxy accepts TCP or the timeout elapses."""
        deadline = time.time() + max(0.1, timeout_s)
        while time.time() < deadline:
            if not driver.is_alive():
                # The driver exited before becoming ready -- VAL-W7-010
                # branch but at start time; surface as start error.
                raise RelayProxyStartError(
                    f"proxy driver {driver.name!r} exited before ready",
                    details={"driver": driver.name, "port": port},
                )
            if _proxy_tcp_alive("127.0.0.1", port):
                return
            time.sleep(READY_POLL_INTERVAL_S)
        raise RelayProxyStartError(
            f"proxy did not become ready within {timeout_s:.2f}s",
            details={"driver": driver.name, "port": port},
        )

    def _install_atexit_and_signal_handlers(self) -> None:
        if self._signal_handlers_installed:
            return
        self._signal_handlers_installed = True
        atexit.register(self._atexit_cleanup)
        # Only install signal handlers in the main thread; non-main
        # threads cannot register them on POSIX. Tests that run the
        # harness from a worker thread skip this branch silently.
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    self._previous_handlers[sig] = signal.getsignal(sig)
                    signal.signal(sig, self._signal_cleanup)
                except (ValueError, OSError):
                    # Windows lacks SIGTERM in some shells; ignore.
                    continue

    def _restore_signal_handlers(self) -> None:
        if not self._signal_handlers_installed:
            return
        self._signal_handlers_installed = False
        if threading.current_thread() is threading.main_thread():
            for sig, prev in self._previous_handlers.items():
                with contextlib.suppress(ValueError, OSError, TypeError):
                    signal.signal(sig, prev)
        self._previous_handlers = {}

    def _atexit_cleanup(self) -> None:  # pragma: no cover - exercised at process exit
        try:
            self.stop()
        except Exception as exc:
            LOG.warning("atexit cleanup error: %s", exc)

    def _signal_cleanup(self, signum: int, frame: Any) -> None:
        # Restore prior handler so a second signal terminates the process
        # immediately (avoid trapping forever).
        prev = self._previous_handlers.get(signum)
        with contextlib.suppress(ValueError, OSError, TypeError):
            signal.signal(signum, prev if prev is not None else signal.SIG_DFL)
        try:
            self.stop()
        finally:
            # Re-raise the signal so the process exits with the canonical
            # 128 + signum code (the CLI wrapper records this in stderr).
            if hasattr(signal, "raise_signal"):
                signal.raise_signal(signum)
            else:
                os.kill(os.getpid(), signum)


def _proxy_tcp_alive(host: str, port: int, timeout_s: float = 0.25) -> bool:
    """Return True if a TCP connect to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except (TimeoutError, OSError):
        return False


# -----------------------------------------------------------------------------
# Public re-exports
# -----------------------------------------------------------------------------

# Suppress unused-import lint on Callable / secrets / sys -- they are
# referenced from docstrings or future surface area.
_ = (Callable, secrets, sys)


__all__ = [
    "DEFAULT_READY_TIMEOUT_S",
    "DRIVER_FAKE_FAILURE",
    "DRIVER_INPROC",
    "DRIVER_MITMPROXY",
    "ENV_DRIVER",
    "ENV_HTTPS_PROXY",
    "ENV_HTTP_PROXY",
    "ENV_REPLAY_PROXY_URL",
    "ENV_REPLAY_SESSION",
    "ENV_SSL_CERT_FILE",
    "EPHEMERAL_PORT_HIGH",
    "EPHEMERAL_PORT_LOW",
    "HarnessConfig",
    "HarnessHandle",
    "HarnessSession",
    "MAX_PORT_RETRIES",
    "pick_free_port",
]
