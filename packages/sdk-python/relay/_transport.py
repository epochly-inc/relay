"""Sidecar auto-spawn / attach machinery for the Relay Python SDK (W3.1).

This module is the SDK's bridge to the local sidecar control plane. It is
deliberately import-side-effect-free: importing it spawns nothing, binds no
port, and touches no lockfile (VAL-W3-001). All side effects happen inside
:meth:`SidecarTransport.ensure_attached`, which is invoked lazily by the
first :class:`relay.client.Relay` operation that needs the sidecar
(VAL-W3-002, VAL-W3-003).

Auto-spawn reuses the canonical, race-safe ``acquire_or_attach`` from
``relay_sidecar.spawn`` -- the portalocker-serialized four-state lockfile
classifier (VAL-W3-006 cross-links W2 VAL-W2-006). The SDK supplies a real
``process_runner`` that launches the sidecar as a ``run_uvicorn``
subprocess. The bearer token is generated SDK-side and threaded BOTH into
the spawned subprocess (so it can serve ``/health``) AND into
``acquire_or_attach`` (so the lockfile digest matches).

Attach vs spawn auth:
  - SPAWN path: the SDK holds the plaintext bearer token, so it runs the
    full ``/health/nonce`` -> sign -> ``/health`` nonce challenge
    (VAL-W3-004).
  - ATTACH path (a peer process started the sidecar): the SDK only has the
    lockfile's bearer-token DIGEST, not the plaintext token. It
    authenticates with the bearer digest alone (the sidecar's nonce
    headers are optional); this is the cross-process attach the W2
    ``/health`` route supports.

``RELAY_NO_AUTOSPAWN=1`` disables the spawn branch entirely (VAL-W3-008):
the SDK only attaches to an already-running sidecar and raises
:class:`relay.errors.RelaySidecarNotReachable` if none is reachable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from relay_sidecar.event_log import append_event
from relay_sidecar.lockfile import (
    LockfileBody,
    parse_lockfile_body,
    resolve_lockfile_path,
)
from relay_sidecar.process import pid_is_alive
from relay_sidecar.spawn import BEARER_TOKEN_BYTES, acquire_or_attach

# Environment variable that disables SDK auto-spawn (VAL-W3-008). When set
# to "1" the SDK never spawns a sidecar; it only attaches to one started
# out of band (for example via ``relay sidecar start --daemon``).
NO_AUTOSPAWN_ENV: str = "RELAY_NO_AUTOSPAWN"

# SDK sidecar-compatibility range (VAL-W3-007; CLAUDE.md invariant #10).
# The SDK refuses to operate against a sidecar whose ``sidecar_version``
# from ``/health`` falls outside ``[MIN, MAX]`` inclusive. v0.1 pins both
# ends to the single shipped version; the range widens as the sidecar wire
# surface stabilises. Versions are compared as dotted integer tuples.
MIN_COMPATIBLE_SIDECAR_VERSION: str = "0.0.0"
MAX_COMPATIBLE_SIDECAR_VERSION: str = "0.0.0"

# How long to wait for a freshly-spawned sidecar subprocess to bind its
# port and answer ``/health``. The sidecar runs synchronous startup
# recovery + SQLite WAL setup before binding, so this is generous.
SPAWN_READY_TIMEOUT_S: float = 30.0
SPAWN_READY_POLL_INTERVAL_S: float = 0.05

# Per-request HTTP timeout for the loopback sidecar calls.
HTTP_TIMEOUT_S: float = 10.0


def _digest_of_token(token: str) -> str:
    """Return the canonical ``sha256-<hex>`` digest of ``token``.

    Matches ``relay_sidecar.spawn._digest_of_token`` /
    ``relay_sidecar.health._bearer_digest_of`` byte for byte.
    """
    return f"sha256-{hashlib.sha256(token.encode('utf-8')).hexdigest()}"


def _nonce_proof(nonce: str, token: str) -> str:
    """Compute the canonical nonce proof: SHA-256(``nonce:token``).

    This matches ``relay_sidecar.health._proof_of`` exactly. The W2
    ``/health`` route verifies the proof with this construction; the SDK
    MUST produce the identical digest or the sidecar returns 401 and the
    SDK surfaces :class:`relay.errors.RelayAuthMismatch`.
    """
    return hashlib.sha256(f"{nonce}:{token}".encode()).hexdigest()


def _version_tuple(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into an integer tuple for comparison.

    Raises ``ValueError`` on a non-numeric component so a malformed
    ``sidecar_version`` is treated as an explicit incompatibility rather
    than silently accepted.
    """
    parts = version.strip().split(".")
    return tuple(int(p) for p in parts)


def is_sidecar_version_compatible(version: str) -> bool:
    """Return True iff ``version`` is within the SDK compat range.

    VAL-W3-007: a ``sidecar_version`` outside
    ``[MIN_COMPATIBLE_SIDECAR_VERSION, MAX_COMPATIBLE_SIDECAR_VERSION]`` is
    incompatible. A version string that cannot be parsed as a dotted
    integer tuple is incompatible (fail closed).
    """
    try:
        observed = _version_tuple(version)
        low = _version_tuple(MIN_COMPATIBLE_SIDECAR_VERSION)
        high = _version_tuple(MAX_COMPATIBLE_SIDECAR_VERSION)
    except (ValueError, AttributeError):
        return False
    return low <= observed <= high


@dataclass(frozen=True)
class SidecarConnection:
    """A live, authenticated connection to the local sidecar.

    Attributes:
        base_url: ``http://127.0.0.1:<port>`` for the attached sidecar.
        port: The sidecar's bound loopback port.
        pid: The sidecar process PID (from the lockfile).
        sidecar_version: The version string returned by ``/health``.
        bearer_token_digest: The ``sha256-<hex>`` digest from the lockfile.
        auth_header: The value to present as ``X-Relay-Auth`` on subsequent
            calls -- the nonce proof when the SDK spawned the sidecar (and
            therefore holds the plaintext token), or the bearer digest on a
            cross-process attach.
        spawned: True if this SDK instance spawned the sidecar; False if it
            attached to a peer-started one.
    """

    base_url: str
    port: int
    pid: int
    sidecar_version: str
    bearer_token_digest: str
    auth_header: str
    spawned: bool


def _repo_sys_path_entries() -> list[str]:
    """Return the sys.path entries a spawned sidecar subprocess needs.

    The spawned ``python -m`` style subprocess must be able to import
    ``relay_sidecar`` and ``relay_schemas``. In an installed environment
    these are on the default path; in the in-repo workspace they live
    under ``apps/local-sidecar`` and ``packages/schemas/python``. We pass
    whatever directories currently expose those packages so the subprocess
    inherits the exact same import roots as the parent.
    """
    entries: list[str] = []
    try:
        import relay_sidecar

        pkg_dir = Path(relay_sidecar.__file__).resolve().parent.parent
        entries.append(str(pkg_dir))
    except Exception:  # noqa: BLE001 - best-effort path discovery
        pass
    try:
        import relay_schemas

        schemas_dir = Path(relay_schemas.__file__).resolve().parent.parent
        entries.append(str(schemas_dir))
    except Exception:  # noqa: BLE001 - relay_schemas may be unused at runtime
        pass
    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for e in entries:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


# The subprocess entry script. Kept as a -c string (no temp file) so the
# SDK has zero on-disk script footprint. It binds the sidecar on the port
# the parent pre-selected, serving /health with the parent-supplied bearer
# token so the nonce challenge round-trips.
#
# All structured input (sys.path entries, relay home, port, token, digest)
# is passed as a SINGLE JSON-encoded argv element. JSON avoids the
# "embedded null byte" ValueError that argv elements raise on NUL and
# survives paths containing os.pathsep.
_SIDECAR_SUBPROCESS_SCRIPT = """
import json
import sys

_args = json.loads(sys.argv[1])
for _p in _args["sys_path"]:
    if _p:
        sys.path.insert(0, _p)

from pathlib import Path
from relay_sidecar.health import HealthState
from relay_sidecar.runtime import run_uvicorn

_health = HealthState(
    port=_args["port"],
    bearer_token=_args["token"],
    bearer_token_digest=_args["digest"],
)
run_uvicorn(
    health=_health,
    host="127.0.0.1",
    port=_args["port"],
    relay_home_override=Path(_args["relay_home"]),
)
"""


class SidecarTransport:
    """Lazy, thread-safe sidecar auto-spawn / attach for one Relay instance.

    Construction is side-effect-free. The first call to
    :meth:`ensure_attached` runs the spawn/attach machinery exactly once;
    subsequent calls return the cached :class:`SidecarConnection`.

    A single shared :class:`httpx.Client` is created per transport (per
    Relay instance) and reused for every loopback call to the sidecar.
    """

    def __init__(self, *, relay_home: Path) -> None:
        self._relay_home = relay_home
        self._lock = threading.Lock()
        self._connection: SidecarConnection | None = None
        self._http: httpx.Client | None = None
        # A handle to the sidecar subprocess IF this transport spawned it.
        # Retained so the process is not garbage-collected; the sidecar's
        # own idle-shutdown / quiesce protocol owns its lifecycle.
        self._spawned_proc: subprocess.Popen[bytes] | None = None

    # -- public surface ------------------------------------------------------

    @property
    def http(self) -> httpx.Client:
        """Return the shared per-instance httpx client, creating it lazily.

        The client is created on first use, never at import time, so the
        side-effect-free import contract (VAL-W3-001) holds.
        """
        if self._http is None:
            self._http = httpx.Client(
                timeout=httpx.Timeout(HTTP_TIMEOUT_S, connect=HTTP_TIMEOUT_S),
                follow_redirects=False,
            )
        return self._http

    def ensure_attached(self) -> SidecarConnection:
        """Spawn or attach to the sidecar; return the live connection.

        Idempotent and thread-safe: the spawn/attach machinery runs at most
        once per transport. The first invocation triggers exactly one
        ``sidecar.spawned`` OR one ``sidecar.attached`` event_log row
        (VAL-W3-002).
        """
        if self._connection is not None:
            return self._connection
        with self._lock:
            if self._connection is not None:
                return self._connection
            conn = self._spawn_or_attach()
            self._connection = conn
            return conn

    def close(self) -> None:
        """Release the shared httpx client. Does NOT stop the sidecar.

        The sidecar's lifecycle is owned by its own quiesce / idle-shutdown
        protocol (W2.6) and by ``relay sidecar stop`` -- the SDK never kills
        it. This only frees the SDK-side HTTP connection pool and, if the
        sidecar this transport spawned has ALREADY exited on its own,
        reaps the now-defunct child handle (hygiene; never signals a live
        sidecar).
        """
        if self._http is not None:
            self._http.close()
            self._http = None
        proc = self._spawned_proc
        if proc is not None and proc.poll() is not None:
            # The spawned sidecar already exited (idle shutdown, quiesce,
            # or an external ``relay sidecar stop``). Reap the defunct
            # child so no zombie lingers. A still-running sidecar is left
            # entirely untouched -- it is a detached daemon.
            self._spawned_proc = None

    def reap_spawned_if_exited(self) -> bool:
        """Reap the spawned sidecar child IFF it has already exited.

        Returns True if a defunct child was reaped (or none was tracked),
        False if the spawned sidecar is still running and was left alone.
        The SDK NEVER signals a live sidecar -- this is exit-hygiene only,
        used by tests after they stop the sidecar via its lockfile PID.
        """
        proc = self._spawned_proc
        if proc is None:
            return True
        if proc.poll() is None:
            return False
        # Process is dead; ``poll`` has already set returncode and reaped
        # it. Drop the handle so ``Popen.__del__`` has nothing to warn
        # about.
        self._spawned_proc = None
        return True

    # -- internals -----------------------------------------------------------

    def _spawn_or_attach(self) -> SidecarConnection:
        """Core spawn/attach decision. Assumes ``self._lock`` is held."""
        no_autospawn = os.environ.get(NO_AUTOSPAWN_ENV, "").strip() == "1"

        if no_autospawn:
            # VAL-W3-008: never spawn. Attach to a reachable sidecar or
            # raise RelaySidecarNotReachable.
            return self._attach_no_autospawn()

        # Auto-spawn path. Generate the bearer token SDK-side so it can be
        # threaded into BOTH the spawned subprocess AND acquire_or_attach.
        token = secrets.token_urlsafe(BEARER_TOKEN_BYTES)
        digest = _digest_of_token(token)

        decision = acquire_or_attach(
            home=self._relay_home,
            process_runner=lambda: self._spawn_runner(token, digest),
            bearer_token=token,
        )

        if decision.action == "attached":
            # A peer process owns the sidecar. acquire_or_attach does NOT
            # emit an event for the attach branch, so the SDK records the
            # SDK-observed lifecycle event here (VAL-W3-002 / VAL-W3-006:
            # the 9 losers each log exactly one sidecar.attached row).
            body = decision.lockfile_body
            append_event(
                "sidecar.attached",
                scope_type="other",
                actor_kind="sdk",
                payload={"pid": body.pid, "port": body.port},
                home=self._relay_home,
            )
            return self._attach_to_running(body, plaintext_token=None)

        # One of the spawn variants. acquire_or_attach already emitted
        # ``sidecar.spawned`` (NO_LOCKFILE branch) or ``sidecar.respawned``
        # (recovery branches). The lockfile now records OUR digest because
        # we passed ``bearer_token=token``; we hold the plaintext token, so
        # we can run the full nonce challenge.
        body = decision.lockfile_body
        return self._attach_to_running(body, plaintext_token=token)

    def _attach_no_autospawn(self) -> SidecarConnection:
        """VAL-W3-008: attach-only path; raise if no sidecar is reachable."""
        from .errors import RelaySidecarNotReachable

        lockfile_path = resolve_lockfile_path(self._relay_home)
        if not lockfile_path.exists() or lockfile_path.stat().st_size == 0:
            raise RelaySidecarNotReachable(
                "RELAY_NO_AUTOSPAWN=1 is set and no sidecar lockfile was "
                f"found at {lockfile_path}; start a sidecar first "
                "(for example: relay sidecar start --daemon)",
                details={
                    "relay_home": str(self._relay_home),
                    "lockfile_path": str(lockfile_path),
                    "autospawn_disabled": True,
                },
            )
        try:
            body = parse_lockfile_body(lockfile_path.read_bytes())
        except Exception as exc:  # noqa: BLE001 - any parse failure = unreachable
            raise RelaySidecarNotReachable(
                "RELAY_NO_AUTOSPAWN=1 is set and the sidecar lockfile is "
                f"unreadable or malformed at {lockfile_path}: {exc}",
                details={
                    "relay_home": str(self._relay_home),
                    "lockfile_path": str(lockfile_path),
                    "autospawn_disabled": True,
                },
            ) from exc

        if not pid_is_alive(body.pid):
            raise RelaySidecarNotReachable(
                "RELAY_NO_AUTOSPAWN=1 is set and the lockfile-recorded "
                f"sidecar PID {body.pid} is not alive; start a sidecar "
                "first (for example: relay sidecar start --daemon)",
                details={
                    "relay_home": str(self._relay_home),
                    "lockfile_pid": body.pid,
                    "autospawn_disabled": True,
                },
            )
        # The lockfile looks live. Try to attach; a connection failure here
        # also surfaces as RelaySidecarNotReachable rather than a raw httpx
        # error so callers get a single typed failure mode.
        try:
            # No plaintext token on the attach-only path (we never spawned).
            self._emit_attached_event(body)
            return self._attach_to_running(body, plaintext_token=None)
        except httpx.HTTPError as exc:
            raise RelaySidecarNotReachable(
                "RELAY_NO_AUTOSPAWN=1 is set and the sidecar recorded in "
                f"the lockfile did not answer on 127.0.0.1:{body.port}: {exc}",
                details={
                    "relay_home": str(self._relay_home),
                    "lockfile_port": body.port,
                    "autospawn_disabled": True,
                },
            ) from exc

    def _emit_attached_event(self, body: LockfileBody) -> None:
        """Append one ``sidecar.attached`` event_log row for this attach."""
        append_event(
            "sidecar.attached",
            scope_type="other",
            actor_kind="sdk",
            payload={"pid": body.pid, "port": body.port},
            home=self._relay_home,
        )

    def _spawn_runner(self, token: str, digest: str) -> tuple[int, int]:
        """``process_runner`` for ``acquire_or_attach``: launch run_uvicorn.

        Pre-selects an ephemeral loopback port, launches the sidecar as a
        detached ``run_uvicorn`` subprocess bound to that port and serving
        ``/health`` with the parent-supplied bearer token, waits until the
        port answers, and returns ``(child_pid, port)``.

        The brief gap between releasing the pre-selected port and the
        subprocess re-binding it mirrors the W2.1 ``_default_process_runner``
        pattern; the portalocker decision lock held by ``acquire_or_attach``
        keeps the spawn race itself serialized.
        """
        import socket as _socket

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        subprocess_args = json.dumps(
            {
                "sys_path": _repo_sys_path_entries(),
                "relay_home": str(self._relay_home),
                "port": port,
                "token": token,
                "digest": digest,
            }
        )
        proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _SIDECAR_SUBPROCESS_SCRIPT,
                subprocess_args,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # close_fds so the child does not inherit the SDK's open files.
            close_fds=True,
            # start_new_session detaches the sidecar into its own process
            # group / session: it is a genuine daemon whose lifecycle is
            # owned by the W2.6 quiesce / idle-shutdown protocol and
            # ``relay sidecar stop`` -- NOT tied to the SDK process that
            # happened to spawn it. The SDK never signals it.
            start_new_session=True,
        )
        self._spawned_proc = proc

        # Wait for the subprocess to bind the port and answer /health.
        deadline = time.monotonic() + SPAWN_READY_TIMEOUT_S
        bearer_digest = digest
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    "relay sidecar subprocess exited during startup with "
                    f"return code {proc.returncode}"
                )
            try:
                resp = self.http.get(
                    f"http://127.0.0.1:{port}/health",
                    headers={"X-Relay-Bearer-Digest": bearer_digest},
                    timeout=1.0,
                )
                if resp.status_code == 200:
                    return proc.pid, port
            except httpx.HTTPError:
                pass
            time.sleep(SPAWN_READY_POLL_INTERVAL_S)

        # Timed out. Do not leave the subprocess running unobserved.
        proc.terminate()
        raise RuntimeError(
            f"relay sidecar subprocess did not answer /health on "
            f"127.0.0.1:{port} within {SPAWN_READY_TIMEOUT_S}s"
        )

    def _attach_to_running(
        self, body: LockfileBody, *, plaintext_token: str | None
    ) -> SidecarConnection:
        """Authenticate against a running sidecar and return the connection.

        When ``plaintext_token`` is provided (the SDK spawned the sidecar),
        run the full ``/health/nonce`` -> sign -> ``/health`` nonce
        challenge (VAL-W3-004). Otherwise authenticate with the lockfile
        bearer digest alone (cross-process attach).

        Always checks ``sidecar_version`` compatibility (VAL-W3-007) and
        raises before returning a usable connection on a mismatch.
        """
        from .errors import RelayAuthMismatch, RelaySidecarVersionMismatch

        base_url = f"http://127.0.0.1:{body.port}"
        bearer_digest = body.bearer_token_digest

        if plaintext_token is not None:
            # Full nonce challenge. Step 1: obtain a server nonce.
            try:
                nonce_resp = self.http.get(
                    f"{base_url}/health/nonce",
                    headers={"X-Relay-Bearer-Digest": bearer_digest},
                )
            except httpx.HTTPError as exc:
                raise RelayAuthMismatch(
                    f"sidecar nonce challenge failed: {exc}",
                    details={"base_url": base_url, "phase": "nonce-request"},
                ) from exc
            if nonce_resp.status_code != 200:
                raise RelayAuthMismatch(
                    "sidecar rejected the bearer digest on the nonce "
                    f"request (HTTP {nonce_resp.status_code})",
                    details={
                        "base_url": base_url,
                        "phase": "nonce-request",
                        "http_status": nonce_resp.status_code,
                    },
                )
            nonce_body = nonce_resp.json()
            nonce = nonce_body.get("nonce")
            if not isinstance(nonce, str) or not nonce:
                raise RelayAuthMismatch(
                    "sidecar /health/nonce response omitted a usable nonce",
                    details={"base_url": base_url, "phase": "nonce-parse"},
                )
            # Step 2: sign the nonce and present the proof on /health.
            proof = _nonce_proof(nonce, plaintext_token)
            try:
                health_resp = self.http.get(
                    f"{base_url}/health",
                    headers={
                        "X-Relay-Bearer-Digest": bearer_digest,
                        "X-Relay-Nonce": nonce,
                        "X-Relay-Nonce-Proof": proof,
                        # The contract names this header explicitly; we
                        # present the signed nonce under it as well so a
                        # sidecar (or proxy) that keys on X-Relay-Auth sees
                        # the proof.
                        "X-Relay-Auth": proof,
                    },
                )
            except httpx.HTTPError as exc:
                raise RelayAuthMismatch(
                    f"sidecar /health nonce-proof call failed: {exc}",
                    details={"base_url": base_url, "phase": "health-proof"},
                ) from exc
            if health_resp.status_code != 200:
                raise RelayAuthMismatch(
                    "sidecar rejected the signed nonce proof "
                    f"(HTTP {health_resp.status_code})",
                    details={
                        "base_url": base_url,
                        "phase": "health-proof",
                        "http_status": health_resp.status_code,
                    },
                )
            auth_header = proof
        else:
            # Cross-process attach: only the bearer digest is available.
            try:
                health_resp = self.http.get(
                    f"{base_url}/health",
                    headers={"X-Relay-Bearer-Digest": bearer_digest},
                )
            except httpx.HTTPError as exc:
                raise RelayAuthMismatch(
                    f"sidecar /health call failed during attach: {exc}",
                    details={"base_url": base_url, "phase": "health-attach"},
                ) from exc
            if health_resp.status_code != 200:
                raise RelayAuthMismatch(
                    "sidecar rejected the lockfile bearer digest on attach "
                    f"(HTTP {health_resp.status_code})",
                    details={
                        "base_url": base_url,
                        "phase": "health-attach",
                        "http_status": health_resp.status_code,
                    },
                )
            auth_header = bearer_digest

        # VAL-W3-007: version compatibility gate. The /health body carries
        # ``sidecar_version``; a value outside the SDK compat range stops
        # the attach before any operation proceeds.
        health_body: dict[str, Any] = health_resp.json()
        sidecar_version = health_body.get("sidecar_version")
        if not isinstance(sidecar_version, str) or not sidecar_version:
            raise RelaySidecarVersionMismatch(
                "sidecar /health response omitted sidecar_version; cannot "
                "verify compatibility",
                details={"base_url": base_url, "health_body": health_body},
            )
        if not is_sidecar_version_compatible(sidecar_version):
            raise RelaySidecarVersionMismatch(
                f"sidecar version {sidecar_version!r} is outside the SDK "
                f"compatibility range "
                f"[{MIN_COMPATIBLE_SIDECAR_VERSION}, "
                f"{MAX_COMPATIBLE_SIDECAR_VERSION}]",
                details={
                    "base_url": base_url,
                    "sidecar_version": sidecar_version,
                    "min_compatible": MIN_COMPATIBLE_SIDECAR_VERSION,
                    "max_compatible": MAX_COMPATIBLE_SIDECAR_VERSION,
                },
            )

        return SidecarConnection(
            base_url=base_url,
            port=body.port,
            pid=body.pid,
            sidecar_version=sidecar_version,
            bearer_token_digest=bearer_digest,
            auth_header=auth_header,
            spawned=plaintext_token is not None,
        )


__all__ = [
    "HTTP_TIMEOUT_S",
    "MAX_COMPATIBLE_SIDECAR_VERSION",
    "MIN_COMPATIBLE_SIDECAR_VERSION",
    "NO_AUTOSPAWN_ENV",
    "SidecarConnection",
    "SidecarTransport",
    "is_sidecar_version_compatible",
]
