"""FastAPI asyncio runtime + lifecycle for the local sidecar (W2.2 + W2.6).

Builds on the W2.1 ``health.build_app`` skeleton. W2.2 lands:

  - The modern FastAPI ``lifespan`` async context manager (replacing the
    deprecated ``@app.on_event`` decorators).
  - A SINGLE shared ``httpx.AsyncClient`` instantiated in lifespan startup
    and reused for every outbound request the sidecar issues (eng plan A2;
    VAL-W2-013). Construction calls are counted via a module-level
    ``_async_client_init_counter`` so tests can assert ``count == 1`` after
    N=50 outbound requests.
  - An ``aiosqlite`` connection pool whose ``PRAGMA journal_mode=WAL`` and
    ``PRAGMA busy_timeout = 5000`` run BEFORE the HTTP listener binds the
    port (VAL-W2-014). The bind timestamp is recorded on
    ``app.state.bound_at_monotonic`` so tests can assert
    ``port_bind_timestamp <= first_request_timestamp``.
  - A ``_draining`` flag toggled in lifespan shutdown plus an HTTP
    middleware that returns ``503 Retry-After: 30`` for new requests once
    draining is true (eng plan A1 + X1; VAL-W2-015). In-flight requests
    proceed to completion; SIGTERM is wired to an ``asyncio.Event`` that
    the lifespan awaits.
  - All route handlers are ``async def`` (VAL-W2-012; grep guard).
  - Zero blocking I/O inside async handler bodies (VAL-W2-016; AST lint).

W2.6 extends the lifespan with the FULL quiesce protocol (VAL-W2-043
through VAL-W2-048):

  - ``InflightTracker`` registered on ``RuntimeState.quiesce.tracker``;
    long-running operations (ingest, gate evaluate, replay session,
    background flush) acquire it via ``async with tracker.acquire(...)``
    so the idle-countdown task only fires when the sidecar is genuinely
    idle (VAL-W2-043 + VAL-W2-048).
  - ``/v1/ingest`` placeholder endpoint that participates in the tracker
    so VAL-W2-044 (drain rejects new ingest with 503) is exercisable end
    to end while the full ingest surface lands later in W3+.
  - Lifespan tear-down ordering on graceful shutdown:
      1. ``state.draining = True`` (drain middleware now answers 503).
      2. Wait for tracker.in_flight_count to reach 0 (bounded by
         ``RELAY_SIDECAR_DRAIN_DEADLINE_S``; defaults to 30s matching the
         manifest service.local-sidecar.quiesce_timeout_ms).
      3. ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer connection
         BEFORE closing aiosqlite connections (VAL-W2-045 -- WAL file
         size = 0 post-shutdown).
      4. Close the SidecarDatabase (cancels writer task, closes
         connections).
      5. Close the shared httpx.AsyncClient.
      6. Clear the lockfile via ``local_atomic_file_write(path, b"")``
         (VAL-W2-047) so the next ``acquire_or_attach`` classifies it as
         NO_LOCK rather than STALE_PID.
  - SIGUSR1 (or SIGTERM on Windows) handler triggers the force-stop path:
      a. Emit one ``sidecar.forced_stop`` event_log_entries row BEFORE
         killing any in-flight transaction (VAL-W2-046).
      b. Set ``state.quiesce.force_stop_requested = True`` so the
         lifespan tear-down branch SKIPS the WAL checkpoint AND SKIPS
         the lockfile clear (force-stop deliberately leaves the
         lockfile in place; the next spawn observes STALE_PID and
         clears via spawn.py).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
from fastapi import FastAPI, Request

# Server-side ReDoS budget enforcement at POST /v1/redaction-policies
# (VAL-V3M5-001/002/004, spec AI line 5665). Reuse the sdk-python
# evaluator rather than duplicating the 50 ms wall-clock budget logic
# in the sidecar (no-duplicate-implementation guard in
# test_audit_v3_redos_publish::test_v3m5_archive_bomb_cap_regression_lock).
from relay.redaction_budget import (
    REDACTION_REGEX_BUDGET_MS,
    RelayBudgetExceededError,
    evaluate_matcher_budget,
)
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from . import __version__
from .db import DEFAULT_READER_COUNT, SidecarDatabase
from .errors import (
    RELAY_SIDECAR_DB_CORRUPT_CODE,
    RelayDiskFullError,
    RelaySQLiteBusyExhausted,
)
from .health import HealthState, _register_health_routes
from .lockfile import relay_home, resolve_lockfile_path
from .manifest_enforcement import (
    ManifestRegistry,
    enforce_command_hash,
    enforce_manifest_active_or_in_grace,
)
from .primitives import local_atomic_file_write
from .primitives.transactional_db_write import (
    set_active_database,
    transactional_db_write,
)
from .quiesce import (
    InflightTracker,
    QuiesceState,
    force_stop_signal_number,
    resolve_idle_timeout_seconds,
)
from .recovery import recover_or_refuse
from .side_effect_markers import (
    EnforcementRejection,
    check_span_marker_pairing,
)
from .state_engine.handoff import (
    ACTOR_NOT_REGISTERED,
    MANIFEST_NOT_ACTIVE,
    SCOPE_ID_MISMATCH,
    validate_three_anchor_handoff,
)
from .state_engine.http_endpoint import build_state_router
from .validation.ingest_limits import validate_span_size_and_depth
from .validation.ingest_utf8 import validate_indexed_utf8
from .validation.raw_capture import evaluate_raw_capture_on_request


def _sha256_canonical(body: bytes) -> str:
    """Compute the canonical Relay sha256 wire form ``sha256-<64 lowercase hex>``.

    Audit fix (2026-05-17 P0): canonical envelopes (envelopes.yaml,
    VAL-W1-009) and the manifest_versions CHECK constraint pin the
    hyphen form. The legacy ``sha256:<hex>`` (colon) form is rejected.
    """
    return "sha256-" + hashlib.sha256(body).hexdigest()


# In-memory idempotency-cache bounds (DoS hardening for the same attack
# class as ``_prune_nonce_store``/``MAX_ISSUED_NONCES`` in health.py and the
# rate-limit-bucket stale sweep in ``_rate_limit_state`` below). The HTTP
# ``Idempotency-Key`` is attacker-controlled with effectively unlimited
# cardinality (26-char Crockford ULID grammar); without bounds an
# authenticated client can stream distinct keys to grow
# ``runtime.idempotency_store`` without limit, each entry retaining the full
# response_body -> authenticated memory-exhaustion DoS. The DB-backed
# ``idempotency_records`` table already carries a 24h TTL (spec B.2); the
# in-memory map mirrors the SAME TTL so the two stay consistent (a key still
# replays its cached response within the window) plus a hard size cap.
IDEMPOTENCY_RECORD_TTL_S: float = 24 * 60 * 60  # 24h, matches the DB TTL.
MAX_IDEMPOTENCY_RECORDS: int = 4096  # mirrors MAX_ISSUED_NONCES style.

# Key under which each in-memory idempotency record carries its insertion
# stamp (``runtime._now_epoch_s()`` value). Read only by the prune helper;
# ``_response_for_existing`` ignores it, so adding it is response-neutral.
_IDEMPOTENCY_STORED_AT_KEY: str = "_stored_at_epoch_s"


def _prune_idempotency_store(
    store: dict[str, dict[str, dict[str, Any]]],
    *,
    now: float,
    ttl_s: float = IDEMPOTENCY_RECORD_TTL_S,
    max_entries: int = MAX_IDEMPOTENCY_RECORDS,
) -> None:
    """Bound the in-memory idempotency cache in place (DoS hardening).

    Structurally mirrors ``health._prune_nonce_store``: two reclamation
    passes, both mutating ``store`` directly. ``store`` is the nested
    ``surface -> {key -> record}`` map; a record carries its insertion stamp
    under ``_IDEMPOTENCY_STORED_AT_KEY``.

      1. TTL sweep: drop every record whose age ``now - stored_at`` exceeds
         ``ttl_s``. The DB-backed row for the same key has the SAME 24h TTL
         and is itself expired, so retaining the in-memory copy is pure leak
         (a replay past the TTL re-executes rather than returning stale
         cache). A record missing the stamp (e.g. a record hydrated from the
         DB before stamping) is treated as just-inserted (age 0) so it is
         never dropped by the sweep.
      2. Size cap: if more than ``max_entries`` records survive the TTL
         sweep, evict the OLDEST (smallest ``stored_at``) records until the
         cap holds. This bounds memory even for a client that streams many
         distinct keys inside the TTL window. Records missing a stamp sort
         as newest (treated as age 0) so a just-inserted record survives.

    Empty per-surface dicts are removed so the outer map does not retain
    empty surface shells.
    """

    def _stored_at(record: dict[str, Any]) -> float:
        raw = record.get(_IDEMPOTENCY_STORED_AT_KEY)
        if isinstance(raw, int | float):
            return float(raw)
        # Missing/garbage stamp: treat as just-inserted so it is neither
        # swept by the TTL pass nor preferentially evicted by the cap.
        return now

    # (1) TTL sweep.
    for surface in list(store.keys()):
        per_surface = store[surface]
        expired_keys = [
            key
            for key, record in per_surface.items()
            if (now - _stored_at(record)) > ttl_s
        ]
        for key in expired_keys:
            del per_surface[key]
        if not per_surface:
            del store[surface]

    # (2) Size cap: evict oldest-first across all surfaces until at/under cap.
    flat = [
        (surface, key, _stored_at(record))
        for surface, per_surface in store.items()
        for key, record in per_surface.items()
    ]
    overflow = len(flat) - max_entries
    if overflow > 0:
        flat.sort(key=lambda triple: triple[2])  # oldest first
        for surface, key, _stamp in flat[:overflow]:
            bucket = store.get(surface)
            if bucket is not None:
                bucket.pop(key, None)
                if not bucket:
                    del store[surface]


def _hydrated_stored_at(expires_at: Any, now: float) -> float:
    """Insertion stamp for a DB-hydrated idempotency record.

    A row hydrated from ``idempotency_records`` must expire in the in-memory
    cache exactly WHEN its DB row does -- not 24h after hydration -- so the
    in-memory TTL stays consistent with the authoritative DB ``expires_at``.
    Since ``expires_at == stored_at + TTL``, the in-memory stamp is
    ``expires_at - TTL``. Falls back to ``now`` (a fresh stamp) on a missing or
    unparseable ``expires_at`` -- a safe degradation that, at worst, slightly
    delays eviction without serving a past-TTL row (the DB query already
    filtered expired rows).
    """
    if isinstance(expires_at, str) and expires_at:
        try:
            return (
                datetime.fromisoformat(expires_at).timestamp()
                - IDEMPOTENCY_RECORD_TTL_S
            )
        except ValueError:
            return now
    return now


# Fields appended to an evidence-bundle record AFTER its canonical digest
# was computed (see the POST /v1/evidence-bundles create handler). The
# digest is taken over the record EXCLUDING these mutable/derived/alias
# fields, so the integrity check at /verify must exclude the same set to
# reconstruct the original canonical bytes (VAL-CRYPTO-007).
_EVIDENCE_DIGEST_EXCLUDED_FIELDS: frozenset[str] = frozenset(
    {
        "bundle_digest",
        "claims_count",
        "state",
        "bundle_id",
        "digest",
        "scope_kind",
    }
)


def _recompute_bundle_digest(record: dict[str, Any]) -> str | None:
    """Recompute the canonical digest of the CURRENT live bundle record.

    VAL-CRYPTO-007 fix: the prior /verify implementation re-hashed the
    immutable stored blob whose hash IS the recorded digest -- a tautology
    that can never detect record tampering. Instead, re-serialize the
    current record (excluding the mutable digest/claims_count/state and the
    legacy alias fields that were added after the digest was computed) with
    the exact canonicalization used at create time, so a divergence between
    the live record and its claimed digest is detected.

    Returns the ``sha256-<hex>`` wire form, or ``None`` if the record is
    not a mapping.
    """
    if not isinstance(record, dict):
        return None
    reduced = {
        k: v
        for k, v in record.items()
        if k not in _EVIDENCE_DIGEST_EXCLUDED_FIELDS
    }
    canonical = json.dumps(
        reduced, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _sha256_canonical(canonical)


async def _parse_verify_body(request: Request) -> dict[str, Any]:
    """Parse the optional JSON body of the public /verify endpoint.

    The endpoint is callable with no body at all. Any non-object or
    malformed body degrades to an empty mapping so the verification path is
    deterministic regardless of caller input.
    """
    try:
        raw = await request.body()
        body = json.loads(raw) if raw else {}
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(body, dict):
        return {}
    return body


# Audit fix (2026-05-17 P0): legacy X-Relay-Scopes header gate. The
# header was treated as authoritative without any cryptographic binding,
# which is an auth-bypass risk. The header is now disabled by default
# and only honoured when ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER``
# is truthy. Existing W2.x tests opt-in via the env var.
_LEGACY_SCOPE_HEADER_ENV: str = "RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER"


def _legacy_scope_header_allowed() -> bool:
    """Return True iff the legacy X-Relay-Scopes header is enabled."""
    raw = os.environ.get(_LEGACY_SCOPE_HEADER_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


# Drain grace window advertised to clients via ``Retry-After``. Matches the
# manifest service.local-sidecar.quiesce_timeout_ms (30000 ms = 30 s).
DRAIN_RETRY_AFTER_S: int = 30

# Sidecar SQLite database filename. Lives under ``${RELAY_HOME}``. W2.2
# only enables WAL on this DB; full schema lands in W2.3+.
SIDECAR_DB_FILENAME: str = "sidecar.db"

# Drain deadline (seconds): the lifespan tear-down waits at most this long
# for in-flight operations to complete before forcing the WAL checkpoint
# and closing connections. Matches the manifest
# service.local-sidecar.quiesce_timeout_ms (30000 ms = 30 s) by default.
# Tests override via ``RELAY_SIDECAR_DRAIN_DEADLINE_S``.
DEFAULT_DRAIN_DEADLINE_S: float = 30.0
DRAIN_DEADLINE_ENV: str = "RELAY_SIDECAR_DRAIN_DEADLINE_S"


def _resolve_drain_deadline_seconds(
    default: float = DEFAULT_DRAIN_DEADLINE_S,
) -> float:
    """Resolve the drain-wait deadline from ``RELAY_SIDECAR_DRAIN_DEADLINE_S``.

    Returns ``default`` when the env var is unset or empty. Raises
    ``ValueError`` on a non-numeric or non-positive override.
    """
    raw = os.environ.get(DRAIN_DEADLINE_ENV, "").strip()
    if not raw:
        return float(default)
    parsed = float(raw)
    if parsed <= 0.0:
        raise ValueError(
            f"{DRAIN_DEADLINE_ENV} must be a positive float; got {raw!r}"
        )
    return parsed

# Module-level test counter. Every ``httpx.AsyncClient.__init__`` call
# through ``build_runtime_app`` increments this; VAL-W2-013 asserts the
# value is exactly 1 after N=50 outbound requests. Tests reset it via
# ``reset_async_client_init_counter()``.
_async_client_init_counter: int = 0


def reset_async_client_init_counter() -> None:
    """Reset the test counter to 0. Test-only entrypoint."""
    global _async_client_init_counter
    _async_client_init_counter = 0


def get_async_client_init_count() -> int:
    """Return the current count of httpx.AsyncClient instantiations."""
    return _async_client_init_counter


def _make_async_client() -> httpx.AsyncClient:
    """Construct the singleton ``httpx.AsyncClient`` and bump the counter.

    Centralising construction here makes the VAL-W2-013 counter exact:
    each call to ``build_runtime_app`` produces exactly one client, and
    callers obtain the client via ``app.state.http_client`` rather than
    re-instantiating.
    """
    global _async_client_init_counter
    client = httpx.AsyncClient(
        # Modest defaults: the sidecar is local-only and proxies to the
        # hosted control plane / model providers. Aggressive timeouts here
        # would surface latency issues clearly during W3+ ingest work.
        timeout=httpx.Timeout(30.0, connect=10.0),
        # No follow_redirects: providers should return non-redirected.
        follow_redirects=False,
    )
    _async_client_init_counter += 1
    return client


@dataclass
class RuntimeState:
    """Per-process runtime state attached to ``app.state``.

    Attributes:
        health: The W2.1 ``HealthState`` (bearer token, nonce store, port).
        sqlite_path: Absolute path to ``sidecar.db``.
        bound_at_monotonic: ``loop.time()`` value captured at the end of
            lifespan startup, just before ``yield``. Used by VAL-W2-014
            to prove ``port_bind_timestamp <= first_request_timestamp``.
        draining: Toggled to True in the lifespan ``finally`` block when
            uvicorn invokes shutdown on SIGTERM. The DrainMiddleware
            checks this flag and returns 503 + Retry-After for new
            requests once set.
        database: The W2.3 ``SidecarDatabase`` owning the writer + reader
            connections and the single-writer queue. None before lifespan
            startup; populated in ``lifespan`` and closed in shutdown.
        reader_count: Number of reader connections to open. Default
            ``DEFAULT_READER_COUNT`` (2) per VAL-W2-023 (>= 2 connections).
        lockfile_path: Path to ``${RELAY_HOME}/sidecar.lock``. The lifespan
            tear-down clears this file via ``local_atomic_file_write`` on
            graceful shutdown (VAL-W2-047). Force-stop intentionally
            leaves it untouched so the next ``acquire_or_attach`` observes
            STALE_PID and clears via the spawn path.
        quiesce: W2.6 quiesce-protocol state (in-flight tracker, force-stop
            flag, idle-shutdown trigger). Populated in lifespan startup;
            consumed by the lifespan tear-down + the SIGUSR1 handler.
        idle_timeout_seconds: Resolved idle-window length (seconds). The
            lifespan idle-countdown task uses this as the
            ``asyncio.wait_for`` timeout when waiting on
            ``quiesce.tracker.idle_event``. None until lifespan startup
            resolves the env override; see :func:`resolve_idle_timeout_seconds`.
        drain_deadline_seconds: Upper bound on how long the lifespan
            tear-down waits for in-flight operations to complete before
            forcing the WAL checkpoint. Resolved once at lifespan startup
            via :func:`_resolve_drain_deadline_seconds`.
    """

    health: HealthState
    sqlite_path: Path
    bound_at_monotonic: float | None = None
    draining: bool = False
    database: SidecarDatabase | None = None
    reader_count: int = DEFAULT_READER_COUNT
    lockfile_path: Path | None = None
    quiesce: QuiesceState = field(default_factory=QuiesceState)
    idle_timeout_seconds: float | None = None
    drain_deadline_seconds: float | None = None
    # W3 manifest enforcement (CLAUDE.md keystone invariant 3, spec F line 4100).
    # Seeded at lifespan startup from the operation manifest; the new
    # ingest routes (/v1/ingest/runs, /v1/ingest/spans:batch) look up
    # declared command_hashes via this registry before accepting any
    # submission. Empty in production until seeded; tests register
    # entries directly.
    manifest_registry: ManifestRegistry = field(default_factory=ManifestRegistry)
    # V2M02 w2.3/w2.4: in-memory replay + eval registries. The hosted
    # control-plane writers for replay_cases / replay_fixtures /
    # replay_results / eval_datasets / eval_runs are out-of-scope for the
    # OSS sidecar at M02 (they land in later milestones). The HTTP
    # surface lands now so SDKs + downstream clients have stable
    # endpoints to call; payloads round-trip through these registries to
    # preserve canonical response shapes per spec B.6 lines 3459-3468.
    # ALL writes go through these in-process containers; ALL writers
    # stamp ``written_by = "control_plane"`` (keystone invariant #1).
    replay_cases: dict[str, dict[str, Any]] = field(default_factory=dict)
    replay_fixtures: dict[str, list[dict[str, Any]]] = field(
        default_factory=dict
    )
    replay_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    eval_datasets: dict[str, dict[str, Any]] = field(default_factory=dict)
    eval_runs: dict[str, dict[str, Any]] = field(default_factory=dict)
    # V2M02 w2.5/w2.6/w2.7/w2.8: in-memory registries for gates,
    # gate_policies, gate_decision_drafts, gate_decisions, gate_rounds,
    # evidence_bundles, manifests + manifest versions, and
    # redaction_policies. The local sidecar persists these via direct DB
    # writer connection AND mirrors them in-memory so reads avoid the
    # writer queue. All writers stamp ``written_by = "control_plane"``
    # (keystone invariant #1) and ``decided_by = "gate_engine"`` for
    # gate_decisions (database CHECK constraint enforces).
    gates: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_drafts: dict[str, dict[str, Any]] = field(default_factory=dict)
    # gate_drafts_active maps (gate_id, round) -> draft_id so the second
    # POST from a different worker_id detects a conflict (RELAY-GATE-014).
    gate_drafts_active: dict[tuple[str, int], dict[str, Any]] = field(
        default_factory=dict
    )
    gate_decisions: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_rounds: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    evidence_bundles: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_bundle_blobs: dict[str, bytes] = field(default_factory=dict)
    manifests: dict[str, dict[str, Any]] = field(default_factory=dict)
    manifest_version_bodies: dict[tuple[str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    redaction_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    # W2.9 idempotency: surface -> {key -> (request_digest, response)}.
    idempotency_store: dict[str, dict[str, dict[str, Any]]] = field(
        default_factory=dict
    )
    # VAL-IDEMP-002: in-flight reservation registry closing the
    # check-then-store TOCTOU window. Maps (surface, key) -> a reservation
    # record {"event": asyncio.Event, "owner": asyncio.Task | None,
    # "digest": str} inserted SYNCHRONOUSLY on the cache-miss path of
    # _check_idempotency (no ``await`` between the miss check and the
    # insert, so the insert is atomic within the single-threaded asyncio
    # event loop). A second concurrent request for the same (surface, key)
    # observes the reservation, waits on the event for the winner to store,
    # then replays the stored response -- it never executes the handler
    # body a second time. The winner finalizes the reservation in
    # _store_idempotency (sets the event, removes the record). The scope of
    # this mechanism is INTRA-PROCESS: it closes the asyncio race within a
    # single sidecar process. The cross-process backstop remains the
    # DB-backed idempotency_records UNIQUE primary key written through
    # ``transactional_db_write_raw`` in _store_idempotency.
    idempotency_inflight: dict[tuple[str, str], dict[str, Any]] = field(
        default_factory=dict
    )
    # VAL-IDEMP-002 (test determinism seam): an OPTIONAL async hook fired
    # inside _check_idempotency at the EXACT check-then-reserve TOCTOU
    # window -- after the cache-miss lookup returns None and BEFORE the
    # synchronous reservation install. Production leaves this ``None`` (the
    # hook is never awaited, so there is zero behavioral or performance
    # impact on the real path). Concurrency tests install a hook (e.g. an
    # ``asyncio.Barrier(2)`` rendezvous) so BOTH racing same-(surface, key)
    # coroutines are provably in-flight at the reservation window before
    # either proceeds -- making the race the reservation closes deterministic
    # under any event-loop scheduling. The hook is passed the
    # ``(surface, key)`` reservation tuple. Any exception it raises propagates
    # to the caller (so a misbehaving test fails loudly rather than silently
    # skipping the rendezvous).
    idempotency_reserve_hook: (
        Callable[[tuple[str, str]], Awaitable[None]] | None
    ) = None
    # W2.10 rate-limit buckets. bucket_key -> (window_start_epoch, count).
    rate_limit_buckets: dict[str, tuple[int, int]] = field(default_factory=dict)
    # W2.11 token registry. token -> {scopes: set[str], project_id: str}.
    # Seeded by tests; the default OSS profile has no registered tokens
    # (clients use ``X-Relay-Scopes`` for the legacy header path).
    registered_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """FastAPI lifespan: init SQLite WAL + httpx client BEFORE serving;
    drain + WAL-checkpoint + lockfile-clear on shutdown (W2.6 quiesce).

    Order matters for VAL-W2-014: the listener does not begin accepting
    connections until ``yield``. Uvicorn calls the lifespan startup
    portion, awaits its completion, THEN binds the port. Therefore every
    PRAGMA executed here completes strictly before the first request.

    Startup adds W2.6 quiesce wiring:
      - Construct an :class:`InflightTracker` and bind it to
        ``state.quiesce.tracker`` so route handlers can register
        long-running operations.
      - Resolve the idle-timeout window from
        ``RELAY_SIDECAR_IDLE_TIMEOUT_S`` (default 60s) and the drain
        deadline from ``RELAY_SIDECAR_DRAIN_DEADLINE_S`` (default 30s).
      - Spawn the idle-countdown task that calls
        ``await asyncio.wait_for(tracker.idle_event.wait(), timeout=IDLE)``
        in a loop; on a TimeoutError that fires while the event is still
        set (i.e. truly idle), it triggers graceful shutdown by setting
        ``state.quiesce.idle_shutdown_triggered = True`` and
        ``server.should_exit = True`` (when running under uvicorn).
      - Install a SIGUSR1 handler (POSIX) that triggers the force-stop
        path: emit a ``sidecar.forced_stop`` event_log_entries row BEFORE
        cancelling in-flight transactions, then mark
        ``state.quiesce.force_stop_requested = True`` so the lifespan
        tear-down skips the graceful WAL checkpoint AND the lockfile
        clear.

    Shutdown sequence (graceful path; force-stop branch noted inline):
      1. ``state.draining = True`` so DrainMiddleware now answers 503.
      2. Brief asyncio.sleep(0) so concurrent middleware sees the flag.
      3. Cancel the idle-countdown task (its await will raise
         CancelledError; we suppress it).
      4. Wait for ``tracker.idle_event`` with deadline =
         ``state.drain_deadline_seconds``. Force-stop path skips the
         wait (operations have already been signalled by the SIGUSR1
         handler).
      5. Run ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer
         connection BEFORE closing aiosqlite. SKIPPED on force-stop.
      6. Close the SidecarDatabase (cancels writer task, closes all
         connections).
      7. Close the shared ``httpx.AsyncClient``.
      8. Clear the lockfile via ``local_atomic_file_write(path, b"")``.
         SKIPPED on force-stop so the next spawn classifies STALE_PID.

    The fundamental ordering invariant for VAL-W2-045 is:
    WAL CHECKPOINT comes BEFORE database close which comes BEFORE
    lockfile clear. This guarantees the WAL file is truncated to size
    zero before any subsequent reader observes the database file.
    """
    state: RuntimeState = app.state.runtime

    # ---- Startup ----
    # 0. STARTUP RECOVERY (VAL-W2-049, -050, -051, -054, -055).
    #    Probe ``state.sqlite_path`` BEFORE creating SidecarDatabase or
    #    opening any aiosqlite connection. ``recover_or_refuse`` runs the
    #    fast-path quick_check (<= 2s budget) -> slow-path integrity_check
    #    -> WAL replay -> schema_version compare. On corruption, schema
    #    mismatch, or WAL-replay failure, it calls
    #    ``exit_with_structured_error`` which writes the structured JSON
    #    envelope to stderr and ``sys.exit``s with the appropriate code (3,
    #    5). The synchronous call is intentional: we MUST refuse to open
    #    the database before the migration runner blindly stamps a
    #    pristine schema on top of a corrupt file.
    #
    #    For production exit-code propagation through uvicorn, the
    #    ``run_uvicorn`` entrypoint runs this same probe BEFORE entering
    #    the asyncio loop -- a SystemExit raised from inside the lifespan
    #    coroutine is caught by uvicorn and would not preserve the exit
    #    code. The lifespan-side call here is the defensive backstop for
    #    callers that build the runtime app directly (tests +
    #    in-process embedders) and rely on the recovery contract.
    recover_or_refuse(state.sqlite_path)
    # 1. SQLite database manager (writer + N readers, WAL + busy_timeout
    #    + migrations + single-writer queue). Per VAL-W2-014 ALL of this
    #    completes BEFORE the listener binds the port. Per VAL-W2-017/-018
    #    every connection runs PRAGMA journal_mode=WAL + busy_timeout=5000.
    state.database = SidecarDatabase(
        db_path=state.sqlite_path,
        reader_count=state.reader_count,
    )
    await state.database.open()
    # Register the database as the process-wide instance backing the
    # ``transactional_db_write`` module-level primitive.
    set_active_database(state.database)
    # 2. Single shared httpx.AsyncClient.
    app.state.http_client = _make_async_client()
    # 3. W2.6 quiesce wiring. The tracker lives on the QuiesceState so
    #    route handlers can reach it via app.state.runtime.quiesce.tracker
    #    (no module-level globals; one tracker per RuntimeState).
    tracker = InflightTracker()
    state.quiesce.tracker = tracker
    # Resolve env-overrideable timing windows once at startup so they
    # are immutable for the lifespan duration.
    state.idle_timeout_seconds = resolve_idle_timeout_seconds()
    state.drain_deadline_seconds = _resolve_drain_deadline_seconds()
    # 4. Idle-countdown task: triggers graceful shutdown when the sidecar
    #    has been continuously idle for state.idle_timeout_seconds. We
    #    capture a reference to the task on app.state so the lifespan
    #    tear-down can cancel it.
    app.state.idle_countdown_task = asyncio.create_task(
        _idle_countdown_loop(app, state),
        name="sidecar-idle-countdown",
    )
    # 5. SIGUSR1 force-stop handler. POSIX only; on Windows the helper
    #    falls back to SIGTERM (graceful drain only). We install via
    #    add_signal_handler so the handler runs on the loop thread (the
    #    only thread that may touch asyncio primitives).
    _install_force_stop_signal_handler(app, state)
    # 6. Record bind-ready timestamp. Uvicorn binds AFTER startup yields,
    #    so the next ``time.monotonic()`` (taken from the handler side) is
    #    strictly greater than this value.
    loop = asyncio.get_running_loop()
    state.bound_at_monotonic = loop.time()

    try:
        yield
    finally:
        # ---- Shutdown ----
        # Toggle drain BEFORE closing anything so any concurrent handler
        # sees the flag on its next entry to the middleware.
        state.draining = True
        # Brief yield to let scheduled tasks observe the flag.
        await asyncio.sleep(0)

        force_stop = state.quiesce.force_stop_requested

        # Cancel the idle-countdown task. Its CancelledError is benign;
        # we suppress and await it so the task slot is reaped.
        idle_task = getattr(app.state, "idle_countdown_task", None)
        if idle_task is not None and not idle_task.done():
            idle_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await idle_task

        # Uninstall the SIGUSR1 handler so a re-run of the lifespan in
        # the same process (rare, mostly tests) does not pile up handlers.
        _uninstall_force_stop_signal_handler()

        # On the graceful path (no force-stop), wait for in-flight
        # operations to complete up to the drain deadline. Force-stop
        # has ALREADY emitted its forensic event_log row in the SIGUSR1
        # handler and SHOULD NOT block on the in-flight tracker (the
        # operations have been notified that they are being killed).
        if not force_stop:
            tracker = state.quiesce.tracker
            deadline = state.drain_deadline_seconds or DEFAULT_DRAIN_DEADLINE_S
            if tracker is not None:
                with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
                    await asyncio.wait_for(
                        tracker.idle_event.wait(), timeout=deadline
                    )

        # WAL CHECKPOINT (VAL-W2-045) -- on graceful path only. Forced
        # stop deliberately skips so the WAL retains uncommitted bytes
        # and the next startup runs WAL recovery (covered by W2.7).
        #
        # W2.7 VAL-W2-053: detect a failed checkpoint (busy != 0 or raised
        # exception) and surface it. We invoke BOTH helpers: the existing
        # ``_wal_checkpoint_truncate`` (kept for VAL-W2-045's monkeypatch
        # surface) AND the new ``_wal_checkpoint_truncate_with_status``
        # whose return value the lifespan inspects for busy-flag failures.
        if not force_stop and state.database is not None:
            await _wal_checkpoint_truncate(state.database)
            ok, reason = await _wal_checkpoint_truncate_with_status(
                state.database
            )
            if not ok:
                state.quiesce.wal_checkpoint_failed = True
                state.quiesce.wal_checkpoint_failure_reason = reason
                # Per VAL-W2-053: emit the structured envelope to stderr
                # so subprocess-based runs observe the error AND preserve
                # the WAL file (do NOT delete the WAL or close
                # connections any more aggressively than the normal path).
                # The exit code 6 is signalled via uvicorn's should_exit
                # when running under uvicorn; in-process tests assert
                # the flag on state.quiesce instead.
                _surface_wal_checkpoint_failure(app, state, reason)

        # Close the SQLite database manager (cancels the writer task,
        # drains pending requests, closes all connections). Clear the
        # module-level registration so a subsequent
        # ``transactional_db_write`` call surfaces a clean RuntimeError
        # rather than touching a closed connection.
        #
        # W2.7 VAL-W2-053: SQLite's libsqlite removes the WAL file on
        # the LAST connection close UNLESS uncheckpointed frames remain
        # AND the file was opened with FCNTL_PERSIST_WAL. aiosqlite does
        # not expose a portable PERSIST_WAL switch, so we side-step the
        # ambiguity by copying the WAL bytes to a sentinel preserved
        # path BEFORE closing connections when checkpoint failed. The
        # next-startup recovery path (recovery.py) inspects both
        # ``<db>-wal`` AND ``<db>-wal.preserved``; presence of either
        # triggers the WAL replay branch.
        wal_cp_failed = state.quiesce.wal_checkpoint_failed
        if wal_cp_failed and state.database is not None:
            _preserve_wal_for_next_startup(state.sqlite_path)
        if state.database is not None:
            await state.database.close()
            state.database = None
        set_active_database(None)

        # Close the httpx client. ``aclose`` cancels in-flight outbound
        # requests gracefully.
        client: httpx.AsyncClient | None = getattr(app.state, "http_client", None)
        if client is not None:
            await client.aclose()

        # CLEAR LOCKFILE (VAL-W2-047) -- on graceful path only. Force-stop
        # AND wal-checkpoint-failure paths both leave it in place so the
        # next acquire_or_attach observes STALE_PID and clears via the
        # spawn path.
        if not force_stop and not wal_cp_failed and state.lockfile_path is not None:
            with contextlib.suppress(FileNotFoundError, OSError):
                local_atomic_file_write(
                    state.lockfile_path, b"", mode=0o600
                )


async def _wal_checkpoint_truncate(database: SidecarDatabase) -> None:
    """Run ``PRAGMA wal_checkpoint(TRUNCATE)`` on the writer connection.

    Per VAL-W2-045 the WAL file MUST be truncated to size zero before
    aiosqlite connections close so a subsequent reader observes a
    fully-checkpointed database file. The TRUNCATE variant blocks until
    every reader has caught up to the latest commit AND truncates the
    WAL to zero bytes (vs PASSIVE which is a no-op on contention and
    FULL which checkpoints without truncating).

    The function borrows the writer connection via the same internal
    accessor used by the W2.4 state engine (``database._writer``). We
    do NOT route through ``transactional_db_write`` because PRAGMA is
    a connection-scoped meta-statement, not a state-mutation row write.

    Errors are surfaced rather than swallowed: a failed checkpoint is
    a real problem and the lifespan tear-down should observe it. The
    caller wraps the call in a contextlib.suppress only on tear-down
    paths where the database is already half-closed.
    """
    conn = database._writer
    if conn is None:
        return
    # PRAGMA wal_checkpoint returns a row (busy, log_size, frames_checkpointed).
    # We don't inspect the values here; aiosqlite consumes them and the
    # WAL file size on disk is the observable test artifact.
    async with conn.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
        await cur.fetchall()
    # Commit any implicit transaction the PRAGMA opened (defensive).
    with contextlib.suppress(Exception):
        await conn.commit()


def _preserve_wal_for_next_startup(db_path: Path) -> None:
    """W2.7 VAL-W2-053: copy ``<db>-wal`` to a sentinel preserved path.

    SQLite removes ``<db>-wal`` on the last connection close (no
    standard PRAGMA exposes ``SQLITE_FCNTL_PERSIST_WAL``). To honour
    VAL-W2-053's "preserve the WAL" contract we copy the WAL bytes
    to ``<db>-wal.preserved`` BEFORE the close call removes them. The
    next-startup recovery path inspects both names.

    Best-effort: failure to copy is non-fatal. Without the preserve
    copy, the failed-checkpoint warning is still emitted on stderr;
    only the next-startup replay loses the in-flight frames.
    """
    wal_path = db_path.parent / (db_path.name + "-wal")
    if not wal_path.exists():
        return
    try:
        body = wal_path.read_bytes()
    except OSError:
        return
    if not body:
        return
    preserved = wal_path.parent / (wal_path.name + ".preserved")
    with contextlib.suppress(OSError):
        local_atomic_file_write(preserved, body, mode=0o600)


def _surface_wal_checkpoint_failure(
    app: FastAPI, state: RuntimeState, reason: str
) -> None:
    """W2.7 VAL-W2-053: emit structured envelope + signal exit code 6.

    The lifespan tear-down calls this when
    ``_wal_checkpoint_truncate_with_status`` reports failure. Behaviour:

      - Mark ``state.quiesce.wal_checkpoint_failed = True`` (the caller
        already does this; we re-assert defensively).
      - Emit the JSON envelope to stderr (subprocess tests parse it).
      - When running under uvicorn (``app.state.uvicorn_server`` set),
        set ``server.should_exit = True`` so the process exits with the
        configured code on the next loop iteration. Direct sys.exit(6)
        would crash in-process tests; uvicorn's should_exit path lets
        the loop unwind cleanly.

    Exit code 6 itself is enforced by the CLI entrypoint (W5) which
    inspects ``state.quiesce.wal_checkpoint_failed`` after the lifespan
    exits and calls ``sys.exit(6)`` accordingly. For pure-asgi tests the
    flag on ``state.quiesce`` is the observable evidence.
    """
    from .errors import (
        RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
        RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
    )
    from .recovery import (
        EXIT_CODE_WAL_CHECKPOINT_FAILED,
        _wal_size,
    )

    state.quiesce.wal_checkpoint_failed = True
    state.quiesce.wal_checkpoint_failure_reason = reason
    db_path = state.sqlite_path
    wal_path = db_path.parent / (db_path.name + "-wal")
    envelope = {
        "code": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED_CODE,
        "error_class": RELAY_SIDECAR_WAL_CHECKPOINT_FAILED,
        "exit_code": EXIT_CODE_WAL_CHECKPOINT_FAILED,
        "message": (
            "sidecar shutdown: PRAGMA wal_checkpoint(TRUNCATE) failed; "
            "WAL preserved for next-startup recovery"
        ),
        "details": {
            "db_path": str(db_path),
            "wal_path": str(wal_path),
            "wal_present": wal_path.exists(),
            "wal_size_bytes": _wal_size(db_path),
            "underlying_error": reason,
        },
    }
    line = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    import sys as _sys

    _sys.stderr.write(line + "\n")
    _sys.stderr.flush()
    server = getattr(app.state, "uvicorn_server", None)
    if server is not None:
        server.should_exit = True


async def _wal_checkpoint_truncate_with_status(
    database: SidecarDatabase,
) -> tuple[bool, str]:
    """W2.7 VAL-W2-053: run TRUNCATE checkpoint and report success.

    Returns ``(success, reason)``:

      - ``(True, "")`` -- the PRAGMA returned ``(busy=0, ...)`` and no
        exception was raised. The WAL has been truncated to size 0 (or
        is empty pending the final connection close).
      - ``(False, <reason>)`` -- the PRAGMA returned ``busy=1`` (a
        reader held an old snapshot beyond the busy_timeout window) OR
        raised an exception. ``reason`` carries the failure detail.

    Why TWO helpers: the original ``_wal_checkpoint_truncate`` is used
    by VAL-W2-045 tests that monkeypatch the function name and inspect
    the call order. Adding the status detection there would change the
    return type and break those tests. The new helper wraps the same
    PRAGMA but with a (success, reason) return contract.
    """
    conn = database._writer
    if conn is None:
        return (True, "")
    try:
        async with conn.execute("PRAGMA wal_checkpoint(TRUNCATE)") as cur:
            # aiosqlite types fetchall() as Iterable[Row]; at runtime it
            # returns a concrete list. Materialize for indexing/len below.
            rows = list(await cur.fetchall())
    except Exception as e:  # noqa: BLE001
        return (False, f"{type(e).__name__}: {e}")
    with contextlib.suppress(Exception):
        await conn.commit()
    # PRAGMA wal_checkpoint(TRUNCATE) returns a single row
    # ``(busy, log_size, frames_checkpointed)``. busy=1 means SQLite
    # could not acquire the writer/reader lock to truncate. busy=0
    # means the truncate succeeded. We treat busy != 0 as failure.
    if not rows:
        return (True, "")
    first = rows[0]
    try:
        busy_flag = int(first[0])
    except (TypeError, ValueError, IndexError):
        return (True, "")
    if busy_flag != 0:
        return (
            False,
            (
                f"PRAGMA wal_checkpoint(TRUNCATE) returned busy={busy_flag}; "
                f"a reader holds an old snapshot beyond the busy_timeout window"
            ),
        )
    return (True, "")


# Module-level reference to the loop slot we installed our SIGUSR1
# handler on, used by _uninstall_force_stop_signal_handler. We track
# the loop instead of the handler because asyncio.add_signal_handler
# overwrites any prior registration on (loop, signal); to "uninstall"
# we call remove_signal_handler on the same (loop, signal) pair.
_signal_handler_loop: asyncio.AbstractEventLoop | None = None
_signal_handler_signum: int | None = None


def _install_force_stop_signal_handler(app: FastAPI, state: RuntimeState) -> None:
    """Install a loop-bound SIGUSR1 handler that triggers force-stop.

    POSIX only. On Windows ``loop.add_signal_handler`` is unavailable;
    the handler is silently skipped (force-stop on Windows degrades to
    SIGTERM = graceful drain).
    """
    global _signal_handler_loop, _signal_handler_signum
    if os.name == "nt":  # pragma: no cover (Windows-only)
        return
    loop = asyncio.get_running_loop()
    signum = force_stop_signal_number()
    try:
        loop.add_signal_handler(
            signum, lambda: _on_force_stop(app, state, "signal")
        )
    except (NotImplementedError, ValueError, RuntimeError):
        # Common cases that legitimately skip signal-handler installation
        # without failing startup:
        #  - NotImplementedError: certain custom loops do not implement
        #    add_signal_handler at all (older uvloop versions).
        #  - ValueError: signum is invalid or unsupported on this platform.
        #  - RuntimeError: "set_wakeup_fd only works in main thread of
        #    the main interpreter" -- pytest-asyncio runs the test loop
        #    on the main thread typically, but some test fixtures (and
        #    pytest-xdist worker processes) install loops on worker
        #    threads. The force-stop API still works via the
        #    request_force_stop helper for in-process tests; only the
        #    OS-level SIGUSR1 entry is unavailable on those loops.
        return
    _signal_handler_loop = loop
    _signal_handler_signum = signum


def _uninstall_force_stop_signal_handler() -> None:
    """Remove the previously-installed SIGUSR1 handler, if any."""
    global _signal_handler_loop, _signal_handler_signum
    if _signal_handler_loop is None or _signal_handler_signum is None:
        return
    if os.name == "nt":  # pragma: no cover
        return
    with contextlib.suppress(Exception):
        _signal_handler_loop.remove_signal_handler(_signal_handler_signum)
    _signal_handler_loop = None
    _signal_handler_signum = None


def _on_force_stop(app: FastAPI, state: RuntimeState, reason: str) -> None:
    """Loop-bound force-stop entry point. Schedules the async forced-stop work.

    Invoked from the loop's signal-handler slot OR from
    :func:`request_force_stop` (in-process tests). Idempotent: only the
    FIRST invocation schedules the async task; subsequent calls no-op.
    """
    if state.quiesce.force_stop_requested:
        return
    state.quiesce.force_stop_requested = True
    state.quiesce.force_stop_reason = reason
    state.draining = True
    # Schedule the async forced-stop work (event_log row + server.exit).
    asyncio.get_running_loop().create_task(
        _execute_forced_stop(app, state),
        name="sidecar-forced-stop",
    )


async def _execute_forced_stop(app: FastAPI, state: RuntimeState) -> None:
    """Emit ``sidecar.forced_stop`` event_log row, then signal exit.

    Per VAL-W2-046: the row MUST be emitted BEFORE the in-flight
    transaction is killed. Per CLAUDE.md keystone invariant #8 (atomic
    persistence -- four primitives only), the row is written through
    ``transactional_db_write`` (atomic primitive #2). The primitive
    enqueues onto the SidecarDatabase writer queue, which serialises
    behind any in-flight CAS transaction holding the writer connection;
    the queued write completes once that transaction commits or rolls
    back. The CAS transaction, if any, is then ROLLBACK-ed by the
    lifespan tear-down's ``database.close()`` which cancels the writer
    task (any pending future is failed via the W2.3 close path).

    History: an earlier implementation opened a separate short-lived
    aiosqlite (db-connect) handle and INSERTed directly, justifying it
    as the "one place" outside the four primitives. That violated
    keystone #8. Routing through ``transactional_db_write`` is correct
    because:

      - The CAS path holds ``database._state_engine_writer_lock`` (an
        asyncio.Lock among CAS callers), NOT the queue itself. The
        queue's writer task and the CAS path SHARE the underlying
        ``database._writer`` connection; SQLite-level serialisation
        across them is exactly what we want.
      - The forced_stop event is always emitted from a fresh asyncio
        task scheduled by ``_on_force_stop`` -- no awaiter is blocked on
        the queued write completing, so there is no opportunity for
        deadlock.

    Idempotent: the function checks ``_force_stop_row_written`` to
    avoid double-writing on multiple invocations.
    """
    if getattr(state.quiesce, "_force_stop_row_written", False):
        return
    db_path = state.sqlite_path
    if not db_path.exists() or state.database is None:
        # Database file never materialised OR database manager not
        # registered (lifespan startup failed before DB open). Nothing
        # to record; mark and proceed to the exit signal.
        state.quiesce._force_stop_row_written = True  # type: ignore[attr-defined]
        server = getattr(app.state, "uvicorn_server", None)
        if server is not None:
            server.should_exit = True
        return
    event_id = str(uuid.uuid4())
    occurred_at = (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    payload = {
        "reason": state.quiesce.force_stop_reason or "signal",
        "in_flight_count": (
            state.quiesce.tracker.in_flight_count
            if state.quiesce.tracker is not None
            else 0
        ),
        "in_flight_descriptions": (
            state.quiesce.tracker.in_flight_descriptions()
            if state.quiesce.tracker is not None
            else []
        ),
    }
    # Sentinel project id matches the W2.3 db.py:_flush_retry_buffer
    # convention for sidecar-internal observability rows.
    sentinel_project_id = "00000000-0000-0000-0000-000000000000"
    sentinel_scope_id = "00000000-0000-0000-0000-000000000000"
    row: dict[str, Any] = {
        "event_id": event_id,
        "schema_version": "relay.event_log_entry.v1",
        "project_id": sentinel_project_id,
        "scope_type": "other",
        "scope_id": sentinel_scope_id,
        "event_type": "sidecar.forced_stop",
        "actor_kind": "control_plane",
        "actor_id": None,
        "manifest_commit_hash": None,
        "payload": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "occurred_at": occurred_at,
        "event_kind": "sidecar_forced_stop",
    }
    # Atomic primitive #2 -- the only sanctioned write path per
    # keystone #8. The primitive's busy-retry + backoff loop handles
    # SQLITE_BUSY transparently. Best-effort forensic write: if the
    # writer task has already been cancelled or the budget is exhausted
    # under heavy contention, we proceed with the exit path; the
    # in-process state of state.quiesce.force_stop_* still records the
    # forced-stop intent.
    with contextlib.suppress(Exception):
        await transactional_db_write(
            table="event_log_entries",
            row=row,
            scope_id=sentinel_scope_id,
        )
    # Mark recorded to avoid double-writes on repeat triggers.
    state.quiesce._force_stop_row_written = True  # type: ignore[attr-defined]
    # Signal exit. If running under uvicorn, app.state.uvicorn_server
    # carries the Server instance and we set should_exit; otherwise
    # ASGI tests rely on the in-flight tracker + draining flag alone.
    server = getattr(app.state, "uvicorn_server", None)
    if server is not None:
        server.should_exit = True


def request_force_stop(app: FastAPI, *, reason: str = "api") -> None:
    """In-process force-stop trigger (used by tests and the CLI helper).

    Equivalent to receiving SIGUSR1 from outside the process. Safe to
    call from any coroutine; idempotent.
    """
    state: RuntimeState = app.state.runtime
    _on_force_stop(app, state, reason)


async def _idle_countdown_loop(app: FastAPI, state: RuntimeState) -> None:
    """Idle-countdown task: trigger graceful shutdown when continuously idle.

    Loop:
      1. Await ``tracker.idle_event`` with timeout = idle_timeout_seconds.
      2. If wait_for raises TimeoutError -> the sidecar was idle for the
         entire window. Trigger graceful shutdown.
      3. Otherwise (the await returned because the event is set; we
         observed an idle moment) immediately recheck: if the tracker
         is STILL idle AFTER another idle_timeout_seconds wait, exit.
         Concretely: we re-await with the timeout each iteration; if
         operations come and go we keep looping.

    Cancellation: the lifespan tear-down cancels this task; CancelledError
    unwinds cleanly.
    """
    tracker = state.quiesce.tracker
    if tracker is None:
        return
    timeout = state.idle_timeout_seconds or 60.0
    while True:
        # Wait for the tracker to be idle. If currently idle, this
        # returns immediately (the event is set); otherwise we block
        # until the last in-flight op releases.
        await tracker.idle_event.wait()
        # Now we are idle. Sleep for the full timeout window. If a new
        # operation acquires the tracker mid-sleep, the event will be
        # cleared but our sleep continues; at the END of the sleep we
        # check whether we're still idle. Continuously-idle for the
        # full window -> trigger shutdown.
        try:
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            raise
        if tracker.in_flight_count == 0 and tracker.idle_event.is_set():
            # Truly idle for the full window. Trigger graceful shutdown.
            state.quiesce.idle_shutdown_triggered = True
            state.draining = True
            server = getattr(app.state, "uvicorn_server", None)
            if server is not None:
                server.should_exit = True
            return
        # Otherwise: an op acquired the tracker during the sleep window.
        # Loop and wait for the next idle moment.


class DrainMiddleware:
    """Pure-ASGI middleware: 503 + Retry-After for new requests when draining.

    Why pure-ASGI (not starlette's BaseHTTPMiddleware): the BaseHTTPMiddleware
    runs the wrapped handler in a separate task and surfaces uvicorn
    graceful-shutdown cancellation as HTTP 500 "Internal Server Error" for
    in-flight requests. The pure-ASGI form below sits directly on the
    ASGI receive/send wire so in-flight responses pass through unmodified
    while new requests during drain are short-circuited.

    VAL-W2-015 semantics:
      - HTTP request arrives, draining=False -> pass through to downstream.
      - HTTP request arrives, draining=True  -> 503 + Retry-After.
      - Lifespan / websocket scopes always pass through (drain applies only
        to HTTP requests).
    """

    def __init__(self, app: ASGIApp, runtime: RuntimeState) -> None:
        self.app = app
        self.runtime = runtime

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http" or not self.runtime.draining:
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            status_code=503,
            content={
                "code": "RELAY-SIDECAR-007",
                "error_class": "RELAY-SIDECAR-DRAINING",
                "message": (
                    "sidecar is draining; retry after the advertised window"
                ),
            },
            headers={"Retry-After": str(DRAIN_RETRY_AFTER_S)},
        )
        await response(scope, receive, send)


class _IdempotencyReservationReleaseMiddleware:
    """Pure-ASGI middleware: release a request's pending idempotency
    reservations on completion (VAL-IDEMP-002).

    The idempotency winner records the (surface, key) tuples it reserved on
    the per-request ASGI ``scope`` (see ``_reserve_idempotency_for_request``).
    The success path finalizes the reservation in ``_store_idempotency``;
    this middleware deterministically releases any reservation that is STILL
    pending when the request finishes -- i.e. an aborted winner that took an
    early-return validation path or raised -- so the key cannot wedge a
    later genuine retry. Releasing sets the reservation event (waking any
    loser blocked on it) and removes the reservation from
    ``idempotency_inflight``.

    Pure-ASGI (not BaseHTTPMiddleware) so it shares the exact ``scope`` dict
    the route handler mutates and so the release runs in a ``finally`` on
    EVERY exit path (normal response, early-return, exception)."""

    def __init__(self, app: ASGIApp, release: Callable[[Scope], None]) -> None:
        self.app = app
        self._release = release

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            self._release(scope)


def build_runtime_app(
    *,
    health: HealthState,
    sqlite_path: Path | None = None,
    relay_home_override: Path | None = None,
) -> FastAPI:
    """Build the full asyncio runtime app (W2.2 entrypoint).

    Composes the W2.1 ``build_health_app`` routes (``/health``,
    ``/health/nonce``) with the W2.2 lifespan + drain middleware + the
    diagnostic ``GET /diagnostics/sqlite`` route used by VAL-W2-014.

    Args:
        health: HealthState carrying bearer-token + port + nonce store.
        sqlite_path: Override the SQLite DB path (tests inject a tmpdir).
            Defaults to ``${RELAY_HOME}/sidecar.db``.
        relay_home_override: Override ``${RELAY_HOME}`` discovery.

    Returns:
        A FastAPI app ready for ``uvicorn.run(app, ...)``. The app's
        ``state.runtime`` carries the RuntimeState; ``state.http_client``
        is bound during startup (None before).
    """
    base_home = relay_home_override if relay_home_override is not None else relay_home()
    db_path = (
        sqlite_path if sqlite_path is not None else base_home / SIDECAR_DB_FILENAME
    )
    # W2.6: resolve the lockfile path so the lifespan tear-down can clear
    # it on graceful shutdown (VAL-W2-047). The path is purely advisory
    # at runtime construction time; the spawn-side caller (W5 CLI) is
    # responsible for writing the lockfile. If the file does not exist
    # at tear-down time, the clear is a no-op (FileNotFoundError suppressed).
    #
    # IMPORTANT: when ``sqlite_path`` is explicitly overridden (test
    # injection via tmp_path), derive the lockfile path from the db's
    # parent directory rather than ``relay_home()``. Otherwise tests that
    # forget to monkeypatch RELAY_HOME would clobber the developer's real
    # ~/.relay/sidecar.lock on tear-down. Production (sqlite_path=None)
    # still resolves to ${RELAY_HOME}/sidecar.lock as expected.
    if sqlite_path is not None:
        lockfile_path = db_path.parent / "sidecar.lock"
    else:
        lockfile_path = resolve_lockfile_path(base_home)

    runtime = RuntimeState(
        health=health,
        sqlite_path=db_path,
        lockfile_path=lockfile_path,
    )

    # Construct the FastAPI app with the lifespan attached at __init__.
    # This is critical: starlette captures the lifespan during app
    # construction; mutating ``app.router.lifespan_context`` afterwards
    # does NOT re-bind, and the lifespan will silently never run. We
    # then graft the W2.1 health routes onto the same app via the
    # helper from health.py (instead of constructing a second FastAPI).
    app = FastAPI(title="relay-sidecar", version=__version__, lifespan=lifespan)
    _register_health_routes(app, health)
    # Drain middleware fires for every HTTP request including /health.
    # Pass the runtime explicitly so the middleware does not depend on
    # ``app.state.runtime`` being set (FastAPI builds the middleware stack
    # lazily on first request, so app.state assignment timing matters).
    app.add_middleware(DrainMiddleware, runtime=runtime)

    # VAL-W2-020: SQLITE_BUSY exhaustion surfaces as HTTP 503 with a
    # structured RELAY-SQLITE-BUSY-EXHAUSTED envelope (NOT a bare 500
    # carrying sqlite3.OperationalError).
    @app.exception_handler(RelaySQLiteBusyExhausted)
    async def _sqlite_busy_handler(
        _request: Any, exc: RelaySQLiteBusyExhausted
    ) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_envelope())

    # Attach runtime state.
    app.state.runtime = runtime
    app.state.http_client = None  # populated in lifespan startup

    # W2.4: register the state-engine HTTP boundary.
    # ``POST /v1/state/transition`` validates the three-anchor handoff
    # (VAL-W2-062) BEFORE forwarding to ``compare_and_set_state``. The
    # database_getter closure resolves the active SidecarDatabase from
    # app.state.runtime so the router does not need lifespan visibility.
    def _get_database() -> SidecarDatabase:
        db = runtime.database
        if db is None:
            raise RuntimeError(
                "state-transition handler invoked before lifespan startup "
                "registered SidecarDatabase on app.state.runtime"
            )
        return db

    app.include_router(build_state_router(database_getter=_get_database))

    @app.get("/diagnostics/sqlite")
    async def diagnostics_sqlite() -> dict[str, Any]:
        """Return the current SQLite journal_mode + busy_timeout values.

        Used by VAL-W2-014 to prove ``journal_mode == "wal"`` is in effect
        on a fresh connection AFTER the lifespan startup hook completed.
        The handler opens a short-lived aiosqlite connection per call;
        WAL is a file-level mode so the value is visible from any
        connection to the same DB file.
        """
        async with aiosqlite.connect(str(runtime.sqlite_path)) as conn:
            async with conn.execute("PRAGMA journal_mode") as cur:
                row = await cur.fetchone()
                journal_mode = row[0] if row else None
            async with conn.execute("PRAGMA busy_timeout") as cur:
                row = await cur.fetchone()
                busy_timeout = row[0] if row else None
        return {
            "sqlite": {
                "journal_mode": journal_mode,
                "busy_timeout": busy_timeout,
                "db_path": str(runtime.sqlite_path),
            },
            "sidecar_version": __version__,
        }

    @app.get("/diagnostics/runtime")
    async def diagnostics_runtime() -> dict[str, Any]:
        """Return runtime metadata: bound_at_monotonic, draining, port."""
        loop_time = asyncio.get_running_loop().time()
        return {
            "bound_at_monotonic": runtime.bound_at_monotonic,
            "observed_at_monotonic": loop_time,
            "draining": runtime.draining,
            "port": runtime.health.port,
            "sidecar_version": __version__,
        }

    @app.post("/v1/ingest")
    async def v1_ingest(request: Request) -> dict[str, Any]:
        """W2.6 placeholder ingest endpoint that participates in the
        in-flight tracker so VAL-W2-044 can exercise the drain path.

        The full ingest surface (envelope validation, schema_version
        checking, signed-bundle storage, ack semantics) lands in W3+;
        for W2.6 this handler does the minimum needed to:

          - Acquire the in-flight tracker so the idle-countdown task
            sees a live operation (VAL-W2-043 evidence path).
          - Sleep for the caller-controlled ``hold_ms`` query parameter
            (default 0). Tests use this to keep the tracker busy
            during the SIGTERM -> drain assertion window.
          - Respond with 200 + {"accepted": true, "operation_id": ...}.

        When ``state.draining=True``, the DrainMiddleware short-circuits
        BEFORE this handler runs and returns 503 + Retry-After +
        RELAY-SIDECAR-DRAINING envelope. So the only entry to this
        handler is on the non-draining path.
        """
        # Read hold_ms from query string. starlette Request lookup keeps
        # the handler's signature dependency-free (no FastAPI Query
        # injection needed).
        hold_ms_raw = request.query_params.get("hold_ms", "0")
        try:
            hold_ms = int(hold_ms_raw)
        except (TypeError, ValueError):
            hold_ms = 0
        if hold_ms < 0:
            hold_ms = 0
        tracker = runtime.quiesce.tracker
        if tracker is None:
            # Lifespan startup never bound a tracker; treat as a degraded
            # configuration error and reject. Tests would catch this.
            return {"accepted": False, "reason": "tracker-unbound"}
        async with tracker.acquire(description="ingest") as op:
            if hold_ms > 0:
                await asyncio.sleep(hold_ms / 1000.0)
            return {
                "accepted": True,
                "operation_id": op.operation_id,
                "held_ms": hold_ms,
            }

    # ----------------------------------------------------------------------
    # V2 M02 W2.1 ingest-namespace scope + body-shape helpers
    # (VAL-V2M02-001..009).
    # ----------------------------------------------------------------------
    #
    # Scope-auth is hosted-only in production (tokens issued by the hosted
    # control plane carry their scope set). The OSS sidecar mirrors the
    # surface so SDKs/tests exercise the same code paths. Per
    # contract.md:620-626 ("scopes are seeded onto a local 'dev' token via
    # a fixture"), the OSS profile reads the active scope set from the
    # ``X-Relay-Scopes`` request header (CSV). A missing header behaves
    # identically to an empty scope set: any non-public endpoint with a
    # declared ``scope_required`` returns 403 + RELAY-AUTH-014.

    # V2M02 W2.9 (VAL-V2M02-072..074): every error envelope MUST carry a
    # unique ULID-shaped ``request_id`` and a span-correlated ``trace_id``,
    # plus an optional ``documentation_url`` of the canonical form
    # ``https://relay.epochly.com/docs/errors/<CODE>``. The set of error
    # codes with published docs pages is curated below; the helper omits
    # ``documentation_url`` when the code is not listed.
    _DOC_URL_PUBLISHED_CODES: frozenset[str] = frozenset(
        {
            "RELAY-ING-001", "RELAY-ING-021", "RELAY-ING-031",
            "RELAY-GATE-014", "RELAY-GATE-021", "RELAY-AUTH-001",
            "RELAY-AUTH-014", "RELAY-EVID-001", "RELAY-EVID-014",
            "RELAY-RATE-001", "RELAY-RATE-014", "RELAY-REPLAY-014",
            "RELAY-IDEMPOTENCY-001", "RELAY-PAGE-001",
            "RELAY-PAGE-EXPIRED", "RELAY-NOT-FOUND",
            "RELAY-OSS-HOSTED-ONLY", "RELAY-G-RAW-CAPTURE-DENIED",
            "RELAY-SIDECAR-007",
        }
    )

    def _new_request_id() -> str:
        """Return a ULID-shaped 26-char Crockford base32 id.

        Format: 10-char timestamp (48-bit ms) + 16-char randomness. The
        spec accepts ULIDs in this canonical form; the test regex uses
        ``[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}``.
        """
        alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        ts_ms = int(datetime.now(tz=UTC).timestamp() * 1000) & ((1 << 48) - 1)
        ts_chars: list[str] = []
        x = ts_ms
        for _ in range(10):
            ts_chars.append(alphabet[x & 0x1F])
            x >>= 5
        rand_bytes = os.urandom(10)
        rand_int = int.from_bytes(rand_bytes, "big")
        rand_chars: list[str] = []
        for _ in range(16):
            rand_chars.append(alphabet[rand_int & 0x1F])
            rand_int >>= 5
        return "".join(reversed(ts_chars)) + "".join(reversed(rand_chars))

    def _build_error_envelope(
        *,
        code: str,
        http_status: int,
        message: str,
        blocked_surface: str,
        retry_advice: str = "do_not_retry",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
        documentation_url: str | None = None,
    ) -> dict[str, Any]:
        """Build a spec B.4 canonical error envelope.

        VAL-V2M02-072..074 require ``message``, ``request_id``,
        ``trace_id`` (ULID-shaped), plus an optional ``documentation_url``
        of the form ``https://relay.epochly.com/docs/errors/<CODE>`` for
        codes with published docs. ``request_id`` / ``trace_id`` default
        to fresh ULIDs when callers omit them so existing callers
        retain spec compliance.
        """
        rid = request_id if request_id else _new_request_id()
        tid = trace_id if trace_id else _new_request_id()
        # Audit R3 BUG-A5 (2026-05-18): the canonical ErrorEnvelope
        # (packages/schemas/python/relay_schemas/envelopes.py:1172,
        # ConfigDict(extra="forbid")) rejects any property not in the
        # declared set. ``error_class`` was a sidecar-only legacy field
        # mirroring ``code``; it is rejected by strict validators and
        # ``code`` already conveys the same information. Removed here;
        # tests that previously asserted on ``error_class`` now assert
        # on ``code`` (the canonical anchor).
        env: dict[str, Any] = {
            "schema_version": "relay.error.v1",
            "code": code,
            "http_status": http_status,
            "message": message,
            "blocked_surface": blocked_surface,
            "retry_advice": retry_advice,
            "request_id": rid,
            "trace_id": tid,
        }
        if details is not None:
            env["details"] = details
        url = documentation_url
        if url is None and code in _DOC_URL_PUBLISHED_CODES:
            url = f"https://relay.epochly.com/docs/errors/{code}"
        if url is not None:
            env["documentation_url"] = url
        return env

    def _extract_request_scopes(request: Request) -> frozenset[str]:
        """Parse ``X-Relay-Scopes`` header into a normalized scope set.

        Treats missing/empty headers as the empty set. Whitespace around
        each CSV item is stripped. Duplicate entries collapse.

        Audit fix (2026-05-17 P0): the legacy ``X-Relay-Scopes`` header
        path is auth-bypass-risky (caller asserts its own scopes without
        any cryptographic binding). The header is now disabled by
        default and only honoured when
        ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` is truthy. When
        disabled, this helper returns the empty set regardless of the
        header content so downstream scope checks fall through to the
        bearer-token path.
        """
        if not _legacy_scope_header_allowed():
            return frozenset()
        raw = request.headers.get("x-relay-scopes")
        if not raw:
            return frozenset()
        items = {part.strip() for part in raw.split(",") if part.strip()}
        return frozenset(items)

    # NOTE: ``_check_required_scope`` was removed (round-3 dead-code
    # cleanup). It enforced a single ``scope_required`` value sourced
    # ONLY from ``_extract_request_scopes`` (the legacy
    # ``X-Relay-Scopes`` header path). After VAL-ISO-002 migrated the
    # read/replay/eval routes and fix-r2-iso-ingest-bearer-auth migrated
    # the ingest write routes, every caller now uses ``_check_auth``
    # (which merges bearer-token scopes with the optionally-enabled
    # legacy header). The helper had zero executable callers and was
    # deleted; ``RELAY-AUTH-014`` is still emitted by ``_check_auth`` for
    # the same scope-rejection condition.

    # Maximum batch body size for the spans/contract-results batch routes
    # (spec B.4 RELAY-ING-021: payload > 1 MiB returns 413). The limit is
    # measured against the raw HTTP body bytes; the check fires BEFORE
    # JSON parsing so a 100 MiB body cannot exhaust memory.
    _BATCH_BODY_BYTE_LIMIT: int = 1024 * 1024  # 1 MiB

    # Canonical-write fields a SDK must NEVER set on /v1/ingest/runs. The
    # control plane writes these fields exclusively (CLAUDE.md keystone
    # invariant #1; spec line 1966 RELAY-ING-031).
    _CANONICAL_WRITE_FIELDS: frozenset[str] = frozenset(
        {"status", "primary_failure_class", "written_by",
         "accepted_at", "finalized_at"}
    )

    # Minimum required fields on a well-formed ``relay.ingest.run.v1``
    # envelope per spec line 1932-1958. The body-shape gate rejects with
    # 422 + RELAY-ING-001 when any are missing.
    _REQUIRED_RUN_FIELDS: tuple[str, ...] = (
        "schema_version",
        "run_id",
        "project_id",
        "trace_id",
        "client_lifecycle_status",
        "started_at",
        "manifest_commit_hash",
        "actor_identity_hash",
        "redaction_policy_version",
        "idempotency_key",
        "sequence_number",
    )

    async def _read_body_with_size_cap(
        request: Request,
        *,
        blocked_surface: str,
        cap: int = _BATCH_BODY_BYTE_LIMIT,
    ) -> bytes | JSONResponse:
        """Read raw body bytes; return 413 + RELAY-ING-021 if > ``cap``.

        Performs the size check BEFORE JSON parsing so an oversized body
        cannot exhaust JSON-decoder memory.
        """
        raw = await request.body()
        if len(raw) > cap:
            return JSONResponse(
                status_code=413,
                content=_build_error_envelope(
                    code="RELAY-ING-021",
                    http_status=413,
                    message=(
                        f"request body {len(raw)} bytes exceeds "
                        f"{cap} byte cap"
                    ),
                    blocked_surface=blocked_surface,
                    details={"body_bytes": len(raw), "cap_bytes": cap},
                ),
            )
        return raw

    # ----------------------------------------------------------------------
    # W3 manifest-enforced ingest routes (VAL-V2M03-012, VAL-V2M03-013).
    # ----------------------------------------------------------------------
    #
    # Per CLAUDE.md keystone invariant 3 + spec F line 4100: the control
    # plane refuses any submission whose ``command_hash`` does not match a
    # declared command in the active manifest version, OR whose
    # ``manifest_commit_hash`` is neither active nor in grace. Both
    # checks return HTTP 422 + ``RELAY-GATE-021`` envelope.

    async def _enforce_manifest_anchors(
        body: dict[str, Any],
    ) -> JSONResponse | tuple[str, str]:
        """Validate manifest + command anchors. Return JSONResponse on
        reject or a (manifest_commit_hash, command_hash) tuple on accept.
        """
        manifest_commit_hash = body.get("manifest_commit_hash")
        command_hash = body.get("command_hash")
        if not isinstance(manifest_commit_hash, str) or not isinstance(
            command_hash, str
        ):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": (
                        "manifest_commit_hash and command_hash MUST be "
                        "non-empty strings"
                    ),
                },
            )

        cmd_reject = enforce_command_hash(
            registry=runtime.manifest_registry,
            manifest_commit_hash=manifest_commit_hash,
            command_hash=command_hash,
        )
        if cmd_reject is not None:
            return JSONResponse(
                status_code=cmd_reject.http_status,
                content=cmd_reject.envelope,
            )

        db = runtime.database
        if db is None:
            return JSONResponse(
                status_code=503,
                content={
                    "code": "RELAY-SIDECAR-007",
                    "error_class": "RELAY-SIDECAR-NOT-READY",
                    "message": "sidecar database not yet available",
                },
            )
        reader = db.acquire_reader()
        manifest_reject = await enforce_manifest_active_or_in_grace(
            reader, manifest_commit_hash=manifest_commit_hash
        )
        if manifest_reject is not None:
            return JSONResponse(
                status_code=manifest_reject.http_status,
                content=manifest_reject.envelope,
            )
        return manifest_commit_hash, command_hash

    async def _enforce_side_effect_pairing(
        *,
        spans: list[Any],
        database: Any,
    ) -> EnforcementRejection | None:
        """M04 w4 side-effect marker/proof check (VAL-V2M04-011..015).

        For every span carrying ``side_effect_class != 'read_only'``,
        verify that a paired ``side_effect_markers`` row exists AND a
        ``side_effect_proofs`` row exists. Returns the first rejection
        encountered (consistent with the prior per-span validators) or
        None when all spans pass.

        ``database`` is the SidecarDatabase instance; we use a reader
        connection to look up the marker / proof existence. ``None`` is
        treated as "no markers/proofs exist" -- any enforced span fails
        the pairing check.
        """
        if not spans:
            return None
        # Pre-filter spans that require enforcement so we don't query
        # for read_only spans (the dominant case).
        from .side_effect_markers import is_enforced_class

        enforced_spans = [
            s for s in spans
            if isinstance(s, dict) and is_enforced_class(s.get("side_effect_class"))
        ]
        if not enforced_spans:
            return None

        # Collect the set of idempotency_keys to look up.
        keys: list[str] = []
        for s in enforced_spans:
            k = s.get("idempotency_key")
            if isinstance(k, str) and k:
                keys.append(k)

        # Build existence sets via single reader queries.
        marker_keys: set[str] = set()
        proof_keys: set[str] = set()
        if database is not None and keys:
            reader = database.acquire_reader()
            placeholders = ",".join("?" for _ in keys)
            sql_markers = (
                f"SELECT idempotency_key FROM side_effect_markers "
                f"WHERE idempotency_key IN ({placeholders})"
            )
            async with reader.execute(sql_markers, tuple(keys)) as cur:
                async for row in cur:
                    marker_keys.add(str(row[0]))
            # For proofs we join through markers; a span passes the proof
            # check iff a side_effect_proofs row exists for its marker.
            sql_proofs = (
                f"SELECT m.idempotency_key FROM side_effect_proofs p "
                f"JOIN side_effect_markers m ON m.marker_id = p.marker_id "
                f"WHERE m.idempotency_key IN ({placeholders})"
            )
            async with reader.execute(sql_proofs, tuple(keys)) as cur:
                async for row in cur:
                    proof_keys.add(str(row[0]))

        for s in enforced_spans:
            k = s.get("idempotency_key")
            has_marker = isinstance(k, str) and k in marker_keys
            has_proof = isinstance(k, str) and k in proof_keys
            rejection = check_span_marker_pairing(
                span=s, has_marker=has_marker, has_proof=has_proof
            )
            if rejection is not None:
                return rejection
        return None

    _RUNS_SURFACE: str = "POST /v1/ingest/runs"

    @app.post("/v1/ingest/runs")
    async def v1_ingest_runs(request: Request) -> JSONResponse:
        """Run-submission ingest (VAL-V2M02-001..004, VAL-V2M03-012).

        Order of checks (outer gates first so the most specific error is
        returned):

          1. JSON-decode + non-empty-object check (RELAY-ING-001).
          2. Three-anchor manifest enforcement (RELAY-GATE-021). The
             manifest gate is the OUTERMOST invariant per CLAUDE.md
             keystone #3/#4 so a stale handoff surfaces before any other
             reason.
          3. Body-shape detection: minimal manifest-only bodies short-
             circuit to the legacy 200 acceptance path that V2M03 covers
             (scope-system-exempt; V2M03 landed before scope auth).
          4. ``ingest:write`` scope check (RELAY-AUTH-014) for v2m02
             full-envelope bodies.
          5. Canonical-write-field rejection (RELAY-ING-031). Runs BEFORE
             the required-fields gate so a body that BOTH sets ``status``
             AND omits a required field produces RELAY-ING-031 (the
             keystone-#1 invariant) rather than RELAY-ING-001.
          6. Required-field body-shape check (RELAY-ING-001).
          7. Defense-in-depth raw_capture rejection (M08 W8).
          8. Tracker-acquire + 201 with ``{run_id, schema_version}``.
        """
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_RUNS_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_RUNS_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        # Auth gate. Runs ONCE here -- after manifest-anchor enforcement (the
        # outermost invariant, keystone #3/#4) and before the body-shape
        # branch -- so it covers BOTH the legacy manifest-only acceptance
        # path AND the full-envelope path. ``ingest:write`` is required on
        # every path; no widening.
        #
        # Security follow-up (2026-05-31): the legacy manifest-only path
        # previously returned 200 {accepted: True} with NO auth check
        # (scope-system-exempt; V2M03 landed before scope auth), letting an
        # UNAUTHENTICATED client POST {manifest_commit_hash, command_hash}
        # and obtain an acceptance + a quiesce tracker op in the secure
        # default. A structural review flagged this as an auth bypass.
        # Hoisting the single ``_check_auth`` above the body-shape branch
        # closes that path while preserving the legacy 200 response SHAPE
        # for authenticated anchor-only callers.
        #
        # ``_check_auth`` (vs the older ``_check_required_scope``, migrated
        # in the VAL-ISO-002 round-2 follow-up) merges bearer-token scopes
        # with the legacy ``X-Relay-Scopes`` header so both auth paths work;
        # the exact required scope and the legacy/API-key path are preserved.
        scope_reject = _check_auth(
            request,
            required_scope="ingest:write",
            blocked_surface=_RUNS_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        # Body-shape detection: V2M03 manifest-enforcement tests submit
        # the two anchor fields only; preserve the legacy 200 +
        # {accepted=True} response shape for that path so V2M03's contract
        # assertions keep their semantics. Bodies that carry any
        # non-anchor field MUST pass the full v2m02 shape checks below.
        non_anchor_keys = set(body) - {
            "manifest_commit_hash",
            "command_hash",
        }
        if not non_anchor_keys:
            # Legacy manifest-only acceptance path (V2M03-012). Auth has
            # already been enforced above (ingest:write), so this branch
            # only short-circuits the v2m02 full-envelope body shape while
            # preserving the legacy 200 + {accepted: True} contract for
            # authenticated anchor-only callers.
            tracker = runtime.quiesce.tracker
            # Populated in lifespan startup before any route runs; route
            # handlers never execute pre-startup (invariant narrowing).
            assert tracker is not None
            async with tracker.acquire(description="ingest/runs") as op:
                return JSONResponse(
                    status_code=200,
                    content={
                        "accepted": True,
                        "operation_id": op.operation_id,
                        "endpoint": "/v1/ingest/runs",
                    },
                )
        # ---- v2m02 full-envelope path ----
        # Auth was the FIRST gate above (shared with the legacy path); the
        # canonical-write / required-field / raw_capture gates follow.
        invalid_fields = sorted(
            f for f in _CANONICAL_WRITE_FIELDS if f in body
        )
        if invalid_fields:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-031",
                    http_status=422,
                    message=(
                        "SDK attempted to set canonical-write field(s) "
                        f"{invalid_fields!r}; the control plane writes these "
                        "fields exclusively (CLAUDE.md keystone invariant #1, "
                        "spec line 1966)"
                    ),
                    blocked_surface=_RUNS_SURFACE,
                    details={"invalid_fields": invalid_fields},
                ),
            )
        missing_fields = [
            f for f in _REQUIRED_RUN_FIELDS if body.get(f) in (None, "")
        ]
        if missing_fields:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        "relay.ingest.run.v1 envelope missing required "
                        f"field(s): {missing_fields!r}"
                    ),
                    blocked_surface=_RUNS_SURFACE,
                    details={"missing_fields": missing_fields},
                ),
            )
        # Step 7: defense-in-depth raw_capture rejection (M08 W8). Mirrors
        # the spans:batch gate (see v1_ingest_spans_batch). The runs
        # surface carries the canonical raw-eligible fields at the body
        # root (no span wrapper); evaluate_raw_capture_on_request has a
        # self-contained fallback for that shape (raw_capture.py:360-363).
        # Per CLAUDE.md keystone invariant #7 the absence of an applied
        # policy is treated as raw_capture=false (default-deny).
        raw_rejection = evaluate_raw_capture_on_request(body=body)
        if raw_rejection is not None:
            return JSONResponse(
                status_code=raw_rejection.http_status,
                content=raw_rejection.as_envelope(),
            )
        tracker = runtime.quiesce.tracker
        # Populated in lifespan startup before any route runs (invariant).
        assert tracker is not None
        async with tracker.acquire(description="ingest/runs"):
            return JSONResponse(
                status_code=201,
                content={
                    "run_id": body["run_id"],
                    "schema_version": body["schema_version"],
                },
            )

    _SPANS_BATCH_SURFACE: str = "POST /v1/ingest/spans:batch"
    _CONTRACT_RESULTS_BATCH_SURFACE: str = (
        "POST /v1/ingest/contract-results:batch"
    )

    @app.post("/v1/ingest/spans:batch")
    async def v1_ingest_spans_batch(request: Request) -> JSONResponse:
        """Spans-batch ingest (VAL-V2M02-005..007, VAL-V2M03-012,
        VAL-V2M08-002, 003, 010).

        Order of checks (outer-gate-first layering):

          1. Body-size cap (RELAY-ING-021) BEFORE JSON parse so an
             oversized body cannot exhaust the JSON decoder.
          2. JSON-decode + non-empty-object check (RELAY-ING-001).
          3. Three-anchor manifest enforcement (RELAY-GATE-021).
          4. Body-shape detection: minimal manifest-only bodies short-
             circuit to the legacy 200 acceptance path (V2M03).
          5. ``ingest:write`` scope check (RELAY-AUTH-014) for v2m02
             full-envelope bodies.
          6. M08-W8 per-span size/depth + UTF-8 hardening.
          7. Defense-in-depth raw_capture rejection.
          8. M04 side-effect pairing check.
          9. Tracker-acquire + 202 with ``{accepted_count, batch_id}``.
        """
        raw_or_reject = await _read_body_with_size_cap(
            request, blocked_surface=_SPANS_BATCH_SURFACE
        )
        if isinstance(raw_or_reject, JSONResponse):
            return raw_or_reject
        try:
            body = (
                json.loads(raw_or_reject.decode("utf-8"))
                if raw_or_reject
                else {}
            )
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_SPANS_BATCH_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_SPANS_BATCH_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        # Body-shape detection: V2M03 minimal-anchor bodies preserve the
        # legacy 200 + {accepted=True, endpoint=...} response (scope-system-
        # exempt; mirrors the runs handler).
        non_anchor_keys = set(body) - {
            "manifest_commit_hash",
            "command_hash",
        }
        if not non_anchor_keys:
            tracker = runtime.quiesce.tracker
            # Populated in lifespan startup before any route runs (invariant).
            assert tracker is not None
            async with tracker.acquire(description="ingest/spans:batch") as op:
                return JSONResponse(
                    status_code=200,
                    content={
                        "accepted": True,
                        "operation_id": op.operation_id,
                        "endpoint": "/v1/ingest/spans:batch",
                    },
                )
        # ---- v2m02 full-envelope path ----
        # Auth is the FIRST gate on this path (before the M08-W8 per-span
        # hardening, raw_capture, and side-effect-pairing gates below).
        # Migrated from ``_check_required_scope`` to ``_check_auth`` (round-2
        # follow-up to VAL-ISO-002): the legacy-header-only check rejected a
        # bearer token with ``ingest:write`` 403 in the secure default.
        scope_reject = _check_auth(
            request,
            required_scope="ingest:write",
            blocked_surface=_SPANS_BATCH_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        # M08-W8 hardening: per-span size + nesting + indexed-UTF-8
        # checks (VAL-V2M08-002, 003, 010). The body's "spans" array
        # may be absent (legacy submission shape) or empty -- both
        # accepted; only declared spans are validated.
        spans = body.get("spans")
        accepted_count: int = 0
        # Audit fix (2026-05-17 P0): the raw_capture gate was nested
        # inside ``if isinstance(spans, list):`` so a malformed body
        # (``spans`` omitted, or ``"spans": "foo"``) bypassed BOTH the
        # raw_capture defense-in-depth check and the side-effect
        # pairing check. Move the raw_capture gate OUT of the list-only
        # branch so it runs on every well-formed POST regardless of
        # the spans field shape. ``evaluate_raw_capture_on_request``
        # has a self-contained fallback for non-list bodies
        # (raw_capture.py lines 354-363).
        raw_rejection = evaluate_raw_capture_on_request(body=body)
        if raw_rejection is not None:
            return JSONResponse(
                status_code=raw_rejection.http_status,
                content=raw_rejection.as_envelope(),
            )
        if isinstance(spans, list):
            for span in spans:
                if not isinstance(span, dict):
                    continue
                size_or_depth = validate_span_size_and_depth(span)
                if size_or_depth is not None:
                    return JSONResponse(
                        status_code=size_or_depth["http_status"],
                        content=size_or_depth,
                    )
                attrs = span.get("attributes")
                if isinstance(attrs, dict):
                    utf8_reject = validate_indexed_utf8(attrs)
                    if utf8_reject is not None:
                        return JSONResponse(
                            status_code=utf8_reject["http_status"],
                            content=utf8_reject,
                        )
            # M04 w4-side-effects (VAL-V2M04-011..015, -035): paired-row
            # check for spans whose side_effect_class != 'read_only'.
            # The side-effect pairing check is intrinsically per-span;
            # a non-list ``spans`` body has nothing to pair so the
            # check stays inside the list-only branch.
            side_reject = await _enforce_side_effect_pairing(
                spans=spans,
                database=runtime.database,
            )
            if side_reject is not None:
                return JSONResponse(
                    status_code=422,
                    content={
                        "code": side_reject.code,
                        "error_class": side_reject.code,
                        "message": side_reject.message,
                        "details": side_reject.details,
                    },
                )
            accepted_count = sum(1 for s in spans if isinstance(s, dict))
        tracker = runtime.quiesce.tracker
        # Populated in lifespan startup before any route runs (invariant).
        assert tracker is not None
        async with tracker.acquire(description="ingest/spans:batch") as op:
            return JSONResponse(
                status_code=202,
                content={
                    "accepted_count": accepted_count,
                    "batch_id": op.operation_id,
                },
            )

    @app.post("/v1/ingest/contract-results:batch")
    async def v1_ingest_contract_results_batch(
        request: Request,
    ) -> JSONResponse:
        """Contract-results batch ingest (VAL-V2M02-008, VAL-V2M02-009).

        Order of checks:

          1. Body-size cap (RELAY-ING-021) BEFORE JSON parse.
          2. JSON-decode + non-empty-object check (RELAY-ING-001).
          3. Three-anchor manifest enforcement (RELAY-GATE-021).
          4. ``ingest:write`` scope check (RELAY-AUTH-014).
          5. Validate ``contract_results`` is a list.
          6. Tracker-acquire + 202 with ``{accepted_count, batch_id}``.

        Persistence to the ``contract_results`` table (migration 0012,
        VAL-V2M01-002) lands in a follow-up feature; this surface owns
        the wire contract and the rejection envelope shape.
        """
        raw_or_reject = await _read_body_with_size_cap(
            request, blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE
        )
        if isinstance(raw_or_reject, JSONResponse):
            return raw_or_reject
        try:
            body = (
                json.loads(raw_or_reject.decode("utf-8"))
                if raw_or_reject
                else {}
            )
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        enforced = await _enforce_manifest_anchors(body)
        if isinstance(enforced, JSONResponse):
            return enforced
        # Auth is the FIRST gate after manifest enforcement (before the
        # ``contract_results`` shape check below). Migrated from
        # ``_check_required_scope`` to ``_check_auth`` (round-2 follow-up to
        # VAL-ISO-002): the legacy-header-only check rejected a bearer token
        # with ``ingest:write`` 403 in the secure default.
        scope_reject = _check_auth(
            request,
            required_scope="ingest:write",
            blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        contract_results = body.get("contract_results")
        if not isinstance(contract_results, list):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        "request body must include a 'contract_results' "
                        "array (may be empty)"
                    ),
                    blocked_surface=_CONTRACT_RESULTS_BATCH_SURFACE,
                ),
            )
        accepted_count = sum(
            1 for r in contract_results if isinstance(r, dict)
        )
        tracker = runtime.quiesce.tracker
        # Populated in lifespan startup before any route runs (invariant).
        assert tracker is not None
        async with tracker.acquire(
            description="ingest/contract-results:batch"
        ) as op:
            return JSONResponse(
                status_code=202,
                content={
                    "accepted_count": accepted_count,
                    "batch_id": op.operation_id,
                },
            )

    # ----------------------------------------------------------------------
    # V2M02 w2.2 read endpoints (VAL-V2M02-010..020).
    #
    # All five run-namespace read endpoints. Source of truth is the
    # local SQLite ``run_results`` / ``spans`` / ``root_cause_hypotheses``
    # tables seeded by writers in later milestones; for M02 the routes
    # query whatever rows exist and return canonical envelopes per spec
    # B.6 lines 3452-3456. Every handler enforces ``runs:read`` via
    # ``_check_required_scope`` per spec B.1 line 3363.
    # ----------------------------------------------------------------------

    # Cursor signing: opaque server-signed pagination tokens per spec B.3
    # lines 3381-3390. The key is per-process so two sidecars cannot
    # accept each other's cursors (defense-in-depth; the OSS profile
    # is single-process by design).
    #
    # All paginated GETs sign + verify via ``_sign_cursor_ttl`` /
    # ``_verify_cursor_ttl`` (defined later in this factory). Those
    # helpers wrap the payload in a ``{payload, issued_at}`` envelope
    # so a stolen cursor expires after ``_CURSOR_TTL_S`` (1 hour) per
    # spec B.3 lines 3381-3390 and VAL-V2M02-070. The non-TTL
    # ``_sign_cursor`` / ``_verify_cursor`` variants were removed in
    # the V2M02 audit cleanup because they let cursors live forever.
    _cursor_signing_key: bytes = hashlib.sha256(
        f"{runtime.sqlite_path}:{uuid.uuid4()}".encode()
    ).digest()

    _RUN_LIST_SURFACE: str = "GET /v1/projects/{project_id}/runs"
    _RUN_DETAIL_SURFACE: str = "GET /v1/runs/{run_id}"
    _RUN_TRACE_SURFACE: str = "GET /v1/runs/{run_id}/trace"
    _RUN_RESULT_SURFACE: str = "GET /v1/runs/{run_id}/result"
    _RUN_EXPLAIN_SURFACE: str = "GET /v1/runs/{run_id}/explain"

    def _not_found(*, surface: str, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content=_build_error_envelope(
                code="RELAY-NOT-FOUND",
                http_status=404,
                message=message,
                blocked_surface=surface,
            ),
        )

    @app.get("/v1/projects/{project_id}/runs")
    async def v1_list_project_runs(
        project_id: str,
        request: Request,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JSONResponse:
        """List runs for a project with cursor pagination (VAL-V2M02-010,
        VAL-V2M02-011, VAL-V2M02-012).

        Pagination per spec B.3 lines 3381-3390:
          - ``limit`` defaults to 100, max 500.
          - ``next_cursor`` is opaque + HMAC-signed.
          - ``has_more`` is True iff a subsequent page exists.
        Sort order is ``(decided_at DESC, run_id ASC)`` for stable paging.
        """
        # V3M5 F03 (VAL-V3M5-008): reject RTL-override / zero-width / BOM
        # in the inbound project_id BEFORE any hashing / canonical lookup.
        id_reject = _validate_id_field(
            project_id, "project_id", blocked_surface=_RUN_LIST_SURFACE
        )
        if id_reject is not None:
            return id_reject
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_RUN_LIST_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        effective_limit = max(1, min(int(limit), 500))
        offset = 0
        if cursor is not None:
            payload, err = _verify_cursor_ttl(cursor)
            if err == "expired":
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-EXPIRED",
                        http_status=400,
                        message="cursor expired (1h TTL exceeded)",
                        blocked_surface=_RUN_LIST_SURFACE,
                    ),
                )
            if payload is None or payload.get("project_id") != project_id:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-001",
                        http_status=400,
                        message="cursor signature invalid (tampered)",
                        blocked_surface=_RUN_LIST_SURFACE,
                    ),
                )
            offset = int(payload.get("offset", 0))

        db = runtime.database
        if db is None:
            return JSONResponse(
                status_code=503,
                content=_build_error_envelope(
                    code="RELAY-SIDECAR-007",
                    http_status=503,
                    message="sidecar database not yet available",
                    blocked_surface=_RUN_LIST_SURFACE,
                ),
            )
        reader = db.acquire_reader()
        # Over-fetch by one to detect ``has_more``.
        async with reader.execute(
            "SELECT run_id, project_id, schema_version, status, "
            "manifest_commit_hash, actor_identity_hash, decided_at "
            "FROM run_results WHERE project_id = ? "
            "ORDER BY decided_at DESC, run_id ASC LIMIT ? OFFSET ?",
            (project_id, effective_limit + 1, offset),
        ) as cur:
            # aiosqlite types fetchall() as Iterable[Row]; at runtime it
            # returns a concrete list. Materialize for len()/slice below.
            rows = list(await cur.fetchall())
        has_more = len(rows) > effective_limit
        page_rows = rows[:effective_limit]
        items = [
            {
                "run_id": r[0],
                "project_id": r[1],
                "schema_version": r[2],
                "status": r[3],
                "manifest_commit_hash": r[4],
                "actor_identity_hash": r[5],
                "decided_at": r[6],
            }
            for r in page_rows
        ]
        next_cursor: str | None = None
        if has_more:
            next_cursor = _sign_cursor_ttl(
                {"project_id": project_id, "offset": offset + effective_limit}
            )
        return JSONResponse(
            status_code=200,
            content={
                "items": items,
                "next_cursor": next_cursor,
                "has_more": has_more,
            },
        )

    @app.get("/v1/runs/{run_id}")
    async def v1_get_run(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Run detail (VAL-V2M02-013, VAL-V2M02-014).

        Returns the canonical ``relay.run.v1`` envelope. The local sidecar
        synthesizes the envelope from the ``run_results`` row plus the
        manifest/actor anchors; the hosted control plane projects this
        from the runs table directly.
        """
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in run_id.
        id_reject = _validate_id_field(
            run_id, "run_id", blocked_surface=_RUN_DETAIL_SURFACE
        )
        if id_reject is not None:
            return id_reject
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_RUN_DETAIL_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_DETAIL_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT run_id, project_id, status, manifest_commit_hash, "
            "actor_identity_hash, decided_at FROM run_results "
            "WHERE run_id = ?",
            (run_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_RUN_DETAIL_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        # Audit fix (2026-05-17 P0): drop the made-up
        # ``relay.run.v1`` schema_version literal. It is NOT in
        # ``KNOWN_SCHEMA_IDS`` (packages/evals/.../schema_match.py); the
        # canonical persisted run shape is ``relay.run_result.v1``
        # returned by /v1/runs/{run_id}/result. This endpoint is a
        # transport convenience that returns identifying fields only.
        return JSONResponse(
            status_code=200,
            content={
                "run_id": row[0],
                "project_id": row[1],
                "status": row[2],
                "started_at": row[5],
                "ended_at": row[5],
                "manifest_commit_hash": row[3],
                "actor_identity_hash": row[4],
            },
        )

    @app.get("/v1/runs/{run_id}/trace")
    async def v1_get_run_trace(
        run_id: str,
        request: Request,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JSONResponse:
        """Run trace (VAL-V2M02-015, VAL-V2M02-016, VAL-V3M2-008/009).

        Returns spans ordered by ``started_at`` with parent_span_id
        references intact. Unknown run_id (no row in run_results) is 404.

        V3 M02 F04: paginated via the same HMAC-signed TTL cursor
        primitive used by the runs + gate-rounds endpoints. ``limit``
        defaults to 100, caps at 500. ``next_cursor`` is None on the
        final page; a tampered cursor returns 400 RELAY-PAGE-001 per
        VAL-V3M2-009.
        """
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in run_id.
        id_reject = _validate_id_field(
            run_id, "run_id", blocked_surface=_RUN_TRACE_SURFACE
        )
        if id_reject is not None:
            return id_reject
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_RUN_TRACE_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        effective_limit = max(1, min(int(limit), 500))
        offset = 0
        if cursor is not None:
            payload, err = _verify_cursor_ttl(cursor)
            if err == "expired":
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-EXPIRED",
                        http_status=400,
                        message="cursor expired (1h TTL exceeded)",
                        blocked_surface=_RUN_TRACE_SURFACE,
                    ),
                )
            if payload is None or payload.get("run_id") != run_id:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-001",
                        http_status=400,
                        message="cursor signature invalid (tampered)",
                        blocked_surface=_RUN_TRACE_SURFACE,
                    ),
                )
            offset = int(payload.get("offset", 0))
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_TRACE_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (run_id,)
        ) as cur:
            run_row = await cur.fetchone()
        if run_row is None:
            return _not_found(
                surface=_RUN_TRACE_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        # Over-fetch by one to detect has_more.
        async with reader.execute(
            "SELECT span_id, parent_span_id, span_type, name, status, "
            "started_at, ended_at, error_class FROM spans "
            "WHERE run_id = ? ORDER BY started_at ASC, span_id ASC "
            "LIMIT ? OFFSET ?",
            (run_id, effective_limit + 1, offset),
        ) as cur:
            # aiosqlite types fetchall() as Iterable[Row]; at runtime it
            # returns a concrete list. Materialize for len()/slice below.
            span_rows = list(await cur.fetchall())
        has_more = len(span_rows) > effective_limit
        page_rows = span_rows[:effective_limit]
        spans = [
            {
                "span_id": r[0],
                "parent_span_id": r[1],
                "span_type": r[2],
                "name": r[3],
                "status": r[4],
                "started_at": r[5],
                "ended_at": r[6],
                "error_class": r[7],
            }
            for r in page_rows
        ]
        next_cursor: str | None = None
        if has_more:
            next_cursor = _sign_cursor_ttl(
                {"run_id": run_id, "offset": offset + effective_limit}
            )
        # Audit fix (2026-05-17 P0): drop the made-up
        # ``relay.trace.v1`` schema_version literal. No canonical Trace
        # envelope exists; the wrapping "list of spans" is a transport
        # shape, not a canonical persisted envelope.
        return JSONResponse(
            status_code=200,
            content={
                "run_id": run_id,
                "spans": spans,
                "next_cursor": next_cursor,
                "has_more": has_more,
            },
        )

    @app.get("/v1/runs/{run_id}/result")
    async def v1_get_run_result(
        run_id: str, request: Request
    ) -> JSONResponse:
        """Canonical RunResult (VAL-V2M02-017, VAL-V2M02-018).

        Returns the ``run_results`` row including ``written_by``. The
        control-plane invariant (#1) is enforced at the SQL layer via the
        ``written_by_control_plane`` CHECK constraint on the table; this
        handler is read-only.
        """
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in run_id.
        id_reject = _validate_id_field(
            run_id, "run_id", blocked_surface=_RUN_RESULT_SURFACE
        )
        if id_reject is not None:
            return id_reject
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_RUN_RESULT_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_RESULT_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT run_result_id, run_id, project_id, schema_version, "
            "written_by, status, primary_failure_class, error_priority_rule, "
            "evidence_bundle_id, manifest_commit_hash, actor_identity_hash, "
            "decided_at, decision_epoch, signature, signature_key_id "
            "FROM run_results WHERE run_id = ?",
            (run_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_RUN_RESULT_SURFACE,
                message=f"run_result for run_id {run_id!r} not found",
            )
        return JSONResponse(
            status_code=200,
            content={
                "run_result_id": row[0],
                "run_id": row[1],
                "project_id": row[2],
                "schema_version": row[3],
                "written_by": row[4],
                "status": row[5],
                "primary_failure_class": row[6],
                "error_priority_rule": row[7],
                "evidence_bundle_id": row[8],
                "manifest_commit_hash": row[9],
                "actor_identity_hash": row[10],
                "decided_at": row[11],
                "decision_epoch": row[12],
                "signature": row[13],
                "signature_key_id": row[14],
            },
        )

    @app.get("/v1/runs/{run_id}/explain")
    async def v1_get_run_explain(
        run_id: str,
        request: Request,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JSONResponse:
        """Root cause hypotheses (VAL-V2M02-019, VAL-V2M02-020,
        VAL-V3M2-008/009).

        The generator implementation lands in M05; M02 ships the route
        serving whatever rows M05 produces. Returns an empty list for
        runs with no hypotheses (NOT 404 -- the spec is explicit on
        this), 404 only if the run itself is unknown.

        V3 M02 F04: paginated via the same HMAC-signed TTL cursor
        primitive used by runs + gate-rounds. ``limit`` defaults to
        100, caps at 500. A tampered cursor returns 400 RELAY-PAGE-001
        per VAL-V3M2-009.
        """
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in run_id.
        id_reject = _validate_id_field(
            run_id, "run_id", blocked_surface=_RUN_EXPLAIN_SURFACE
        )
        if id_reject is not None:
            return id_reject
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_RUN_EXPLAIN_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        effective_limit = max(1, min(int(limit), 500))
        offset = 0
        if cursor is not None:
            payload, err = _verify_cursor_ttl(cursor)
            if err == "expired":
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-EXPIRED",
                        http_status=400,
                        message="cursor expired (1h TTL exceeded)",
                        blocked_surface=_RUN_EXPLAIN_SURFACE,
                    ),
                )
            if payload is None or payload.get("run_id") != run_id:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-001",
                        http_status=400,
                        message="cursor signature invalid (tampered)",
                        blocked_surface=_RUN_EXPLAIN_SURFACE,
                    ),
                )
            offset = int(payload.get("offset", 0))
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_RUN_EXPLAIN_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (run_id,)
        ) as cur:
            run_row = await cur.fetchone()
        if run_row is None:
            return _not_found(
                surface=_RUN_EXPLAIN_SURFACE,
                message=f"run_id {run_id!r} not found",
            )
        # Over-fetch by one to detect has_more.
        async with reader.execute(
            "SELECT hypothesis_id, run_id, span_id, hypothesis_class, "
            "confidence, evidence_refs, evidence_refs_digest, generator, "
            "created_at FROM root_cause_hypotheses "
            "WHERE run_id = ? ORDER BY created_at ASC, hypothesis_id ASC "
            "LIMIT ? OFFSET ?",
            (run_id, effective_limit + 1, offset),
        ) as cur:
            # aiosqlite types fetchall() as Iterable[Row]; at runtime it
            # returns a concrete list. Materialize for len()/slice below.
            rows = list(await cur.fetchall())
        has_more = len(rows) > effective_limit
        page_rows = rows[:effective_limit]
        hypotheses = [
            {
                "schema_version": "relay.root_cause_hypothesis.v1",
                "hypothesis_id": r[0],
                "run_id": r[1],
                "span_id": r[2],
                "hypothesis_class": r[3],
                "confidence": r[4],
                "evidence_refs": json.loads(r[5]) if r[5] else [],
                "evidence_refs_digest": r[6],
                "generator": r[7],
                "created_at": r[8],
            }
            for r in page_rows
        ]
        next_cursor: str | None = None
        if has_more:
            next_cursor = _sign_cursor_ttl(
                {"run_id": run_id, "offset": offset + effective_limit}
            )
        return JSONResponse(
            status_code=200,
            content={
                "run_id": run_id,
                "hypotheses": hypotheses,
                "next_cursor": next_cursor,
                "has_more": has_more,
            },
        )

    # ----------------------------------------------------------------------
    # V2M02 w2.3 replay endpoints (VAL-V2M02-021..030).
    #
    # The hosted writers for replay_cases / replay_fixtures / replay_results
    # do not exist in the OSS sidecar at M02; the canonical SQLite tables
    # for these objects land in later milestones. The HTTP surface lands
    # now so SDKs + CLI have stable endpoints. Each handler round-trips
    # canonical response shapes via in-memory registries on RuntimeState.
    # ``written_by = "control_plane"`` is stamped on every persisted
    # envelope per keystone invariant #1.
    # ----------------------------------------------------------------------

    _REPLAY_CREATE_SURFACE: str = "POST /v1/replay-cases"
    _REPLAY_GET_SURFACE: str = "GET /v1/replay-cases/{case_id}"
    _REPLAY_FIXTURES_SURFACE: str = "POST /v1/replay-cases/{case_id}/fixtures"
    _REPLAY_RUN_SURFACE: str = "POST /v1/replay-cases/{case_id}/run"
    _REPLAY_RESULT_SURFACE: str = "GET /v1/replay-results/{result_id}"

    @app.post("/v1/replay-cases")
    async def v1_create_replay_case(request: Request) -> JSONResponse:
        """Create a replay case from a failed run (VAL-V2M02-021,
        VAL-V2M02-022). Returns 201 + ``{case_id}``; unknown
        ``from_run_id`` returns 404.
        """
        scope_reject = _check_auth(
            request,
            required_scope="replay:write",
            blocked_surface=_REPLAY_CREATE_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_CREATE_SURFACE,
                ),
            )
        from_run_id = body.get("from_run_id")
        if not isinstance(from_run_id, str) or not from_run_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="from_run_id MUST be a non-empty string",
                    blocked_surface=_REPLAY_CREATE_SURFACE,
                ),
            )
        # Verify the source run exists.
        db = runtime.database
        if db is None:
            return _not_found(
                surface=_REPLAY_CREATE_SURFACE,
                message="sidecar database not yet available",
            )
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT 1 FROM run_results WHERE run_id = ?", (from_run_id,)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return _not_found(
                surface=_REPLAY_CREATE_SURFACE,
                message=f"from_run_id {from_run_id!r} not found",
            )
        case_id = f"case-{uuid.uuid4().hex}"
        created_at = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
        # Audit fix (2026-05-17 P0): align response shape with the
        # canonical ReplayCase envelope (envelopes.yaml:444-475,
        # Pydantic at envelopes.py:873-895). Field renames:
        # ``case_id`` -> ``replay_case_id``,
        # ``from_run_id`` -> ``source_run_id``.
        # Required-fields backfilled with sensible defaults:
        # ``project_id``, ``failure_signature_hash`` (synthesized from
        # source_run_id), ``inputs_ref``, ``inputs_digest`` (canonical
        # sha256 of the empty inputs body). Legacy aliases
        # (``case_id``, ``from_run_id``, ``scope_name``) mirrored.
        failure_signature_hash = body.get(
            "failure_signature_hash"
        ) or f"sig-{from_run_id}"
        inputs_ref = body.get("inputs_ref", f"local://inputs/{case_id}")
        inputs_digest = body.get("inputs_digest") or _sha256_canonical(b"{}")
        case = {
            "schema_version": "relay.replay_case.v1",
            "replay_case_id": case_id,
            "project_id": body.get(
                "project_id", "00000000-0000-0000-0000-000000000000"
            ),
            "source_run_id": from_run_id,
            "failure_signature_hash": failure_signature_hash,
            "inputs_ref": inputs_ref,
            "inputs_digest": inputs_digest,
            # Legacy aliases for back-compat during transition.
            "case_id": case_id,
            "from_run_id": from_run_id,
            "scope_name": body.get("scope_name"),
            "written_by": "control_plane",
            "created_at": created_at,
        }
        runtime.replay_cases[case_id] = case
        runtime.replay_fixtures.setdefault(case_id, [])
        return JSONResponse(
            status_code=201,
            content={
                "replay_case_id": case_id,
                # Legacy alias for back-compat.
                "case_id": case_id,
                "schema_version": "relay.replay_case.v1",
            },
        )

    @app.get("/v1/replay-cases/{case_id}")
    async def v1_get_replay_case(
        case_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_REPLAY_GET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        case = runtime.replay_cases.get(case_id)
        if case is None:
            return _not_found(
                surface=_REPLAY_GET_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        fixtures = runtime.replay_fixtures.get(case_id, [])
        return JSONResponse(
            status_code=200,
            content={**case, "fixtures_count": len(fixtures)},
        )

    @app.post("/v1/replay-cases/{case_id}/fixtures")
    async def v1_post_replay_fixture(
        case_id: str, request: Request
    ) -> JSONResponse:
        """Upload a fixture for a replay case (VAL-V2M02-025,
        VAL-V2M02-026). Persistence path mirrors the spec
        ``object_put_with_digest`` primitive: the digest returned is the
        sha256 of the canonical JSON payload.
        """
        scope_reject = _check_auth(
            request,
            required_scope="replay:write",
            blocked_surface=_REPLAY_FIXTURES_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_FIXTURES_SURFACE,
                ),
            )
        if case_id not in runtime.replay_cases:
            return _not_found(
                surface=_REPLAY_FIXTURES_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        canonical = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        # Audit fix (2026-05-17 P0): canonical sha256 wire form is the
        # hyphen prefix per VAL-W1-009 / envelopes.yaml.
        digest = _sha256_canonical(canonical)
        fixture_id = f"fix-{uuid.uuid4().hex}"
        record = {
            "fixture_id": fixture_id,
            "case_id": case_id,
            "fixture_kind": body.get("fixture_kind"),
            "digest": digest,
            "payload": body,
            "written_by": "control_plane",
        }
        runtime.replay_fixtures.setdefault(case_id, []).append(record)
        return JSONResponse(
            status_code=201,
            content={"fixture_id": fixture_id, "digest": digest},
        )

    @app.post("/v1/replay-cases/{case_id}/run")
    async def v1_post_replay_run(
        case_id: str, request: Request
    ) -> JSONResponse:
        """Execute a reproduction (VAL-V2M02-027, VAL-V2M02-028).

        Mode defaults to ``cassette`` per keystone invariant #9
        (cassette-first replay). Live mode against ``mutating`` or
        ``external_irreversible`` tools is refused with
        ``RELAY-REPLAY-014`` per spec B.4 line 3428.
        """
        scope_reject = _check_auth(
            request,
            required_scope="replay:write",
            blocked_surface=_REPLAY_RUN_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        if case_id not in runtime.replay_cases:
            return _not_found(
                surface=_REPLAY_RUN_SURFACE,
                message=f"case_id {case_id!r} not found",
            )
        mode = body.get("mode", "cassette")
        if mode not in ("cassette", "live"):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=f"mode must be 'cassette' or 'live'; got {mode!r}",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        if mode == "live":
            side_effect = body.get("side_effect_class")
            if side_effect in ("mutating", "external_irreversible"):
                return JSONResponse(
                    status_code=422,
                    content=_build_error_envelope(
                        code="RELAY-REPLAY-014",
                        http_status=422,
                        message=(
                            "live replay against side_effect_class "
                            f"{side_effect!r} is refused; cassette mode is "
                            "the default (keystone invariant #9)"
                        ),
                        blocked_surface=_REPLAY_RUN_SURFACE,
                        details={"side_effect_class": side_effect},
                    ),
                )
        manifest_hash = body.get("manifest_commit_hash")
        if not isinstance(manifest_hash, str) or not manifest_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="manifest_commit_hash MUST be a non-empty string",
                    blocked_surface=_REPLAY_RUN_SURFACE,
                ),
            )
        result_id = f"rr-{uuid.uuid4().hex}"
        await_url = f"/v1/replay-results/{result_id}"
        result_record = {
            "schema_version": "relay.replay_result.v1",
            "replay_result_id": result_id,
            "case_id": case_id,
            "replay_mode": mode,
            "manifest_commit_hash": manifest_hash,
            "digest_ok": True,
            "outcome": "pending",
            "evidence": {"bundle_id": None, "claims": []},
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.replay_results[result_id] = result_record
        return JSONResponse(
            status_code=202,
            content={"replay_result_id": result_id, "await_url": await_url},
        )

    @app.get("/v1/replay-results/{result_id}")
    async def v1_get_replay_result(
        result_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_REPLAY_RESULT_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        record = runtime.replay_results.get(result_id)
        if record is None:
            return _not_found(
                surface=_REPLAY_RESULT_SURFACE,
                message=f"replay_result {result_id!r} not found",
            )
        return JSONResponse(status_code=200, content=record)

    # ----------------------------------------------------------------------
    # V2M02 w2.4 eval endpoints (VAL-V2M02-031..036).
    #
    # The hosted writers for eval_datasets / eval_runs land in later
    # milestones; the route surface lands now so SDKs have stable
    # endpoints. Same in-memory pattern as replay; written_by is
    # always "control_plane".
    # ----------------------------------------------------------------------

    _EVAL_DATASET_SURFACE: str = "POST /v1/eval-datasets"
    _EVAL_RUN_CREATE_SURFACE: str = "POST /v1/eval-runs"
    _EVAL_RUN_GET_SURFACE: str = "GET /v1/eval-runs/{eval_run_id}"

    @app.post("/v1/eval-datasets")
    async def v1_create_eval_dataset(request: Request) -> JSONResponse:
        scope_reject = _check_auth(
            request,
            required_scope="replay:write",
            blocked_surface=_EVAL_DATASET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        name = body.get("name")
        if not isinstance(name, str) or not name:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="name MUST be a non-empty string",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        fixtures = body.get("fixtures", [])
        if not isinstance(fixtures, list):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="fixtures MUST be an array (may be empty)",
                    blocked_surface=_EVAL_DATASET_SURFACE,
                ),
            )
        dataset_id = f"ds-{uuid.uuid4().hex}"
        # Audit fix (2026-05-17 P0): drop the made-up
        # ``relay.eval_dataset.v1`` schema_version literal. No canonical
        # EvalDataset envelope exists in ``envelopes.yaml`` /
        # ``KNOWN_SCHEMA_IDS``; the canonical eval primitives are
        # eval_run (migration 0001_eval_runs.sql) + replay_fixture.
        record = {
            "dataset_id": dataset_id,
            "name": name,
            "description": body.get("description"),
            "fixtures": fixtures,
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.eval_datasets[dataset_id] = record
        return JSONResponse(
            status_code=201,
            content={
                "dataset_id": dataset_id,
            },
        )

    @app.post("/v1/eval-runs")
    async def v1_create_eval_run(request: Request) -> JSONResponse:
        scope_reject = _check_auth(
            request,
            required_scope="replay:write",
            blocked_surface=_EVAL_RUN_CREATE_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        dataset_id = body.get("dataset_id")
        if not isinstance(dataset_id, str) or not dataset_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="dataset_id MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        if dataset_id not in runtime.eval_datasets:
            return _not_found(
                surface=_EVAL_RUN_CREATE_SURFACE,
                message=f"dataset_id {dataset_id!r} not found",
            )
        contract_id = body.get("contract_id")
        manifest_hash = body.get("manifest_commit_hash")
        if not isinstance(contract_id, str) or not contract_id:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="contract_id MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        if not isinstance(manifest_hash, str) or not manifest_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="manifest_commit_hash MUST be a non-empty string",
                    blocked_surface=_EVAL_RUN_CREATE_SURFACE,
                ),
            )
        eval_run_id = f"er-{uuid.uuid4().hex}"
        await_url = f"/v1/eval-runs/{eval_run_id}"
        # Audit-R3 (2026-05-18): drop made-up wire-level schema_version
        # "relay.eval_run.v1" (not in KNOWN_SCHEMA_IDS / envelopes.yaml /
        # openapi.yaml). Wire responses no longer surface a schema_version
        # for this endpoint; persisted storage tables in packages/evals/
        # keep their own internal column independent of canonical envelope
        # set.
        record = {
            "eval_run_id": eval_run_id,
            "dataset_id": dataset_id,
            "contract_id": contract_id,
            "manifest_commit_hash": manifest_hash,
            "status": "queued",
            "metrics": {},
            "evidence": {"bundle_id": None, "claims": []},
            "written_by": "control_plane",
            "created_at": datetime.now(tz=UTC)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        runtime.eval_runs[eval_run_id] = record
        return JSONResponse(
            status_code=202,
            content={"eval_run_id": eval_run_id, "await_url": await_url},
        )

    @app.get("/v1/eval-runs/{eval_run_id}")
    async def v1_get_eval_run(
        eval_run_id: str, request: Request
    ) -> JSONResponse:
        scope_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_EVAL_RUN_GET_SURFACE,
        )
        if scope_reject is not None:
            return scope_reject
        record = runtime.eval_runs.get(eval_run_id)
        if record is None:
            return _not_found(
                surface=_EVAL_RUN_GET_SURFACE,
                message=f"eval_run {eval_run_id!r} not found",
            )
        return JSONResponse(status_code=200, content=record)

    # ======================================================================
    # V2M02 W2.5/2.6/2.7/2.8 + cross-cutting W2.9/2.10/2.11
    # (VAL-V2M02-037..084).
    # ======================================================================
    #
    # The five gates routes (w2.5), four evidence routes (w2.6), two
    # manifest routes (w2.7), two redaction-policy routes (w2.8), plus
    # idempotency (w2.9), rate-limit headers (w2.10), bearer-auth + scope
    # checks (w2.11), and the hosted-only token-issuance stubs.
    #
    # All canonical envelopes carry ``written_by = "control_plane"`` per
    # keystone invariant #1 (gate_decisions additionally carry
    # ``decided_by = "gate_engine"`` per the DB CHECK constraint).
    # Pagination uses a TTL-aware HMAC-signed cursor (`_sign_cursor_ttl`
    # / `_verify_cursor_ttl`) so a tampered or expired cursor returns 400
    # with a structured code (VAL-V2M02-069, -070).
    # ----------------------------------------------------------------------

    # ---- Surface constants for stable blocked_surface strings -----------
    _GATE_CONFIGURE_SURFACE: str = "PUT /v1/gates/{gate_id}"
    _GATE_POLICY_SURFACE: str = "PUT /v1/gate-policies/{policy_id}"
    _GATE_DRAFT_SURFACE: str = "POST /v1/gates/{gate_id}/drafts"
    _GATE_DECISION_SURFACE: str = "GET /v1/gate-decisions/{decision_id}"
    _GATE_ROUNDS_SURFACE: str = "GET /v1/gates/{gate_id}/rounds"
    _EVIDENCE_CREATE_SURFACE: str = "POST /v1/evidence-bundles"
    _EVIDENCE_GET_SURFACE: str = "GET /v1/evidence-bundles/{bundle_id}"
    _EVIDENCE_DOWNLOAD_SURFACE: str = (
        "GET /v1/evidence-bundles/{bundle_id}/download"
    )
    _EVIDENCE_VERIFY_SURFACE: str = (
        "POST /v1/evidence-bundles/{bundle_id}/verify"
    )
    _MANIFEST_CREATE_SURFACE: str = "POST /v1/manifests"
    _MANIFEST_VERSION_SURFACE: str = (
        "GET /v1/manifests/{manifest_id}/versions/{commit_hash}"
    )
    _REDACTION_POLICY_CREATE_SURFACE: str = "POST /v1/redaction-policies"
    _REDACTION_POLICY_GET_SURFACE: str = (
        "GET /v1/redaction-policies/{policy_id}"
    )
    _AUTH_TOKENS_CREATE_SURFACE: str = "POST /v1/auth/tokens"
    _AUTH_TOKENS_DELETE_SURFACE: str = "DELETE /v1/auth/tokens/{token_id}"

    # ---- Time helpers (UTC Z-suffixed ISO) ------------------------------
    def _now_iso_z() -> str:
        return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")

    def _now_epoch_s() -> int:
        return int(datetime.now(tz=UTC).timestamp())

    # ---- W2.9 cursor pagination v2 (TTL + tamper detection) -------------
    #
    # The cursor envelope is JSON {payload, issued_at}. The HMAC is
    # computed over ``json.dumps`` (sort_keys + compact separators) and
    # prefixed onto the base64url-encoded body. Two failure modes are
    # distinguished:
    #   - signature mismatch -> RELAY-PAGE-001 (tampered/invalid)
    #   - issued_at > 1h ago -> RELAY-PAGE-EXPIRED (per VAL-V2M02-070)
    _CURSOR_TTL_S: int = 3600

    def _sign_cursor_ttl(payload: dict[str, Any]) -> str:
        envelope = {"payload": payload, "issued_at": _now_epoch_s()}
        raw = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        sig = hmac.new(_cursor_signing_key, raw, hashlib.sha256).digest()[:16]
        token = base64.urlsafe_b64encode(sig + raw).decode("ascii").rstrip("=")
        return token

    def _verify_cursor_ttl(
        token: str, *, max_age_s: int = _CURSOR_TTL_S
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Verify + decode a TTL-aware cursor.

        Returns ``(payload, None)`` on success.
        Returns ``(None, "tampered")`` on signature mismatch / decode err.
        Returns ``(None, "expired")`` when ``issued_at`` is older than
        ``max_age_s``.
        """
        try:
            padded = token + "=" * (-len(token) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:  # noqa: BLE001
            return None, "tampered"
        if len(decoded) < 16:
            return None, "tampered"
        sig, raw = decoded[:16], decoded[16:]
        expected = hmac.new(
            _cursor_signing_key, raw, hashlib.sha256
        ).digest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None, "tampered"
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None, "tampered"
        if not isinstance(envelope, dict):
            return None, "tampered"
        issued_at = envelope.get("issued_at")
        if not isinstance(issued_at, int):
            return None, "tampered"
        if _now_epoch_s() - issued_at > max_age_s:
            return None, "expired"
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return None, "tampered"
        return payload, None

    # ---- W2.11 bearer auth (Authorization: Bearer <token>) --------------
    #
    # Two scope-sourcing paths coexist for backward compatibility:
    #
    #   (a) Legacy ``X-Relay-Scopes`` CSV header. Used by existing
    #       VAL-V2M02-001..036 tests; if present, ``_check_required_scope``
    #       (defined earlier) handles the route.
    #
    #   (b) New ``Authorization: Bearer <token>`` header. The token is
    #       looked up in ``runtime.registered_tokens``; the token's
    #       scope set is used for the check. Missing/unknown token
    #       returns 401 RELAY-AUTH-001 per VAL-V2M02-080/081.
    #
    # ``_check_auth`` returns:
    #   None                                -> auth ok, proceed
    #   JSONResponse(status_code=401|403)   -> auth failed
    #
    # Public routes (verify) MUST NOT call ``_check_auth``.
    def _resolve_scopes_from_token(request: Request) -> tuple[
        frozenset[str] | None, str | None, str | None
    ]:
        """Return (scopes_or_None, token_or_None, error_reason).

        ``error_reason`` is one of {None, "missing", "invalid"}.
        ``scopes_or_None`` is None when the bearer header is absent or
        invalid; otherwise the token's registered scope set.
        """
        auth_hdr = request.headers.get("authorization", "").strip()
        if not auth_hdr:
            return None, None, "missing"
        parts = auth_hdr.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None, None, "invalid"
        token = parts[1].strip()
        if not token:
            return None, None, "invalid"
        record = runtime.registered_tokens.get(token)
        if record is None:
            return None, token, "invalid"
        scopes = record.get("scopes")
        if isinstance(scopes, frozenset):
            return scopes, token, None
        if isinstance(scopes, list | set | tuple):
            return frozenset(scopes), token, None
        return frozenset(), token, None

    def _check_auth(
        request: Request,
        *,
        required_scope: str | None,
        blocked_surface: str,
    ) -> JSONResponse | None:
        """Enforce bearer + scope. ``required_scope=None`` -> presence-only.

        Returns None on success, or a 401/403 JSONResponse with the
        canonical envelope on failure.

        Order: bearer-presence (401 RELAY-AUTH-001) BEFORE scope-check
        (403 RELAY-AUTH-014) per spec B.4 lines 3417-3419. The legacy
        ``X-Relay-Scopes`` header is honoured when present as the
        secondary scope source so existing tests keep working.
        """
        scopes_from_token, _token, err = _resolve_scopes_from_token(request)
        legacy_scopes = _extract_request_scopes(request)
        # Determine the effective scope set:
        #   1. If a valid bearer token is present, use its scopes.
        #   2. Else if X-Relay-Scopes is present (legacy), use it AND
        #      do NOT require a bearer (back-compat for older tests).
        #   3. Else 401 RELAY-AUTH-001.
        # Audit fix (2026-05-17 P0): the legacy-header branch is now
        # gated by ``RELAY_SIDECAR_ALLOW_LEGACY_SCOPE_HEADER`` (default
        # off). Without the env var, only bearer tokens authenticate;
        # the auth-bypass surfaced by self-asserted X-Relay-Scopes is
        # closed by default.
        legacy_header_present = (
            _legacy_scope_header_allowed()
            and request.headers.get("x-relay-scopes") is not None
        )
        if scopes_from_token is not None:
            effective = scopes_from_token
        elif legacy_scopes or legacy_header_present:
            # Legacy path: header present (possibly empty). Skip 401.
            effective = legacy_scopes
        else:
            # No bearer, no legacy header -> 401.
            msg = (
                "missing bearer token: Authorization header required"
                if err == "missing"
                else "invalid bearer token"
            )
            return JSONResponse(
                status_code=401,
                content=_build_error_envelope(
                    code="RELAY-AUTH-001",
                    http_status=401,
                    message=msg,
                    blocked_surface=blocked_surface,
                ),
                headers=_rate_limit_headers_for(request),
            )
        if err == "invalid" and scopes_from_token is None and not legacy_scopes:
            # Bearer header present but malformed/unknown AND no legacy
            # header -> 401 (caught above). Defense-in-depth here in
            # case both branches change later.
            return JSONResponse(
                status_code=401,
                content=_build_error_envelope(
                    code="RELAY-AUTH-001",
                    http_status=401,
                    message="invalid bearer token",
                    blocked_surface=blocked_surface,
                ),
                headers=_rate_limit_headers_for(request),
            )
        if required_scope is not None and required_scope not in effective:
            return JSONResponse(
                status_code=403,
                content=_build_error_envelope(
                    code="RELAY-AUTH-014",
                    http_status=403,
                    message=(
                        f"token lacks required scope {required_scope!r}; "
                        f"present scopes: {sorted(effective)!r}"
                    ),
                    blocked_surface=blocked_surface,
                    details={"required_scope": required_scope},
                ),
                headers=_rate_limit_headers_for(request),
            )
        return None

    # ---- W2.10 rate limiting --------------------------------------------
    #
    # Three buckets per request (most restrictive wins):
    #   - per-project: 100 RPS (VAL-V2M02-077). Source: ``X-Relay-Project``
    #     header OR project_id derived from the bearer token record.
    #   - per-JWT (token):  30 RPS (VAL-V2M02-078). Source: bearer token.
    #   - per-IP:            5 RPS (VAL-V2M02-079). Source: client IP.
    #     The per-IP bucket is the only one enforced on the public
    #     /verify endpoint.
    #
    # Bucket implementation: fixed 1-second window counter. ``Reset`` is
    # the next second-boundary epoch. Defaults are intentionally high
    # enough to never trip during the normal plumbing tier; tests opt
    # into low limits via ``RELAY_SIDECAR_RATELIMIT_*`` env overrides.
    def _bucket_limit(env_var: str, default: int) -> int:
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            return default
        try:
            v = int(raw)
            return max(1, v)
        except (TypeError, ValueError):
            return default

    def _rate_limit_state(
        key: str, limit: int
    ) -> tuple[int, int, int]:
        """Increment the bucket; return (limit, remaining, reset_epoch).

        Single fixed-window-per-second counter. Stored on
        ``runtime.rate_limit_buckets``.

        VAL-ISO-008 (DoS hardening): bucket keys are derived from
        unauthenticated, attacker-controlled inputs
        (``ip:<X-Forwarded-For>``, ``jwt:<bearer>``,
        ``project:<X-Relay-Project>``). Without pruning, a request loop
        carrying a unique header value per request would create a
        permanent entry per value and grow ``runtime.rate_limit_buckets``
        without bound -> memory-exhaustion DoS. The window is a single
        second (``reset_epoch = window_start + 1``), so any entry whose
        ``window_start < now`` belongs to a dead window and can never be
        consulted again. Sweep those stale entries on each access so the
        dict is bounded by the number of distinct buckets ACTIVE in the
        current 1-second window, while counting for live keys is
        unaffected (the live key's own count is preserved below).
        """
        now = _now_epoch_s()
        buckets = runtime.rate_limit_buckets
        # Prune dead windows (anything started before the current second).
        # Build the survivor list first to avoid mutating during iteration.
        stale = [k for k, (ws, _c) in buckets.items() if ws < now]
        for k in stale:
            del buckets[k]
        window_start, count = buckets.get(key, (now, 0))
        if now != window_start:
            window_start, count = now, 0
        count += 1
        buckets[key] = (window_start, count)
        remaining = max(0, limit - count)
        reset_epoch = window_start + 1
        return limit, remaining, reset_epoch

    def _client_ip(request: Request) -> str:
        # Honour the standard reverse-proxy header when present so tests
        # can simulate distinct client IPs without a real network.
        xff = request.headers.get("x-forwarded-for", "").strip()
        if xff:
            return xff.split(",")[0].strip()
        client = request.client
        if client is None:
            return "0.0.0.0"  # noqa: S104  (loopback test default)
        return client.host

    def _resolve_project_id_for_rate_limit(request: Request) -> str:
        raw = request.headers.get("x-relay-project", "").strip()
        if raw:
            return raw
        _scopes, token, _err = _resolve_scopes_from_token(request)
        if token:
            rec = runtime.registered_tokens.get(token, {})
            pid = rec.get("project_id")
            if isinstance(pid, str) and pid:
                return pid
        # Fallback: use the client IP so traffic is at least bounded.
        return f"ip:{_client_ip(request)}"

    def _rate_limit_headers_for(
        request: Request, *, surface_class: str = "default"
    ) -> dict[str, str]:
        """Return rate-limit headers for the *current* request without
        re-incrementing. Re-uses the most recent bucket state computed
        by ``_apply_rate_limit``. Defensive default when nothing has
        run yet (e.g. early auth failure path).
        """
        snap = getattr(request.state, "_relay_ratelimit_snapshot", None)
        if isinstance(snap, dict):
            return {
                "X-RateLimit-Limit": str(snap["limit"]),
                "X-RateLimit-Remaining": str(snap["remaining"]),
                "X-RateLimit-Reset": str(snap["reset"]),
            }
        # Fallback when the middleware has not populated the snapshot
        # (e.g. WebSocket scopes never reach here). Use a generous
        # default so clients see well-formed headers.
        return {
            "X-RateLimit-Limit": "1000000",
            "X-RateLimit-Remaining": "999999",
            "X-RateLimit-Reset": str(_now_epoch_s() + 1),
        }

    # ---- W2.9 idempotency helpers ---------------------------------------
    def _digest_of_bytes(body: bytes) -> str:
        # Audit fix (2026-05-17 P0): canonical sha256 wire form is the
        # hyphen prefix per VAL-W1-009 / envelopes.yaml.
        return _sha256_canonical(body)

    # V3M2 F03 (spec section B.6 line 3517): an inbound HTTP request
    # whose Idempotency-Key header is set MUST match the Crockford-
    # base32 ULID grammar ^[0-9A-HJKMNP-TV-Z]{26}$. Crockford excludes
    # the visually-ambiguous I, L, O, U letters. Validation MUST run
    # BEFORE any canonical hashing (VAL-V3M2-007) so an invalid input
    # never reaches _canonical_idempotency_key. The pattern is module-
    # local (compiled once per build_runtime_app call) so the per-
    # request cost is a single re.fullmatch.
    _ULID_GRAMMAR_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")

    # V3 M05 F03 (spec section AI adversarial guards; VAL-V3M5-008):
    # Inbound HTTP ID fields (Idempotency-Key, run_id, gate_id, project_id)
    # MUST be validated to reject U+202E (RIGHT-TO-LEFT OVERRIDE),
    # U+200B (ZERO WIDTH SPACE), U+200C (ZERO WIDTH NON-JOINER),
    # U+200D (ZERO WIDTH JOINER), and U+FEFF (BOM) BEFORE any hashing or
    # canonical processing. These visually-invisible-or-misleading code
    # points are the classic vehicles for smuggling a divergent wire form
    # past naive string-equality checks (e.g. an attacker presents
    # ``run-XYZ`` that *renders* as ``run-XYZ`` but whose byte content
    # contains an embedded U+202E flipping the apparent reading order).
    # Idempotency-Key is independently covered by ``_ULID_GRAMMAR_RE``
    # above (which excludes every non-ASCII code point); this guard is
    # the SAME contract for path parameters where the ULID grammar does
    # not apply (run_id / gate_id / project_id are free-form identifiers
    # in the sidecar, not necessarily ULID-shaped).
    _BANNED_ID_CODEPOINTS: frozenset[str] = frozenset(
        {
            "‮",  # RIGHT-TO-LEFT OVERRIDE
            "​",  # ZERO WIDTH SPACE
            "‌",  # ZERO WIDTH NON-JOINER
            "‍",  # ZERO WIDTH JOINER
            "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
        }
    )

    def _validate_id_field(
        value: str, field_name: str, *, blocked_surface: str
    ) -> JSONResponse | None:
        """Reject an HTTP-boundary ID containing any banned code point.

        Returns None on accept (value contains no banned code point), or
        a 400 ``RELAY-ID-INVALID`` JSONResponse when ``value`` contains
        one of ``_BANNED_ID_CODEPOINTS``. The check is a single-pass
        membership scan over the string; the cost is O(len(value)) and
        runs BEFORE any hashing or canonical processing per VAL-V3M5-008.

        The envelope ``details`` record the offending ``field`` and the
        first banned code point observed (as ``U+XXXX`` hex) so callers
        can pinpoint the violation without re-encoding the raw bytes.
        """
        for ch in value:
            if ch in _BANNED_ID_CODEPOINTS:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-ID-INVALID",
                        http_status=400,
                        message=(
                            f"ID field {field_name!r} contains a banned "
                            f"code point (U+{ord(ch):04X}); inbound IDs "
                            "MUST NOT carry RTL-override / zero-width / "
                            "BOM characters"
                        ),
                        blocked_surface=blocked_surface,
                        details={
                            "field": field_name,
                            "banned_codepoint": f"U+{ord(ch):04X}",
                        },
                    ),
                )
        return None

    def _coerce_int_field(
        raw: Any,
        field_name: str,
        *,
        blocked_surface: str,
        request: Request,
    ) -> tuple[int | None, JSONResponse | None]:
        """Coerce a JSON body field to int, failing closed as 422.

        VAL-CANON-002: write handlers previously coerced client-controlled
        JSON body fields with a bare ``int()`` (e.g. ``draft_ttl_seconds``,
        ``remediation_round_cap``, ``round``). A non-numeric string made
        ``int()`` raise ``ValueError`` which was unhandled, surfacing as a
        bare HTTP 500 rather than the canonical RELAY-ING-001 422
        ingest-validation envelope that sibling malformed-field rejections
        already emit.

        Returns ``(value, None)`` on success or ``(None, JSONResponse)``
        carrying a canonical RELAY-ING-001 422 envelope when ``raw`` cannot
        be coerced to an int. Only the ``int()`` ``(TypeError, ValueError)``
        is caught; no other error is masked. Booleans are rejected because
        ``int(True)`` would silently coerce to 1 -- a non-int JSON type is a
        malformed field, not a numeric value.

        Codex-review P2: a non-integral JSON number (e.g. ``1.9``, ``0.5``)
        is also rejected. Previously a bare ``int(raw)`` TRUNCATED such a
        float (``1.9 -> 1``, ``0.5 -> 0``), silently accepting malformed
        input, while a non-integral numeric STRING (``"1.9"``) was already
        rejected (``int("1.9")`` raises ``ValueError``). Number and string
        handling are now symmetric: both reject non-integral values. An
        integer-valued number (``1.0``) is still accepted, coerced to its
        exact int.
        """
        if isinstance(raw, bool):
            return None, JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        f"field {field_name!r} MUST be an integer, "
                        "not a boolean"
                    ),
                    blocked_surface=blocked_surface,
                    details={"field": field_name},
                ),
                headers=_rate_limit_headers_for(request),
            )
        # Reject non-integral JSON numbers BEFORE int() so a fractional
        # float is not silently truncated. float.is_integer() is True only
        # for whole-valued floats (1.0, -3.0); NaN/inf return False, so they
        # are rejected too (int(nan) would raise anyway, but rejecting here
        # keeps the message consistent). int subclasses (real JSON integers)
        # are not float, so they skip this branch and pass through unchanged.
        if isinstance(raw, float) and not raw.is_integer():
            return None, JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        f"field {field_name!r} MUST be an integer-valued "
                        "JSON number or numeric string"
                    ),
                    blocked_surface=blocked_surface,
                    details={"field": field_name},
                ),
                headers=_rate_limit_headers_for(request),
            )
        try:
            return int(raw), None
        except (TypeError, ValueError):
            return None, JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message=(
                        f"field {field_name!r} MUST be an integer-valued "
                        "JSON number or numeric string"
                    ),
                    blocked_surface=blocked_surface,
                    details={"field": field_name},
                ),
                headers=_rate_limit_headers_for(request),
            )

    def _canonical_idempotency_key(*, surface: str, user_key: str) -> str:
        """Derive the canonical ULID-grammar idempotency_key.

        Audit fix (2026-05-17 P0): the canonical ``idempotency_records``
        table (packages/schemas/sql/0002_control_plane.sql lines 107-126;
        envelopes.yaml IdempotencyRecord) keys on a Crockford-base32 ULID
        matching ``^[0-9A-HJKMNP-TV-Z]{26}$``. The HTTP layer accepts an
        arbitrary client-supplied Idempotency-Key string; this helper
        compresses ``(surface, user_key)`` into a deterministic 26-char
        Crockford-base32 token suitable as the canonical primary key.

        The first 130 bits of ``sha256(surface || ':' || user_key)`` are
        encoded as 26 Crockford-base32 characters (130 / 5 = 26). The
        ``surface || ':' || user_key`` composition preserves the legacy
        sidecar semantic where the same client Idempotency-Key on two
        distinct endpoints did NOT collide; without the surface prefix the
        canonical PK would alias cross-endpoint reuse, breaking the
        existing replay behavior asserted by the V2M02 W2.9 idempotency
        tests.
        """
        alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        material = (surface + ":" + user_key).encode("utf-8")
        digest = hashlib.sha256(material).digest()
        # Take the leading 17 bytes (136 bits) so we have enough material
        # for 26 base32 chars (130 bits) without padding artefacts.
        leading = int.from_bytes(digest[:17], "big")
        # Shift down to exactly 130 bits.
        leading >>= 136 - 130
        chars: list[str] = []
        for _ in range(26):
            chars.append(alphabet[leading & 0x1F])
            leading >>= 5
        return "".join(reversed(chars))

    # VAL-IDEMP-002: per-request reservation ledger. The winner records the
    # (surface, key) tuples it reserved on the ASGI ``request.scope`` (which
    # is strictly per-request and independent of asyncio task identity --
    # unlike ``asyncio.current_task()``, which is shared when a handler runs
    # inline in the caller's task, e.g. under httpx.ASGITransport). On the
    # success path _store_idempotency finalizes the reservation (sets its
    # event, removes it from ``idempotency_inflight``). On ANY non-store exit
    # path (early-return validation error, raised exception) the
    # _IdempotencyReservationReleaseMiddleware releases every still-pending
    # reservation recorded on the scope: it sets the reservation event (to
    # wake any waiting loser) and removes it from ``idempotency_inflight`` (so
    # a later genuine request with the same key can win and execute). This
    # makes abort handling deterministic instead of relying on wall-clock
    # timeouts or task liveness.
    _IDEMP_SCOPE_LEDGER_KEY = "relay_idempotency_reservations"

    def _reserve_idempotency_for_request(
        request: Request, reservation_key: tuple[str, str]
    ) -> None:
        ledger = request.scope.get(_IDEMP_SCOPE_LEDGER_KEY)
        if ledger is None:
            ledger = []
            request.scope[_IDEMP_SCOPE_LEDGER_KEY] = ledger
        ledger.append(reservation_key)

    def _release_request_idempotency_reservations(scope: Scope) -> None:
        """Release every still-pending reservation recorded on a request
        scope. Called by the release middleware on request completion (any
        exit path). A reservation that was already finalized by
        _store_idempotency is absent from ``idempotency_inflight`` and is
        skipped; a still-present one is an aborted winner -> set its event
        (wake waiting losers) and remove it (free the key)."""
        ledger = scope.get(_IDEMP_SCOPE_LEDGER_KEY)
        if not ledger:
            return
        inflight = runtime.idempotency_inflight
        for reservation_key in ledger:
            reservation = inflight.pop(reservation_key, None)
            if reservation is not None:
                reservation["event"].set()

    async def _check_idempotency(
        request: Request, *, surface: str, body_bytes: bytes
    ) -> tuple[JSONResponse | None, str | None, str | None]:
        """Look up an existing idempotency record.

        Returns (replay_response, key_or_None, digest_or_None):
          - replay_response is non-None if the request is an exact
            replay (same key + same digest) -> caller returns it.
          - replay_response is a 409 JSONResponse if the key matches a
            stored entry but with a different digest -> caller returns.
          - replay_response is None when no record exists -> caller
            proceeds; key + digest are passed back so the success path
            can call ``_store_idempotency``.
        Returns ``(None, None, None)`` when the request did NOT supply
        an idempotency key (no idempotency enforcement applies).

        Audit R3 BUG-A2 (2026-05-18): on a cache miss this helper also
        queries the ``idempotency_records`` table using the SAME
        canonical_key derivation (``_canonical_idempotency_key``) that
        ``_store_idempotency`` uses, so replay semantics survive sidecar
        restart. Pre-fix the writer persisted to DB but the reader only
        consulted the in-memory map; after restart the in-memory map is
        empty and the DB row was unreachable -- replays re-executed.

        V3M2 F03 (spec section B.6 line 3517; VAL-V3M2-006, VAL-V3M2-007):
        when the ``Idempotency-Key`` header is PRESENT we first enforce
        the Crockford-base32 ULID grammar ``^[0-9A-HJKMNP-TV-Z]{26}$``
        BEFORE any canonical hashing (``_canonical_idempotency_key``)
        runs. A present-but-invalid header returns 400 +
        RELAY-IDEMPOTENCY-014 so callers cannot smuggle non-ULID keys
        into the canonical idempotency table (whose primary key is a
        ULID by schema constraint). An ABSENT header (``None``) still
        bypasses idempotency enforcement entirely, preserving the legacy
        "header is optional" contract.
        """
        # Raw header lookup BEFORE strip/normalisation: a present-but-
        # empty header (Idempotency-Key: "") is treated as present-and-
        # invalid (12-case matrix item 1 in VAL-V3M2-006). Missing
        # header (header dict returns None) continues to bypass.
        raw_key = request.headers.get("idempotency-key")
        if raw_key is None:
            return None, None, None
        # Grammar validation runs BEFORE _canonical_idempotency_key
        # (VAL-V3M2-007). Uses re.fullmatch so an embedded newline
        # cannot bypass the anchors via re.match's $-before-newline
        # behavior.
        if _ULID_GRAMMAR_RE.fullmatch(raw_key) is None:
            return (
                JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-IDEMPOTENCY-014",
                        http_status=400,
                        message=(
                            "Idempotency-Key header does not match the "
                            "canonical Crockford-base32 ULID grammar "
                            "^[0-9A-HJKMNP-TV-Z]{26}$ (spec B.6)"
                        ),
                        blocked_surface=surface,
                        details={
                            "header_length": len(raw_key),
                            "expected_pattern": (
                                "^[0-9A-HJKMNP-TV-Z]{26}$"
                            ),
                        },
                    ),
                    headers=_rate_limit_headers_for(request),
                ),
                None,
                None,
            )
        key = raw_key
        digest = _digest_of_bytes(body_bytes)

        def _response_for_existing(record: dict[str, Any]) -> JSONResponse:
            """Build the replay (same digest) or 409 (different digest)
            response for an already-stored idempotency record."""
            if record["request_digest"] == digest:
                return JSONResponse(
                    status_code=record["response_status"],
                    content=record["response_body"],
                    headers={
                        **_rate_limit_headers_for(request),
                        "Idempotent-Replay": "true",
                    },
                )
            return JSONResponse(
                status_code=409,
                content=_build_error_envelope(
                    code="RELAY-IDEMPOTENCY-001",
                    http_status=409,
                    message=(
                        f"Idempotency-Key {key!r} was reused with a "
                        "different request body digest; original "
                        "digest is preserved per spec B.2"
                    ),
                    blocked_surface=surface,
                    details={
                        "key": key,
                        "stored_digest": record["request_digest"],
                        "submitted_digest": digest,
                    },
                ),
                headers=_rate_limit_headers_for(request),
            )

        async def _lookup_existing() -> dict[str, Any] | None:
            """Look up a STORED record (in-memory map first, then the
            DB-backed table). Returns None on a genuine miss."""
            # In-memory map: surface -> {key: {digest, status, body}}.
            store = runtime.idempotency_store.setdefault(surface, {})
            now_s = float(_now_epoch_s())
            rec = store.get(key)
            if rec is not None:
                # Enforce the in-memory TTL on SERVE: an entry past its 24h TTL
                # must be a miss (re-execute) rather than replay a stale
                # response. _prune_idempotency_store only runs after stores, so
                # a hit between prunes could otherwise return an expired record.
                stamp = rec.get(_IDEMPOTENCY_STORED_AT_KEY)
                if (
                    isinstance(stamp, int | float)
                    and (now_s - float(stamp)) > IDEMPOTENCY_RECORD_TTL_S
                ):
                    del store[key]
                    rec = None
            if rec is None:
                # BUG-A2 fix: cache miss falls back to the DB-backed table
                # using the SAME canonical_key derivation as the writer. The DB
                # query already excludes expired rows.
                db_rec = await _lookup_idempotency_db(
                    surface=surface, user_key=key
                )
                if db_rec is not None:
                    # Stamp the hydrated copy with the DB row's real insertion
                    # time (expires_at - TTL) so it expires in-memory exactly
                    # when the DB row does, not 24h later.
                    expires_at = db_rec.pop("expires_at", None)
                    db_rec[_IDEMPOTENCY_STORED_AT_KEY] = _hydrated_stored_at(
                        expires_at, now_s
                    )
                    store[key] = db_rec
                    # Bound the map after hydration too (the store path is not
                    # the only way a record enters the in-memory cache).
                    _prune_idempotency_store(
                        runtime.idempotency_store, now=now_s
                    )
                    # Return the freshly-fetched record even if the size cap
                    # evicted it from the in-memory map: it is a valid (DB
                    # source-of-truth) response, so replay it rather than
                    # re-execute.
                    rec = db_rec
            return rec

        existing = await _lookup_existing()
        if existing is not None:
            return _response_for_existing(existing), key, digest

        # VAL-IDEMP-002: genuine cache miss. Close the check-then-store
        # TOCTOU by RESERVING the (surface, key) atomically before the
        # caller runs the write-handler body. There MUST be no ``await``
        # between observing "no reservation" and inserting our own, so the
        # reserve is atomic within the single-threaded asyncio event loop:
        # a concurrent coroutine cannot interleave and also win the race.
        reservation_key = (surface, key)
        inflight = runtime.idempotency_inflight
        # VAL-IDEMP-002 (test determinism): fire the optional reserve hook at
        # the EXACT check-then-reserve window -- AFTER the cache-miss lookup
        # observed "no record" and BEFORE the synchronous reservation install
        # below. Production leaves the hook None (never awaited). A
        # concurrency test installs an ``asyncio.Barrier(2)`` here so BOTH
        # racing same-(surface, key) coroutines are provably past the lookup
        # and competing for the reservation at the same instant, making the
        # race the reservation loop closes deterministic under any scheduling.
        # This await is OUTSIDE the synchronous reservation loop, so the
        # no-await atomicity of the check-then-reserve itself is preserved.
        reserve_hook = runtime.idempotency_reserve_hook
        if reserve_hook is not None:
            await reserve_hook(reservation_key)
        while True:
            reservation = inflight.get(reservation_key)
            if reservation is None:
                # WINNER: install a pending reservation, then return so the
                # caller executes the handler body exactly once.
                # _store_idempotency finalizes (sets the event, removes the
                # reservation) on the success path; the per-request release
                # ledger (_reserve_idempotency_for_request below + the
                # release middleware) deterministically clears the
                # reservation on ANY exit path -- including an early-return
                # validation error or an exception -- so an aborted winner
                # never wedges the key for a later genuine retry.
                new_reservation = {
                    "event": asyncio.Event(),
                    "digest": digest,
                }
                inflight[reservation_key] = new_reservation
                _reserve_idempotency_for_request(request, reservation_key)
                return None, key, digest

            # LOSER: a concurrent (or prior, not-yet-released) request holds
            # the reservation. Wait for the winner to store its result (the
            # winner sets the event in _store_idempotency) or to release the
            # reservation without storing (an aborted winner -- the release
            # middleware sets the event AND removes the reservation). We
            # never execute the handler body in parallel.
            event: asyncio.Event = reservation["event"]
            await event.wait()
            # The winner finished (stored or aborted). If it stored, the
            # record is now present -> replay (same digest) or 409.
            existing = await _lookup_existing()
            if existing is not None:
                return _response_for_existing(existing), key, digest
            # The winner aborted without storing (the release path sets the
            # event and removes the reservation). The key produced no
            # committed result, so it is free. Loop: either we now win the
            # reservation ourselves and execute, or a newer winner has
            # already taken it and we wait again. This converges because
            # each iteration either stores a result (terminal replay) or
            # consumes exactly one aborted reservation.

    async def _lookup_idempotency_db(
        *, surface: str, user_key: str
    ) -> dict[str, Any] | None:
        """Look up an idempotency record by canonical key on the reader pool.

        Audit R3 BUG-A2 (2026-05-18): shared by ``_check_idempotency``.
        Uses the SAME canonical_key derivation as ``_store_idempotency``
        so the read/write keys are guaranteed to match. Returns the
        same shape as the in-memory map (``request_digest``,
        ``response_status``, ``response_body``) on hit, or None on
        miss / when the DB is unavailable / on any read error (best-
        effort lookup; downstream callers proceed as if cache miss so
        the request is re-executed instead of silently failing).
        """
        db = runtime.database
        if db is None:
            return None
        canonical_key = _canonical_idempotency_key(
            surface=surface, user_key=user_key
        )
        # The idempotency_records table carries a 24h ``expires_at`` (spec B.2);
        # serving a record past its TTL would replay a stale response instead of
        # re-executing. The key is UNIQUE so this returns 0 or 1 row -- fetch it
        # then enforce the TTL by PARSING the timestamp. A lexicographic string
        # compare is UNSAFE across mixed fractional/whole-second RFC3339 forms
        # (e.g. "...00Z" sorts AFTER "...00.5Z"), so an expired row could
        # otherwise compare as live and be replayed.
        now_dt = datetime.now(tz=UTC)
        try:
            reader = db.acquire_reader()
            async with reader.execute(
                "SELECT request_digest, response_status, response_body, "
                "expires_at FROM idempotency_records "
                "WHERE idempotency_key = ?",
                (canonical_key,),
            ) as cur:
                row = await cur.fetchone()
        except Exception:  # noqa: BLE001
            return None
        if row is None:
            return None
        request_digest, response_status, response_body_text, expires_at = row
        # TTL check (parsed, not lexicographic). An expired OR unparseable
        # expires_at is a miss -- re-execute rather than replay a stale/invalid
        # row (matches the corrupted-body handling below).
        try:
            if datetime.fromisoformat(expires_at) <= now_dt:
                return None
        except (TypeError, ValueError):
            return None
        try:
            response_body: Any = (
                json.loads(response_body_text)
                if response_body_text is not None
                else None
            )
        except (TypeError, ValueError):
            # Corrupted body in cache row -- treat as miss so the
            # request re-executes rather than returning garbage.
            return None
        return {
            "request_digest": request_digest,
            "response_status": int(response_status),
            "response_body": response_body,
            # Transient: consumed by _lookup_existing to stamp the hydrated
            # in-memory copy so it expires WHEN the DB row does (popped before
            # the record is cached).
            "expires_at": expires_at,
        }

    async def _store_idempotency(
        *,
        surface: str,
        key: str,
        digest: str,
        response_status: int,
        response_body: Any,
    ) -> None:
        """Persist the (key, surface, digest, response) tuple in memory +
        the SQLite ``idempotency_records`` table with 24h TTL.

        Audit fix (2026-05-17 P0): writes use the canonical column shape
        landed by migration 0021 (idempotency_key ULID PK, project_id,
        schema_version pinned literal, sha256-<hex> request_digest, plus
        the sidecar-only informational columns surface/response_body/
        response_headers). The user-supplied HTTP ``Idempotency-Key`` is
        compressed into the canonical ULID via
        ``_canonical_idempotency_key``; the original header value is
        preserved in the in-memory store keyed by ``key`` for HTTP-layer
        replay-detection symmetry.

        Audit R3 BUG-A1 (2026-05-18 P0): the write is routed through
        ``transactional_db_write_raw`` so it serializes through the SAME
        single-writer queue (and the SAME ``_state_engine_writer_lock``)
        as event_log_entries and compare_and_set_state. The previous
        implementation called ``db._writer.execute(...)`` followed by
        ``db._writer.commit()`` directly. That bypassed keystone
        invariant #8 (the four atomic-persistence primitives) AND raced
        the writer queue + CAS coroutines that share the same aiosqlite
        connection -- SQLite would raise "cannot start a transaction
        within a transaction" when CAS held a BEGIN IMMEDIATE while
        this path issued an implicit-transaction INSERT.

        The raw helper returns ``idempotent=True`` when a row already
        exists with the same canonical_key (its UNIQUE PK collision
        path), which matches the semantics of the previous
        ``INSERT OR REPLACE``: the in-memory cache (above) and a 24h
        TTL together mean the same canonical_key cannot legitimately
        carry a different response, so re-INSERT semantics suffice.
        """
        per_surface = runtime.idempotency_store.setdefault(surface, {})
        per_surface[key] = {
            "request_digest": digest,
            "response_status": response_status,
            "response_body": response_body,
            # DoS hardening: stamp insertion time so the in-memory cache can
            # be TTL-swept and size-capped by _prune_idempotency_store (the
            # DB row carries the SAME 24h TTL). Read only by the prune
            # helper; _response_for_existing ignores it.
            _IDEMPOTENCY_STORED_AT_KEY: _now_epoch_s(),
        }
        # Bound the in-memory cache after every store, mirroring the
        # nonce-store prune (_prune_nonce_store) and the rate-limit bucket
        # sweep (_rate_limit_state). The just-inserted record above is the
        # newest entry, so the size-cap eviction (oldest-first) never drops
        # it and a legitimate immediate replay always finds its result.
        _prune_idempotency_store(
            runtime.idempotency_store, now=float(_now_epoch_s())
        )
        # VAL-IDEMP-002: finalize the in-flight reservation installed by
        # _check_idempotency. The in-memory record is written ABOVE first,
        # so any loser woken by the event immediately finds the stored
        # result and replays it. Removing the reservation and setting its
        # event wakes every waiting loser. Order matters: record-then-
        # signal guarantees a woken loser never observes an empty store.
        reservation = runtime.idempotency_inflight.pop((surface, key), None)
        if reservation is not None:
            reservation["event"].set()
        db = runtime.database
        if db is None:
            return
        try:
            now = datetime.now(tz=UTC)
            # 24h TTL per spec B.2.
            from datetime import timedelta

            first_seen_at = now.isoformat().replace("+00:00", "Z")
            expires_at = (now + timedelta(hours=24)).isoformat().replace(
                "+00:00", "Z"
            )
            body_json = json.dumps(
                response_body, sort_keys=True, separators=(",", ":")
            )
            canonical_key = _canonical_idempotency_key(
                surface=surface, user_key=key
            )
            # Sentinel project_id when the originating request did not
            # resolve a tenant. The canonical schema requires NOT NULL;
            # the sentinel zero-UUID documents the "unauthenticated"
            # case explicitly.
            project_id = "00000000-0000-0000-0000-000000000000"
            row = {
                "idempotency_key": canonical_key,
                "schema_version": "relay.idempotency_record.v1",
                "project_id": project_id,
                "request_digest": digest,
                "response_status": response_status,
                "response_ref": None,
                "first_seen_at": first_seen_at,
                "expires_at": expires_at,
                "surface": surface,
                "response_body": body_json,
                "response_headers": "{}",
            }
            # BUG-A1 fix: route through the writer queue so the write
            # serializes with CAS / event_log / gate_decision writers
            # under ``_state_engine_writer_lock`` (db.py:692). The
            # ``natural_key_column`` is ``idempotency_key`` (the table's
            # PRIMARY KEY); a UNIQUE collision is treated as idempotent
            # (the raw helper returns the prior rowid with
            # idempotent=True) which is exactly what we want for the
            # idempotency cache.
            await db.transactional_db_write_raw(
                table="idempotency_records",
                row=row,
                natural_key=canonical_key,
                natural_key_column="idempotency_key",
            )
        except Exception:  # noqa: BLE001
            # Best-effort: a write failure should NOT lose the in-memory
            # record; tests that probe the DB row will fail loudly which
            # is the correct signal.
            return

    # ---- W2.10 rate-limit middleware (header injection + 429 path) ------
    #
    # Wraps the FastAPI app so every HTTP request receives X-RateLimit-*
    # headers on the way out (both 2xx and non-2xx paths -- VAL-V2M02-075,
    # -076). When a configured bucket is exhausted, returns 429 with the
    # canonical envelope BEFORE the route runs (VAL-V2M02-077..079).
    class _RateLimitMiddleware:
        def __init__(self, asgi_app: ASGIApp, runtime_state: RuntimeState) -> None:
            self.app = asgi_app
            self.runtime = runtime_state

        async def __call__(
            self, scope: Scope, receive: Receive, send: Send
        ) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return
            path = scope.get("path", "")
            method = scope.get("method", "GET").upper()
            # Pick limits by surface class.
            ip = "unknown"
            client = scope.get("client")
            if client and len(client) > 0:
                ip = client[0]
            headers = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in scope.get("headers", [])
            }
            xff = headers.get("x-forwarded-for", "").strip()
            if xff:
                ip = xff.split(",")[0].strip()
            project_hdr = headers.get("x-relay-project", "").strip()
            auth_hdr = headers.get("authorization", "").strip()
            token = None
            if auth_hdr.lower().startswith("bearer "):
                token = auth_hdr.split(None, 1)[1].strip() or None
            project_id = project_hdr or (
                runtime.registered_tokens.get(token, {}).get("project_id")
                if token
                else None
            )
            project_id = project_id or f"ip:{ip}"

            # Choose limits.
            is_verify_route = (
                method == "POST" and path.endswith("/verify")
                and "/v1/evidence-bundles/" in path
            )
            project_limit = _bucket_limit(
                "RELAY_SIDECAR_RATELIMIT_PROJECT_RPS", 100000
            )
            jwt_limit = _bucket_limit(
                "RELAY_SIDECAR_RATELIMIT_JWT_RPS", 100000
            )
            ip_limit = _bucket_limit(
                "RELAY_SIDECAR_RATELIMIT_IP_RPS", 100000
            )

            # Compute bucket consumption. Always consume the per-project
            # bucket; consume per-JWT only when a token is present;
            # consume per-IP only on the verify route (or fall through).
            limits: list[tuple[str, int, str]] = []
            if is_verify_route:
                # Public verify route -> per-IP only.
                limits.append((f"ip:{ip}:verify", ip_limit, "RELAY-RATE-014"))
            else:
                limits.append(
                    (f"project:{project_id}", project_limit, "RELAY-RATE-001")
                )
                if token:
                    limits.append(
                        (f"jwt:{token}", jwt_limit, "RELAY-RATE-001")
                    )

            best_remaining = None
            best_limit = 0
            best_reset = _now_epoch_s() + 1
            failing_code: str | None = None
            for bucket_key, lim, code in limits:
                lim_v, remaining, reset_epoch = _rate_limit_state(
                    bucket_key, lim
                )
                if remaining == 0 and lim_v <= 0:
                    pass
                if best_remaining is None or remaining < best_remaining:
                    best_remaining = remaining
                    best_limit = lim_v
                    best_reset = reset_epoch
                if remaining < 0 or (lim_v > 0 and (lim_v + 1) <= 0):
                    failing_code = code
                # remaining < 0 cannot happen with max(0, ...); detect
                # exhaustion as remaining == 0 AND the bucket would have
                # exceeded on this call. We over-count by 1 to know;
                # since we compute remaining = max(0, lim - count) after
                # increment, the exhaustion check is: count > lim.
                # That happens when remaining == 0 AND lim - count < 0,
                # which the helper cannot return directly. We therefore
                # re-derive:
                window_start, count = self.runtime.rate_limit_buckets[
                    bucket_key
                ]
                if count > lim_v:
                    failing_code = code

            if best_remaining is None:
                best_remaining = 999999
                best_limit = 1000000
            rl_headers = {
                "X-RateLimit-Limit": str(best_limit),
                "X-RateLimit-Remaining": str(best_remaining),
                "X-RateLimit-Reset": str(best_reset),
            }

            if failing_code is not None:
                # 429 path.
                envelope = _build_error_envelope(
                    code=failing_code,
                    http_status=429,
                    message=(
                        f"rate limit exceeded for bucket; retry after "
                        f"{best_reset - _now_epoch_s()}s"
                    ),
                    blocked_surface=f"{method} {path}",
                    retry_advice="retry_after",
                )
                response = JSONResponse(
                    status_code=429,
                    content=envelope,
                    headers={
                        **rl_headers,
                        "Retry-After": str(
                            max(1, best_reset - _now_epoch_s())
                        ),
                    },
                )
                await response(scope, receive, send)
                return

            # Stash the snapshot so handlers can re-emit headers on their
            # own JSONResponse instances (for the early auth-fail path).
            # The standard send-wrapper below also injects headers.
            async def send_wrapper(message: MutableMapping[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    existing = message.get("headers", [])
                    # Drop any pre-existing X-RateLimit headers so the
                    # middleware is authoritative.
                    filtered = [
                        (k, v)
                        for k, v in existing
                        if k.decode("latin-1").lower()
                        not in (
                            "x-ratelimit-limit",
                            "x-ratelimit-remaining",
                            "x-ratelimit-reset",
                        )
                    ]
                    for hk, hv in rl_headers.items():
                        filtered.append(
                            (hk.encode("latin-1"), hv.encode("latin-1"))
                        )
                    message["headers"] = filtered
                await send(message)

            # Bind snapshot to the request scope state if FastAPI has
            # populated it; otherwise rely on send_wrapper.
            state_snap = scope.setdefault("state", {})
            state_snap["_relay_ratelimit_snapshot"] = {
                "limit": best_limit,
                "remaining": best_remaining,
                "reset": best_reset,
            }

            await self.app(scope, receive, send_wrapper)

    app.add_middleware(_RateLimitMiddleware, runtime_state=runtime)
    # VAL-IDEMP-002: release any idempotency reservation left pending when a
    # request finishes (aborted winner / exception path). Added LAST so it is
    # the OUTERMOST middleware -- its ``finally`` runs after the route and the
    # inner middlewares, guaranteeing the reservation is released on every
    # exit path before the response leaves the process.
    app.add_middleware(
        _IdempotencyReservationReleaseMiddleware,
        release=_release_request_idempotency_reservations,
    )

    # =====================================================================
    # W2.5 Gates endpoints (VAL-V2M02-037..048)
    # =====================================================================

    @app.put("/v1/gates/{gate_id}")
    async def v1_put_gate(gate_id: str, request: Request) -> JSONResponse:
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in gate_id
        # BEFORE auth, idempotency hashing, and body parsing.
        id_reject = _validate_id_field(
            gate_id, "gate_id", blocked_surface=_GATE_CONFIGURE_SURFACE
        )
        if id_reject is not None:
            return id_reject
        auth_reject = _check_auth(
            request,
            required_scope="gates:configure",
            blocked_surface=_GATE_CONFIGURE_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        # VAL-IDEMP-001: the idempotency surface MUST carry the resolved
        # path parameter (the concrete gate_id), not the un-interpolated
        # "{gate_id}" template. The canonical idempotency key derives the
        # ONLY gate-distinguishing material from the surface string; passing
        # the literal template aliases every gate_id to a single key, so a
        # write to gate B is wrongly replayed as gate A's. Folding the
        # concrete gate_id in keeps distinct gates distinct while a genuine
        # retry of the SAME gate still collides (idempotent replay).
        idemp_surface = f"PUT /v1/gates/{gate_id}"
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request, surface=idemp_surface, body_bytes=body_bytes
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_GATE_CONFIGURE_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_GATE_CONFIGURE_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        existed = gate_id in runtime.gates
        # VAL-CANON-002: coerce client-controlled int body fields through
        # _coerce_int_field so a non-numeric value fails closed as a
        # canonical RELAY-ING-001 422 instead of an unhandled ValueError
        # (bare HTTP 500).
        draft_ttl_seconds, ttl_reject = _coerce_int_field(
            body.get("draft_ttl_seconds", 900),
            "draft_ttl_seconds",
            blocked_surface=_GATE_CONFIGURE_SURFACE,
            request=request,
        )
        if ttl_reject is not None:
            return ttl_reject
        remediation_round_cap, cap_reject = _coerce_int_field(
            body.get("remediation_round_cap", 5),
            "remediation_round_cap",
            blocked_surface=_GATE_CONFIGURE_SURFACE,
            request=request,
        )
        if cap_reject is not None:
            return cap_reject
        # Audit-R3 (2026-05-18): drop made-up wire-level schema_version
        # "relay.gate.v1" (not in KNOWN_SCHEMA_IDS / envelopes.yaml /
        # openapi.yaml). Gates are internal configuration objects, not a
        # canonical persisted envelope. Wire responses no longer surface
        # a schema_version literal for this endpoint.
        record = {
            "gate_id": gate_id,
            "name": body.get("name", gate_id),
            "scope_type": body.get("scope_type", "run"),
            "enabled": bool(body.get("enabled", True)),
            "draft_ttl_seconds": draft_ttl_seconds,
            "remediation_round_cap": remediation_round_cap,
            "cascade_on_block": bool(body.get("cascade_on_block", True)),
            "written_by": "control_plane",
            "updated_at": _now_iso_z(),
        }
        runtime.gates[gate_id] = record
        status = 200 if existed else 201
        resp_body = {
            "gate_id": gate_id,
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=idemp_surface,
                key=idemp_key,
                digest=idemp_digest,
                response_status=status,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=status,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.put("/v1/gate-policies/{policy_id}")
    async def v1_put_gate_policy(
        policy_id: str, request: Request
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="gates:configure",
            blocked_surface=_GATE_POLICY_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        # VAL-IDEMP-001: fold the resolved policy_id into the idempotency
        # surface so two distinct policies never alias the same idempotency
        # record (the un-interpolated "{policy_id}" template aliased them).
        idemp_surface = f"PUT /v1/gate-policies/{policy_id}"
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request, surface=idemp_surface, body_bytes=body_bytes
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_GATE_POLICY_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        existed = policy_id in runtime.gate_policies
        record = {
            "schema_version": "relay.gate_policy.v1",
            "gate_policy_id": policy_id,
            "gate_id": body.get("gate_id"),
            "policy_version": body.get("policy_version", "v1"),
            "conditions": body.get("conditions", []),
            "blocking_severity": body.get("blocking_severity", "p0_only"),
            "effective_at": body.get("effective_at", _now_iso_z()),
            "written_by": "control_plane",
        }
        runtime.gate_policies[policy_id] = record
        status = 200 if existed else 201
        resp_body = {
            "policy_id": policy_id,
            "schema_version": "relay.gate_policy.v1",
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=idemp_surface,
                key=idemp_key,
                digest=idemp_digest,
                response_status=status,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=status,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.post("/v1/gates/{gate_id}/drafts")
    async def v1_post_gate_draft(
        gate_id: str, request: Request
    ) -> JSONResponse:
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in gate_id
        # BEFORE auth, idempotency hashing, and body parsing.
        id_reject = _validate_id_field(
            gate_id, "gate_id", blocked_surface=_GATE_DRAFT_SURFACE
        )
        if id_reject is not None:
            return id_reject
        auth_reject = _check_auth(
            request,
            required_scope="gates:execute",
            blocked_surface=_GATE_DRAFT_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        # VAL-IDEMP-001: _GATE_DRAFT_SURFACE is the un-interpolated template
        # "POST /v1/gates/{gate_id}/drafts" (line 3007); the concrete gate_id
        # was never substituted before the surface reached
        # _canonical_idempotency_key. Because the surface is the only
        # gate-distinguishing material in the key derivation, distinct gates
        # (POST /v1/gates/A/drafts vs .../B/drafts) computed the SAME key, so
        # gate B's draft was wrongly replayed as gate A's. Fold the resolved
        # gate_id into the surface: distinct gates -> distinct keys, while a
        # genuine retry of the same gate still collides (idempotent replay).
        idemp_surface = f"POST /v1/gates/{gate_id}/drafts"
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request, surface=idemp_surface, body_bytes=body_bytes
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_GATE_DRAFT_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        # Three-anchor handoff validation (VAL-V2M02-043, keystone #4).
        manifest_commit_hash = body.get("manifest_commit_hash")
        actor_identity_hash = body.get("actor_identity_hash")
        if not isinstance(manifest_commit_hash, str) or not manifest_commit_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-GATE-021",
                    http_status=422,
                    message="manifest_commit_hash MUST be a non-empty string",
                    blocked_surface=_GATE_DRAFT_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        if not isinstance(actor_identity_hash, str) or not actor_identity_hash:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-GATE-021",
                    http_status=422,
                    message="actor_identity_hash MUST be a non-empty string",
                    blocked_surface=_GATE_DRAFT_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        # VAL-ISO-025: a ``handoff_stale`` body flag used to short-circuit
        # to RELAY-GATE-021 here. That was a client-triggerable control-flow
        # backdoor -- any caller could force the stale-handoff rejection
        # path from the request body, independent of the actual anchor
        # validity. It has been REMOVED. The genuine stale path is the
        # three-anchor mismatch detected unconditionally by
        # ``validate_three_anchor_handoff`` below (RELAY-GATE-021 with a
        # structured reason of ACTOR_NOT_REGISTERED / MANIFEST_NOT_ACTIVE /
        # SCOPE_ID_MISMATCH). Tests exercise the stale path by seeding the
        # actors/manifest_versions registries to a genuinely-stale state,
        # not by a client-settable flag.
        #
        # VAL-ISO-003 (fail closed) + audit fix (2026-05-17 P0): per
        # CLAUDE.md keystone #4 + spec C.5, every gate-draft submission MUST
        # consult the actors + manifest_versions registries. The prior
        # implementation only ran ``validate_three_anchor_handoff`` when
        # BOTH tables were already non-empty (``actors_seeded and
        # manifests_seeded``); on an unseeded DB it SKIPPED validation and
        # accepted whatever actor/manifest anchors the body carried -- a
        # silent bypass of the three-anchor handoff. There is no fallback
        # skip path: the validator runs UNCONDITIONALLY and already fails
        # closed for empty registries (an empty ``actors`` table yields
        # ACTOR_NOT_REGISTERED; an empty ``manifest_versions`` table yields
        # MANIFEST_NOT_ACTIVE). A missing database connection is itself a
        # state in which the handoff cannot be validated, so it also fails
        # closed rather than accepting an unvalidatable submission.
        db = runtime.database
        if db is None:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-GATE-021",
                    http_status=422,
                    message=(
                        "three-anchor handoff cannot be validated: the "
                        "control-plane registries are unavailable "
                        "(keystone invariant #4 -- fail closed)"
                    ),
                    blocked_surface=_GATE_DRAFT_SURFACE,
                    details={
                        "reason": "registry_unavailable",
                        "manifest_commit_hash": manifest_commit_hash,
                        "actor_identity_hash": actor_identity_hash,
                    },
                ),
                headers=_rate_limit_headers_for(request),
            )
        reader = db.acquire_reader()
        handoff_result = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="gate_round",
            scope_id=gate_id,
            payload={
                "actor_identity_hash": actor_identity_hash,
                "manifest_commit_hash": manifest_commit_hash,
            },
        )
        if not handoff_result.ok:
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-GATE-021",
                    http_status=422,
                    message=(
                        "three-anchor handoff rejected: "
                        f"{handoff_result.reason}"
                    ),
                    blocked_surface=_GATE_DRAFT_SURFACE,
                    details={
                        "reason": handoff_result.reason,
                        "manifest_commit_hash": manifest_commit_hash,
                        "actor_identity_hash": actor_identity_hash,
                        "valid_reasons": [
                            SCOPE_ID_MISMATCH,
                            ACTOR_NOT_REGISTERED,
                            MANIFEST_NOT_ACTIVE,
                        ],
                    },
                ),
                headers=_rate_limit_headers_for(request),
            )
        worker_id = body.get("worker_id") or "worker-default"
        # VAL-CANON-002: a non-numeric ``round`` must fail closed as a
        # canonical RELAY-ING-001 422 rather than an unhandled ValueError.
        round_n, round_reject = _coerce_int_field(
            body.get("round", 1),
            "round",
            blocked_surface=_GATE_DRAFT_SURFACE,
            request=request,
        )
        if round_reject is not None:
            return round_reject
        # round_reject is None implies a successful coercion, so round_n is
        # a concrete int (narrowing for the type checker / dict-key types).
        assert round_n is not None
        gate_cfg = runtime.gates.get(gate_id, {})
        # VAL-CANON-002: gate_cfg["draft_ttl_seconds"] is normally an int
        # (v1_put_gate now coerces it via _coerce_int_field), but wrap the
        # read defensively so a non-int stored value can never escalate to
        # an unhandled ValueError (bare HTTP 500); fail closed as 422.
        draft_ttl, ttl_reject = _coerce_int_field(
            gate_cfg.get("draft_ttl_seconds", 900),
            "draft_ttl_seconds",
            blocked_surface=_GATE_DRAFT_SURFACE,
            request=request,
        )
        if ttl_reject is not None:
            return ttl_reject
        # ttl_reject is None implies a successful coercion, so draft_ttl is a
        # concrete int (narrowing for the type checker before the arithmetic
        # in the TTL-expiry comparison below).
        assert draft_ttl is not None
        # VAL-ISO-026: the active-draft conflict map
        # ``runtime.gate_drafts_active`` was written when a draft was
        # created and read to reject a second worker (RELAY-GATE-014) but
        # NEVER cleared -- so once a draft for (gate_id, round) was
        # recorded, any DIFFERENT worker was rejected forever (perma-block)
        # and the map leaked one entry per distinct (gate_id, round). Treat
        # an entry whose TTL has elapsed (``submitted_at_epoch +
        # draft_ttl_seconds < now``) as ABSENT: the round is effectively
        # closed once its draft window expires, so a new worker must be
        # admitted. We compare integer epochs (not RFC3339 strings, cf.
        # VAL-CANON-004) to avoid serializer-mismatch hazards. The active
        # entry is also superseded below when the same round is
        # (re)submitted, so resolution clears the prior record rather than
        # leaving it pending indefinitely.
        now_epoch = _now_epoch_s()
        # Conflict detection: same (gate_id, round) from a different worker
        # while an earlier, NON-EXPIRED draft is still pending ->
        # 409 RELAY-GATE-014.
        active = runtime.gate_drafts_active.get((gate_id, round_n))
        if active is not None:
            submitted_epoch = active.get("submitted_at_epoch")
            expired = (
                isinstance(submitted_epoch, int)
                and (submitted_epoch + draft_ttl) < now_epoch
            )
            if expired:
                # Round window closed: clear the stale entry so a new
                # worker is not perma-blocked, then fall through to create
                # a fresh draft.
                del runtime.gate_drafts_active[(gate_id, round_n)]
                active = None
        if active is not None and active.get("worker_id") != worker_id:
            return JSONResponse(
                status_code=409,
                content=_build_error_envelope(
                    code="RELAY-GATE-014",
                    http_status=409,
                    message=(
                        f"a draft for gate {gate_id!r} round {round_n} is "
                        f"already pending from worker {active['worker_id']!r}"
                    ),
                    blocked_surface=_GATE_DRAFT_SURFACE,
                    details={
                        "existing_worker_id": active["worker_id"],
                        "submitted_worker_id": worker_id,
                        "round": round_n,
                    },
                ),
                headers=_rate_limit_headers_for(request),
            )
        draft_id = f"draft-{uuid.uuid4().hex}"
        gate_round_id = f"round-{uuid.uuid4().hex}"
        draft_record = {
            "schema_version": "relay.gate_decision_draft.v1",
            "draft_id": draft_id,
            "gate_id": gate_id,
            "gate_round_id": gate_round_id,
            "round": round_n,
            "worker_id": worker_id,
            "manifest_commit_hash": manifest_commit_hash,
            "actor_identity_hash": actor_identity_hash,
            "submitted_at": _now_iso_z(),
            "submitted_at_epoch": now_epoch,
            "written_by": "control_plane",
            "resolution_state": "pending",
        }
        runtime.gate_drafts[draft_id] = draft_record
        runtime.gate_drafts_active[(gate_id, round_n)] = draft_record
        # Track the round under the gate for VAL-V2M02-047.
        runtime.gate_rounds.setdefault(gate_id, []).append(
            {
                "schema_version": "relay.gate_round.v1",
                "gate_round_id": gate_round_id,
                "gate_id": gate_id,
                "round": round_n,
                "initiated_by": "control_plane",
                "opened_at": _now_iso_z(),
                "closed_at": None,
                "written_by": "control_plane",
            }
        )
        resp_body = {
            "draft_id": draft_id,
            "gate_round_id": gate_round_id,
            "await_url": f"/v1/gate-decisions/{draft_id}",
            "draft_ttl_seconds": draft_ttl,
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=idemp_surface,
                key=idemp_key,
                digest=idemp_digest,
                response_status=202,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=202,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/gate-decisions/{decision_id}")
    async def v1_get_gate_decision(
        decision_id: str, request: Request
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_GATE_DECISION_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        record = runtime.gate_decisions.get(decision_id)
        if record is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=f"gate_decision {decision_id!r} not found",
                    blocked_surface=_GATE_DECISION_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        return JSONResponse(
            status_code=200,
            content=record,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/gates/{gate_id}/rounds")
    async def v1_list_gate_rounds(
        gate_id: str,
        request: Request,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JSONResponse:
        # V3M5 F03 (VAL-V3M5-008): reject banned code points in gate_id.
        id_reject = _validate_id_field(
            gate_id, "gate_id", blocked_surface=_GATE_ROUNDS_SURFACE
        )
        if id_reject is not None:
            return id_reject
        auth_reject = _check_auth(
            request,
            required_scope="gates:configure",
            blocked_surface=_GATE_ROUNDS_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        # limit validation per VAL-V2M02-071.
        try:
            limit_i = int(limit)
        except (TypeError, ValueError):
            limit_i = -1
        if limit_i <= 0:
            return JSONResponse(
                status_code=400,
                content=_build_error_envelope(
                    code="RELAY-PAGE-001",
                    http_status=400,
                    message=(
                        f"limit must be a positive integer; got {limit!r}"
                    ),
                    blocked_surface=_GATE_ROUNDS_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        effective_limit = min(limit_i, 500)
        offset = 0
        if cursor is not None:
            payload, err = _verify_cursor_ttl(cursor)
            if err == "expired":
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-EXPIRED",
                        http_status=400,
                        message="cursor expired (1h TTL exceeded)",
                        blocked_surface=_GATE_ROUNDS_SURFACE,
                    ),
                    headers=_rate_limit_headers_for(request),
                )
            if err == "tampered" or payload is None:
                return JSONResponse(
                    status_code=400,
                    content=_build_error_envelope(
                        code="RELAY-PAGE-001",
                        http_status=400,
                        message="cursor signature invalid (tampered)",
                        blocked_surface=_GATE_ROUNDS_SURFACE,
                    ),
                    headers=_rate_limit_headers_for(request),
                )
            offset = int(payload.get("offset", 0))
        all_rounds = list(runtime.gate_rounds.get(gate_id, []))
        page = all_rounds[offset : offset + effective_limit + 1]
        has_more = len(page) > effective_limit
        items = page[:effective_limit]
        next_cursor: str | None = None
        if has_more:
            next_cursor = _sign_cursor_ttl(
                {"gate_id": gate_id, "offset": offset + effective_limit}
            )
        return JSONResponse(
            status_code=200,
            content={
                "items": items,
                "next_cursor": next_cursor,
                "has_more": has_more,
            },
            headers=_rate_limit_headers_for(request),
        )

    # =====================================================================
    # W2.6 Evidence-bundle endpoints (VAL-V2M02-049..056)
    # =====================================================================

    @app.post("/v1/evidence-bundles")
    async def v1_create_evidence_bundle(
        request: Request,
    ) -> JSONResponse:
        # Audit fix (2026-05-17 P0): POST is a WRITE operation; the
        # prior implementation incorrectly required ``evidence:read``
        # for a CREATE. The canonical scope for writing evidence
        # bundles is ``evidence:write``.
        auth_reject = _check_auth(
            request,
            required_scope="evidence:write",
            blocked_surface=_EVIDENCE_CREATE_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request,
            surface=_EVIDENCE_CREATE_SURFACE,
            body_bytes=body_bytes,
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_EVIDENCE_CREATE_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        bundle_id = f"eb-{uuid.uuid4().hex}"
        # Audit fix (2026-05-17 P0): align response shape with the
        # canonical EvidenceBundle envelope (envelopes.yaml:371-404,
        # Pydantic at envelopes.py:811-837). Field renames:
        # ``bundle_id`` -> ``evidence_bundle_id``,
        # ``digest`` -> ``bundle_digest``,
        # ``scope_kind`` -> ``scope_type``.
        # Required-fields backfilled with sensible defaults so the OSS
        # in-memory record round-trips the canonical shape until the
        # hosted signer + DPA approver land in M03+. Legacy aliases
        # (``bundle_id``, ``digest``, ``scope_kind``) are ALSO mirrored
        # on the in-memory record so download / verify / existing CLI
        # consumers keep working through the canonical-rename transition.
        bundle_payload = {
            "schema_version": "relay.evidence_bundle.v1",
            "evidence_bundle_id": bundle_id,
            "org_id": body.get(
                "org_id", "00000000-0000-0000-0000-000000000000"
            ),
            "project_id": body.get(
                "project_id", "00000000-0000-0000-0000-000000000000"
            ),
            "scope_type": body.get("scope_type", body.get("scope_kind", "run")),
            "scope_id": body.get("scope_id", ""),
            "acef_core_version": "0.3.0",
            "relay_extension_version": "v1",
            "verification_status": "unverified",
            "redaction_policy_version": body.get(
                "redaction_policy_version", "local-dev"
            ),
            "object_ref": f"local://{bundle_id}.tar.gz",
            "claims": body.get("claims", []),
            "signer_key_id": body.get("signer_key_id", "key-local-dev"),
            "trust_anchor": "https://relay.epochly.com/.well-known/jwks.json",
            "signatures": [
                {
                    "signer_key_id": body.get(
                        "signer_key_id", "key-local-dev"
                    ),
                    "algorithm": "ed25519",
                    "value": (
                        "sig-"
                        + hashlib.sha256(bundle_id.encode()).hexdigest()[:32]
                    ),
                    "valid": True,
                }
            ],
            "written_by": "control_plane",
            "created_at": _now_iso_z(),
        }
        canonical = json.dumps(
            bundle_payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        # Audit fix (2026-05-17 P0): canonical sha256 wire form is the
        # hyphen prefix per VAL-W1-009 / envelopes.yaml.
        digest = _sha256_canonical(canonical)
        bundle_payload["bundle_digest"] = digest
        bundle_payload["claims_count"] = len(bundle_payload["claims"])
        bundle_payload["state"] = body.get("state", "signed")
        # Legacy aliases (in-memory only) for back-compat during the
        # canonical-rename transition.
        bundle_payload["bundle_id"] = bundle_id
        bundle_payload["digest"] = digest
        bundle_payload["scope_kind"] = bundle_payload["scope_type"]
        runtime.evidence_bundles[bundle_id] = bundle_payload
        # Persist the raw canonical bytes so /download can serve them.
        runtime.evidence_bundle_blobs[bundle_id] = canonical
        resp_body = {
            "evidence_bundle_id": bundle_id,
            "bundle_digest": digest,
            # Legacy aliases on the response for back-compat during
            # the canonical-rename transition.
            "bundle_id": bundle_id,
            "digest": digest,
            "await_url": f"/v1/evidence-bundles/{bundle_id}",
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=_EVIDENCE_CREATE_SURFACE,
                key=idemp_key,
                digest=idemp_digest,
                response_status=201,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=201,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/evidence-bundles/{bundle_id}")
    async def v1_get_evidence_bundle(
        bundle_id: str, request: Request
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="evidence:read",
            blocked_surface=_EVIDENCE_GET_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        record = runtime.evidence_bundles.get(bundle_id)
        if record is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=f"evidence_bundle {bundle_id!r} not found",
                    blocked_surface=_EVIDENCE_GET_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        if record.get("state") == "tombstoned":
            return JSONResponse(
                status_code=410,
                content=_build_error_envelope(
                    code="RELAY-EVID-001",
                    http_status=410,
                    message=(
                        f"evidence_bundle {bundle_id!r} is tombstoned under "
                        "retention or legal hold"
                    ),
                    blocked_surface=_EVIDENCE_GET_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        return JSONResponse(
            status_code=200,
            content=record,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/evidence-bundles/{bundle_id}/download")
    async def v1_download_evidence_bundle(
        bundle_id: str, request: Request
    ) -> Any:
        from starlette.responses import Response

        auth_reject = _check_auth(
            request,
            required_scope="evidence:read",
            blocked_surface=_EVIDENCE_DOWNLOAD_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        blob = runtime.evidence_bundle_blobs.get(bundle_id)
        if blob is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=f"evidence_bundle {bundle_id!r} not found",
                    blocked_surface=_EVIDENCE_DOWNLOAD_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        return Response(
            content=blob,
            status_code=200,
            media_type="application/gzip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{bundle_id}.tar.gz"'
                ),
                **_rate_limit_headers_for(request),
            },
        )

    @app.post("/v1/evidence-bundles/{bundle_id}/verify")
    async def v1_verify_evidence_bundle(
        bundle_id: str, request: Request
    ) -> JSONResponse:
        # PUBLIC endpoint: no auth required per VAL-V2M02-055.
        record = runtime.evidence_bundles.get(bundle_id)
        if record is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=f"evidence_bundle {bundle_id!r} not found",
                    blocked_surface=_EVIDENCE_VERIFY_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        # Fail-honest / fail-closed (VAL-CRYPTO-006, VAL-CRYPTO-007).
        #
        # This is the documented local OSS sidecar stub. It does NOT hold
        # trust-anchor key material and does NOT perform offline JWS/ed25519
        # verification (the real verifier lives in ``packages/verifier`` and
        # the hosted control plane). Issued bundles carry a fabricated
        # ``sig-<sha256-prefix>`` value and ``verification_status:
        # "unverified"`` (set at create time). It is therefore dishonest for
        # this route to ever report ``signatures_ok: true`` -- doing so would
        # let a consumer treat an un-cryptographically-verified bundle as
        # verified, breaching keystone invariants #2 ("pass without evidence
        # is not a pass") and #11 (trust anchor). We surface the unverified
        # state explicitly instead of stamping green.
        #
        # ``digest_ok`` is an INTEGRITY check, not a signature check: we
        # re-serialize the CURRENT live record (excluding the mutable
        # digest/claims_count/state/legacy-alias fields that were tacked on
        # after the digest was computed) and compare to the recorded
        # ``bundle_digest``. This detects divergence between the live record
        # and its claimed digest -- unlike the prior tautology which
        # re-hashed the same immutable stored bytes the digest was taken from.
        body = await _parse_verify_body(request)
        tampered = bool(body.get("tampered"))

        recomputed = _recompute_bundle_digest(record)
        recorded_digest = record.get("bundle_digest") or record.get("digest")
        digest_ok = (
            recomputed is not None and recomputed == recorded_digest
        )

        # Signatures: NEVER green without real cryptographic verification.
        # The OSS stub performs none, so signatures_ok is always false here
        # (and explicitly so when the caller asserts ``tampered``).
        signatures_reason = (
            "signature validation failed"
            if tampered
            else (
                "OSS local sidecar does not perform cryptographic signature "
                "verification; use the offline verifier (packages/verifier) "
                "or the hosted control plane to verify signatures"
            )
        )
        sigs_checked: list[dict[str, Any]] = []
        for sig in record.get("signatures", []):
            sigs_checked.append(
                {
                    "signer_key_id": sig.get("signer_key_id"),
                    "algorithm": sig.get("algorithm", "ed25519"),
                    # Fail-closed boolean (codex-review verify-signatures-ok-
                    # false). The OSS stub performs NO cryptographic
                    # verification, so a signature is never proven valid here.
                    # ``valid`` MUST be a concrete boolean ``false`` -- never
                    # ``null``: the verifier-output schema
                    # (packages/schemas/raw/verifier-output.yaml) declares the
                    # per-signature verdict (``ok``) as a required boolean, and
                    # ``null`` is neither schema-conformant nor fail-closed (a
                    # consumer's boolean check would treat null as falsy by
                    # luck, not by contract). The honest "not verified here"
                    # signal lives in ``verification_status: unverified`` and
                    # ``failure_reason`` below, not in a null tri-state.
                    "valid": False,
                    "failure_reason": signatures_reason,
                }
            )
        # Fail-closed: an unverified bundle reports ``signatures_ok: false``
        # (a real JSON boolean), never ``null`` (keystone invariants #2/#11).
        signatures_ok = False

        verify_result = {
            "bundle_id": bundle_id,
            "verifier_engine_version": __version__,
            # The bundle was never cryptographically verified by this route.
            # Closed enum per VAL-W1-019: unverified|verified|tampered|revoked.
            "verification_status": "tampered" if tampered else "unverified",
            "structure_ok": True,
            "digest_ok": digest_ok,
            "signatures_ok": signatures_ok,
            "signatures_reason": signatures_reason,
            "signatures_checked": sigs_checked,
            "claims_count": record.get("claims_count", 0),
        }
        return JSONResponse(
            status_code=200,
            content=verify_result,
            headers=_rate_limit_headers_for(request),
        )

    # =====================================================================
    # W2.7 Manifest endpoints (VAL-V2M02-057..060)
    # =====================================================================

    @app.post("/v1/manifests")
    async def v1_create_manifest(request: Request) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="gates:configure",
            blocked_surface=_MANIFEST_CREATE_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request,
            surface=_MANIFEST_CREATE_SURFACE,
            body_bytes=body_bytes,
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_MANIFEST_CREATE_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        # commit_hash = sha256 of canonical body JSON.
        # Audit fix (2026-05-17 P0): canonical sha256 wire form is the
        # hyphen prefix per VAL-W1-009 / envelopes.yaml AND the
        # manifest_versions CHECK constraint at migration 0006:75-76
        # ``commit_hash LIKE 'sha256-%'`` rejects the colon form.
        canonical = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        commit_hash = _sha256_canonical(canonical)
        manifest_id = body.get("manifest_id") or f"mfst-{uuid.uuid4().hex}"

        # Parse the declared command_hashes from the body up front (pure
        # parse, no side effects). They are registered in-memory below, AFTER
        # the durable write succeeds. The list is filtered to the sha256-
        # wire form so the later register_commands call cannot raise on it.
        commands = body.get("commands") or []
        declared_hashes: list[str] = []
        if isinstance(commands, list):
            for cmd in commands:
                if isinstance(cmd, dict):
                    ch = cmd.get("command_hash")
                    if isinstance(ch, str) and ch.startswith("sha256-"):
                        declared_hashes.append(ch)

        # F5 (manifest persistence): persist the ManifestVersion anchor row to
        # ``manifest_versions`` FIRST, as the durable gate, so the DB-backed
        # three-anchor handoff lookup (handoff._manifest_is_active_or_in_grace)
        # can find it (keystone invariant #4). The prior implementation
        # registered the manifest in memory and then wrapped this write in
        # ``contextlib.suppress(Exception)``: a failed write returned HTTP 201
        # with the commit_hash while the DB row was absent -- an in-memory/DB
        # split-brain (GET worked via the in-memory views, but the handoff
        # lookup found nothing). We now make durable persistence the gate: on
        # failure we surface a structured 5xx and register NOTHING in memory,
        # so there is no split-brain in either direction.
        manifest_version_id = f"mv-{uuid.uuid4().hex}"
        db = runtime.database
        write_result = None
        if db is not None:
            try:
                write_result = await db.transactional_db_write_raw(
                    table="manifest_versions",
                    row={
                        "manifest_version_id": manifest_version_id,
                        "manifest_id": manifest_id,
                        "project_id": (
                            body.get("project_id", "") or "default"
                        ),
                        "commit_hash": commit_hash,
                        "schema_version": "relay.manifest.v1",
                        "effective_at": _now_iso_z(),
                    },
                    natural_key=commit_hash,
                    natural_key_column="commit_hash",
                )
            except RelaySQLiteBusyExhausted as exc:
                # SQLITE_BUSY budget exhausted -> registered RELAY-SQLITE-001
                # (503). We build the CANONICAL ErrorEnvelope here rather than
                # re-raising to the global RelaySQLiteBusyExhausted handler:
                # that handler returns ``exc.to_envelope()``, which is NOT a
                # canonical ErrorEnvelope (it omits schema_version/
                # blocked_surface/retry_advice/request_id/trace_id and carries
                # the forbidden ``error_class`` field, which the closed
                # ErrorEnvelope schema rejects). Nothing is registered in
                # memory yet, so there is no split-brain.
                return JSONResponse(
                    status_code=exc.http_status,
                    content=_build_error_envelope(
                        code=exc.code,
                        http_status=exc.http_status,
                        message=exc.message,
                        blocked_surface=_MANIFEST_CREATE_SURFACE,
                        retry_advice="after_retry_after",
                        details={
                            "manifest_id": manifest_id,
                            "commit_hash": commit_hash,
                            "attempts": exc.attempts,
                        },
                    ),
                    # retry_advice=after_retry_after MUST be backed by a real
                    # Retry-After header (roborev e19ec7c). SQLite-busy is a
                    # transient write-contention condition; advise a 1 s backoff.
                    headers={**_rate_limit_headers_for(request), "Retry-After": "1"},
                )
            except RelayDiskFullError as exc:
                # ENOSPC mid-write -> registered RELAY-SIDECAR-011 (507).
                return JSONResponse(
                    status_code=exc.http_status,
                    content=_build_error_envelope(
                        code=exc.code,
                        http_status=exc.http_status,
                        message=exc.message,
                        blocked_surface=_MANIFEST_CREATE_SURFACE,
                        retry_advice="after_retry_after",
                        details={
                            "manifest_id": manifest_id,
                            "commit_hash": commit_hash,
                        },
                    ),
                    headers=_rate_limit_headers_for(request),
                )
            except Exception as exc:  # noqa: BLE001
                # Any other persistence failure (schema drift, IntegrityError,
                # OperationalError, etc.). Do NOT swallow -- a silent 201 with
                # a missing manifest_versions row is exactly the F5 split-brain.
                # Surface a structured 5xx (registered RELAY-SIDECAR-010 local
                # sidecar-database error code; the concrete failure class is
                # recorded in details) and register NOTHING in memory.
                return JSONResponse(
                    status_code=500,
                    content=_build_error_envelope(
                        code=RELAY_SIDECAR_DB_CORRUPT_CODE,
                        http_status=500,
                        message=(
                            "manifest_versions persistence failed; manifest "
                            "registration was not made durable"
                        ),
                        blocked_surface=_MANIFEST_CREATE_SURFACE,
                        retry_advice="after_retry_after",
                        details={
                            "manifest_id": manifest_id,
                            "commit_hash": commit_hash,
                            "error_class": type(exc).__name__,
                        },
                    ),
                    headers=_rate_limit_headers_for(request),
                )

        # F5 follow-on (orphan manifest_id): the raw writer dedups on
        # ``commit_hash`` (its natural_key_column), but the manifest_versions
        # uniqueness constraint is UNIQUE(manifest_id, commit_hash) (migration
        # 0006) and an auto-generated manifest_id is NOT part of the dedupe key.
        # On an idempotent re-post -- the same body re-submitted WITHOUT a
        # manifest_id generates a fresh random manifest_id each time -- the
        # writer finds the existing commit_hash row and inserts NOTHING for our
        # freshly-generated manifest_id; returning that id would orphan it (no
        # durable manifest_versions row). Adopt the EXISTING row's manifest_id
        # so the returned/registered id ALWAYS resolves to a persisted row.
        # (When the body DOES carry a manifest_id it is part of commit_hash, so
        # the existing row's manifest_id equals ours and this is a no-op.)
        if db is not None and write_result is not None and write_result.idempotent:
            reader = db.acquire_reader()
            async with reader.execute(
                "SELECT manifest_id FROM manifest_versions "
                "WHERE commit_hash = ? LIMIT 1",
                (commit_hash,),
            ) as cur:
                existing_row = await cur.fetchone()
            if existing_row is not None:
                manifest_id = str(existing_row[0])

        # Durable row committed (or no DB attached, e.g. pure-asgi unit tests)
        # -> now register the derived in-memory views. Audit fix (2026-05-17
        # P0): parent Manifest envelope pins ``relay.manifest_parent.v1``
        # (envelopes.yaml:847) to avoid colliding with ManifestVersion's
        # ``relay.manifest.v1`` literal (envelopes.yaml:236).
        runtime.manifests[manifest_id] = {
            "schema_version": "relay.manifest_parent.v1",
            "manifest_id": manifest_id,
            "name": body.get("name", manifest_id),
            "project_id": body.get("project_id", ""),
            "latest_commit_hash": commit_hash,
            "written_by": "control_plane",
            "created_at": _now_iso_z(),
        }
        runtime.manifest_version_bodies[(manifest_id, commit_hash)] = {
            "schema_version": "relay.manifest.v1",
            "manifest_id": manifest_id,
            "commit_hash": commit_hash,
            "body": body,
            "written_by": "control_plane",
            "effective_at": _now_iso_z(),
        }
        # Audit fix (2026-05-17 P0): seed the ManifestRegistry with declared
        # command_hashes so the newly-created manifest can serve as the
        # manifest_commit_hash anchor for subsequent ingest (keystone
        # invariant #3). ``declared_hashes`` is pre-filtered to the sha256-
        # wire form, so register_commands cannot raise on it; the guard
        # stays defensive against future drift.
        if declared_hashes:
            try:
                runtime.manifest_registry.register_commands(
                    manifest_commit_hash=commit_hash,
                    command_hashes=declared_hashes,
                )
            except (TypeError, ValueError):
                return JSONResponse(
                    status_code=422,
                    content=_build_error_envelope(
                        code="RELAY-ING-001",
                        http_status=422,
                        message=(
                            "manifest body 'commands[].command_hash' "
                            "entries must be sha256-<hex> wire form"
                        ),
                        blocked_surface=_MANIFEST_CREATE_SURFACE,
                    ),
                    headers=_rate_limit_headers_for(request),
                )
        resp_body = {
            "manifest_id": manifest_id,
            "commit_hash": commit_hash,
            "schema_version": "relay.manifest_parent.v1",
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=_MANIFEST_CREATE_SURFACE,
                key=idemp_key,
                digest=idemp_digest,
                response_status=201,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=201,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/manifests/{manifest_id}/versions/{commit_hash}")
    async def v1_get_manifest_version(
        manifest_id: str, commit_hash: str, request: Request
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_MANIFEST_VERSION_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        record = runtime.manifest_version_bodies.get((manifest_id, commit_hash))
        if record is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=(
                        f"manifest {manifest_id!r} commit {commit_hash!r} "
                        "not found"
                    ),
                    blocked_surface=_MANIFEST_VERSION_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        return JSONResponse(
            status_code=200,
            content=record,
            headers=_rate_limit_headers_for(request),
        )

    # =====================================================================
    # W2.8 Redaction-policy endpoints (VAL-V2M02-061..064)
    # =====================================================================

    @app.post("/v1/redaction-policies")
    async def v1_create_redaction_policy(
        request: Request,
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="gates:configure",
            blocked_surface=_REDACTION_POLICY_CREATE_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        body_bytes = await request.body()
        idemp_reject, idemp_key, idemp_digest = await _check_idempotency(
            request,
            surface=_REDACTION_POLICY_CREATE_SURFACE,
            body_bytes=body_bytes,
        )
        if idemp_reject is not None:
            return idemp_reject
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:  # noqa: BLE001
            body = None
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=422,
                content=_build_error_envelope(
                    code="RELAY-ING-001",
                    http_status=422,
                    message="request body must be a JSON object",
                    blocked_surface=_REDACTION_POLICY_CREATE_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        # Keystone invariant #7: raw_capture=True requires a signed DPA
        # reference + an org-admin ``approved_by`` actor.
        raw_capture = bool(body.get("raw_capture", False))
        if raw_capture:
            dpa = body.get("dpa_reference")
            approver = body.get("approved_by")
            if not dpa or not approver:
                return JSONResponse(
                    status_code=422,
                    content=_build_error_envelope(
                        code="RELAY-G-RAW-CAPTURE-DENIED",
                        http_status=422,
                        message=(
                            "raw_capture=true requires a signed dpa_reference "
                            "AND an approved_by org-admin actor "
                            "(keystone invariant #7, spec G.1)"
                        ),
                        blocked_surface=_REDACTION_POLICY_CREATE_SURFACE,
                        details={
                            "dpa_reference_present": bool(dpa),
                            "approved_by_present": bool(approver),
                        },
                    ),
                    headers=_rate_limit_headers_for(request),
                )
        # Server-side ReDoS budget gate (VAL-V3M5-001/002/004; spec AI
        # line 5665). Every ``regex`` matcher in the candidate policy is
        # evaluated against two adversarial sentinels (1 KiB and 64 KiB
        # total bytes); a matcher whose wall-clock latency exceeds the
        # 50 ms per-input budget on either sentinel rejects publish
        # with HTTP 400 RELAY-REDACT-014. The budget evaluator is
        # imported from the sdk-python module
        # (relay.redaction_budget.evaluate_matcher_budget); no
        # duplicate budget logic lives in the sidecar (single source of
        # truth for the 50 ms budget constant). The 1 KiB sentinel is
        # evaluated first so an obvious adversarial pattern is rejected
        # before the more expensive 64 KiB run.
        #
        # Sentinel construction: a length-bounded ReDoS-triggering
        # prefix (``'a' * 22 + '!'``, ~100 ms catastrophic backtrack on
        # patterns like ``^(a+)+$``) padded to exactly N bytes with
        # filler that the engine never reaches because the prefix
        # mismatch forces an early failure. Total byte count is
        # exactly N so the wire field ``sentinel_bytes`` reports the
        # declared sentinel size.
        #
        # Why not ``'a' * N`` or ``'a' * (N-1) + '!'``? Python's
        # ``re`` engine holds the GIL for the duration of a single
        # regex match (with only coarse-grained release points).
        # A pattern such as ``^(a+)+$`` against an N=1024 input that
        # mismatches at the end runs in O(2^N) and never returns,
        # so the evaluator's 50 ms ``done.wait`` cannot wake the
        # main thread. A length-22 backtrack prefix completes in
        # well under a second while still exceeding the 50 ms budget,
        # so the publish handler stays responsive.
        _SENTINEL_REDOS_PREFIX = "a" * 22 + "!"
        _SENTINEL_1KIB = _SENTINEL_REDOS_PREFIX + "x" * (1024 - len(_SENTINEL_REDOS_PREFIX))
        _SENTINEL_64KIB = _SENTINEL_REDOS_PREFIX + "x" * (
            64 * 1024 - len(_SENTINEL_REDOS_PREFIX)
        )
        matchers = body.get("matchers")
        if isinstance(matchers, list):
            for matcher in matchers:
                if not isinstance(matcher, dict):
                    continue
                if matcher.get("kind") != "regex":
                    continue
                pattern = matcher.get("pattern")
                if not isinstance(pattern, str) or not pattern:
                    continue
                matcher_id = str(
                    matcher.get("matcher_id")
                    or matcher.get("id")
                    or "unnamed-regex"
                )
                for sentinel_bytes, sentinel in (
                    (1024, _SENTINEL_1KIB),
                    (65536, _SENTINEL_64KIB),
                ):
                    try:
                        rejection = evaluate_matcher_budget(
                            matcher_id=matcher_id,
                            pattern=pattern,
                            stress_inputs=[sentinel],
                        )
                    except RelayBudgetExceededError as exc:
                        # Stuck-thread cap saturated. Fail closed; we
                        # cannot safely launch more probe threads. The
                        # publish is rejected with the same envelope
                        # code so the caller surface is uniform.
                        return JSONResponse(
                            status_code=400,
                            content=_build_error_envelope(
                                code="RELAY-REDACT-014",
                                http_status=400,
                                message=(
                                    "redaction policy publish refused: "
                                    "regex probe thread pool saturated "
                                    f"({exc!s})"
                                ),
                                blocked_surface=(
                                    _REDACTION_POLICY_CREATE_SURFACE
                                ),
                                details={
                                    "matcher_id": matcher_id,
                                    "sentinel_bytes": sentinel_bytes,
                                    "measured_ms": float(
                                        REDACTION_REGEX_BUDGET_MS
                                    ),
                                    "reason": "thread_pool_saturated",
                                },
                            ),
                            headers=_rate_limit_headers_for(request),
                        )
                    if rejection is not None:
                        # Over-budget matcher. Surface the wire fields
                        # documented in the evaluator (matcher_id,
                        # measured_ms) plus the sentinel size that
                        # tripped the budget so the policy author can
                        # diagnose the offending pattern.
                        return JSONResponse(
                            status_code=400,
                            content=_build_error_envelope(
                                code="RELAY-REDACT-014",
                                http_status=400,
                                message=(
                                    f"redaction matcher {matcher_id!r} "
                                    f"exceeded the "
                                    f"{REDACTION_REGEX_BUDGET_MS} ms "
                                    f"per-input ReDoS regex budget on "
                                    f"the {sentinel_bytes}-byte "
                                    "sentinel; revise the pattern."
                                ),
                                blocked_surface=(
                                    _REDACTION_POLICY_CREATE_SURFACE
                                ),
                                details={
                                    "matcher_id": matcher_id,
                                    "measured_ms": float(
                                        rejection.get(
                                            "measured_ms", 0.0
                                        )
                                    ),
                                    "sentinel_bytes": sentinel_bytes,
                                    "budget_ms": (
                                        REDACTION_REGEX_BUDGET_MS
                                    ),
                                },
                            ),
                            headers=_rate_limit_headers_for(request),
                        )
        policy_id = body.get("policy_id") or f"rp-{uuid.uuid4().hex}"
        version = body.get("policy_version") or body.get("version") or "v1"
        # Audit fix (2026-05-17 P0): align with canonical RedactionPolicy
        # envelope (envelopes.yaml:590-639, Pydantic at
        # envelopes.py:1128-1169). Fixes: schema_version was the made-up
        # ``relay.redaction_policy.v1`` -> canonical ``relay.redaction.v1``.
        # Field renames: ``policy_id`` -> ``redaction_policy_id``;
        # ``dpa_reference`` -> ``dpa_ref``;
        # ``approved_by`` -> ``approver_user_id``.
        # Required-fields backfilled (``org_id``, ``version``, ``created_at``).
        # Legacy aliases mirrored on record + response.
        record = {
            "schema_version": "relay.redaction.v1",
            "redaction_policy_id": policy_id,
            "org_id": body.get(
                "org_id", "00000000-0000-0000-0000-000000000000"
            ),
            "version": version,
            "raw_capture": raw_capture,
            "dpa_ref": body.get("dpa_ref") or body.get("dpa_reference"),
            "approver_user_id": (
                body.get("approver_user_id") or body.get("approved_by")
            ),
            "created_at": _now_iso_z(),
            # Legacy aliases (in-memory only) for back-compat.
            "policy_id": policy_id,
            "policy_version": version,
            "body": body,
            "written_by": "control_plane",
            "effective_at": _now_iso_z(),
        }
        runtime.redaction_policies[policy_id] = record
        resp_body = {
            "redaction_policy_id": policy_id,
            "version": version,
            "schema_version": "relay.redaction.v1",
            # Legacy alias for back-compat.
            "policy_id": policy_id,
        }
        if idemp_key and idemp_digest:
            await _store_idempotency(
                surface=_REDACTION_POLICY_CREATE_SURFACE,
                key=idemp_key,
                digest=idemp_digest,
                response_status=201,
                response_body=resp_body,
            )
        return JSONResponse(
            status_code=201,
            content=resp_body,
            headers=_rate_limit_headers_for(request),
        )

    @app.get("/v1/redaction-policies/{policy_id}")
    async def v1_get_redaction_policy(
        policy_id: str, request: Request
    ) -> JSONResponse:
        auth_reject = _check_auth(
            request,
            required_scope="runs:read",
            blocked_surface=_REDACTION_POLICY_GET_SURFACE,
        )
        if auth_reject is not None:
            return auth_reject
        record = runtime.redaction_policies.get(policy_id)
        if record is None:
            return JSONResponse(
                status_code=404,
                content=_build_error_envelope(
                    code="RELAY-NOT-FOUND",
                    http_status=404,
                    message=f"redaction_policy {policy_id!r} not found",
                    blocked_surface=_REDACTION_POLICY_GET_SURFACE,
                ),
                headers=_rate_limit_headers_for(request),
            )
        return JSONResponse(
            status_code=200,
            content=record,
            headers=_rate_limit_headers_for(request),
        )

    # =====================================================================
    # W2.11 Hosted-only token issuance stubs (VAL-V2M02-084)
    # =====================================================================
    # [OUT-OF-SCOPE-PRIVATE] These endpoints belong to the hosted
    # control plane; the OSS sidecar exposes route stubs that return
    # 501 with documentation pointing to cloud-upgrade docs.

    @app.post("/v1/auth/tokens")
    async def v1_create_auth_token(request: Request) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-OSS-HOSTED-ONLY",
                http_status=501,
                message=(
                    "POST /v1/auth/tokens is hosted-only; the OSS sidecar "
                    "does not issue bearer tokens. See cloud-upgrade docs."
                ),
                blocked_surface=_AUTH_TOKENS_CREATE_SURFACE,
                documentation_url=(
                    "https://relay.epochly.com/docs/cloud-upgrade/auth"
                ),
            ),
            headers=_rate_limit_headers_for(request),
        )

    @app.delete("/v1/auth/tokens/{token_id}")
    async def v1_delete_auth_token(
        token_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-OSS-HOSTED-ONLY",
                http_status=501,
                message=(
                    "DELETE /v1/auth/tokens/{token_id} is hosted-only; the "
                    "OSS sidecar does not manage bearer-token lifecycles."
                ),
                blocked_surface=_AUTH_TOKENS_DELETE_SURFACE,
                documentation_url=(
                    "https://relay.epochly.com/docs/cloud-upgrade/auth"
                ),
            ),
            headers=_rate_limit_headers_for(request),
        )

    # =====================================================================
    # V3 M2 F02 hosted-only assessment/compliance/usage 501 stubs
    # (VAL-V3M2-004, VAL-V3M2-005)
    # =====================================================================
    # [OUT-OF-SCOPE-PRIVATE] The 5 routes below belong to the private
    # ``relay-platform`` hosted control plane (.ops boundaries.md
    # DEFERRED item #3). The OSS sidecar exposes them only as 501 stubs
    # so SDK callers see a deterministic ``RELAY-HOSTED-ONLY`` envelope
    # rather than a 404 (which would falsely suggest a missing or
    # renamed route). Implementing the actual hosted logic in the OSS
    # tree is a P0 boundary violation per CLAUDE.md "Repository
    # topology" + "DEFERRED items".
    #
    # Per VAL-V3M2-005 the envelope MUST carry:
    #   code            = "RELAY-HOSTED-ONLY"
    #   http_status     = 501
    #   blocked_surface = "hosted_control_plane"

    _HOSTED_ONLY_MESSAGE: str = (
        "This endpoint is provided by the hosted Relay control plane; "
        "not available in OSS sidecar."
    )

    @app.post("/v1/evidence-bundles/{bundle_id}/assess")
    async def v1_evidence_bundle_assess(
        bundle_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-HOSTED-ONLY",
                http_status=501,
                blocked_surface="hosted_control_plane",
                message=_HOSTED_ONLY_MESSAGE,
            ),
        )

    @app.get("/v1/assessment-bundles/{bundle_id}")
    async def v1_assessment_bundle_get(
        bundle_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-HOSTED-ONLY",
                http_status=501,
                blocked_surface="hosted_control_plane",
                message=_HOSTED_ONLY_MESSAGE,
            ),
        )

    @app.get("/v1/assessment-bundles/{bundle_id}/gaps")
    async def v1_assessment_bundle_gaps(
        bundle_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-HOSTED-ONLY",
                http_status=501,
                blocked_surface="hosted_control_plane",
                message=_HOSTED_ONLY_MESSAGE,
            ),
        )

    @app.get("/v1/projects/{project_id}/compliance/readiness")
    async def v1_project_compliance_readiness(
        project_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-HOSTED-ONLY",
                http_status=501,
                blocked_surface="hosted_control_plane",
                message=_HOSTED_ONLY_MESSAGE,
            ),
        )

    @app.get("/v1/orgs/{org_id}/usage")
    async def v1_org_usage(
        org_id: str, request: Request
    ) -> JSONResponse:
        return JSONResponse(
            status_code=501,
            content=_build_error_envelope(
                code="RELAY-HOSTED-ONLY",
                http_status=501,
                blocked_surface="hosted_control_plane",
                message=_HOSTED_ONLY_MESSAGE,
            ),
        )

    @app.get("/diagnostics/quiesce")
    async def diagnostics_quiesce() -> dict[str, Any]:
        """Return current quiesce state: in-flight count, idle event,
        force-stop flag, idle-shutdown trigger.

        Used by the W2.6 tests (VAL-W2-043, VAL-W2-046, VAL-W2-048) to
        observe the tracker without poking private attributes.
        """
        tracker = runtime.quiesce.tracker
        return {
            "in_flight_count": tracker.in_flight_count if tracker else 0,
            "in_flight_descriptions": (
                tracker.in_flight_descriptions() if tracker else []
            ),
            "total_acquires": tracker.total_acquires if tracker else 0,
            "idle_event_set": (
                tracker.idle_event.is_set() if tracker else True
            ),
            "force_stop_requested": runtime.quiesce.force_stop_requested,
            "force_stop_reason": runtime.quiesce.force_stop_reason,
            "idle_shutdown_triggered": runtime.quiesce.idle_shutdown_triggered,
            "idle_timeout_seconds": runtime.idle_timeout_seconds,
            "drain_deadline_seconds": runtime.drain_deadline_seconds,
            "lockfile_path": (
                str(runtime.lockfile_path)
                if runtime.lockfile_path is not None
                else None
            ),
        }

    @app.get("/diagnostics/db")
    async def diagnostics_db() -> dict[str, Any]:
        """Return SidecarDatabase stats: connection counts, reader pragmas.

        Used by VAL-W2-023 to prove >= 2 aiosqlite connections (writer +
        readers) are open and that readers carry PRAGMA query_only = 1.
        Reader pragmas are read via the actual reader connections (NOT a
        fresh transient connection) so the test sees the persistent
        query_only setting.
        """
        db = runtime.database
        if db is None:
            return {
                "open": False,
                "connect_call_count": 0,
                "reader_count": 0,
                "readers": [],
            }
        readers_info: list[dict[str, Any]] = []
        for i in range(db.reader_count):
            conn = db.acquire_reader()
            async with conn.execute("PRAGMA query_only") as cur:
                row = await cur.fetchone()
                query_only = int(row[0]) if row else None
            async with conn.execute("PRAGMA busy_timeout") as cur:
                row = await cur.fetchone()
                busy_timeout = int(row[0]) if row else None
            readers_info.append(
                {
                    "index": i,
                    "query_only": query_only,
                    "busy_timeout": busy_timeout,
                }
            )
        return {
            "open": True,
            "connect_call_count": db.connect_call_count,
            "reader_count": db.reader_count,
            "readers": readers_info,
        }

    return app


def run_uvicorn(
    *,
    health: HealthState,
    host: str = "127.0.0.1",
    port: int = 0,
    sqlite_path: Path | None = None,
    relay_home_override: Path | None = None,
) -> None:  # pragma: no cover (exercised by subprocess tests, not in-process)
    """Run the sidecar under uvicorn.

    Used by W5's CLI entrypoint and by the W2.7 subprocess tests (which
    spawn this via ``subprocess.Popen`` so SIGTERM + structured exit
    codes are real).

    Startup contract (W2.7 wiring; STR-001 fix):
      - Resolve the same ``sqlite_path`` the lifespan would resolve.
      - Synchronously invoke :func:`recover_or_refuse` BEFORE constructing
        the FastAPI app or entering the asyncio loop. On corruption,
        schema-version mismatch, or WAL-replay failure, recovery calls
        :func:`exit_with_structured_error` which writes the JSON envelope
        to stderr and ``sys.exit``s with the appropriate code (3, 5, or
        6). Doing this OUTSIDE the asyncio loop is critical: a SystemExit
        raised inside a uvicorn lifespan coroutine is caught and the
        custom exit code is lost; raising here causes the Python
        interpreter to honour the code verbatim. The lifespan still
        re-invokes recovery defensively for in-process callers of
        :func:`build_runtime_app`.

    Args:
        health: HealthState for the bearer/nonce surface.
        host: Bind host. Defaults to 127.0.0.1 (loopback-only; never 0.0.0.0).
        port: Bind port. 0 means ephemeral.
        sqlite_path: SQLite DB path override.
        relay_home_override: Override ``${RELAY_HOME}`` discovery; passed
            through to :func:`build_runtime_app` so tests can run a real
            sidecar subprocess against a tmpdir.
    """
    import uvicorn

    # Resolve the effective SQLite path with the SAME fall-through that
    # ``build_runtime_app`` applies, so the pre-launch recovery probe and
    # the lifespan-startup recovery probe inspect the same file.
    base_home = (
        relay_home_override
        if relay_home_override is not None
        else relay_home()
    )
    effective_db_path = (
        sqlite_path if sqlite_path is not None else base_home / SIDECAR_DB_FILENAME
    )
    # STR-001 fix: probe BEFORE entering asyncio. Recovery sys.exit on
    # corruption / schema mismatch propagates the exit code unmolested.
    recover_or_refuse(effective_db_path)

    app = build_runtime_app(
        health=health,
        sqlite_path=sqlite_path,
        relay_home_override=relay_home_override,
    )
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=os.environ.get("RELAY_SIDECAR_LOG_LEVEL", "warning"),
        access_log=False,
        # Force the default asyncio loop so the loop.add_signal_handler path
        # is reachable. uvloop on macOS supports add_signal_handler but the
        # test surface is more portable on the stdlib loop.
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    # Wire the live Server handle onto app.state BEFORE serving so the SIGUSR1
    # force-stop and idle-shutdown paths (which read
    # getattr(app.state, "uvicorn_server", None) to set .should_exit /
    # .force_exit) can actually terminate this daemon. Without this the handle
    # is None and those paths are inert (re-hunt #4).
    app.state.uvicorn_server = server
    server.run()


__all__ = [
    "DRAIN_RETRY_AFTER_S",
    "IDEMPOTENCY_RECORD_TTL_S",
    "MAX_IDEMPOTENCY_RECORDS",
    "DrainMiddleware",
    "RuntimeState",
    "SIDECAR_DB_FILENAME",
    "build_runtime_app",
    "get_async_client_init_count",
    "lifespan",
    "reset_async_client_init_counter",
    "run_uvicorn",
]
