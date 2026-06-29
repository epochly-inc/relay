"""HTTP boundary for state transitions (VAL-W2-056, VAL-W2-062).

Per VAL-W2-062: ``POST /v1/state/transition`` MUST validate the three-
anchor handoff at the HTTP handler entry BEFORE forwarding to the state
engine. A stale handoff (e.g., a ``manifest_commit_hash`` that is not
active or in grace) MUST return HTTP 409 + ``RELAY-GATE-021`` AND MUST NOT
issue any state-engine database call.

Per VAL-W2-056 (context reinjection guard): a resumed worker that holds a
stale in-memory ``manifest_commit_hash`` for its scope MUST be refused
with HTTP 409 + ``RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED``. The check is
distinct from the three-anchor handoff: VAL-W2-062 fails when the
*supplied* hash is not active globally; VAL-W2-056 fails when the
*supplied* hash differs from the *scope's pinned* hash recorded at scope
creation. The handler enforces both, in this order:

    1. context_pinned_hash check (VAL-W2-056) -- HTTP 409 +
       RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED.
    2. three-anchor handoff (VAL-W2-030/-031/-032/-062) -- HTTP 409 +
       RELAY-GATE-021.
    3. state-engine compare_and_set_state.

The state engine is injected so the test can substitute a mock and verify
"zero state-engine invocations on rejected handoff" (VAL-W2-062 evidence).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite
from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from ..db import SidecarDatabase
from ..errors import RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE
from .compare_and_set import (
    ACTOR_NOT_ALLOWED,
    EXPECTED_FROM_MISMATCH,
    GUARD_FAILED,
    HANDOFF_INVALID,
    INVALID_TRANSITION,
    TERMINAL_STATE,
    UNKNOWN_GUARD,
    UNKNOWN_SCOPE,
    ActorRef,
    StateTransitionResult,
    compare_and_set_state,
)
from .handoff import (
    ACTOR_NOT_REGISTERED,
    MANIFEST_NOT_ACTIVE,
    SCOPE_ID_MISMATCH,
    HandoffResult,
    validate_three_anchor_handoff,
)

# RELAY-GATE-021 wire-format error code (already present in
# packages/schemas/raw/relay-error-codes.yaml; emitted on failed three-
# anchor handoff per spec C.5).
RELAY_GATE_021_CODE: str = "RELAY-GATE-021"
RELAY_GATE_021_CLASS: str = "RELAY-GATE-021"

# RELAY-GATE-001 is the registered gate-namespace catch-all (spec C; docs
# error-codes.yaml: "Gate decision request failed in a way more specific
# codes do not classify"). The state-engine compare_and_set reason codes
# (EXPECTED_FROM_MISMATCH, TERMINAL_STATE, INVALID_TRANSITION,
# ACTOR_NOT_ALLOWED, GUARD_FAILED, UNKNOWN_SCOPE, UNKNOWN_GUARD) have no
# dedicated wire-format code in packages/schemas/raw/relay-error-codes.yaml,
# so the canonical ErrorEnvelope for those rejections carries this catch-all
# code with the specific reason preserved in ``details.reason``. HANDOFF_INVALID
# is the sole exception: it maps to RELAY-GATE-021 (three-anchor handoff).
RELAY_GATE_001_CODE: str = "RELAY-GATE-001"

# Per-surface ``blocked_surface`` constant for every ErrorEnvelope emitted
# by the POST /v1/state/transition route. Mirrors runtime.py's per-surface
# constants (e.g. ``_RUNS_SURFACE``). The route's 400/409 responses are
# declared as ``$ref: ErrorEnvelope`` in packages/schemas/raw/openapi.yaml,
# so every body MUST be a canonical ErrorEnvelope (spec B.4): closed schema
# (additionalProperties:false), required schema_version/code/http_status/
# blocked_surface/retry_advice/request_id/trace_id, and NO ``error_class``.
_STATE_TRANSITION_SURFACE: str = "state_transition"


def _new_request_id() -> str:
    """Return a ULID-shaped 26-char Crockford base32 id.

    Copies the algorithm of ``runtime.py``'s closure-scoped
    ``_new_request_id`` exactly (that closure is not importable). Format:
    10-char timestamp (48-bit ms) + 16-char randomness, using the Crockford
    base32 alphabet so the value matches ``[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}``.
    Used to populate the required ``request_id`` / ``trace_id`` fields of an
    ErrorEnvelope when the route has no upstream-supplied ids.
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


def _relay_error_envelope(
    *,
    code: str,
    http_status: int,
    message: str,
    blocked_surface: str,
    retry_advice: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a spec B.4 canonical ErrorEnvelope dict for this route.

    Mirrors ``runtime.py``'s closure-scoped ``_build_error_envelope``
    structure exactly: emits ``schema_version`` (const ``relay.error.v1``),
    ``code``, ``http_status``, ``message``, ``blocked_surface``,
    ``retry_advice``, fresh ULID-shaped ``request_id`` / ``trace_id``, and an
    optional ``details`` object. The legacy ``error_class`` field is NOT
    emitted -- the canonical ErrorEnvelope is ``additionalProperties:false``
    and rejects it (``code`` already carries the same anchor).
    """
    env: dict[str, Any] = {
        "schema_version": "relay.error.v1",
        "code": code,
        "http_status": http_status,
        "message": message,
        "blocked_surface": blocked_surface,
        "retry_advice": retry_advice,
        "request_id": _new_request_id(),
        "trace_id": _new_request_id(),
    }
    if details is not None:
        env["details"] = details
    return env


def _ing_001_envelope(message: str) -> dict[str, Any]:
    """Build the canonical RELAY-ING-001 (400) ErrorEnvelope for this route.

    All malformed-body / missing-anchor validation failures on
    POST /v1/state/transition share this envelope shape. ``retry_advice`` is
    ``after_fix`` because the caller must correct the request body before
    retrying.
    """
    return _relay_error_envelope(
        code="RELAY-ING-001",
        http_status=400,
        message=message,
        blocked_surface=_STATE_TRANSITION_SURFACE,
        retry_advice="after_fix",
    )


@dataclass
class StateEngineProtocol:
    """Adapter object so tests can inject a mock state engine.

    The default factory wires ``compare_and_set_state`` directly. Tests
    construct a ``StateEngineProtocol(transition_fn=mock_fn)`` where
    ``mock_fn`` records invocations; VAL-W2-062 asserts the mock was
    never called on a rejected handoff.
    """

    transition_fn: Callable[..., Awaitable[StateTransitionResult]]


def _default_state_engine(database: SidecarDatabase) -> StateEngineProtocol:
    """Bind the real compare_and_set_state for production use."""

    async def _call(
        *,
        scope_kind: str,
        scope_id: str,
        expected_from: str,
        event: str,
        actor: ActorRef,
        payload: dict[str, Any] | None = None,
        project_id: str | None = None,
        manifest_commit_hash: str | None = None,
    ) -> StateTransitionResult:
        return await compare_and_set_state(
            database=database,
            scope_kind=scope_kind,
            scope_id=scope_id,
            expected_from=expected_from,
            event=event,
            actor=actor,
            payload=payload,
            project_id=project_id,
            manifest_commit_hash=manifest_commit_hash,
        )

    return StateEngineProtocol(transition_fn=_call)


async def _scope_pinned_manifest_hash(
    reader: aiosqlite.Connection,
    *,
    scope_kind: str,
    scope_id: str,
) -> str | None:
    """Return the manifest_commit_hash pinned to a scope at creation time.

    Looks up the FIRST event_log_entries row for the scope (the
    ``state_transition`` row emitted when the scope was created) and
    returns its ``manifest_commit_hash`` column. None if the scope has
    no recorded state-transition row yet (VAL-W2-056 requires the scope
    to have a transition history before the guard fires; a brand-new
    scope is allowed to set the manifest hash).

    Used by VAL-W2-056 context-reinjection guard: a worker resuming from
    a long-running operation MUST submit the SAME manifest hash it pinned
    at scope creation. Mismatch -> refusal.
    """
    async with reader.execute(
        "SELECT manifest_commit_hash FROM event_log_entries "
        "WHERE scope_id = ? AND scope_type = ? "
        "AND event_kind = 'state_transition' "
        "AND manifest_commit_hash IS NOT NULL "
        "ORDER BY ingest_sequence ASC LIMIT 1",
        (scope_id, scope_kind),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return None
    return str(row[0])


def _gate_021_envelope(reason: str) -> dict[str, Any]:
    """Build the canonical RELAY-GATE-021 ErrorEnvelope (spec B.4).

    A stale three-anchor handoff is non-retryable as-is: the caller must
    re-authenticate / refresh the manifest, not blindly retry. Hence
    ``retry_advice="do_not_retry"``.
    """
    return _relay_error_envelope(
        code=RELAY_GATE_021_CODE,
        http_status=409,
        message="three-anchor handoff failed",
        blocked_surface=_STATE_TRANSITION_SURFACE,
        retry_advice="do_not_retry",
        details={"reason": reason},
    )


def _context_envelope(observed_hash: str | None, pinned_hash: str | None) -> dict[str, Any]:
    """Build the RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED ErrorEnvelope (VAL-W2-056).

    ``code`` is the W1-compliant numeric token ``RELAY-SIDECAR-008`` (the
    descriptive ``RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED`` form does NOT match
    the ``^RELAY-[A-Z]+-[0-9]{3}$`` code pattern and is therefore not a valid
    ErrorEnvelope ``code``). ``retry_advice="after_fix"``: the worker must
    reload manifest/contract/procedures from disk (the "fix") before
    retrying.
    """
    return _relay_error_envelope(
        code=RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE,
        http_status=409,
        message=(
            "resumed operation must reload manifest+contract+procedures "
            "from disk; in-memory hash differs from active pinned hash"
        ),
        blocked_surface=_STATE_TRANSITION_SURFACE,
        retry_advice="after_fix",
        details={
            "observed_manifest_commit_hash": observed_hash,
            "pinned_manifest_commit_hash": pinned_hash,
        },
    )


def build_state_router(
    *,
    database_getter: Callable[[], SidecarDatabase],
    state_engine_factory: Callable[[SidecarDatabase], StateEngineProtocol] | None = None,
) -> APIRouter:
    """Build the /v1/state router.

    Args:
        database_getter: Callable returning the active SidecarDatabase.
            Indirection lets tests construct a router before app.state is
            populated by the lifespan.
        state_engine_factory: Optional override for testing. Default wires
            the real compare_and_set_state.

    Returns:
        An APIRouter with a single POST /v1/state/transition handler.
    """
    factory = state_engine_factory if state_engine_factory is not None else _default_state_engine
    router = APIRouter()

    @router.post("/v1/state/transition")
    async def state_transition(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope("request body must be a JSON object"),
            )
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope("request body must be a JSON object"),
            )
        # Mandatory anchor fields.
        scope_kind = body.get("scope_kind")
        scope_id = body.get("scope_id")
        expected_from = body.get("expected_from")
        event = body.get("event")
        actor_payload = body.get("actor") or {}
        actor_kind = actor_payload.get("kind") if isinstance(actor_payload, dict) else None
        actor_identity_hash = (
            actor_payload.get("identity_hash") if isinstance(actor_payload, dict) else None
        )
        manifest_commit_hash = body.get("manifest_commit_hash")
        project_id = body.get("project_id")
        payload = body.get("payload") or {}
        run_id = body.get("run_id", scope_id if scope_kind == "run" else None)

        # Basic schema validation -- missing required fields -> 400.
        if not isinstance(scope_kind, str) or not isinstance(scope_id, str):
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope("scope_kind and scope_id MUST be strings"),
            )
        if not isinstance(expected_from, str) or not isinstance(event, str):
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope("expected_from and event MUST be strings"),
            )
        if not isinstance(actor_kind, str) or not isinstance(actor_identity_hash, str):
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope(
                    "actor.kind and actor.identity_hash MUST be strings"
                ),
            )
        if not isinstance(manifest_commit_hash, str):
            return JSONResponse(
                status_code=400,
                content=_ing_001_envelope("manifest_commit_hash MUST be a string"),
            )

        database = database_getter()
        reader = database.acquire_reader()

        # --- VAL-W2-056: context-reinjection guard ---
        # If the scope has a pinned manifest hash from a prior transition,
        # the submitted hash MUST match. Mismatch -> 409 +
        # RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED.
        pinned_hash = await _scope_pinned_manifest_hash(
            reader, scope_kind=scope_kind, scope_id=scope_id
        )
        if pinned_hash is not None and pinned_hash != manifest_commit_hash:
            return JSONResponse(
                status_code=409,
                content=_context_envelope(
                    observed_hash=manifest_commit_hash, pinned_hash=pinned_hash
                ),
            )

        # --- VAL-W2-062: three-anchor handoff validation BEFORE state engine ---
        handoff_payload = {
            "actor_identity_hash": actor_identity_hash,
            "manifest_commit_hash": manifest_commit_hash,
            "run_id": run_id,
        }
        handoff: HandoffResult = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind=scope_kind,
            scope_id=scope_id,
            payload=handoff_payload,
        )
        if not handoff.ok:
            return JSONResponse(
                status_code=409,
                content=_gate_021_envelope(reason=str(handoff.reason)),
            )

        # --- Three anchors valid -> proceed to state engine ---
        engine = factory(database)
        actor = ActorRef(kind=actor_kind, identity_hash=actor_identity_hash)
        result = await engine.transition_fn(
            scope_kind=scope_kind,
            scope_id=scope_id,
            expected_from=expected_from,
            event=event,
            actor=actor,
            payload=payload if isinstance(payload, dict) else {},
            project_id=project_id if isinstance(project_id, str) else None,
            manifest_commit_hash=manifest_commit_hash,
        )

        if result.ok:
            return JSONResponse(
                status_code=200,
                content={
                    "ok": True,
                    "new_state": result.new_state,
                    "epoch": result.epoch,
                    "idempotent": result.idempotent,
                    "event_id": result.event_id,
                },
            )
        # Map state-engine reason codes to HTTP status. Every post-CAS
        # rejection MUST surface as a canonical ErrorEnvelope (spec B.4) --
        # the route declares its 4xx bodies as ``$ref: ErrorEnvelope`` in
        # openapi.yaml (closed schema, code pattern ^RELAY-[A-Z]+-[0-9]{3}$).
        # The prior implementation returned a BARE dict here, violating that
        # contract and the module docstring's "every 400/409 body MUST be a
        # canonical ErrorEnvelope" invariant.
        #
        # HANDOFF_INVALID is the CAS-internal three-anchor handoff guard
        # rejection (keystone #4 / spec C.5): HTTP 409 + RELAY-GATE-021,
        # identical to the pre-CAS handoff rejection above. The prior map had
        # NO entry for it, so a cross-project handoff fell through to an
        # UNDECLARED 422. UNKNOWN_GUARD (fail-closed defense against
        # transition-table drift) shares INVALID_TRANSITION's 422.
        status_map = {
            UNKNOWN_SCOPE: 404,
            EXPECTED_FROM_MISMATCH: 409,
            INVALID_TRANSITION: 422,
            ACTOR_NOT_ALLOWED: 403,
            GUARD_FAILED: 422,
            TERMINAL_STATE: 409,
            HANDOFF_INVALID: 409,
            UNKNOWN_GUARD: 422,
        }
        reason = str(result.reason)
        status = status_map.get(reason, 422)
        # HANDOFF_INVALID -> RELAY-GATE-021; every other reason -> the
        # registered gate-namespace catch-all RELAY-GATE-001 (the specific
        # reason rides in details.reason). The transition is still REJECTED
        # exactly as before (fail-closed) -- only the response SHAPE changes.
        code = RELAY_GATE_021_CODE if reason == HANDOFF_INVALID else RELAY_GATE_001_CODE
        details: dict[str, Any] = {"reason": reason}
        if result.observed_state is not None:
            details["observed_state"] = result.observed_state
        if result.epoch is not None:
            details["epoch"] = result.epoch
        if result.event_id is not None:
            details["event_id"] = result.event_id
        if result.extras:
            details["extras"] = result.extras
        return JSONResponse(
            status_code=status,
            content=_relay_error_envelope(
                code=code,
                http_status=status,
                message=f"state transition rejected: {reason}",
                blocked_surface=_STATE_TRANSITION_SURFACE,
                # The rejected request is terminal as submitted: the caller
                # must change the scope state, actor, or manifest anchor (a
                # new request), not blindly retry the identical body.
                retry_advice="do_not_retry",
                details=details,
            ),
        )

    return router


__all__ = [
    "RELAY_GATE_021_CLASS",
    "RELAY_GATE_021_CODE",
    "StateEngineProtocol",
    "build_state_router",
]


# Re-export the unused-import sentinels at module level so static analysis
# does not flag handoff reason constants imported for cross-module use.
_ = (ACTOR_NOT_REGISTERED, MANIFEST_NOT_ACTIVE, SCOPE_ID_MISMATCH)
