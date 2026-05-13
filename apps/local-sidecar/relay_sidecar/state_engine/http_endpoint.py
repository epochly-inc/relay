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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import aiosqlite
from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from ..db import SidecarDatabase
from ..errors import (
    RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED,
    RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE,
)
from .compare_and_set import (
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
    """Build the canonical RELAY-GATE-021 error envelope (spec B.4)."""
    return {
        "code": RELAY_GATE_021_CODE,
        "error_class": RELAY_GATE_021_CLASS,
        "http_status": 409,
        "message": "three-anchor handoff failed",
        "details": {"reason": reason},
    }


def _context_envelope(observed_hash: str | None, pinned_hash: str | None) -> dict[str, Any]:
    """Build the RELAY-SIDECAR-CONTEXT-NOT-REHYDRATED envelope (VAL-W2-056)."""
    return {
        "code": RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED_CODE,
        "error_class": RELAY_SIDECAR_CONTEXT_NOT_REHYDRATED,
        "http_status": 409,
        "message": (
            "resumed operation must reload manifest+contract+procedures "
            "from disk; in-memory hash differs from active pinned hash"
        ),
        "details": {
            "observed_manifest_commit_hash": observed_hash,
            "pinned_manifest_commit_hash": pinned_hash,
        },
    }


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
        body = await request.json()
        if not isinstance(body, dict):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": "request body must be a JSON object",
                },
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
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": "scope_kind and scope_id MUST be strings",
                },
            )
        if not isinstance(expected_from, str) or not isinstance(event, str):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": "expected_from and event MUST be strings",
                },
            )
        if not isinstance(actor_kind, str) or not isinstance(actor_identity_hash, str):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": "actor.kind and actor.identity_hash MUST be strings",
                },
            )
        if not isinstance(manifest_commit_hash, str):
            return JSONResponse(
                status_code=400,
                content={
                    "code": "RELAY-ING-001",
                    "error_class": "RELAY-ING-001",
                    "message": "manifest_commit_hash MUST be a string",
                },
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
        # Map state-engine reason codes to HTTP status.
        status_map = {
            "UNKNOWN_SCOPE": 404,
            "EXPECTED_FROM_MISMATCH": 409,
            "INVALID_TRANSITION": 422,
            "ACTOR_NOT_ALLOWED": 403,
            "GUARD_FAILED": 422,
            "TERMINAL_STATE": 409,
        }
        status = status_map.get(str(result.reason), 422)
        return JSONResponse(
            status_code=status,
            content={
                "ok": False,
                "reason": result.reason,
                "observed_state": result.observed_state,
                "epoch": result.epoch,
                "event_id": result.event_id,
            },
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
