"""HTTP routes for the explain pipeline (M05 w5-explain; VAL-V2M05-019/020/021).

Exposes a FastAPI :class:`APIRouter` that the local-sidecar mounts onto its
application surface. The router implements the canonical promotion API:

    POST /v1/replay-cases?from_hypothesis_id=<uuid>

Behavior per spec T line 4884 and CLAUDE.md keystone invariant #1:

  - 201 + ``{replay_case_id, run_id}`` when the source hypothesis exists
    AND has ``reviewer_decision == 'accept'``. The source row's
    ``promoted_to_replay_case_id`` is updated atomically.
  - 422 + structured error envelope when the hypothesis exists but is not
    in the ``accept`` state (NULL / 'modify' / 'reject').
  - 404 + structured error envelope when the hypothesis_id is unknown.
  - The control plane writes the new ``replay_cases`` row; the SDK / CLI
    never bypass this endpoint.

The router accepts an injected :class:`PromotionService` so the sidecar can
plug in its SQLite-backed store while tests use an in-memory store.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from relay_explain.engine import HypothesisRecord

# ---------------------------------------------------------------------------
# Protocol consumed by the router
# ---------------------------------------------------------------------------


class PromotionService(Protocol):
    """Storage adapter consumed by the promotion endpoint."""

    def get_hypothesis(self, hypothesis_id: str) -> HypothesisRecord | None:
        """Return the hypothesis row or ``None`` if absent."""

    def create_replay_case(
        self, *, hypothesis: HypothesisRecord
    ) -> str:
        """Create the replay_cases row and return its replay_case_id.

        Implementations MUST be transactional with
        :meth:`mark_promoted` so the promotion is atomic.
        """

    def mark_promoted(
        self, *, hypothesis_id: str, replay_case_id: str
    ) -> None:
        """Update ``promoted_to_replay_case_id`` on the source row."""

    def get_replay_case(self, replay_case_id: str) -> dict[str, Any] | None:
        """Return the persisted replay_case payload or ``None``."""


# ---------------------------------------------------------------------------
# Default in-memory implementation (tests + reference)
# ---------------------------------------------------------------------------


@dataclass
class InMemoryPromotionService:
    """Reference promotion service for tests and local-only flows."""

    hypotheses: dict[str, HypothesisRecord] = field(default_factory=dict)
    replay_cases: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add_hypothesis(self, record: HypothesisRecord) -> None:
        self.hypotheses[record.hypothesis_id] = record

    # ---- PromotionService protocol ---------------------------------------

    def get_hypothesis(self, hypothesis_id: str) -> HypothesisRecord | None:
        return self.hypotheses.get(hypothesis_id)

    def create_replay_case(self, *, hypothesis: HypothesisRecord) -> str:
        replay_case_id = str(uuid.uuid4())
        self.replay_cases[replay_case_id] = {
            "replay_case_id": replay_case_id,
            "run_id": hypothesis.run_id,
            "source_hypothesis_id": hypothesis.hypothesis_id,
        }
        return replay_case_id

    def mark_promoted(
        self, *, hypothesis_id: str, replay_case_id: str
    ) -> None:
        existing = self.hypotheses[hypothesis_id]
        self.hypotheses[hypothesis_id] = HypothesisRecord(
            **{
                **existing.__dict__,
                "promoted_to_replay_case_id": replay_case_id,
            }
        )

    def get_replay_case(self, replay_case_id: str) -> dict[str, Any] | None:
        return self.replay_cases.get(replay_case_id)


# ---------------------------------------------------------------------------
# Router factory
# ---------------------------------------------------------------------------


def build_explain_router(service: PromotionService) -> APIRouter:
    """Return a FastAPI router bound to ``service``.

    The router does not own any global state; callers (sidecar / tests)
    own the :class:`PromotionService` lifecycle.
    """
    router = APIRouter()

    @router.post("/v1/replay-cases", status_code=201)
    async def promote_replay_case(
        request: Request,
        from_hypothesis_id: str = Query(..., min_length=1),
    ) -> JSONResponse:
        """Promote an accepted hypothesis into a new replay_case."""
        return _promote(service, from_hypothesis_id)

    @router.get("/v1/replay-cases/{replay_case_id}")
    async def get_replay_case(replay_case_id: str) -> JSONResponse:
        payload = service.get_replay_case(replay_case_id)
        if payload is None:
            return _error_response(
                status_code=404,
                code="RELAY-EXPLAIN-001",
                message=(
                    f"replay_case_id {replay_case_id!r} not found"
                ),
            )
        return JSONResponse(status_code=200, content=payload)

    return router


def _promote(service: PromotionService, hypothesis_id: str) -> JSONResponse:
    record = service.get_hypothesis(hypothesis_id)
    if record is None:
        return _error_response(
            status_code=404,
            code="RELAY-EXPLAIN-001",
            message=f"hypothesis_id {hypothesis_id!r} not found",
        )
    decision = record.reviewer_decision
    if decision != "accept":
        return _error_response(
            status_code=422,
            code="RELAY-EXPLAIN-001",
            message=(
                f"hypothesis {hypothesis_id!r} has reviewer_decision="
                f"{decision!r}; promotion threshold requires 'accept'"
            ),
        )
    if record.promoted_to_replay_case_id is not None:
        # Idempotent: return the existing replay_case_id, do not create a
        # second row. Spec T does not enumerate this case; treat as
        # idempotent success per the spec's general convention.
        existing_rc = record.promoted_to_replay_case_id
        payload = service.get_replay_case(existing_rc) or {
            "replay_case_id": existing_rc,
            "run_id": record.run_id,
            "source_hypothesis_id": record.hypothesis_id,
        }
        return JSONResponse(status_code=201, content=payload)
    replay_case_id = service.create_replay_case(hypothesis=record)
    service.mark_promoted(
        hypothesis_id=record.hypothesis_id,
        replay_case_id=replay_case_id,
    )
    payload = service.get_replay_case(replay_case_id) or {
        "replay_case_id": replay_case_id,
        "run_id": record.run_id,
        "source_hypothesis_id": record.hypothesis_id,
    }
    return JSONResponse(status_code=201, content=payload)


def _error_response(*, status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
            }
        },
    )


__all__ = [
    "InMemoryPromotionService",
    "PromotionService",
    "build_explain_router",
]
