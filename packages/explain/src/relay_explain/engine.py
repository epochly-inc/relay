"""Explain ingestion engine (M05 w5-explain).

The explain engine is the sole writer of ``root_cause_hypotheses`` per
CLAUDE.md keystone invariant #1. It enforces:

  - Wire-format validation against ``relay.root_cause_hypothesis.v1``
    (VAL-V2M05-001..006).
  - LLM taxonomy clamp: out-of-enum hypothesis_class maps to ``unknown``
    plus a ``taxonomy_review_required`` event (VAL-V2M05-014).
  - Cross-row span_id existence check against the run's spans set
    (VAL-V2M05-015 -> RELAY-EXPLAIN-001).
  - Dedupe key (run_id, hypothesis_class, evidence_refs_digest) with
    max(confidence) merge (VAL-V2M05-012).
  - Generator taxonomy regex enforced before INSERT (VAL-V2M05-009).

The engine is deliberately storage-agnostic: callers inject a writable
``HypothesisStore`` protocol implementation (the sidecar passes a SQLite
adapter; the hosted control plane will pass a Postgres adapter).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from relay_schemas.error_codes import RelayErrorCode
from relay_schemas.root_cause_hypothesis import (
    GENERATOR_REGEX,
    HYPOTHESIS_CLASSES,
    REVIEWER_DECISIONS,
    validate,
)

_GENERATOR_RE = re.compile(GENERATOR_REGEX)


class SpanNotOnRunError(Exception):
    """Raised when an ingested hypothesis's span_id is not on the run.

    The wire envelope carries ``code = RelayErrorCode.RELAY_EXPLAIN_001`` and
    the API surface returns HTTP 422. VAL-V2M05-015.
    """

    code: str = RelayErrorCode.RELAY_EXPLAIN_001

    def __init__(self, run_id: str, span_id: str) -> None:
        super().__init__(
            f"span_id {span_id!r} is not present on run {run_id!r}"
        )
        self.run_id = run_id
        self.span_id = span_id


class DuplicateHypothesis(Exception):
    """Raised when the dedupe path detects an existing row.

    The engine catches this internally and converts the operation into a
    ``max(confidence)`` UPDATE rather than surfacing it to callers; tests
    use this exception type to assert the path was exercised.
    """

    def __init__(self, hypothesis_id: str) -> None:
        super().__init__(
            f"hypothesis dedupe collision for hypothesis_id {hypothesis_id!r}"
        )
        self.hypothesis_id = hypothesis_id


def canonical_evidence_refs_digest(evidence_refs: list[Any]) -> str:
    """Return a SHA-256 hex digest over the canonical JSON of evidence_refs.

    Canonicalisation: ``json.dumps(value, sort_keys=True, separators=(',',':'))``.
    Deterministic across processes and OS; safe for the (run_id,
    hypothesis_class, digest) dedupe key.
    """
    canonical = json.dumps(evidence_refs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class HypothesisRecord:
    """In-memory row corresponding to a root_cause_hypotheses row."""

    hypothesis_id: str
    run_id: str
    span_id: str | None
    hypothesis_class: str
    confidence: float
    evidence_refs: list[Any]
    evidence_refs_digest: str
    generator: str
    reviewer_email: str | None
    reviewer_decision: str | None
    promoted_to_replay_case_id: str | None
    schema_version: str
    created_at: str


@dataclass
class _EventLogEntry:
    """In-memory taxonomy-review event for the unit-of-work."""

    name: str
    hypothesis_id: str
    payload: dict[str, Any]


class HypothesisStore(Protocol):
    """Minimal storage protocol consumed by :class:`ExplainEngine`.

    The sidecar provides a SQLite-backed implementation; tests provide
    in-memory implementations. The store owns persistence (transactional
    INSERT / UPDATE / event log append) and validates referential integrity
    against the spans and runs tables.
    """

    def span_belongs_to_run(self, run_id: str, span_id: str) -> bool:
        """Return True iff ``span_id`` is a row in ``spans`` with that run."""
        ...

    def find_by_dedupe(
        self,
        run_id: str,
        hypothesis_class: str,
        evidence_refs_digest: str,
    ) -> HypothesisRecord | None:
        """Return the existing row with the dedupe triple, if any."""

    def insert(self, record: HypothesisRecord) -> None:
        """Insert a fresh row. May raise on UNIQUE constraint violation."""

    def update_confidence(self, hypothesis_id: str, new_confidence: float) -> None:
        """Bump ``confidence`` for an existing dedupe-matched row."""

    def append_event(self, entry: _EventLogEntry) -> None:
        """Append a ``taxonomy_review_required`` (or equivalent) event."""


@dataclass
class IngestResult:
    """Outcome of a single ingest call.

    ``record`` is the row in its final persisted shape. ``deduped`` is True
    when the call merged into an existing row instead of inserting a new
    one. ``taxonomy_event`` is populated when the engine clamped an
    out-of-enum class to ``unknown``.
    """

    record: HypothesisRecord
    deduped: bool = False
    taxonomy_event: _EventLogEntry | None = None


@dataclass
class ExplainEngine:
    """Stateless engine over a pluggable :class:`HypothesisStore`."""

    store: HypothesisStore

    def ingest(self, payload: dict[str, Any]) -> IngestResult:
        """Validate, clamp, dedupe, and persist a single hypothesis envelope.

        Steps:

        1. Normalise/clamp ``hypothesis_class`` if out of enum -- the
           original is stashed in the taxonomy event payload (VAL-V2M05-014).
        2. Validate the payload against the canonical v1 schema. Generator
           regex is also enforced here.
        3. Cross-check ``span_id`` against the run's spans (when supplied);
           on miss, raise :class:`SpanNotOnRunError` (VAL-V2M05-015).
        4. Compute ``evidence_refs_digest`` and look for a dedupe match;
           if found, take ``max(old, new)`` confidence (VAL-V2M05-012).
        5. Otherwise insert. Return the final :class:`IngestResult`.
        """
        clamped_payload, taxonomy_event = self._clamp_taxonomy(dict(payload))
        validate(clamped_payload)
        if not _GENERATOR_RE.match(str(clamped_payload["generator"])):
            raise ValueError(
                f"generator {clamped_payload['generator']!r} does not match "
                f"{GENERATOR_REGEX}"
            )
        decision = clamped_payload.get("reviewer_decision")
        if decision is not None and decision not in REVIEWER_DECISIONS:
            raise ValueError(
                f"reviewer_decision {decision!r} not in {sorted(REVIEWER_DECISIONS)}"
            )

        run_id = str(clamped_payload["run_id"])
        span_id = clamped_payload.get("span_id")
        if span_id is not None and not self.store.span_belongs_to_run(
            run_id, str(span_id)
        ):
            raise SpanNotOnRunError(run_id=run_id, span_id=str(span_id))

        evidence_refs = list(clamped_payload.get("evidence_refs") or [])
        digest = canonical_evidence_refs_digest(evidence_refs)
        hypothesis_class = str(clamped_payload["hypothesis_class"])
        confidence = float(clamped_payload["confidence"])
        hypothesis_id = str(clamped_payload["hypothesis_id"])

        existing = self.store.find_by_dedupe(run_id, hypothesis_class, digest)
        if existing is not None:
            new_conf = max(existing.confidence, confidence)
            if new_conf != existing.confidence:
                self.store.update_confidence(existing.hypothesis_id, new_conf)
                existing = HypothesisRecord(**{**existing.__dict__, "confidence": new_conf})
            if taxonomy_event is not None:
                self.store.append_event(taxonomy_event)
            return IngestResult(record=existing, deduped=True, taxonomy_event=taxonomy_event)

        record = HypothesisRecord(
            hypothesis_id=hypothesis_id,
            run_id=run_id,
            span_id=str(span_id) if span_id is not None else None,
            hypothesis_class=hypothesis_class,
            confidence=confidence,
            evidence_refs=evidence_refs,
            evidence_refs_digest=digest,
            generator=str(clamped_payload["generator"]),
            reviewer_email=clamped_payload.get("reviewer_email"),
            reviewer_decision=clamped_payload.get("reviewer_decision"),
            promoted_to_replay_case_id=clamped_payload.get(
                "promoted_to_replay_case_id"
            ),
            schema_version=str(clamped_payload["schema_version"]),
            created_at=str(clamped_payload["created_at"]),
        )
        self.store.insert(record)
        if taxonomy_event is not None:
            self.store.append_event(taxonomy_event)
        return IngestResult(record=record, taxonomy_event=taxonomy_event)

    def _clamp_taxonomy(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any], _EventLogEntry | None]:
        raw = payload.get("hypothesis_class")
        if isinstance(raw, str) and raw in HYPOTHESIS_CLASSES:
            return payload, None
        original = raw
        payload["hypothesis_class"] = "unknown"
        return (
            payload,
            _EventLogEntry(
                name="taxonomy_review_required",
                hypothesis_id=str(payload.get("hypothesis_id", "")),
                payload={
                    "original_hypothesis_class": original,
                    "clamped_to": "unknown",
                    "schema_version": payload.get("schema_version"),
                },
            ),
        )


# ---------------------------------------------------------------------------
# Convenience helpers for callers building payloads at the wire layer.
# ---------------------------------------------------------------------------


def new_hypothesis_id() -> str:
    """Return a fresh UUID4 string suitable for ``hypothesis_id``."""
    return str(uuid.uuid4())


def now_rfc3339() -> str:
    """Return the current UTC timestamp formatted as RFC 3339 with ``Z``."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class InMemoryHypothesisStore:
    """In-memory :class:`HypothesisStore` for tests and local-only flows.

    The sidecar uses a SQLite-backed adapter; this implementation is
    suitable for unit tests of the engine itself.
    """

    spans_by_run: dict[str, set[str]] = field(default_factory=dict)
    rows: dict[str, HypothesisRecord] = field(default_factory=dict)
    dedupe_index: dict[tuple[str, str, str], str] = field(default_factory=dict)
    events: list[_EventLogEntry] = field(default_factory=list)

    def register_span(self, run_id: str, span_id: str) -> None:
        self.spans_by_run.setdefault(run_id, set()).add(span_id)

    # ---- HypothesisStore protocol ----------------------------------------

    def span_belongs_to_run(self, run_id: str, span_id: str) -> bool:
        return span_id in self.spans_by_run.get(run_id, set())

    def find_by_dedupe(
        self,
        run_id: str,
        hypothesis_class: str,
        evidence_refs_digest: str,
    ) -> HypothesisRecord | None:
        key = (run_id, hypothesis_class, evidence_refs_digest)
        hypothesis_id = self.dedupe_index.get(key)
        if hypothesis_id is None:
            return None
        return self.rows[hypothesis_id]

    def insert(self, record: HypothesisRecord) -> None:
        key = (
            record.run_id,
            record.hypothesis_class,
            record.evidence_refs_digest,
        )
        if key in self.dedupe_index:
            raise DuplicateHypothesis(record.hypothesis_id)
        self.rows[record.hypothesis_id] = record
        self.dedupe_index[key] = record.hypothesis_id

    def update_confidence(self, hypothesis_id: str, new_confidence: float) -> None:
        row = self.rows[hypothesis_id]
        self.rows[hypothesis_id] = HypothesisRecord(
            **{**row.__dict__, "confidence": new_confidence}
        )

    def append_event(self, entry: _EventLogEntry) -> None:
        self.events.append(entry)


# ---------------------------------------------------------------------------
# Promotion threshold (VAL-V3M4-009).
#
# Per spec AJ, a hypothesis is promoted to a replay_case ONLY after
# reviewer_decision == 'accept'. Confidence alone is not sufficient. The
# function below is the canonical promotion entry point consumed by the
# sidecar's HTTP route handler (apps/local-sidecar -> packages/explain/
# api.py) AND by any non-HTTP caller that needs the same gate.
#
# The HTTP route at api.py::_promote already enforces the same check and
# returns HTTP 422; this function is the storage-agnostic equivalent that
# raises a typed exception instead of an HTTP response, so callers above
# the HTTP boundary (e.g. a CLI batch promoter, a test harness, the
# canonical promotion-from-batch-review path) can branch on the
# exception type.
# ---------------------------------------------------------------------------


class PromotionDeniedError(Exception):
    """Raised when ``promote_hypothesis_to_replay_case`` is invoked on a
    hypothesis whose ``reviewer_decision`` is not ``'accept'``.

    Carries ``hypothesis_id`` and ``reviewer_decision`` so the caller can
    surface a structured error envelope without re-querying the row.
    """

    def __init__(
        self,
        *,
        hypothesis_id: str,
        reviewer_decision: str | None,
    ) -> None:
        super().__init__(
            f"hypothesis {hypothesis_id!r} cannot be promoted: "
            f"reviewer_decision={reviewer_decision!r}; "
            "promotion threshold requires 'accept' "
            "(spec AJ reviewer-accepted threshold)"
        )
        self.hypothesis_id = hypothesis_id
        self.reviewer_decision = reviewer_decision


class HypothesisNotFoundError(Exception):
    """Raised when ``promote_hypothesis_to_replay_case`` cannot find the
    source hypothesis row."""

    def __init__(self, hypothesis_id: str) -> None:
        super().__init__(
            f"hypothesis {hypothesis_id!r} not found"
        )
        self.hypothesis_id = hypothesis_id


# Local protocol mirror of api.PromotionService to avoid a circular import.
# api.py imports HypothesisRecord from engine.py; we cannot import
# PromotionService from api.py here without circularity. The Protocol is
# structurally identical, so any object implementing api.PromotionService
# satisfies _PromotionLike at static type-check time too.
class _PromotionLike(Protocol):
    def get_hypothesis(self, hypothesis_id: str) -> HypothesisRecord | None: ...

    def create_replay_case(
        self, *, hypothesis: HypothesisRecord
    ) -> str: ...

    def mark_promoted(
        self, *, hypothesis_id: str, replay_case_id: str
    ) -> None: ...

    def get_replay_case(self, replay_case_id: str) -> dict[str, Any] | None: ...


def promote_hypothesis_to_replay_case(
    service: _PromotionLike,
    *,
    hypothesis_id: str,
) -> str:
    """Promote an accepted hypothesis into a new replay_case.

    Enforces VAL-V3M4-009: ``reviewer_decision`` MUST equal ``'accept'``.
    Any other value (``None`` / ``'modify'`` / ``'reject'`` / ``'pending'``)
    raises :class:`PromotionDeniedError`. Confidence alone is not
    sufficient.

    Returns the ``replay_case_id`` (existing one if the hypothesis was
    already promoted; newly created one otherwise). The source row is
    marked ``promoted_to_replay_case_id`` so a subsequent call is
    idempotent.

    Raises:
      - :class:`HypothesisNotFoundError`: source row missing.
      - :class:`PromotionDeniedError`: reviewer_decision != 'accept'.
    """
    record = service.get_hypothesis(hypothesis_id)
    if record is None:
        raise HypothesisNotFoundError(hypothesis_id)
    if record.reviewer_decision != "accept":
        raise PromotionDeniedError(
            hypothesis_id=hypothesis_id,
            reviewer_decision=record.reviewer_decision,
        )
    if record.promoted_to_replay_case_id is not None:
        # Idempotent: the row was already promoted in a prior call.
        return record.promoted_to_replay_case_id
    replay_case_id = service.create_replay_case(hypothesis=record)
    service.mark_promoted(
        hypothesis_id=hypothesis_id,
        replay_case_id=replay_case_id,
    )
    return replay_case_id


# ---------------------------------------------------------------------------
# Re-export the in-memory promotion service so callers can construct it
# via ``from relay_explain.engine import InMemoryPromotionService``.
# The canonical definition lives in relay_explain.api; we import-and-
# re-export here as a convenience surface (and because the V3M4-F02
# unit tests import it alongside the new PromotionDeniedError + helper).
# This is a one-way re-export: relay_explain.api remains the owner of
# the dataclass; engine.py only forwards the name.
# ---------------------------------------------------------------------------

from relay_explain.api import InMemoryPromotionService  # noqa: E402

__all__ = [
    "DuplicateHypothesis",
    "ExplainEngine",
    "HypothesisNotFoundError",
    "HypothesisRecord",
    "HypothesisStore",
    "IngestResult",
    "InMemoryHypothesisStore",
    "InMemoryPromotionService",
    "PromotionDeniedError",
    "SpanNotOnRunError",
    "_EventLogEntry",
    "canonical_evidence_refs_digest",
    "new_hypothesis_id",
    "now_rfc3339",
    "promote_hypothesis_to_replay_case",
]
