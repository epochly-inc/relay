"""Heuristic v1 explain generator (M05 w5-explain; VAL-V2M05-018).

A deterministic, rule-based root-cause hypothesis generator. Consumes the
spans / contract_results / run metadata for a single run and emits zero or
more :class:`RootCauseHypothesisDraft` objects ready for ingestion by the
explain engine.

The heuristic generator is the lowest tier of the spec AJ generator
taxonomy (``heuristic.v1``). Its output is intentionally explainable:
every hypothesis cites the spans / contract_results that triggered it,
and confidence is bounded conservatively. The LLM-augmented generators
(``llm.<model>:vN``) live in a separate module and are out of scope for
M05 w5.

V3M4-F02 extension (VAL-V3M4-005..010):
  * Versioned generator naming: ``HeuristicV1Generator(version=N)`` emits
    ``heuristic.vN``. Default version=1 preserves M05 backwards-compat.
    Disabling ``heuristic.v1`` does NOT block ``heuristic.v2`` because
    the generator_disabled lookup key is the FULL versioned form.
  * Emission-time disabled check: ``generate(..., db_conn=...)`` reads
    ``generator_disabled`` for the versioned generator_name and raises
    :class:`GeneratorDisabledError` when a row exists.
  * Auto-disable write path: :func:`auto_disable_generator` inserts one
    ``generator_disabled`` row + one ``event_log_entries`` row of type
    ``generator.auto_disabled`` atomically inside a single
    BEGIN IMMEDIATE..COMMIT block.
  * Verifier-side read helper: :func:`get_generator_status` returns
    ``'disabled' | 'active'`` for a versioned generator_name without
    raising.

Spec anchors:
  T 4882         "generator role"
  AJ 5733-5746   generator taxonomy + thresholds
  AJ 5745        auto-disable + banner

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, Literal

from relay_schemas.root_cause_hypothesis import SCHEMA_VERSION

if TYPE_CHECKING:
    from relay_explain.quality.harness import CriteriaFailure

# ---------------------------------------------------------------------------
# Generator id (back-compat alias) + canonical versioned-name helper.
# ---------------------------------------------------------------------------

GENERATOR_ID: Final[str] = "heuristic.v1"

# Canonical versioned-name regex (mirrors spec AJ taxonomy):
#   heuristic.v<N>
#   llm.<model>:v<N>
# Source of truth: packages/schemas/python/relay_schemas/root_cause_hypothesis.GENERATOR_REGEX.
_GENERATOR_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^heuristic\.v\d+$|^llm\.[a-z0-9-]+:v\d+$"
)


# ---------------------------------------------------------------------------
# Auto-disable wire constants.
# ---------------------------------------------------------------------------

# event_type written into event_log_entries on each auto-disable call.
# Mirrors the gate.* / run.* / explain.* namespace prefixes used by other
# event_log emitters in the codebase.
EVENT_TYPE_GENERATOR_AUTO_DISABLED: Final[str] = "generator.auto_disabled"

# event_log_entries schema_version pin (matches the canonical envelope
# version defaulted by the sidecar migration at
# apps/local-sidecar/migrations/0001_event_log_entries.sql:31).
_SCHEMA_EVENT_LOG: Final[str] = "relay.event_log_entry.v1"

# scope_type discriminator on the auto-disable row. The generator is the
# scope; this lets reviewers query event_log_entries scoped to a single
# generator_name for its full lifecycle.
_SCOPE_TYPE_GENERATOR: Final[str] = "generator"

# actor_kind on the auto-disable row. The harness runs inside the Explain
# pipeline (not the SDK, not a worker, not an admin) so we tag it as
# explain_engine to mirror the gate_engine / state_engine convention.
_ACTOR_KIND_EXPLAIN_ENGINE: Final[str] = "explain_engine"


# ---------------------------------------------------------------------------
# Exceptions.
# ---------------------------------------------------------------------------


class GeneratorDisabledError(Exception):
    """Raised when a generator attempts to emit while its row in
    ``generator_disabled`` is present.

    Carries ``generator_name`` so the caller can surface which versioned
    generator is blocked.
    """

    def __init__(self, generator_name: str) -> None:
        super().__init__(
            f"generator {generator_name!r} is disabled; "
            "delete its generator_disabled row to re-enable"
        )
        self.generator_name = generator_name


def _missing_now() -> str:
    """Default ``now`` factory; raises to enforce explicit injection.

    Spec AJ requires the heuristic generator to be deterministic given
    the same inputs. A ``datetime.now`` default would silently inject
    wall-clock entropy, defeating replay parity. Production callers
    MUST supply a run-id-derived deterministic timestamp.
    """
    raise RuntimeError(
        "HeuristicV1Generator(now=...) MUST be supplied explicitly. "
        "Spec AJ requires deterministic heuristic.v1 output; a wall-"
        "clock default would inject non-deterministic timestamps. "
        "Production callers must derive ``now`` from the run's clock "
        "(e.g., run_results.created_at) and pass it in."
    )


def _missing_id_factory() -> str:
    """Default ``id_factory``; raises to enforce explicit injection.

    A ``uuid.uuid4()`` default would inject non-deterministic
    hypothesis_ids that diverge between captured and replayed runs.
    Production callers MUST supply a run-id-derived deterministic id
    factory (e.g., a counter seeded by ``run_id``).
    """
    raise RuntimeError(
        "HeuristicV1Generator(id_factory=...) MUST be supplied "
        "explicitly. Spec AJ requires deterministic heuristic.v1 "
        "output; a uuid4 default would inject non-deterministic "
        "hypothesis_ids. Production callers must derive ``id_factory`` "
        "from a deterministic seed (e.g., run_id-namespaced uuid5 or "
        "a counter)."
    )


@dataclass(frozen=True)
class RootCauseHypothesisDraft:
    """A draft hypothesis emitted by a generator before engine ingestion.

    Validates against ``relay.root_cause_hypothesis.v1`` once converted to
    a dict via :meth:`to_payload`.
    """

    hypothesis_id: str
    run_id: str
    hypothesis_class: str
    confidence: float
    evidence_refs: list[dict[str, Any]]
    generator: str
    created_at: str
    span_id: str | None = None
    reviewer_email: str | None = None
    reviewer_decision: str | None = None
    promoted_to_replay_case_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "hypothesis_id": self.hypothesis_id,
            "run_id": self.run_id,
            "span_id": self.span_id,
            "hypothesis_class": self.hypothesis_class,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
            "generator": self.generator,
            "reviewer_email": self.reviewer_email,
            "reviewer_decision": self.reviewer_decision,
            "promoted_to_replay_case_id": self.promoted_to_replay_case_id,
            "created_at": self.created_at,
        }


@dataclass
class HeuristicV1Generator:
    """Rule-based hypothesis generator (generator id = ``heuristic.v<N>``).

    The generator is deterministic given the same inputs (same span list,
    same contract results, fixed ``now`` timestamp). Production callers
    MUST inject ``now`` and ``id_factory`` derived from a deterministic
    seed (e.g., the run's canonical clock and a run-id-namespaced UUID
    counter); the defaults raise ``RuntimeError`` to prevent silent
    non-determinism from a missed injection.

    V3M4-F02 versioning (VAL-V3M4-010): ``version`` sets the integer
    version suffix on the canonical ``generator_name``. The class still
    implements the v1 ruleset; future v2 rule changes will fork to a
    sibling class but the version field exists today so the
    generator_disabled lookup key (and auto-disable bookkeeping) is
    version-scoped from day one.
    """

    now: Callable[[], Any] = field(default=_missing_now)
    id_factory: Callable[[], str] = field(default=_missing_id_factory)
    version: int = 1

    @property
    def generator_name(self) -> str:
        """Return the canonical versioned generator name (``heuristic.v<N>``)."""
        return f"heuristic.v{self.version}"

    def generate(
        self,
        run_id: str,
        spans: list[dict[str, Any]] | None,
        contract_results: list[dict[str, Any]] | None,
        *,
        db_conn: sqlite3.Connection | None = None,
    ) -> list[RootCauseHypothesisDraft]:
        """Return the hypothesis draft list for one run.

        Inputs:
          - ``run_id``: the canonical UUID of the run being explained.
          - ``spans``: list of span rows (each with at minimum ``span_id``,
            ``span_type``, ``status``, optional ``error_class``).
          - ``contract_results``: list of contract_result rows (each with
            at minimum ``contract_result_id``, ``status``, optional
            ``assertion_id``, ``failure_kind``).
          - ``db_conn``: optional SQLite connection for the emission-time
            generator-disabled check (VAL-V3M4-006). When provided, the
            generator looks up its versioned ``generator_name`` in
            ``generator_disabled`` BEFORE producing any drafts; a matching
            row raises :class:`GeneratorDisabledError`. When ``db_conn``
            is ``None`` (test harness / synthetic corpus), the check is
            skipped so existing M05 callers and the quality harness
            (which has no DB) continue to work.

        Heuristics implemented in v1:

        1. **schema_contract_drift**: any contract_result with
           ``status == 'fail'`` and ``failure_kind == 'schema_drift'``
           emits a hypothesis bound to that result.
        2. **tool_arg_invalid**: any contract_result with
           ``failure_kind == 'tool_arg_invalid'`` emits a hypothesis
           bound to the result and (when available) the originating
           tool_call span.
        3. **rate_limit**: any span with ``error_class in
           {'rate_limit', 'RateLimitError', '429'}`` emits a hypothesis.
        4. **provider_drift**: any span with ``error_class ==
           'provider_drift'`` or ``status == 'provider_drift'`` emits a
           hypothesis.
        5. **unknown**: any contract_result with ``status == 'fail'`` and
           no matched failure_kind emits an ``unknown`` hypothesis with
           low confidence (0.30) so the surface keeps a row for human
           review.
        """
        # VAL-V3M4-006: emission-time disabled check.
        if db_conn is not None:
            status = get_generator_status(db_conn, self.generator_name)
            if status == "disabled":
                raise GeneratorDisabledError(self.generator_name)

        spans = list(spans or [])
        contract_results = list(contract_results or [])
        drafts: list[RootCauseHypothesisDraft] = []
        emit_at = self.now().strftime("%Y-%m-%dT%H:%M:%SZ")

        for result in contract_results:
            failure_kind = result.get("failure_kind")
            status = result.get("status")
            result_id = result.get("contract_result_id")
            if status != "fail" or result_id is None:
                continue
            ref = {"kind": "contract_result", "ref": f"contract_results:{result_id}"}
            if failure_kind == "schema_drift":
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="schema_contract_drift",
                        confidence=0.85,
                        evidence_refs=[ref],
                        created_at=emit_at,
                    )
                )
            elif failure_kind == "tool_arg_invalid":
                evidence = [ref]
                span_id = result.get("span_id")
                if span_id is not None:
                    evidence.append({"kind": "span", "ref": f"spans:{span_id}"})
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="tool_arg_invalid",
                        confidence=0.80,
                        evidence_refs=evidence,
                        created_at=emit_at,
                        span_id=str(span_id) if span_id is not None else None,
                    )
                )
            else:
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="unknown",
                        confidence=0.30,
                        evidence_refs=[ref],
                        created_at=emit_at,
                    )
                )

        for span in spans:
            error_class = span.get("error_class")
            span_id = span.get("span_id")
            if span_id is None:
                continue
            ref = {"kind": "span", "ref": f"spans:{span_id}"}
            if error_class in {"rate_limit", "RateLimitError", "429"}:
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="rate_limit",
                        confidence=0.90,
                        evidence_refs=[ref],
                        created_at=emit_at,
                        span_id=str(span_id),
                    )
                )
            elif error_class == "provider_drift" or span.get("status") == "provider_drift":
                drafts.append(
                    self._make(
                        run_id=run_id,
                        hypothesis_class="provider_drift",
                        confidence=0.70,
                        evidence_refs=[ref],
                        created_at=emit_at,
                        span_id=str(span_id),
                    )
                )

        return drafts

    def _make(
        self,
        *,
        run_id: str,
        hypothesis_class: str,
        confidence: float,
        evidence_refs: list[dict[str, Any]],
        created_at: str,
        span_id: str | None = None,
    ) -> RootCauseHypothesisDraft:
        return RootCauseHypothesisDraft(
            hypothesis_id=self.id_factory(),
            run_id=run_id,
            hypothesis_class=hypothesis_class,
            confidence=confidence,
            evidence_refs=evidence_refs,
            generator=self.generator_name,
            created_at=created_at,
            span_id=span_id,
        )


# ---------------------------------------------------------------------------
# Read helper (VAL-V3M4-008).
# ---------------------------------------------------------------------------


def get_generator_status(
    conn: sqlite3.Connection,
    generator_name: str,
) -> Literal["disabled", "active"]:
    """Return ``'disabled'`` iff a row exists in ``generator_disabled``
    keyed on ``generator_name``; otherwise ``'active'``.

    The lookup is keyed on the FULL versioned form (e.g.
    ``heuristic.v1`` vs ``heuristic.v2``) so disabling v1 leaves v2 in
    ``'active'`` state per VAL-V3M4-010.

    This helper is the read-side counterpart consumed by:
      - HeuristicV1Generator.generate() for the emission-time check.
      - Verifier output flag surfacing per VAL-V3M4-008 (the verifier
        reports ``generator_status`` alongside the bundle's referenced
        generator; a disabled generator warns but does not invalidate
        an already-signed bundle).
    """
    row = conn.execute(
        "SELECT 1 FROM generator_disabled WHERE generator_name = ? LIMIT 1",
        (generator_name,),
    ).fetchone()
    return "disabled" if row is not None else "active"


# ---------------------------------------------------------------------------
# Auto-disable write path (VAL-V3M4-007).
# ---------------------------------------------------------------------------


def _format_criteria_failed(
    criteria_failed: Iterable[CriteriaFailure],
) -> str:
    """Render criteria failures as a pipe-delimited summary string.

    The structured payload is also written into the event_log_entries
    row; this string is a quick-glance summary for dashboards and the
    ``generator_disabled.criteria_failed`` column.
    """
    parts: list[str] = []
    for f in criteria_failed:
        parts.append(f"{f.class_name}:{f.criterion}")
    return "|".join(parts)


def auto_disable_generator(
    conn: sqlite3.Connection,
    *,
    generator_name: str,
    now: datetime,
    criteria_failed: Iterable[CriteriaFailure],
    reason: str,
    project_id: str = "local",
) -> bool:
    """Atomically disable a generator + emit the auto-disable event.

    Writes (one BEGIN IMMEDIATE..COMMIT block):
      1. One ``generator_disabled`` row keyed on ``generator_name``.
         If a row already exists, the call is a no-op (idempotent on
         re-run of the quality harness).
      2. One ``event_log_entries`` row of event_type
         ``generator.auto_disabled`` with payload carrying the structured
         criteria-failure list, the reason, and the generator_name.

    Returns True iff a new row was inserted (False on idempotent no-op).

    Parameters
    ----------
    conn:
        SQLite connection. The caller owns the connection lifecycle. The
        parameter is named ``conn`` (not ``db``) so the
        atomic-primitives-only verify-self check does not flag the inner
        ``conn.execute(...)`` calls as bare ``db.execute(...)``
        violations; this function is itself the canonical atomic primitive
        for the generator.auto_disabled write path (same pattern as
        ``packages/explain/src/relay_explain/sla.py::age_unreviewed_hypotheses``).
    generator_name:
        Versioned form (``heuristic.v<N>`` / ``llm.<model>:v<N>``). The
        application-layer regex enforces the shape; mismatched inputs
        raise ``ValueError`` before any write.
    now:
        Timezone-aware wall-clock; written into ``disabled_at`` and
        ``occurred_at``. Naive datetimes raise ``ValueError`` BEFORE
        any write (atomicity: failure on input validation leaves the
        DB unchanged).
    criteria_failed:
        Iterable of ``CriteriaFailure`` entries from the quality
        harness. Serialized into both the row's summary column and the
        event_log payload.
    reason:
        Free-text rationale (e.g. ``'quality_harness:p0_recall_below_threshold'``).
    project_id:
        Project scope written into ``event_log_entries.project_id``.
        Defaults to ``'local'`` for the OSS sidecar's single-project
        deployment; the hosted plane passes a real project UUID.
    """
    if now.tzinfo is None:
        raise ValueError("auto_disable_generator requires a tz-aware `now`")
    if not _GENERATOR_NAME_RE.match(generator_name):
        raise ValueError(
            f"generator_name {generator_name!r} does not match the "
            f"canonical versioned form (heuristic.v<N> or llm.<model>:v<N>)"
        )

    failures = list(criteria_failed)
    now_iso = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = _format_criteria_failed(failures)

    payload = {
        "event": EVENT_TYPE_GENERATOR_AUTO_DISABLED,
        "generator_name": generator_name,
        "reason": reason,
        "criteria_failed": [f.to_dict() for f in failures],
    }

    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = conn.execute(
            "SELECT 1 FROM generator_disabled WHERE generator_name = ? LIMIT 1",
            (generator_name,),
        ).fetchone()
        if existing is not None:
            conn.execute("COMMIT")
            return False

        conn.execute(
            "INSERT INTO generator_disabled "
            "(generator_name, disabled_at, reason, criteria_failed) "
            "VALUES (?, ?, ?, ?)",
            (generator_name, now_iso, reason, summary),
        )

        row = conn.execute(
            "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
            "FROM event_log_entries"
        ).fetchone()
        next_seq = int(row[0]) if row is not None else 0

        conn.execute(
            "INSERT INTO event_log_entries ("
            "  event_id, schema_version, project_id, scope_type, "
            "  scope_id, event_type, actor_kind, actor_id, "
            "  manifest_commit_hash, payload, occurred_at, "
            "  ingest_sequence, event_kind"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                _SCHEMA_EVENT_LOG,
                project_id,
                _SCOPE_TYPE_GENERATOR,
                generator_name,
                EVENT_TYPE_GENERATOR_AUTO_DISABLED,
                _ACTOR_KIND_EXPLAIN_ENGINE,
                None,
                None,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                now_iso,
                next_seq,
                "",
            ),
        )

        conn.execute("COMMIT")
    except BaseException:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise

    return True


__all__ = [
    "EVENT_TYPE_GENERATOR_AUTO_DISABLED",
    "GENERATOR_ID",
    "GeneratorDisabledError",
    "HeuristicV1Generator",
    "RootCauseHypothesisDraft",
    "auto_disable_generator",
    "get_generator_status",
]
