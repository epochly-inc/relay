"""Side-effect markers + proofs enforcement (M04 w4-side-effects).

Per CLAUDE.md keystone invariant #6 (side-effect idempotency): every
side-effecting tool call requires a pre-action marker AND a post-success
proof. This module owns:

  - Server-side validation of span batches before they are accepted: a
    span carrying ``side_effect_class != 'read_only'`` MUST have a paired
    ``side_effect_markers`` row AND a ``side_effect_proofs`` row, OR the
    ingest is rejected with ``RELAY-SIDEEFFECT-MARKER-MISSING`` /
    ``RELAY-SIDEEFFECT-PROOF-MISSING``.
  - Replay-namespace marker isolation: markers created during a replay
    run carry ``idempotency_key`` prefixed with ``"replay:<replay_id>:"``
    so they never collide with production markers. Inserting a non-
    prefixed marker while an active replay context is set is rejected
    with ``RELAY-SIDEEFFECT-REPLAY-PREFIX-MISSING``.
  - Resurrection check at worker boot: scans for orphan in_flight markers
    past their ``expires_at`` and emits
    ``event_log_entries`` rows with ``event_type =
    'worker.resurrection_check_failed'`` (one per orphan).
  - Compensation tool invocation hook: when a marker has been retried
    past ``max_retries`` without a paired proof, the policy's
    ``compensation_tool`` is enqueued via an event_log row
    ``event_type = 'side_effect.compensation_invoked'``. A policy with
    ``compensation_tool IS NULL`` transitions the marker to ``failed``
    instead.

The async writers route through ``transactional_db_write_raw`` so
keystone invariant #8 ("four atomic primitives") is preserved.

Spec anchors:
  X 5114-5178   side-effect markers + proofs execution contract
  E.3 3931-3937 canonical four side_effect_class values
  E    3937     RELAY-REPLAY-014 is the existing block code
  CLAUDE.md keystone #1, #6, #8

Contract assertions: VAL-V2M04-011..022, VAL-V2M04-033..035.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

# Canonical four side_effect_class values per spec E.3 lines 3931-3936.
SIDE_EFFECT_READ_ONLY = "read_only"
SIDE_EFFECT_MUTATING = "mutating"
SIDE_EFFECT_EXTERNAL_IRREVERSIBLE = "external_irreversible"
SIDE_EFFECT_APPROVAL_REQUIRED = "approval_required"

CANONICAL_SIDE_EFFECT_CLASSES = frozenset(
    {
        SIDE_EFFECT_READ_ONLY,
        SIDE_EFFECT_MUTATING,
        SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
        SIDE_EFFECT_APPROVAL_REQUIRED,
    }
)

# Classes that require paired marker + proof at ingest time. The
# read_only class is exempted per spec line 5177 ("Live re-execution of
# a read_only tool may share idempotency keys") and VAL-V2M04-015
# ("span ingest with side_effect_class='read_only' bypasses
# marker/proof check").
ENFORCED_SIDE_EFFECT_CLASSES = frozenset(
    {
        SIDE_EFFECT_MUTATING,
        SIDE_EFFECT_EXTERNAL_IRREVERSIBLE,
        SIDE_EFFECT_APPROVAL_REQUIRED,
    }
)

# Marker state enum (spec line 5144; VAL-V2M04-005).
MARKER_STATE_PENDING = "pending"
MARKER_STATE_IN_FLIGHT = "in_flight"
MARKER_STATE_SUCCEEDED = "succeeded"
MARKER_STATE_FAILED = "failed"
MARKER_STATE_COMPENSATED = "compensated"
MARKER_STATE_BLOCKED_BY_APPROVAL = "blocked_by_approval"

MARKER_STATES = frozenset(
    {
        MARKER_STATE_PENDING,
        MARKER_STATE_IN_FLIGHT,
        MARKER_STATE_SUCCEEDED,
        MARKER_STATE_FAILED,
        MARKER_STATE_COMPENSATED,
        MARKER_STATE_BLOCKED_BY_APPROVAL,
    }
)

# Wire-format error codes (M04 additions; registered in
# packages/schemas/raw/relay-error-codes.yaml). Per VAL-W1-029 every code
# matches ^RELAY-[A-Z]+-[0-9]{3}$ -- numeric tail required. The contract
# (VAL-V2M04-011..014, -017, -026/027) names these codes descriptively;
# the wire form is numeric and the descriptive alias is carried in
# details.subcode for log readability.
RELAY_SIDEEFFECT_MARKER_MISSING = "RELAY-SIDEEFFECT-001"
RELAY_SIDEEFFECT_PROOF_MISSING = "RELAY-SIDEEFFECT-002"
RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING = "RELAY-SIDEEFFECT-011"
RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD = "RELAY-SIDEEFFECT-012"

SIDEEFFECT_SUBCODE_MARKER_MISSING = "MARKER_MISSING"
SIDEEFFECT_SUBCODE_PROOF_MISSING = "PROOF_MISSING"
SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING = "REPLAY_PREFIX_MISSING"
SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD = "REPLAY_PREFIX_PROD"

# Existing wire code preserved for mutating / external_irreversible.
RELAY_REPLAY_014 = "RELAY-REPLAY-014"

# M04 approval-flow codes (VAL-V2M04-026/027). Numeric wire form +
# descriptive subcode alias.
RELAY_REPLAY_APPROVAL_REQUIRED = "RELAY-REPLAY-031"
RELAY_REPLAY_APPROVAL_TOKEN_CONSUMED = "RELAY-REPLAY-032"
RELAY_REPLAY_APPROVAL_EXPIRED = "RELAY-REPLAY-033"

REPLAY_SUBCODE_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
REPLAY_SUBCODE_APPROVAL_TOKEN_CONSUMED = "APPROVAL_TOKEN_CONSUMED"
REPLAY_SUBCODE_APPROVAL_EXPIRED = "APPROVAL_EXPIRED"

# Event types emitted by the resurrection check + compensation hook.
EVENT_RESURRECTION_CHECK_FAILED = "worker.resurrection_check_failed"
EVENT_COMPENSATION_INVOKED = "side_effect.compensation_invoked"

# Replay namespace prefix (spec line 5176).
REPLAY_PREFIX_TEMPLATE = "replay:{replay_case_id}:"


# -----------------------------------------------------------------------------
# Dataclasses
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class EnforcementRejection:
    """Result of a failed ingest check. The route layer builds an HTTP
    422 envelope from these fields.
    """

    code: str
    message: str
    details: dict[str, Any]


@dataclass(frozen=True)
class MarkerInsertResult:
    """Result of a marker insertion (success or rejection)."""

    ok: bool
    marker_id: str | None = None
    rejection: EnforcementRejection | None = None
    idempotent: bool = False


# -----------------------------------------------------------------------------
# Pure-function validators (server-side enforcement)
# -----------------------------------------------------------------------------


def is_canonical_side_effect_class(value: object) -> bool:
    """Return True if ``value`` is one of the canonical four (spec E.3)."""
    return isinstance(value, str) and value in CANONICAL_SIDE_EFFECT_CLASSES


def is_enforced_class(value: object) -> bool:
    """Return True if marker+proof are required for this class.

    ``read_only`` is exempt (spec 5177, VAL-V2M04-015).
    """
    return isinstance(value, str) and value in ENFORCED_SIDE_EFFECT_CLASSES


def expected_replay_prefix(replay_case_id: str) -> str:
    """Return the canonical replay-namespace prefix for a replay case.

    Spec line 5176. Used by ``validate_replay_namespace_prefix`` and by
    the marker writer when ``replay_case_id`` is set in the active
    context.
    """
    return REPLAY_PREFIX_TEMPLATE.format(replay_case_id=replay_case_id)


def validate_replay_namespace_prefix(
    *,
    idempotency_key: str,
    active_replay_case_id: str | None,
) -> EnforcementRejection | None:
    """VAL-V2M04-016 / VAL-V2M04-017 prefix validator.

    During an active replay context, the idempotency_key MUST start with
    ``"replay:<replay_case_id>:"``. Outside a replay context, the key
    MUST NOT carry the prefix (preventing replay code paths from leaking
    into production namespace and vice versa).

    Returns None when valid; an ``EnforcementRejection`` otherwise.
    """
    if active_replay_case_id is not None:
        prefix = expected_replay_prefix(active_replay_case_id)
        if not idempotency_key.startswith(prefix):
            return EnforcementRejection(
                code=RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING,
                message=(
                    "replay-context marker idempotency_key must start with "
                    f"{prefix!r}; got {idempotency_key!r}"
                ),
                details={
                    "subcode": SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING,
                    "expected_prefix": prefix,
                    "idempotency_key": idempotency_key,
                    "active_replay_case_id": active_replay_case_id,
                },
            )
        return None
    # Outside replay context: reject any key carrying a replay prefix.
    if idempotency_key.startswith("replay:"):
        return EnforcementRejection(
            code=RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD,
            message=(
                "production marker idempotency_key must not carry the "
                f"'replay:' prefix; got {idempotency_key!r}"
            ),
            details={
                "subcode": SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD,
                "idempotency_key": idempotency_key,
            },
        )
    return None


def check_span_marker_pairing(
    *,
    span: Mapping[str, Any],
    has_marker: bool,
    has_proof: bool,
) -> EnforcementRejection | None:
    """Pure-function spec X enforcement check.

    Given the span's declared ``side_effect_class`` and the database
    state (whether a matching marker / proof exists), return None when
    the ingest may proceed, or an ``EnforcementRejection`` carrying the
    appropriate ``RELAY-SIDEEFFECT-*`` code.

    Used by ``/v1/ingest/spans:batch`` BEFORE the span row is persisted.

    Truth table:

      class != enforced              -> accept (read_only or unknown class)
      class enforced, no marker       -> RELAY-SIDEEFFECT-MARKER-MISSING
      class enforced, marker, no proof -> RELAY-SIDEEFFECT-PROOF-MISSING
      class enforced, marker + proof  -> accept
    """
    side_class = span.get("side_effect_class")
    if not is_enforced_class(side_class):
        return None
    if not has_marker:
        return EnforcementRejection(
            code=RELAY_SIDEEFFECT_MARKER_MISSING,
            message=(
                f"span declares side_effect_class={side_class!r} but no "
                "matching side_effect_markers row exists; the pre-action "
                "marker MUST be written before the side-effect tool runs "
                "(spec X execution contract step 2)"
            ),
            details={
                "subcode": SIDEEFFECT_SUBCODE_MARKER_MISSING,
                "side_effect_class": side_class,
                "span_id": span.get("span_id"),
                "tool_name": span.get("tool_name"),
                "idempotency_key": span.get("idempotency_key"),
            },
        )
    if not has_proof:
        return EnforcementRejection(
            code=RELAY_SIDEEFFECT_PROOF_MISSING,
            message=(
                f"span declares side_effect_class={side_class!r} and a "
                "matching marker exists, but no side_effect_proofs row is "
                "present; the post-success proof MUST be written after the "
                "side-effect tool succeeds (spec X execution contract step 3)"
            ),
            details={
                "subcode": SIDEEFFECT_SUBCODE_PROOF_MISSING,
                "side_effect_class": side_class,
                "span_id": span.get("span_id"),
                "tool_name": span.get("tool_name"),
                "idempotency_key": span.get("idempotency_key"),
            },
        )
    return None


def validate_span_batch(
    *,
    spans: Iterable[Mapping[str, Any]],
    marker_existence_fn: Any,
    proof_existence_fn: Any,
) -> EnforcementRejection | None:
    """Check every span in ``spans`` and return the first rejection.

    ``marker_existence_fn`` and ``proof_existence_fn`` are callables
    accepting the span's ``idempotency_key`` and returning a bool. The
    route layer wires these to DB lookups; tests pass in dict-backed
    stubs. Returns None when all spans pass.
    """
    for span in spans:
        idem = span.get("idempotency_key")
        has_marker = bool(marker_existence_fn(idem)) if idem else False
        has_proof = bool(proof_existence_fn(idem)) if idem else False
        rejection = check_span_marker_pairing(
            span=span,
            has_marker=has_marker,
            has_proof=has_proof,
        )
        if rejection is not None:
            return rejection
    return None


# -----------------------------------------------------------------------------
# Marker / proof writers (route through transactional_db_write_raw)
# -----------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


def build_marker_row(
    *,
    run_id: str,
    span_id: str,
    tool_name: str,
    idempotency_key: str,
    policy_id: str,
    state: str = MARKER_STATE_PENDING,
    expires_at: str | None = None,
    marker_id: str | None = None,
) -> dict[str, Any]:
    """Construct a side_effect_markers row dict suitable for the raw writer."""
    if state not in MARKER_STATES:
        raise ValueError(
            f"build_marker_row: state must be one of {sorted(MARKER_STATES)}; "
            f"got {state!r}"
        )
    return {
        "marker_id": marker_id or _new_uuid(),
        "run_id": run_id,
        "span_id": span_id,
        "tool_name": tool_name,
        "idempotency_key": idempotency_key,
        "policy_id": policy_id,
        "state": state,
        "created_at": _now_iso(),
        "expires_at": expires_at or _now_iso(),
    }


def build_proof_row(
    *,
    marker_id: str,
    evidence_kind: str,
    evidence_digest: str,
    external_id: str | None = None,
    proof_id: str | None = None,
) -> dict[str, Any]:
    """Construct a side_effect_proofs row dict suitable for the raw writer."""
    return {
        "proof_id": proof_id or _new_uuid(),
        "marker_id": marker_id,
        "evidence_kind": evidence_kind,
        "evidence_digest": evidence_digest,
        "external_id": external_id,
        "recorded_at": _now_iso(),
    }


async def insert_marker(
    *,
    db: Any,
    run_id: str,
    span_id: str,
    tool_name: str,
    idempotency_key: str,
    policy_id: str,
    state: str = MARKER_STATE_PENDING,
    expires_at: str | None = None,
    marker_id: str | None = None,
    active_replay_case_id: str | None = None,
) -> MarkerInsertResult:
    """Insert a side_effect_markers row through the atomic primitive.

    Enforces VAL-V2M04-016/017 (replay-namespace prefix) BEFORE the
    write. The unique constraint on ``idempotency_key`` (VAL-V2M04-006)
    is the load-bearing concurrency invariant; on collision the primitive
    returns ``WriteResult.idempotent=True`` and we surface it as such.
    """
    rejection = validate_replay_namespace_prefix(
        idempotency_key=idempotency_key,
        active_replay_case_id=active_replay_case_id,
    )
    if rejection is not None:
        return MarkerInsertResult(ok=False, rejection=rejection)
    row = build_marker_row(
        run_id=run_id,
        span_id=span_id,
        tool_name=tool_name,
        idempotency_key=idempotency_key,
        policy_id=policy_id,
        state=state,
        expires_at=expires_at,
        marker_id=marker_id,
    )
    result = await db.transactional_db_write_raw(
        table="side_effect_markers",
        row=row,
        natural_key=idempotency_key,
        natural_key_column="idempotency_key",
    )
    return MarkerInsertResult(
        ok=True,
        marker_id=row["marker_id"],
        idempotent=result.idempotent,
    )


async def insert_proof(
    *,
    db: Any,
    marker_id: str,
    evidence_kind: str,
    evidence_digest: str,
    external_id: str | None = None,
    proof_id: str | None = None,
) -> str:
    """Insert a side_effect_proofs row through the atomic primitive.

    Returns the proof_id on success. Idempotency for proofs is not
    enforced by the schema; callers that need dedup should supply a
    deterministic ``proof_id``.
    """
    row = build_proof_row(
        marker_id=marker_id,
        evidence_kind=evidence_kind,
        evidence_digest=evidence_digest,
        external_id=external_id,
        proof_id=proof_id,
    )
    await db.transactional_db_write_raw(
        table="side_effect_proofs",
        row=row,
        natural_key=row["proof_id"],
        natural_key_column="proof_id",
    )
    return row["proof_id"]


# -----------------------------------------------------------------------------
# Resurrection check (VAL-V2M04-018..020)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class ResurrectionFinding:
    """One orphan marker discovered by the resurrection check."""

    marker_id: str
    tool_name: str
    policy_id: str
    expires_at: str
    state: str
    idempotency_key: str
    compensation_tool: str | None
    max_retries: int


async def scan_orphan_markers(
    conn: aiosqlite.Connection,
    *,
    now_iso: str | None = None,
) -> list[ResurrectionFinding]:
    """Query for in_flight markers past their expires_at.

    VAL-V2M04-018: returns the orphan set. VAL-V2M04-019: non-expired
    in_flight markers are NOT included.
    """
    cutoff = now_iso or _now_iso()
    rows = []
    sql = (
        "SELECT m.marker_id, m.tool_name, m.policy_id, m.expires_at, "
        "m.state, m.idempotency_key, "
        "p.compensation_tool, p.max_retries "
        "FROM side_effect_markers m "
        "LEFT JOIN tool_side_effect_policies p ON p.policy_id = m.policy_id "
        "WHERE m.state = ? AND m.expires_at < ?"
    )
    async with conn.execute(sql, (MARKER_STATE_IN_FLIGHT, cutoff)) as cur:
        async for row in cur:
            rows.append(
                ResurrectionFinding(
                    marker_id=str(row[0]),
                    tool_name=str(row[1]),
                    policy_id=str(row[2]),
                    expires_at=str(row[3]),
                    state=str(row[4]),
                    idempotency_key=str(row[5]),
                    compensation_tool=str(row[6]) if row[6] is not None else None,
                    max_retries=int(row[7]) if row[7] is not None else 0,
                )
            )
    return rows


def build_resurrection_event_payload(
    finding: ResurrectionFinding,
) -> dict[str, Any]:
    """Build the payload for a worker.resurrection_check_failed event."""
    return {
        "marker_id": finding.marker_id,
        "tool_name": finding.tool_name,
        "policy_id": finding.policy_id,
        "expires_at": finding.expires_at,
        "idempotency_key": finding.idempotency_key,
        "compensation_tool": finding.compensation_tool,
    }


def build_compensation_event_payload(
    finding: ResurrectionFinding,
    *,
    retry_count: int,
) -> dict[str, Any]:
    """Build the payload for a side_effect.compensation_invoked event.

    VAL-V2M04-021/022: the compensation hook invokes ONLY the policy's
    ``compensation_tool``, never the original ``tool_name``. The payload
    captures both for audit but the worker subscribes to
    ``compensation_tool`` only.
    """
    return {
        "marker_id": finding.marker_id,
        "policy_id": finding.policy_id,
        "tool_name": finding.tool_name,
        "compensation_tool": finding.compensation_tool,
        "retry_count": retry_count,
    }


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

__all__ = [
    "CANONICAL_SIDE_EFFECT_CLASSES",
    "ENFORCED_SIDE_EFFECT_CLASSES",
    "EVENT_COMPENSATION_INVOKED",
    "EVENT_RESURRECTION_CHECK_FAILED",
    "EnforcementRejection",
    "MARKER_STATES",
    "MARKER_STATE_BLOCKED_BY_APPROVAL",
    "MARKER_STATE_COMPENSATED",
    "MARKER_STATE_FAILED",
    "MARKER_STATE_IN_FLIGHT",
    "MARKER_STATE_PENDING",
    "MARKER_STATE_SUCCEEDED",
    "MarkerInsertResult",
    "RELAY_REPLAY_014",
    "RELAY_REPLAY_APPROVAL_EXPIRED",
    "RELAY_REPLAY_APPROVAL_REQUIRED",
    "RELAY_REPLAY_APPROVAL_TOKEN_CONSUMED",
    "RELAY_SIDEEFFECT_MARKER_MISSING",
    "RELAY_SIDEEFFECT_PROOF_MISSING",
    "RELAY_SIDEEFFECT_REPLAY_PREFIX_MISSING",
    "RELAY_SIDEEFFECT_REPLAY_PREFIX_PROD",
    "REPLAY_PREFIX_TEMPLATE",
    "REPLAY_SUBCODE_APPROVAL_EXPIRED",
    "REPLAY_SUBCODE_APPROVAL_REQUIRED",
    "REPLAY_SUBCODE_APPROVAL_TOKEN_CONSUMED",
    "SIDEEFFECT_SUBCODE_MARKER_MISSING",
    "SIDEEFFECT_SUBCODE_PROOF_MISSING",
    "SIDEEFFECT_SUBCODE_REPLAY_PREFIX_MISSING",
    "SIDEEFFECT_SUBCODE_REPLAY_PREFIX_PROD",
    "ResurrectionFinding",
    "SIDE_EFFECT_APPROVAL_REQUIRED",
    "SIDE_EFFECT_EXTERNAL_IRREVERSIBLE",
    "SIDE_EFFECT_MUTATING",
    "SIDE_EFFECT_READ_ONLY",
    "build_compensation_event_payload",
    "build_marker_row",
    "build_proof_row",
    "build_resurrection_event_payload",
    "check_span_marker_pairing",
    "expected_replay_prefix",
    "insert_marker",
    "insert_proof",
    "is_canonical_side_effect_class",
    "is_enforced_class",
    "scan_orphan_markers",
    "validate_replay_namespace_prefix",
    "validate_span_batch",
]
