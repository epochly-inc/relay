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

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


# VAL-CANON-004 follow-up: the canonical, lexicographically-sortable UTC
# string form for marker ``expires_at`` and the resurrection cutoff.
#
# Form: ``YYYY-MM-DDTHH:MM:SS.ffffff+00:00`` -- fixed width, microsecond
# precision, explicit ``+00:00`` offset. Two properties make it the right
# choice for an index-backed range scan:
#
#   1. Fixed width + identical suffix: every value has the same byte
#      length and shares the ``+00:00`` tail, so SQLite's lexicographic
#      TEXT compare on the ``(state, expires_at)`` composite index sorts
#      EXACTLY in chronological order. (A bare ``+00:00`` convention is
#      NOT sufficient on its own: a whole-second value rendered without a
#      fraction -- ``...44+00:00`` -- sorts BEFORE ``...44.000001+00:00``
#      because ``+`` (0x2B) < ``.`` (0x2E). Forcing the microsecond
#      fraction removes that hazard.)
#   2. Single canonical writer form: the marker write path emits ONLY
#      this form, and the cutoff is computed in the same form, so the SQL
#      ``expires_at < cutoff`` compare is both correct AND able to use the
#      composite index's range bound -- restoring the index efficiency
#      that the canon-004 correctness fix had dropped.
#
# A ``Z`` suffix would be equally sortable, but ``+00:00`` is what the
# Pydantic wire layer and ``_now_iso`` already emit on the sidecar, so we
# standardize on it to minimize churn. Legacy / non-canonical rows are
# still classified correctly by the Python ``_parse_iso_to_aware_utc``
# re-check in ``scan_orphan_markers`` (the SQL index narrows; Python
# confirms), so correctness is never weaker than the canon-004
# Python-only compare.
def _canonical_expires_at(dt: datetime) -> str:
    """Return ``dt`` as the canonical sortable UTC string.

    Naive datetimes are assumed UTC (matching the writer, which only ever
    constructs aware UTC values). The result is always
    ``YYYY-MM-DDTHH:MM:SS.ffffff+00:00``.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="microseconds")


# Exact match for the canonical form. Used by ``scan_orphan_markers`` to
# tell, cheaply and without parsing, whether a stored ``expires_at`` is
# already in the lexicographically-sortable form (so its lexicographic
# order against the canonical cutoff equals its chronological order) or is
# a legacy / non-canonical value that needs the Python datetime re-check.
_CANONICAL_EXPIRES_AT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+00:00$"
)


def _is_canonical_expires_at(value: str) -> bool:
    """True if ``value`` is exactly the canonical sortable UTC form."""
    return bool(_CANONICAL_EXPIRES_AT_RE.match(value))


# Default marker lifetime when no policy-derived expires_at is supplied.
# Spec V2M04: an in_flight marker's expires_at controls when the
# resurrection scan (scan_orphan_markers) classifies it as orphaned. The
# previous default of ``_now_iso()`` made every marker an orphan as soon
# as it was written; the resurrection / compensation hook fired
# immediately and silently invalidated the side-effect idempotency
# contract. We default to one hour from creation so callers that do not
# supply an explicit lifetime get a sane, finite-but-non-zero window.
# Callers that need a different TTL (e.g. policy.approval_ttl_seconds)
# pass ``expires_at`` explicitly.
DEFAULT_MARKER_TTL_SECONDS: int = 3600


def _now_plus_seconds_iso(seconds: int) -> str:
    # VAL-CANON-004 follow-up: emit the canonical, lexicographically-
    # sortable UTC form (microsecond precision, ``+00:00`` suffix) so the
    # stored ``expires_at`` is index-comparable against the cutoff. The
    # prior ``.replace("+00:00", "Z")`` produced a ``Z`` suffix that sorted
    # inconsistently against the ``+00:00`` cutoff and was variable width
    # on a whole second.
    return _canonical_expires_at(datetime.now(tz=UTC) + timedelta(seconds=seconds))


def _parse_iso_to_aware_utc(value: str) -> datetime:
    """Parse an RFC3339/ISO-8601 timestamp to a timezone-aware UTC datetime.

    VAL-CANON-004: ``expires_at`` is serialized by
    ``_now_plus_seconds_iso`` with a ``Z`` suffix, while the resurrection
    cutoff is serialized by ``_now_iso`` with a ``+00:00`` suffix. Both
    denote UTC, but a raw lexicographic string compare treats them as
    distinct (``Z`` 0x5A sorts after ``+`` 0x2B and ``.`` 0x2E), so an
    expired ``Z``-suffixed marker can be mis-classified as live. Normalize
    BOTH sides through this parser before comparing.

    ``datetime.fromisoformat`` accepts ``+00:00`` on all supported
    Pythons; the ``Z`` suffix is only accepted natively from 3.11+, so we
    normalize it to ``+00:00`` first to keep the parse robust. A naive
    timestamp (no offset) is assumed to be UTC, matching the writer, which
    only ever emits aware UTC values.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


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
    """Construct a side_effect_markers row dict suitable for the raw writer.

    When ``expires_at`` is omitted, the row defaults to
    ``now() + DEFAULT_MARKER_TTL_SECONDS`` so the marker is not
    immediately eligible for ``scan_orphan_markers()``.
    """
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
        "expires_at": expires_at or _now_plus_seconds_iso(
            DEFAULT_MARKER_TTL_SECONDS
        ),
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


def _orphan_scan_sql(cutoff_iso: str) -> tuple[str, tuple[Any, ...]]:
    """Build the resurrection-scan SQL + params.

    VAL-CANON-004 follow-up: the filter is index-backed AND correct.

    Correctness AND efficiency both rely on the single canonical
    ``expires_at`` form (``_canonical_expires_at`` /
    ``_now_plus_seconds_iso``): every value written by the marker writer is
    fixed-width, microsecond-precision, ``+00:00``-suffixed, so SQLite's
    lexicographic TEXT compare on the ``(state, expires_at)`` composite
    index (``side_effect_markers_state``) sorts EXACTLY in chronological
    order. The cutoff is canonicalized to the same form below, so
    ``m.expires_at < ?`` is a true index range bound -- a
    ``SEARCH ... USING INDEX side_effect_markers_state (state=? AND
    expires_at<?)`` plan rather than a scan of every in_flight row.

    The earlier canon-004 fix dropped this range bound (``WHERE m.state =
    ?`` only) because the two serializers disagreed (``Z`` vs ``+00:00``)
    and a lexicographic compare mis-ordered them; canonicalizing both
    sides removes that hazard while keeping the index.

    The SQL filter NARROWS by the index; the Python
    ``_parse_iso_to_aware_utc`` re-check in ``scan_orphan_markers`` then
    CONFIRMS each candidate AND rescues any legacy / non-canonical row the
    string compare would mis-order (so correctness is never weaker than the
    canon-004 Python-only compare). See ``scan_orphan_markers``.
    """
    sql = (
        "SELECT m.marker_id, m.tool_name, m.policy_id, m.expires_at, "
        "m.state, m.idempotency_key, "
        "p.compensation_tool, p.max_retries "
        "FROM side_effect_markers m "
        "LEFT JOIN tool_side_effect_policies p ON p.policy_id = m.policy_id "
        "WHERE m.state = ? AND m.expires_at < ?"
    )
    return sql, (MARKER_STATE_IN_FLIGHT, cutoff_iso)


async def scan_orphan_markers(
    conn: aiosqlite.Connection,
    *,
    now_iso: str | None = None,
) -> list[ResurrectionFinding]:
    """Query for in_flight markers past their expires_at.

    VAL-V2M04-018: returns the orphan set. VAL-V2M04-019: non-expired
    in_flight markers are NOT included.

    VAL-CANON-004 (+ perf follow-up): the cutoff and every written
    ``expires_at`` share a single canonical, lexicographically-sortable UTC
    form, so the SQL ``state = ? AND expires_at < ?`` filter is BOTH correct
    AND index-backed by the ``(state, expires_at)`` composite index
    (``side_effect_markers_state``). Correctness is kept NO WEAKER than the
    canon-004 Python-only compare via two disjoint passes, both keyed on
    the ``state`` equality so both use the index:

      Pass 1 -- the index range scan ``expires_at < cutoff``. For a
        canonical row this lexicographic bound is exactly chronological, so
        it is the fast common path. Each matched row is CONFIRMED by the
        Python ``_parse_iso_to_aware_utc`` compare, which also rejects any
        non-canonical row that the lexicographic bound matched but is not
        actually expired (a false positive).

      Pass 2 -- the complement ``expires_at >= cutoff``, restricted to
        NON-canonical (legacy) rows. These are exactly the rows whose
        lexicographic order against the canonical cutoff can disagree with
        their chronological order (e.g. a ``Z``-suffixed or fraction-less
        value not yet normalized by migration 0034), so pass 1's bound may
        have skipped a genuinely-expired one (a false negative). Pass 2
        classifies them purely by the timezone-aware datetime compare.

    Together the two passes cover every in_flight row exactly once and the
    orphan classification ultimately rests on the timezone-aware datetime
    compare, identical to the canon-004 Python-only behavior. Once
    migration 0034 has normalized all rows, pass 2 matches no legacy rows
    and the scan is a pure index range scan.
    """
    # Canonicalize the cutoff to the single sortable form so the SQL bound
    # compares like-for-like against canonical ``expires_at`` values.
    cutoff_dt = _parse_iso_to_aware_utc(now_iso or _now_iso())
    cutoff_canonical = _canonical_expires_at(cutoff_dt)

    rows: list[ResurrectionFinding] = []
    seen_marker_ids: set[str] = set()

    def _accept(row: Any) -> None:
        marker_id = str(row[0])
        if marker_id in seen_marker_ids:
            return
        seen_marker_ids.add(marker_id)
        rows.append(
            ResurrectionFinding(
                marker_id=marker_id,
                tool_name=str(row[1]),
                policy_id=str(row[2]),
                expires_at=str(row[3]),
                state=str(row[4]),
                idempotency_key=str(row[5]),
                compensation_tool=str(row[6]) if row[6] is not None else None,
                max_retries=int(row[7]) if row[7] is not None else 0,
            )
        )

    # Pass 1: index-backed range scan over canonical values. The Python
    # re-check confirms each candidate against the timezone-aware cutoff.
    sql, params = _orphan_scan_sql(cutoff_canonical)
    async with conn.execute(sql, params) as cur:
        async for row in cur:
            if _parse_iso_to_aware_utc(str(row[3])) < cutoff_dt:
                _accept(row)

    # Pass 2: defensive fallback for legacy / non-canonical ``expires_at``
    # rows whose lexicographic order against the canonical cutoff does NOT
    # match their chronological order (so the index range bound in pass 1
    # could have skipped them). We scan the remaining in_flight rows that
    # are NOT in canonical form and classify them purely by the
    # timezone-aware datetime compare -- guaranteeing correctness is never
    # weaker than the canon-004 Python-only compare. The
    # ``expires_at >= ?`` predicate restricts pass 2 to exactly the rows
    # pass 1 did not already match (still using the same index for the
    # ``state`` equality), so the two passes are disjoint and the common
    # case (all-canonical) does zero extra per-row datetime parsing beyond
    # the confirmation in pass 1.
    fallback_sql = (
        "SELECT m.marker_id, m.tool_name, m.policy_id, m.expires_at, "
        "m.state, m.idempotency_key, "
        "p.compensation_tool, p.max_retries "
        "FROM side_effect_markers m "
        "LEFT JOIN tool_side_effect_policies p ON p.policy_id = m.policy_id "
        "WHERE m.state = ? AND m.expires_at >= ?"
    )
    async with conn.execute(
        fallback_sql, (MARKER_STATE_IN_FLIGHT, cutoff_canonical)
    ) as cur:
        async for row in cur:
            expires_at = str(row[3])
            # A value already in canonical form cannot be chronologically
            # before the canonical cutoff while lexicographically >=, so the
            # only rows that flip here are non-canonical (legacy). Skip
            # canonical rows cheaply to avoid double-classifying.
            if _is_canonical_expires_at(expires_at):
                continue
            if _parse_iso_to_aware_utc(expires_at) < cutoff_dt:
                _accept(row)

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
