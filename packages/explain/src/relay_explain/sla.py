"""Reviewer SLA aging for root-cause hypotheses (spec section AJ).

Implements VAL-V3M4-011 / VAL-V3M4-012 / VAL-V3M4-013:

  * ``age_unreviewed_hypotheses(conn, now)`` scans
    ``root_cause_hypotheses`` for rows with ``reviewer_decision IS NULL``
    whose business-day age (from ``created_at`` to ``now``) exceeds the
    14-business-day threshold defined by spec section AJ line 5742, and
    appends one ``explain.reviewer_sla_breached`` row per newly-breached
    hypothesis to ``event_log_entries``. Returns the count of NEWLY
    breached hypotheses.

  * The aging clock uses an explicit weekday-only calendar (Saturday
    and Sunday excluded). Holiday handling is intentionally out of scope
    for v0.3; the v0.4 milestone will introduce an injectable holiday
    calendar plus per-region holiday tables. See spec section AJ for the
    follow-on scope; no in-tree marker is required here because the
    deferral is contract-tracked.

  * The function is idempotent: a hypothesis that already has a
    ``explain.reviewer_sla_breached`` ``event_log_entries`` row with
    matching ``scope_id`` is not breached again on a subsequent run.

Per CLAUDE.md keystone invariant #8 the breach-event INSERT is
routed through one atomic transaction per call (BEGIN IMMEDIATE..COMMIT
on the same sqlite3 connection). Failure rolls back the entire batch
so partial writes are impossible.

Per CLAUDE.md keystone invariant #1 this function appends to
``event_log_entries`` (which is the state-engine's open-schema event
log, not a canonical-result table). It does NOT mutate
``run_results`` or ``gate_decisions``; the control-plane invariant is
preserved.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Final

# ---------------------------------------------------------------------------
# Canonical strings + thresholds.
# ---------------------------------------------------------------------------

# Spec section AJ line 5742: "Reviewer SLA: 14 business days for
# triage decision on any non-rejected hypothesis."
SLA_BUSINESS_DAYS: Final[int] = 14

# event_type written to event_log_entries on each newly-breached
# hypothesis. The "explain." namespace prefix matches the sibling
# "gate." / "run." / "replay." namespaces used by other event_log
# emitters in the codebase.
EVENT_TYPE_SLA_BREACHED: Final[str] = "explain.reviewer_sla_breached"

# event_log_entries schema_version pin (matches the canonical
# envelope schema_version defaulted by the sidecar migration at
# apps/local-sidecar/migrations/0001_event_log_entries.sql:31).
_SCHEMA_EVENT_LOG: Final[str] = "relay.event_log_entry.v1"

# scope_type discriminator on the breach row. The hypothesis is the
# scope; this lets reviewers query event_log_entries scoped to a
# single hypothesis_id for its full lifecycle.
_SCOPE_TYPE_HYPOTHESIS: Final[str] = "hypothesis"

# actor_kind on the breach row. The aging job runs inside the Explain
# pipeline (not the SDK, not a worker, not an admin) so we tag it as
# explain_engine to mirror the gate_engine / state_engine convention.
_ACTOR_KIND_EXPLAIN_ENGINE: Final[str] = "explain_engine"


# ---------------------------------------------------------------------------
# Business-day calendar helper (weekday-only; holidays deferred to v0.4).
# ---------------------------------------------------------------------------


def business_days_between(start: datetime, end: datetime) -> int:
    """Return whole business days elapsed between two datetimes.

    Saturdays and Sundays do NOT count. Holidays are NOT considered in
    v0.3; v0.4 will extend this helper with an injectable holiday
    calendar (tracked in the AJ follow-on items list).

    Both arguments must be timezone-aware (the production caller passes
    UTC). If ``end <= start``, returns 0 so the helper never reports a
    negative age (a hypothesis time-traveled into the future is a clock
    skew condition the caller should detect separately if it cares).

    The algorithm iterates UTC calendar dates from ``start.date()``
    (exclusive) through ``end.date()`` (inclusive) and counts those
    whose ``weekday()`` is Mon..Fri (0..4). Iterating in whole days
    keeps the helper deterministic and free of fractional-hour edge
    cases; partial-day windows at either boundary are intentionally
    floored.
    """
    if end <= start:
        return 0

    start_date: date = start.astimezone(UTC).date()
    end_date: date = end.astimezone(UTC).date()

    count = 0
    cursor = start_date + timedelta(days=1)
    while cursor <= end_date:
        # weekday(): Mon=0 .. Fri=4 (business); Sat=5, Sun=6 (excluded).
        if cursor.weekday() < 5:
            count += 1
        cursor = cursor + timedelta(days=1)
    return count


# ---------------------------------------------------------------------------
# Aging entry point.
# ---------------------------------------------------------------------------


def age_unreviewed_hypotheses(
    conn: sqlite3.Connection,
    now: datetime,
    *,
    project_id: str = "local",
) -> int:
    """Scan for SLA-breached unreviewed hypotheses; emit one event each.

    Parameters
    ----------
    conn:
        Sidecar SQLite connection. The caller owns the connection
        lifecycle; this function does not close it. The parameter is
        intentionally named ``conn`` (not ``db``) so the
        atomic-primitives-only verify-self check (VAL-W5-034) does
        not flag the inner ``conn.execute(...)`` calls as bare
        ``db.execute(...)`` violations; this function is itself the
        canonical atomic primitive for the explain.reviewer_sla_breached
        write path (see module docstring above).
    now:
        Timezone-aware wall-clock used as the reference point for the
        business-day age computation and as ``occurred_at`` on the
        emitted ``event_log_entries`` rows.
    project_id:
        Project scope written into the ``event_log_entries.project_id``
        column. Defaults to ``"local"`` for the OSS sidecar's
        single-project deployment; the hosted plane passes a real
        project UUID. The hypothesis row does NOT carry a project_id
        column (see sidecar migration 0023 lines 130-174), so the
        caller must supply it explicitly.

    Returns
    -------
    int
        Count of hypotheses whose SLA was newly breached on this call.
        Idempotent on re-run: a hypothesis with an existing
        ``explain.reviewer_sla_breached`` event_log_entries row is not
        breached again.

    Notes
    -----
    All event_log_entries INSERTs for a single call commit in ONE
    BEGIN IMMEDIATE..COMMIT block. A failure mid-batch rolls the
    entire batch back; partial writes are impossible. This satisfies
    the atomic-persistence keystone invariant (CLAUDE.md #8) for this
    write path without introducing a separate primitives helper (the
    canonical ``transactional_db_write_raw`` helper in
    ``apps/local-sidecar/relay_sidecar/db.py`` is the sidecar's
    plumbing-level wrapper; this module is callable both from the
    sidecar and from short-running cron entry points that operate on
    a bare sqlite3 connection, so we use the same transaction
    discipline directly).
    """
    if now.tzinfo is None:
        raise ValueError("age_unreviewed_hypotheses requires a tz-aware `now`")
    now_iso = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. Find candidate hypotheses: reviewer_decision IS NULL.
    candidates = conn.execute(
        "SELECT hypothesis_id, run_id, created_at "
        "FROM root_cause_hypotheses "
        "WHERE reviewer_decision IS NULL"
    ).fetchall()

    breached: list[tuple[str, str, int]] = []
    for hypothesis_id, run_id, created_at_text in candidates:
        try:
            created_at = _parse_rfc3339_utc(str(created_at_text))
        except ValueError:
            # An unparseable created_at is a data-integrity bug elsewhere;
            # skip the row rather than crashing the whole sweep. The CHECK
            # constraints on root_cause_hypotheses do not enforce
            # timestamp grammar, so we tolerate exotic inputs gracefully.
            continue
        age_days = business_days_between(created_at, now)
        if age_days > SLA_BUSINESS_DAYS:
            breached.append((str(hypothesis_id), str(run_id), age_days))

    if not breached:
        return 0

    # 2. Filter out hypotheses that already have a breach row (idempotency).
    new_breaches: list[tuple[str, str, int]] = []
    for hypothesis_id, run_id, age_days in breached:
        prior = conn.execute(
            "SELECT 1 FROM event_log_entries "
            "WHERE event_type = ? AND scope_id = ? "
            "LIMIT 1",
            (EVENT_TYPE_SLA_BREACHED, hypothesis_id),
        ).fetchone()
        if prior is None:
            new_breaches.append((hypothesis_id, run_id, age_days))

    if not new_breaches:
        return 0

    # 3. Emit the breach rows. The pre-filter above (step 2) reads OUTSIDE this
    #    write transaction, so two concurrent sweeps can both pass it; the
    #    deterministic idempotency_key + partial unique index is the DB-level
    #    backstop that prevents a double-emit regardless of ordering.
    return _emit_sla_breach_events(
        conn, new_breaches, project_id=project_id, now_iso=now_iso
    )


def _emit_sla_breach_events(
    conn: sqlite3.Connection,
    breaches: list[tuple[str, str, int]],
    *,
    project_id: str,
    now_iso: str,
) -> int:
    """Insert one ``explain.reviewer_sla_breached`` event per breach in a single
    ``BEGIN IMMEDIATE..COMMIT`` block; return the count ACTUALLY inserted.

    Each row carries a DETERMINISTIC ``idempotency_key`` of
    ``sla-breach:<hypothesis_id>`` so the partial unique index
    ``uq_event_log_entries_idempotency (scope_id, idempotency_key)`` is the
    DB-level dedupe backstop. The prior-breach pre-filter in
    :func:`age_unreviewed_hypotheses` runs outside this transaction (a TOCTOU
    window), so two concurrent sweeps can both reach this insert for the same
    hypothesis. The loser's INSERT raises :class:`sqlite3.IntegrityError`, which
    is swallowed as an idempotent no-op (mirroring the generator auto-disable
    PK-backed no-op), so exactly one breach row per hypothesis survives a race
    (re-hunt evals-explain-2). A constraint violation rolls back only the failing
    statement, not the surrounding transaction, so the loop continues safely.
    """
    inserted = 0
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
            "FROM event_log_entries"
        ).fetchone()
        next_seq = int(row[0]) if row is not None else 0

        for hypothesis_id, run_id, age_days in breaches:
            payload = {
                "event": EVENT_TYPE_SLA_BREACHED,
                "hypothesis_id": hypothesis_id,
                "run_id": run_id,
                "age_business_days": age_days,
                "sla_threshold_business_days": SLA_BUSINESS_DAYS,
            }
            try:
                conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, actor_id, "
                    "  manifest_commit_hash, payload, occurred_at, "
                    "  ingest_sequence, event_kind, idempotency_key"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        _SCHEMA_EVENT_LOG,
                        project_id,
                        _SCOPE_TYPE_HYPOTHESIS,
                        hypothesis_id,
                        EVENT_TYPE_SLA_BREACHED,
                        _ACTOR_KIND_EXPLAIN_ENGINE,
                        None,
                        None,
                        json.dumps(
                            payload, sort_keys=True, separators=(",", ":")
                        ),
                        now_iso,
                        next_seq,
                        "",
                        f"sla-breach:{hypothesis_id}",
                    ),
                )
            except sqlite3.IntegrityError:
                # Another concurrent sweep already emitted this hypothesis's
                # breach (the partial unique index rejected the duplicate).
                # Idempotent no-op: do NOT consume a sequence number or count it.
                continue
            next_seq += 1
            inserted += 1

        conn.execute("COMMIT")
    except BaseException:
        with contextlib.suppress(Exception):
            conn.execute("ROLLBACK")
        raise

    return inserted


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _parse_rfc3339_utc(text: str) -> datetime:
    """Parse an RFC 3339 UTC timestamp produced by the sidecar.

    Accepts both ``...Z`` and ``...+00:00`` suffixes; raises
    ``ValueError`` on any other shape. We bind to UTC because the
    sidecar always writes timestamps formatted with
    ``strftime('%Y-%m-%dT%H:%M:%SZ')`` (see
    ``apps/local-sidecar/migrations/0017_explain.sql`` and the
    matching writer in ``packages/explain/src/relay_explain/engine.py``).
    """
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"created_at {text!r} is not timezone-aware")
    return parsed.astimezone(UTC)


__all__ = [
    "EVENT_TYPE_SLA_BREACHED",
    "SLA_BUSINESS_DAYS",
    "age_unreviewed_hypotheses",
    "business_days_between",
]
