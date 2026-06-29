"""Spec AJ reviewer SLA aging (14 business days).

Tests cover VAL-V3M4-011, VAL-V3M4-012, VAL-V3M4-013:

  * VAL-V3M4-011: ``age_unreviewed_hypotheses(db, now)`` finds hypotheses
    with ``reviewer_decision IS NULL`` whose business-day age exceeds 14.
  * VAL-V3M4-012: On breach, writes one ``explain.reviewer_sla_breached``
    row into ``event_log_entries`` per newly-breached hypothesis with
    payload carrying ``hypothesis_id``, ``age_business_days``, ``run_id``.
  * VAL-V3M4-013: The aging clock uses an explicit weekday-only calendar
    (Sat/Sun excluded). Holiday handling is deferred to v0.4.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from relay_explain.sla import (
    EVENT_TYPE_SLA_BREACHED,
    SLA_BUSINESS_DAYS,
    age_unreviewed_hypotheses,
    business_days_between,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"


# ===========================================================================
# Shared fixtures: SQLite with root_cause_hypotheses + event_log_entries.
# ===========================================================================


def _extract_create_stmt(migrations_dir: Path, table: str) -> str:
    """Find the last (lex-order) CREATE TABLE statement for ``table``.

    Mirrors the production migration application order (0017 then 0023
    rebuilds the table). Returns the most recent definition.
    """
    pattern = re.compile(
        rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?{re.escape(table)}"
        r"[\s\S]+?\);",
        re.IGNORECASE,
    )
    found: str | None = None
    for sql_path in sorted(migrations_dir.glob("*.sql")):
        text = sql_path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            found = match.group(0)
    assert found, f"CREATE TABLE for {table} not found"
    return found + ";\n"


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    """In-memory SQLite seeded with the two tables this module touches."""
    c = sqlite3.connect(":memory:")
    try:
        c.executescript(
            _extract_create_stmt(_SIDECAR_MIGRATIONS, "root_cause_hypotheses")
        )
        c.executescript(
            _extract_create_stmt(_SIDECAR_MIGRATIONS, "event_log_entries")
        )
        yield c
    finally:
        c.close()


def _insert_hypothesis(
    conn: sqlite3.Connection,
    *,
    hypothesis_id: str,
    run_id: str,
    created_at: datetime,
    reviewer_decision: str | None = None,
    hypothesis_class: str = "schema_contract_drift",
) -> None:
    conn.execute(
        """
        INSERT INTO root_cause_hypotheses (
          hypothesis_id, run_id, span_id, hypothesis_class, confidence,
          evidence_refs, evidence_refs_digest, generator,
          reviewer_email, reviewer_decision, promoted_to_replay_case_id,
          schema_version, created_at
        ) VALUES (?, ?, NULL, ?, 0.5,
                  '[]', ?, 'heuristic.v1',
                  NULL, ?, NULL,
                  'relay.root_cause_hypothesis.v1', ?)
        """,
        (
            hypothesis_id,
            run_id,
            hypothesis_class,
            # evidence_refs_digest must be unique per dedupe key; salt
            # with hypothesis_id so multi-row test fixtures do not
            # collide on the UNIQUE (run_id, class, digest) constraint.
            f"sha256-{hypothesis_id}",
            reviewer_decision,
            created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    conn.commit()


# ===========================================================================
# VAL-V3M4-013: business-day calendar (Sat/Sun excluded)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_business_days_zero_when_same_day() -> None:
    """Same instant -> 0 business days."""
    t = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)  # Monday
    assert business_days_between(t, t) == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_business_days_excludes_weekend() -> None:
    """Fri -> Mon spans 3 calendar days but only 1 business day."""
    fri = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)  # Friday
    mon = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)  # Monday
    # Mon - Fri = 3 calendar days. Sat/Sun excluded -> 1 business day
    # of elapsed full business-day boundaries.
    assert business_days_between(fri, mon) == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_business_days_across_two_weekends() -> None:
    """Mon -> Mon two weeks later = 10 business days."""
    a = datetime(2026, 5, 4, 9, 0, 0, tzinfo=UTC)  # Monday
    b = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)  # Monday two weeks later
    # 14 calendar days; 4 weekend days excluded -> 10 business days.
    assert business_days_between(a, b) == 10


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_business_days_negative_window_returns_zero() -> None:
    """If now < created_at the helper returns 0 (no breach in the future)."""
    a = datetime(2026, 5, 18, tzinfo=UTC)
    b = datetime(2026, 5, 11, tzinfo=UTC)  # earlier
    assert business_days_between(a, b) == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_business_days_excludes_saturday_creation_and_sunday_now() -> None:
    """Created Sat noon, asked Sun noon eight days later -> 5 business days.

    Days between Sat 2026-05-16 and Sun 2026-05-24:
      Sun17 (wknd), Mon18, Tue19, Wed20, Thu21, Fri22, Sat23 (wknd),
      Sun24 (wknd).
    Business-day count = 5 (Mon..Fri).
    """
    sat = datetime(2026, 5, 16, 12, 0, 0, tzinfo=UTC)  # Saturday
    next_sun = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)  # Sunday +8d
    assert business_days_between(sat, next_sun) == 5


# ===========================================================================
# VAL-V3M4-011: helper finds NULL-reviewer hypotheses older than threshold
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_age_helper_returns_zero_on_empty_db(conn: sqlite3.Connection) -> None:
    """No hypotheses -> 0 newly breached and no event rows."""
    now = datetime(2026, 6, 30, 12, 0, 0, tzinfo=UTC)
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 0
    row = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries WHERE event_type = ?",
        (EVENT_TYPE_SLA_BREACHED,),
    ).fetchone()
    assert row[0] == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_age_helper_finds_unreviewed_over_threshold(
    conn: sqlite3.Connection,
) -> None:
    """A hypothesis 25 business days old, no decision -> breached."""
    # Created Monday 2026-04-13 at 09:00 UTC.
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    # Now Monday 2026-05-18 at 09:00 UTC = 25 business days later
    # (35 calendar days, 10 weekend days excluded).
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-aged",
        run_id="run-aged",
        created_at=created,
    )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_age_helper_ignores_under_threshold(
    conn: sqlite3.Connection,
) -> None:
    """A hypothesis 10 business days old -> NOT breached (14 > 10)."""
    # Monday 2026-05-04 -> Monday 2026-05-18 = 10 business days.
    created = datetime(2026, 5, 4, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-young",
        run_id="run-young",
        created_at=created,
    )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_age_helper_ignores_decided_hypotheses(
    conn: sqlite3.Connection,
) -> None:
    """Decided hypotheses (any non-NULL decision) are not aged."""
    created = datetime(2026, 1, 5, 9, 0, 0, tzinfo=UTC)  # very old
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    for i, decision in enumerate(["accept", "reject", "modify", "pending"]):
        _insert_hypothesis(
            conn,
            hypothesis_id=f"hyp-decided-{i}",
            run_id=f"run-decided-{i}",
            created_at=created,
            reviewer_decision=decision,
        )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_age_helper_idempotent_does_not_double_breach(
    conn: sqlite3.Connection,
) -> None:
    """Re-running the helper does not duplicate breach events."""
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-once",
        run_id="run-once",
        created_at=created,
    )
    first = age_unreviewed_hypotheses(conn, now)
    assert first == 1
    # Second run with same now: no NEW breaches because the event row
    # already exists.
    second = age_unreviewed_hypotheses(conn, now)
    assert second == 0
    # And still only one event row total.
    row = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries "
        "WHERE event_type = ? AND scope_id = ?",
        (EVENT_TYPE_SLA_BREACHED, "hyp-once"),
    ).fetchone()
    assert row[0] == 1


# ---------------------------------------------------------------------------
# TOCTOU double-emit backstop (re-hunt evals-explain-2). The prior-breach
# pre-filter reads OUTSIDE the write transaction, so two concurrent sweeps can
# both pass it and both INSERT -> two breach rows for one hypothesis (verified
# COUNT=2). The fix gives each breach a DETERMINISTIC idempotency_key
# (``sla-breach:<hid>``) so the partial unique index
# uq_event_log_entries_idempotency (scope_id, idempotency_key) is the DB-level
# backstop; the loser's INSERT raises IntegrityError and is swallowed as an
# idempotent no-op. (The shared fixture builds only the TABLE, so these tests
# also create the index that ships in the same migration.)
# ---------------------------------------------------------------------------


def _create_idempotency_index(conn: sqlite3.Connection) -> None:
    conn.executescript(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_event_log_entries_idempotency "
        "ON event_log_entries(scope_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL;"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_sla_breach_sets_deterministic_idempotency_key(
    conn: sqlite3.Connection,
) -> None:
    _create_idempotency_index(conn)
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn, hypothesis_id="hyp-key", run_id="run-key", created_at=created
    )
    assert age_unreviewed_hypotheses(conn, now) == 1
    key = conn.execute(
        "SELECT idempotency_key FROM event_log_entries "
        "WHERE event_type = ? AND scope_id = ?",
        (EVENT_TYPE_SLA_BREACHED, "hyp-key"),
    ).fetchone()[0]
    assert key == "sla-breach:hyp-key"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_sla_breach_db_backstop_swallows_concurrent_duplicate(
    conn: sqlite3.Connection,
) -> None:
    from relay_explain.sla import _emit_sla_breach_events

    _create_idempotency_index(conn)
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn, hypothesis_id="hyp-race", run_id="run-race", created_at=created
    )
    # Winner: a real sweep emits the breach (sets the deterministic key).
    assert age_unreviewed_hypotheses(conn, now) == 1
    # Loser: a concurrent sweep that computed new_breaches BEFORE the winner
    # committed re-attempts the SAME breach. The DB unique index rejects it and
    # the helper swallows the IntegrityError -> no-op, exactly one row survives.
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    second = _emit_sla_breach_events(
        conn, [("hyp-race", "run-race", 99)], project_id="local", now_iso=now_iso
    )
    assert second == 0
    count = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries "
        "WHERE event_type = ? AND scope_id = ?",
        (EVENT_TYPE_SLA_BREACHED, "hyp-race"),
    ).fetchone()[0]
    assert count == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_sla_breach_non_dedupe_integrity_error_reraises(
    conn: sqlite3.Connection,
) -> None:
    """A NON-dedupe IntegrityError (a NOT NULL / trigger / PK-collision class
    failure, NOT the deterministic-key duplicate) MUST re-raise, not be silently
    swallowed as an idempotent no-op (roborev df5390e). Simulated with a trigger
    that rejects the breach insert; since no dedupe row exists, the handler
    re-raises and no row is committed."""
    from relay_explain.sla import _emit_sla_breach_events

    _create_idempotency_index(conn)
    conn.executescript(
        "CREATE TRIGGER reject_breach BEFORE INSERT ON event_log_entries "
        "WHEN NEW.event_type = 'explain.reviewer_sla_breached' "
        "BEGIN SELECT RAISE(ABORT, 'simulated non-dedupe constraint'); END;"
    )
    now_iso = "2026-05-18T09:00:00Z"
    with pytest.raises(sqlite3.IntegrityError):
        _emit_sla_breach_events(
            conn, [("hyp-z", "run-z", 99)], project_id="local", now_iso=now_iso
        )
    # No breach row committed (the error propagated, the batch rolled back).
    count = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries WHERE event_type = ?",
        (EVENT_TYPE_SLA_BREACHED,),
    ).fetchone()[0]
    assert count == 0


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-011")
def test_sla_breach_unrelated_row_with_same_key_reraises(
    conn: sqlite3.Connection,
) -> None:
    """If a NON-breach event row already occupies (scope_id, idempotency_key),
    the breach insert's IntegrityError MUST NOT be treated as an idempotent
    duplicate -- the existing row is not a reviewer_sla_breached event, so the
    confirmation query (now scoped by event_type) finds nothing and the error
    re-raises rather than silently suppressing the breach (roborev d08550b)."""
    import uuid

    from relay_explain.sla import (
        _ACTOR_KIND_EXPLAIN_ENGINE,
        _SCHEMA_EVENT_LOG,
        _SCOPE_TYPE_HYPOTHESIS,
        _emit_sla_breach_events,
    )

    _create_idempotency_index(conn)
    hyp = "hyp-collide"
    # Pre-insert an UNRELATED event row occupying the SAME (scope_id,
    # idempotency_key) the breach would use.
    conn.execute(
        "INSERT INTO event_log_entries ("
        "  event_id, schema_version, project_id, scope_type, scope_id, "
        "  event_type, actor_kind, actor_id, manifest_commit_hash, payload, "
        "  occurred_at, ingest_sequence, event_kind, idempotency_key"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            _SCHEMA_EVENT_LOG,
            "local",
            _SCOPE_TYPE_HYPOTHESIS,
            hyp,
            "explain.some_other_event",  # NOT a breach event
            _ACTOR_KIND_EXPLAIN_ENGINE,
            None,
            None,
            "{}",
            "2026-05-18T09:00:00Z",
            0,
            "",
            f"sla-breach:{hyp}",
        ),
    )
    conn.commit()

    with pytest.raises(sqlite3.IntegrityError):
        _emit_sla_breach_events(
            conn, [(hyp, "run", 99)], project_id="local",
            now_iso="2026-05-18T09:00:00Z",
        )
    # The unrelated row did NOT mask the failure; no breach row was written.
    cnt = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries WHERE event_type = ?",
        (EVENT_TYPE_SLA_BREACHED,),
    ).fetchone()[0]
    assert cnt == 0


# ===========================================================================
# VAL-V3M4-012: event_log_entries row with required payload fields
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-012")
def test_breach_writes_event_log_row_with_payload(
    conn: sqlite3.Connection,
) -> None:
    """The breach event carries hypothesis_id, age_business_days, run_id."""
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-evidence",
        run_id="run-evidence",
        created_at=created,
    )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 1
    rows = conn.execute(
        "SELECT event_type, scope_type, scope_id, actor_kind, payload, "
        "       occurred_at, ingest_sequence "
        "FROM event_log_entries WHERE event_type = ?",
        (EVENT_TYPE_SLA_BREACHED,),
    ).fetchall()
    assert len(rows) == 1
    (
        event_type,
        scope_type,
        scope_id,
        actor_kind,
        payload_text,
        occurred_at,
        ingest_seq,
    ) = rows[0]
    assert event_type == EVENT_TYPE_SLA_BREACHED
    assert scope_type == "hypothesis"
    assert scope_id == "hyp-evidence"
    assert actor_kind == "explain_engine"
    payload = json.loads(payload_text)
    assert payload["hypothesis_id"] == "hyp-evidence"
    assert payload["run_id"] == "run-evidence"
    assert payload["age_business_days"] == 25
    assert payload["sla_threshold_business_days"] == SLA_BUSINESS_DAYS
    # occurred_at is the `now` we passed in (RFC 3339 UTC).
    assert occurred_at == "2026-05-18T09:00:00Z"
    assert isinstance(ingest_seq, int)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-012")
def test_breach_event_ingest_sequence_monotonic(
    conn: sqlite3.Connection,
) -> None:
    """Two breaches emit rows with strictly increasing ingest_sequence."""
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-a",
        run_id="run-a",
        created_at=created,
    )
    _insert_hypothesis(
        conn,
        hypothesis_id="hyp-b",
        run_id="run-b",
        created_at=created,
    )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 2
    seqs = [
        r[0]
        for r in conn.execute(
            "SELECT ingest_sequence FROM event_log_entries "
            "WHERE event_type = ? ORDER BY scope_id ASC",
            (EVENT_TYPE_SLA_BREACHED,),
        ).fetchall()
    ]
    assert len(seqs) == 2
    assert seqs[0] != seqs[1]
    assert max(seqs) - min(seqs) == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-012")
def test_breach_event_atomic_with_no_partial_write(
    conn: sqlite3.Connection,
) -> None:
    """All breach event_log rows for one call commit together.

    Indirect proof: after a successful call, the count of new
    event_log rows equals the returned count.
    """
    created = datetime(2026, 4, 13, 9, 0, 0, tzinfo=UTC)
    now = datetime(2026, 5, 18, 9, 0, 0, tzinfo=UTC)
    for i in range(3):
        _insert_hypothesis(
            conn,
            hypothesis_id=f"hyp-multi-{i}",
            run_id=f"run-multi-{i}",
            created_at=created,
        )
    count = age_unreviewed_hypotheses(conn, now)
    assert count == 3
    row = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries WHERE event_type = ?",
        (EVENT_TYPE_SLA_BREACHED,),
    ).fetchone()
    assert row[0] == 3


# ===========================================================================
# Constant sanity: 14 business days per spec section AJ line 5742.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-013")
def test_sla_threshold_constant_is_fourteen() -> None:
    assert SLA_BUSINESS_DAYS == 14
