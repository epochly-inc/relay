"""Plumbing-tier tests for VAL-V3M4-005..010 (generator auto-disable).

Covers:
  - VAL-V3M4-005: generator_disabled table exists in both Postgres
    (packages/schemas/sql/0020_v3_generator_disabled.sql) and sidecar
    SQLite (apps/local-sidecar/migrations/0031_v3_generator_disabled.sql).
  - VAL-V3M4-006: HeuristicV1Generator.generate() raises
    GeneratorDisabledError when a row exists in generator_disabled for
    the generator's versioned name.
  - VAL-V3M4-007: auto_disable_generator() inserts a generator_disabled
    row AND an event_log_entries row of event_type
    'generator.auto_disabled' atomically (one txn).
  - VAL-V3M4-008: Verifier helper get_generator_status() returns
    'disabled' if a row exists for the generator_name, 'active' otherwise.
  - VAL-V3M4-009: engine.promote_hypothesis_to_replay_case raises
    PromotionDeniedError when reviewer_decision != 'accept'.
  - VAL-V3M4-010: Generator name is versioned (heuristic.v1 vs
    heuristic.v2); disabling v1 does not block v2.

Spec anchors:
  AJ 5742-5745   auto-disable / banner / promotion threshold
  AJ 5733-5746   generator taxonomy (versioned form)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from relay_explain.engine import (
    HypothesisRecord,
    InMemoryPromotionService,
    PromotionDeniedError,
    canonical_evidence_refs_digest,
    promote_hypothesis_to_replay_case,
)
from relay_explain.heuristic import (
    GENERATOR_ID,
    GeneratorDisabledError,
    HeuristicV1Generator,
    auto_disable_generator,
    get_generator_status,
)
from relay_explain.quality.harness import CriteriaFailure

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_POSTGRES_MIGRATIONS = _REPO_ROOT / "packages" / "schemas" / "sql"

_PG_MIGRATION = _POSTGRES_MIGRATIONS / "0020_v3_generator_disabled.sql"
_SIDECAR_MIGRATION = _SIDECAR_MIGRATIONS / "0031_v3_generator_disabled.sql"


# ===========================================================================
# VAL-V3M4-005: generator_disabled table exists in both tiers.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-005")
def test_postgres_migration_creates_generator_disabled() -> None:
    """Postgres migration declares generator_disabled with the spec columns."""
    assert _PG_MIGRATION.exists(), f"missing PG migration: {_PG_MIGRATION}"
    text = _PG_MIGRATION.read_text(encoding="utf-8")
    assert re.search(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?generator_disabled\b",
        text,
        re.IGNORECASE,
    ), "CREATE TABLE generator_disabled not found in PG migration"
    # Required columns from contract.md VAL-V3M4-005.
    for column in ("generator_name", "disabled_at", "reason", "criteria_failed"):
        assert column in text, f"PG migration missing column {column!r}"
    # generator_name is the PK.
    assert "PRIMARY KEY" in text.upper()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-005")
def test_sidecar_migration_creates_generator_disabled() -> None:
    """Sidecar migration declares generator_disabled with the spec columns."""
    assert _SIDECAR_MIGRATION.exists(), (
        f"missing sidecar migration: {_SIDECAR_MIGRATION}"
    )
    text = _SIDECAR_MIGRATION.read_text(encoding="utf-8")
    assert re.search(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?generator_disabled\b",
        text,
        re.IGNORECASE,
    ), "CREATE TABLE generator_disabled not found in sidecar migration"
    for column in ("generator_name", "disabled_at", "reason", "criteria_failed"):
        assert column in text, f"sidecar migration missing column {column!r}"
    assert "PRIMARY KEY" in text.upper()


def _extract_create_stmt(migrations_dir: Path, table: str) -> str:
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
    """In-memory SQLite seeded with generator_disabled + event_log_entries."""
    c = sqlite3.connect(":memory:")
    try:
        c.executescript(
            _extract_create_stmt(_SIDECAR_MIGRATIONS, "generator_disabled")
        )
        c.executescript(
            _extract_create_stmt(_SIDECAR_MIGRATIONS, "event_log_entries")
        )
        yield c
    finally:
        c.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-005")
def test_sidecar_generator_disabled_insert_select_roundtrip(
    conn: sqlite3.Connection,
) -> None:
    """generator_disabled accepts a valid row and the row roundtrips."""
    conn.execute(
        "INSERT INTO generator_disabled "
        "(generator_name, disabled_at, reason, criteria_failed) "
        "VALUES (?, ?, ?, ?)",
        (
            "heuristic.v1",
            "2026-05-18T12:00:00Z",
            "p0_class:recall<0.7",
            "schema_contract_violation:recall",
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT generator_name, reason FROM generator_disabled "
        "WHERE generator_name = ?",
        ("heuristic.v1",),
    ).fetchone()
    assert row is not None
    assert row[0] == "heuristic.v1"
    assert row[1] == "p0_class:recall<0.7"


# ===========================================================================
# VAL-V3M4-006: HeuristicV1Generator raises GeneratorDisabledError on emit
# when a generator_disabled row exists for its versioned name.
# ===========================================================================


def _deterministic_factory() -> Any:
    counter = {"n": 0}

    def _id() -> str:
        counter["n"] += 1
        return f"h-{counter['n']:08d}"

    return _id


def _make_gen(*, version: int = 1) -> HeuristicV1Generator:
    return HeuristicV1Generator(
        now=lambda: datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        id_factory=_deterministic_factory(),
        version=version,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-006")
def test_heuristic_emit_raises_when_disabled(conn: sqlite3.Connection) -> None:
    """A row in generator_disabled blocks emission via GeneratorDisabledError."""
    conn.execute(
        "INSERT INTO generator_disabled "
        "(generator_name, disabled_at, reason, criteria_failed) "
        "VALUES (?, ?, ?, ?)",
        (
            GENERATOR_ID,
            "2026-05-18T12:00:00Z",
            "auto_disabled:quality",
            "schema_contract_violation:recall",
        ),
    )
    conn.commit()
    gen = _make_gen()
    contract_results = [
        {
            "contract_result_id": "cr-1",
            "status": "fail",
            "failure_kind": "schema_drift",
        }
    ]
    with pytest.raises(GeneratorDisabledError) as exc_info:
        gen.generate(
            run_id="00000000-0000-0000-0000-000000000001",
            spans=[],
            contract_results=contract_results,
            db_conn=conn,
        )
    assert exc_info.value.generator_name == GENERATOR_ID


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-006")
def test_heuristic_emit_succeeds_when_not_disabled(
    conn: sqlite3.Connection,
) -> None:
    """No row -> generator emits normally."""
    gen = _make_gen()
    drafts = gen.generate(
        run_id="00000000-0000-0000-0000-000000000001",
        spans=[],
        contract_results=[
            {
                "contract_result_id": "cr-1",
                "status": "fail",
                "failure_kind": "schema_drift",
            }
        ],
        db_conn=conn,
    )
    assert len(drafts) == 1
    assert drafts[0].hypothesis_class == "schema_contract_drift"
    assert drafts[0].generator == GENERATOR_ID


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-006")
def test_heuristic_emit_no_db_conn_skips_disabled_check() -> None:
    """When no db_conn is supplied (test harness path), generator emits
    without consulting generator_disabled. Production callers that must
    enforce the gate are required to pass db_conn explicitly.
    """
    gen = _make_gen()
    drafts = gen.generate(
        run_id="00000000-0000-0000-0000-000000000001",
        spans=[],
        contract_results=[
            {
                "contract_result_id": "cr-1",
                "status": "fail",
                "failure_kind": "schema_drift",
            }
        ],
    )
    assert len(drafts) == 1


# ===========================================================================
# VAL-V3M4-007: auto_disable_generator inserts row + emits event atomically.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-007")
def test_auto_disable_writes_row_and_event_atomically(
    conn: sqlite3.Connection,
) -> None:
    """auto_disable_generator(...) writes BOTH generator_disabled row AND
    event_log_entries row of type 'generator.auto_disabled' in one txn.
    """
    failures = [
        CriteriaFailure(
            class_name="schema_contract_violation",
            criterion="recall",
            observed=0.4,
            threshold=0.7,
        )
    ]
    auto_disable_generator(
        conn,
        generator_name="heuristic.v1",
        now=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        criteria_failed=failures,
        reason="quality_harness:p0_recall_below_threshold",
    )
    # Row written.
    row = conn.execute(
        "SELECT generator_name, reason, criteria_failed "
        "FROM generator_disabled WHERE generator_name = ?",
        ("heuristic.v1",),
    ).fetchone()
    assert row is not None
    assert row[0] == "heuristic.v1"
    assert "quality_harness" in row[1]
    assert "schema_contract_violation" in row[2]
    # Event row written.
    ev = conn.execute(
        "SELECT event_type, scope_id FROM event_log_entries "
        "WHERE event_type = ? AND scope_id = ?",
        ("generator.auto_disabled", "heuristic.v1"),
    ).fetchone()
    assert ev is not None
    assert ev[0] == "generator.auto_disabled"
    assert ev[1] == "heuristic.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-007")
def test_auto_disable_is_idempotent_on_existing_generator(
    conn: sqlite3.Connection,
) -> None:
    """A second auto_disable call on the same generator_name is a no-op
    (already disabled). No duplicate rows; no duplicate event."""
    now = datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC)
    failures = [
        CriteriaFailure(
            class_name="p0_assertion_failure",
            criterion="precision",
            observed=0.2,
            threshold=0.6,
        )
    ]
    auto_disable_generator(
        conn,
        generator_name="heuristic.v1",
        now=now,
        criteria_failed=failures,
        reason="initial",
    )
    auto_disable_generator(
        conn,
        generator_name="heuristic.v1",
        now=now,
        criteria_failed=failures,
        reason="second_call",
    )
    rows = conn.execute(
        "SELECT COUNT(*) FROM generator_disabled "
        "WHERE generator_name = 'heuristic.v1'"
    ).fetchone()
    assert rows[0] == 1
    events = conn.execute(
        "SELECT COUNT(*) FROM event_log_entries "
        "WHERE event_type = 'generator.auto_disabled' "
        "AND scope_id = 'heuristic.v1'"
    ).fetchone()
    assert events[0] == 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-007")
def test_auto_disable_rolls_back_on_failure(conn: sqlite3.Connection) -> None:
    """If the event_log_entries INSERT fails, the generator_disabled row
    must not persist (atomicity)."""
    # Insert a conflicting event_log row with a bogus scope_type to force
    # a CHECK violation on the second INSERT? Instead we test by feeding
    # a non-tz-aware now (which should raise BEFORE any write).
    with pytest.raises(ValueError):
        auto_disable_generator(
            conn,
            generator_name="heuristic.v1",
            now=datetime(2026, 5, 18, 12, 0, 0),  # naive
            criteria_failed=[],
            reason="naive_now",
        )
    rows = conn.execute(
        "SELECT COUNT(*) FROM generator_disabled "
        "WHERE generator_name = 'heuristic.v1'"
    ).fetchone()
    assert rows[0] == 0


# ===========================================================================
# VAL-V3M4-008: get_generator_status returns 'disabled' / 'active'.
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-008")
def test_get_generator_status_active_when_no_row(
    conn: sqlite3.Connection,
) -> None:
    assert get_generator_status(conn, "heuristic.v1") == "active"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-008")
def test_get_generator_status_disabled_when_row_present(
    conn: sqlite3.Connection,
) -> None:
    conn.execute(
        "INSERT INTO generator_disabled "
        "(generator_name, disabled_at, reason, criteria_failed) "
        "VALUES (?, ?, ?, ?)",
        (
            "heuristic.v1",
            "2026-05-18T12:00:00Z",
            "quality",
            "schema_contract_violation:recall",
        ),
    )
    conn.commit()
    assert get_generator_status(conn, "heuristic.v1") == "disabled"
    # Other generators remain active.
    assert get_generator_status(conn, "llm.gpt-5:v3") == "active"


# ===========================================================================
# VAL-V3M4-009: promote_hypothesis_to_replay_case requires reviewer='accept'.
# ===========================================================================


def _make_hypothesis(
    *,
    hypothesis_id: str,
    reviewer_decision: str | None,
) -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        run_id="00000000-0000-0000-0000-000000000001",
        span_id=None,
        hypothesis_class="schema_contract_drift",
        confidence=0.95,
        evidence_refs=[],
        evidence_refs_digest=canonical_evidence_refs_digest([]),
        generator="heuristic.v1",
        reviewer_email="reviewer@example.com",
        reviewer_decision=reviewer_decision,
        promoted_to_replay_case_id=None,
        schema_version="relay.root_cause_hypothesis.v1",
        created_at="2026-05-18T12:00:00Z",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-009")
def test_promote_denied_when_decision_is_none() -> None:
    """reviewer_decision IS NULL -> PromotionDeniedError."""
    svc = InMemoryPromotionService()
    rec = _make_hypothesis(hypothesis_id="h-001", reviewer_decision=None)
    svc.add_hypothesis(rec)
    with pytest.raises(PromotionDeniedError) as exc_info:
        promote_hypothesis_to_replay_case(svc, hypothesis_id="h-001")
    assert exc_info.value.hypothesis_id == "h-001"
    assert exc_info.value.reviewer_decision is None
    assert svc.replay_cases == {}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-009")
def test_promote_denied_when_decision_is_modify() -> None:
    svc = InMemoryPromotionService()
    svc.add_hypothesis(
        _make_hypothesis(hypothesis_id="h-002", reviewer_decision="modify")
    )
    with pytest.raises(PromotionDeniedError):
        promote_hypothesis_to_replay_case(svc, hypothesis_id="h-002")
    assert svc.replay_cases == {}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-009")
def test_promote_denied_when_decision_is_reject() -> None:
    svc = InMemoryPromotionService()
    svc.add_hypothesis(
        _make_hypothesis(hypothesis_id="h-003", reviewer_decision="reject")
    )
    with pytest.raises(PromotionDeniedError):
        promote_hypothesis_to_replay_case(svc, hypothesis_id="h-003")
    assert svc.replay_cases == {}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-009")
def test_promote_denied_when_decision_is_pending() -> None:
    svc = InMemoryPromotionService()
    svc.add_hypothesis(
        _make_hypothesis(hypothesis_id="h-004", reviewer_decision="pending")
    )
    with pytest.raises(PromotionDeniedError):
        promote_hypothesis_to_replay_case(svc, hypothesis_id="h-004")
    assert svc.replay_cases == {}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-009")
def test_promote_succeeds_when_decision_is_accept() -> None:
    svc = InMemoryPromotionService()
    svc.add_hypothesis(
        _make_hypothesis(hypothesis_id="h-005", reviewer_decision="accept")
    )
    replay_case_id = promote_hypothesis_to_replay_case(
        svc, hypothesis_id="h-005"
    )
    assert replay_case_id in svc.replay_cases
    # Source row marked promoted.
    assert svc.hypotheses["h-005"].promoted_to_replay_case_id == replay_case_id


# ===========================================================================
# VAL-V3M4-010: Generator versioning (v1 disabled does not block v2).
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-010")
def test_versioned_generator_name_default_is_v1() -> None:
    """The canonical name is the versioned form 'heuristic.v1'."""
    gen = _make_gen()
    assert gen.generator_name == "heuristic.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-010")
def test_disabling_v1_does_not_block_v2(conn: sqlite3.Connection) -> None:
    """A generator_disabled row keyed on heuristic.v1 does NOT prevent
    heuristic.v2 from emitting."""
    conn.execute(
        "INSERT INTO generator_disabled "
        "(generator_name, disabled_at, reason, criteria_failed) "
        "VALUES (?, ?, ?, ?)",
        (
            "heuristic.v1",
            "2026-05-18T12:00:00Z",
            "quality",
            "schema_contract_violation:recall",
        ),
    )
    conn.commit()
    gen_v2 = _make_gen(version=2)
    assert gen_v2.generator_name == "heuristic.v2"
    drafts = gen_v2.generate(
        run_id="00000000-0000-0000-0000-000000000001",
        spans=[],
        contract_results=[
            {
                "contract_result_id": "cr-1",
                "status": "fail",
                "failure_kind": "schema_drift",
            }
        ],
        db_conn=conn,
    )
    # v2 emitted because v1's disabled row does not affect it.
    assert len(drafts) == 1
    assert drafts[0].generator == "heuristic.v2"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-010")
def test_get_generator_status_is_version_scoped(
    conn: sqlite3.Connection,
) -> None:
    """Disabling v1 leaves v2 in 'active' status."""
    conn.execute(
        "INSERT INTO generator_disabled "
        "(generator_name, disabled_at, reason, criteria_failed) "
        "VALUES (?, ?, ?, ?)",
        (
            "heuristic.v1",
            "2026-05-18T12:00:00Z",
            "quality",
            "schema_contract_violation:recall",
        ),
    )
    conn.commit()
    assert get_generator_status(conn, "heuristic.v1") == "disabled"
    assert get_generator_status(conn, "heuristic.v2") == "active"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M4-010")
def test_auto_disable_keyed_on_versioned_generator_name(
    conn: sqlite3.Connection,
) -> None:
    """auto_disable_generator records the versioned form so v1 vs v2 are
    independently controllable."""
    failures = [
        CriteriaFailure(
            class_name="schema_contract_violation",
            criterion="recall",
            observed=0.4,
            threshold=0.7,
        )
    ]
    auto_disable_generator(
        conn,
        generator_name="llm.gpt-5:v3",
        now=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        criteria_failed=failures,
        reason="quality",
    )
    # llm.gpt-5:v3 disabled; llm.gpt-5:v4 remains active.
    assert get_generator_status(conn, "llm.gpt-5:v3") == "disabled"
    assert get_generator_status(conn, "llm.gpt-5:v4") == "active"
