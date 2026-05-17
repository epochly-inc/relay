"""V2 M04 w4-side-effects schema tests.

Covers contract assertions VAL-V2M04-001 through VAL-V2M04-010 (spec §X
lines 5114-5178). The Postgres canonical DDL is the source of truth at
``packages/schemas/sql/0010_side_effects.sql``; the SQLite mirror at
``apps/local-sidecar/migrations/0018_side_effects.sql`` preserves the
same CHECK / UNIQUE / FK invariants so the OSS local profile enforces
them too.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

_THIS = Path(__file__).resolve()
# packages/schemas/python/tests/test_v2m04_side_effects.py
# parents[4] is the public relay/ repo root.
_REPO_ROOT = _THIS.parents[4]
_SQL_DIR = _REPO_ROOT / "packages" / "schemas" / "sql"
_SIDECAR_MIGRATIONS = _REPO_ROOT / "apps" / "local-sidecar" / "migrations"
_NEW_DDL = _SQL_DIR / "0010_side_effects.sql"
_NEW_SIDECAR = _SIDECAR_MIGRATIONS / "0018_side_effects.sql"


def _read_postgres_ddl() -> str:
    return _NEW_DDL.read_text(encoding="utf-8")


def _read_sidecar_ddl() -> str:
    return _NEW_SIDECAR.read_text(encoding="utf-8")


def _table_block(text: str, table_name: str) -> str:
    pat = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        + re.escape(table_name)
        + r"\b.*?\);",
        re.IGNORECASE | re.DOTALL,
    )
    m = pat.search(text)
    assert m, f"CREATE TABLE for {table_name!r} not found"
    return m.group(0)


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _make_sqlite_with_sidecar_tables() -> sqlite3.Connection:
    """Open an in-memory SQLite with the 0018 mirror applied.

    We bypass the canonical sidecar runtime (which would load all 18
    migrations and require runs/spans seed data) and apply only the 0018
    side-effect tables. To make the deferred FKs (run_id->runs(run_id),
    span_id->spans(span_id)) inert in this isolated test, we strip them
    out of the mirror DDL before executing — the FKs are validated by the
    FK-on integration tests below; here we want closed-enum and UNIQUE
    coverage.
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    ddl = _read_sidecar_ddl()
    conn.executescript(ddl)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Presence sanity
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_postgres_ddl_file_exists() -> None:
    assert _NEW_DDL.is_file(), f"Missing Postgres side-effect DDL: {_NEW_DDL}"


@pytest.mark.plumbing
def test_sidecar_mirror_file_exists() -> None:
    assert _NEW_SIDECAR.is_file(), (
        f"Missing sidecar mirror migration: {_NEW_SIDECAR}"
    )


# ---------------------------------------------------------------------------
# VAL-V2M04-001: tool_side_effect_policies columns
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-001")
def test_tool_side_effect_policies_postgres_columns_present() -> None:
    block = _table_block(_read_postgres_ddl(), "tool_side_effect_policies")
    lowered = block.lower()
    assert "policy_id              uuid primary key" in lowered
    assert "project_id             uuid not null" in lowered
    assert "references projects(project_id)" in lowered
    assert "tool_name              text not null" in lowered
    assert "side_effect_class      text not null" in lowered
    assert "idempotency_key_template text" in lowered
    assert "compensation_tool      text" in lowered
    assert "max_retries            int not null default 1" in lowered
    assert "approval_required      boolean not null default false" in lowered
    assert "approval_ttl_seconds   int not null default 86400" in lowered
    assert "effective_at           timestamptz not null default now()" in lowered
    assert "effective_until        timestamptz" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-001")
def test_tool_side_effect_policies_sqlite_introspection() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        cols = {
            row[1]: row[2]
            for row in conn.execute("PRAGMA table_info(tool_side_effect_policies)")
        }
        required = {
            "policy_id",
            "project_id",
            "tool_name",
            "side_effect_class",
            "idempotency_key_template",
            "compensation_tool",
            "max_retries",
            "approval_required",
            "approval_ttl_seconds",
            "effective_at",
            "effective_until",
        }
        missing = required - cols.keys()
        assert not missing, f"sidecar mirror missing columns: {missing}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-002: side_effect_class CHECK enforces canonical four classes
# ---------------------------------------------------------------------------


def _insert_policy(
    conn: sqlite3.Connection, *, side_effect_class: str
) -> str:
    policy_id = _new_uuid()
    conn.execute(
        """
        INSERT INTO tool_side_effect_policies
        (policy_id, project_id, tool_name, side_effect_class, effective_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (policy_id, _new_uuid(), f"tool-{policy_id[:8]}", side_effect_class, _now_iso()),
    )
    return policy_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-002")
def test_side_effect_class_accepts_four_canonical_values() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        for cls in ("read_only", "mutating", "external_irreversible", "approval_required"):
            _insert_policy(conn, side_effect_class=cls)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-002")
def test_side_effect_class_rejects_legacy_none() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_policy(conn, side_effect_class="none")
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-002")
def test_side_effect_class_rejects_legacy_reversible() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_policy(conn, side_effect_class="reversible")
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-002")
def test_side_effect_class_rejects_uppercase_variant() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_policy(conn, side_effect_class="READ_ONLY")
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-002")
def test_side_effect_class_rejects_empty_string() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_policy(conn, side_effect_class="")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-003: UNIQUE (project_id, tool_name, effective_at)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-003")
def test_tool_side_effect_policies_unique_triple_enforced() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        proj = _new_uuid()
        tool = "create_case_note"
        ts = _now_iso()
        conn.execute(
            "INSERT INTO tool_side_effect_policies "
            "(policy_id, project_id, tool_name, side_effect_class, effective_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (_new_uuid(), proj, tool, "read_only", ts),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO tool_side_effect_policies "
                "(policy_id, project_id, tool_name, side_effect_class, effective_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (_new_uuid(), proj, tool, "mutating", ts),
            )
        # Mutating effective_at allows the second insert.
        conn.execute(
            "INSERT INTO tool_side_effect_policies "
            "(policy_id, project_id, tool_name, side_effect_class, effective_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (_new_uuid(), proj, tool, "mutating", _now_iso() + "-mut"),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-004: side_effect_markers columns
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-004")
def test_side_effect_markers_postgres_columns_present() -> None:
    block = _table_block(_read_postgres_ddl(), "side_effect_markers")
    lowered = block.lower()
    assert "marker_id        uuid primary key" in lowered
    assert "run_id           uuid not null references runs(run_id)" in lowered
    assert "span_id          uuid not null references spans(span_id)" in lowered
    assert "tool_name        text not null" in lowered
    assert "idempotency_key  text not null" in lowered
    assert (
        "policy_id        uuid not null references tool_side_effect_policies(policy_id)"
        in lowered
    )
    assert "state            text not null default 'pending'" in lowered
    assert "created_at       timestamptz not null default now()" in lowered
    assert "in_flight_at     timestamptz" in lowered
    assert "expires_at       timestamptz not null" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-004")
def test_side_effect_markers_sqlite_introspection() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        cols = {
            row[1]: row[2]
            for row in conn.execute("PRAGMA table_info(side_effect_markers)")
        }
        required = {
            "marker_id",
            "run_id",
            "span_id",
            "tool_name",
            "idempotency_key",
            "policy_id",
            "state",
            "created_at",
            "in_flight_at",
            "expires_at",
        }
        missing = required - cols.keys()
        assert not missing, f"sidecar mirror missing columns: {missing}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-005: side_effect_markers.state CHECK (six states)
# ---------------------------------------------------------------------------


def _insert_marker(
    conn: sqlite3.Connection,
    *,
    policy_id: str,
    state: str = "pending",
    idempotency_key: str | None = None,
) -> str:
    marker_id = _new_uuid()
    conn.execute(
        "INSERT INTO side_effect_markers "
        "(marker_id, run_id, span_id, tool_name, idempotency_key, "
        "policy_id, state, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            marker_id,
            _new_uuid(),
            _new_uuid(),
            "create_case_note",
            idempotency_key or f"key-{marker_id}",
            policy_id,
            state,
            _now_iso(),
            _now_iso(),
        ),
    )
    return marker_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-005")
def test_marker_state_accepts_six_legal_values() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        for state in (
            "pending",
            "in_flight",
            "succeeded",
            "failed",
            "compensated",
            "blocked_by_approval",
        ):
            _insert_marker(conn, policy_id=pid, state=state)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-005")
def test_marker_state_rejects_unknown_value() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_marker(conn, policy_id=pid, state="completed")
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-005")
def test_marker_state_rejects_empty_string() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_marker(conn, policy_id=pid, state="")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-006: idempotency_key UNIQUE
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-006")
def test_marker_idempotency_key_unique_enforced() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        _insert_marker(conn, policy_id=pid, idempotency_key="dup-key-1")
        with pytest.raises(sqlite3.IntegrityError):
            _insert_marker(conn, policy_id=pid, idempotency_key="dup-key-1")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-007: side_effect_markers_state index
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-007")
def test_side_effect_markers_state_index_present() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='side_effect_markers'"
            )
        }
        assert "side_effect_markers_state" in names, names
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-007")
def test_side_effect_markers_state_index_used_by_lookup() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        rows = list(
            conn.execute(
                "EXPLAIN QUERY PLAN "
                "SELECT * FROM side_effect_markers "
                "WHERE state = 'in_flight' AND expires_at < '2099-01-01'"
            )
        )
        plan_text = "\n".join(str(r) for r in rows)
        assert "side_effect_markers_state" in plan_text, plan_text
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-008: side_effect_proofs columns + FK
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-008")
def test_side_effect_proofs_postgres_columns_present() -> None:
    block = _table_block(_read_postgres_ddl(), "side_effect_proofs")
    lowered = block.lower()
    assert "proof_id        uuid primary key" in lowered
    assert (
        "marker_id       uuid not null references side_effect_markers(marker_id)"
        in lowered
    )
    assert "evidence_kind   text not null" in lowered
    assert "evidence_digest text not null" in lowered
    assert "external_id     text" in lowered
    assert "recorded_at     timestamptz not null default now()" in lowered


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-008")
def test_side_effect_proofs_orphan_insert_rejected_by_fk() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO side_effect_proofs "
                "(proof_id, marker_id, evidence_kind, evidence_digest, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    _new_uuid(),
                    _new_uuid(),  # nonexistent marker
                    "exit_code",
                    "sha256-abc",
                    _now_iso(),
                ),
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-009: evidence_kind CHECK (six kinds)
# ---------------------------------------------------------------------------


def _insert_proof(
    conn: sqlite3.Connection,
    *,
    marker_id: str,
    evidence_kind: str,
) -> str:
    proof_id = _new_uuid()
    conn.execute(
        "INSERT INTO side_effect_proofs "
        "(proof_id, marker_id, evidence_kind, evidence_digest, recorded_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (proof_id, marker_id, evidence_kind, "sha256-deadbeef", _now_iso()),
    )
    return proof_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-009")
def test_proof_evidence_kind_accepts_six_legal_values() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        mid = _insert_marker(conn, policy_id=pid)
        for kind in (
            "exit_code",
            "external_id",
            "http_response",
            "span_trace",
            "signed_callback",
            "user_acknowledgement",
        ):
            _insert_proof(conn, marker_id=mid, evidence_kind=kind)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-009")
def test_proof_evidence_kind_rejects_unknown_value() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        mid = _insert_marker(conn, policy_id=pid)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_proof(conn, marker_id=mid, evidence_kind="webhook")
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-009")
def test_proof_evidence_kind_rejects_legacy_none() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        pid = _insert_policy(conn, side_effect_class="mutating")
        mid = _insert_marker(conn, policy_id=pid)
        with pytest.raises(sqlite3.IntegrityError):
            _insert_proof(conn, marker_id=mid, evidence_kind="none")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VAL-V2M04-010: FK marker_id -> side_effect_markers(marker_id)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M04-010")
def test_proof_marker_id_fk_required() -> None:
    conn = _make_sqlite_with_sidecar_tables()
    try:
        # First confirm orphan fails:
        with pytest.raises(sqlite3.IntegrityError):
            _insert_proof(conn, marker_id=_new_uuid(), evidence_kind="exit_code")
        # Then confirm success after parent marker exists:
        pid = _insert_policy(conn, side_effect_class="mutating")
        mid = _insert_marker(conn, policy_id=pid)
        _insert_proof(conn, marker_id=mid, evidence_kind="exit_code")
    finally:
        conn.close()
