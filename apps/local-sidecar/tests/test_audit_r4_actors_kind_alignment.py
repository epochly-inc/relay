"""Audit-R4 (2026-05-18) actors.kind alignment regression tests.

BUG-G2: the audit-R3 batch widened envelopes.yaml + openapi.yaml
Actor.kind enum to 14 values including ``bot`` and ``reviewer``, but the
sidecar SQLite CHECK at
``apps/local-sidecar/migrations/0006_manifest_versions.sql:44-45`` was
NOT updated. Migration
``0024_audit_r4_actors_kind_alignment.sql`` rebuilds the actors table
with the canonical 14-value CHECK to close the gap.

These tier-1 plumbing tests exercise the constraint directly: applying
every migration in lex order to a fresh in-memory SQLite DB, then
attempting INSERTs that exercise the boundary of the closed enum.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

_MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"


def _apply_all_migrations(conn: sqlite3.Connection) -> None:
    """Apply every .sql file under migrations/ in lex order.

    Mirrors the production migration runner at
    ``apps/local-sidecar/relay_sidecar/db.py:580`` -- tracks applied
    filenames in ``__schema_migrations`` so destructive DROP/RENAME
    migrations run exactly once.
    """
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS __schema_migrations ("
        "  filename   TEXT PRIMARY KEY,"
        "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ");"
    )
    for sql in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        filename = sql.name
        cur = conn.execute(
            "SELECT 1 FROM __schema_migrations WHERE filename = ?",
            (filename,),
        )
        if cur.fetchone() is not None:
            continue
        conn.executescript(sql.read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO __schema_migrations (filename) VALUES (?)",
            (filename,),
        )
    conn.commit()


def _make_fresh_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    # Match production: enforce foreign keys + CHECK constraints.
    conn.execute("PRAGMA foreign_keys = ON")
    _apply_all_migrations(conn)
    return conn


@pytest.mark.plumbing
def test_audit_r4_actors_kind_accepts_bot() -> None:
    """``kind='bot'`` MUST be INSERTable post-0024 (was rejected pre-0024).

    Mirrors the wire-format Actor.kind enum locked in envelopes.yaml and
    openapi.yaml during audit-R3.
    """
    conn = _make_fresh_db()
    try:
        conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, registered_at) VALUES (?, ?, ?)",
            (
                "sha256-" + "a" * 64,
                "bot",
                "2026-05-18T00:00:00Z",
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT kind FROM actors WHERE identity_hash = ?",
            ("sha256-" + "a" * 64,),
        ).fetchone()
        assert row is not None
        assert row[0] == "bot"
    finally:
        conn.close()


@pytest.mark.plumbing
def test_audit_r4_actors_kind_accepts_reviewer() -> None:
    """``kind='reviewer'`` MUST be INSERTable post-0024."""
    conn = _make_fresh_db()
    try:
        conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, registered_at) VALUES (?, ?, ?)",
            (
                "sha256-" + "b" * 64,
                "reviewer",
                "2026-05-18T00:00:00Z",
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT kind FROM actors WHERE identity_hash = ?",
            ("sha256-" + "b" * 64,),
        ).fetchone()
        assert row is not None
        assert row[0] == "reviewer"
    finally:
        conn.close()


@pytest.mark.plumbing
def test_audit_r4_actors_kind_rejects_invalid_kind() -> None:
    """An unknown kind MUST fail the CHECK constraint.

    Guards against accidental widening of the closed enum: only the 14
    canonical values are admissible. ``invalid_kind`` is not one of
    them, so the INSERT must raise sqlite3.IntegrityError.
    """
    conn = _make_fresh_db()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO actors "
                "(identity_hash, kind, registered_at) VALUES (?, ?, ?)",
                (
                    "sha256-" + "c" * 64,
                    "invalid_kind",
                    "2026-05-18T00:00:00Z",
                ),
            )
            conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
def test_audit_r4_actors_kind_accepts_all_14_canonical_values() -> None:
    """Every one of the 14 canonical Actor.kind values MUST be INSERTable.

    This is the byte-equal pair to
    ``test_d9b_actor_kind_envelopes_yaml_widened`` and
    ``test_d9b_actor_kind_openapi_yaml_widened`` in
    ``packages/schemas/python/tests/test_audit_r3_schema_fixes.py``: those
    tests assert the wire layer matches the canonical set; this test
    asserts the sidecar SQLite layer matches it too. Drift between
    any of the three is a P0 violation of keystone #4 (three-anchor
    handoff).
    """
    canonical = [
        "human",
        "bot",
        "reviewer",
        "sdk",
        "machine",
        "worker",
        "gate_engine",
        "result_writer",
        "evidence_signer",
        "cron",
        "control_plane",
        "validation_worker",
        "ingest_worker",
        "replay_worker",
    ]
    conn = _make_fresh_db()
    try:
        for idx, kind in enumerate(canonical):
            # 64-hex hashes derived from the index to keep them distinct.
            ihex = f"{idx:064x}"
            conn.execute(
                "INSERT INTO actors "
                "(identity_hash, kind, registered_at) VALUES (?, ?, ?)",
                ("sha256-" + ihex, kind, "2026-05-18T00:00:00Z"),
            )
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM actors").fetchone()[0]
        assert count == len(canonical)
    finally:
        conn.close()
