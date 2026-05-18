"""Audit fix: sidecar ``scope_state`` table must enforce the per-kind
state set as defense-in-depth (VAL-W1-011 mirror).

The canonical Postgres schema at
``packages/schemas/sql/0002_control_plane.sql`` (extended by
``0008_scope_state_extension.sql``) carries a cross-column CHECK
constraint ``scope_state_state_per_kind`` that rejects e.g.
``(scope_kind='run', state='building')`` because ``building`` is not in
the legal state set for ``run`` scopes.

Pre-fix the sidecar accepted ANY (scope_kind, state) combination so long
as ``scope_kind`` itself was in the kind enum -- which defeats the
defense-in-depth this CHECK is meant to provide. The fix lands a SQLite
trigger (BEFORE INSERT + BEFORE UPDATE) that mirrors the canonical
per-kind CHECK and aborts with ``RELAY-STATE-003``.

Per-kind legal state sets (mirror of
``packages/schemas/sql/0008_scope_state_extension.sql`` lines 110-133):

  - run             -> {pending, captured, validating, gated,
                        result_written, terminal}
  - replay_case     -> {proposed, fixtures_ready, executing, analyzed,
                        terminal}
  - gate_round      -> {open, draft_received, evaluating, decision_written,
                        restarted, terminal}
  - evidence_bundle -> {building, signed, published, superseded, revoked}
  - eval_run        -> {pending, running, scored, terminal}
  - release         -> {open, gated, released, rolled_back, terminal}

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import aiosqlite
import pytest

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[1] / "migrations"
)


async def _bootstrap(db_path: Path) -> None:
    # Audit-R3 (2026-05-18): mirror __schema_migrations tracker so the
    # FastAPI lifespan _run_migrations pass skips already-applied non-
    # idempotent migrations (e.g. 0023 DROP COLUMN).
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.executescript(
            "CREATE TABLE IF NOT EXISTS __schema_migrations ("
            "  filename   TEXT PRIMARY KEY,"
            "  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ");"
        )
        for sql in sorted(MIGRATIONS_DIR.glob("*.sql")):
            filename = sql.name
            async with conn.execute(
                "SELECT 1 FROM __schema_migrations WHERE filename = ?",
                (filename,),
            ) as cur:
                if await cur.fetchone() is not None:
                    continue
            await conn.executescript(sql.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO __schema_migrations (filename) VALUES (?)",
                (filename,),
            )
        await conn.commit()


# ---------------------------------------------------------------------------
# Each (scope_kind, state) pair in this matrix is INVALID per spec sectionW
# and the canonical Postgres CHECK. The sidecar MUST reject all of them.
# ---------------------------------------------------------------------------

INVALID_COMBINATIONS = [
    # state belongs to evidence_bundle, not run
    ("run", "building"),
    # state belongs to gate_round, not run
    ("run", "draft_received"),
    # state belongs to run, not replay_case
    ("replay_case", "captured"),
    # state belongs to evidence_bundle, not replay_case
    ("replay_case", "signed"),
    # state belongs to run, not gate_round
    ("gate_round", "captured"),
    # state belongs to replay_case, not gate_round
    ("gate_round", "proposed"),
    # state belongs to run, not evidence_bundle
    ("evidence_bundle", "captured"),
    # state belongs to gate_round, not evidence_bundle
    ("evidence_bundle", "open"),
    # state belongs to evidence_bundle, not eval_run
    ("eval_run", "signed"),
    # state belongs to release, not eval_run
    ("eval_run", "released"),
    # state belongs to evidence_bundle, not release
    ("release", "signed"),
    # state belongs to eval_run, not release
    ("release", "scored"),
    # totally unknown state
    ("run", "not_a_real_state"),
]


@pytest.mark.plumbing
@pytest.mark.parametrize(("scope_kind", "state"), INVALID_COMBINATIONS)
@pytest.mark.asyncio
async def test_insert_rejects_invalid_kind_state_combination(
    tmp_path: Path, scope_kind: str, state: str
) -> None:
    """Inserting an invalid (scope_kind, state) pair MUST raise."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    async with aiosqlite.connect(str(db_path)) as conn:
        # epoch=1 to bypass the initial-state trigger (we want the
        # per-kind state check itself to fire, independent of the
        # initial-state policy).
        with pytest.raises(aiosqlite.IntegrityError) as exc_info:
            await conn.execute(
                "INSERT INTO scope_state ("
                "scope_kind, scope_id, project_id, state, epoch, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 1, ?, ?)",
                (
                    scope_kind,
                    "11111111-1111-1111-1111-111111111111",
                    "00000000-0000-0000-0000-000000000000",
                    state,
                    "2026-05-17T00:00:00Z",
                    "2026-05-17T00:00:00Z",
                ),
            )
    assert "RELAY-STATE-003" in str(exc_info.value), exc_info.value


# ---------------------------------------------------------------------------
# Valid (scope_kind, state) pairs MUST be accepted on UPDATE after the
# initial-state row is created with epoch=0.
# ---------------------------------------------------------------------------

VALID_TRANSITIONS = [
    ("run", "pending", "captured"),
    ("run", "pending", "result_written"),
    ("replay_case", "proposed", "fixtures_ready"),
    ("replay_case", "proposed", "analyzed"),
    ("gate_round", "open", "draft_received"),
    ("gate_round", "open", "decision_written"),
    ("evidence_bundle", "building", "signed"),
    ("evidence_bundle", "building", "published"),
    ("eval_run", "pending", "running"),
    ("eval_run", "pending", "scored"),
    ("release", "open", "gated"),
    ("release", "open", "released"),
]


@pytest.mark.plumbing
@pytest.mark.parametrize(
    ("scope_kind", "initial_state", "target_state"),
    VALID_TRANSITIONS,
)
@pytest.mark.asyncio
async def test_update_accepts_valid_kind_state_combination(
    tmp_path: Path,
    scope_kind: str,
    initial_state: str,
    target_state: str,
) -> None:
    """A legal transition does NOT trip the per-kind state trigger."""
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    scope_id = "22222222-2222-2222-2222-222222222222"
    project_id = "00000000-0000-0000-0000-000000000000"
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute(
            "INSERT INTO scope_state ("
            "scope_kind, scope_id, project_id, state, epoch, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            (
                scope_kind,
                scope_id,
                project_id,
                initial_state,
                "2026-05-17T00:00:00Z",
                "2026-05-17T00:00:00Z",
            ),
        )
        await conn.execute(
            "UPDATE scope_state SET state = ?, epoch = epoch + 1, "
            "updated_at = ? WHERE scope_kind = ? AND scope_id = ?",
            (
                target_state,
                "2026-05-17T00:00:01Z",
                scope_kind,
                scope_id,
            ),
        )
        await conn.commit()
        async with conn.execute(
            "SELECT state FROM scope_state "
            "WHERE scope_kind = ? AND scope_id = ?",
            (scope_kind, scope_id),
        ) as cur:
            row = await cur.fetchone()
    assert row is not None
    assert row[0] == target_state


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_update_rejects_invalid_target_state(tmp_path: Path) -> None:
    """An UPDATE that lands on a state outside the per-kind set MUST
    raise; this guards against engine bugs mutating to a value the
    state machine doesn't define.
    """
    db_path = tmp_path / "sidecar.db"
    await _bootstrap(db_path)
    scope_id = "33333333-3333-3333-3333-333333333333"
    project_id = "00000000-0000-0000-0000-000000000000"
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute(
            "INSERT INTO scope_state ("
            "scope_kind, scope_id, project_id, state, epoch, "
            "created_at, updated_at) "
            "VALUES ('run', ?, ?, 'pending', 0, ?, ?)",
            (
                scope_id,
                project_id,
                "2026-05-17T00:00:00Z",
                "2026-05-17T00:00:00Z",
            ),
        )
        with pytest.raises(aiosqlite.IntegrityError) as exc_info:
            await conn.execute(
                "UPDATE scope_state SET state = 'signed', "
                "epoch = epoch + 1, updated_at = ? "
                "WHERE scope_kind = 'run' AND scope_id = ?",
                ("2026-05-17T00:00:01Z", scope_id),
            )
    assert "RELAY-STATE-003" in str(exc_info.value), exc_info.value
