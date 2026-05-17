"""VAL-W2-059: Exhaustive state-transition table coverage test.

A parameterized pytest test enumerates every (state, event, target_state)
row in packages/schemas/raw/state-transition-table.yaml for the four
scope kinds. For each row:
  (a) seed a scope_state row at ``state``,
  (b) call compare_and_set_state with expected_from=state, event=event,
      and a cassette-backed happy-path actor,
  (c) assert post-call state equals target_state AND one event_log row
      was written.

Test additionally asserts the IN-MEMORY TRANSITION_TABLE count equals
the YAML-declared count: drift between YAML and code triggers failure.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    TRANSITION_TABLE,
    ActorRef,
    compare_and_set_state,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_YAML_PATH = (
    _REPO_ROOT / "packages" / "schemas" / "raw" / "state-transition-table.yaml"
)


def _ts() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _load_yaml_transitions() -> list[dict]:
    """Return a flat list of (scope_kind, from, event, to, actor) tuples."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    rows: list[dict] = []
    for scope_kind, body in data["scope_kinds"].items():
        for t in body["transitions"]:
            rows.append(
                {
                    "scope_kind": scope_kind,
                    "from": t["from"],
                    "event": t["event"],
                    "to": t["to"],
                    "actor": t["actor"],
                }
            )
    return rows


_YAML_TRANSITIONS = _load_yaml_transitions()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
def test_transition_count_matches_yaml() -> None:
    """In-memory TRANSITION_TABLE row count == YAML row count."""
    assert TRANSITION_TABLE.transition_count == len(_YAML_TRANSITIONS), (
        TRANSITION_TABLE.transition_count,
        len(_YAML_TRANSITIONS),
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
def test_every_yaml_transition_is_in_table() -> None:
    """Every YAML row resolves through TransitionTable.lookup."""
    misses: list[dict] = []
    for row in _YAML_TRANSITIONS:
        t = TRANSITION_TABLE.lookup(row["scope_kind"], row["from"], row["event"])
        if t is None or t.to_state != row["to"]:
            misses.append(row)
    assert not misses, misses


def _seed_scope_at_state(
    db_path: Path, scope_kind: str, scope_id: str, state: str, project_id: str
) -> None:
    """Insert a scope_state row directly at the given state (test setup).

    The sidecar's spec W initial-state policy trigger (migration 0016) rejects
    epoch=0 inserts whose state is not the transition-table origin state for
    the scope_kind. To simulate "the scope is mid-flight already at <state>",
    seed with epoch=1 unless <state> is the canonical origin state for the
    scope_kind. epoch is the optimistic-concurrency aggregate version per
    spec C.4 lines 3679-3722; epoch>=1 means at least one transition has
    occurred and the row is no longer an "initial" row from the trigger's
    point of view.
    """
    import sqlite3 as _sqlite3

    _origin_state: dict[str, str] = {
        "run": "pending",
        "replay_case": "proposed",
        "gate_round": "open",
        "evidence_bundle": "building",
        "eval_run": "pending",
        "release": "open",
    }
    seed_epoch = 0 if state == _origin_state.get(scope_kind) else 1
    now = _ts()
    conn = _sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO scope_state "
            "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scope_kind, scope_id, project_id, state, seed_epoch, now, now),
        )
        conn.commit()
    finally:
        conn.close()


def _seed_actor_and_manifest(
    db_path: Path, *, identity_hash: str, commit_hash: str
) -> None:
    """Seed actors + manifest_versions rows so the three-anchor handoff
    guard (VAL-V2M03-024..030) can validate against a real registry.

    Used by `test_every_yaml_transition_executes` for the
    gate_round.open -> draft.submitted row whose guard is
    `three_anchor_handoff_valid` (spec C.5).
    """
    import sqlite3 as _sqlite3

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    conn = _sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors "
            "(identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, NULL)",
            (identity_hash, "worker", now),
        )
        conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, NULL, 86400)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                commit_hash,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-059")
@pytest.mark.parametrize(
    "transition",
    _YAML_TRANSITIONS,
    ids=lambda t: f"{t['scope_kind']}.{t['from']}->{t['event']}->{t['to']}",
)
@pytest.mark.asyncio
async def test_every_yaml_transition_executes(tmp_path, transition) -> None:
    """Every YAML transition successfully advances state when seeded."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope_at_state(
            tmp_path / "sidecar.db",
            transition["scope_kind"],
            scope_id,
            transition["from"],
            project_id,
        )
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        # The gate_round.open -> draft.submitted transition is guarded by
        # three_anchor_handoff_valid (spec C.5); seed the actor + manifest
        # rows so the guard validates against a real registry. The handoff
        # validator uses the writer connection but only SELECTs, so the
        # registry rows must be committed before compare_and_set_state is
        # invoked.
        if (
            transition["scope_kind"] == "gate_round"
            and transition["event"] == "draft.submitted"
        ):
            _seed_actor_and_manifest(
                tmp_path / "sidecar.db",
                identity_hash=identity_hash,
                commit_hash=commit_hash,
            )
            handoff_payload: dict = {
                "actor_identity_hash": identity_hash,
                "manifest_commit_hash": commit_hash,
            }
        else:
            handoff_payload = {}
        actor = ActorRef(
            kind=transition["actor"],
            identity_hash=identity_hash,
        )
        result = await compare_and_set_state(
            database=db,
            scope_kind=transition["scope_kind"],
            scope_id=scope_id,
            expected_from=transition["from"],
            event=transition["event"],
            actor=actor,
            payload=handoff_payload,
            project_id=project_id,
            manifest_commit_hash=commit_hash if handoff_payload else None,
        )
        assert result.ok is True, (transition, result)
        assert result.new_state == transition["to"], (transition, result.new_state)

        # Exactly one state_transition event_log row for this scope.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, (transition, row)
    finally:
        await db.close()
