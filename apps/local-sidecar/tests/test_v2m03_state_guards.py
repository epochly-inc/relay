"""VAL-V2M03-024..035: per-transition guards + three-anchor enforcement.

Tests the w3-state-guards sub-feature (operation
``relay-v0.2-oss-completeness``, milestone M03-W3, spec sections C.3-C.5,
lines 3623-3760). Twelve assertions:

  VAL-V2M03-024: state-transition-table.yaml carries explicit `guards`
                 field per row.
  VAL-V2M03-025: state engine evaluates ALL guards before applying
                 transition.
  VAL-V2M03-026: ingest.run_received requires valid Idempotency-Key AND
                 valid manifest_commit_hash guards.
  VAL-V2M03-027: validation.complete requires all required contracts
                 evaluated.
  VAL-V2M03-028: gate.all_decided requires all bound gates to have
                 non-remediate decisions.
  VAL-V2M03-029: evidence.signed requires manifest digest valid AND key
                 not revoked.
  VAL-V2M03-030: compare_and_set_state internally invokes the three-
                 anchor handoff for handoff events.
  VAL-V2M03-031: new callers cannot bypass three-anchor enforcement.
  VAL-V2M03-032: state engine emits state.invalid_transition event on
                 unknown transitions.
  VAL-V2M03-033: state engine rejects actor not in allowed_actor_kinds.
  VAL-V2M03-034: state engine uses serializable isolation for
                 compare_and_set_state.
  VAL-V2M03-035: state engine is idempotent on (scope, expected_from,
                 event) retries.

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    ACTOR_NOT_ALLOWED,
    GUARD_FAILED,
    HANDOFF_INVALID,
    INVALID_TRANSITION,
    INVALID_TRANSITION_EVENT_TYPE,
    TRANSITION_TABLE,
    ActorRef,
    Transition,
    TransitionTable,
    compare_and_set_state,
    init_scope,
    register_guard,
    registered_guard_names,
)
from relay_sidecar.state_engine.transitions import ScopeKindSpec

_REPO_ROOT = Path(__file__).resolve().parents[3]
_YAML_PATH = (
    _REPO_ROOT / "packages" / "schemas" / "raw" / "state-transition-table.yaml"
)


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


# -- VAL-V2M03-024 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-024")
def test_yaml_every_row_has_non_empty_guards_drawn_from_registry() -> None:
    """Every YAML transition row has a non-empty `guards` list drawn
    from the canonical registered guard registry."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    assert data["schema"] == "relay.state_transition_table.v1"
    registered = set(registered_guard_names())
    offenders: list[str] = []
    for scope_kind, body in data["scope_kinds"].items():
        for t in body["transitions"]:
            row_id = f"{scope_kind}.{t['from']}->{t['event']}->{t['to']}"
            guards = t.get("guards", [])
            if not isinstance(guards, list) or len(guards) == 0:
                offenders.append(f"{row_id}: missing or empty guards list")
                continue
            for g in guards:
                if g not in registered:
                    offenders.append(
                        f"{row_id}: guard {g!r} not in registry"
                    )
    assert not offenders, offenders


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-024")
def test_in_memory_transition_table_carries_guard_names_per_row() -> None:
    """TRANSITION_TABLE rows expose `guard_names` matching the YAML."""
    data = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8"))
    for scope_kind, body in data["scope_kinds"].items():
        for t in body["transitions"]:
            yaml_guards = tuple(t["guards"])
            tr = TRANSITION_TABLE.lookup(scope_kind, t["from"], t["event"])
            assert tr is not None, (scope_kind, t)
            assert tr.guard_names == yaml_guards, (scope_kind, t, tr.guard_names)


# -- VAL-V2M03-025 -----------------------------------------------------------


def _build_table_with_guards(guards_for_first: tuple[str, ...]) -> TransitionTable:
    """Construct a custom TransitionTable that adds extra guards to the
    `run.pending -> run.captured` transition."""
    spec = ScopeKindSpec(
        scope_kind="run",
        initial_state="pending",
        terminal_states=frozenset({"terminal"}),
        transitions=(
            Transition(
                scope_kind="run",
                from_state="pending",
                event="ingest.run_received",
                to_state="captured",
                allowed_actor_kinds=("sdk",),
                event_log_type="run.captured",
                guard_names=guards_for_first,
            ),
        ),
    )
    return TransitionTable({"run": spec})


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-025")
@pytest.mark.asyncio
async def test_engine_invokes_all_guards_and_short_circuits_on_failure(tmp_path) -> None:
    """A transition with three guards (one False, two True) invokes all
    three; result is GUARD_FAILED; no state mutation occurs."""
    counts: dict[str, int] = {"g1": 0, "g2": 0, "g3": 0}

    async def _g1(conn, scope_kind, scope_id, payload, mch):
        counts["g1"] += 1
        return True, {}

    async def _g2(conn, scope_kind, scope_id, payload, mch):
        counts["g2"] += 1
        return True, {}

    async def _g3(conn, scope_kind, scope_id, payload, mch):
        counts["g3"] += 1
        return False, {"reason": "stub failure"}

    register_guard("v2m03_test_g1", _g1, override=True)
    register_guard("v2m03_test_g2", _g2, override=True)
    register_guard("v2m03_test_g3", _g3, override=True)

    table = _build_table_with_guards(
        ("v2m03_test_g1", "v2m03_test_g2", "v2m03_test_g3")
    )

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
            table=table,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
            table=table,
        )
        assert result.ok is False, result
        assert result.reason == GUARD_FAILED
        assert result.extras.get("failed_guard") == "v2m03_test_g3"
        # All three guards invoked once (left-to-right; short-circuit happens
        # AFTER the failing guard, so g1/g2/g3 each count = 1).
        assert counts == {"g1": 1, "g2": 1, "g3": 1}, counts

        # scope_state epoch unchanged.
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT state, epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        assert row[0] == "pending"
        assert int(row[1]) == 0, row

        # No state_transition event_log row emitted on guard failure.
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            count_row = await cur.fetchone()
        assert count_row is not None and int(count_row[0]) == 0, count_row
    finally:
        await db.close()


# -- VAL-V2M03-026 -----------------------------------------------------------


def _seed_actor_and_manifest(
    db_path: Path,
    *,
    identity_hash: str,
    commit_hash: str,
    actor_kind: str = "sdk",
    revoked: bool = False,
    project_id: str | None = None,
) -> str:
    """Seed an actor + manifest row; returns the manifest's project_id.

    Per VAL-V3M3-001, the manifest registry is now scoped by
    ``(project_id, commit_hash)``. Callers that want the seeded manifest
    to validate for a specific scope must pass ``project_id=<scope's
    project_id>``. When ``project_id`` is None a fresh uuid is generated;
    this is fine for negative-path tests (cross-project mismatch) but
    happy-path tests must thread the scope's project_id.
    """
    effective_project_id = project_id or str(uuid.uuid4())
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "INSERT INTO actors (identity_hash, kind, registered_at, revoked_at) "
            "VALUES (?, ?, ?, ?)",
            (identity_hash, actor_kind, now, now if revoked else None),
        )
        conn.execute(
            "INSERT INTO manifest_versions "
            "(manifest_version_id, manifest_id, project_id, commit_hash, "
            " effective_at, effective_until, grace_window_seconds) "
            "VALUES (?, ?, ?, ?, ?, NULL, 86400)",
            (
                str(uuid.uuid4()),
                str(uuid.uuid4()),
                effective_project_id,
                commit_hash,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return effective_project_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-026")
@pytest.mark.asyncio
async def test_ingest_run_received_guards_explicit_invalid_key(tmp_path) -> None:
    """idempotency_key_invalid=True in payload -> GUARD_FAILED on
    valid_idempotency_key."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            payload={"idempotency_key_invalid": True},
            project_id=project_id,
        )
        assert result.ok is False
        assert result.reason == GUARD_FAILED
        assert result.extras.get("failed_guard") == "valid_idempotency_key"
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-026")
@pytest.mark.asyncio
async def test_ingest_run_received_guards_manifest_not_registered(tmp_path) -> None:
    """manifest_commit_hash supplied AND registry has rows AND hash missing
    -> GUARD_FAILED on valid_manifest_commit_hash."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        # Seed a DIFFERENT manifest so the registry is non-empty; this
        # forces the lenient bootstrap branch to NOT apply.
        _seed_actor_and_manifest(
            tmp_path / "sidecar.db",
            identity_hash="sha256-" + "z" * 64,
            commit_hash="sha256-" + "d" * 64,
        )
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
            manifest_commit_hash="sha256-" + "e" * 64,  # not registered
        )
        assert result.ok is False
        assert result.reason == GUARD_FAILED
        assert result.extras.get("failed_guard") == "valid_manifest_commit_hash"
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-026")
@pytest.mark.asyncio
async def test_ingest_run_received_guards_all_satisfied(tmp_path) -> None:
    """All guards satisfied -> ok=True; state transitions to captured."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        identity_hash = "sha256-" + "a" * 64
        commit_hash = "sha256-" + "b" * 64
        project_id = str(uuid.uuid4())
        # Per VAL-V3M3-001 the manifest registry is project-scoped; seed
        # the manifest_versions row under the same project_id as the
        # scope so the per-project guard succeeds.
        _seed_actor_and_manifest(
            tmp_path / "sidecar.db",
            identity_hash=identity_hash,
            commit_hash=commit_hash,
            project_id=project_id,
        )
        scope_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash=identity_hash)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
            manifest_commit_hash=commit_hash,
        )
        assert result.ok is True, result
        assert result.new_state == "captured"
    finally:
        await db.close()


# -- VAL-V2M03-027 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-027")
@pytest.mark.asyncio
async def test_validation_complete_requires_all_required_contracts_evaluated(
    tmp_path,
) -> None:
    """payload.required_contract_ids = [c1, c2] but contract_results is
    empty -> GUARD_FAILED. After inserting rows, retry succeeds."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        # Seed scope_state already at 'validating'.
        _seed_scope_at(db_path, "run", scope_id, "validating", project_id)
        actor = ActorRef(
            kind="validation_worker", identity_hash="sha256-" + "a" * 64
        )
        # Attempt without contract_results rows -> GUARD_FAILED.
        # Create the table to ensure non-lenient mode.
        _create_min_contract_results_table(db_path)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="validating",
            event="validation.complete",
            actor=actor,
            payload={"required_contract_ids": ["c1", "c2"]},
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == GUARD_FAILED
        assert result.extras.get("failed_guard") in {
            "all_required_contracts_evaluated",
            "contract_results_written",
        }

        # Insert contract_results rows (full schema per migration 0012).
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            for cid in ("c1", "c2"):
                conn.execute(
                    "INSERT INTO contract_results ("
                    "  contract_result_id, run_id, contract_id, contract_version,"
                    "  outcome, evaluation_engine_version, evaluated_at, metadata"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        scope_id,
                        cid,
                        "1",
                        "pass",
                        "test-engine/0",
                        _now_z(),
                        "{}",
                    ),
                )
            conn.commit()
        finally:
            conn.close()

        # Retry succeeds.
        result2 = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="validating",
            event="validation.complete",
            actor=actor,
            payload={"required_contract_ids": ["c1", "c2"]},
            project_id=project_id,
        )
        assert result2.ok is True, result2
        assert result2.new_state == "gated"
    finally:
        await db.close()


# -- VAL-V2M03-028 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-028")
@pytest.mark.asyncio
async def test_gate_all_decided_requires_all_bound_gates_non_remediate(
    tmp_path,
) -> None:
    """One gate accept + one gate remediate -> GUARD_FAILED.
    Then change remediate -> block -> ok=True."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        # gate_decisions rows are append-only (migration 0009 trigger
        # ``gate_decisions_no_update``); use TWO independent scopes for the
        # negative-then-positive contrast required by VAL-V2M03-028.
        bundle_id = _seed_min_evidence_bundle(db_path)

        # --- Scope A: one accept + one remediate -> GUARD_FAILED ---------
        _seed_scope_at(db_path, "run", scope_id, "gated", project_id)
        _insert_gate_decision_as_engine(
            db_path, bundle_id=bundle_id, scope_id=scope_id,
            gate_id="g1", action="accept",
        )
        _insert_gate_decision_as_engine(
            db_path, bundle_id=bundle_id, scope_id=scope_id,
            gate_id="g2", action="remediate",
        )
        actor = ActorRef(
            kind="result_writer", identity_hash="sha256-" + "a" * 64
        )
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="gated",
            event="gate.all_decided",
            actor=actor,
            payload={"bound_gate_ids": ["g1", "g2"]},
            project_id=project_id,
        )
        assert result.ok is False
        assert result.reason == GUARD_FAILED
        assert result.extras.get("failed_guard") == "all_bound_gates_decided"

        # --- Scope B: one accept + one block -> ok=True ------------------
        scope_id_b = str(uuid.uuid4())
        _seed_scope_at(db_path, "run", scope_id_b, "gated", project_id)
        _insert_gate_decision_as_engine(
            db_path, bundle_id=bundle_id, scope_id=scope_id_b,
            gate_id="g1", action="accept",
        )
        _insert_gate_decision_as_engine(
            db_path, bundle_id=bundle_id, scope_id=scope_id_b,
            gate_id="g2", action="block",
        )
        result2 = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id_b,
            expected_from="gated",
            event="gate.all_decided",
            actor=actor,
            payload={"bound_gate_ids": ["g1", "g2"]},
            project_id=project_id,
        )
        assert result2.ok is True, result2
        assert result2.new_state == "result_written"
    finally:
        await db.close()


# -- VAL-V2M03-029 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-029")
@pytest.mark.asyncio
async def test_evidence_signed_requires_manifest_and_key_not_revoked(
    tmp_path,
) -> None:
    """Revoked key -> GUARD_FAILED. Invalid digest -> GUARD_FAILED.
    Both valid -> ok=True."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        commit_hash = "sha256-" + "b" * 64
        _seed_actor_and_manifest(
            db_path,
            identity_hash="sha256-" + "a" * 64,
            commit_hash=commit_hash,
        )
        _create_min_key_lifecycle_table(db_path)

        # (a) Revoked key -> fail.
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA busy_timeout = 5000")
            conn.execute(
                "INSERT INTO key_lifecycle (key_id, event_type, event_at) "
                "VALUES (?, ?, ?)",
                ("k_revoked", "revoke", _now_z()),
            )
            conn.commit()
        finally:
            conn.close()

        scope_id_a = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope_at(db_path, "evidence_bundle", scope_id_a, "building", project_id)
        actor = ActorRef(
            kind="evidence_signer", identity_hash="sha256-" + "a" * 64
        )
        result_a = await compare_and_set_state(
            database=db,
            scope_kind="evidence_bundle",
            scope_id=scope_id_a,
            expected_from="building",
            event="bundle.signed",
            actor=actor,
            payload={
                "manifest_digest": commit_hash,
                "signing_key_id": "k_revoked",
            },
            project_id=project_id,
        )
        assert result_a.ok is False, result_a
        assert result_a.reason == GUARD_FAILED
        assert result_a.extras.get("failed_guard") == "signing_key_not_revoked"

        # (b) Invalid manifest_digest (not in registry; registry non-empty).
        scope_id_b = str(uuid.uuid4())
        _seed_scope_at(db_path, "evidence_bundle", scope_id_b, "building", project_id)
        result_b = await compare_and_set_state(
            database=db,
            scope_kind="evidence_bundle",
            scope_id=scope_id_b,
            expected_from="building",
            event="bundle.signed",
            actor=actor,
            payload={
                "manifest_digest": "sha256-" + "f" * 64,
                "signing_key_id": "k_active",
            },
            project_id=project_id,
        )
        assert result_b.ok is False
        assert result_b.reason == GUARD_FAILED
        assert result_b.extras.get("failed_guard") == "manifest_digest_valid"

        # (c) Both valid -> ok=True.
        scope_id_c = str(uuid.uuid4())
        _seed_scope_at(db_path, "evidence_bundle", scope_id_c, "building", project_id)
        result_c = await compare_and_set_state(
            database=db,
            scope_kind="evidence_bundle",
            scope_id=scope_id_c,
            expected_from="building",
            event="bundle.signed",
            actor=actor,
            payload={
                "manifest_digest": commit_hash,
                "signing_key_id": "k_active",
            },
            project_id=project_id,
        )
        assert result_c.ok is True, result_c
        assert result_c.new_state == "signed"
    finally:
        await db.close()


# -- VAL-V2M03-030 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-030")
@pytest.mark.asyncio
async def test_cas_invokes_three_anchor_handoff_internally(tmp_path) -> None:
    """compare_and_set_state for gate.open -> gate.draft_received invokes
    the three-anchor handoff guard internally; ACTOR_NOT_REGISTERED handoff
    rejection surfaces as HANDOFF_INVALID."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope_at(db_path, "gate_round", scope_id, "open", project_id)
        actor = ActorRef(kind="worker", identity_hash="sha256-" + "a" * 64)
        # NO actor seeded -> handoff guard fails with ACTOR_NOT_REGISTERED.
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            payload={
                "actor_identity_hash": "sha256-" + "a" * 64,
                "manifest_commit_hash": "sha256-" + "b" * 64,
            },
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == HANDOFF_INVALID, result
        assert result.extras.get("failed_guard") == "three_anchor_handoff_valid"
        assert (
            result.extras.get("guard_diagnostics", {}).get("handoff_reason")
            in {"ACTOR_NOT_REGISTERED", "MANIFEST_NOT_ACTIVE"}
        )
    finally:
        await db.close()


# -- VAL-V2M03-031 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-031")
@pytest.mark.asyncio
async def test_new_caller_cannot_bypass_three_anchor_enforcement(tmp_path) -> None:
    """A 'naive new caller' that omits actor_identity_hash from the
    payload MUST be rejected by the engine WITHOUT the caller explicitly
    invoking validate_three_anchor_handoff."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope_at(db_path, "gate_round", scope_id, "open", project_id)
        actor = ActorRef(kind="worker", identity_hash="sha256-" + "a" * 64)
        # Naive caller: payload is EMPTY (no anchors). The engine
        # internally evaluates three_anchor_handoff_valid guard and
        # rejects without the caller doing anything extra.
        result = await compare_and_set_state(
            database=db,
            scope_kind="gate_round",
            scope_id=scope_id,
            expected_from="open",
            event="draft.submitted",
            actor=actor,
            payload={},  # NO anchors at all
            project_id=project_id,
        )
        assert result.ok is False, result
        assert result.reason == HANDOFF_INVALID
        # No state_transition log emitted (rejection occurred BEFORE CAS).
        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_kind = 'state_transition'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0
        # scope_state.epoch unchanged from the seeded value.
        # _seed_scope_at seeds epoch=0 for the canonical initial state
        # (gate_round.open is the initial state) so the assertion is
        # epoch == 0 after the rejected handoff.
        async with reader.execute(
            "SELECT epoch FROM scope_state WHERE scope_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 0, row
    finally:
        await db.close()


# -- VAL-V2M03-032 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-032")
@pytest.mark.asyncio
async def test_engine_emits_state_invalid_transition_on_unknown_event(
    tmp_path,
) -> None:
    """Unknown event 'definitely.not.a.real.event' on run.pending ->
    INVALID_TRANSITION + one state.invalid_transition event_log row with
    payload containing the offending event and from-state."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="definitely.not.a.real.event",
            actor=actor,
            project_id=project_id,
        )
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT payload FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = ?",
            (scope_id, INVALID_TRANSITION_EVENT_TYPE),
        ) as cur:
            rows = await cur.fetchall()
        assert len(rows) == 1, rows
        import json as _json

        payload_recorded = _json.loads(rows[0][0])
        assert payload_recorded.get("event") == "definitely.not.a.real.event"
        assert payload_recorded.get("expected_from") == "pending"
    finally:
        await db.close()


# -- VAL-V2M03-033 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-033")
@pytest.mark.asyncio
async def test_engine_rejects_actor_not_in_allowed_kinds(tmp_path) -> None:
    """run.gated -> run.result_written with actor.kind='sdk' (only
    result_writer is allowed) -> ACTOR_NOT_ALLOWED. Repeat with
    result_writer (and bound_gate_ids empty) -> ok=True."""
    db_path = tmp_path / "sidecar.db"
    db = SidecarDatabase(db_path=db_path, reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        _seed_scope_at(db_path, "run", scope_id, "gated", project_id)
        sdk_actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        bad = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="gated",
            event="gate.all_decided",
            actor=sdk_actor,
            project_id=project_id,
        )
        assert bad.ok is False
        assert bad.reason == ACTOR_NOT_ALLOWED

        good_actor = ActorRef(
            kind="result_writer", identity_hash="sha256-" + "a" * 64
        )
        good = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="gated",
            event="gate.all_decided",
            actor=good_actor,
            project_id=project_id,
        )
        assert good.ok is True
        assert good.new_state == "result_written"
    finally:
        await db.close()


# -- VAL-V2M03-034 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-034")
@pytest.mark.asyncio
async def test_concurrent_compare_and_set_optimistic_concurrency(tmp_path) -> None:
    """Two concurrent attempts to advance the same scope: exactly one ok
    (non-idempotent) wins; the loser observes EXPECTED_FROM_MISMATCH OR an
    idempotent replay (because the second call sees the new state and
    treats it as a retry of the same event)."""
    import asyncio

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)

        async def one() -> Any:
            return await compare_and_set_state(
                database=db,
                scope_kind="run",
                scope_id=scope_id,
                expected_from="pending",
                event="ingest.run_received",
                actor=actor,
                project_id=project_id,
            )

        results = await asyncio.gather(one(), one())
        winners = [r for r in results if r.ok and not r.idempotent]
        # Exactly one non-idempotent winner; loser is either idempotent
        # (same event applied) or rejected with EXPECTED_FROM_MISMATCH.
        assert len(winners) == 1, results
    finally:
        await db.close()


# -- VAL-V2M03-035 -----------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M03-035")
@pytest.mark.asyncio
async def test_engine_idempotent_on_retried_event(tmp_path) -> None:
    """Replaying the same (scope, expected_from, event) -> idempotent
    success without epoch bump or duplicate event_log row."""
    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id = str(uuid.uuid4())
        project_id = str(uuid.uuid4())
        await init_scope(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            project_id=project_id,
        )
        actor = ActorRef(kind="sdk", identity_hash="sha256-" + "a" * 64)
        first = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert first.ok is True and first.idempotent is False, first

        second = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="ingest.run_received",
            actor=actor,
            project_id=project_id,
        )
        assert second.ok is True
        assert second.idempotent is True, second
        assert second.new_state == "captured"

        reader = db.acquire_reader()
        async with reader.execute(
            "SELECT COUNT(*) FROM event_log_entries "
            "WHERE scope_id = ? AND event_type = 'run.captured'",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
        assert row is not None and int(row[0]) == 1, row
    finally:
        await db.close()


# -- helpers -----------------------------------------------------------------


def _seed_scope_at(
    db_path: Path, scope_kind: str, scope_id: str, state: str, project_id: str
) -> None:
    """Insert scope_state row directly at given state (epoch=1 unless
    initial). Matches test_state_transition_coverage helper."""
    _origin: dict[str, str] = {
        "run": "pending",
        "replay_case": "proposed",
        "gate_round": "open",
        "evidence_bundle": "building",
    }
    seed_epoch = 0 if state == _origin.get(scope_kind) else 1
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
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


def _create_min_contract_results_table(db_path: Path) -> None:
    """Create a minimal contract_results table for the guard's SELECT to
    target. The OSS schema may have a richer DDL; this is a test fixture
    that provides the columns the guard inspects."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS contract_results ("
            "  run_id TEXT NOT NULL,"
            "  contract_id TEXT NOT NULL"
            ")"
        )
        conn.commit()
    finally:
        conn.close()


def _create_min_gate_decisions_table(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS gate_decisions ("
            "  run_id TEXT NOT NULL,"
            "  gate_id TEXT NOT NULL,"
            "  action TEXT NOT NULL"
            ")"
        )
        conn.commit()
    finally:
        conn.close()


def _create_min_key_lifecycle_table(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS key_lifecycle ("
            "  key_id TEXT NOT NULL,"
            "  event_type TEXT NOT NULL,"
            "  event_at TEXT NOT NULL"
            ")"
        )
        conn.commit()
    finally:
        conn.close()


def _insert_gate_decision_as_engine(
    db_path: Path,
    *,
    bundle_id: str,
    scope_id: str,
    gate_id: str,
    action: str,
    scope_type: str = "run",
    round_: int = 1,
) -> None:
    """Insert one gate_decisions row while transiently adopting the
    ``relay_gate_engine`` role (required by migration 0009 trigger).

    The role is restored to ``relay_state_engine`` afterwards so concurrent
    state-engine writes (in the same test) are unaffected.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            "UPDATE _sidecar_role SET role = ? WHERE id = 0",
            ("relay_gate_engine",),
        )
        try:
            conn.execute(
                "INSERT INTO gate_decisions ("
                "  gate_decision_id, gate_id, scope_type, scope_id, round,"
                "  action, evidence_bundle_id, decided_at, manifest_commit_hash,"
                "  actor_identity_hash, signature, signature_key_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    gate_id,
                    scope_type,
                    scope_id,
                    round_,
                    action,
                    bundle_id,
                    _now_z(),
                    "sha256-" + "0" * 64,
                    "sha256-" + "0" * 64,
                    "stub-sig",
                    "stub-key",
                ),
            )
        finally:
            conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                ("relay_state_engine",),
            )
        conn.commit()
    finally:
        conn.close()


def _seed_min_evidence_bundle(db_path: Path) -> str:
    """Insert one placeholder evidence_bundles row that satisfies all
    NOT NULL columns + CHECK constraints declared in migration 0009.

    Spec W (deferred trigger): an evidence_bundles row REQUIRES a paired
    scope_state row with (scope_kind='evidence_bundle', scope_id=bundle_id)
    inserted in the same transaction. We satisfy that by inserting both
    rows inside one BEGIN..COMMIT block.

    Returns the bundle_id (UUID string) to be referenced by FK columns.
    """
    bundle_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    now = _now_z()
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO scope_state "
            "(scope_kind, scope_id, project_id, state, epoch, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 0, ?, ?)",
            ("evidence_bundle", bundle_id, project_id, "building", now, now),
        )
        conn.execute(
            "INSERT INTO evidence_bundles ("
            "  bundle_id, artifact_digest, command, exit_code, span_ids,"
            "  contract_assertion_ids, agent_worker_id, manifest_commit_hash,"
            "  timestamp, environment, redaction_policy_version, bundle_digest"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                bundle_id,
                "sha256-" + "0" * 64,
                "stub-command",
                0,
                "[]",
                "[]",
                "stub-worker",
                "sha256-" + "0" * 64,
                now,
                "test",
                "v0",
                "sha256-" + "0" * 64,
            ),
        )
        conn.execute("COMMIT")
    finally:
        conn.close()
    return bundle_id
