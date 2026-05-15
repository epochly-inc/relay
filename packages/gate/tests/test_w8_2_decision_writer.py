"""W8.2 plumbing tests for the gate_decisions writer.

Covers VAL-W8-010..019, VAL-W8-040, VAL-W8-042..044 as a single
integration-style test surface against the real W8.2 SQLite migration
(apps/local-sidecar/migrations/0009_gate_decision_writer.sql). Each
test seeds the actors + manifest_versions handoff anchors, then drives
the GateDecisionWriter directly.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import aiosqlite
import pytest
from _w8_2_helpers import (
    fetch_count,
    fetch_one,
    make_bundle_inputs,
    make_decision_inputs,
    make_ephemeral_signing_key,
    seed_draft,
    setup_writer_fixture,
)
from relay_gate_engine import (
    CANONICAL_ANCHOR_ORDER,
    EVENT_DECISION_WRITTEN,
    RELAY_GATE_021,
    DecisionWriteResult,
    HandoffPayload,
    canonical_decision_payload,
    canonical_json_bytes,
    recompute_bundle_digest,
    sign_payload,
    verify_payload,
)
from relay_gate_engine.db_grants import (
    NON_ENGINE_ROLES,
    ROLE_GATE_ENGINE,
)

# ---------------------------------------------------------------------------
# VAL-W8-010: gate_decisions writes route through compare_and_set_state.
# ---------------------------------------------------------------------------
#
# The W8.2 writer is the SINGLE production-code path that issues INSERT
# INTO gate_decisions. The W5.5 verify-self ``control-plane-write-only``
# check enforces grep-level absence outside the allowlisted gate-engine
# tree; the assertion below confirms the writer-as-canonical-entry-point
# is wired and round-trips one INSERT through the borrow lock.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-010")
@pytest.mark.asyncio
async def test_writes_route_through_writer(tmp_path) -> None:
    """Happy-path write produces one gate_decisions + one evidence_bundles row."""
    f = await setup_writer_fixture(tmp_path)
    try:
        inputs = make_decision_inputs(
            gate_id=f.gate_id,
            scope_type="run",
            scope_id=f.scope_id,
            round_=f.round_,
            actor_identity_hash=f.actor_hash,
            manifest_commit_hash=f.manifest_hash,
        )
        result: DecisionWriteResult = await f.writer.write(
            draft_id=f.draft_id,
            inputs=inputs,
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert result.ok, result
        assert result.gate_decision_id is not None
        assert result.evidence_bundle_id is not None

        # One gate_decisions row exists and is bound to one evidence_bundle.
        assert await fetch_count(f.database, "gate_decisions") == 1
        assert await fetch_count(f.database, "evidence_bundles") == 1
        # decided_by is pinned to 'gate_engine' (VAL-W8-012 happy side).
        row = await fetch_one(
            f.database,
            "SELECT decided_by FROM gate_decisions WHERE gate_decision_id = ?",
            (result.gate_decision_id,),
        )
        assert row is not None and row[0] == "gate_engine"
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-011: DB role grants prevent non-engine writes.
# ---------------------------------------------------------------------------
#
# The OSS local profile emulates the Postgres role grants via the
# _sidecar_role single-row table. A direct INSERT issued under any
# non-engine role token MUST be rejected by the gate_decisions_role_check
# trigger.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-011")
@pytest.mark.asyncio
@pytest.mark.parametrize("role", list(NON_ENGINE_ROLES))
async def test_non_engine_role_blocks_insert(tmp_path, role: str) -> None:
    """Each non-engine role token rejects INSERT INTO gate_decisions."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # First write a valid decision so the bundle FK can resolve in the
        # second (illegal) attempt below.
        inputs = make_decision_inputs(
            gate_id=f.gate_id,
            scope_type="run",
            scope_id=f.scope_id,
            round_=f.round_,
            actor_identity_hash=f.actor_hash,
            manifest_commit_hash=f.manifest_hash,
        )
        valid = await f.writer.write(
            draft_id=f.draft_id,
            inputs=inputs,
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert valid.ok
        bundle_id = valid.evidence_bundle_id
        assert bundle_id is not None

        # Drop role to the test value and attempt a direct INSERT.
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            # NOTE: simulate the role by inserting the test role token.
            # The CHECK on _sidecar_role would normally pin id=0; we
            # UPDATE the existing single row.
            await conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                (role,),
            )
            await conn.commit()
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, schema_version, gate_id, scope_type, "
                    "  scope_id, round, action, evidence_bundle_id, "
                    "  decided_by, decided_at, manifest_commit_hash, "
                    "  actor_identity_hash, signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        "relay.gate_decision.v1",
                        f.gate_id,
                        "run",
                        f.scope_id,
                        2,
                        "accept",
                        bundle_id,
                        "gate_engine",
                        "2026-05-14T12:00:00Z",
                        f.manifest_hash,
                        f.actor_hash,
                        "fake-sig",
                        "fake-kid",
                    ),
                )
                await conn.commit()
            assert "gate_decisions_role_check" in str(exc_info.value)
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-012: decided_by CHECK constraint blocks non-engine attribution.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-012")
@pytest.mark.asyncio
async def test_decided_by_check_blocks_non_engine_attribution(tmp_path) -> None:
    """A direct INSERT with decided_by != 'gate_engine' violates CHECK."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # Seed a bundle so the FK doesn't fire before the CHECK.
        inputs = make_decision_inputs(
            gate_id=f.gate_id,
            scope_type="run",
            scope_id=f.scope_id,
            round_=f.round_,
            actor_identity_hash=f.actor_hash,
            manifest_commit_hash=f.manifest_hash,
        )
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=inputs,
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok and ok.evidence_bundle_id is not None
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            await conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                (ROLE_GATE_ENGINE,),
            )
            await conn.commit()
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, schema_version, gate_id, scope_type, "
                    "  scope_id, round, action, evidence_bundle_id, "
                    "  decided_by, decided_at, manifest_commit_hash, "
                    "  actor_identity_hash, signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        "relay.gate_decision.v1",
                        f.gate_id,
                        "run",
                        f.scope_id,
                        2,
                        "accept",
                        ok.evidence_bundle_id,
                        "worker",  # WRONG
                        "2026-05-14T12:00:00Z",
                        f.manifest_hash,
                        f.actor_hash,
                        "fake-sig",
                        "fake-kid",
                    ),
                )
                await conn.commit()
            assert (
                "decided_by_gate_engine" in str(exc_info.value)
                or "CHECK" in str(exc_info.value).upper()
            )
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-013: Three-anchor handoff validated before any write.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-013")
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "anchor_to_break",
    ["scope", "actor", "manifest"],
)
async def test_handoff_anchor_mismatch_rejects_without_write(
    tmp_path, anchor_to_break: str,
) -> None:
    """Each single-anchor mismatch yields RELAY-GATE-021 + zero rows."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # Build a handoff payload that breaks exactly one anchor.
        payload_kwargs: dict[str, Any] = {
            "actor_identity_hash": f.actor_hash,
            "manifest_commit_hash": f.manifest_hash,
            "run_id": f.scope_id,
        }
        if anchor_to_break == "scope":
            payload_kwargs["run_id"] = str(uuid.uuid4())  # mismatched
        elif anchor_to_break == "actor":
            payload_kwargs["actor_identity_hash"] = "sha256-" + "z" * 64
        elif anchor_to_break == "manifest":
            payload_kwargs["manifest_commit_hash"] = "sha256-" + "z" * 64

        inputs = make_decision_inputs(
            gate_id=f.gate_id,
            scope_type="run",
            scope_id=f.scope_id,
            round_=f.round_,
            actor_identity_hash=f.actor_hash,
            manifest_commit_hash=f.manifest_hash,
        )
        result = await f.writer.write(
            draft_id=f.draft_id,
            inputs=inputs,
            handoff_payload=HandoffPayload(**payload_kwargs),
        )
        assert not result.ok
        assert result.error_envelope is not None
        assert result.error_envelope["code"] == RELAY_GATE_021
        assert result.mismatched_anchor == anchor_to_break

        # Zero gate_decisions rows persisted.
        assert await fetch_count(f.database, "gate_decisions") == 0
        # Zero evidence_bundles persisted (writer should never even
        # touch the bundle table on rejected_handoff).
        assert await fetch_count(f.database, "evidence_bundles") == 0
        # The draft is marked rejected_handoff.
        row = await fetch_one(
            f.database,
            "SELECT resolution_state FROM gate_decision_drafts WHERE draft_id = ?",
            (f.draft_id,),
        )
        assert row is not None and row[0] == "rejected_handoff"
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-014: Rejected-handoff drafts do NOT consume a remediation round.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-014")
@pytest.mark.asyncio
async def test_rejected_handoff_does_not_consume_round_budget(tmp_path) -> None:
    """7 rejected handoffs leave round budget intact; 8th valid accepts."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # No gate_rounds rows yet.
        assert await fetch_count(f.database, "gate_rounds") == 0

        # Submit 7 rejected drafts (each with a unique draft_id so the
        # gate_decision_drafts UNIQUE constraint does not collide).
        bad_manifest = "sha256-" + "z" * 64
        for _i in range(7):
            bad_draft_id = str(uuid.uuid4())
            await seed_draft(
                f.database,
                draft_id=bad_draft_id,
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                worker_id=str(uuid.uuid4()),
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=bad_manifest,
            )
            res = await f.writer.write(
                draft_id=bad_draft_id,
                inputs=make_decision_inputs(
                    gate_id=f.gate_id,
                    scope_type="run",
                    scope_id=f.scope_id,
                    round_=f.round_,
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=f.manifest_hash,
                ),
                handoff_payload=HandoffPayload(
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=bad_manifest,
                    run_id=f.scope_id,
                ),
            )
            assert not res.ok and res.mismatched_anchor == "manifest"

        # No gate_rounds rows consumed.
        assert await fetch_count(f.database, "gate_rounds") == 0

        # 8th draft (the original valid draft) is accepted.
        res = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert res.ok
        # One gate_rounds row now exists for round=1.
        assert await fetch_count(f.database, "gate_rounds") == 1
        row = await fetch_one(
            f.database,
            "SELECT round FROM gate_rounds WHERE scope_id = ?",
            (f.scope_id,),
        )
        assert row is not None and int(row[0]) == 1
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-015: gate_decisions rows are immutable after insert.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-015")
@pytest.mark.asyncio
async def test_gate_decisions_rows_are_immutable(tmp_path) -> None:
    """UPDATE on a written gate_decisions row raises by trigger."""
    f = await setup_writer_fixture(tmp_path)
    try:
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "UPDATE gate_decisions SET action = ? WHERE gate_decision_id = ?",
                    ("block", ok.gate_decision_id),
                )
                await conn.commit()
            assert "gate_decisions_no_update" in str(exc_info.value)
            # DELETE is also blocked.
            with pytest.raises(aiosqlite.IntegrityError) as exc2:
                await conn.execute(
                    "DELETE FROM gate_decisions WHERE gate_decision_id = ?",
                    (ok.gate_decision_id,),
                )
                await conn.commit()
            assert "gate_decisions_no_delete" in str(exc2.value)
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-016: Every gate_decisions row binds a non-null evidence_bundle_id.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-016")
@pytest.mark.asyncio
async def test_missing_bundle_fk_blocks_insert(tmp_path) -> None:
    """An INSERT referencing a non-existent bundle id raises by FK trigger."""
    f = await setup_writer_fixture(tmp_path)
    try:
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            await conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                (ROLE_GATE_ENGINE,),
            )
            await conn.commit()
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, schema_version, gate_id, scope_type, "
                    "  scope_id, round, action, evidence_bundle_id, "
                    "  decided_by, decided_at, manifest_commit_hash, "
                    "  actor_identity_hash, signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        "relay.gate_decision.v1",
                        f.gate_id,
                        "run",
                        f.scope_id,
                        1,
                        "accept",
                        "missing-bundle-id",
                        "gate_engine",
                        "2026-05-14T12:00:00Z",
                        f.manifest_hash,
                        f.actor_hash,
                        "x",
                        "k",
                    ),
                )
                await conn.commit()
            assert "gate_decisions_evidence_fk" in str(exc_info.value)
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-017: Evidence bundle binds the ten required fields.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-017")
@pytest.mark.asyncio
async def test_evidence_bundle_binds_ten_required_fields(tmp_path) -> None:
    """The bundle bound to the decision carries all ten required fields."""
    f = await setup_writer_fixture(tmp_path)
    try:
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            async with conn.execute(
                "SELECT bundle_id, schema_version, artifact_digest, command, "
                "       exit_code, span_ids, contract_assertion_ids, "
                "       agent_worker_id, manifest_commit_hash, timestamp, "
                "       environment, redaction_policy_version, bundle_digest "
                "FROM evidence_bundles WHERE bundle_id = ?",
                (ok.evidence_bundle_id,),
            ) as cur:
                row = await cur.fetchone()
            assert row is not None
            cols = [
                "bundle_id", "schema_version", "artifact_digest", "command",
                "exit_code", "span_ids", "contract_assertion_ids",
                "agent_worker_id", "manifest_commit_hash", "timestamp",
                "environment", "redaction_policy_version", "bundle_digest",
            ]
            bundle = dict(zip(cols, row, strict=True))
            for k in cols:
                assert bundle[k] is not None and bundle[k] != "", (k, bundle[k])
            # Recompute the bundle_digest and assert equality with stored.
            recomputed = recompute_bundle_digest(bundle)
            assert recomputed == bundle["bundle_digest"], (recomputed, bundle["bundle_digest"])
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-018: gate_decisions write is atomic with gate_rounds and
#             event_log_entries (single transaction).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-018")
@pytest.mark.asyncio
async def test_decision_write_is_atomic(tmp_path) -> None:
    """One write produces (1, 1, 1, 1) rows for the 4 canonical tables."""
    f = await setup_writer_fixture(tmp_path)
    try:
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok
        # All four canonical tables now hold one row.
        gd = await fetch_count(f.database, "gate_decisions")
        eb = await fetch_count(f.database, "evidence_bundles")
        gr = await fetch_count(f.database, "gate_rounds")
        ele = await fetch_count(
            f.database,
            "event_log_entries",
            where="event_type = ?",
            params=(EVENT_DECISION_WRITTEN,),
        )
        assert (gd, eb, gr, ele) == (1, 1, 1, 1), (gd, eb, gr, ele)

        # gate_rounds.gate_decision_id binds to the new decision.
        row = await fetch_one(
            f.database,
            "SELECT gate_decision_id FROM gate_rounds WHERE scope_id = ?",
            (f.scope_id,),
        )
        assert row is not None and row[0] == ok.gate_decision_id
    finally:
        await f.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-018")
@pytest.mark.asyncio
async def test_decision_write_rolls_back_on_failure(tmp_path) -> None:
    """A trigger-induced failure rolls the entire transaction back."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # Build inputs whose evidence_bundle.manifest_commit_hash differs
        # from the decision's manifest_commit_hash so the
        # gate_decisions_bundle_manifest_match trigger fires INSIDE the
        # transaction (after the bundle INSERT but before COMMIT).
        bad_bundle = make_bundle_inputs(
            manifest_commit_hash="sha256-" + "c" * 64,  # different
        )
        from relay_gate_engine import GateDecisionInputs

        inputs = GateDecisionInputs(
            gate_id=f.gate_id,
            scope_type="run",
            scope_id=f.scope_id,
            round_=f.round_,
            action="accept",
            strict_pass=True,
            failed_assertion_ids=(),
            unmet_conditions=(),
            cascade_on_block=True,
            manifest_commit_hash=f.manifest_hash,  # mismatched vs bundle
            actor_identity_hash=f.actor_hash,
            evidence_bundle=bad_bundle,
        )
        with pytest.raises(aiosqlite.IntegrityError) as exc_info:
            await f.writer.write(
                draft_id=f.draft_id,
                inputs=inputs,
                handoff_payload=HandoffPayload(
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=f.manifest_hash,
                    run_id=f.scope_id,
                ),
            )
        assert "gate_decisions_bundle_manifest_match" in str(exc_info.value)

        # Atomicity: zero rows in either canonical table.
        assert await fetch_count(f.database, "gate_decisions") == 0
        assert await fetch_count(f.database, "evidence_bundles") == 0
        assert await fetch_count(f.database, "gate_rounds") == 0
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-019: gate_decisions are signed before the transaction commits.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-019")
@pytest.mark.asyncio
async def test_signature_required_before_commit(tmp_path) -> None:
    """An INSERT with empty signature is blocked by the trigger."""
    f = await setup_writer_fixture(tmp_path)
    try:
        # First write a valid bundle for FK satisfaction.
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok and ok.evidence_bundle_id is not None
        async with aiosqlite.connect(str(f.database.db_path)) as conn:
            await conn.execute(
                "UPDATE _sidecar_role SET role = ? WHERE id = 0",
                (ROLE_GATE_ENGINE,),
            )
            await conn.commit()
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, schema_version, gate_id, scope_type, "
                    "  scope_id, round, action, evidence_bundle_id, "
                    "  decided_by, decided_at, manifest_commit_hash, "
                    "  actor_identity_hash, signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        "relay.gate_decision.v1",
                        f.gate_id,
                        "run",
                        f.scope_id,
                        99,
                        "accept",
                        ok.evidence_bundle_id,
                        "gate_engine",
                        "2026-05-14T12:00:00Z",
                        f.manifest_hash,
                        f.actor_hash,
                        "",  # empty signature
                        "kid",
                    ),
                )
                await conn.commit()
            assert "gate_decisions_signature_required" in str(exc_info.value)

        # Sanity: the written row's signature can be verified against the
        # canonical payload + signer's public key. We have to reach into
        # the writer for the key.
        row = await fetch_one(
            f.database,
            "SELECT signature, signature_key_id, gate_id, scope_type, "
            "       scope_id, round, action, strict_pass, "
            "       failed_assertion_ids, unmet_conditions, "
            "       evidence_bundle_id, cascade_on_block, decided_by, "
            "       decided_at, manifest_commit_hash, actor_identity_hash "
            "FROM gate_decisions WHERE gate_decision_id = ?",
            (ok.gate_decision_id,),
        )
        assert row is not None
        signature_b64u = str(row[0])
        # Reconstruct the canonical payload that was signed.
        payload = canonical_decision_payload(
            gate_decision_id=ok.gate_decision_id,
            schema_version="relay.gate_decision.v1",
            gate_id=str(row[2]),
            scope_type=str(row[3]),
            scope_id=str(row[4]),
            round_=int(row[5]),
            action=str(row[6]),
            strict_pass=bool(row[7]),
            failed_assertion_ids=json.loads(row[8]),
            unmet_conditions=json.loads(row[9]),
            evidence_bundle_id=str(row[10]),
            cascade_on_block=bool(row[11]),
            decided_by=str(row[12]),
            decided_at=str(row[13]),
            manifest_commit_hash=str(row[14]),
            actor_identity_hash=str(row[15]),
        )
        public_key = f.writer._signing_key.private_key.public_key()
        assert verify_payload(
            payload=payload,
            signature_b64u=signature_b64u,
            public_key=public_key,
        )
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-042: gate_rounds.round bookkeeping invariant under
#             rejected_handoff resolutions (SQL snapshot).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-042")
@pytest.mark.asyncio
async def test_gate_rounds_count_invariant_under_rejected_handoff(
    tmp_path,
) -> None:
    """count(gate_rounds) is unchanged across N=10 rejected drafts."""
    f = await setup_writer_fixture(tmp_path)
    try:
        before_count = await fetch_count(f.database, "gate_rounds")
        before_max_row = await fetch_one(
            f.database,
            "SELECT COALESCE(MAX(round), 0) FROM gate_rounds WHERE scope_id = ?",
            (f.scope_id,),
        )
        before_max = int(before_max_row[0]) if before_max_row is not None else 0

        bad_manifest = "sha256-" + "z" * 64
        for _ in range(10):
            bad_draft_id = str(uuid.uuid4())
            await seed_draft(
                f.database,
                draft_id=bad_draft_id,
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                worker_id=str(uuid.uuid4()),
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=bad_manifest,
            )
            res = await f.writer.write(
                draft_id=bad_draft_id,
                inputs=make_decision_inputs(
                    gate_id=f.gate_id,
                    scope_type="run",
                    scope_id=f.scope_id,
                    round_=f.round_,
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=f.manifest_hash,
                ),
                handoff_payload=HandoffPayload(
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=bad_manifest,
                    run_id=f.scope_id,
                ),
            )
            assert not res.ok and res.error_envelope is not None
            assert res.error_envelope["code"] == RELAY_GATE_021

        after_count = await fetch_count(f.database, "gate_rounds")
        after_max_row = await fetch_one(
            f.database,
            "SELECT COALESCE(MAX(round), 0) FROM gate_rounds WHERE scope_id = ?",
            (f.scope_id,),
        )
        after_max = int(after_max_row[0]) if after_max_row is not None else 0
        assert before_count == after_count == 0, (before_count, after_count)
        assert before_max == after_max == 0, (before_max, after_max)

        # 10 rejected_handoff drafts persisted.
        rejected = await fetch_count(
            f.database,
            "gate_decision_drafts",
            where="resolution_state = ?",
            params=("rejected_handoff",),
        )
        assert rejected == 10

        # Subsequent valid draft accepted into round R0+1=1.
        res_ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert res_ok.ok
        new_max_row = await fetch_one(
            f.database,
            "SELECT MAX(round) FROM gate_rounds WHERE scope_id = ?",
            (f.scope_id,),
        )
        assert new_max_row is not None and int(new_max_row[0]) == before_max + 1
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-043: evidence_bundles.manifest_commit_hash binds to draft's anchor.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-043")
@pytest.mark.asyncio
async def test_bundle_manifest_binds_to_draft_anchor(tmp_path) -> None:
    """SQL JOIN guard: count of mismatched (decision, bundle, draft) trio = 0."""
    f = await setup_writer_fixture(tmp_path)
    try:
        ok = await f.writer.write(
            draft_id=f.draft_id,
            inputs=make_decision_inputs(
                gate_id=f.gate_id,
                scope_type="run",
                scope_id=f.scope_id,
                round_=f.round_,
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
            ),
            handoff_payload=HandoffPayload(
                actor_identity_hash=f.actor_hash,
                manifest_commit_hash=f.manifest_hash,
                run_id=f.scope_id,
            ),
        )
        assert ok.ok
        # JOIN guard query: every accepted decision binds a bundle whose
        # manifest_commit_hash matches the draft's manifest_commit_hash.
        row = await fetch_one(
            f.database,
            "SELECT count(*) FROM gate_decisions gd "
            "JOIN gate_decision_drafts gdd "
            "  ON gdd.resolved_gate_decision_id = gd.gate_decision_id "
            "JOIN evidence_bundles eb "
            "  ON eb.bundle_id = gd.evidence_bundle_id "
            "WHERE eb.manifest_commit_hash <> gdd.manifest_commit_hash",
        )
        assert row is not None and int(row[0]) == 0

        # Negative branch: a mismatched bundle would be blocked by the
        # trigger (already exercised in test_decision_write_rolls_back_on_failure).
    finally:
        await f.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-044: RELAY-GATE-021 envelope carries mismatched_anchor attribution.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-044")
@pytest.mark.asyncio
async def test_relay_gate_021_envelope_carries_mismatched_anchor(
    tmp_path,
) -> None:
    """Each anchor-mismatch case carries the expected attribution token."""
    cases: dict[str, str] = {
        "scope": "scope",
        "actor": "actor",
        "manifest": "manifest",
    }
    seen: set[str] = set()
    for break_anchor in cases:
        f = await setup_writer_fixture(tmp_path / f"db-{break_anchor}")
        try:
            payload_kwargs: dict[str, Any] = {
                "actor_identity_hash": f.actor_hash,
                "manifest_commit_hash": f.manifest_hash,
                "run_id": f.scope_id,
            }
            if break_anchor == "scope":
                payload_kwargs["run_id"] = str(uuid.uuid4())
            elif break_anchor == "actor":
                payload_kwargs["actor_identity_hash"] = "sha256-" + "z" * 64
            elif break_anchor == "manifest":
                payload_kwargs["manifest_commit_hash"] = "sha256-" + "z" * 64
            res = await f.writer.write(
                draft_id=f.draft_id,
                inputs=make_decision_inputs(
                    gate_id=f.gate_id,
                    scope_type="run",
                    scope_id=f.scope_id,
                    round_=f.round_,
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=f.manifest_hash,
                ),
                handoff_payload=HandoffPayload(**payload_kwargs),
            )
            assert not res.ok
            assert res.error_envelope is not None
            assert res.error_envelope["code"] == RELAY_GATE_021
            assert res.error_envelope["mismatched_anchor"] == cases[break_anchor]
            seen.add(res.error_envelope["mismatched_anchor"])
        finally:
            await f.database.close()

    assert seen == {"scope", "actor", "manifest"}, seen


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-044")
@pytest.mark.asyncio
async def test_canonical_anchor_order_is_deterministic(tmp_path) -> None:
    """All-anchors-mismatch returns canonical first anchor; N=10 repeats agree."""
    # The W2 validator checks scope -> actor -> manifest in that order and
    # short-circuits on the first failure; so an all-anchors-mismatch case
    # returns 'scope' (since scope is checked first and fails).
    assert CANONICAL_ANCHOR_ORDER == ("scope", "actor", "manifest")

    observed: list[str] = []
    for i in range(10):
        f = await setup_writer_fixture(tmp_path / f"db-all-{i}")
        try:
            res = await f.writer.write(
                draft_id=f.draft_id,
                inputs=make_decision_inputs(
                    gate_id=f.gate_id,
                    scope_type="run",
                    scope_id=f.scope_id,
                    round_=f.round_,
                    actor_identity_hash=f.actor_hash,
                    manifest_commit_hash=f.manifest_hash,
                ),
                handoff_payload=HandoffPayload(
                    actor_identity_hash="sha256-" + "z" * 64,  # break actor
                    manifest_commit_hash="sha256-" + "z" * 64,  # break manifest
                    run_id=str(uuid.uuid4()),  # break scope
                ),
            )
            assert not res.ok and res.mismatched_anchor is not None
            observed.append(res.mismatched_anchor)
        finally:
            await f.database.close()

    # Deterministic across N=10 repeats: 'scope' (first in canonical order).
    assert observed == ["scope"] * 10, observed


# ---------------------------------------------------------------------------
# Additional canonical-JSON byte-determinism test (W8.2 helper invariant).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-010")
def test_canonical_json_bytes_is_stable() -> None:
    """canonical_json_bytes produces byte-identical output across runs."""
    payload = canonical_decision_payload(
        gate_decision_id="dec-1",
        schema_version="relay.gate_decision.v1",
        gate_id="g-1",
        scope_type="run",
        scope_id="s-1",
        round_=1,
        action="accept",
        strict_pass=True,
        failed_assertion_ids=[],
        unmet_conditions=[],
        evidence_bundle_id="b-1",
        cascade_on_block=True,
        decided_by="gate_engine",
        decided_at="2026-05-14T12:00:00Z",
        manifest_commit_hash="sha256-deadbeef",
        actor_identity_hash="sha256-feedface",
    )
    a = canonical_json_bytes(payload)
    b = canonical_json_bytes(payload)
    assert a == b
    # Round-trip through JSON parser must yield the same dict.
    assert json.loads(a.decode("utf-8")) == payload


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-019")
def test_signing_round_trip_with_ephemeral_key() -> None:
    """An ephemeral key signs + verifies the canonical payload."""
    key = make_ephemeral_signing_key()
    payload = {"a": 1, "b": "two", "c": [1, 2, 3]}
    sig_b64u, kid = sign_payload(payload, key)
    assert sig_b64u and kid == "test-w8-2-kid"
    assert verify_payload(
        payload=payload,
        signature_b64u=sig_b64u,
        public_key=key.private_key.public_key(),
    )
    # A tampered payload fails verification.
    assert not verify_payload(
        payload={"a": 1, "b": "two", "c": [1, 2, 4]},
        signature_b64u=sig_b64u,
        public_key=key.private_key.public_key(),
    )


# ---------------------------------------------------------------------------
# VAL-W8-040: rly verify-self covers gate engine invariants.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-040")
def test_verify_self_includes_gate_engine_invariants_check() -> None:
    """The verify-self runner includes the gate-engine-invariants check."""
    from pathlib import Path as _P

    from relay_cli.invariants.runner import CHECK_ORDER, run_all_checks

    assert "gate-engine-invariants" in CHECK_ORDER, CHECK_ORDER
    repo_root = _P(__file__).resolve().parents[3]
    result = run_all_checks(repo_root)
    by_name = {c.name: c for c in result.checks}
    assert "gate-engine-invariants" in by_name
    # On a healthy tree, the migration is present and every required
    # trigger is declared -> the check passes with zero findings.
    gate_check = by_name["gate-engine-invariants"]
    assert gate_check.status == "pass", gate_check
    assert gate_check.findings == ()
