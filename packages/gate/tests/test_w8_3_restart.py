"""W8.3 plumbing tests for gate restart on failure.

Covers VAL-W8-020..027 against the real migration 0010 schema
(``gate_round_inputs``) plus the W8.2 / W2 migrations the restart
coordinator depends on. Each test drives the RestartCoordinator
directly through the SidecarDatabase writer borrow lock and asserts
the canonical row-level evidence required by the contract.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import aiosqlite
import pytest
from _w8_2_helpers import (
    fetch_count,
    fetch_one,
    seed_draft,
)
from _w8_3_helpers import (
    fetch_all,
    fetch_event_log_payload,
    seed_extra_draft,
    seed_gate_round,
    setup_restart_fixture,
)
from relay_gate_engine import (
    CANCELLATION_REASON_SUPERSEDED,
    EVENT_GATE_RESTARTED,
    INITIATED_BY_REMEDIATION,
    RestartCoordinator,
    UnchangedResubmissionError,
    compute_inputs_digest,
    validate_remediation_directive,
)
from relay_schemas.error_codes import RelayErrorCode

# ---------------------------------------------------------------------------
# VAL-W8-020: Late-gate failure creates a NEW gate_rounds entry, not a retry.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-020")
@pytest.mark.asyncio
async def test_restart_creates_new_gate_rounds_row(tmp_path: Path) -> None:
    """Restart inserts round N+1 with restart_predecessor and initiated_by='remediation'."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        result = await f.coordinator.restart(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            prior_gate_round_id=f.prior_gate_round_id,
            failing_gate_id="gate-testing-uuid",
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result.new_round == f.prior_round + 1

        # Two gate_rounds rows exist: round N (seeded) and round N+1 (new).
        rows = await fetch_all(
            wf.database,
            "SELECT round, initiated_by, restart_predecessor "
            "FROM gate_rounds WHERE scope_type = ? AND scope_id = ? "
            "ORDER BY round ASC",
            ("run", wf.scope_id),
        )
        assert len(rows) == 2
        assert rows[0] == (f.prior_round, "submission", None)
        # The new row has the canonical fields.
        new_round_row, new_initiated, new_predecessor = rows[1]
        assert new_round_row == f.prior_round + 1
        assert new_initiated == INITIATED_BY_REMEDIATION
        assert new_predecessor == f.prior_gate_round_id
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-021: Restart re-injects ALL THREE gates, not only the failing one.
# ---------------------------------------------------------------------------
#
# The plumbing-level assertion: a restart does NOT carry forward any prior-
# round gate_decisions. The new round starts empty; the caller writes three
# fresh gate_decisions (one per gate) in round N+1 via the W8.2 writer.
# We assert: after restart, there is ONE gate_rounds row at round N+1 with
# gate_decision_id IS NULL (no decisions copied), and the unique constraint
# on gate_decisions (gate_id, scope_type, scope_id, round) admits three new
# distinct gate_id values at round N+1 (the three gates) without collision.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-021")
@pytest.mark.asyncio
async def test_restart_does_not_carry_forward_decisions(tmp_path: Path) -> None:
    """Restart leaves round N+1's gate_decision_id NULL; three new gates can write."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        result = await f.coordinator.restart(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            prior_gate_round_id=f.prior_gate_round_id,
            failing_gate_id="gate-testing-uuid",
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )
        new_round = result.new_round

        # The new gate_rounds row carries no gate_decision_id (decisions
        # are written fresh by the W8.2 writer in the new round).
        row = await fetch_one(
            wf.database,
            "SELECT gate_decision_id FROM gate_rounds "
            "WHERE gate_round_id = ?",
            (result.new_gate_round_id,),
        )
        assert row is not None
        assert row[0] is None

        # The unique constraint UNIQUE(gate_id, scope_type, scope_id, round)
        # admits three distinct gate_id values at the new round.
        # We insert three fake gate_decisions rows directly to confirm.
        async with aiosqlite.connect(str(wf.database.db_path)) as conn:
            # First, the writer needs a valid evidence_bundle. Insert one
            # directly (we are inspecting schema constraints, not exercising
            # the writer).
            bundle_id = str(uuid.uuid4())
            await conn.execute(
                "UPDATE _sidecar_role SET role = 'relay_gate_engine' WHERE id = 0",
            )
            await conn.execute(
                "INSERT INTO evidence_bundles ("
                "  bundle_id, artifact_digest, command, exit_code, "
                "  span_ids, contract_assertion_ids, agent_worker_id, "
                "  manifest_commit_hash, timestamp, environment, "
                "  redaction_policy_version, bundle_digest"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    bundle_id,
                    "sha256-" + "f" * 64,
                    "uv run pytest",
                    0,
                    "[]",
                    "[]",
                    "worker-test",
                    wf.manifest_hash,
                    "2026-05-15T12:00:00Z",
                    "local",
                    "v1",
                    "sha256-" + "c" * 64,
                ),
            )
            for gate_name in ("gate-scrutiny", "gate-structural", "gate-testing"):
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, gate_id, scope_type, scope_id, "
                    "  round, action, evidence_bundle_id, decided_by, "
                    "  decided_at, manifest_commit_hash, actor_identity_hash, "
                    "  signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        gate_name,
                        "run",
                        wf.scope_id,
                        new_round,
                        "accept",
                        bundle_id,
                        "gate_engine",
                        "2026-05-15T12:00:00Z",
                        wf.manifest_hash,
                        wf.actor_hash,
                        "sig",
                        "kid",
                    ),
                )
            await conn.commit()

        # Three rows at round N+1 with three distinct gate_id values.
        count = await fetch_count(
            wf.database,
            "gate_decisions",
            "scope_type = ? AND scope_id = ? AND round = ?",
            ("run", wf.scope_id, new_round),
        )
        assert count == 3
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-022: Retry-only-failed-gate is impossible by construction.
# ---------------------------------------------------------------------------
#
# A grep against the gate package source for banned function name patterns
# returns zero hits. The only function that transitions to a new round is
# RestartCoordinator.restart, which always re-injects three gates.


_BANNED_RETRY_NAMES = (
    "retry_gate",
    "re_evaluate_gate_only",
    "retry_single_gate",
    "rerun_failed_gate_only",
    "retry_only_failed_gate",
)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-022")
def test_no_retry_only_failed_gate_function_exists() -> None:
    """Grep guard: zero hits for retry-only-failed-gate names in gate sources."""
    import relay_gate_engine

    pkg_root = Path(relay_gate_engine.__file__).resolve().parent
    hits: list[tuple[str, str]] = []
    for py_file in pkg_root.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for banned in _BANNED_RETRY_NAMES:
            # Match only function definitions or callables, not comments
            # documenting the ban. The patterns we look for are
            # ``def <banned>(`` or ``<banned>(`` at a call site, but we
            # accept the names appearing inside a tuple literal that is
            # itself the guard list. Suppress hits that occur on a line
            # containing the constant tuple name.
            for line_no, line in enumerate(text.splitlines(), start=1):
                # Skip lines that document the guard or list banned names.
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if stripped.startswith('"') or stripped.startswith("'"):
                    continue
                if f"def {banned}(" in line or f"async def {banned}(" in line:
                    hits.append((str(py_file.relative_to(pkg_root)), f"L{line_no}: {line.strip()}"))
    assert hits == [], (
        f"Banned retry-only-failed-gate function names found: {hits}"
    )

    # And the public re-exports of relay_gate_engine MUST NOT contain any
    # of the banned names.
    public = set(relay_gate_engine.__all__)
    for banned in _BANNED_RETRY_NAMES:
        assert banned not in public, f"banned name {banned!r} is publicly exported"


# ---------------------------------------------------------------------------
# VAL-W8-023: Prior round's pending drafts are canceled on restart.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-023")
@pytest.mark.asyncio
async def test_restart_cancels_pending_drafts(tmp_path: Path) -> None:
    """Pending drafts for the prior round move to 'cancelled' with the
    canonical cancellation_reason and never produce a gate_decisions row.
    """
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        # Seed two extra pending drafts in the prior round (the W8.2 fixture
        # already seeded one).
        extra_draft_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        for did in extra_draft_ids:
            await seed_extra_draft(
                wf.database,
                draft_id=did,
                gate_id=wf.gate_id,
                scope_type="run",
                scope_id=wf.scope_id,
                round_=f.prior_round,
                worker_id=str(uuid.uuid4()),
                actor_identity_hash=wf.actor_hash,
                manifest_commit_hash=wf.manifest_hash,
                resolution_state="pending",
            )

        # Also seed one already-resolved draft; the restart MUST NOT touch it.
        already_resolved_id = str(uuid.uuid4())
        await seed_extra_draft(
            wf.database,
            draft_id=already_resolved_id,
            gate_id=wf.gate_id,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=f.prior_round,
            worker_id=str(uuid.uuid4()),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
            resolution_state="resolved",
        )

        result = await f.coordinator.restart(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            prior_gate_round_id=f.prior_gate_round_id,
            failing_gate_id="gate-testing-uuid",
            failing_assertion_ids=("VAL-W8-027b",),
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )

        # The pending drafts (W8.2 fixture seed + two extras) are now cancelled.
        all_drafts = await fetch_all(
            wf.database,
            "SELECT draft_id, resolution_state, cancellation_reason "
            "FROM gate_decision_drafts "
            "WHERE scope_type = ? AND scope_id = ? AND round = ?",
            ("run", wf.scope_id, f.prior_round),
        )
        by_id = {r[0]: (r[1], r[2]) for r in all_drafts}

        # The W8.2 fixture's draft + the two extras are cancelled with the
        # canonical reason.
        for did in [wf.draft_id, *extra_draft_ids]:
            state, reason = by_id[did]
            assert state == "cancelled", f"draft {did} state={state}"
            assert reason == CANCELLATION_REASON_SUPERSEDED, (
                f"draft {did} reason={reason}"
            )
        # The already-resolved draft is NOT touched.
        state, reason = by_id[already_resolved_id]
        assert state == "resolved"
        assert reason is None

        # No gate_decisions row exists for any cancelled draft (the W8.2
        # writer was never invoked for them).
        for did in [wf.draft_id, *extra_draft_ids]:
            count = await fetch_count(
                wf.database,
                "gate_decisions",
                "evidence_bundle_id IN ("
                "  SELECT bundle_id FROM evidence_bundles "
                "  WHERE agent_worker_id = ?"
                ")",
                (did,),
            )
            assert count == 0
        # And the coordinator's return value lists the three cancelled drafts.
        assert set(result.cancelled_draft_ids) == {wf.draft_id, *extra_draft_ids}
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-024: validationRound is monotonically increasing per scope.
# ---------------------------------------------------------------------------
#
# The gate_decisions UNIQUE(gate_id, scope_type, scope_id, round) constraint
# rejects a duplicate-round insert. We confirm directly against the schema.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-024")
@pytest.mark.asyncio
async def test_duplicate_round_rejected_by_unique_constraint(tmp_path: Path) -> None:
    """Two gate_decisions rows with the same (gate_id, scope, round) violate UNIQUE."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        async with aiosqlite.connect(str(wf.database.db_path)) as conn:
            await conn.execute(
                "UPDATE _sidecar_role SET role = 'relay_gate_engine' WHERE id = 0",
            )
            bundle_id = str(uuid.uuid4())
            await conn.execute(
                "INSERT INTO evidence_bundles ("
                "  bundle_id, artifact_digest, command, exit_code, "
                "  span_ids, contract_assertion_ids, agent_worker_id, "
                "  manifest_commit_hash, timestamp, environment, "
                "  redaction_policy_version, bundle_digest"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    bundle_id,
                    "sha256-" + "e" * 64,
                    "uv run pytest",
                    0,
                    "[]",
                    "[]",
                    "worker-test",
                    wf.manifest_hash,
                    "2026-05-15T12:00:00Z",
                    "local",
                    "v1",
                    "sha256-" + "d" * 64,
                ),
            )
            await conn.execute(
                "INSERT INTO gate_decisions ("
                "  gate_decision_id, gate_id, scope_type, scope_id, "
                "  round, action, evidence_bundle_id, decided_by, "
                "  decided_at, manifest_commit_hash, actor_identity_hash, "
                "  signature, signature_key_id"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    wf.gate_id,
                    "run",
                    wf.scope_id,
                    2,
                    "accept",
                    bundle_id,
                    "gate_engine",
                    "2026-05-15T12:00:00Z",
                    wf.manifest_hash,
                    wf.actor_hash,
                    "sig1",
                    "kid",
                ),
            )
            with pytest.raises(aiosqlite.IntegrityError) as exc_info:
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, gate_id, scope_type, scope_id, "
                    "  round, action, evidence_bundle_id, decided_by, "
                    "  decided_at, manifest_commit_hash, actor_identity_hash, "
                    "  signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        wf.gate_id,
                        "run",
                        wf.scope_id,
                        2,  # duplicate round
                        "accept",
                        bundle_id,
                        "gate_engine",
                        "2026-05-15T12:00:00Z",
                        wf.manifest_hash,
                        wf.actor_hash,
                        "sig2",
                        "kid",
                    ),
                )
            err = str(exc_info.value).lower()
            assert "unique" in err

            # Max round for the scope is monotonically the highest insert.
            await conn.commit()
        rows = await fetch_all(
            wf.database,
            "SELECT MAX(round) FROM gate_decisions "
            "WHERE gate_id = ? AND scope_type = ? AND scope_id = ?",
            (wf.gate_id, "run", wf.scope_id),
        )
        assert rows[0][0] == 2
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-025: Restart emits the gate.restarted event with required payload.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-025")
@pytest.mark.asyncio
async def test_restart_emits_gate_restarted_event(tmp_path: Path) -> None:
    """Payload contains failing_gate_id + failing_assertion_ids + predecessor_round_id."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        failing_gate = "gate-testing-uuid-w8-025"
        failing_assertions = ("VAL-W8-A", "VAL-W8-B")
        result = await f.coordinator.restart(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            prior_gate_round_id=f.prior_gate_round_id,
            failing_gate_id=failing_gate,
            failing_assertion_ids=failing_assertions,
            actor_identity_hash=wf.actor_hash,
            manifest_commit_hash=wf.manifest_hash,
        )

        # Look up the event row.
        row = await fetch_one(
            wf.database,
            "SELECT event_type, payload, event_kind FROM event_log_entries "
            "WHERE event_id = ?",
            (result.event_id,),
        )
        assert row is not None
        event_type, payload_json, event_kind = row
        assert event_type == EVENT_GATE_RESTARTED
        assert event_kind == "gate_restarted"

        payload = json.loads(payload_json)
        # The three documented payload keys are present.
        assert payload["failing_gate_id"] == failing_gate
        assert payload["failing_assertion_ids"] == list(failing_assertions)
        assert payload["predecessor_round_id"] == f.prior_gate_round_id
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-026: Restart respects remediation directive from prior round.
# ---------------------------------------------------------------------------
#
# When a prior remediate decision named required_evidence in unmet_conditions,
# a new draft that does NOT carry the required evidence MUST be marked
# action='invalid'. The static helper validate_remediation_directive
# returns the still-unmet conditions; the caller writes the invalid decision.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-026")
def test_remediation_directive_satisfied() -> None:
    """When the new draft includes the required evidence, satisfied=True."""
    prior_unmet = [
        {
            "failed_assertion_id": "VAL-W8-X",
            "required_evidence": ["evidence-ref-001", "evidence-ref-002"],
        }
    ]
    new_refs = ["evidence-ref-001", "evidence-ref-002", "evidence-ref-extra"]
    result = validate_remediation_directive(
        prior_unmet_conditions=prior_unmet,
        new_evidence_refs=new_refs,
    )
    assert result.satisfied is True
    assert result.still_unmet == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-026")
def test_remediation_directive_missing_required_evidence() -> None:
    """When required_evidence is missing, satisfied=False and conditions are listed."""
    prior_unmet = [
        {
            "failed_assertion_id": "VAL-W8-X",
            "required_evidence": ["evidence-ref-001", "evidence-ref-002"],
        }
    ]
    new_refs = ["evidence-ref-001"]  # missing 002
    result = validate_remediation_directive(
        prior_unmet_conditions=prior_unmet,
        new_evidence_refs=new_refs,
    )
    assert result.satisfied is False
    assert len(result.still_unmet) == 1
    cond = result.still_unmet[0]
    assert cond["failed_assertion_id"] == "VAL-W8-X"
    assert "evidence-ref-002" in cond["missing_evidence"]
    assert "evidence-ref-001" not in cond["missing_evidence"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-026")
def test_remediation_directive_evidence_refs_as_dicts() -> None:
    """Evidence refs may be dicts with a 'ref' key (matches A.3 evidence_refs[])."""
    prior_unmet = [
        {
            "failed_assertion_id": "VAL-W8-Y",
            "required_evidence": ["evidence-ref-A"],
        }
    ]
    new_refs = [{"ref": "evidence-ref-A", "kind": "stdout"}]
    result = validate_remediation_directive(
        prior_unmet_conditions=prior_unmet,
        new_evidence_refs=new_refs,
    )
    assert result.satisfied is True


# ---------------------------------------------------------------------------
# VAL-W8-027: Unchanged re-submission returns RELAY-GATE-041 and does NOT
# consume a round.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-027")
@pytest.mark.asyncio
async def test_unchanged_resubmission_returns_relay_gate_041(tmp_path: Path) -> None:
    """Identical (command_hash + manifest + release_sha + inputs_digest) returns RELAY-GATE-041."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        prior_command_hash = "sha256-prior-cmd"
        prior_release_sha = "sha256-prior-release"
        prior_evidence_refs = ["evidence-A", "evidence-B"]
        # Record the prior round's inputs.
        await f.coordinator.record_round_inputs(
            draft_id=wf.draft_id,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=f.prior_round,
            command_hash=prior_command_hash,
            manifest_commit_hash=wf.manifest_hash,
            release_sha=prior_release_sha,
            evidence_refs=prior_evidence_refs,
        )

        # Snapshot the round counter before the check.
        rounds_before = await fetch_count(
            wf.database,
            "gate_rounds",
            "scope_type = ? AND scope_id = ?",
            ("run", wf.scope_id),
        )

        # Identical re-submission.
        guard = await f.coordinator.check_unchanged_resubmission(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            new_command_hash=prior_command_hash,
            new_manifest_commit_hash=wf.manifest_hash,
            new_release_sha=prior_release_sha,
            new_evidence_refs=prior_evidence_refs,
        )
        assert guard.ok is False
        assert guard.error_envelope is not None
        assert guard.error_envelope["code"] == RelayErrorCode.RELAY_GATE_041
        assert guard.error_envelope["code"] == "RELAY-GATE-041"
        assert guard.prior_round == f.prior_round

        # Round counter is unchanged: the check did NOT consume a round.
        rounds_after = await fetch_count(
            wf.database,
            "gate_rounds",
            "scope_type = ? AND scope_id = ?",
            ("run", wf.scope_id),
        )
        assert rounds_after == rounds_before
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-027")
@pytest.mark.asyncio
async def test_changed_resubmission_passes_guard(tmp_path: Path) -> None:
    """A new draft with a changed anchor passes the guard and may proceed."""
    f = await setup_restart_fixture(tmp_path)
    try:
        wf = f.writer
        await f.coordinator.record_round_inputs(
            draft_id=wf.draft_id,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=f.prior_round,
            command_hash="sha256-prior",
            manifest_commit_hash=wf.manifest_hash,
            release_sha="sha256-rel",
            evidence_refs=["ev-1"],
        )
        # Change just the evidence_refs.
        guard = await f.coordinator.check_unchanged_resubmission(
            scope_type="run",
            scope_id=wf.scope_id,
            prior_round=f.prior_round,
            new_command_hash="sha256-prior",
            new_manifest_commit_hash=wf.manifest_hash,
            new_release_sha="sha256-rel",
            new_evidence_refs=["ev-1", "ev-2"],
        )
        assert guard.ok is True
        assert guard.error_envelope is None
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-027")
def test_compute_inputs_digest_is_deterministic() -> None:
    """Two calls with the same inputs produce the same digest."""
    d1 = compute_inputs_digest(
        command_hash="sha256-a",
        manifest_commit_hash="sha256-b",
        release_sha="sha256-c",
        evidence_refs=["ref-1", "ref-2"],
    )
    d2 = compute_inputs_digest(
        command_hash="sha256-a",
        manifest_commit_hash="sha256-b",
        release_sha="sha256-c",
        evidence_refs=["ref-1", "ref-2"],
    )
    assert d1 == d2
    # Changing any input flips the digest.
    d3 = compute_inputs_digest(
        command_hash="sha256-a",
        manifest_commit_hash="sha256-b",
        release_sha="sha256-c",
        evidence_refs=["ref-1", "ref-3"],
    )
    assert d3 != d1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-027")
def test_unchanged_resubmission_error_carries_relay_gate_041() -> None:
    """UnchangedResubmissionError.code is the canonical RELAY-GATE-041 token."""
    err = UnchangedResubmissionError("test")
    assert err.code == RelayErrorCode.RELAY_GATE_041
    assert err.code == "RELAY-GATE-041"


# ---------------------------------------------------------------------------
# Coverage helpers: ensure we did not break unrelated paths.
# ---------------------------------------------------------------------------
#
# A simple smoke check: the migration 0010 declares gate_round_inputs with
# the columns the coordinator queries. We do a SELECT against pragma_table_info
# to confirm the schema lands.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-020")
@pytest.mark.asyncio
async def test_migration_0010_declares_gate_round_inputs(tmp_path: Path) -> None:
    """gate_round_inputs table exists with the canonical columns after migration."""
    f = await setup_restart_fixture(tmp_path, seed_prior_round=False)
    try:
        rows = await fetch_all(
            f.writer.database,
            "SELECT name FROM pragma_table_info('gate_round_inputs') ORDER BY cid ASC",
        )
        names = [r[0] for r in rows]
        # The ten declared columns in 0010_gate_restart.sql.
        expected = {
            "gate_round_inputs_id",
            "scope_type",
            "scope_id",
            "round",
            "draft_id",
            "inputs_digest",
            "command_hash",
            "manifest_commit_hash",
            "release_sha",
            "recorded_at",
        }
        assert expected.issubset(set(names))
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Extra: silence unused-import warnings on the imports we keep for the file.
# ---------------------------------------------------------------------------
# (RestartCoordinator and seed_draft are imported above so tests within the
# same module can reference them; the helpers' export list keeps them stable
# across test additions.)
_ = RestartCoordinator
_ = seed_draft
_ = seed_gate_round
_ = fetch_event_log_payload
