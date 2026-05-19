"""W8.4 plumbing tests: admin.reopen and admin.terminate transitions.

Covers VAL-W8-035, VAL-W8-036, VAL-W8-037. Drives the real migration
0011 schema (``admin_override_audit``, ``evidence_x_relay_extensions``,
``gate_stalled_state``) end-to-end via :class:`AdminActionService`.

V3M1-F03 (2026-05-18) renamed the gate-admin override audit table
from its historical name to ``admin_override_audit`` (sidecar
migration 0026) to free the canonical §V hosted name; query sites
below have been updated.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from _w8_4_helpers import (
    fetch_all,
    fetch_one,
    seed_evidence_bundle,
    seed_gate_round,
    seed_stalled,
    setup_circuit_breaker_fixture,
)
from relay_gate_engine import (
    AUDIT_ACTION_REOPEN,
    AUDIT_ACTION_TERMINATE,
    EVENT_ADMIN_REOPEN,
    EVENT_ADMIN_TERMINATE,
    INITIATED_BY_ADMIN_OVERRIDE,
    MAX_REASON_BYTES,
    STALLED_REASON_ADMIN_TERMINATED,
    STALLED_REASON_CAP_EXCEEDED,
    X_RELAY_ADMIN_TERMINATE_NS,
    AdminActor,
    AdminReasonError,
    StalledStateAlreadyTerminatedError,
    StalledStateMissingError,
    fetch_audit_entry,
)
from relay_gate_engine.errors import AdminAuthorizationError
from relay_schemas.error_codes import RelayErrorCode

# ---------------------------------------------------------------------------
# VAL-W8-035: admin.reopen requires org_owner / org_admin role.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_reopen_rejects_member_role(tmp_path: Path) -> None:
    """admin.reopen invoked by a 'member' role raises
    AdminAuthorizationError (RELAY-AUTH-014; HTTP 403)."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Stall the scope first so reopen has a target.
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "c" * 64,
            role="member",
        )
        with pytest.raises(AdminAuthorizationError) as excinfo:
            await f.admin.reopen(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                actor=actor,
                reason="should not pass",
                manifest_commit_hash=wf.manifest_hash,
            )
        env = excinfo.value.to_envelope()
        assert env["code"] == RelayErrorCode.RELAY_AUTH_014
        assert env["payload"]["actor_role"] == "member"

        # Defense in depth: zero audit rows written.
        rows = await fetch_all(
            wf.database,
            "SELECT audit_id FROM admin_override_audit WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert rows == []
        # gate_stalled_state.reopened_at remains NULL.
        sr = await fetch_one(
            wf.database,
            "SELECT reopened_at FROM gate_stalled_state WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert sr is not None
        assert sr[0] is None
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["org_owner", "org_admin"])
async def test_reopen_admin_opens_new_round(
    tmp_path: Path, role: str
) -> None:
    """org_owner or org_admin can reopen; a new gate_rounds row appears."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Seed the terminal round + stalled state.
        prior_round_id = await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=5,
        )
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )

        actor = AdminActor(
            identity_hash="sha256-" + "d" * 64,
            role=role,
        )
        result = await f.admin.reopen(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            actor=actor,
            reason="design partner request: contract widened",
            manifest_commit_hash=wf.manifest_hash,
        )
        assert result.new_round == 6
        assert result.prior_round_id == prior_round_id

        # New gate_rounds row exists at round 6 with initiated_by='admin_override'.
        rows = await fetch_all(
            wf.database,
            "SELECT round, initiated_by, restart_predecessor "
            "FROM gate_rounds WHERE scope_id = ? ORDER BY round",
            (wf.scope_id,),
        )
        rounds_by_num = {int(r[0]): (r[1], r[2]) for r in rows}
        assert 5 in rounds_by_num
        assert 6 in rounds_by_num
        assert rounds_by_num[6][0] == INITIATED_BY_ADMIN_OVERRIDE
        assert rounds_by_num[6][1] == prior_round_id

        # gate_stalled_state.reopened_at populated.
        sr = await fetch_one(
            wf.database,
            "SELECT reopened_at, terminated_at FROM gate_stalled_state "
            "WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert sr is not None
        assert sr[0] is not None
        assert sr[1] is None  # not terminated
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-036: reopen audit row carries reason + actor + prior + new round id.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-036")
@pytest.mark.asyncio
async def test_reopen_audit_row_has_four_required_fields(
    tmp_path: Path,
) -> None:
    """admin_override_audit row contains reason, actor identity, prior
    round id, new round id."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        prior_round_id = await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=5,
        )
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "9" * 64,
            role="org_admin",
        )
        reason = "design partner request: contract widened to allow new assertion"
        result = await f.admin.reopen(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            actor=actor,
            reason=reason,
            manifest_commit_hash=wf.manifest_hash,
        )

        audit = await fetch_audit_entry(wf.database, audit_id=result.audit_id)
        assert audit is not None
        # Four required fields:
        assert audit["reason"] == reason
        assert audit["actor_identity_hash"] == actor.identity_hash
        assert audit["prior_round_id"] == prior_round_id
        assert audit["new_round_id"] == result.new_gate_round_id
        # Plus discriminators.
        assert audit["action"] == AUDIT_ACTION_REOPEN
        assert audit["actor_role"] == "org_admin"
        assert audit["scope_id"] == wf.scope_id
        assert audit["manifest_commit_hash"] == wf.manifest_hash

        # payload JSON also carries the same fields (defense in depth).
        payload = json.loads(audit["payload"])
        for key in ("reason", "prior_round_id", "new_round_id"):
            assert key in payload
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-036")
@pytest.mark.asyncio
async def test_reopen_rejects_empty_reason(tmp_path: Path) -> None:
    """Empty reason raises AdminReasonError before any DB write."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "e" * 64,
            role="org_admin",
        )
        with pytest.raises(AdminReasonError) as excinfo:
            await f.admin.reopen(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                actor=actor,
                reason="",
                manifest_commit_hash=wf.manifest_hash,
            )
        assert excinfo.value.payload["reason_bytes"] == 0
        # No audit row written.
        rows = await fetch_all(
            wf.database,
            "SELECT audit_id FROM admin_override_audit WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert rows == []
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-036")
@pytest.mark.asyncio
async def test_reopen_rejects_oversize_reason(tmp_path: Path) -> None:
    """Reason > 2 KiB raises AdminReasonError before any DB write."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "f" * 64,
            role="org_admin",
        )
        oversize = "x" * (MAX_REASON_BYTES + 1)
        with pytest.raises(AdminReasonError) as excinfo:
            await f.admin.reopen(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                actor=actor,
                reason=oversize,
                manifest_commit_hash=wf.manifest_hash,
            )
        assert excinfo.value.payload["reason_bytes"] == MAX_REASON_BYTES + 1
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_reopen_against_non_stalled_scope_errors(
    tmp_path: Path,
) -> None:
    """Reopen against a scope with no gate_stalled_state row raises."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        actor = AdminActor(
            identity_hash="sha256-" + "1" * 64,
            role="org_owner",
        )
        with pytest.raises(StalledStateMissingError):
            await f.admin.reopen(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                actor=actor,
                reason="why",
                manifest_commit_hash=wf.manifest_hash,
            )
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_reopen_against_terminated_scope_errors(
    tmp_path: Path,
) -> None:
    """Reopen against an already-terminated scope raises."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
            terminated_at="2026-05-15T13:00:00.000000Z",
            reason=STALLED_REASON_ADMIN_TERMINATED,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "2" * 64,
            role="org_owner",
        )
        with pytest.raises(StalledStateAlreadyTerminatedError):
            await f.admin.reopen(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                actor=actor,
                reason="should-not-pass",
                manifest_commit_hash=wf.manifest_hash,
            )
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# VAL-W8-037: terminate seals final block + x-relay/admin-terminate claim.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-037")
@pytest.mark.asyncio
async def test_terminate_writes_x_relay_extension_claim(
    tmp_path: Path,
) -> None:
    """admin.terminate as org_owner writes the x-relay/admin-terminate
    extension claim on the bound evidence bundle."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        # Seed a stalled scope + bundle to bind to.
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        bundle_id = await seed_evidence_bundle(
            wf.database, manifest_commit_hash=wf.manifest_hash
        )

        actor = AdminActor(
            identity_hash="sha256-" + "a" * 64,
            role="org_owner",
        )
        result = await f.admin.terminate(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            evidence_bundle_id=bundle_id,
            actor=actor,
            manifest_commit_hash=wf.manifest_hash,
            reason="risk: cannot satisfy contract",
        )
        assert result.extension_id != ""
        assert result.claim_digest.startswith("sha256-")

        # evidence_x_relay_extensions row exists with the canonical namespace.
        ext = await fetch_one(
            wf.database,
            "SELECT extension_namespace, claim_digest, payload, "
            "       evidence_bundle_id "
            "FROM evidence_x_relay_extensions WHERE extension_id = ?",
            (result.extension_id,),
        )
        assert ext is not None
        assert ext[0] == X_RELAY_ADMIN_TERMINATE_NS
        assert ext[1] == result.claim_digest
        assert ext[3] == bundle_id
        # Payload carries the canonical fields.
        payload = json.loads(ext[2])
        assert payload["extension_namespace"] == X_RELAY_ADMIN_TERMINATE_NS
        assert payload["scope_id"] == wf.scope_id
        assert payload["gate_id"] == wf.gate_id
        assert payload["terminal_round"] == 5
        assert payload["actor_identity_hash"] == actor.identity_hash
        assert payload["actor_role"] == "org_owner"

        # gate_stalled_state.terminated_at is set; reason is admin_terminated.
        sr = await fetch_one(
            wf.database,
            "SELECT terminated_at, reason FROM gate_stalled_state "
            "WHERE scope_id = ?",
            (wf.scope_id,),
        )
        assert sr is not None
        assert sr[0] is not None
        assert sr[1] == STALLED_REASON_ADMIN_TERMINATED

        # admin_override_audit row was written.
        audit = await fetch_audit_entry(
            wf.database, audit_id=result.audit_id
        )
        assert audit is not None
        assert audit["action"] == AUDIT_ACTION_TERMINATE
        assert audit["actor_role"] == "org_owner"
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_terminate_rejects_non_admin_role(tmp_path: Path) -> None:
    """admin.terminate by a non-admin raises AdminAuthorizationError."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        bundle_id = await seed_evidence_bundle(
            wf.database, manifest_commit_hash=wf.manifest_hash
        )
        actor = AdminActor(
            identity_hash="sha256-" + "b" * 64,
            role="member",
        )
        with pytest.raises(AdminAuthorizationError):
            await f.admin.terminate(
                scope_type="run",
                scope_id=wf.scope_id,
                gate_id=wf.gate_id,
                evidence_bundle_id=bundle_id,
                actor=actor,
                manifest_commit_hash=wf.manifest_hash,
            )
        # No x-relay claim was written.
        rows = await fetch_all(
            wf.database,
            "SELECT extension_id FROM evidence_x_relay_extensions",
        )
        assert rows == []
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-037")
@pytest.mark.asyncio
async def test_terminate_event_log_emits_admin_terminate(
    tmp_path: Path,
) -> None:
    """The terminate path emits one event_log_entries row with
    event_type='admin.terminate' carrying the extension_id."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        bundle_id = await seed_evidence_bundle(
            wf.database, manifest_commit_hash=wf.manifest_hash
        )
        actor = AdminActor(
            identity_hash="sha256-" + "3" * 64,
            role="org_owner",
        )
        result = await f.admin.terminate(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            evidence_bundle_id=bundle_id,
            actor=actor,
            manifest_commit_hash=wf.manifest_hash,
        )
        evt = await fetch_one(
            wf.database,
            "SELECT event_type, payload FROM event_log_entries "
            "WHERE event_type = ? AND scope_id = ? "
            "ORDER BY ingest_sequence DESC LIMIT 1",
            (EVENT_ADMIN_TERMINATE, wf.scope_id),
        )
        assert evt is not None
        assert evt[0] == EVENT_ADMIN_TERMINATE
        payload = json.loads(evt[1])
        assert payload["extension_id"] == result.extension_id
        assert payload["evidence_bundle_id"] == bundle_id
        assert payload["actor_role"] == "org_owner"
    finally:
        await f.writer.database.close()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-037")
@pytest.mark.asyncio
async def test_terminate_idempotent(tmp_path: Path) -> None:
    """A second terminate call on an already-terminated scope is a
    no-op and returns the prior timestamp."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        bundle_id = await seed_evidence_bundle(
            wf.database, manifest_commit_hash=wf.manifest_hash
        )
        actor = AdminActor(
            identity_hash="sha256-" + "4" * 64,
            role="org_owner",
        )
        first = await f.admin.terminate(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            evidence_bundle_id=bundle_id,
            actor=actor,
            manifest_commit_hash=wf.manifest_hash,
        )
        second = await f.admin.terminate(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            evidence_bundle_id=bundle_id,
            actor=actor,
            manifest_commit_hash=wf.manifest_hash,
        )
        assert second.audit_id == ""
        # Still exactly ONE x-relay extension row.
        rows = await fetch_all(
            wf.database,
            "SELECT extension_id FROM evidence_x_relay_extensions "
            "WHERE evidence_bundle_id = ?",
            (bundle_id,),
        )
        assert len(rows) == 1
        # The original is preserved.
        assert rows[0][0] == first.extension_id
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Reopen-then-stall-clear: after reopen, assert_not_stalled passes.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_reopen_followed_by_assert_not_stalled_is_silent(
    tmp_path: Path,
) -> None:
    """After admin.reopen, the breaker.assert_not_stalled passes."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=5,
        )
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
            reason=STALLED_REASON_CAP_EXCEEDED,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "5" * 64,
            role="org_owner",
        )
        await f.admin.reopen(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            actor=actor,
            reason="re-opening for follow-up",
            manifest_commit_hash=wf.manifest_hash,
        )
        # Now the breaker should let new drafts through.
        await f.breaker.assert_not_stalled(
            scope_type="run", scope_id=wf.scope_id
        )
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# Spec gap #1: audit row reopen_reason_required CHECK constraint.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-036")
@pytest.mark.asyncio
async def test_admin_override_audit_reopen_reason_check_constraint(
    tmp_path: Path,
) -> None:
    """SQL-layer CHECK rejects direct INSERT of admin.reopen with empty
    reason (defence in depth against application bypass)."""
    import aiosqlite

    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        audit_id = str(uuid.uuid4())
        async with aiosqlite.connect(str(wf.database.db_path)) as conn:
            with pytest.raises(aiosqlite.IntegrityError) as excinfo:
                await conn.execute(
                    "INSERT INTO admin_override_audit ("
                    "  audit_id, scope_type, scope_id, gate_id, "
                    "  action, actor_kind, actor_identity_hash, "
                    "  actor_role, reason, manifest_commit_hash, "
                    "  occurred_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        audit_id,
                        "run",
                        wf.scope_id,
                        wf.gate_id,
                        AUDIT_ACTION_REOPEN,
                        "user",
                        "sha256-" + "6" * 64,
                        "org_admin",
                        "",  # empty reason -- CHECK violation expected
                        wf.manifest_hash,
                        "2026-05-15T12:00:00.000000Z",
                    ),
                )
                await conn.commit()
            assert (
                "admin_override_audit_reopen_reason_required" in str(excinfo.value)
                or "CHECK constraint failed" in str(excinfo.value)
            )
    finally:
        await f.writer.database.close()


# ---------------------------------------------------------------------------
# admin.reopen event log shape.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-035")
@pytest.mark.asyncio
async def test_reopen_emits_event_log_entry(tmp_path: Path) -> None:
    """admin.reopen emits one event_log row with event_type='admin.reopen'."""
    f = await setup_circuit_breaker_fixture(tmp_path)
    try:
        wf = f.writer
        await seed_gate_round(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            round_=5,
        )
        await seed_stalled(
            wf.database,
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            terminal_round=5,
        )
        actor = AdminActor(
            identity_hash="sha256-" + "7" * 64,
            role="org_admin",
        )
        result = await f.admin.reopen(
            scope_type="run",
            scope_id=wf.scope_id,
            gate_id=wf.gate_id,
            actor=actor,
            reason="follow-up evidence ready",
            manifest_commit_hash=wf.manifest_hash,
        )
        evt = await fetch_one(
            wf.database,
            "SELECT event_type, payload FROM event_log_entries "
            "WHERE event_type = ? AND scope_id = ? "
            "ORDER BY ingest_sequence DESC LIMIT 1",
            (EVENT_ADMIN_REOPEN, wf.scope_id),
        )
        assert evt is not None
        assert evt[0] == EVENT_ADMIN_REOPEN
        payload = json.loads(evt[1])
        assert payload["audit_id"] == result.audit_id
        assert payload["new_round_id"] == result.new_gate_round_id
        assert payload["new_round"] == 6
    finally:
        await f.writer.database.close()
