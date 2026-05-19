"""Admin transitions out of ``gate.stalled`` state (W8.4).

Implements VAL-W8-035 / VAL-W8-036 / VAL-W8-037 and the canonical
transitions in spec section AD lines 5471-5488:

  - ``admin.reopen``    (gate.stalled -> gate.open, new round opens)
                        Required actor role: ``org_owner`` or ``org_admin``.
                        Required input: non-empty reason (<= 2 KiB).
                        Side effects: writes one ``admin_override_audit``
                        row, one ``event_log_entries`` row, one new
                        ``gate_rounds`` row, UPDATEs the
                        ``gate_stalled_state`` row to set
                        ``reopened_at``.

  - ``admin.terminate`` (gate.stalled -> gate.terminal)
                        Required actor role: ``org_owner`` or ``org_admin``.
                        Side effects: writes one ``admin_override_audit``
                        row, one ``event_log_entries`` row, one
                        ``evidence_x_relay_extensions`` row with
                        ``extension_namespace='x-relay/admin-terminate'``,
                        UPDATEs the ``gate_stalled_state`` row to set
                        ``terminated_at`` and ``reason='admin_terminated'``.
                        Does NOT write a ``gate_decisions`` row directly
                        in this OSS scaffold -- the caller (gate engine)
                        sees the terminate marker and writes its
                        canonical final-block decision via the W8.2
                        ``GateDecisionWriter``. The x-relay extension
                        claim attaches to the existing evidence bundle
                        the caller supplies.

VAL-W8-035 narrative says the API returns 403 on a non-admin actor; this
module raises :class:`AdminAuthorizationError` (``RELAY-AUTH-014``) and
the API layer maps it to HTTP 403.

Per CLAUDE.md keystone #4, every admin action carries the three-anchor
handoff: actor_identity_hash + manifest_commit_hash + scope_id. The audit
row records all three.

Per contract gap #4 (the gate-admin override audit table is not in §A
schemas we have), this module is the canonical writer for the table
introduced in migration 0011 (renamed to ``admin_override_audit`` by
V3M1-F03 migration 0026 to free the canonical §V hosted name). Per
contract gap #6 (canonical x-relay/admin-terminate
claim shape unspecified), the OSS profile records the generic shape
``{extension_namespace, payload, claim_digest, signature}``; W11 ACEF
wire format will tighten the schema.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from relay_sidecar.state_engine import init_scope_on_conn

from .circuit_breaker import (
    STALLED_REASON_ADMIN_TERMINATED,
)
from .decision_writer import SCHEMA_EVENT_LOG, _borrow_gate_writer
from .errors import (
    AdminAuthorizationError,
    GateEngineError,
)
from .signed_decision import (
    canonical_json_bytes,
    sha256_wire,
)

# ---------------------------------------------------------------------------
# Canonical constants.
# ---------------------------------------------------------------------------

#: Roles permitted to invoke admin.reopen / admin.terminate
#: (VAL-W8-035, spec AD lines 5479-5480).
ADMIN_ROLES: Final[frozenset[str]] = frozenset({"org_owner", "org_admin"})

#: ``admin_override_audit.action`` value for the reopen path.
AUDIT_ACTION_REOPEN: Final[str] = "admin.reopen"

#: ``admin_override_audit.action`` value for the terminate path.
AUDIT_ACTION_TERMINATE: Final[str] = "admin.terminate"

#: ``event_log_entries.event_type`` written on the reopen transition
#: (mirrors spec AD line 5479 ``admin.reopen``).
EVENT_ADMIN_REOPEN: Final[str] = "admin.reopen"

#: ``event_log_entries.event_type`` written on the terminate transition
#: (mirrors spec AD line 5480 ``admin.terminate``).
EVENT_ADMIN_TERMINATE: Final[str] = "admin.terminate"

#: ACEF extension namespace for the admin-terminate claim
#: (VAL-W8-037; spec ACEF acceptance criteria line 2861).
X_RELAY_ADMIN_TERMINATE_NS: Final[str] = "x-relay/admin-terminate"

#: Maximum admit reason length (VAL-W8-036). Mirrors migration 0011
#: ``admin_override_audit_reason_max`` CHECK (V3M1-F03 migration 0026
#: renamed both the table and the CHECK from the historical name to
#: free the canonical §V hosted name).
MAX_REASON_BYTES: Final[int] = 2048

#: ``gate_rounds.initiated_by`` value for an admin-reopen new round.
INITIATED_BY_ADMIN_OVERRIDE: Final[str] = "admin_override"

#: ``gate_rounds.schema_version`` -- mirrors the W8.2 writer constant.
SCHEMA_GATE_ROUND: Final[str] = "relay.gate_round.v1"

#: Historical ``schema_version`` literal for the gate-admin override
#: audit envelope. Audit-R3 dropped the schema_version column from the
#: sidecar mirror (migration 0023) because the envelope is not in
#: envelopes.yaml / KNOWN_SCHEMA_IDS; the constant is retained for
#: backwards-compatible imports.
SCHEMA_AUDIT_LOG_ENTRY: Final[str] = "relay.audit_log_entry.v1"

#: ``evidence_x_relay_extensions.schema_version`` -- matches migration 0011 DEFAULT.
SCHEMA_X_RELAY_EXTENSION: Final[str] = "relay.evidence_x_relay_extension.v1"


# ---------------------------------------------------------------------------
# Public dataclasses.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdminActor:
    """The minimal admin-actor reference required for admin transitions.

    Attributes:
        identity_hash: sha256-<hex> wire form of the actor's identity
            certificate (CLAUDE.md keystone #4).
        role: One of the allowed admin roles (validated against
            :data:`ADMIN_ROLES` before any DB write).
        kind: Actor kind recorded on event_log row (default 'user').
    """

    identity_hash: str
    role: str
    kind: str = "user"


@dataclass(frozen=True)
class ReopenResult:
    """Outcome of one :meth:`AdminActionService.reopen` call.

    Attributes:
        audit_id: UUID of the appended ``admin_override_audit`` row.
        event_id: UUID of the appended ``event_log_entries`` row.
        new_gate_round_id: UUID of the new ``gate_rounds`` row opened
            by the admin transition (VAL-W8-035: "a new round opens").
        new_round: The integer round number of the new row
            (= prior_terminal_round + 1).
        prior_round_id: gate_round_id of the round that was terminal
            before the reopen.
        reopened_at: RFC 3339 timestamp recorded on the row.
    """

    audit_id: str
    event_id: str
    new_gate_round_id: str
    new_round: int
    prior_round_id: str
    reopened_at: str


@dataclass(frozen=True)
class TerminateResult:
    """Outcome of one :meth:`AdminActionService.terminate` call.

    Attributes:
        audit_id: UUID of the appended ``admin_override_audit`` row.
        event_id: UUID of the appended ``event_log_entries`` row.
        extension_id: UUID of the
            ``evidence_x_relay_extensions`` row carrying the
            x-relay/admin-terminate claim (VAL-W8-037).
        claim_digest: sha256-<hex> over the canonical JSON of the
            x-relay/admin-terminate payload.
        terminated_at: RFC 3339 timestamp recorded on the row.
    """

    audit_id: str
    event_id: str
    extension_id: str
    claim_digest: str
    terminated_at: str


# ---------------------------------------------------------------------------
# Errors.
# ---------------------------------------------------------------------------


class StalledStateMissingError(GateEngineError):
    """Admin action attempted against a scope that is NOT in
    ``gate.stalled`` state.

    The reopen / terminate API is only valid against scopes that have
    actually been stalled by the circuit breaker; calling reopen on a
    healthy scope is a caller bug and surfaces as
    ``RELAY-GATE-001`` (generic gate evaluation failure) with a
    descriptive message.
    """

    # inherits RELAY-GATE-001 from GateEngineError.


class StalledStateAlreadyTerminatedError(GateEngineError):
    """Admin action attempted against a scope that has already been
    terminated. Once terminated, the scope is permanently closed;
    reopen is rejected.
    """

    # inherits RELAY-GATE-001 from GateEngineError.


class AdminReasonError(GateEngineError):
    """admin.reopen invoked with an empty or oversize reason.

    VAL-W8-036: "reopen MUST require a non-empty reason (<= 2 KiB)".
    """

    # inherits RELAY-GATE-001 from GateEngineError.


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _now_rfc3339_utc() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _assert_admin_role(actor: AdminActor) -> None:
    """VAL-W8-035: reject non-admin actors before any DB write."""
    if actor.role not in ADMIN_ROLES:
        raise AdminAuthorizationError(
            f"admin action requires role in {sorted(ADMIN_ROLES)!r}; "
            f"actor.role={actor.role!r}",
            payload={
                "actor_role": actor.role,
                "allowed_roles": sorted(ADMIN_ROLES),
            },
        )


def _validate_reason(reason: str) -> str:
    """VAL-W8-036: non-empty, <= 2 KiB."""
    if not isinstance(reason, str):
        raise AdminReasonError(
            "admin.reopen reason must be a string",
            payload={"reason_type": type(reason).__name__},
        )
    encoded = reason.encode("utf-8")
    if len(encoded) == 0:
        raise AdminReasonError(
            "admin.reopen reason must be non-empty",
            payload={"reason_bytes": 0},
        )
    if len(encoded) > MAX_REASON_BYTES:
        raise AdminReasonError(
            f"admin.reopen reason exceeds {MAX_REASON_BYTES}-byte cap",
            payload={
                "reason_bytes": len(encoded),
                "max_bytes": MAX_REASON_BYTES,
            },
        )
    return reason


def _build_x_relay_admin_terminate_payload(
    *,
    scope_type: str,
    scope_id: str,
    gate_id: str,
    terminal_round: int,
    actor_identity_hash: str,
    actor_role: str,
    reason: str,
    terminated_at: str,
    manifest_commit_hash: str,
) -> dict[str, Any]:
    """Canonical x-relay/admin-terminate claim body.

    Per contract gap #6, spec leaves the precise shape unspecified. The
    OSS profile records the fields the gate engine needs for downstream
    verifier checks: actor identity + role + reason + scope + round +
    timestamp + manifest commit. W11 will tighten when ACEF publishes
    the canonical schema.
    """
    return {
        "extension_namespace": X_RELAY_ADMIN_TERMINATE_NS,
        "schema_version": "relay.x_relay_admin_terminate.v1",
        "scope_type": scope_type,
        "scope_id": str(scope_id),
        "gate_id": str(gate_id),
        "terminal_round": int(terminal_round),
        "actor_identity_hash": actor_identity_hash,
        "actor_role": actor_role,
        "reason": reason,
        "terminated_at": terminated_at,
        "manifest_commit_hash": manifest_commit_hash,
    }


# ---------------------------------------------------------------------------
# AdminActionService.
# ---------------------------------------------------------------------------


@dataclass
class AdminActionService:
    """Single production-code path for admin.reopen / admin.terminate.

    The service is stateless w.r.t. requests; one instance serves any
    number of admin transitions against the same SidecarDatabase.

    Construction args:
      database: The active SidecarDatabase whose writer connection
        the service borrows via :func:`_borrow_gate_writer`.
      project_id: OSS single-tenant sentinel by default.
      signing_key_id: The key id recorded on the
        ``evidence_x_relay_extensions`` row written by terminate. The
        actual signature is computed over the canonical JSON of the
        payload by the caller-supplied signer; this module records the
        signature it is handed (the signing primitives live in the W2
        signer module).
    """

    database: Any
    project_id: str = "00000000-0000-0000-0000-000000000000"
    signing_key_id: str = "local-admin-terminate-kid"

    # ----- reopen ----------------------------------------------------

    async def reopen(
        self,
        *,
        scope_type: str,
        scope_id: str,
        gate_id: str,
        actor: AdminActor,
        reason: str,
        manifest_commit_hash: str,
        signature: str = "",
    ) -> ReopenResult:
        """Transition a stalled scope back to ``gate.open`` with a new
        round.

        VAL-W8-035: role check happens BEFORE any DB write. Non-admin
        actors raise :class:`AdminAuthorizationError`.

        VAL-W8-036: non-empty <= 2 KiB reason is required.

        Side effects (all in ONE BEGIN IMMEDIATE..COMMIT block):
          1. UPDATE gate_stalled_state SET reopened_at = now()
             WHERE (scope_type, scope_id) matches.
          2. INSERT one gate_rounds row with
             ``initiated_by='admin_override'`` and
             ``restart_predecessor=prior_round_id``.
          3. INSERT one admin_override_audit row with the reopen action,
             the reason, the prior round id, the new round id.
          4. INSERT one event_log_entries row with
             ``event_type='admin.reopen'``.
        """
        _assert_admin_role(actor)
        _validate_reason(reason)

        now = _now_rfc3339_utc()
        audit_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        new_gate_round_id = str(uuid.uuid4())

        async with _borrow_gate_writer(self.database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                # Lookup stalled state + prior round.
                async with conn.execute(
                    "SELECT gate_id, terminal_round, reason, "
                    "       reopened_at, terminated_at "
                    "FROM gate_stalled_state "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (scope_type, str(scope_id)),
                ) as cur:
                    row = await cur.fetchone()
                if row is None:
                    await conn.execute("ROLLBACK")
                    raise StalledStateMissingError(
                        "scope is not in gate.stalled; admin.reopen is "
                        "only valid against stalled scopes",
                        payload={
                            "scope_type": scope_type,
                            "scope_id": str(scope_id),
                        },
                    )
                terminal_round = int(row[1])
                terminated_at = row[4]
                if terminated_at is not None:
                    await conn.execute("ROLLBACK")
                    raise StalledStateAlreadyTerminatedError(
                        "scope was already admin-terminated; "
                        "admin.reopen is no longer valid",
                        payload={
                            "scope_type": scope_type,
                            "scope_id": str(scope_id),
                            "terminated_at": str(terminated_at),
                        },
                    )

                # Resolve prior gate_round_id (the terminal round row).
                async with conn.execute(
                    "SELECT gate_round_id FROM gate_rounds "
                    "WHERE scope_type = ? AND scope_id = ? AND round = ?",
                    (scope_type, str(scope_id), terminal_round),
                ) as cur:
                    pr = await cur.fetchone()
                prior_round_id = "" if pr is None else str(pr[0])

                new_round = terminal_round + 1

                # 1. UPDATE gate_stalled_state SET reopened_at.
                await conn.execute(
                    "UPDATE gate_stalled_state "
                    "SET reopened_at = ? "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (now, scope_type, str(scope_id)),
                )

                # 2a. INSERT the paired scope_state row for the new
                # gate_round (spec W line 5112 paired-row invariant;
                # migration 0008 / 0016 deferred trigger). state engine
                # is the canonical writer of scope_state per CLAUDE.md
                # keystone invariant #1.
                await init_scope_on_conn(
                    conn=conn,
                    scope_kind="gate_round",
                    scope_id=new_gate_round_id,
                    project_id=self.project_id,
                    initial_state="open",
                )

                # 2. INSERT new gate_rounds row (admin_override).
                await conn.execute(
                    "INSERT INTO gate_rounds ("
                    "  gate_round_id, schema_version, scope_type, "
                    "  scope_id, round, initiated_by, "
                    "  restart_predecessor, gate_decision_id, "
                    "  opened_at, closed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_gate_round_id,
                        SCHEMA_GATE_ROUND,
                        scope_type,
                        str(scope_id),
                        new_round,
                        INITIATED_BY_ADMIN_OVERRIDE,
                        prior_round_id or None,
                        None,
                        now,
                        None,
                    ),
                )

                # 3. INSERT admin_override_audit row.
                audit_payload = {
                    "reason": reason,
                    "prior_round_id": prior_round_id,
                    "new_round_id": new_gate_round_id,
                    "terminal_round": terminal_round,
                    "new_round": new_round,
                }
                # Audit-R3 (2026-05-18): the audit table's schema_version
                # column was dropped (sidecar migration 0023) because
                # relay.audit_log_entry.v1 is not a canonical envelope
                # in envelopes.yaml / openapi.yaml / KNOWN_SCHEMA_IDS.
                # V3M1-F03 (2026-05-18): table renamed from the historical
                # name to admin_override_audit (migration 0026) to free
                # the canonical §V hosted name.
                await conn.execute(
                    "INSERT INTO admin_override_audit ("
                    "  audit_id, project_id, scope_type, "
                    "  scope_id, gate_id, action, actor_kind, "
                    "  actor_identity_hash, actor_role, reason, "
                    "  prior_round_id, new_round_id, "
                    "  manifest_commit_hash, payload, occurred_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        audit_id,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        str(gate_id),
                        AUDIT_ACTION_REOPEN,
                        actor.kind,
                        actor.identity_hash,
                        actor.role,
                        reason,
                        prior_round_id or None,
                        new_gate_round_id,
                        manifest_commit_hash,
                        json.dumps(
                            audit_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )

                # 4. INSERT event_log_entries row.
                event_payload = {
                    "event": EVENT_ADMIN_REOPEN,
                    "scope_id": str(scope_id),
                    "gate_id": str(gate_id),
                    "audit_id": audit_id,
                    "prior_round_id": prior_round_id,
                    "new_round_id": new_gate_round_id,
                    "terminal_round": terminal_round,
                    "new_round": new_round,
                    "actor_role": actor.role,
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    seq_row = await cur.fetchone()
                next_seq = int(seq_row[0]) if seq_row is not None else 0
                await conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, actor_id, "
                    "  manifest_commit_hash, payload, occurred_at, "
                    "  ingest_sequence, event_kind"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        SCHEMA_EVENT_LOG,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        EVENT_ADMIN_REOPEN,
                        actor.kind,
                        actor.identity_hash,
                        manifest_commit_hash,
                        json.dumps(
                            event_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                        next_seq,
                        AUDIT_ACTION_REOPEN,
                    ),
                )

                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise

        return ReopenResult(
            audit_id=audit_id,
            event_id=event_id,
            new_gate_round_id=new_gate_round_id,
            new_round=new_round,
            prior_round_id=prior_round_id,
            reopened_at=now,
        )

    # ----- terminate -------------------------------------------------

    async def terminate(
        self,
        *,
        scope_type: str,
        scope_id: str,
        gate_id: str,
        evidence_bundle_id: str,
        actor: AdminActor,
        manifest_commit_hash: str,
        reason: str = "",
        signature: str = "",
    ) -> TerminateResult:
        """Transition a stalled scope to ``gate.terminal`` (final block).

        VAL-W8-037: writes an x-relay/admin-terminate claim attached to
        the bound evidence bundle. Spec AD line 5480: "final block;
        sealed evidence bundle includes admin terminate claim". The
        canonical final gate_decisions block row is written by the
        caller (gate engine) via the W8.2 GateDecisionWriter after
        consulting this service; this method records the audit + event
        + x-relay extension claim in one transaction.

        Side effects (all in ONE BEGIN IMMEDIATE..COMMIT block):
          1. UPDATE gate_stalled_state SET terminated_at = now(),
             reason = 'admin_terminated'.
          2. INSERT one admin_override_audit row.
          3. INSERT one event_log_entries row with
             ``event_type='admin.terminate'``.
          4. INSERT one evidence_x_relay_extensions row referencing
             the bound bundle, with
             ``extension_namespace='x-relay/admin-terminate'``.
        """
        _assert_admin_role(actor)
        # reason is optional for terminate but if supplied, must fit cap.
        if reason:
            _validate_reason(reason)

        now = _now_rfc3339_utc()
        audit_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        extension_id = str(uuid.uuid4())

        x_relay_payload = _build_x_relay_admin_terminate_payload(
            scope_type=scope_type,
            scope_id=str(scope_id),
            gate_id=str(gate_id),
            terminal_round=0,  # set below from row
            actor_identity_hash=actor.identity_hash,
            actor_role=actor.role,
            reason=reason,
            terminated_at=now,
            manifest_commit_hash=manifest_commit_hash,
        )

        async with _borrow_gate_writer(self.database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                async with conn.execute(
                    "SELECT terminal_round, terminated_at "
                    "FROM gate_stalled_state "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (scope_type, str(scope_id)),
                ) as cur:
                    row = await cur.fetchone()
                if row is None:
                    await conn.execute("ROLLBACK")
                    raise StalledStateMissingError(
                        "scope is not in gate.stalled; admin.terminate "
                        "is only valid against stalled scopes",
                        payload={
                            "scope_type": scope_type,
                            "scope_id": str(scope_id),
                        },
                    )
                terminal_round = int(row[0])
                prior_terminated_at = row[1]
                if prior_terminated_at is not None:
                    # Already terminated -- idempotent no-op.
                    await conn.execute("ROLLBACK")
                    return TerminateResult(
                        audit_id="",
                        event_id="",
                        extension_id="",
                        claim_digest="",
                        terminated_at=str(prior_terminated_at),
                    )

                # Verify the bundle exists (FK-equivalent check).
                async with conn.execute(
                    "SELECT bundle_id FROM evidence_bundles "
                    "WHERE bundle_id = ?",
                    (str(evidence_bundle_id),),
                ) as cur:
                    b = await cur.fetchone()
                if b is None:
                    await conn.execute("ROLLBACK")
                    raise GateEngineError(
                        "evidence_bundle_id does not reference a known "
                        "evidence_bundles row; cannot bind "
                        "x-relay/admin-terminate claim",
                        payload={
                            "evidence_bundle_id": str(evidence_bundle_id),
                        },
                    )

                # Update x_relay_payload with the resolved terminal_round
                # before digest computation so the digest binds the
                # canonical body.
                x_relay_payload["terminal_round"] = terminal_round
                claim_digest = sha256_wire(canonical_json_bytes(x_relay_payload))

                # 1. UPDATE gate_stalled_state.
                await conn.execute(
                    "UPDATE gate_stalled_state "
                    "SET terminated_at = ?, reason = ? "
                    "WHERE scope_type = ? AND scope_id = ?",
                    (
                        now,
                        STALLED_REASON_ADMIN_TERMINATED,
                        scope_type,
                        str(scope_id),
                    ),
                )

                # 2. INSERT admin_override_audit.
                audit_payload = {
                    "evidence_bundle_id": str(evidence_bundle_id),
                    "extension_id": extension_id,
                    "claim_digest": claim_digest,
                    "terminal_round": terminal_round,
                }
                # Audit-R3 (2026-05-18): the audit table's schema_version
                # column was dropped (sidecar migration 0023).
                # V3M1-F03 (2026-05-18): table renamed to
                # admin_override_audit (migration 0026).
                await conn.execute(
                    "INSERT INTO admin_override_audit ("
                    "  audit_id, project_id, scope_type, "
                    "  scope_id, gate_id, action, actor_kind, "
                    "  actor_identity_hash, actor_role, reason, "
                    "  prior_round_id, new_round_id, "
                    "  manifest_commit_hash, payload, occurred_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        audit_id,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        str(gate_id),
                        AUDIT_ACTION_TERMINATE,
                        actor.kind,
                        actor.identity_hash,
                        actor.role,
                        reason,
                        None,
                        None,
                        manifest_commit_hash,
                        json.dumps(
                            audit_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )

                # 3. INSERT event_log_entries.
                event_payload = {
                    "event": EVENT_ADMIN_TERMINATE,
                    "scope_id": str(scope_id),
                    "gate_id": str(gate_id),
                    "audit_id": audit_id,
                    "extension_id": extension_id,
                    "evidence_bundle_id": str(evidence_bundle_id),
                    "terminal_round": terminal_round,
                    "actor_role": actor.role,
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    seq_row = await cur.fetchone()
                next_seq = int(seq_row[0]) if seq_row is not None else 0
                await conn.execute(
                    "INSERT INTO event_log_entries ("
                    "  event_id, schema_version, project_id, scope_type, "
                    "  scope_id, event_type, actor_kind, actor_id, "
                    "  manifest_commit_hash, payload, occurred_at, "
                    "  ingest_sequence, event_kind"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id,
                        SCHEMA_EVENT_LOG,
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        EVENT_ADMIN_TERMINATE,
                        actor.kind,
                        actor.identity_hash,
                        manifest_commit_hash,
                        json.dumps(
                            event_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                        next_seq,
                        AUDIT_ACTION_TERMINATE,
                    ),
                )

                # 4. INSERT evidence_x_relay_extensions.
                effective_signature = (
                    signature
                    if signature
                    else f"unsigned-local-{extension_id}"
                )
                # Audit-R3 (2026-05-18): evidence_x_relay_extensions.
                # schema_version column was dropped (sidecar migration
                # 0023) because relay.evidence_x_relay_extension.v1 is
                # not a canonical envelope.
                await conn.execute(
                    "INSERT INTO evidence_x_relay_extensions ("
                    "  extension_id, evidence_bundle_id, "
                    "  extension_namespace, claim_digest, payload, "
                    "  manifest_commit_hash, signer_key_id, signature, "
                    "  created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        extension_id,
                        str(evidence_bundle_id),
                        X_RELAY_ADMIN_TERMINATE_NS,
                        claim_digest,
                        json.dumps(
                            x_relay_payload,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        manifest_commit_hash,
                        self.signing_key_id,
                        effective_signature,
                        now,
                    ),
                )

                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise

        return TerminateResult(
            audit_id=audit_id,
            event_id=event_id,
            extension_id=extension_id,
            claim_digest=claim_digest,
            terminated_at=now,
        )


# ---------------------------------------------------------------------------
# Convenience: audit-row fetch helper.
# ---------------------------------------------------------------------------


async def fetch_audit_entry(
    database: Any,
    *,
    audit_id: str,
) -> Mapping[str, Any] | None:
    """Return one ``admin_override_audit`` row by id, or ``None``.

    Returned mapping carries the column names as keys for ease of test
    assertions. Production callers should query directly with a typed
    DAL.
    """
    # Audit-R3 (2026-05-18): the audit table's schema_version column was
    # dropped by sidecar migration 0023 (not a canonical envelope).
    # V3M1-F03 (2026-05-18): table renamed to admin_override_audit
    # (migration 0026) to free the canonical §V hosted name.
    async with (
        _borrow_gate_writer(database) as conn,
        conn.execute(
            "SELECT audit_id, project_id, scope_type, "
            "       scope_id, gate_id, action, actor_kind, "
            "       actor_identity_hash, actor_role, reason, "
            "       prior_round_id, new_round_id, manifest_commit_hash, "
            "       payload, occurred_at "
            "FROM admin_override_audit WHERE audit_id = ?",
            (str(audit_id),),
        ) as cur,
    ):
        row = await cur.fetchone()
    if row is None:
        return None
    columns = (
        "audit_id",
        "project_id",
        "scope_type",
        "scope_id",
        "gate_id",
        "action",
        "actor_kind",
        "actor_identity_hash",
        "actor_role",
        "reason",
        "prior_round_id",
        "new_round_id",
        "manifest_commit_hash",
        "payload",
        "occurred_at",
    )
    return dict(zip(columns, row, strict=True))


__all__ = [
    "ADMIN_ROLES",
    "AUDIT_ACTION_REOPEN",
    "AUDIT_ACTION_TERMINATE",
    "EVENT_ADMIN_REOPEN",
    "EVENT_ADMIN_TERMINATE",
    "INITIATED_BY_ADMIN_OVERRIDE",
    "MAX_REASON_BYTES",
    "SCHEMA_AUDIT_LOG_ENTRY",
    "SCHEMA_GATE_ROUND",
    "SCHEMA_X_RELAY_EXTENSION",
    "X_RELAY_ADMIN_TERMINATE_NS",
    "AdminActionService",
    "AdminActor",
    "AdminReasonError",
    "ReopenResult",
    "StalledStateAlreadyTerminatedError",
    "StalledStateMissingError",
    "TerminateResult",
    "fetch_audit_entry",
]
