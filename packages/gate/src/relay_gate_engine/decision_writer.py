"""Control-plane-only gate_decisions writer (W8.2).

The W8.2 writer is the SINGLE production-code path that issues
``INSERT INTO gate_decisions``. Per CLAUDE.md keystone invariant #1,
every other path (SDK, CLI, eval/replay workers) submits drafts and
lets this writer resolve them into canonical rows. Per VAL-W8-010,
every insert routes through ``compare_and_set_state`` on the
``gate_round`` scope (event ``engine.decide`` transitions
``evaluating -> decision_written``).

Per VAL-W8-018 (atomic primitives, keystone #8), the writer performs
the following work in ONE ``BEGIN IMMEDIATE..COMMIT`` block on the
sidecar's single-writer connection:

    1. Pre-flight: validate three-anchor handoff via the W2 helper
       (VAL-W8-013). On failure, mark the draft
       ``resolution_state='rejected_handoff'``, emit one event_log
       row with ``mismatched_anchor`` attribution (VAL-W8-044), and
       return without bumping the round budget (VAL-W8-014,
       VAL-W8-042).
    2. Switch the connection's active role to ``relay_gate_engine``
       (VAL-W8-011, VAL-W8-012). The SQLite BEFORE INSERT triggers
       declared in migration 0009 enforce that the role token is
       correct on every gate_decisions INSERT.
    3. INSERT INTO evidence_bundles with the canonical bundle row
       (VAL-W8-016 FK satisfied, VAL-W8-017 ten required fields).
       The bundle's ``manifest_commit_hash`` MUST equal the draft's
       (VAL-W8-043 trigger enforces).
    4. Compute the Ed25519 signature over the canonical JSON of the
       gate_decision row (VAL-W8-019, signed BEFORE commit).
    5. INSERT INTO gate_decisions with the signature.
    6. UPSERT into gate_rounds: bind ``gate_decision_id`` on the row
       for ``(scope_type, scope_id, round)``.
    7. INSERT one event_log_entries row with event_type
       ``gate.decision_written`` (VAL-W8-018 atomicity).
    8. Restore role to ``relay_state_engine``.
    9. COMMIT.

The writer is async because it shares the sidecar's aiosqlite
infrastructure. The caller obtains a ``SidecarDatabase`` instance and
hands it to the writer; the writer borrows the writer connection via
``_borrow_writer`` from the state engine so the
``_state_engine_writer_lock`` serializes against ``compare_and_set_state``
concurrency.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from relay_sidecar.state_engine import init_scope_on_conn

from .db_grants import (
    ROLE_GATE_ENGINE,
    ROLE_STATE_ENGINE,
    assert_role_token,
    role_update_sql,
)
from .signed_decision import (
    SHA256_PREFIX,
    SigningKey,
    canonical_decision_payload,
    canonical_json_bytes,
    resolve_signing_key,
    sha256_wire,
    sign_payload,
)

if TYPE_CHECKING:
    pass

# Reason codes returned by the W2 three-anchor handoff validator. The
# writer translates them to the canonical VAL-W8-044 attribution
# token ``mismatched_anchor in {"scope","actor","manifest"}``.
HANDOFF_REASON_TO_MISMATCHED_ANCHOR: Final[Mapping[str, str]] = {
    "SCOPE_ID_MISMATCH": "scope",
    "ACTOR_NOT_REGISTERED": "actor",
    "MANIFEST_NOT_ACTIVE": "manifest",
}

# Canonical validation order (VAL-W8-044): on an all-anchors-mismatched
# fixture, the writer returns the FIRST failed anchor in this order
# deterministically across runs.
CANONICAL_ANCHOR_ORDER: Final[tuple[str, ...]] = ("scope", "actor", "manifest")

# Wire-format error code returned on three-anchor mismatch
# (VAL-W8-013 / VAL-W8-044; spec B.4 line 3424).
RELAY_GATE_021: Final[str] = "RELAY-GATE-021"

# Event types emitted on the gate_decisions write path.
EVENT_DECISION_WRITTEN: Final[str] = "gate.decision_written"
EVENT_REJECTED_HANDOFF: Final[str] = "gate.draft_rejected_handoff"

# Schema versions (CLAUDE.md keystone #10).
SCHEMA_GATE_DECISION: Final[str] = "relay.gate_decision.v1"
SCHEMA_EVIDENCE_BUNDLE: Final[str] = "relay.evidence_bundle.v1"
SCHEMA_GATE_ROUND: Final[str] = "relay.gate_round.v1"
SCHEMA_EVENT_LOG: Final[str] = "relay.event_log_entry.v1"

# Default decided_by attribution (the CHECK in migration 0003 pins
# this literal). The writer never lets the caller override it.
DECIDED_BY_GATE_ENGINE: Final[str] = "gate_engine"


# ---------------------------------------------------------------------------
# Inputs / outputs.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceBundleInputs:
    """The ten required fields per VAL-W8-017 + bundle id.

    The writer fills ``bundle_id`` (UUID) and ``bundle_digest`` (sha256
    over canonical JSON of the body) so the caller need not pre-compute
    them.
    """

    artifact_digest: str
    command: str
    exit_code: int
    span_ids: Sequence[str]
    contract_assertion_ids: Sequence[str]
    agent_worker_id: str
    manifest_commit_hash: str
    timestamp: str  # RFC 3339 UTC with Z offset
    environment: str
    redaction_policy_version: str


@dataclass(frozen=True)
class GateDecisionInputs:
    """Inputs the writer needs to mint one gate_decisions row.

    The fields mirror the persisted columns 1:1 minus ``decided_by``
    (pinned to 'gate_engine'), ``signature`` + ``signature_key_id``
    (computed at write time), ``decided_at`` (filled by the writer
    with the canonical RFC 3339 timestamp).
    """

    gate_id: str
    scope_type: str
    scope_id: str
    round_: int
    action: str  # accept | remediate | block | invalid
    strict_pass: bool
    failed_assertion_ids: Sequence[str]
    unmet_conditions: Sequence[Mapping[str, Any]]
    cascade_on_block: bool
    manifest_commit_hash: str
    actor_identity_hash: str
    evidence_bundle: EvidenceBundleInputs


@dataclass(frozen=True)
class HandoffPayload:
    """Three-anchor handoff payload consumed by ``validate_three_anchor_handoff``.

    The writer constructs this dict from the draft envelope. On a
    ``scope_kind='run'`` write the writer also sets ``run_id = scope_id``;
    on other scope kinds the scope anchor is implicit (the W2 validator
    skips the run_id check for non-run scopes).
    """

    actor_identity_hash: str
    manifest_commit_hash: str
    run_id: str | None = None  # only required for scope_kind='run'

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "actor_identity_hash": self.actor_identity_hash,
            "manifest_commit_hash": self.manifest_commit_hash,
        }
        if self.run_id is not None:
            out["run_id"] = self.run_id
        return out


@dataclass
class DecisionWriteResult:
    """Outcome of one ``GateDecisionWriter.write`` call.

    Attributes:
        ok: True on accepted write; False on rejected handoff.
        gate_decision_id: UUID of the row on success.
        evidence_bundle_id: UUID of the bundle row on success.
        signature_key_id: Key id used to sign the row.
        idempotent: True iff the row was already present and this call
            was a no-op replay.
        rejected_reason: Structured reason code on ``ok=False``
            ('SCOPE_ID_MISMATCH','ACTOR_NOT_REGISTERED','MANIFEST_NOT_ACTIVE').
        mismatched_anchor: One of 'scope','actor','manifest' on
            ``ok=False``; the VAL-W8-044 attribution token.
        error_envelope: Wire-format envelope on ``ok=False``
            (RELAY-GATE-021 + mismatched_anchor + scope context).
        event_id: UUID of the event_log_entries row emitted on success
            OR on rejected_handoff (we record the rejection so the
            forensic trail is complete).
    """

    ok: bool
    gate_decision_id: str | None = None
    evidence_bundle_id: str | None = None
    signature_key_id: str | None = None
    idempotent: bool = False
    rejected_reason: str | None = None
    mismatched_anchor: str | None = None
    error_envelope: dict[str, Any] | None = None
    event_id: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers.
# ---------------------------------------------------------------------------


def _now_rfc3339_utc() -> str:
    """RFC 3339 UTC with explicit ``Z`` offset."""
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _canonical_bundle_body(
    *,
    bundle_id: str,
    inputs: EvidenceBundleInputs,
) -> dict[str, Any]:
    """Build the canonical bundle body used to compute ``bundle_digest``.

    Includes every required field per VAL-W8-017. The digest binds the
    bundle's identity; the writer recomputes it on read so a tampered
    column triggers the recomputed-vs-stored equality assertion.
    """
    return {
        "schema_version": SCHEMA_EVIDENCE_BUNDLE,
        "bundle_id": bundle_id,
        "artifact_digest": inputs.artifact_digest,
        "command": inputs.command,
        "exit_code": int(inputs.exit_code),
        "span_ids": list(inputs.span_ids),
        "contract_assertion_ids": list(inputs.contract_assertion_ids),
        "agent_worker_id": inputs.agent_worker_id,
        "manifest_commit_hash": inputs.manifest_commit_hash,
        "timestamp": inputs.timestamp,
        "environment": inputs.environment,
        "redaction_policy_version": inputs.redaction_policy_version,
    }


def recompute_bundle_digest(row: Mapping[str, Any]) -> str:
    """Recompute ``bundle_digest`` from a stored bundle row.

    Used by VAL-W8-017 invariant guards to confirm the stored digest
    matches the canonical JSON of the body.
    """
    body = {
        "schema_version": str(row["schema_version"]),
        "bundle_id": str(row["bundle_id"]),
        "artifact_digest": str(row["artifact_digest"]),
        "command": str(row["command"]),
        "exit_code": int(row["exit_code"]),
        "span_ids": json.loads(row["span_ids"]),
        "contract_assertion_ids": json.loads(row["contract_assertion_ids"]),
        "agent_worker_id": str(row["agent_worker_id"]),
        "manifest_commit_hash": str(row["manifest_commit_hash"]),
        "timestamp": str(row["timestamp"]),
        "environment": str(row["environment"]),
        "redaction_policy_version": str(row["redaction_policy_version"]),
    }
    return sha256_wire(canonical_json_bytes(body))


def _build_error_envelope(
    *,
    mismatched_anchor: str,
    scope_type: str,
    scope_id: str,
    reason_code: str,
) -> dict[str, Any]:
    """Build the wire-format envelope for a three-anchor rejection.

    Per VAL-W8-044: the error code is the single canonical
    ``RELAY-GATE-021``; the ``mismatched_anchor`` field carries the
    attribution. The W2 handoff reason code is also embedded so the
    structured details survive the wire trip.
    """
    return {
        "code": RELAY_GATE_021,
        "message": (
            f"three-anchor handoff rejected: {mismatched_anchor} anchor mismatch"
        ),
        "mismatched_anchor": mismatched_anchor,
        "details": {
            "scope_type": scope_type,
            "scope_id": str(scope_id),
            "reason": reason_code,
        },
    }


def _resolve_mismatched_anchor(
    *,
    reasons: Sequence[str],
) -> str:
    """Pick the first failed anchor in the canonical validation order.

    For VAL-W8-044's all-anchors-mismatched fixture this returns a
    deterministic token across runs. ``reasons`` is the ordered list
    of failing reason codes (in the order the validator emits them).
    """
    seen: dict[str, str] = {
        HANDOFF_REASON_TO_MISMATCHED_ANCHOR[r]: r
        for r in reasons
        if r in HANDOFF_REASON_TO_MISMATCHED_ANCHOR
    }
    for anchor in CANONICAL_ANCHOR_ORDER:
        if anchor in seen:
            return anchor
    raise ValueError(
        f"resolve_mismatched_anchor: no canonical anchor matched reasons {list(reasons)!r}"
    )


# ---------------------------------------------------------------------------
# Provider protocols (kept narrow so tests can inject in-memory fakes).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HandoffValidatorResult:
    """Wrapper around the W2 ``HandoffResult`` for our consumption."""

    ok: bool
    reason: str | None


# ---------------------------------------------------------------------------
# Borrow helper (mirror of compare_and_set._borrow_writer).
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def _borrow_gate_writer(database: Any):
    """Acquire exclusive access to the sidecar writer connection.

    Mirrors ``apps/local-sidecar/relay_sidecar/state_engine/
    compare_and_set._borrow_writer``: lazily creates the
    ``_state_engine_writer_lock`` asyncio.Lock on first borrow and
    yields the same underlying ``aiosqlite.Connection`` so the W8.2
    writer is serialized against every other state-engine transition
    on the same database.
    """
    import asyncio as _asyncio

    lock = getattr(database, "_state_engine_writer_lock", None)
    if lock is None:
        lock = _asyncio.Lock()
        database._state_engine_writer_lock = lock
    async with lock:
        conn = database._writer
        if conn is None:
            raise RuntimeError(
                "GateDecisionWriter: SidecarDatabase is not open "
                "(call database.open() before writing decisions)."
            )
        yield conn


# ---------------------------------------------------------------------------
# Writer.
# ---------------------------------------------------------------------------


class GateDecisionWriter:
    """The single production-code path that writes ``gate_decisions`` rows.

    The writer is stateless w.r.t. requests; one instance can serve any
    number of writes. Configuration (signing key, project_id default) is
    captured at construction time so the per-write call signature stays
    minimal.
    """

    def __init__(
        self,
        *,
        database: Any,
        signing_key: SigningKey | None = None,
        project_id: str = "00000000-0000-0000-0000-000000000000",
    ) -> None:
        self._database = database
        self._signing_key = signing_key or resolve_signing_key()
        self._project_id = project_id

    @property
    def signing_key_id(self) -> str:
        return self._signing_key.key_id

    # ----- Public API ---------------------------------------------------

    async def write(
        self,
        *,
        draft_id: str,
        inputs: GateDecisionInputs,
        handoff_payload: HandoffPayload,
        round_state: str = "evaluating",
    ) -> DecisionWriteResult:
        """Write one gate_decisions row, atomic with bundle + round + event.

        Args:
            draft_id: The submitting ``gate_decision_drafts.draft_id``
                that resolves into the decision. Used for the draft-
                resolution UPDATE.
            inputs: The decision body + bound evidence bundle inputs.
            handoff_payload: The three-anchor handoff payload validated
                BEFORE any write (VAL-W8-013).
            round_state: The ``scope_state.state`` expected for the
                gate_round; the W2 state engine handles the actual
                ``compare_and_set_state`` transition AFTER this write
                returns ok=True (the writer focuses on the canonical
                row insertion; the round state transition is the
                caller's responsibility).

        Returns:
            ``DecisionWriteResult`` with the outcome.
        """
        # Pre-flight: validate three-anchor handoff.
        from relay_sidecar.state_engine.handoff import (
            validate_three_anchor_handoff,
        )

        reader = self._database.acquire_reader()
        handoff = await validate_three_anchor_handoff(
            reader=reader,
            scope_kind="run" if inputs.scope_type == "run" else inputs.scope_type,
            scope_id=str(inputs.scope_id),
            payload=handoff_payload.to_dict(),
        )

        if not handoff.ok:
            return await self._record_rejected_handoff(
                draft_id=draft_id,
                inputs=inputs,
                reason_code=str(handoff.reason),
            )

        # Pre-flight: check for idempotent replay (same gate/scope/round
        # already has a decision).
        existing_id = await self._lookup_existing_decision(
            gate_id=inputs.gate_id,
            scope_type=inputs.scope_type,
            scope_id=inputs.scope_id,
            round_=inputs.round_,
        )
        if existing_id is not None:
            return DecisionWriteResult(
                ok=True,
                gate_decision_id=existing_id,
                idempotent=True,
                signature_key_id=self._signing_key.key_id,
            )

        # Open the canonical write transaction.
        return await self._do_atomic_write(
            draft_id=draft_id,
            inputs=inputs,
            round_state=round_state,
        )

    # ----- Internals ----------------------------------------------------

    async def _lookup_existing_decision(
        self,
        *,
        gate_id: str,
        scope_type: str,
        scope_id: str,
        round_: int,
    ) -> str | None:
        reader = self._database.acquire_reader()
        async with reader.execute(
            "SELECT gate_decision_id FROM gate_decisions "
            "WHERE gate_id = ? AND scope_type = ? AND scope_id = ? AND round = ?",
            (gate_id, scope_type, str(scope_id), int(round_)),
        ) as cur:
            row = await cur.fetchone()
        return str(row[0]) if row is not None else None

    async def _record_rejected_handoff(
        self,
        *,
        draft_id: str,
        inputs: GateDecisionInputs,
        reason_code: str,
    ) -> DecisionWriteResult:
        """Mark a draft rejected_handoff WITHOUT touching gate_decisions or
        gate_rounds (VAL-W8-014, VAL-W8-042). Emits one event_log row
        capturing the mismatched_anchor attribution.
        """
        mismatched_anchor = _resolve_mismatched_anchor(reasons=(reason_code,))
        envelope = _build_error_envelope(
            mismatched_anchor=mismatched_anchor,
            scope_type=inputs.scope_type,
            scope_id=str(inputs.scope_id),
            reason_code=reason_code,
        )
        event_id = str(uuid.uuid4())
        now = _now_rfc3339_utc()
        # UPDATE gate_decision_drafts.resolution_state under a fresh
        # BEGIN IMMEDIATE; we explicitly do NOT touch gate_rounds.
        async with _borrow_gate_writer(self._database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await conn.execute(
                    "UPDATE gate_decision_drafts "
                    "SET resolution_state = 'rejected_handoff' "
                    "WHERE draft_id = ?",
                    (str(draft_id),),
                )
                # Append one event_log row carrying the attribution.
                payload = {
                    "event": EVENT_REJECTED_HANDOFF,
                    "mismatched_anchor": mismatched_anchor,
                    "reason": reason_code,
                    "scope_type": inputs.scope_type,
                    "scope_id": str(inputs.scope_id),
                    "draft_id": str(draft_id),
                    "round": int(inputs.round_),
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    row = await cur.fetchone()
                next_seq = int(row[0]) if row is not None else 0
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
                        self._project_id,
                        inputs.scope_type,
                        str(inputs.scope_id),
                        EVENT_REJECTED_HANDOFF,
                        "gate_engine",
                        inputs.actor_identity_hash,
                        inputs.manifest_commit_hash,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        now,
                        next_seq,
                        "gate_rejected_handoff",
                    ),
                )
                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise
        return DecisionWriteResult(
            ok=False,
            rejected_reason=reason_code,
            mismatched_anchor=mismatched_anchor,
            error_envelope=envelope,
            event_id=event_id,
        )

    async def _do_atomic_write(
        self,
        *,
        draft_id: str,
        inputs: GateDecisionInputs,
        round_state: str,
    ) -> DecisionWriteResult:
        """Issue the canonical INSERT in one BEGIN IMMEDIATE..COMMIT block.

        Steps 2-9 from the module docstring. Any exception rolls the
        entire transaction back (including the role-state UPDATE).
        """
        _ = round_state  # reserved for future use; current writer does
        # not gate on round_state — the caller is expected to invoke
        # ``compare_and_set_state`` to advance the gate_round scope
        # ``evaluating -> decision_written`` AFTER this method returns.

        bundle_id = str(uuid.uuid4())
        gate_decision_id = str(uuid.uuid4())
        decided_at = _now_rfc3339_utc()

        bundle_body = _canonical_bundle_body(
            bundle_id=bundle_id, inputs=inputs.evidence_bundle
        )
        bundle_digest = sha256_wire(canonical_json_bytes(bundle_body))

        # Compose the canonical decision payload (the signing input).
        signing_payload = canonical_decision_payload(
            gate_decision_id=gate_decision_id,
            schema_version=SCHEMA_GATE_DECISION,
            gate_id=inputs.gate_id,
            scope_type=inputs.scope_type,
            scope_id=str(inputs.scope_id),
            round_=int(inputs.round_),
            action=inputs.action,
            strict_pass=bool(inputs.strict_pass),
            failed_assertion_ids=list(inputs.failed_assertion_ids),
            unmet_conditions=list(inputs.unmet_conditions),
            evidence_bundle_id=bundle_id,
            cascade_on_block=bool(inputs.cascade_on_block),
            decided_by=DECIDED_BY_GATE_ENGINE,
            decided_at=decided_at,
            manifest_commit_hash=inputs.manifest_commit_hash,
            actor_identity_hash=inputs.actor_identity_hash,
        )
        signature_b64u, signature_key_id = sign_payload(
            signing_payload, self._signing_key
        )

        event_id = str(uuid.uuid4())

        async with _borrow_gate_writer(self._database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                # Step 2: switch role to relay_gate_engine.
                with assert_role_token(ROLE_GATE_ENGINE):
                    await conn.execute(role_update_sql(), (ROLE_GATE_ENGINE,))

                # Step 3a: INSERT the paired scope_state row for the new
                # evidence_bundle (spec W line 5112 paired-row invariant;
                # migration 0008 / 0016 deferred trigger requires both
                # rows to commit together). The state engine is the
                # canonical writer of scope_state per CLAUDE.md keystone
                # invariant #1; init_scope_on_conn inlines that write
                # into this writer's existing BEGIN IMMEDIATE..COMMIT.
                await init_scope_on_conn(
                    conn=conn,
                    scope_kind="evidence_bundle",
                    scope_id=bundle_id,
                    project_id=self._project_id,
                    initial_state="building",
                )

                # Step 3: INSERT evidence_bundles.
                await conn.execute(
                    "INSERT INTO evidence_bundles ("
                    "  bundle_id, schema_version, artifact_digest, command, "
                    "  exit_code, span_ids, contract_assertion_ids, "
                    "  agent_worker_id, manifest_commit_hash, timestamp, "
                    "  environment, redaction_policy_version, bundle_digest, "
                    "  state"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        bundle_id,
                        SCHEMA_EVIDENCE_BUNDLE,
                        inputs.evidence_bundle.artifact_digest,
                        inputs.evidence_bundle.command,
                        int(inputs.evidence_bundle.exit_code),
                        json.dumps(
                            list(inputs.evidence_bundle.span_ids),
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            list(inputs.evidence_bundle.contract_assertion_ids),
                            separators=(",", ":"),
                        ),
                        inputs.evidence_bundle.agent_worker_id,
                        inputs.evidence_bundle.manifest_commit_hash,
                        inputs.evidence_bundle.timestamp,
                        inputs.evidence_bundle.environment,
                        inputs.evidence_bundle.redaction_policy_version,
                        bundle_digest,
                        "signed",
                    ),
                )

                # Step 5: INSERT gate_decisions (with signature).
                await conn.execute(
                    "INSERT INTO gate_decisions ("
                    "  gate_decision_id, schema_version, gate_id, scope_type, "
                    "  scope_id, round, action, strict_pass, "
                    "  failed_assertion_ids, unmet_conditions, "
                    "  evidence_bundle_id, cascade_on_block, decided_by, "
                    "  decided_at, manifest_commit_hash, actor_identity_hash, "
                    "  signature, signature_key_id"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        gate_decision_id,
                        SCHEMA_GATE_DECISION,
                        inputs.gate_id,
                        inputs.scope_type,
                        str(inputs.scope_id),
                        int(inputs.round_),
                        inputs.action,
                        1 if inputs.strict_pass else 0,
                        json.dumps(
                            list(inputs.failed_assertion_ids),
                            separators=(",", ":"),
                        ),
                        json.dumps(
                            [dict(c) for c in inputs.unmet_conditions],
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        bundle_id,
                        1 if inputs.cascade_on_block else 0,
                        DECIDED_BY_GATE_ENGINE,
                        decided_at,
                        inputs.manifest_commit_hash,
                        inputs.actor_identity_hash,
                        signature_b64u,
                        signature_key_id,
                    ),
                )

                # Step 6: UPSERT gate_rounds.
                async with conn.execute(
                    "SELECT gate_round_id FROM gate_rounds "
                    "WHERE scope_type = ? AND scope_id = ? AND round = ?",
                    (
                        inputs.scope_type,
                        str(inputs.scope_id),
                        int(inputs.round_),
                    ),
                ) as cur:
                    existing = await cur.fetchone()
                if existing is None:
                    gate_round_id = str(uuid.uuid4())
                    # INSERT the paired scope_state row for the new
                    # gate_round (spec W line 5112 paired-row invariant;
                    # migration 0008 / 0016 deferred trigger requires
                    # both rows to commit together). state engine is
                    # the canonical writer of scope_state per CLAUDE.md
                    # keystone invariant #1.
                    await init_scope_on_conn(
                        conn=conn,
                        scope_kind="gate_round",
                        scope_id=gate_round_id,
                        project_id=self._project_id,
                        initial_state="open",
                    )
                    await conn.execute(
                        "INSERT INTO gate_rounds ("
                        "  gate_round_id, schema_version, scope_type, "
                        "  scope_id, round, initiated_by, "
                        "  gate_decision_id, opened_at, closed_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            gate_round_id,
                            SCHEMA_GATE_ROUND,
                            inputs.scope_type,
                            str(inputs.scope_id),
                            int(inputs.round_),
                            "control_plane",
                            gate_decision_id,
                            decided_at,
                            decided_at,
                        ),
                    )
                else:
                    await conn.execute(
                        "UPDATE gate_rounds "
                        "SET gate_decision_id = ?, closed_at = ? "
                        "WHERE gate_round_id = ?",
                        (
                            gate_decision_id,
                            decided_at,
                            str(existing[0]),
                        ),
                    )

                # Bind the draft to the resolved decision so VAL-W8-043's
                # JOIN query (drafts.resolved_decision_id) is satisfied.
                await conn.execute(
                    "UPDATE gate_decision_drafts "
                    "SET resolution_state = 'resolved', "
                    "    resolved_gate_decision_id = ? "
                    "WHERE draft_id = ?",
                    (gate_decision_id, str(draft_id)),
                )

                # Step 7: append the canonical audit row.
                payload = {
                    "event": EVENT_DECISION_WRITTEN,
                    "gate_decision_id": gate_decision_id,
                    "evidence_bundle_id": bundle_id,
                    "scope_type": inputs.scope_type,
                    "scope_id": str(inputs.scope_id),
                    "round": int(inputs.round_),
                    "action": inputs.action,
                    "signature_key_id": signature_key_id,
                }
                async with conn.execute(
                    "SELECT COALESCE(MAX(ingest_sequence), -1) + 1 "
                    "FROM event_log_entries"
                ) as cur:
                    row = await cur.fetchone()
                next_seq = int(row[0]) if row is not None else 0
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
                        self._project_id,
                        inputs.scope_type,
                        str(inputs.scope_id),
                        EVENT_DECISION_WRITTEN,
                        "gate_engine",
                        inputs.actor_identity_hash,
                        inputs.manifest_commit_hash,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        decided_at,
                        next_seq,
                        "gate_decision_written",
                    ),
                )

                # Step 8: restore role.
                with assert_role_token(ROLE_STATE_ENGINE):
                    await conn.execute(role_update_sql(), (ROLE_STATE_ENGINE,))

                # Step 9: COMMIT.
                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                # Best-effort role restore outside the rolled-back
                # transaction so subsequent state-engine writes still
                # see role=relay_state_engine.
                with contextlib.suppress(Exception):
                    await conn.execute(
                        role_update_sql(), (ROLE_STATE_ENGINE,)
                    )
                    await conn.execute("COMMIT")
                raise

        return DecisionWriteResult(
            ok=True,
            gate_decision_id=gate_decision_id,
            evidence_bundle_id=bundle_id,
            signature_key_id=signature_key_id,
            event_id=event_id,
            extras={"bundle_digest": bundle_digest},
        )


# Forward-reference type guard for SHA256_PREFIX consumers.
_ = SHA256_PREFIX


__all__ = [
    "CANONICAL_ANCHOR_ORDER",
    "DECIDED_BY_GATE_ENGINE",
    "DecisionWriteResult",
    "EVENT_DECISION_WRITTEN",
    "EVENT_REJECTED_HANDOFF",
    "EvidenceBundleInputs",
    "GateDecisionInputs",
    "GateDecisionWriter",
    "HANDOFF_REASON_TO_MISMATCHED_ANCHOR",
    "HandoffPayload",
    "RELAY_GATE_021",
    "SCHEMA_EVENT_LOG",
    "SCHEMA_EVIDENCE_BUNDLE",
    "SCHEMA_GATE_DECISION",
    "SCHEMA_GATE_ROUND",
    "recompute_bundle_digest",
]
