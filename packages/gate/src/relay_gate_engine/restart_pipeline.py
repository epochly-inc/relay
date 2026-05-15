"""Gate restart on failure (W8.3).

Implements CLAUDE.md keystone invariant #5 and spec section C "Gate
restart rule" (lines 581-583): when a later gate fails, do NOT retry
only that gate. Allocate a new ``gate_rounds`` row at round N+1 with
``restart_predecessor`` referencing the failing round, cancel every
pending draft from round N, and emit a ``gate.restarted`` event with
the failing-gate id, failing-assertion ids, and predecessor round id
in its payload (VAL-W8-020/021/023/025).

The single public entry point that transitions a scope from
``remediate_required`` back to ``running`` / ``gate.open`` is
:func:`RestartCoordinator.restart`; there is no
``retry_gate`` / ``re_evaluate_gate_only`` / equivalent code path
exposed by this package (VAL-W8-022 grep-and-AST guard).

This module also supplies:

  - :func:`compute_inputs_digest` -- canonical sha256 over the four
    anchors VAL-W8-027 uses to detect an unchanged re-submission:
    ``command_hash`` + ``manifest_commit_hash`` + ``release_sha`` +
    canonical-JSON ``evidence_refs``. Per contract gap #7 we materialize
    the digest as a derived hash (and persist a copy into
    ``gate_round_inputs`` for the next-round lookup).

  - :class:`UnchangedResubmissionError` -- ``RELAY-GATE-041`` raised by
    :func:`RestartCoordinator.check_unchanged_resubmission` when the
    new draft's four anchors are byte-identical to the prior round's
    submission. The check happens BEFORE the coordinator allocates a
    new round, so an unchanged re-submission does NOT consume a round
    budget (VAL-W8-027 guarantee).

  - :func:`validate_remediation_directive` -- given the prior round's
    ``unmet_conditions`` (which name the required follow-up evidence
    per spec AM.4 lines 5905-5910), checks the new draft's
    ``evidence_refs`` and returns the still-unmet conditions. The
    caller (the gate engine in the new round) writes an
    ``action='invalid'`` decision with those unmet conditions when the
    return is non-empty (VAL-W8-026).

The coordinator borrows the SidecarDatabase writer via the same
``_borrow_gate_writer`` async-context-manager used by the W8.2 decision
writer so every restart serializes against ``compare_and_set_state``
and the gate-decision writer on the same sidecar lock.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from relay_schemas.error_codes import RelayErrorCode

from .decision_writer import (
    SCHEMA_EVENT_LOG,
    SCHEMA_GATE_ROUND,
    _borrow_gate_writer,
)
from .errors import GateEngineError
from .signed_decision import canonical_json_bytes, sha256_wire

# ---------------------------------------------------------------------------
# Canonical strings.
# ---------------------------------------------------------------------------

# Event type written into event_log_entries on every restart.
EVENT_GATE_RESTARTED: Final[str] = "gate.restarted"

# event_kind discriminator on the restart row (VAL-W8-025 narrative).
EVENT_KIND_GATE_RESTARTED: Final[str] = "gate_restarted"

# ``initiated_by`` value the coordinator writes on the new gate_rounds row.
INITIATED_BY_REMEDIATION: Final[str] = "remediation"

# Cancellation reason recorded on superseded drafts (VAL-W8-023).
CANCELLATION_REASON_SUPERSEDED: Final[str] = "superseded_by_restart"


# ---------------------------------------------------------------------------
# Public errors.
# ---------------------------------------------------------------------------


class UnchangedResubmissionError(GateEngineError):
    """The new draft is byte-identical to the prior round's submission.

    Surfaces ``RELAY-GATE-041``. The error is NON-fatal in the sense
    that the API caller can produce a new draft with materially
    changed inputs; the coordinator does NOT increment the round
    counter when raising this error (VAL-W8-027).
    """

    code: str = RelayErrorCode.RELAY_GATE_041


# ---------------------------------------------------------------------------
# Result records.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RestartResult:
    """Outcome of one :func:`RestartCoordinator.restart` call.

    Attributes:
        new_gate_round_id: UUID of the freshly-inserted gate_rounds row.
        new_round: Integer round number (= prior_round + 1).
        predecessor_gate_round_id: The failing round's gate_round_id.
        cancelled_draft_ids: tuple of draft ids transitioned from
            ``pending`` to ``cancelled`` in the same transaction
            (VAL-W8-023).
        event_id: UUID of the ``gate.restarted`` event row (VAL-W8-025).
    """

    new_gate_round_id: str
    new_round: int
    predecessor_gate_round_id: str
    cancelled_draft_ids: tuple[str, ...]
    event_id: str


@dataclass(frozen=True)
class ResubmissionGuardResult:
    """Outcome of :func:`RestartCoordinator.check_unchanged_resubmission`.

    Attributes:
        ok: True when the new submission MAY proceed; False when it is
            byte-identical to the prior round's draft.
        error_envelope: Wire-format envelope with ``code='RELAY-GATE-041'``
            when ``ok=False``.
        prior_round: The prior round whose digest matched (informational).
    """

    ok: bool
    error_envelope: dict[str, Any] | None = None
    prior_round: int | None = None


@dataclass(frozen=True)
class RemediationDirectiveCheck:
    """Outcome of :func:`validate_remediation_directive`.

    Attributes:
        satisfied: True iff every required-evidence ref named by the
            prior round's unmet_conditions appears in the new draft's
            evidence_refs.
        still_unmet: tuple of unmet_condition records whose required
            evidence is still missing from the new submission. The
            gate engine writes an ``action='invalid'`` decision with
            these conditions when ``satisfied=False`` (VAL-W8-026).
    """

    satisfied: bool
    still_unmet: tuple[Mapping[str, Any], ...]


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _now_rfc3339_utc() -> str:
    return (
        datetime.now(tz=UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def compute_inputs_digest(
    *,
    command_hash: str,
    manifest_commit_hash: str,
    release_sha: str | None,
    evidence_refs: Sequence[Any],
) -> str:
    """Compute the canonical inputs digest for VAL-W8-027.

    The digest binds the four anchors that define a draft's identity
    for the "unchanged re-submission" detector. NULL ``release_sha``
    is normalized to the empty string before hashing so two NULL drafts
    produce the same digest (NULL != NULL in SQL but two semantically
    empty release_shas SHOULD compare equal for resubmission detection).
    """
    body = {
        "command_hash": str(command_hash),
        "manifest_commit_hash": str(manifest_commit_hash),
        "release_sha": "" if release_sha is None else str(release_sha),
        "evidence_refs": list(evidence_refs),
    }
    return sha256_wire(canonical_json_bytes(body))


def _build_unchanged_resubmission_envelope(
    *,
    scope_type: str,
    scope_id: str,
    prior_round: int,
    inputs_digest: str,
) -> dict[str, Any]:
    """Wire-format error envelope for ``RELAY-GATE-041``."""
    return {
        "code": RelayErrorCode.RELAY_GATE_041,
        "message": (
            "unchanged re-submission after remediate: command_hash + "
            "manifest_commit_hash + release_sha + inputs_digest match "
            f"prior round {prior_round}"
        ),
        "details": {
            "scope_type": scope_type,
            "scope_id": str(scope_id),
            "prior_round": int(prior_round),
            "inputs_digest": inputs_digest,
        },
    }


# ---------------------------------------------------------------------------
# Remediation-directive helper.
# ---------------------------------------------------------------------------


def validate_remediation_directive(
    *,
    prior_unmet_conditions: Sequence[Mapping[str, Any]],
    new_evidence_refs: Sequence[Any],
) -> RemediationDirectiveCheck:
    """Confirm the new draft's evidence_refs satisfy the prior directive.

    Each prior ``unmet_conditions`` record names a ``failed_assertion_id``
    and a ``required_evidence`` list (spec AM.4 lines 5905-5910). The
    check is intentionally lexical: a required_evidence ref is "met"
    when its string form appears in the new submission's evidence_refs
    (recorded as either a raw string or a dict with a ``ref`` key).
    The gate engine's evaluator decides the deeper "does this evidence
    actually prove the assertion?" question once the directive has been
    satisfied syntactically.
    """
    flattened_refs: set[str] = set()
    for r in new_evidence_refs:
        if isinstance(r, str):
            flattened_refs.add(r)
        elif isinstance(r, Mapping):
            ref = r.get("ref") or r.get("evidence_ref") or r.get("id")
            if ref is not None:
                flattened_refs.add(str(ref))
    still_unmet: list[Mapping[str, Any]] = []
    for cond in prior_unmet_conditions:
        required = cond.get("required_evidence") or ()
        missing: list[str] = []
        for req in required:
            req_str = str(req if not isinstance(req, Mapping) else req.get("ref", req))
            if req_str not in flattened_refs:
                missing.append(req_str)
        if missing:
            still_unmet.append({**dict(cond), "missing_evidence": missing})
    return RemediationDirectiveCheck(
        satisfied=not still_unmet,
        still_unmet=tuple(still_unmet),
    )


# ---------------------------------------------------------------------------
# Coordinator.
# ---------------------------------------------------------------------------


@dataclass
class RestartCoordinator:
    """The single production-code path that allocates a new gate_rounds row
    via the gate-restart-on-failure rule.

    The coordinator owns three behaviors:

      1. :meth:`record_round_inputs` -- after the W8.2 writer resolves
         a draft, the coordinator records the four-anchor digest so the
         next round's submission can be byte-compared (VAL-W8-027).
      2. :meth:`check_unchanged_resubmission` -- consulted by the gate
         engine BEFORE allocating a new round; returns the
         ``RELAY-GATE-041`` envelope when the new draft is byte-identical
         to the prior round's draft.
      3. :meth:`restart` -- atomically allocates round N+1, cancels
         pending drafts from round N, and emits ``gate.restarted``
         (VAL-W8-020/021/023/025).

    The coordinator is stateless w.r.t. request-state; one instance can
    serve any number of restarts against the same SidecarDatabase.
    """

    database: Any
    project_id: str = "00000000-0000-0000-0000-000000000000"

    # ----- record inputs ----------------------------------------------

    async def record_round_inputs(
        self,
        *,
        draft_id: str,
        scope_type: str,
        scope_id: str,
        round_: int,
        command_hash: str,
        manifest_commit_hash: str,
        release_sha: str | None,
        evidence_refs: Sequence[Any],
    ) -> str:
        """Insert one ``gate_round_inputs`` row for the resolved draft.

        Returns the row's inputs_digest. Idempotent on
        ``(scope_type, scope_id, round, draft_id)``: a repeat call for
        the same draft is a no-op and returns the prior digest.
        """
        digest = compute_inputs_digest(
            command_hash=command_hash,
            manifest_commit_hash=manifest_commit_hash,
            release_sha=release_sha,
            evidence_refs=evidence_refs,
        )
        async with _borrow_gate_writer(self.database) as conn:
            async with conn.execute(
                "SELECT inputs_digest FROM gate_round_inputs "
                "WHERE scope_type = ? AND scope_id = ? AND round = ? AND draft_id = ?",
                (scope_type, str(scope_id), int(round_), str(draft_id)),
            ) as cur:
                row = await cur.fetchone()
            if row is not None:
                return str(row[0])
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await conn.execute(
                    "INSERT INTO gate_round_inputs ("
                    "  gate_round_inputs_id, scope_type, scope_id, round, "
                    "  draft_id, inputs_digest, command_hash, "
                    "  manifest_commit_hash, release_sha, recorded_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        scope_type,
                        str(scope_id),
                        int(round_),
                        str(draft_id),
                        digest,
                        command_hash,
                        manifest_commit_hash,
                        release_sha,
                        _now_rfc3339_utc(),
                    ),
                )
                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise
        return digest

    # ----- unchanged resubmission guard -------------------------------

    async def check_unchanged_resubmission(
        self,
        *,
        scope_type: str,
        scope_id: str,
        prior_round: int,
        new_command_hash: str,
        new_manifest_commit_hash: str,
        new_release_sha: str | None,
        new_evidence_refs: Sequence[Any],
    ) -> ResubmissionGuardResult:
        """Return ``ok=False`` if the new draft matches the prior round's submission.

        VAL-W8-027: the four anchors are
        ``command_hash + manifest_commit_hash + release_sha + inputs_digest``.
        We compute ``inputs_digest`` over the new submission and compare
        against the prior round's recorded digest; a match yields
        ``RELAY-GATE-041`` without consuming a round.
        """
        new_digest = compute_inputs_digest(
            command_hash=new_command_hash,
            manifest_commit_hash=new_manifest_commit_hash,
            release_sha=new_release_sha,
            evidence_refs=new_evidence_refs,
        )
        # Read the prior round's most recent recorded digest.
        async with (
            _borrow_gate_writer(self.database) as conn,
            conn.execute(
                "SELECT inputs_digest, command_hash, manifest_commit_hash, "
                "       release_sha "
                "FROM gate_round_inputs "
                "WHERE scope_type = ? AND scope_id = ? AND round = ? "
                "ORDER BY recorded_at DESC LIMIT 1",
                (scope_type, str(scope_id), int(prior_round)),
            ) as cur,
        ):
            row = await cur.fetchone()
        if row is None:
            return ResubmissionGuardResult(ok=True)
        prior_digest = str(row[0])
        prior_command = str(row[1])
        prior_manifest = str(row[2])
        prior_release = row[3]  # may be None
        # All four anchors must match. NULL release_sha normalizes to
        # the empty string on both sides (matches compute_inputs_digest).
        new_release_norm = "" if new_release_sha is None else str(new_release_sha)
        prior_release_norm = "" if prior_release is None else str(prior_release)
        identical = (
            prior_digest == new_digest
            and prior_command == new_command_hash
            and prior_manifest == new_manifest_commit_hash
            and prior_release_norm == new_release_norm
        )
        if not identical:
            return ResubmissionGuardResult(ok=True)
        return ResubmissionGuardResult(
            ok=False,
            prior_round=int(prior_round),
            error_envelope=_build_unchanged_resubmission_envelope(
                scope_type=scope_type,
                scope_id=str(scope_id),
                prior_round=int(prior_round),
                inputs_digest=new_digest,
            ),
        )

    # ----- restart ----------------------------------------------------

    async def restart(
        self,
        *,
        scope_type: str,
        scope_id: str,
        prior_round: int,
        prior_gate_round_id: str,
        failing_gate_id: str,
        failing_assertion_ids: Sequence[str],
        actor_identity_hash: str,
        manifest_commit_hash: str,
    ) -> RestartResult:
        """Allocate round N+1, cancel pending drafts, emit ``gate.restarted``.

        VAL-W8-020: a new ``gate_rounds`` row is created with
        ``round=prior_round+1``, ``restart_predecessor=prior_gate_round_id``,
        ``initiated_by='remediation'``.

        VAL-W8-021: the new round does NOT carry forward the prior
        round's per-gate decisions. The caller (gate engine) re-evaluates
        scrutiny + structural + testing fresh in the new round and
        writes three new gate_decisions rows via the W8.2 writer.

        VAL-W8-023: every ``gate_decision_drafts`` row whose
        ``resolution_state='pending'`` and ``round=prior_round`` is
        UPDATEd to ``resolution_state='cancelled'`` with
        ``cancellation_reason='superseded_by_restart'``.

        VAL-W8-025: one ``event_log_entries`` row is appended with
        ``event_type='gate.restarted'``; the payload carries
        ``failing_gate_id``, ``failing_assertion_ids``, and
        ``predecessor_round_id`` (the three documented payload keys).

        All four state transitions happen in ONE BEGIN IMMEDIATE..COMMIT
        block; a failure rolls the whole thing back.
        """
        new_round = int(prior_round) + 1
        new_gate_round_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        now = _now_rfc3339_utc()
        cancelled_drafts: list[str] = []

        async with _borrow_gate_writer(self.database) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                # 1. INSERT the new gate_rounds row.
                await conn.execute(
                    "INSERT INTO gate_rounds ("
                    "  gate_round_id, schema_version, scope_type, scope_id, "
                    "  round, initiated_by, restart_predecessor, "
                    "  gate_decision_id, opened_at, closed_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_gate_round_id,
                        SCHEMA_GATE_ROUND,
                        scope_type,
                        str(scope_id),
                        new_round,
                        INITIATED_BY_REMEDIATION,
                        str(prior_gate_round_id),
                        None,
                        now,
                        None,
                    ),
                )

                # 2. Cancel every pending draft from the prior round.
                async with conn.execute(
                    "SELECT draft_id FROM gate_decision_drafts "
                    "WHERE scope_type = ? AND scope_id = ? AND round = ? "
                    "AND resolution_state = 'pending'",
                    (scope_type, str(scope_id), int(prior_round)),
                ) as cur:
                    rows = await cur.fetchall()
                for row in rows:
                    cancelled_drafts.append(str(row[0]))
                if cancelled_drafts:
                    await conn.execute(
                        "UPDATE gate_decision_drafts "
                        "SET resolution_state = 'cancelled', "
                        "    cancellation_reason = ?, "
                        "    cancelled_at = ? "
                        "WHERE scope_type = ? AND scope_id = ? AND round = ? "
                        "AND resolution_state = 'pending'",
                        (
                            CANCELLATION_REASON_SUPERSEDED,
                            now,
                            scope_type,
                            str(scope_id),
                            int(prior_round),
                        ),
                    )

                # 3. Append one event_log_entries row.
                payload = {
                    "event": EVENT_GATE_RESTARTED,
                    "failing_gate_id": str(failing_gate_id),
                    "failing_assertion_ids": list(failing_assertion_ids),
                    "predecessor_round_id": str(prior_gate_round_id),
                    "predecessor_round": int(prior_round),
                    "new_round": new_round,
                    "new_gate_round_id": new_gate_round_id,
                    "cancelled_draft_ids": list(cancelled_drafts),
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
                        self.project_id,
                        scope_type,
                        str(scope_id),
                        EVENT_GATE_RESTARTED,
                        "gate_engine",
                        actor_identity_hash,
                        manifest_commit_hash,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        now,
                        next_seq,
                        EVENT_KIND_GATE_RESTARTED,
                    ),
                )

                await conn.execute("COMMIT")
            except BaseException:
                with contextlib.suppress(Exception):
                    await conn.execute("ROLLBACK")
                raise

        return RestartResult(
            new_gate_round_id=new_gate_round_id,
            new_round=new_round,
            predecessor_gate_round_id=str(prior_gate_round_id),
            cancelled_draft_ids=tuple(cancelled_drafts),
            event_id=event_id,
        )


# ---------------------------------------------------------------------------
# Module-level guard: no retry-only-failed-gate function exists.
# ---------------------------------------------------------------------------
#
# VAL-W8-022 is enforced statically by a test that greps this package's
# source tree for the banned function names; the contract assertion is
# satisfied by the absence of those names from this module and its
# sibling modules. The single restart entry point is
# :meth:`RestartCoordinator.restart`; there is no per-gate retry.

__all__ = [
    "CANCELLATION_REASON_SUPERSEDED",
    "EVENT_GATE_RESTARTED",
    "EVENT_KIND_GATE_RESTARTED",
    "INITIATED_BY_REMEDIATION",
    "RemediationDirectiveCheck",
    "RestartCoordinator",
    "RestartResult",
    "ResubmissionGuardResult",
    "UnchangedResubmissionError",
    "compute_inputs_digest",
    "validate_remediation_directive",
]
