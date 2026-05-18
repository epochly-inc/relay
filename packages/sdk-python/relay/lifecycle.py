"""Lifecycle envelope builders for the Relay Python SDK (W3.2).

This module owns the wire-format ingest envelopes the SDK submits to the
local sidecar control plane. Per CLAUDE.md keystone invariant #1 and spec
A.1, the SDK NEVER writes canonical-result fields -- they are written
exclusively by the control plane.

Three envelope builders live here:

  * :func:`build_ingest_run_envelope` -- the
    ``POST /v1/ingest/runs`` body (spec lines 1932-1958). Carries
    lifecycle metadata only; rejects every canonical-write field at the
    SDK boundary BEFORE any HTTP I/O (VAL-W3-009, VAL-W3-010).
  * :func:`build_gate_draft_envelope` -- the
    ``POST /v1/gates/{gate_id}/drafts`` body (spec lines 2195-2252). The
    SDK submits evidence drafts; the gate engine writes the canonical
    ``GateDecision`` row (VAL-W3-013).
  * :func:`build_evidence_envelope` -- the evidence submit body. Binds
    artifact digest + command + exit code + span IDs +
    ``manifest_commit_hash`` per spec K and CLAUDE.md invariant #2; a
    missing field is rejected at the SDK boundary (VAL-W3-015).

The module is import-side-effect-free: pure-Python construction only, no
network/file/sidecar contact.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

from . import _ulid

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

# Closed enum for the SDK-observed lifecycle. Spec lines 1789, 1941 + sql
# CHECK constraint at spec line 1790. VAL-W3-012: any value outside this
# set is rejected at the SDK boundary BEFORE the request is sent.
LIFECYCLE_STATUSES: Final[frozenset[str]] = frozenset(
    {"started", "client_succeeded", "client_failed", "client_aborted"}
)

# Canonical-result fields the SDK MUST NEVER set. The sidecar rejects an
# envelope carrying any of these with HTTP 422 + RELAY-ING-031 (spec line
# 1966; VAL-W3-010). The SDK checks BEFORE issuing the request so a
# programmer error never crosses the wire.
CANONICAL_WRITE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "status",
        "primary_failure_class",
        "written_by",
        "accepted_at",
        "finalized_at",
    }
)

# The three-anchor handoff required by spec C.5 + CLAUDE.md invariant #4.
# Every lifecycle envelope MUST carry all three. A missing/empty anchor
# yields RELAY-GATE-021 (or scope-equivalent RELAY-ING-022) per VAL-W3-011.
HANDOFF_ANCHORS: Final[tuple[str, str, str]] = (
    "scope_id",  # run_id for run-scoped ingest
    "actor_identity_hash",
    "manifest_commit_hash",
)

# Wire schema_version literal for the run-ingest envelope (spec line 1936).
INGEST_RUN_SCHEMA_VERSION: Final[str] = "relay.ingest.run.v1"

# Wire schema_version literal for the gate-decision-draft envelope (spec
# line 217 envelopes.yaml + spec A.3).
GATE_DRAFT_SCHEMA_VERSION: Final[str] = "relay.gate_decision_draft.v1"

# Wire schema_version literal for the evidence-bundle submit envelope
# (spec line K + envelopes.yaml).
EVIDENCE_SUBMIT_SCHEMA_VERSION: Final[str] = "relay.evidence_submit.v1"

# Required evidence-binding fields per CLAUDE.md invariant #2 + spec K.
# A missing field raises RelayEvidenceIncomplete at the SDK boundary.
EVIDENCE_REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "artifact_digest_sha256",
    "command_id",
    "exit_code",
    "span_ids",
    "assertion_ids",
    "actor_identity_hash",
    "manifest_commit_hash",
    "redaction_policy_version",
)


# ---------------------------------------------------------------------------
# Validation helpers (raise typed errors from .errors)
# ---------------------------------------------------------------------------


def _require_non_empty_str(name: str, value: Any) -> str:
    """Return ``value`` if a non-empty string; else raise RelayConfigError."""
    from .errors import RelayConfigError

    if not isinstance(value, str) or not value:
        raise RelayConfigError(
            f"{name} must be a non-empty string",
            details={"field": name, "received_type": type(value).__name__},
        )
    return value


def _validate_lifecycle_status(status: Any) -> str:
    """VAL-W3-012: reject any client_lifecycle_status outside the enum.

    Raised at the SDK boundary BEFORE any HTTP request is issued, so the
    invalid value never reaches the sidecar.
    """
    from .errors import RelayLifecycleInvalid

    if not isinstance(status, str) or status not in LIFECYCLE_STATUSES:
        raise RelayLifecycleInvalid(
            f"client_lifecycle_status must be one of "
            f"{sorted(LIFECYCLE_STATUSES)!r}; received {status!r}",
            details={
                "field": "client_lifecycle_status",
                "received": status,
                "allowed": sorted(LIFECYCLE_STATUSES),
            },
        )
    return status


def _reject_canonical_write_fields(extras: dict[str, Any]) -> None:
    """VAL-W3-010: refuse any envelope carrying a canonical-write field.

    Raised at the SDK boundary so a programmer error never crosses the
    wire. The sidecar's HTTP 422 + RELAY-ING-031 path is the
    defense-in-depth layer; this SDK-side check is the primary gate.
    """
    from .errors import RelayCanonicalStatusForbidden

    forbidden = sorted(set(extras).intersection(CANONICAL_WRITE_FIELDS))
    if forbidden:
        raise RelayCanonicalStatusForbidden(
            "ingest envelope must not carry canonical-result fields; "
            f"the control plane is the sole writer (offending: {forbidden!r})",
            details={
                "forbidden_fields": forbidden,
                "all_canonical_fields": sorted(CANONICAL_WRITE_FIELDS),
            },
        )


def _validate_three_anchor_handoff(
    *,
    scope_id: Any,
    actor_identity_hash: Any,
    manifest_commit_hash: Any,
) -> tuple[str, str, str]:
    """VAL-W3-011: every envelope MUST carry all three handoff anchors.

    A missing or empty anchor raises RelayHandoffIncomplete; the
    ``details.mismatched_anchor`` field names the offending anchor(s) so
    callers (and tests) can attribute the failure precisely.
    """
    from .errors import RelayHandoffIncomplete

    missing: list[str] = []
    if not isinstance(scope_id, str) or not scope_id:
        missing.append("scope_id")
    if not isinstance(actor_identity_hash, str) or not actor_identity_hash:
        missing.append("actor_identity_hash")
    if not isinstance(manifest_commit_hash, str) or not manifest_commit_hash:
        missing.append("manifest_commit_hash")
    if missing:
        raise RelayHandoffIncomplete(
            "three-anchor handoff incomplete; "
            f"missing anchors: {missing!r}",
            details={"mismatched_anchor": missing},
        )
    return scope_id, actor_identity_hash, manifest_commit_hash


# ---------------------------------------------------------------------------
# Envelope builders
# ---------------------------------------------------------------------------


def build_ingest_run_envelope(
    *,
    run_id: str,
    trace_id: str,
    project_id: str,
    agent: dict[str, Any],
    client_lifecycle_status: str,
    started_at: str,
    sdk_version: str,
    sdk_clock: str,
    manifest_commit_hash: str,
    actor_identity_hash: str,
    redaction_policy_version: str,
    sequence_number: int,
    metadata: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a wire-format ``POST /v1/ingest/runs`` envelope.

    Spec lines 1932-1958. Carries lifecycle metadata ONLY -- no canonical
    result field may be set. The SDK rejects any caller-supplied
    canonical-write field BEFORE the request is sent.

    Per VAL-W3-009: a ``rg`` over this module for the literals
    ``"status"``, ``"primary_failure_class"``, and ``"written_by"`` as
    keys in outbound bodies returns zero matches. The only references
    are in :data:`CANONICAL_WRITE_FIELDS` (the denylist itself) and in
    ``error_class`` / ``details`` payloads on the SDK error type.

    Per VAL-W3-017: an ``idempotency_key`` is generated via
    :func:`relay._ulid.new_ulid` when the caller does not pre-supply
    one. Two adjacent calls produce distinct keys.
    """
    # 1) Three-anchor handoff first; a stale handoff is the most common
    #    failure shape, and we want it surfaced before any other check
    #    that touches the same fields.
    scope_id, actor, manifest = _validate_three_anchor_handoff(
        scope_id=run_id,
        actor_identity_hash=actor_identity_hash,
        manifest_commit_hash=manifest_commit_hash,
    )

    # 2) Lifecycle-status enum.
    status = _validate_lifecycle_status(client_lifecycle_status)

    # 3) Trivial non-empty-string fields.
    trace_id = _require_non_empty_str("trace_id", trace_id)
    project_id = _require_non_empty_str("project_id", project_id)
    started_at = _require_non_empty_str("started_at", started_at)
    sdk_version = _require_non_empty_str("sdk_version", sdk_version)
    sdk_clock = _require_non_empty_str("sdk_clock", sdk_clock)
    redaction_policy_version = _require_non_empty_str(
        "redaction_policy_version", redaction_policy_version
    )

    if not isinstance(agent, dict) or not agent:
        from .errors import RelayConfigError

        raise RelayConfigError(
            "agent must be a non-empty dict",
            details={"field": "agent", "received_type": type(agent).__name__},
        )
    if not isinstance(sequence_number, int) or sequence_number < 0:
        from .errors import RelayConfigError

        raise RelayConfigError(
            "sequence_number must be a non-negative int",
            details={"field": "sequence_number", "received": sequence_number},
        )

    # 4) Refuse any escape-hatch attempt to set canonical-write fields.
    #    Caller can supply ``extras`` -- a free-form bag for forward-
    #    compatibility -- but we screen it for canonical fields here.
    extras = dict(extras or {})
    _reject_canonical_write_fields(extras)

    # 5) Allocate the idempotency key if not supplied.
    key = idempotency_key or _ulid.new_ulid()
    # Sanity-check caller-supplied keys: must be a string. We deliberately
    # do NOT validate Crockford alphabet here; that is verified by the
    # SDK's own generator + tests, and the sidecar performs the final
    # cross-language validation.
    key = _require_non_empty_str("idempotency_key", key)

    envelope: dict[str, Any] = {
        "schema_version": INGEST_RUN_SCHEMA_VERSION,
        "run_id": scope_id,
        "trace_id": trace_id,
        "project_id": project_id,
        "agent": dict(agent),
        "client_lifecycle_status": status,
        "started_at": started_at,
        "sdk_version": sdk_version,
        "sdk_clock": sdk_clock,
        "manifest_commit_hash": manifest,
        "actor_identity_hash": actor,
        "redaction_policy_version": redaction_policy_version,
        "idempotency_key": key,
        "sequence_number": int(sequence_number),
        "metadata": dict(metadata) if metadata else {},
    }
    # 6) Merge in extras (already screened). Caller-supplied fields land
    #    AFTER the canonical fields so a typo cannot clobber a structural
    #    field -- the denylist already rejected the canonical-write set.
    for k, v in extras.items():
        if k in envelope:
            from .errors import RelayConfigError

            raise RelayConfigError(
                f"extras key {k!r} collides with a structural envelope field",
                details={"field": k},
            )
        envelope[k] = v
    return envelope


def build_gate_draft_envelope(
    *,
    gate_id: str,
    release_sha: str,
    eval_run_ids: Iterable[str],
    manifest_commit_hash: str,
    actor_identity_hash: str,
    draft_id: str | None = None,
    worker_id: str | None = None,
    scope_type: str | None = None,
    round: int | None = None,
    evidence_refs: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build a ``POST /v1/gates/{gate_id}/drafts`` body.

    Per VAL-W3-013 the SDK submits evidence-only drafts; the gate engine
    writes the canonical :class:`GateDecision`. The SDK NEVER computes
    pass/fail itself.

    Three-anchor handoff is enforced exactly as for the run-ingest
    envelope: missing/empty ``manifest_commit_hash`` or
    ``actor_identity_hash`` raises :class:`RelayHandoffIncomplete`.

    Optional fields (``worker_id``, ``scope_type``, ``round``,
    ``evidence_refs``) are emitted only when supplied; the control plane
    enforces canonical ``required: true`` constraints at the wire/storage
    layer. ``scope_id`` is always emitted and equals ``gate_id`` so the
    envelope round-trips byte-equal to the TypeScript SDK
    (``packages/sdk-typescript/src/lifecycle.ts::buildGateDraftEnvelope``)
    for VAL-W4-020 cross-language parity.
    """
    gate_id = _require_non_empty_str("gate_id", gate_id)
    release_sha = _require_non_empty_str("release_sha", release_sha)
    runs = list(eval_run_ids or [])
    if not runs:
        from .errors import RelayConfigError

        raise RelayConfigError(
            "eval_run_ids must contain >= 1 eval_run reference",
            details={"field": "eval_run_ids"},
        )
    for r in runs:
        _require_non_empty_str("eval_run_id", r)
    _, actor, manifest = _validate_three_anchor_handoff(
        scope_id=gate_id,
        actor_identity_hash=actor_identity_hash,
        manifest_commit_hash=manifest_commit_hash,
    )
    env: dict[str, Any] = {
        "schema_version": GATE_DRAFT_SCHEMA_VERSION,
        "draft_id": draft_id or _ulid.new_ulid(),
        "gate_id": gate_id,
        "scope_id": gate_id,
        "release_sha": release_sha,
        "eval_run_ids": list(runs),
        "manifest_commit_hash": manifest,
        "actor_identity_hash": actor,
        # written_by is INTENTIONALLY absent. The SDK never writes it
        # (VAL-W3-016 grep guard); the gate engine writes the canonical
        # row.
    }
    if worker_id is not None:
        env["worker_id"] = _require_non_empty_str("worker_id", worker_id)
    if scope_type is not None:
        env["scope_type"] = _require_non_empty_str("scope_type", scope_type)
    if round is not None:
        env["round"] = int(round)
    if evidence_refs is not None:
        refs = list(evidence_refs)
        for ref in refs:
            _require_non_empty_str("evidence_ref", ref)
        env["evidence_refs"] = refs
    return env


def _require_evidence_non_empty_str(name: str, value: Any) -> str:
    """Return ``value`` if a non-empty string; else raise RelayEvidenceIncomplete.

    Evidence envelopes have a stricter typed-error surface than the
    generic config validator: every missing or empty required field
    surfaces as :class:`RelayEvidenceIncomplete` so callers can match a
    single exception type (VAL-W3-015 evidence binding).
    """
    from .errors import RelayEvidenceIncomplete

    if not isinstance(value, str) or not value:
        raise RelayEvidenceIncomplete(
            f"{name} must be a non-empty string",
            details={"field": name, "received_type": type(value).__name__},
        )
    return value


def build_evidence_envelope(
    *,
    run_id: str,
    artifact_digest_sha256: str,
    command_id: str,
    exit_code: int,
    span_ids: Iterable[str],
    assertion_ids: Iterable[str],
    actor_identity_hash: str,
    manifest_commit_hash: str,
    redaction_policy_version: str,
) -> dict[str, Any]:
    """Build an evidence-submit envelope.

    Per VAL-W3-015 every required field MUST be present and bound. A
    missing required field raises :class:`RelayEvidenceIncomplete` at
    the SDK boundary BEFORE the request is sent. The error's
    ``details.field`` names the offending field.
    """
    from .errors import RelayEvidenceIncomplete

    # String fields -- evidence-typed validator so the caller sees a
    # uniform RelayEvidenceIncomplete surface for every missing field.
    run_id = _require_evidence_non_empty_str("run_id", run_id)
    artifact_digest_sha256 = _require_evidence_non_empty_str(
        "artifact_digest_sha256", artifact_digest_sha256
    )
    command_id = _require_evidence_non_empty_str("command_id", command_id)
    redaction_policy_version = _require_evidence_non_empty_str(
        "redaction_policy_version", redaction_policy_version
    )

    # exit_code -- must be a proper int (False/True are technically ints
    # but the spec requires a process exit-code, so we accept any int).
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise RelayEvidenceIncomplete(
            "exit_code must be an int (process exit code)",
            details={
                "field": "exit_code",
                "received_type": type(exit_code).__name__,
            },
        )

    # Iterable fields -- must yield >= 1 entry each.
    spans = [str(s) for s in (span_ids or [])]
    if not spans:
        raise RelayEvidenceIncomplete(
            "span_ids must contain >= 1 entry",
            details={"field": "span_ids"},
        )
    asserts_ = [str(a) for a in (assertion_ids or [])]
    if not asserts_:
        raise RelayEvidenceIncomplete(
            "assertion_ids must contain >= 1 entry",
            details={"field": "assertion_ids"},
        )

    # Three-anchor handoff -- shared validator. Surfaces as
    # RelayHandoffIncomplete; this is a distinct typed exception from
    # the evidence-incomplete class because the handoff failure is
    # retryable after_state_change while evidence-incomplete is not.
    _, actor, manifest = _validate_three_anchor_handoff(
        scope_id=run_id,
        actor_identity_hash=actor_identity_hash,
        manifest_commit_hash=manifest_commit_hash,
    )

    return {
        "schema_version": EVIDENCE_SUBMIT_SCHEMA_VERSION,
        "run_id": run_id,
        "artifact_digest_sha256": artifact_digest_sha256,
        "command_id": command_id,
        "exit_code": int(exit_code),
        "span_ids": spans,
        "assertion_ids": asserts_,
        "actor_identity_hash": actor,
        "manifest_commit_hash": manifest,
        "redaction_policy_version": redaction_policy_version,
    }


REPLAY_CASE_CREATE_SCHEMA_VERSION: Final[str] = "relay.replay_case.create.v1"


def build_replay_case_envelope(
    *,
    run_id: str,
    manifest_commit_hash: str,
    actor_identity_hash: str,
    egress_allowlist: Iterable[str] | None = None,
    scope_name: str | None = None,
) -> dict[str, Any]:
    """Build the ``POST /v1/runs/{run_id}/replays`` envelope.

    Audit-r3 BUG-B3: this is the SDK-side ReplayCase submit boundary
    that runs the SSRF guard (:func:`relay.network_policy.validate_egress_entries`)
    over every caller-supplied ``egress_allowlist`` entry BEFORE the
    request leaves the SDK. A rejected entry raises
    :class:`relay.network_policy.EgressDenied` with a structured
    envelope; the SDK does not retry and does not send the request.

    Per spec §AI line 5664 the egress allowlist is a default-deny
    closed set: every entry must clear the RFC1918 / link-local /
    loopback / multicast / reserved / cloud-metadata / reserved-
    hostname checks before it is honored.
    """
    # Three-anchor handoff -- same validator as ingest. A stale handoff
    # is rejected before the SSRF check runs so RELAY-GATE-021 -class
    # errors surface first.
    scope_id, actor, manifest = _validate_three_anchor_handoff(
        scope_id=run_id,
        actor_identity_hash=actor_identity_hash,
        manifest_commit_hash=manifest_commit_hash,
    )
    # SSRF guard. Local import keeps lifecycle.py importable in
    # environments where network_policy was stripped (unlikely, but
    # the SDK boundary should not pull a transitive import for a
    # potentially-empty allowlist).
    from .network_policy import validate_egress_entries

    entries = list(egress_allowlist or [])
    if entries:
        validate_egress_entries(entries)

    envelope: dict[str, Any] = {
        "schema_version": REPLAY_CASE_CREATE_SCHEMA_VERSION,
        "run_id": scope_id,
        "manifest_commit_hash": manifest,
        "actor_identity_hash": actor,
        "egress_allowlist": entries,
    }
    if scope_name:
        envelope["scope_name"] = scope_name
    return envelope


__all__ = [
    "CANONICAL_WRITE_FIELDS",
    "EVIDENCE_REQUIRED_FIELDS",
    "EVIDENCE_SUBMIT_SCHEMA_VERSION",
    "GATE_DRAFT_SCHEMA_VERSION",
    "HANDOFF_ANCHORS",
    "INGEST_RUN_SCHEMA_VERSION",
    "LIFECYCLE_STATUSES",
    "REPLAY_CASE_CREATE_SCHEMA_VERSION",
    "build_evidence_envelope",
    "build_gate_draft_envelope",
    "build_ingest_run_envelope",
    "build_replay_case_envelope",
]
