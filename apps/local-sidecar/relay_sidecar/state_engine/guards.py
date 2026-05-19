"""Per-transition guard registry (VAL-V2M03-024..029, spec C.3 + C.4).

Per CLAUDE.md keystone invariant #1 (control plane writes the result) and
spec C.4 (lines 3702-3705), every transition is gated by a list of
``Guard`` predicates that run inside the same SERIALIZABLE-equivalent
transaction as the CAS update. A single ``Guard.check(...) == False`` short-
circuits the transition with ``reason="GUARD_FAILED"`` and the offending
guard name surfaced in the result's ``extras``.

Per spec C.3 (lines 3640-3672) the canonical guards are:

  - ``valid_idempotency_key``                    (run.pending -> run.captured)
  - ``valid_manifest_commit_hash``               (run.pending -> run.captured)
  - ``spans_batch_settled_or_client_lifecycle_terminal`` (run.captured -> run.validating)
  - ``all_required_contracts_evaluated``         (run.validating -> run.gated)
  - ``contract_results_written``                 (run.validating -> run.gated)
  - ``all_bound_gates_decided``                  (run.gated -> run.result_written)
  - ``auto_transition_allowed``                  (auto.terminal transitions)
  - ``three_anchor_handoff_valid``               (gate.open -> gate.draft_received)
  - ``draft_not_expired``                        (gate.draft_received -> gate.evaluating)
  - ``all_conditions_evaluated``                 (gate.evaluating -> gate.decision_written)
  - ``restart_action_applies``                   (gate.decision_written -> gate.restarted)
  - ``terminal_action_applies``                  (gate.decision_written -> gate.terminal)
  - ``fixtures_have_valid_digests``              (replay_case.proposed -> fixtures_ready)
  - ``sandbox_provisioned``                      (replay_case.fixtures_ready -> executing)
  - ``network_policy_applied``                   (replay_case.fixtures_ready -> executing)
  - ``sandbox_exit_observed``                    (replay_case.executing -> analyzed)
  - ``manifest_digest_valid``                    (evidence.building -> signed)
  - ``signing_key_not_revoked``                  (evidence.building -> signed)
  - ``retention_policy_applied``                 (evidence.signed -> published)
  - ``retention_window_elapsed_and_no_legal_hold`` (evidence.published -> superseded)

The guard registry is built once at module import. Tests register stub
guards via ``register_guard(name, fn, override=True)``; the override flag
prevents accidental shadowing in production code paths.

Default semantics (lenient by design): a guard returns True when the
underlying enforcement table is empty or the relevant payload field is
absent. This matches spec C.4 line 3711 ("guards inspect related tables"):
a missing related row means the precondition is not yet binding. Guards
become STRICT only when a related row demonstrates the precondition must
hold (e.g., the manifest_versions table contains rows but the supplied
commit_hash is not among them -> the guard fails).

Three-anchor handoff is the one exception: when its guard is bound to a
transition, ALL three anchors MUST be present in the payload AND validate
via spec C.5. A missing anchor -> HANDOFF_INVALID (not GUARD_FAILED) so
the caller can distinguish handoff failure from generic guard failure.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import aiosqlite

from .handoff import HandoffResult, validate_three_anchor_handoff

# Guard.check signature: (conn, scope_kind, scope_id, payload,
#                         manifest_commit_hash) -> (ok, diagnostics)
GuardCheckFn = Callable[
    [
        aiosqlite.Connection,  # conn (writer, inside BEGIN IMMEDIATE)
        str,                   # scope_kind
        str,                   # scope_id
        dict[str, Any],        # payload
        str | None,            # manifest_commit_hash
    ],
    Awaitable[tuple[bool, dict[str, Any]]],
]


@dataclass(frozen=True)
class Guard:
    """One named guard predicate evaluated before a transition fires."""

    name: str
    check: GuardCheckFn


# Module-level registry. Populated below; tests may extend via register_guard.
_REGISTRY: dict[str, Guard] = {}


def register_guard(
    name: str, fn: GuardCheckFn, *, override: bool = False
) -> Guard:
    """Add or replace a guard in the registry.

    Args:
        name: The canonical guard name as it appears in
            state-transition-table.yaml.
        fn: Async predicate returning (ok, diagnostics).
        override: When False (default) and ``name`` already registered, a
            ValueError is raised; tests pass override=True to substitute
            stubs.

    Returns:
        The newly registered Guard.
    """
    if name in _REGISTRY and not override:
        raise ValueError(
            f"guard {name!r} already registered; pass override=True to replace"
        )
    g = Guard(name=name, check=fn)
    _REGISTRY[name] = g
    return g


def get_guard(name: str) -> Guard | None:
    """Return the registered guard, or None when unknown."""
    return _REGISTRY.get(name)


def registered_guard_names() -> tuple[str, ...]:
    """Return all currently registered guard names (sorted for stability)."""
    return tuple(sorted(_REGISTRY.keys()))


def is_handoff_guard(name: str) -> bool:
    """True iff the guard is the spec C.5 three-anchor handoff guard.

    Used by ``compare_and_set_state`` to distinguish HANDOFF_INVALID from
    GUARD_FAILED so callers can map to the wire-format
    ``RELAY-GATE-021`` envelope.
    """
    return name == "three_anchor_handoff_valid"


# --- Built-in guard implementations -----------------------------------------

# Convention: each guard returns (ok, diagnostics). On ok=False, the
# diagnostics dict is merged into the GUARD_FAILED extras under the
# 'guard_diagnostics' key. The 'failed_guard' key on extras names the
# offending guard.


async def _guard_valid_idempotency_key(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.pending -> run.captured` Idempotency-Key validation.

    Spec C.3 line 3657: "valid Idempotency-Key". Lenient default: when the
    payload omits an `idempotency_key`, the guard PASSES so that callers
    that pre-date the field (e.g., internal lifecycle bumps) remain
    operational. When the payload provides an explicit key marked invalid
    (``idempotency_key_invalid: True``), the guard FAILS. When the key is
    present AND an ``idempotency_records`` row exists with mismatched
    request_hash, the guard FAILS with a structured diagnostic.
    """
    if payload.get("idempotency_key_invalid") is True:
        return False, {
            "reason": "explicit invalid marker in payload",
            "field": "idempotency_key_invalid",
        }
    key = payload.get("idempotency_key")
    if not isinstance(key, str) or not key:
        # Lenient: no key supplied -> not gated.
        return True, {}
    expected_request_hash = payload.get("request_hash")
    try:
        # Audit fix (2026-05-17 P0): canonical column is ``request_digest``
        # (sha256-<hex>) per packages/schemas/sql/0002_control_plane.sql
        # lines 107-126. The legacy ``request_hash`` column never existed
        # in the canonical schema; the prior SELECT relied on the
        # OperationalError fallback when the column was missing, which
        # silently masked the bug. The post-0021 sidecar schema is
        # mirror-compatible with canonical and exposes ``request_digest``.
        async with conn.execute(
            "SELECT request_digest, response_status FROM idempotency_records "
            "WHERE idempotency_key = ?",
            (key,),
        ) as cur:
            row = await cur.fetchone()
    except aiosqlite.OperationalError:
        # Table may not exist in stripped-down OSS deployments.
        return True, {"note": "idempotency_records table not present"}
    if row is None:
        return True, {}
    stored_request_digest = str(row[0]) if row[0] is not None else None
    if (
        expected_request_hash is not None
        and stored_request_digest is not None
        and stored_request_digest != expected_request_hash
    ):
        return False, {
            "reason": "idempotency_key reuse with different request_digest",
            "idempotency_key": key,
        }
    return True, {}


async def _guard_valid_manifest_commit_hash(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.pending -> run.captured` manifest commit anchor validation.

    Spec C.3 line 3657 + spec C.5 line 3748: "valid manifest_commit_hash"
    scoped per project. Lenient default: when ``manifest_commit_hash`` is
    not supplied at the CAS boundary, the guard passes (no anchor was
    claimed). When supplied, the hash MUST resolve to an active or
    in-grace ``manifest_versions`` row FOR THE CURRENT SCOPE'S PROJECT
    (VAL-V3M3-001 -- a leaked hash from project A must not validate for
    project B).

    The project_id is read from ``scope_state`` for the active scope
    (project_id is set at ``init_scope`` time and never mutates). When
    ``scope_state`` lacks a row (legacy bootstrap), the guard falls back
    to commit_hash-only lookup with a structured note.
    """
    if manifest_commit_hash is None:
        return True, {}
    if not isinstance(manifest_commit_hash, str) or not manifest_commit_hash.startswith(
        "sha256-"
    ):
        return False, {
            "reason": "manifest_commit_hash not in canonical sha256-<hex> wire form",
            "field": "manifest_commit_hash",
        }
    # Resolve project_id for this scope (spec C.5 line 3748 per-project
    # scoping). Reads from the same writer txn -- no isolation surprises.
    project_id: str | None = None
    try:
        async with conn.execute(
            "SELECT project_id FROM scope_state "
            "WHERE scope_kind = ? AND scope_id = ?",
            (scope_kind, scope_id),
        ) as cur:
            row = await cur.fetchone()
        if row is not None and isinstance(row[0], str) and row[0]:
            project_id = row[0]
    except aiosqlite.OperationalError:
        # scope_state absent in stripped fixtures -> lenient fall-through.
        project_id = None

    try:
        if project_id is not None:
            async with conn.execute(
                "SELECT effective_until, grace_window_seconds "
                "FROM manifest_versions "
                "WHERE project_id = ? AND commit_hash = ?",
                (project_id, manifest_commit_hash),
            ) as cur:
                rows = await cur.fetchall()
        else:
            async with conn.execute(
                "SELECT effective_until, grace_window_seconds "
                "FROM manifest_versions WHERE commit_hash = ?",
                (manifest_commit_hash,),
            ) as cur:
                rows = await cur.fetchall()
    except aiosqlite.OperationalError:
        # Table absent -> lenient pass.
        return True, {"note": "manifest_versions table not present"}
    if not rows:
        # No match. Distinguish three cases for a clean audit signal:
        #   (a) empty registry -> lenient bootstrap.
        #   (b) hash exists for ANOTHER project -> per-project mismatch.
        #   (c) hash absent entirely -> generic not-in-registry.
        async with conn.execute(
            "SELECT COUNT(*) FROM manifest_versions"
        ) as cur:
            count_row = await cur.fetchone()
        total = int(count_row[0]) if count_row is not None else 0
        if total == 0:
            return True, {"note": "manifest registry empty (legacy bootstrap)"}
        if project_id is not None:
            async with conn.execute(
                "SELECT 1 FROM manifest_versions WHERE commit_hash = ? LIMIT 1",
                (manifest_commit_hash,),
            ) as cur:
                cross = await cur.fetchone()
            if cross is not None:
                return False, {
                    "reason": (
                        "manifest_commit_hash registered for a different "
                        "project; per-project scope mismatch"
                    ),
                    "field": "manifest_commit_hash",
                    "project_id": project_id,
                }
        return False, {
            "reason": "manifest_commit_hash not in registry",
            "field": "manifest_commit_hash",
        }
    now = datetime.now(tz=UTC)
    from datetime import timedelta
    for row in rows:
        effective_until_text, grace_window_seconds = row[0], int(row[1])
        if effective_until_text is None:
            return True, {}
        try:
            text = str(effective_until_text)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            effective_until = datetime.fromisoformat(text)
            if effective_until.tzinfo is None:
                effective_until = effective_until.replace(tzinfo=UTC)
        except ValueError:
            continue
        if now <= effective_until + timedelta(seconds=grace_window_seconds):
            return True, {}
    return False, {
        "reason": "manifest_commit_hash expired beyond grace window",
        "field": "manifest_commit_hash",
    }


async def _guard_spans_batch_settled_or_client_lifecycle_terminal(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.captured -> run.validating` settle gate.

    Spec C.3 line 3658: "spans batch settled OR client_lifecycle_status in
    {client_succeeded, client_failed, client_aborted}". Lenient default:
    pass when neither signal is provided (legacy bootstrap). FAIL only
    when the payload explicitly declares an unsettled lifecycle state and
    no settled-spans marker is present.
    """
    lifecycle = payload.get("client_lifecycle_status")
    if lifecycle in {"client_succeeded", "client_failed", "client_aborted"}:
        return True, {}
    if payload.get("spans_batch_settled") is True:
        return True, {}
    if "client_lifecycle_status" in payload or "spans_batch_settled" in payload:
        return False, {
            "reason": "neither spans batch settled nor lifecycle terminal",
            "client_lifecycle_status": lifecycle,
        }
    return True, {}


async def _guard_all_required_contracts_evaluated(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.validating -> run.gated`: all required contracts evaluated.

    Lenient: when ``required_contract_ids`` is absent from payload, the
    guard passes (no enforcement claimed). When provided, EACH id MUST
    have a row in ``contract_results`` for the current run.
    """
    required = payload.get("required_contract_ids")
    if not isinstance(required, list) or not required:
        return True, {}
    try:
        placeholders = ",".join("?" * len(required))
        async with conn.execute(
            f"SELECT contract_id FROM contract_results "
            f"WHERE run_id = ? AND contract_id IN ({placeholders})",
            (scope_id, *required),
        ) as cur:
            evaluated = {row[0] for row in await cur.fetchall()}
    except aiosqlite.OperationalError:
        return True, {"note": "contract_results table not present"}
    missing = sorted(set(required) - evaluated)
    if missing:
        return False, {
            "reason": "required contracts not yet evaluated",
            "missing": missing,
        }
    return True, {}


async def _guard_contract_results_written(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.validating -> run.gated`: contract_results rows written.

    Lenient: passes when no required_contract_ids list is provided.
    When provided, at least one ``contract_results`` row MUST exist for
    the run (otherwise the writer never executed).
    """
    required = payload.get("required_contract_ids")
    if not isinstance(required, list) or not required:
        return True, {}
    try:
        async with conn.execute(
            "SELECT COUNT(*) FROM contract_results WHERE run_id = ?",
            (scope_id,),
        ) as cur:
            row = await cur.fetchone()
    except aiosqlite.OperationalError:
        return True, {"note": "contract_results table not present"}
    count = int(row[0]) if row is not None else 0
    if count == 0:
        return False, {
            "reason": "contract_results rows not written for run",
            "run_id": scope_id,
        }
    return True, {}


async def _guard_all_bound_gates_decided(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`run.gated -> run.result_written`: every bound gate has a
    non-`remediate` decision for the current round.

    Lenient: passes when ``bound_gate_ids`` is absent. When provided,
    each gate_id MUST have a ``gate_decisions`` row with action in
    {accept, block, invalid}. The ``gate_decisions`` table is keyed by
    ``(scope_type, scope_id)`` per migration 0003; the guard maps the
    state-engine ``scope_kind`` to the corresponding ``scope_type``
    value (``run`` -> ``run``).
    """
    bound = payload.get("bound_gate_ids")
    if not isinstance(bound, list) or not bound:
        return True, {}
    try:
        placeholders = ",".join("?" * len(bound))
        async with conn.execute(
            f"SELECT gate_id, action FROM gate_decisions "
            f"WHERE scope_type = ? AND scope_id = ? AND gate_id IN ({placeholders})",
            (scope_kind, scope_id, *bound),
        ) as cur:
            decisions = {row[0]: row[1] for row in await cur.fetchall()}
    except aiosqlite.OperationalError:
        return True, {"note": "gate_decisions table not present"}
    bad: dict[str, str] = {}
    for gate_id in bound:
        action = decisions.get(gate_id)
        if action is None or action == "remediate":
            bad[gate_id] = action if action is not None else "no_decision"
    if bad:
        return False, {
            "reason": "bound gates have remediate or no decision",
            "offenders": bad,
        }
    return True, {}


async def _guard_auto_transition_allowed(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Auto-fired transitions are unconditionally allowed by spec.

    The spec marks the actor as the system that just wrote the prior row
    (e.g., ``result_writer`` writing ``run_results``, then auto-firing the
    terminal transition). No additional precondition.
    """
    return True, {}


async def _guard_three_anchor_handoff_valid(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Spec C.5 three-anchor handoff identity check.

    Unlike other guards, three-anchor IS strict: the transition's spec C.3
    row explicitly demands the three anchors. The payload MUST carry
    ``actor_identity_hash`` and ``manifest_commit_hash`` (and, for run
    scope, ``run_id``). The conn IS the writer connection but the handoff
    validator only SELECTs, so it is safe to reuse it as a reader.

    Per spec C.5 line 3748 + VAL-V3M3-001, the manifest anchor is scoped
    per (project_id, commit_hash). If the payload omits ``project_id``,
    the guard reads it from ``scope_state`` (single source of truth set
    at ``init_scope`` time) and injects it into the enriched payload so
    every state-engine path enforces per-project scoping even when
    callers have not been migrated to include project_id in payload.
    """
    enriched_payload = dict(payload)
    if (
        "manifest_commit_hash" not in enriched_payload
        and manifest_commit_hash is not None
    ):
        enriched_payload["manifest_commit_hash"] = manifest_commit_hash
    payload_project_id = enriched_payload.get("project_id")
    if not (isinstance(payload_project_id, str) and payload_project_id):
        try:
            async with conn.execute(
                "SELECT project_id FROM scope_state "
                "WHERE scope_kind = ? AND scope_id = ?",
                (scope_kind, scope_id),
            ) as cur:
                row = await cur.fetchone()
            if row is not None and isinstance(row[0], str) and row[0]:
                enriched_payload["project_id"] = row[0]
        except aiosqlite.OperationalError:
            # scope_state absent -> validator falls back to commit_hash-only
            # legacy lookup. No structural concern: the test path that
            # hits this branch is the legacy bootstrap path.
            pass
    result: HandoffResult = await validate_three_anchor_handoff(
        reader=conn,
        scope_kind=scope_kind,
        scope_id=scope_id,
        payload=enriched_payload,
    )
    if result.ok:
        return True, {}
    return False, {
        "reason": "three-anchor handoff failed",
        "handoff_reason": result.reason,
    }


async def _guard_draft_not_expired(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`gate.draft_received -> gate.evaluating`: draft must not be expired.

    Lenient: passes when no draft_expires_at field is provided. Strict
    when supplied AND in the past.
    """
    expires_at = payload.get("draft_expires_at")
    if not isinstance(expires_at, str):
        return True, {}
    try:
        text = expires_at if not expires_at.endswith("Z") else expires_at[:-1] + "+00:00"
        expiry = datetime.fromisoformat(text)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
    except ValueError:
        return False, {
            "reason": "draft_expires_at not RFC 3339",
            "value": expires_at,
        }
    if datetime.now(tz=UTC) > expiry:
        return False, {
            "reason": "draft expired",
            "draft_expires_at": expires_at,
        }
    return True, {}


async def _guard_all_conditions_evaluated(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`gate.evaluating -> gate.decision_written`: all conditions decided.

    Lenient: passes unless payload sets ``conditions_pending: True``.
    """
    if payload.get("conditions_pending") is True:
        return False, {"reason": "conditions not fully evaluated"}
    return True, {}


async def _guard_restart_action_applies(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Restart-applicable: action in {remediate, block} AND cascade flag on.

    Lenient: passes when ``decision_action`` is absent. Otherwise strict.
    """
    action = payload.get("decision_action")
    if action is None:
        return True, {}
    if action not in {"remediate", "block"}:
        return False, {
            "reason": "decision_action not in {remediate, block}",
            "decision_action": action,
        }
    cascade = payload.get("cascade_on_block", True)
    if cascade is False:
        return False, {"reason": "cascade_on_block is false"}
    return True, {}


async def _guard_terminal_action_applies(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Terminal-applicable: action in {accept, invalid}.

    Lenient: passes when ``decision_action`` is absent.
    """
    action = payload.get("decision_action")
    if action is None:
        return True, {}
    if action not in {"accept", "invalid"}:
        return False, {
            "reason": "decision_action not in {accept, invalid}",
            "decision_action": action,
        }
    return True, {}


async def _guard_fixtures_have_valid_digests(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`replay_case.proposed -> fixtures_ready`: every span has a fixture digest.

    Lenient: passes when ``fixtures`` is absent. When provided, every
    entry MUST carry a non-empty ``digest`` string in sha256 wire form.
    """
    fixtures = payload.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        return True, {}
    bad = [
        i
        for i, f in enumerate(fixtures)
        if not (
            isinstance(f, dict)
            and isinstance(f.get("digest"), str)
            and f["digest"].startswith("sha256-")
        )
    ]
    if bad:
        return False, {
            "reason": "fixtures with missing or malformed digest",
            "indices": bad,
        }
    return True, {}


async def _guard_sandbox_provisioned(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Replay sandbox provisioning marker.

    Lenient: passes unless payload sets ``sandbox_provisioned: False``.
    """
    if payload.get("sandbox_provisioned") is False:
        return False, {"reason": "sandbox not provisioned"}
    return True, {}


async def _guard_network_policy_applied(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Replay sandbox network policy marker.

    Lenient: passes unless payload sets ``network_policy_applied: False``.
    """
    if payload.get("network_policy_applied") is False:
        return False, {"reason": "network policy not applied"}
    return True, {}


async def _guard_sandbox_exit_observed(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Replay sandbox exit marker.

    Lenient: passes unless payload sets ``sandbox_exit_observed: False``.
    """
    if payload.get("sandbox_exit_observed") is False:
        return False, {"reason": "sandbox exit not observed"}
    return True, {}


async def _guard_manifest_digest_valid(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Evidence-signer manifest digest validation.

    Spec C.3 line 3670: "manifest digest valid". Lenient default mirrors
    ``valid_manifest_commit_hash`` but also accepts an explicit
    ``manifest_digest`` field in payload. FAILS when the supplied digest
    is malformed OR provided AND not in registry.
    """
    digest = payload.get("manifest_digest") or manifest_commit_hash
    if digest is None:
        return True, {}
    if not isinstance(digest, str) or not digest.startswith("sha256-"):
        return False, {
            "reason": "manifest_digest not in sha256-<hex> wire form",
            "field": "manifest_digest",
        }
    try:
        async with conn.execute(
            "SELECT 1 FROM manifest_versions WHERE commit_hash = ? LIMIT 1",
            (digest,),
        ) as cur:
            row = await cur.fetchone()
    except aiosqlite.OperationalError:
        return True, {"note": "manifest_versions table not present"}
    if row is None:
        async with conn.execute(
            "SELECT COUNT(*) FROM manifest_versions"
        ) as cur:
            count_row = await cur.fetchone()
        total = int(count_row[0]) if count_row is not None else 0
        if total == 0:
            return True, {"note": "manifest registry empty (legacy bootstrap)"}
        return False, {
            "reason": "manifest_digest not registered",
            "field": "manifest_digest",
        }
    return True, {}


async def _guard_signing_key_not_revoked(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Evidence-signer key revocation gate.

    Lenient: passes when no ``signing_key_id`` provided. When provided,
    consults the ``key_lifecycle`` table; FAILS if the latest event is
    ``revoke``.
    """
    key_id = payload.get("signing_key_id")
    if not isinstance(key_id, str) or not key_id:
        return True, {}
    try:
        async with conn.execute(
            "SELECT event_type FROM key_lifecycle "
            "WHERE key_id = ? ORDER BY event_at DESC LIMIT 1",
            (key_id,),
        ) as cur:
            row = await cur.fetchone()
    except aiosqlite.OperationalError:
        return True, {"note": "key_lifecycle table not present"}
    if row is None:
        return True, {"note": "no lifecycle events for key"}
    if str(row[0]) == "revoke":
        return False, {
            "reason": "signing key revoked",
            "signing_key_id": key_id,
        }
    return True, {}


async def _guard_retention_policy_applied(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """Retention policy applied marker.

    Lenient: passes unless payload sets ``retention_policy_applied: False``.
    """
    if payload.get("retention_policy_applied") is False:
        return False, {"reason": "retention policy not applied"}
    return True, {}


async def _guard_retention_window_elapsed_and_no_legal_hold(
    conn: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    manifest_commit_hash: str | None,
) -> tuple[bool, dict[str, Any]]:
    """`evidence.published -> superseded`: retention window expired AND no hold.

    Lenient: passes when both signals absent. FAILS when the payload
    explicitly declares ``legal_hold_active: True`` or
    ``retention_window_elapsed: False``.
    """
    if payload.get("legal_hold_active") is True:
        return False, {"reason": "legal hold active"}
    if payload.get("retention_window_elapsed") is False:
        return False, {"reason": "retention window not yet elapsed"}
    return True, {}


# --- Registry seeding (run at import) ---------------------------------------

_BUILTIN_GUARDS: tuple[tuple[str, GuardCheckFn], ...] = (
    ("valid_idempotency_key", _guard_valid_idempotency_key),
    ("valid_manifest_commit_hash", _guard_valid_manifest_commit_hash),
    (
        "spans_batch_settled_or_client_lifecycle_terminal",
        _guard_spans_batch_settled_or_client_lifecycle_terminal,
    ),
    ("all_required_contracts_evaluated", _guard_all_required_contracts_evaluated),
    ("contract_results_written", _guard_contract_results_written),
    ("all_bound_gates_decided", _guard_all_bound_gates_decided),
    ("auto_transition_allowed", _guard_auto_transition_allowed),
    ("three_anchor_handoff_valid", _guard_three_anchor_handoff_valid),
    ("draft_not_expired", _guard_draft_not_expired),
    ("all_conditions_evaluated", _guard_all_conditions_evaluated),
    ("restart_action_applies", _guard_restart_action_applies),
    ("terminal_action_applies", _guard_terminal_action_applies),
    ("fixtures_have_valid_digests", _guard_fixtures_have_valid_digests),
    ("sandbox_provisioned", _guard_sandbox_provisioned),
    ("network_policy_applied", _guard_network_policy_applied),
    ("sandbox_exit_observed", _guard_sandbox_exit_observed),
    ("manifest_digest_valid", _guard_manifest_digest_valid),
    ("signing_key_not_revoked", _guard_signing_key_not_revoked),
    ("retention_policy_applied", _guard_retention_policy_applied),
    (
        "retention_window_elapsed_and_no_legal_hold",
        _guard_retention_window_elapsed_and_no_legal_hold,
    ),
)

for _name, _fn in _BUILTIN_GUARDS:
    register_guard(_name, _fn)


__all__ = [
    "Guard",
    "GuardCheckFn",
    "get_guard",
    "is_handoff_guard",
    "register_guard",
    "registered_guard_names",
]
