"""Three-anchor handoff validator (spec C.5, CLAUDE.md keystone invariant #4).

Every control-plane state transition rooted in a worker (or SDK or gate
engine) submission MUST carry three anchors:

    (scope_id, actor_identity_hash, manifest_commit_hash)

The receiver rejects a handoff that fails any anchor. Per CLAUDE.md
"three-anchor handoff" and spec C.5 lines 3736-3756, the canonical
implementation is:

    1. Scope anchor:    payload['run_id'] must equal scope_id when scope_kind='run'.
    2. Actor anchor:    actor_identity_hash must be registered AND not revoked.
    3. Manifest anchor: manifest_commit_hash must be currently active OR in
                        the grace window after a rotation.

Failure of any anchor produces ``HandoffResult(ok=False, reason=<code>)``
with one of the structured reason codes below. On a gate-draft submission,
failed handoff additionally surfaces as the wire-format error code
``RELAY-GATE-021`` (VAL-W2-033).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import aiosqlite

# Structured reason codes returned by validate_three_anchor_handoff.
# These mirror spec C.5 lines 3740, 3744, 3751 exactly.
SCOPE_ID_MISMATCH: str = "SCOPE_ID_MISMATCH"
ACTOR_NOT_REGISTERED: str = "ACTOR_NOT_REGISTERED"
MANIFEST_NOT_ACTIVE: str = "MANIFEST_NOT_ACTIVE"


@dataclass(frozen=True)
class HandoffResult:
    """Outcome of a three-anchor handoff validation.

    Attributes:
        ok: True only when all three anchors pass.
        reason: Structured failure code (one of the constants above) when
            ``ok=False``; None on success.
    """

    ok: bool
    reason: str | None = None


def _parse_rfc3339(value: str) -> datetime:
    """Parse an RFC 3339 / ISO 8601 string into a tz-aware UTC datetime.

    Tolerates both the canonical ``Z`` suffix and the ``+00:00`` form used
    by Python's ``datetime.isoformat``. All comparisons are done in UTC.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


async def _actor_is_active(
    reader: aiosqlite.Connection,
    *,
    actor_identity_hash: str,
) -> bool:
    """Return True iff actor row exists AND revoked_at is NULL."""
    async with reader.execute(
        "SELECT 1 FROM actors WHERE identity_hash = ? AND revoked_at IS NULL",
        (actor_identity_hash,),
    ) as cur:
        row = await cur.fetchone()
    return row is not None


async def _manifest_is_active_or_in_grace(
    reader: aiosqlite.Connection,
    *,
    manifest_commit_hash: str,
    now: datetime,
) -> bool:
    """Return True iff a manifest_versions row matches AND is active OR in grace.

    A row is *active* when ``effective_until IS NULL``. A row is *in grace*
    when ``effective_until IS NOT NULL`` AND
    ``now <= effective_until + grace_window_seconds``.

    The lookup matches by ``commit_hash`` only (the OSS local sidecar does
    not yet scope manifests per-project for the handoff check). The hosted
    Postgres profile will tighten this to ``(project_id, commit_hash)`` per
    spec C.5 line 3748.
    """
    async with reader.execute(
        "SELECT effective_until, grace_window_seconds "
        "FROM manifest_versions WHERE commit_hash = ?",
        (manifest_commit_hash,),
    ) as cur:
        rows = await cur.fetchall()
    if not rows:
        return False
    for row in rows:
        effective_until_text, grace_window_seconds = row[0], int(row[1])
        if effective_until_text is None:
            # Currently active.
            return True
        try:
            effective_until = _parse_rfc3339(str(effective_until_text))
        except ValueError:
            # Malformed timestamp -> treat as not in grace (fail closed).
            continue
        if now <= effective_until + timedelta(seconds=grace_window_seconds):
            return True
    return False


async def validate_three_anchor_handoff(
    *,
    reader: aiosqlite.Connection,
    scope_kind: str,
    scope_id: str,
    payload: dict[str, Any],
    now: datetime | None = None,
) -> HandoffResult:
    """Validate the three-anchor handoff for a worker submission.

    Args:
        reader: An aiosqlite reader connection (PRAGMA query_only = 1) for
            the actor + manifest lookups. The function NEVER writes; it is
            safe to call from any HTTP handler path.
        scope_kind: One of 'run','replay_case','gate_round','evidence_bundle',
            'eval_run','release'. Used only for the scope-anchor branch
            (run_id check).
        scope_id: The scope id from the URL/path. The scope anchor compares
            this to ``payload['run_id']`` when ``scope_kind == 'run'``.
        payload: The submission body. Required keys:
            - ``actor_identity_hash``: sha256-<hex> wire form.
            - ``manifest_commit_hash``: sha256-<hex> wire form.
            - ``run_id`` (only for ``scope_kind == 'run'``).
        now: Override the current time for tests. Default ``datetime.now(UTC)``.

    Returns:
        ``HandoffResult(ok=True)`` on success.
        ``HandoffResult(ok=False, reason=SCOPE_ID_MISMATCH)`` on scope mismatch.
        ``HandoffResult(ok=False, reason=ACTOR_NOT_REGISTERED)`` on unknown
            or revoked actor.
        ``HandoffResult(ok=False, reason=MANIFEST_NOT_ACTIVE)`` on missing
            or out-of-grace manifest hash.

    The function performs checks in spec C.5 order: scope -> actor -> manifest.
    The first failing anchor short-circuits with its specific reason; later
    anchors are not checked.
    """
    now_utc = now if now is not None else datetime.now(tz=UTC)
    now_utc = (
        now_utc.replace(tzinfo=UTC)
        if now_utc.tzinfo is None
        else now_utc.astimezone(UTC)
    )

    # (1) Scope/run anchor.
    if scope_kind == "run":
        run_id = payload.get("run_id")
        if run_id != scope_id:
            return HandoffResult(ok=False, reason=SCOPE_ID_MISMATCH)

    # (2) Actor identity anchor.
    actor_identity_hash = payload.get("actor_identity_hash")
    if not isinstance(actor_identity_hash, str):
        return HandoffResult(ok=False, reason=ACTOR_NOT_REGISTERED)
    if not actor_identity_hash.startswith("sha256-"):
        # Malformed input -- functionally not in the registry.
        return HandoffResult(ok=False, reason=ACTOR_NOT_REGISTERED)
    if not await _actor_is_active(reader, actor_identity_hash=actor_identity_hash):
        return HandoffResult(ok=False, reason=ACTOR_NOT_REGISTERED)

    # (3) Manifest commit anchor.
    manifest_commit_hash = payload.get("manifest_commit_hash")
    if not isinstance(manifest_commit_hash, str):
        return HandoffResult(ok=False, reason=MANIFEST_NOT_ACTIVE)
    if not manifest_commit_hash.startswith("sha256-"):
        return HandoffResult(ok=False, reason=MANIFEST_NOT_ACTIVE)
    if not await _manifest_is_active_or_in_grace(
        reader,
        manifest_commit_hash=manifest_commit_hash,
        now=now_utc,
    ):
        return HandoffResult(ok=False, reason=MANIFEST_NOT_ACTIVE)

    return HandoffResult(ok=True)


__all__ = [
    "ACTOR_NOT_REGISTERED",
    "HandoffResult",
    "MANIFEST_NOT_ACTIVE",
    "SCOPE_ID_MISMATCH",
    "validate_three_anchor_handoff",
]
