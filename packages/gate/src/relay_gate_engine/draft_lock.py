"""Concurrent-draft conflict guard for w8.1 (VAL-W8-007).

Background: every ``gate_decision_drafts`` row carries a unique constraint
on ``(gate_id, scope_type, scope_id, round)`` per spec A.3 line 3016.
When two workers submit drafts for the same key with different
``worker_id`` values, exactly one MUST succeed and the other MUST receive
``RELAY-GATE-014`` (HTTP 409 in W8.2's HTTP surface).

This module provides the in-memory enforcement primitive used by the
gate engine before any persistent write attempt. The persistent path
(W8.2) layers a Postgres unique-constraint violation on top -- both must
fail closed; this Python guard catches the common-case race before
hitting the database.

The lock is keyed on the natural unique tuple
``(gate_id, scope_type, scope_id, round)``. ``acquire`` is non-blocking;
a second caller with a different ``worker_id`` for the same key receives
:class:`DraftLockConflictError`. A second caller with the SAME
``worker_id`` receives ``ok=True`` (idempotent re-entry from the same
worker is permitted; this matches the at-least-once delivery semantics
documented in the spec A.12 idempotency record path).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import threading
from collections.abc import Hashable
from dataclasses import dataclass

from relay_schemas.error_codes import RelayErrorCode

from .errors import GateEngineError

# Lock-key tuple shape. Documented for readers; not enforced as a
# structural type because dict[Hashable, ...] is sufficient at runtime.
LockKey = tuple[Hashable, str, Hashable, int]


class DraftLockConflictError(GateEngineError):
    """Raised when a second worker tries to acquire a held key.

    Surfaces ``RELAY-GATE-014`` (VAL-W8-007). The W8.2 HTTP surface maps
    this to HTTP 409 Conflict.
    """

    code: str = RelayErrorCode.RELAY_GATE_014


@dataclass(frozen=True)
class _LockEntry:
    """Internal record of a held draft lock.

    ``worker_id`` is the worker that successfully acquired; ``draft_id``
    is the draft that opened the lock. Both are surfaced in conflict
    error payloads so the rejected caller can diagnose without a
    database round-trip.
    """

    worker_id: Hashable
    draft_id: Hashable


class DraftLock:
    """Process-local concurrent-draft conflict guard (VAL-W8-007).

    The lock is process-local by design: the W8.2 persistent guard
    (Postgres unique constraint) is the cross-process source of truth.
    This guard is the in-process fast-path; without it, two threads in
    the same engine process could race past the constraint check and
    both attempt the row insert, doubling the cost of a known-conflict
    submission.

    Thread-safe. Uses a single :class:`threading.Lock` to serialize
    ``acquire`` and ``release``. The guard is short-lived: callers
    acquire BEFORE issuing the persistent write and release AFTER the
    decision row is committed (or after the engine rejects the draft).
    """

    def __init__(self) -> None:
        self._mu: threading.Lock = threading.Lock()
        self._held: dict[LockKey, _LockEntry] = {}

    def acquire(
        self,
        *,
        gate_id: Hashable,
        scope_type: str,
        scope_id: Hashable,
        round: int,
        worker_id: Hashable,
        draft_id: Hashable,
    ) -> None:
        """Acquire the lock for the given key on behalf of ``worker_id``.

        Returns normally when the lock is granted (either the key was
        free, or the holder is the same ``worker_id``). Raises
        :class:`DraftLockConflictError` if a different worker already
        holds the key.
        """
        if not isinstance(round, int) or round < 1:
            raise ValueError(
                f"round MUST be a positive int (>= 1); got {round!r}"
            )
        if not isinstance(scope_type, str) or not scope_type:
            raise ValueError(
                f"scope_type MUST be a non-empty string; got {scope_type!r}"
            )
        key: LockKey = (gate_id, scope_type, scope_id, round)
        with self._mu:
            existing = self._held.get(key)
            if existing is None:
                self._held[key] = _LockEntry(
                    worker_id=worker_id, draft_id=draft_id
                )
                return
            if existing.worker_id == worker_id:
                # Same worker re-entering with a different draft_id: still
                # a conflict because the unique constraint pins the key
                # regardless of submitter identity. Matches the spec A.3
                # constraint that names (gate_id, scope_type, scope_id,
                # round) NOT (..., worker_id).
                if existing.draft_id == draft_id:
                    return
                raise DraftLockConflictError(
                    "concurrent draft conflict: same worker resubmitted "
                    "with a different draft_id; the unique key already "
                    "has a draft in flight",
                    payload={
                        "gate_id": str(gate_id),
                        "scope_type": scope_type,
                        "scope_id": str(scope_id),
                        "round": round,
                        "holding_worker_id": str(existing.worker_id),
                        "holding_draft_id": str(existing.draft_id),
                        "rejected_draft_id": str(draft_id),
                    },
                )
            raise DraftLockConflictError(
                "concurrent draft conflict: a different worker already "
                "holds the (gate_id, scope_type, scope_id, round) key",
                payload={
                    "gate_id": str(gate_id),
                    "scope_type": scope_type,
                    "scope_id": str(scope_id),
                    "round": round,
                    "holding_worker_id": str(existing.worker_id),
                    "holding_draft_id": str(existing.draft_id),
                    "rejected_worker_id": str(worker_id),
                    "rejected_draft_id": str(draft_id),
                },
            )

    def release(
        self,
        *,
        gate_id: Hashable,
        scope_type: str,
        scope_id: Hashable,
        round: int,
        worker_id: Hashable,
    ) -> bool:
        """Release the lock if held by ``worker_id``.

        Returns True if a lock was released, False if no lock was held
        for the key. Raises :class:`DraftLockConflictError` if a
        DIFFERENT worker holds the key (a release from the wrong
        worker is a programmer bug; we surface it loudly rather than
        silently dropping the wrong holder's state).
        """
        key: LockKey = (gate_id, scope_type, scope_id, round)
        with self._mu:
            existing = self._held.get(key)
            if existing is None:
                return False
            if existing.worker_id != worker_id:
                raise DraftLockConflictError(
                    "release attempted by non-holder worker; refusing to "
                    "drop the lock state of a different worker",
                    payload={
                        "gate_id": str(gate_id),
                        "scope_type": scope_type,
                        "scope_id": str(scope_id),
                        "round": round,
                        "holding_worker_id": str(existing.worker_id),
                        "release_attempt_worker_id": str(worker_id),
                    },
                )
            del self._held[key]
            return True

    def is_held(
        self,
        *,
        gate_id: Hashable,
        scope_type: str,
        scope_id: Hashable,
        round: int,
    ) -> bool:
        """Return True iff the key is currently locked."""
        key: LockKey = (gate_id, scope_type, scope_id, round)
        with self._mu:
            return key in self._held


__all__ = [
    "DraftLock",
    "DraftLockConflictError",
    "LockKey",
]
