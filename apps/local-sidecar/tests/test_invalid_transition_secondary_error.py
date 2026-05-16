"""Round-3 P1 fix #2: ``compare_and_set_state`` INVALID_TRANSITION branch
MUST NOT propagate secondary I/O exceptions.

After the INVALID_TRANSITION branch ROLLBACKs the parent transaction, it
performs async I/O (``screen_payload``, ``maybe_spillover``) and writes
the forensic ``state.invalid_transition`` row in a fresh micro-txn. If
that secondary I/O raises (e.g., the anti-bypass screen flags the
caller-supplied payload, or the screen itself errors), the caller is
better served by a structured ``StateTransitionResult(reason=
INVALID_TRANSITION, secondary_error_reason=...)`` than by an
uncontrolled exception unwinding past the engine boundary.

Per CLAUDE.md keystone invariant #1 ("the control plane writes the
result") and #8 ("atomic persistence through four primitives"): callers
of compare_and_set_state are entitled to a structured outcome envelope
in every code path. An exception that propagates is observed by the
caller as "unknown state" -- did the transition apply? did the log row
land? -- and provokes unsafe retries.

This guard asserts: if ``screen_payload`` raises (any exception), the
caller receives a ``StateTransitionResult`` whose ``reason ==
INVALID_TRANSITION`` AND whose ``extras['secondary_error_reason']``
identifies the suppressed failure. No exception escapes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import uuid

import pytest
from relay_sidecar.db import SidecarDatabase
from relay_sidecar.state_engine import (
    INVALID_TRANSITION,
    ActorRef,
    compare_and_set_state,
    init_scope,
)


async def _seed_scope(db: SidecarDatabase) -> tuple[str, str]:
    scope_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    await init_scope(
        database=db,
        scope_kind="run",
        scope_id=scope_id,
        project_id=project_id,
    )
    return scope_id, project_id


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_invalid_transition_screen_failure_returns_structured_result(
    tmp_path,
    monkeypatch,
) -> None:
    """If ``screen_payload`` raises during the INVALID_TRANSITION branch,
    ``compare_and_set_state`` MUST return a structured result, NOT propagate.

    Patches ``screen_payload`` (the module-level binding imported into
    ``compare_and_set``) to raise a synthetic Exception. Triggers an
    INVALID_TRANSITION by sending an unknown event for the current
    state. Asserts:
      - no exception escapes,
      - the returned result is a StateTransitionResult,
      - result.ok is False,
      - result.reason == INVALID_TRANSITION,
      - result.extras carries ``secondary_error_reason`` identifying the
        suppressed failure.
    """
    from relay_sidecar.state_engine import compare_and_set as cas_mod

    class _ScreenBoom(RuntimeError):
        pass

    async def _boom_screen(*args: object, **kwargs: object) -> object:
        raise _ScreenBoom("synthetic screen failure for test")

    monkeypatch.setattr(cas_mod, "screen_payload", _boom_screen)

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-bbbb")

        # Bogus event -> INVALID_TRANSITION branch -> screen raises.
        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
        )

        # No exception escaped: we received a structured result.
        assert result is not None
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION, result
        assert "secondary_error_reason" in result.extras, result.extras
        # Cite the class name so callers can branch on the failure kind.
        assert "_ScreenBoom" in result.extras["secondary_error_reason"]
    finally:
        await db.close()


@pytest.mark.plumbing
@pytest.mark.asyncio
async def test_invalid_transition_spillover_failure_returns_structured_result(
    tmp_path,
    monkeypatch,
) -> None:
    """If ``maybe_spillover`` raises during the INVALID_TRANSITION branch,
    ``compare_and_set_state`` MUST return a structured result.

    Same shape as the screen-failure test but patches the spillover step
    instead. Both async-I/O calls in the INVALID_TRANSITION branch must
    be wrapped.
    """
    from relay_sidecar.state_engine import compare_and_set as cas_mod

    class _SpilloverBoom(RuntimeError):
        pass

    def _boom_spillover(*args: object, **kwargs: object) -> object:
        raise _SpilloverBoom("synthetic spillover failure for test")

    monkeypatch.setattr(cas_mod, "maybe_spillover", _boom_spillover)

    db = SidecarDatabase(db_path=tmp_path / "sidecar.db", reader_count=1)
    try:
        await db.open()
        scope_id, project_id = await _seed_scope(db)
        actor = ActorRef(kind="sdk", identity_hash="sha256-cccc")

        result = await compare_and_set_state(
            database=db,
            scope_kind="run",
            scope_id=scope_id,
            expected_from="pending",
            event="not.a.real.event",
            actor=actor,
            project_id=project_id,
        )

        assert result is not None
        assert result.ok is False
        assert result.reason == INVALID_TRANSITION, result
        assert "secondary_error_reason" in result.extras, result.extras
        assert "_SpilloverBoom" in result.extras["secondary_error_reason"]
    finally:
        await db.close()
