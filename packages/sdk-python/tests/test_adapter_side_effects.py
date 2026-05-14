"""W3.5 VAL-W3-047: side-effecting tool calls emit pre-action + post-success.

Per spec X (side-effect idempotency) and CLAUDE.md invariant #6, a tool
declared ``side_effect=True`` MUST produce:

  * a ``tool.pre_action`` event_log entry BEFORE the tool function runs,
  * a ``tool.post_success_proof`` event_log entry on success, carrying
    ``result_hash`` and ``idempotency_key``.

A success without paired markers is rejected (the adapter raises a typed
error). The two events MUST be ordered by ``occurred_at`` with pre_action
strictly before post_success.

Per the contract gap note 1553, the SDK public API for declaring
``side_effect=True`` is the kwarg form on the tool descriptor passed to
the adapter ``register_tool`` surface.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from relay.adapters import register_tool
from relay.adapters._side_effects import (
    SideEffectMarkerMissing,
    SideEffectRecorder,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@dataclass
class _CRMCaseNoteResult:
    case_id: str
    note_id: str


def _good_create_case_note(*, case_id: str, body: str) -> _CRMCaseNoteResult:
    """A real-world side-effecting tool: writes a record to the CRM."""
    return _CRMCaseNoteResult(case_id=case_id, note_id="note_123")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_side_effecting_tool_emits_pre_and_post_markers() -> None:
    recorder = SideEffectRecorder()
    wrapped = register_tool(
        _good_create_case_note,
        name="crm.create_case_note",
        side_effect=True,
        recorder=recorder,
    )
    result = wrapped(case_id="case_42", body="hello")
    assert result.case_id == "case_42"
    events = recorder.events
    assert len(events) == 2
    assert events[0].kind == "tool.pre_action"
    assert events[1].kind == "tool.post_success_proof"
    # Ordering: pre strictly before post.
    assert events[0].occurred_at <= events[1].occurred_at
    # Post-success carries result_hash + idempotency_key.
    post = events[1].attributes
    assert isinstance(post["result_hash"], str)
    assert len(post["result_hash"]) >= 32
    assert isinstance(post["idempotency_key"], str)
    assert post["idempotency_key"]
    # The same idempotency_key is bound to BOTH markers.
    assert events[0].attributes["idempotency_key"] == post["idempotency_key"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_side_effecting_tool_failure_emits_pre_action_only() -> None:
    """A failing side-effecting tool emits the pre-action marker but NOT a
    post-success proof. The exception propagates."""

    def _exploding_tool(**_kw: Any) -> Any:
        raise RuntimeError("CRM down")

    recorder = SideEffectRecorder()
    wrapped = register_tool(
        _exploding_tool,
        name="crm.create_case_note",
        side_effect=True,
        recorder=recorder,
    )
    with pytest.raises(RuntimeError, match="CRM down"):
        wrapped()
    kinds = [e.kind for e in recorder.events]
    assert "tool.pre_action" in kinds
    assert "tool.post_success_proof" not in kinds


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_non_side_effecting_tool_emits_no_markers() -> None:
    def _pure_tool(*, x: int) -> int:
        return x + 1

    recorder = SideEffectRecorder()
    wrapped = register_tool(
        _pure_tool, name="math.inc", side_effect=False, recorder=recorder
    )
    assert wrapped(x=1) == 2
    assert recorder.events == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_side_effect_validator_rejects_post_success_without_pre_action() -> None:
    """The validator surface used by the gate engine raises when a
    post-success event arrives without a paired pre-action marker."""
    from relay.adapters._side_effects import validate_pairing

    events = [
        # post without preceding pre_action -> rejected.
        {
            "kind": "tool.post_success_proof",
            "idempotency_key": "ik-1",
            "occurred_at": 100.0,
        }
    ]
    with pytest.raises(SideEffectMarkerMissing):
        validate_pairing(events)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_idempotency_key_is_stable_across_identical_invocations() -> None:
    """Two identical (same name + same args) invocations produce the same
    idempotency_key so the side-effect engine can deduplicate."""
    recorder = SideEffectRecorder()
    wrapped = register_tool(
        _good_create_case_note,
        name="crm.create_case_note",
        side_effect=True,
        recorder=recorder,
    )
    wrapped(case_id="case_X", body="b")
    wrapped(case_id="case_X", body="b")
    ikeys = [e.attributes["idempotency_key"] for e in recorder.events]
    # Two invocations -> 4 events; identical args -> identical idempotency_key.
    assert len(ikeys) == 4
    assert ikeys[0] == ikeys[1] == ikeys[2] == ikeys[3]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-047")
def test_idempotency_key_differs_for_different_args() -> None:
    recorder = SideEffectRecorder()
    wrapped = register_tool(
        _good_create_case_note,
        name="crm.create_case_note",
        side_effect=True,
        recorder=recorder,
    )
    wrapped(case_id="case_A", body="alpha")
    wrapped(case_id="case_B", body="beta")
    pre_keys = [
        e.attributes["idempotency_key"]
        for e in recorder.events
        if e.kind == "tool.pre_action"
    ]
    assert len(pre_keys) == 2
    assert pre_keys[0] != pre_keys[1]
