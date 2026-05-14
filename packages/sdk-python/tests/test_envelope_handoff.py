"""VAL-W3-011 -- ingest envelope three-anchor handoff combinatoric coverage.

Every SDK-submitted ingest envelope MUST carry all three handoff anchors:
``scope_id`` (``run_id`` for run-scoped ingest), ``actor_identity_hash``,
and ``manifest_commit_hash``. A missing/empty anchor MUST raise
``RelayHandoffIncomplete`` at the SDK boundary AND surface the offending
anchor in ``details.mismatched_anchor`` so the receiver and tests can
attribute the failure precisely.

This test parameterises the 8 representative cells of the 3x4 matrix
covering all-present plus each-singly-absent.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import RelayHandoffIncomplete
from relay.lifecycle import build_ingest_run_envelope

_VALID_AGENT = {"name": "ops-agent", "version": "0.1.0"}
_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR_HASH = "sha256-actorhashactorhashactorhashactorhashactorhashactorhashactorhash"
_MANIFEST_HASH = (
    "sha256-manifesthashmanifesthashmanifesthashmanifesthashmanifesthashma"
)


def _good_kwargs() -> dict:
    return dict(
        run_id=_RUN_ID,
        trace_id="trace-abc",
        project_id="aa111111-2222-3333-4444-555555555555",
        agent=_VALID_AGENT,
        client_lifecycle_status="started",
        started_at="2026-05-12T10:00:00Z",
        sdk_version="relay-python@0.0.0",
        sdk_clock="2026-05-12T10:00:00.123Z",
        manifest_commit_hash=_MANIFEST_HASH,
        actor_identity_hash=_ACTOR_HASH,
        redaction_policy_version="v1",
        sequence_number=1,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-011")
def test_all_three_anchors_present_succeeds() -> None:
    envelope = build_ingest_run_envelope(**_good_kwargs())
    assert envelope["run_id"] == _RUN_ID
    assert envelope["actor_identity_hash"] == _ACTOR_HASH
    assert envelope["manifest_commit_hash"] == _MANIFEST_HASH


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-011")
@pytest.mark.parametrize(
    "missing_anchor, override",
    [
        # scope_id (run_id) missing -- three forms.
        ("scope_id", {"run_id": None}),
        ("scope_id", {"run_id": ""}),
        ("scope_id", {"run_id": 0}),
        # actor_identity_hash missing -- three forms.
        ("actor_identity_hash", {"actor_identity_hash": None}),
        ("actor_identity_hash", {"actor_identity_hash": ""}),
        ("actor_identity_hash", {"actor_identity_hash": 0}),
        # manifest_commit_hash missing -- three forms.
        ("manifest_commit_hash", {"manifest_commit_hash": None}),
        ("manifest_commit_hash", {"manifest_commit_hash": ""}),
    ],
)
def test_singly_missing_anchor_rejected_at_sdk_boundary(
    missing_anchor: str, override: dict
) -> None:
    """Each singly-absent anchor raises RelayHandoffIncomplete; the
    missing anchor is named in ``details.mismatched_anchor``.
    """
    kwargs = _good_kwargs()
    kwargs.update(override)
    with pytest.raises(RelayHandoffIncomplete) as excinfo:
        build_ingest_run_envelope(**kwargs)
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-HANDOFF-INCOMPLETE"
    assert err.code == "RELAY-SDK-007"
    assert missing_anchor in err.details["mismatched_anchor"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-011")
def test_all_three_anchors_missing_lists_all_three() -> None:
    """All-absent case names every offending anchor for the receiver."""
    kwargs = _good_kwargs()
    kwargs.update(
        run_id="",
        actor_identity_hash="",
        manifest_commit_hash="",
    )
    with pytest.raises(RelayHandoffIncomplete) as excinfo:
        build_ingest_run_envelope(**kwargs)
    err = excinfo.value
    mismatched = err.details["mismatched_anchor"]
    assert sorted(mismatched) == sorted(
        ["scope_id", "actor_identity_hash", "manifest_commit_hash"]
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-011")
def test_handoff_retry_advice_is_after_state_change() -> None:
    """A handoff failure is retryable after the caller refreshes the
    manifest commit hash / actor identity. The SDK exposes this advice
    so callers don't infinite-loop on a stale handoff.
    """
    kwargs = _good_kwargs()
    kwargs["manifest_commit_hash"] = ""
    with pytest.raises(RelayHandoffIncomplete) as excinfo:
        build_ingest_run_envelope(**kwargs)
    assert excinfo.value.retry_advice == "after_state_change"
