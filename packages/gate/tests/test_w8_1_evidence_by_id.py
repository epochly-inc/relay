"""W8.1 plumbing tests: VAL-W8-003 evidence bundles consumed by id only.

Verifies the evaluator resolves evidence_bundle_id references through
the EvidenceBundleProvider; missing ids produce action="invalid" with
unmet_conditions naming the bundle; inline artifact bytes / non-id
shapes are rejected with StaleHandoffError.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _w8_1_helpers import (
    GATE_ID_SCRUTINY,
    InMemoryEvidenceProvider,
    make_draft,
    make_gate,
    make_pipeline,
)
from relay_gate_engine import StaleHandoffError


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-003")
def test_missing_evidence_bundle_id_yields_invalid(
    evaluator, evidence_provider: InMemoryEvidenceProvider,
) -> None:
    """A draft referencing a non-existent bundle id -> action='invalid'."""
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(
        gate_id=GATE_ID_SCRUTINY,
        evidence_refs=("bundle-does-not-exist",),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny", gate=gate, draft=draft, now=now,
    )
    assert outcome.action == "invalid"
    assert any(
        u.get("kind") == "missing_evidence_bundle"
        and u.get("evidence_bundle_id") == "bundle-does-not-exist"
        for u in outcome.unmet_conditions
    ), outcome.unmet_conditions


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-003")
def test_present_evidence_bundle_id_resolves(
    evaluator, evidence_provider: InMemoryEvidenceProvider,
) -> None:
    """A present bundle id resolves and the gate accepts."""
    evidence_provider.add("bundle-abc", {"artifact_sha256": "sha256-deadbeef"})
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(
        gate_id=GATE_ID_SCRUTINY,
        evidence_refs=("bundle-abc",),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny", gate=gate, draft=draft, now=now,
    )
    assert outcome.action == "accept"
    assert outcome.unmet_conditions == ()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-003")
def test_evidence_ref_object_with_bundle_id_resolves(
    evaluator, evidence_provider: InMemoryEvidenceProvider,
) -> None:
    """An object {evidence_bundle_id: ...} is the canonical second shape."""
    evidence_provider.add("bundle-xyz", {"artifact_sha256": "sha256-cafef00d"})
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")
    draft = make_draft(
        gate_id=GATE_ID_SCRUTINY,
        evidence_refs=({"evidence_bundle_id": "bundle-xyz"},),
    )
    outcome = pipeline.run_gate(
        gate_name="scrutiny", gate=gate, draft=draft, now=now,
    )
    assert outcome.action == "accept"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W8-003")
def test_inline_artifact_body_is_rejected(evaluator) -> None:
    """Inline artifact bodies (not an id) MUST be rejected.

    A draft passing inline bytes via a list, or a dict without
    evidence_bundle_id, is treated as a stale-handoff signal.
    """
    pipeline = make_pipeline(evaluator)
    now = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)
    gate = make_gate(gate_id=GATE_ID_SCRUTINY, gate_name="scrutiny")

    # Case 1: dict without evidence_bundle_id field.
    draft = make_draft(
        gate_id=GATE_ID_SCRUTINY,
        evidence_refs=({"inline_bytes": "deadbeef"},),
    )
    with pytest.raises(StaleHandoffError):
        pipeline.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft, now=now,
        )

    # Case 2: a non-string non-mapping (e.g., int).
    pipeline2 = make_pipeline(evaluator)
    draft2 = make_draft(
        gate_id=GATE_ID_SCRUTINY,
        evidence_refs=(42,),
    )
    with pytest.raises(StaleHandoffError):
        pipeline2.run_gate(
            gate_name="scrutiny", gate=gate, draft=draft2, now=now,
        )
