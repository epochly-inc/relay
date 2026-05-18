"""Cross-language parity for ``build_gate_draft_envelope`` (P0 audit fix).

Loads ``tests/conformance/lifecycle/gate_draft_parity_fixtures.json``
and asserts the Python SDK's :func:`relay.lifecycle.build_gate_draft_envelope`
emits the canonical envelope dict declared in the fixture for each input
case. The TypeScript SDK runs the same fixture against
:func:`buildGateDraftEnvelope`; combined, the two suites guarantee
byte-equality of the JCS-canonicalised wire body across SDKs (VAL-W4-020
extended to the gate_decision_draft envelope).

The canonical shape mirrors ``envelopes.yaml::GateDecisionDraft``
(``packages/schemas/raw/envelopes.yaml:122``):

  * ``scope_id`` (== ``gate_id``) is ALWAYS present.
  * ``worker_id``, ``scope_type``, ``round``, ``evidence_refs`` are
    OPTIONAL on the SDK boundary and only emitted when the caller
    supplied them. The control plane enforces the canonical
    ``required: true`` constraint at the wire/storage layer.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from relay.lifecycle import build_gate_draft_envelope
from relay_schemas.envelopes import canonical_bytes

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE_PATH = (
    _REPO_ROOT
    / "tests"
    / "conformance"
    / "lifecycle"
    / "gate_draft_parity_fixtures.json"
)


def _load_corpus() -> dict[str, Any]:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.mark.plumbing
def test_gate_draft_parity_corpus_loaded() -> None:
    corpus = _load_corpus()
    assert corpus["schema_version"] == "relay.gate_draft_parity.v1"
    assert len(corpus["fixtures"]) >= 2


@pytest.mark.plumbing
def test_gate_draft_envelope_matches_canonical_fixture() -> None:
    """For every fixture, the Python builder emits the expected envelope."""
    corpus = _load_corpus()
    for fx in corpus["fixtures"]:
        inputs = dict(fx["inputs"])
        # Required fields:
        env = build_gate_draft_envelope(
            gate_id=inputs["gate_id"],
            release_sha=inputs["release_sha"],
            eval_run_ids=inputs["eval_run_ids"],
            manifest_commit_hash=inputs["manifest_commit_hash"],
            actor_identity_hash=inputs["actor_identity_hash"],
            draft_id=inputs.get("draft_id"),
            worker_id=inputs.get("worker_id"),
            scope_type=inputs.get("scope_type"),
            round=inputs.get("round"),
            evidence_refs=inputs.get("evidence_refs"),
        )
        assert env == fx["expected_envelope"], (
            f"fixture {fx['name']!r} -- Python builder output diverges from "
            f"canonical expected envelope.\n"
            f"  expected: {fx['expected_envelope']!r}\n"
            f"  actual:   {env!r}"
        )


@pytest.mark.plumbing
def test_gate_draft_envelope_jcs_bytes_are_deterministic() -> None:
    """Two builds of the same input produce byte-identical JCS bytes.

    Cross-language byte-equality is the load-bearing acceptance
    criterion (CLAUDE.md keystone invariant #10 + spec VAL-W4-020).
    """
    corpus = _load_corpus()
    for fx in corpus["fixtures"]:
        inputs = dict(fx["inputs"])
        kwargs: dict[str, Any] = {
            "gate_id": inputs["gate_id"],
            "release_sha": inputs["release_sha"],
            "eval_run_ids": inputs["eval_run_ids"],
            "manifest_commit_hash": inputs["manifest_commit_hash"],
            "actor_identity_hash": inputs["actor_identity_hash"],
            "draft_id": inputs.get("draft_id"),
        }
        for opt in ("worker_id", "scope_type", "round", "evidence_refs"):
            if opt in inputs:
                kwargs[opt] = inputs[opt]
        first = canonical_bytes(build_gate_draft_envelope(**kwargs))
        second = canonical_bytes(build_gate_draft_envelope(**kwargs))
        assert first == second, (
            f"fixture {fx['name']!r}: JCS bytes diverged across builds"
        )
        # Sanity: the canonical bytes also match canonical_bytes of the
        # expected envelope -- if they don't, the fixture is stale.
        assert first == canonical_bytes(fx["expected_envelope"]), (
            f"fixture {fx['name']!r}: builder output != fixture canonical "
            f"bytes (likely caused by drift between fixture and builder)."
        )


@pytest.mark.plumbing
def test_gate_draft_envelope_omits_canonical_write_fields() -> None:
    """The SDK MUST never set ``written_by`` or other canonical fields.

    CLAUDE.md keystone invariant #1: the control plane writes the result.
    """
    env = build_gate_draft_envelope(
        gate_id="gate-x",
        release_sha="rel-x",
        eval_run_ids=["e-1"],
        manifest_commit_hash="sha256-" + "m" * 64,
        actor_identity_hash="sha256-" + "a" * 64,
        worker_id="worker-1",
        scope_type="run",
        round=1,
    )
    for forbidden in (
        "written_by",
        "resolved_gate_decision_id",
        "draft_kind",
        "resolution_state",
        "decision",
        "action",
    ):
        assert forbidden not in env, (
            f"SDK leaked canonical-write field {forbidden!r} into draft envelope"
        )
