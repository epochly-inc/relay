"""VAL-W3-013 -- run.gate_evaluate submits a draft and reads the canonical
decision.

Per CLAUDE.md keystone invariant #1 and spec line 2192-2252 the SDK
NEVER computes the gate decision itself. It POSTs an evidence-only
``GateDecisionDraft`` to the sidecar, then GETs the canonical
``GateDecision`` row the control plane wrote. The SDK's returned
decision MUST be byte-identical to what the control plane wrote.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import Relay

# Sibling test helper resolved at runtime via pytest's `prepend` import
# mode (the tests dir is on sys.path); pyright does not model that.
from test_loopback_server import LoopbackServer  # pyright: ignore[reportMissingImports]

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"


@pytest.fixture
def server():
    s = LoopbackServer()
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-013")
def test_gate_evaluate_submits_draft_then_reads_canonical(
    server, relay_home_tmp
) -> None:
    """SDK posts a draft envelope, the sidecar returns decision_id, the
    SDK GETs the canonical decision and returns it. The SDK NEVER
    computes pass/fail itself.
    """
    # Scripted sidecar:
    #   1) POST /v1/gates/{gate_id}/drafts -> 200 + {decision_id}
    #   2) GET  /v1/gate-decisions/{decision_id} -> the canonical row,
    #      signed by the control plane.
    canonical_decision = {
        "schema_version": "relay.gate_decision.v1",
        "gate_decision_id": "01JG2YGATEDECISIONABCDEFGH",
        "action": "accept",
        "round": 1,
        "failed_assertions": [],
        "evidence_bundle_id": "01JG2YEVIDENCEBUNDLEABCDEF",
        "signature": "sig-sealed-by-control-plane",
        "written_by": "control_plane",  # READ-ONLY: SDK observes this; never writes.
    }

    server.add_route(
        "POST", "/v1/gates/release-gate-v1/drafts",
        lambda req: (200, {"decision_id": canonical_decision["gate_decision_id"]}, {}),
    )
    server.add_route(
        "GET", f"/v1/gate-decisions/{canonical_decision['gate_decision_id']}",
        lambda req: (200, canonical_decision, {}),
    )

    r = Relay(
        project_key=_VALID_KEY,
        relay_home=relay_home_tmp,
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
        endpoint_url=server.base_url,
        # Post-exit lifecycle flush hits /v1/ingest/runs which is not
        # registered on these test servers; drop_and_log keeps the test
        # focused on the gate-evaluate surface without leaking the
        # 404 into the assertion path.
        flush_policy={"mode": "sync", "on_error": "drop_and_log"},
    )
    with r.run(agent={"name": "ci-agent", "version": "1.0"}) as run:
        decision = run.gate_evaluate(
            gate_id="release-gate-v1",
            release_sha="abc123",
            eval_run_ids=["eval-run-1", "eval-run-2"],
        )

    # The decision the SDK returns IS the canonical row, byte-identical.
    assert decision == canonical_decision
    # The SDK saw both endpoints in order: draft POST first, decision GET second.
    paths = [(req.method, req.path) for req in server.requests]
    assert ("POST", "/v1/gates/release-gate-v1/drafts") in paths
    assert (
        "GET",
        f"/v1/gate-decisions/{canonical_decision['gate_decision_id']}",
    ) in paths
    # Order: draft submission MUST precede canonical read.
    draft_idx = paths.index(("POST", "/v1/gates/release-gate-v1/drafts"))
    decision_idx = paths.index(
        ("GET", f"/v1/gate-decisions/{canonical_decision['gate_decision_id']}")
    )
    assert draft_idx < decision_idx


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-013")
def test_gate_evaluate_draft_carries_three_anchor_handoff(
    server, relay_home_tmp
) -> None:
    """The submitted draft envelope MUST carry actor_identity_hash and
    manifest_commit_hash. The SDK does NOT write written_by.
    """
    server.add_route(
        "POST", "/v1/gates/g1/drafts",
        lambda req: (200, {"decision_id": "01JG2YDECISIONFGHJKMNPQRST"}, {}),
    )
    server.add_route(
        "GET", "/v1/gate-decisions/01JG2YDECISIONFGHJKMNPQRST",
        lambda req: (200, {"action": "accept"}, {}),
    )

    r = Relay(
        project_key=_VALID_KEY,
        relay_home=relay_home_tmp,
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
        endpoint_url=server.base_url,
        # Post-exit lifecycle flush hits /v1/ingest/runs which is not
        # registered on these test servers; drop_and_log keeps the test
        # focused on the gate-evaluate surface without leaking the
        # 404 into the assertion path.
        flush_policy={"mode": "sync", "on_error": "drop_and_log"},
    )
    with r.run(agent={"name": "ci-agent", "version": "1.0"}) as run:
        run.gate_evaluate(
            gate_id="g1", release_sha="abc", eval_run_ids=["e1"]
        )

    draft_req = next(
        req for req in server.requests if req.path == "/v1/gates/g1/drafts"
    )
    body = draft_req.body_json
    assert body["actor_identity_hash"] == _ACTOR
    assert body["manifest_commit_hash"] == _MANIFEST
    # Critical: SDK never writes written_by.
    assert "written_by" not in body
    # Critical: the SDK submits a draft, not a finished decision.
    assert "decision_id" not in body
    assert body["schema_version"] == "relay.gate_decision_draft.v1"
