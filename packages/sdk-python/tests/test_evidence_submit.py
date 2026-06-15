"""VAL-W3-015 -- SDK evidence submit is bound to its claim.

Per CLAUDE.md keystone invariant #2 a pass without paired evidence is
``invalid``, not ``accepted``. The SDK's evidence submit envelope MUST
include every required binding field. A missing field is rejected at
the SDK boundary BEFORE the request is sent.

Required binding fields (spec K):
  - artifact_digest_sha256
  - command_id
  - exit_code
  - span_ids (>= 1)
  - assertion_ids (>= 1)
  - actor_identity_hash
  - manifest_commit_hash
  - redaction_policy_version

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import Relay, RelayEvidenceIncomplete
from relay.lifecycle import build_evidence_envelope

# Sibling test helper resolved at runtime via pytest's `prepend` import
# mode (the tests dir is on sys.path); pyright does not model that.
from test_loopback_server import LoopbackServer  # pyright: ignore[reportMissingImports]

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"


def _good_kwargs() -> dict:
    return dict(
        run_id="01JG2YRUN0123456789ABCDEFG",
        artifact_digest_sha256="sha256-deadbeef" + "0" * 56,
        command_id="cmd-test-tier-1",
        exit_code=0,
        span_ids=["span-1"],
        assertion_ids=["VAL-W3-015"],
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
    )


@pytest.fixture
def server():
    s = LoopbackServer()
    s.start()
    try:
        yield s
    finally:
        s.stop()


# --- happy path -------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-015")
def test_evidence_envelope_includes_every_binding_field() -> None:
    """A well-formed envelope contains every required binding field."""
    env = build_evidence_envelope(**_good_kwargs())
    for required in (
        "artifact_digest_sha256",
        "command_id",
        "exit_code",
        "span_ids",
        "assertion_ids",
        "actor_identity_hash",
        "manifest_commit_hash",
        "redaction_policy_version",
    ):
        assert required in env, f"required field {required!r} missing from envelope"
    assert env["exit_code"] == 0
    assert env["span_ids"] == ["span-1"]
    assert env["schema_version"] == "relay.evidence_submit.v1"


# --- per-field absence raises at SDK boundary -------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-015")
@pytest.mark.parametrize(
    "missing_field, override",
    [
        ("artifact_digest_sha256", {"artifact_digest_sha256": ""}),
        ("artifact_digest_sha256", {"artifact_digest_sha256": None}),
        ("command_id", {"command_id": ""}),
        ("exit_code", {"exit_code": None}),
        ("span_ids", {"span_ids": []}),
        ("span_ids", {"span_ids": None}),
        ("assertion_ids", {"assertion_ids": []}),
        ("assertion_ids", {"assertion_ids": None}),
        ("redaction_policy_version", {"redaction_policy_version": ""}),
    ],
)
def test_evidence_envelope_missing_field_rejected_at_sdk_boundary(
    missing_field: str, override: dict
) -> None:
    kwargs = _good_kwargs()
    kwargs.update(override)
    with pytest.raises(RelayEvidenceIncomplete) as excinfo:
        build_evidence_envelope(**kwargs)
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-EVIDENCE-INCOMPLETE"
    assert err.code == "RELAY-SDK-008"
    # The error names the offending field.
    assert err.details.get("field") == missing_field or any(
        missing_field in str(v) for v in err.details.values()
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-015")
def test_evidence_submit_sends_complete_envelope(
    server, relay_home_tmp
) -> None:
    """run.submit_evidence sends a complete, well-bound envelope.

    Finding #9: the SDK MUST POST the contract route
    ``/v1/evidence-bundles`` (apps/local-sidecar runtime.py:4815,
    packages/schemas/raw/openapi.yaml:873, TS run.ts:410). The earlier
    ``/v1/evidence`` path was unrouted on the real sidecar and 404'd.
    """
    server.add_route(
        "POST", "/v1/evidence-bundles",
        lambda req: (200, {"accepted": True, "claim_id": "01JG2YCLAIM01234567890"}, {}),
    )

    r = Relay(
        project_key=_VALID_KEY,
        relay_home=relay_home_tmp,
        actor_identity_hash=_ACTOR,
        manifest_commit_hash=_MANIFEST,
        redaction_policy_version="v1",
        endpoint_url=server.base_url,
        flush_policy={"mode": "sync", "on_error": "drop_and_log"},
    )
    with r.run(
        run_id="01JG2YRUN0123456789ABCDEFG",
        agent={"name": "evi-agent", "version": "0.1"},
    ) as run:
        resp = run.submit_evidence(
            artifact_digest_sha256="sha256-deadbeef" + "0" * 56,
            command_id="cmd-test",
            exit_code=0,
            span_ids=["span-1"],
            assertion_ids=["VAL-W3-015"],
        )

    assert resp == {"accepted": True, "claim_id": "01JG2YCLAIM01234567890"}
    # Finding #9: contract route is /v1/evidence-bundles, not /v1/evidence.
    assert ("POST", "/v1/evidence-bundles") in [
        (req.method, req.path) for req in server.requests
    ]
    assert ("POST", "/v1/evidence") not in [
        (req.method, req.path) for req in server.requests
    ]
    evidence_req = next(
        req for req in server.requests if req.path == "/v1/evidence-bundles"
    )
    body = evidence_req.body_json
    # Every required field is present and bound.
    assert body["run_id"] == "01JG2YRUN0123456789ABCDEFG"
    assert body["artifact_digest_sha256"].startswith("sha256-deadbeef")
    assert body["exit_code"] == 0
    assert body["span_ids"] == ["span-1"]
    assert body["assertion_ids"] == ["VAL-W3-015"]
    assert body["manifest_commit_hash"] == _MANIFEST
    assert body["actor_identity_hash"] == _ACTOR
    assert body["redaction_policy_version"] == "v1"
    # The SDK does NOT write the canonical decision fields.
    assert "status" not in body
    assert "written_by" not in body
