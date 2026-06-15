"""VAL-W3-014 -- run.replay_create requires canonical RunResult.

Per spec line 2122-2178 the SDK's replay creation path MUST first fetch
the canonical ``run_result`` row. If the run is still in flight (no
``run_result`` yet) the sidecar returns ``RELAY-REPLAY-002`` and the
SDK raises ``RelayReplayPrecondition``. The SDK NEVER derives a replay
case from raw SDK lifecycle metadata.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay import Relay, RelayReplayPrecondition

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
@pytest.mark.fulfills("VAL-W3-014")
def test_replay_create_refuses_when_run_result_not_yet_written(
    server, relay_home_tmp
) -> None:
    """The sidecar reports the run is still in flight (RELAY-REPLAY-002);
    the SDK MUST raise RelayReplayPrecondition and NOT proceed to the
    replay-case create endpoint.
    """
    server.add_route(
        "GET", "/v1/runs/01JG2YINFLIGHT01234567890123/result",
        lambda req: (
            412,
            {
                "schema_version": "relay.error.v1",
                "code": "RELAY-REPLAY-002",
                "error_class": "RUN-RESULT-NOT-YET-WRITTEN",
                "message": "run_result not yet written; cannot derive replay case",
                "retry_advice": {"mode": "after_state_change"},
                "details": {"run_id": "01JG2YINFLIGHT01234567890123"},
            },
            {},
        ),
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
    with (
        r.run(agent={"name": "replay-agent", "version": "0.1"}) as run,
        pytest.raises(RelayReplayPrecondition) as excinfo,
    ):
        run.replay_create(run_id="01JG2YINFLIGHT01234567890123")
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-REPLAY-PRECONDITION"
    assert err.code == "RELAY-SDK-009"

    # The SDK MUST have observed the GET /v1/runs/{run_id}/result endpoint
    # (the canonical precondition fetch). It MUST NOT have proceeded to
    # the replay-case run endpoint (no POST to any /v1/replay-cases/.../run
    # path), and it MUST NOT use the legacy unrouted /v1/runs/.../replays
    # path (finding #10; contract route is POST /v1/replay-cases/{case_id}/run
    # per runtime.py:2798, openapi.yaml:552, TS run.ts:424).
    paths = [(req.method, req.path) for req in server.requests]
    assert (
        "GET", "/v1/runs/01JG2YINFLIGHT01234567890123/result"
    ) in paths
    assert (
        "POST", "/v1/runs/01JG2YINFLIGHT01234567890123/replays"
    ) not in paths
    assert not any(
        method == "POST"
        and path.startswith("/v1/replay-cases/")
        and path.endswith("/run")
        for method, path in paths
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-014")
def test_replay_create_proceeds_when_run_result_is_canonical(
    server, relay_home_tmp
) -> None:
    """When the canonical run_result IS present, the SDK proceeds to the
    contract route POST /v1/replay-cases/{case_id}/run AND returns the
    response.

    Finding #10: the legacy POST /v1/runs/{run_id}/replays path is
    unrouted on the real sidecar. Replay-case execution is
    POST /v1/replay-cases/{case_id}/run (runtime.py:2798,
    openapi.yaml:552), which the TS SDK also targets (run.ts:424). The
    SDK generates the case_id client-side (parity with TS
    ``replayCreate({caseId})``); the caller may also pass it explicitly.
    """
    case_id = "01JG2YREPLAYCASE0123456789AB"
    canonical_result = {
        "schema_version": "relay.run_result.v1",
        "run_result_id": "01JG2YRR01234567890123ABCDEF",
        "run_id": "01JG2YCOMPLETED1234567890123",
        "status": "blocked",
        "primary_failure_class": "STRUCTURED_OUTPUT_INVALID",
        "written_by": "control_plane",
    }
    replay_result = {
        "schema_version": "relay.replay_result.v1",
        "replay_result_id": "01JG2YREPLAYRESULT012345678",
        "case_id": case_id,
        "outcome": "pending",
        "written_by": "control_plane",
    }
    server.add_route(
        "GET", "/v1/runs/01JG2YCOMPLETED1234567890123/result",
        lambda req: (200, canonical_result, {}),
    )
    server.add_route(
        "POST", f"/v1/replay-cases/{case_id}/run",
        lambda req: (202, replay_result, {}),
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
    with r.run(agent={"name": "replay-agent", "version": "0.1"}) as run:
        out = run.replay_create(
            run_id="01JG2YCOMPLETED1234567890123", case_id=case_id
        )

    assert out == replay_result
    # The SDK MUST have issued the contract run route and MUST NOT have
    # used the legacy unrouted /v1/runs/{run_id}/replays path.
    paths = [(req.method, req.path) for req in server.requests]
    assert ("POST", f"/v1/replay-cases/{case_id}/run") in paths
    assert (
        "POST", "/v1/runs/01JG2YCOMPLETED1234567890123/replays"
    ) not in paths
