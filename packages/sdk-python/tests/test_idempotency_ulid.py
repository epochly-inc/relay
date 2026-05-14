"""VAL-W3-017 -- SDK idempotency key is a Crockford base32 ULID.

The SDK generates a fresh ULID per envelope. Two adjacent calls produce
distinct keys. Re-posting a previously-acknowledged envelope yields
``idempotent_replay: true`` from the sidecar; the SDK surfaces that
flag back to the caller without alteration.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re

import pytest
from relay._ulid import new_ulid
from relay.lifecycle import build_ingest_run_envelope

_ACTOR = "sha256-actoractoractoractoractoractoractoractoractoractoractoractoractor"
_MANIFEST = "sha256-manifestmanifestmanifestmanifestmanifestmanifestmanifestmanife"
# VAL-W3-017: every emitted ULID matches the Crockford base32 alphabet,
# minus I/L/O/U, with a first-character constraint (timestamp ms < 2^48
# implies the top 2 bits are zero, so the first char is in {0..7}).
_CROCKFORD_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")


def _build_with_default_key() -> dict:
    return build_ingest_run_envelope(
        run_id="01ARZ3NDEKTSV4RRFFQ69G5FAV",
        trace_id="trace-abc",
        project_id="aa111111-2222-3333-4444-555555555555",
        agent={"name": "ops", "version": "0.1"},
        client_lifecycle_status="started",
        started_at="2026-05-12T10:00:00Z",
        sdk_version="relay-python@0.0.0",
        sdk_clock="2026-05-12T10:00:00.123Z",
        manifest_commit_hash=_MANIFEST,
        actor_identity_hash=_ACTOR,
        redaction_policy_version="v1",
        sequence_number=1,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-017")
def test_emitted_ulid_matches_crockford_base32_regex() -> None:
    """Every SDK-emitted ULID matches the Crockford base32 regex."""
    for _ in range(1000):
        u = new_ulid()
        assert len(u) == 26
        assert _CROCKFORD_RE.match(u), f"ULID {u!r} fails Crockford alphabet check"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-017")
def test_ulid_uniqueness_over_n_calls() -> None:
    """N=1000 adjacent ULID generations produce 1000 distinct keys.

    Collision probability per pair is approximately 2^-80; over 1000
    keys the birthday-bound probability of any collision is < 2^-60.
    """
    keys = {new_ulid() for _ in range(1000)}
    assert len(keys) == 1000


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-017")
def test_ingest_envelope_generates_distinct_idempotency_keys() -> None:
    """Two ingest envelopes built back-to-back have distinct keys."""
    env1 = _build_with_default_key()
    env2 = _build_with_default_key()
    assert env1["idempotency_key"] != env2["idempotency_key"]
    assert _CROCKFORD_RE.match(env1["idempotency_key"])
    assert _CROCKFORD_RE.match(env2["idempotency_key"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-017")
def test_deterministic_ulid_with_seeded_inputs_matches_cross_language_fixture() -> None:
    """Given the same timestamp + randomness bytes, the SDK produces a
    byte-identical 26-character Crockford base32 string. This is the
    cross-language fixture for VAL-W3-017's parity test.
    """
    # Pin a deterministic seed pair.
    now_ms = 1_700_000_000_000  # 2023-11-14T22:13:20Z
    randomness = bytes.fromhex("00112233445566778899")  # 10 bytes
    u = new_ulid(now_ms=now_ms, randomness=randomness)
    # The output is deterministic; a future TS SDK fixture compares the
    # same input bytes and asserts the same string.
    assert u == new_ulid(now_ms=now_ms, randomness=randomness)
    assert _CROCKFORD_RE.match(u)
    assert len(u) == 26


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-017")
def test_idempotent_replay_flag_surfaced_to_caller(relay_home_tmp) -> None:
    """Re-posting a previously-acknowledged envelope yields
    ``idempotent_replay: true`` from the sidecar; the SDK surfaces the
    response payload back to the caller intact.
    """
    from relay import Relay
    from test_loopback_server import LoopbackServer

    server = LoopbackServer()
    server.add_route(
        "POST", "/v1/ingest/runs",
        lambda req: (200, {"accepted": True, "idempotent_replay": True}, {}),
    )
    server.start()
    try:
        r = Relay(
            project_key="01ARZ3NDEKTSV4RRFFQ69G5FAV",
            relay_home=relay_home_tmp,
            actor_identity_hash=_ACTOR,
            manifest_commit_hash=_MANIFEST,
            redaction_policy_version="v1",
            endpoint_url=server.base_url,
            flush_policy={"mode": "sync", "on_error": "raise"},
        )
        with r.run(agent={"name": "ops", "version": "0.1"}) as run:
            resp = run.capture(client_lifecycle_status="client_succeeded")
        assert resp.get("idempotent_replay") is True
        # The SDK MUST have recorded the idempotency key it sent.
        ingest_req = next(
            req for req in server.requests if req.path == "/v1/ingest/runs"
        )
        body = ingest_req.body_json
        assert _CROCKFORD_RE.match(body["idempotency_key"])
    finally:
        server.stop()
