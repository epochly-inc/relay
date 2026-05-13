"""VAL-W2-008: ``/health`` nonce challenge proves process identity.

Replay of a captured nonce >5s later -> 401 ``RELAY-SIDECAR-NONCE-EXPIRED``.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from relay_sidecar.errors import (
    RELAY_SIDECAR_AUTH_MISMATCH,
    RELAY_SIDECAR_NONCE_EXPIRED,
    RELAY_SIDECAR_NONCE_EXPIRED_CODE,
)
from relay_sidecar.health import (
    HealthState,
    _bearer_digest_of,
    _proof_of,
    build_app,
)


def _make_client(nonce_ttl_s: float = 5.0) -> tuple[TestClient, HealthState]:
    token = "test-nonce-token-fixed"  # noqa: S105 (test token)
    state = HealthState(
        port=49998,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
        nonce_ttl_s=nonce_ttl_s,
    )
    return TestClient(build_app(state)), state


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-008")
def test_nonce_round_trip_succeeds_within_ttl() -> None:
    client, state = _make_client()
    issue = client.get(
        "/health/nonce",
        headers={"X-Relay-Bearer-Digest": state.bearer_token_digest},
    )
    assert issue.status_code == 200
    nonce = issue.json()["nonce"]
    proof = _proof_of(nonce, state.bearer_token)

    resp = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": state.bearer_token_digest,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": proof,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-008")
def test_nonce_replay_after_ttl_returns_expired() -> None:
    # Use a tiny TTL so the test runs quickly.
    client, state = _make_client(nonce_ttl_s=0.05)
    issue = client.get(
        "/health/nonce",
        headers={"X-Relay-Bearer-Digest": state.bearer_token_digest},
    )
    assert issue.status_code == 200
    nonce = issue.json()["nonce"]
    proof = _proof_of(nonce, state.bearer_token)

    # Wait past the TTL.
    time.sleep(0.2)

    resp = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": state.bearer_token_digest,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": proof,
        },
    )
    assert resp.status_code == 401
    detail = resp.json()["detail"]
    assert detail["code"] == RELAY_SIDECAR_NONCE_EXPIRED_CODE
    assert detail["error_class"] == RELAY_SIDECAR_NONCE_EXPIRED


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-008")
def test_nonce_one_shot_replay_evicts() -> None:
    """A successfully-verified nonce cannot be reused even within TTL."""
    client, state = _make_client()
    issue = client.get(
        "/health/nonce",
        headers={"X-Relay-Bearer-Digest": state.bearer_token_digest},
    )
    nonce = issue.json()["nonce"]
    proof = _proof_of(nonce, state.bearer_token)
    # First use: success.
    r1 = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": state.bearer_token_digest,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": proof,
        },
    )
    assert r1.status_code == 200
    # Replay: the same nonce now produces NONCE-EXPIRED.
    r2 = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": state.bearer_token_digest,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": proof,
        },
    )
    assert r2.status_code == 401
    assert r2.json()["detail"]["code"] == RELAY_SIDECAR_NONCE_EXPIRED_CODE


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-008")
def test_nonce_bad_proof_returns_mismatch() -> None:
    client, state = _make_client()
    issue = client.get(
        "/health/nonce",
        headers={"X-Relay-Bearer-Digest": state.bearer_token_digest},
    )
    nonce = issue.json()["nonce"]
    resp = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": state.bearer_token_digest,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": "deadbeef" * 8,
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["error_class"] == RELAY_SIDECAR_AUTH_MISMATCH
