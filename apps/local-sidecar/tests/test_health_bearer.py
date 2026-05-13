"""VAL-W2-007: ``/health`` returns 200 with bearer-digest match.

A digest mismatch -> HTTP 401 ``RELAY-SIDECAR-AUTH-MISMATCH``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from relay_sidecar import __version__
from relay_sidecar.errors import (
    RELAY_SIDECAR_AUTH_MISMATCH,
    RELAY_SIDECAR_AUTH_MISMATCH_CODE,
)
from relay_sidecar.health import HealthState, _bearer_digest_of, build_app


@pytest.fixture
def app_and_state() -> tuple[TestClient, HealthState]:
    token = "test-bearer-token-fixed-for-test"  # noqa: S105 (test token)
    state = HealthState(
        port=49999,
        bearer_token=token,
        bearer_token_digest=_bearer_digest_of(token),
    )
    app = build_app(state)
    return TestClient(app), state


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-007")
def test_health_returns_200_with_matching_digest(
    app_and_state: tuple[TestClient, HealthState],
) -> None:
    client, state = app_and_state
    response = client.get(
        "/health",
        headers={"X-Relay-Bearer-Digest": state.bearer_token_digest},
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "ok": True,
        "port": state.port,
        "sidecar_version": __version__,
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-007")
def test_health_returns_401_on_digest_mismatch(
    app_and_state: tuple[TestClient, HealthState],
) -> None:
    client, _ = app_and_state
    response = client.get(
        "/health",
        headers={"X-Relay-Bearer-Digest": "sha256-" + "f" * 64},
    )
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["code"] == RELAY_SIDECAR_AUTH_MISMATCH_CODE
    assert detail["error_class"] == RELAY_SIDECAR_AUTH_MISMATCH


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-007")
def test_health_returns_401_on_missing_digest_header(
    app_and_state: tuple[TestClient, HealthState],
) -> None:
    client, _ = app_and_state
    response = client.get("/health")
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["code"] == RELAY_SIDECAR_AUTH_MISMATCH_CODE
