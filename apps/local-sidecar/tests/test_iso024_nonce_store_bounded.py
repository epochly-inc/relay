"""VAL-ISO-024: the authenticated nonce store MUST be bounded.

Defect (base commit c911607): each successful ``GET /health/nonce``
(authenticated by the correct ``X-Relay-Bearer-Digest``) inserts
``state._issued_nonces[nonce] = issued_at`` (health.py:122). Entries are only
ever removed when that exact nonce is later presented to ``GET /health`` (on
success, or on detected expiry). There is no periodic sweep, no max-size cap,
and no eviction of expired entries on the issue path: a client that keeps
requesting nonces without ever consuming them grows the dict by one entry per
call without bound -- an unauthenticated-prerequisite-free memory DoS for any
holder of the bearer digest.

Fix: on each issue, sweep entries whose ``(monotonic() - issued_at) >
nonce_ttl_s`` and cap the dict size (evict oldest) so a stuck client cannot
grow it without bound. A within-TTL nonce still validates.

These tests are RED at base commit c911607 and GREEN after the fix.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from relay_sidecar.health import (
    HealthState,
    _bearer_digest_of,
    _proof_of,
    build_app,
)

_TOKEN = "test-bearer-token-iso024"
_DIGEST = _bearer_digest_of(_TOKEN)


def _make_state(*, nonce_ttl_s: float) -> HealthState:
    return HealthState(
        port=49999,
        bearer_token=_TOKEN,
        bearer_token_digest=_DIGEST,
        nonce_ttl_s=nonce_ttl_s,
    )


@pytest.mark.plumbing
def test_expired_nonces_swept_on_issue(monkeypatch) -> None:
    """Issuing many nonces past their TTL leaves the store bounded.

    Base-commit defect: each issue appends an entry and nothing reclaims
    expired ones on the issue path, so the dict grows by one per call. With
    the fix, expired entries are swept on each issue so the store does not
    grow without bound when every prior nonce has aged out.
    """
    import relay_sidecar.health as health_mod

    # Drive monotonic time deterministically.
    clock = {"now": 1000.0}
    monkeypatch.setattr(health_mod.time, "monotonic", lambda: clock["now"])

    state = _make_state(nonce_ttl_s=5.0)
    app = build_app(state)
    client = TestClient(app)

    # Issue 200 nonces, advancing the clock by 10s (> TTL) between each so
    # every previously-issued nonce is expired by the time the next is issued.
    for _ in range(200):
        resp = client.get(
            "/health/nonce", headers={"X-Relay-Bearer-Digest": _DIGEST}
        )
        assert resp.status_code == 200, resp.text
        clock["now"] += 10.0

    # With per-issue sweeping, at most a handful of entries survive (the most
    # recently issued one, whose age is 0). It MUST NOT have grown to 200.
    assert len(state._issued_nonces) < 200, (
        "expired nonces must be swept on the issue path; the store grew "
        f"unbounded to {len(state._issued_nonces)} entries"
    )
    assert len(state._issued_nonces) <= 2, len(state._issued_nonces)


@pytest.mark.plumbing
def test_nonce_store_capped_for_stuck_client(monkeypatch) -> None:
    """A client issuing many WITHIN-TTL nonces cannot grow the store without
    bound; the dict is capped (oldest evicted).

    Base-commit defect: no max-size cap, so a client that issues thousands of
    nonces inside the TTL window (never consuming them) grows the dict to that
    many entries. With the fix the dict size is capped.
    """
    import relay_sidecar.health as health_mod

    clock = {"now": 1000.0}
    monkeypatch.setattr(health_mod.time, "monotonic", lambda: clock["now"])

    # Large TTL so none expire during the burst -> only the cap can bound it.
    state = _make_state(nonce_ttl_s=10_000.0)
    app = build_app(state)
    client = TestClient(app)

    for _ in range(5000):
        resp = client.get(
            "/health/nonce", headers={"X-Relay-Bearer-Digest": _DIGEST}
        )
        assert resp.status_code == 200, resp.text
        clock["now"] += 0.001  # tiny advance, all within TTL

    assert len(state._issued_nonces) < 5000, (
        "within-TTL nonce store must be capped; it grew to "
        f"{len(state._issued_nonces)} entries"
    )


@pytest.mark.plumbing
def test_within_ttl_nonce_still_validates(monkeypatch) -> None:
    """A freshly issued, within-TTL nonce still verifies on /health.

    Guards against over-eviction: the sweep/cap must not drop a live nonce
    that the client is about to present.
    """
    import relay_sidecar.health as health_mod

    clock = {"now": 1000.0}
    monkeypatch.setattr(health_mod.time, "monotonic", lambda: clock["now"])

    state = _make_state(nonce_ttl_s=5.0)
    app = build_app(state)
    client = TestClient(app)

    issue = client.get(
        "/health/nonce", headers={"X-Relay-Bearer-Digest": _DIGEST}
    )
    assert issue.status_code == 200, issue.text
    nonce = issue.json()["nonce"]

    # Advance well within TTL.
    clock["now"] += 1.0
    proof = _proof_of(nonce, _TOKEN)
    resp = client.get(
        "/health",
        headers={
            "X-Relay-Bearer-Digest": _DIGEST,
            "X-Relay-Nonce": nonce,
            "X-Relay-Nonce-Proof": proof,
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is True
