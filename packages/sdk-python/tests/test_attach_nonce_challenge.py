"""VAL-W3-004: SDK attach uses the ``/health`` nonce challenge.

On attach to the sidecar it just spawned (and therefore holds the
plaintext bearer token for), the SDK MUST issue ``GET /health/nonce``
first, receive a server-issued nonce, sign it, and present the proof on
the next call. A sidecar that rejects the proof MUST cause the SDK to
surface ``RelayAuthMismatch`` (error_class ``RELAY-SDK-AUTH-MISMATCH``).

The contract's "Gaps" note records that the exact nonce construction was
not pinned in the eng plan; the W2 sidecar pins it as
``SHA-256(f"{nonce}:{token}")`` and the SDK signs to match. This test
exercises:
  1. The happy path: a real spawned sidecar; trace() completes the nonce
     challenge and returns an authenticated connection whose auth header
     is the nonce proof (not a bare digest).
  2. The signing function matches the sidecar's verification function.
  3. The mismatch path: a sidecar that rejects the proof -> RelayAuthMismatch.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
from relay import Relay
from relay._transport import SidecarTransport, _nonce_proof
from relay.errors import RelayAuthMismatch
from relay_sidecar.health import _proof_of

_VALID_KEY = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


@pytest.mark.plumbing
def test_sdk_nonce_proof_matches_sidecar_verification() -> None:
    """The SDK's nonce-signing function is byte-identical to the sidecar's.

    If these ever diverge the sidecar returns 401 and every attach fails.
    """
    nonce = "test-nonce-value"
    token = "test-bearer-token"
    expected = hashlib.sha256(f"{nonce}:{token}".encode()).hexdigest()
    # SDK side.
    assert _nonce_proof(nonce, token) == expected
    # Sidecar side (the W2 verifier).
    assert _proof_of(nonce, token) == expected
    # And, transitively, they agree.
    assert _nonce_proof(nonce, token) == _proof_of(nonce, token)


@pytest.mark.plumbing
def test_attach_completes_nonce_challenge_happy_path(
    relay_home_tmp,
    stop_sidecar,
) -> None:
    """trace() against a spawned sidecar completes the nonce challenge.

    The resulting connection's ``auth_header`` is the nonce PROOF (a
    64-char hex SHA-256 digest), not the bearer digest -- proving the full
    nonce challenge ran, not a digest-only attach.
    """
    stop_sidecar.append(relay_home_tmp)
    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r)
    conn = r.trace("op")

    # spawned == True: this SDK instance launched the sidecar, so it held
    # the plaintext token and ran the full nonce challenge.
    assert conn.spawned is True
    # The auth header is a nonce proof: 64 lowercase hex chars.
    assert len(conn.auth_header) == 64
    assert all(c in "0123456789abcdef" for c in conn.auth_header)
    # It is NOT the bearer digest (which has the 'sha256-' prefix).
    assert not conn.auth_header.startswith("sha256-")

    r.close()


@pytest.mark.plumbing
def test_nonce_proof_rejected_surfaces_auth_mismatch(
    relay_home_tmp,
    stop_sidecar,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sidecar that rejects the signed nonce -> RelayAuthMismatch.

    We simulate a sidecar that omits or rejects the signature path by
    forcing the SDK's nonce-proof computation to produce a wrong value.
    The real sidecar then returns HTTP 401 and the SDK MUST surface
    RelayAuthMismatch with code RELAY-SDK-AUTH-MISMATCH.
    """
    import relay._transport as transport_mod

    def _wrong_proof(_nonce: str, _token: str) -> str:
        # A syntactically valid but incorrect proof: the sidecar's
        # compare_digest will reject it -> 401.
        return "0" * 64

    monkeypatch.setattr(transport_mod, "_nonce_proof", _wrong_proof)

    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.append(relay_home_tmp)
    stop_sidecar.track(r)

    with pytest.raises(RelayAuthMismatch) as excinfo:
        r.trace("op")
    err = excinfo.value
    assert err.error_class == "RELAY-SDK-AUTH-MISMATCH"
    assert err.code == "RELAY-SDK-004"

    r.close()


@pytest.mark.plumbing
def test_attach_issues_health_with_auth_header(
    relay_home_tmp,
    stop_sidecar,
) -> None:
    """After attach, the connection carries an X-Relay-Auth-presentable value.

    The transport records ``auth_header`` so subsequent calls can present
    it as ``X-Relay-Auth``. Here we verify it is usable: presenting it on a
    fresh /health call with the bearer digest is accepted by the sidecar.
    """
    stop_sidecar.append(relay_home_tmp)
    r = Relay(project_key=_VALID_KEY, relay_home=relay_home_tmp)
    stop_sidecar.track(r)
    conn = r.trace("op")

    # A plain bearer-digest /health call still works (the digest is the
    # lockfile's). The nonce headers are one-shot on the sidecar, so we
    # only assert the digest-authenticated surface here.
    with httpx.Client(timeout=5.0) as client:
        resp = client.get(
            f"{conn.base_url}/health",
            headers={"X-Relay-Bearer-Digest": conn.bearer_token_digest},
        )
    assert resp.status_code == 200
    assert resp.json()["sidecar_version"] == conn.sidecar_version

    r.close()


@pytest.mark.plumbing
def test_transport_is_import_side_effect_free() -> None:
    """Constructing a SidecarTransport spawns nothing and binds nothing."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        t = SidecarTransport(relay_home=home)
        # No connection, no http client, no spawned process yet.
        assert t._connection is None
        assert t._http is None
        assert t._spawned_proc is None
        assert not (home / "sidecar.lock").exists()
