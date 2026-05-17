"""W10.4 TSA timestamp + transparency log verification tests.

Covers:
  * VAL-W10-025 (TSA missing)
  * VAL-W10-026 (TSA cert chain validation)
  * VAL-W10-027 (TSA genTime skew +/-300s)
  * VAL-W10-028 (log inclusion absent -> WARN)
  * VAL-W10-029 (witness signature mismatch -> WARN)
  * VAL-W10-030 (inclusion proof verified offline)

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier import (  # noqa: E402
    CLOCK_SKEW_TOLERANCE_SECONDS,
    RELAY_EVID_031,
    RELAY_EVID_038,
    ValidateBundleOptions,
    validate_bundle,
)

# ---------------------------------------------------------------------------
# VAL-W10-025: missing TSA timestamp -> RELAY-EVID-031
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-025")
def test_missing_tsa_token_rejected_with_evid_031() -> None:
    """A bundle whose tsa_token is absent MUST be rejected with
    RELAY-EVID-031 (not a warning)."""
    built = build_bundle(include_tsa=False)
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["overall"] == "fail"
    assert output["tsa_check"] == "missing"
    assert any(
        e["reason"] in ("tsa_missing", "tsa_invalid")
        and e.get("code") == RELAY_EVID_031
        for e in output["errors"]
    ), output["errors"]


# ---------------------------------------------------------------------------
# VAL-W10-026: TSA cert chain validation (tampered .tsr)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-026")
def test_tampered_tsa_imprint_produces_tsa_check_invalid() -> None:
    """A bundle whose tsa_token message_imprint digest is tampered MUST
    produce tsa_check='invalid'."""
    built = build_bundle()
    # Tamper with the message_imprint after construction so the digest
    # no longer matches the binding digest.
    built.bundle["tsa_token"]["message_imprint"][
        "hashed_message_hex"
    ] = "0" * 64

    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["tsa_check"] == "invalid"
    assert output["overall"] == "fail"


# ---------------------------------------------------------------------------
# VAL-W10-027: TSA genTime skew bounded at +/-300s
# ---------------------------------------------------------------------------


# w9-2 unblocked these tests: the cryptographic RFC 3161 verifier is now
# wired and the fixture builder produces a real TimeStampResp signed by an
# ephemeral test root. Tests pass that root via
# ValidateBundleOptions(tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem)
# so the SignerInfo signature verifies end-to-end.


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-027")
def test_tsa_gen_time_at_plus_300_accepted() -> None:
    """Exactly +300 s skew is accepted (boundary)."""
    built = build_bundle(tsa_skew_seconds=300)
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["tsa_check"] == "ok", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-027")
def test_tsa_gen_time_at_minus_300_accepted() -> None:
    """Exactly -300 s skew is accepted (boundary)."""
    built = build_bundle(tsa_skew_seconds=-300)
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["tsa_check"] == "ok", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-027")
def test_tsa_gen_time_at_plus_301_rejected_with_evid_038() -> None:
    """+301 s skew MUST be rejected with RELAY-EVID-038."""
    built = build_bundle(tsa_skew_seconds=301)
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["tsa_check"] == "skew"
    assert any(
        e.get("code") == RELAY_EVID_038 for e in output["errors"]
    ), output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-027")
def test_tsa_gen_time_at_minus_301_rejected_with_evid_038() -> None:
    """-301 s skew MUST be rejected with RELAY-EVID-038."""
    built = build_bundle(tsa_skew_seconds=-301)
    output = validate_bundle(bundle=built.bundle, jwks=built.jwks)
    assert output["tsa_check"] == "skew"
    assert any(
        e.get("code") == RELAY_EVID_038 for e in output["errors"]
    ), output["errors"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-027")
def test_single_source_clock_skew_constant_is_300_seconds() -> None:
    """The +/-300s constant MUST be a single shared symbol (the L.5 +
    AB single-source rule).
    """
    assert CLOCK_SKEW_TOLERANCE_SECONDS == 300


# ---------------------------------------------------------------------------
# VAL-W10-028: transparency log inclusion absent -> WARN, exit 0
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-028")
def test_log_inclusion_absent_produces_warn_not_fail() -> None:
    """A bundle without an inclusion proof MUST produce
    log_inclusion='absent' + a WARN; the bundle itself still verifies."""
    built = build_bundle(include_log_inclusion=False)
    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["log_inclusion"] == "absent"
    assert any(
        w["reason"] == "log_inclusion_absent" for w in output["warnings"]
    ), output["warnings"]
    # log absence alone does NOT fail; overall still pass (assuming all
    # other checks pass).
    assert output["overall"] == "pass", output


# ---------------------------------------------------------------------------
# VAL-W10-029: log witness signature mismatch -> WARN by default
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-029")
def test_log_witness_signature_mismatch_is_warn_not_fail_by_default() -> None:
    """A bundle with a structurally-valid proof but invalid witness
    signature MUST produce log_inclusion='witness_mismatch' + WARN.
    Default mode: bundle still verifies overall (exit 0).

    To exercise this in isolation, we supply a `witness_jwks` whose
    public key for the witness kid DIFFERS from the key that produced
    the witness signature -- so verify_log_inclusion's signature check
    fails while the outer JWS signature (against the bundle's main
    signing key) still verifies.
    """
    from relay_verifier import jwk_from_ed25519_public_key

    built = build_bundle()
    # Build an alternate witness JWKS with a DIFFERENT public key at
    # the same kid -- the witness signature won't verify against it.
    from conftest_w10_4 import make_keypair

    alt_witness_key = make_keypair(b"\x03" * 32)
    alt_witness_jwk = jwk_from_ed25519_public_key(
        alt_witness_key.public_key(), kid="witness-test-kid-1",
    )
    alt_witness_jwks = {"keys": [alt_witness_jwk]}

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            witness_jwks=alt_witness_jwks,
            tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
        ),
    )
    assert output["log_inclusion"] == "witness_mismatch"
    # In default mode the witness mismatch is a WARN.
    assert any(
        w["reason"] == "log_witness_mismatch" for w in output["warnings"]
    )
    # overall stays pass because all other checks pass.
    assert output["overall"] == "pass", output


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-029")
def test_log_witness_signature_mismatch_under_strict_log_is_error() -> None:
    """Under `--strict-log`, witness mismatch promotes to ERROR (fail)."""
    from conftest_w10_4 import make_keypair
    from relay_verifier import jwk_from_ed25519_public_key

    built = build_bundle()
    alt_witness_key = make_keypair(b"\x03" * 32)
    alt_witness_jwk = jwk_from_ed25519_public_key(
        alt_witness_key.public_key(), kid="witness-test-kid-1",
    )
    alt_witness_jwks = {"keys": [alt_witness_jwk]}

    output = validate_bundle(
        bundle=built.bundle,
        jwks=built.jwks,
        options=ValidateBundleOptions(
            strict_log=True, witness_jwks=alt_witness_jwks,
        ),
    )
    assert output["log_inclusion"] == "witness_mismatch"
    assert any(
        e["reason"] == "log_witness_mismatch" for e in output["errors"]
    )
    assert output["overall"] == "fail"


# ---------------------------------------------------------------------------
# VAL-W10-030: inclusion proof verified offline (no network)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-030")
def test_inclusion_proof_verifies_offline_with_no_network() -> None:
    """The inclusion proof MUST verify with zero socket activity. We
    test this by patching socket.socket to fail loudly during the call;
    a verifier that reached for the network would error out here.

    The bundle is built BEFORE the socket is patched so the cert/keypair
    generation (which does NOT require network) completes first; this is
    a behavioural pre-existing constraint of `build_bundle`.
    """
    import socket as _socket

    # Build the bundle (and its ephemeral TSA cert chain) FIRST so the
    # subsequent socket guard catches only the verifier's behaviour, not
    # the fixture builder's keypair generation.
    built = build_bundle()

    original_socket = _socket.socket

    class _ExplodingSocket:
        def __init__(self, *args, **kwargs):
            raise RuntimeError(
                "VAL-W10-030 violation: verify_log_inclusion attempted "
                "to open a socket"
            )

    _socket.socket = _ExplodingSocket  # type: ignore[misc, assignment]
    try:
        output = validate_bundle(
            bundle=built.bundle,
            jwks=built.jwks,
            options=ValidateBundleOptions(
                tsa_extra_trusted_roots_pem=built.tsa_extra_roots_pem,
            ),
        )
    finally:
        _socket.socket = original_socket  # type: ignore[misc]
    assert output["log_inclusion"] == "ok"
    assert output["overall"] == "pass", output
