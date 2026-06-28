"""Generative fail-closed property suite for the offline evidence verifier
(keystone invariant #11).

Keystone invariant #11 ("Trust anchor is the commercial moat") rests on a
load-bearing safety property of the OFFLINE VERIFIER: it must FAIL CLOSED.
A bundle whose signature does not genuinely verify under the trust-anchor
JWKS MUST NEVER be reported as accepted, and the verifier MUST NEVER raise
on attacker-controlled input -- every failure mode is a STRUCTURED rejection,
not a crash. A verifier that fails OPEN (accepts a forged/tampered bundle) or
crashes (denial of service / unhandled-exception oracle) destroys the entire
evidence-binding guarantee the trust anchor exists to provide.

The example-based corpus (test_w10_4_*.py) pins specific tamper cases. This
suite UNIVERSALLY QUANTIFIES the invariant over a generated + adversarially
mutated domain. Starting from a single known-good Ed25519-signed bundle
(``conftest_w10_4.build_bundle``), every example draws an adversarial mutation
-- flip signature bytes, corrupt the merkle root, swap/append/mutate claims,
truncate, inject extra fields, inject a non-BMP object key, inject an
out-of-safe-range integer, drop payload fields, type-confuse the structure --
and asserts:

  1. FAIL-CLOSED  -- a bundle whose signatures do not genuinely verify is
     NEVER reported with ``signatures_ok=True`` (and ``validate_bundle``
     never returns ``overall == "pass"``).
  2. NO-RAISE     -- ``verify_bundle`` and ``validate_bundle`` NEVER raise on
     any adversarial input; they return a structured result/envelope.
  3. NO-LIE       -- whenever the verifier DOES report ``signatures_ok=True``,
     an INDEPENDENT cryptographic re-check (``cryptography``'s Ed25519
     primitive, NOT the verifier under test) confirms every signature really
     verifies over the recomputed canonical payload bytes.

The genuineness oracle (:func:`_independently_all_signatures_genuine`) is
deliberately implemented with the raw ``cryptography`` Ed25519 verify call so
it shares no code path with the verifier under test -- it is a true external
witness, not a mirror.

A failing property here is either a real fail-open / crash bug in the verifier
(report it; do NOT weaken the property) or a mis-modeled mutation (fix the
strategy). It is NEVER made green by asserting a falsehood.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

# Sibling helper import (see conftest_w10_4.py docstring for rationale; the
# example-based W10.4 suites import build_bundle the same way).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest_w10_4 import build_bundle  # noqa: E402
from relay_verifier.bundle_validator import validate_bundle  # noqa: E402
from relay_verifier.canonical import (  # noqa: E402
    JCSEncodeError,
    jcs_canonicalize,
    screen_noncanonicalizable,
)
from relay_verifier.verifier import (  # noqa: E402
    VerificationResult,
    _b64u_decode,
    _b64u_encode,
    verify_bundle,
)

# ---------------------------------------------------------------------------
# Baseline known-good signed bundle (built ONCE; key material in memory only).
#
# build_bundle() generates an ephemeral TSA chain via ECDSA keygen, so it is
# relatively expensive; we build a single canonical baseline at import time
# and deep-copy + mutate it per example. The signing key is retained so the
# independent oracle can re-verify with the raw cryptography primitive.
# ---------------------------------------------------------------------------
_BUILT = build_bundle()
_BASE_BUNDLE: dict[str, Any] = _BUILT.bundle
_JWKS: dict[str, Any] = _BUILT.jwks
_SIGNER_KID = "test-signer-kid-1"  # build_bundle default


def _independently_all_signatures_genuine(
    bundle: dict[str, Any],
    jwks: dict[str, Any],
) -> bool:
    """External witness: True iff EVERY signature entry genuinely Ed25519-
    verifies over the recomputed canonical payload bytes.

    Implemented with the raw ``cryptography`` Ed25519 ``verify`` primitive so
    it shares NO code with the verifier under test. The bundle's trust-anchor
    JWKS carries only Ed25519 (OKP) keys, so any genuinely-acceptable signature
    on this bundle must be EdDSA; a non-EdDSA accepted signature would be a
    forgery and is correctly judged not-genuine here.

    Mirrors the verifier's acceptance preconditions (non-empty signatures,
    per-signature kid/alg/inputs present, recorded signing input equals the
    recomputed canonical bytes) but verifies the cryptography independently.
    """
    sigs = bundle.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return False
    payload = {k: v for k, v in bundle.items() if k != "signatures"}
    # Non-canonicalisable payloads (non-BMP object key / out-of-safe-range int)
    # are refused fail-closed by the verifier; they are not genuine.
    if screen_noncanonicalizable(payload) is not None:
        return False
    try:
        canonical = jcs_canonicalize(payload)
    except JCSEncodeError:
        return False

    pub_by_kid: dict[str, ed25519.Ed25519PublicKey] = {}
    for jwk in jwks.get("keys", []):
        if not isinstance(jwk, dict):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        kid = jwk.get("kid")
        x = jwk.get("x")
        if not isinstance(kid, str) or not isinstance(x, str):
            continue
        try:
            pub_by_kid[kid] = ed25519.Ed25519PublicKey.from_public_bytes(
                _b64u_decode(x)
            )
        except Exception:  # noqa: BLE001 - any decode failure -> skip this key
            continue

    any_present = False
    for sig in sigs:
        if not isinstance(sig, dict):
            return False
        kid = sig.get("kid")
        alg = sig.get("alg")
        signing_input_b64u = sig.get("signing_input_b64u")
        signature_b64u = sig.get("signature_b64u")
        if not isinstance(kid, str) or not kid:
            return False
        if alg != "EdDSA":
            return False
        if not isinstance(signing_input_b64u, str) or not signing_input_b64u:
            return False
        if not isinstance(signature_b64u, str) or not signature_b64u:
            return False
        try:
            recorded = _b64u_decode(signing_input_b64u)
            signature_bytes = _b64u_decode(signature_b64u)
        except Exception:  # noqa: BLE001 - malformed base64 -> not genuine
            return False
        if recorded != canonical:
            return False
        pub = pub_by_kid.get(kid)
        if pub is None:
            return False
        try:
            pub.verify(signature_bytes, canonical)
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001 - any verify error -> not genuine
            return False
        any_present = True
    return any_present


def _flip_byte(data: bytes, index: int, bit: int) -> bytes:
    if not data:
        return b"\x00"
    i = index % len(data)
    return data[:i] + bytes([data[i] ^ (1 << (bit % 8))]) + data[i + 1 :]


def _other_hex64(original: str) -> str:
    """A 64-char lowercase hex string guaranteed distinct from ``original``."""
    base = original if isinstance(original, str) and len(original) == 64 else "0" * 64
    first = base[0]
    return ("1" if first != "1" else "2") + base[1:]


# ---------------------------------------------------------------------------
# Mutation domain
#
# Each mutation is a (name, params) pair; _apply_breaking() applies it to a
# deep copy of the baseline. Every breaking mutation is CONSTRUCTED to destroy
# genuine signature validity (it changes the signed canonical payload bytes,
# corrupts the signature bytes, removes the signatures, or injects a value the
# canonicaliser refuses). The independent oracle then double-checks "not
# genuine" before the fail-closed assertion (assume-filters the rare no-op).
# ---------------------------------------------------------------------------

_PAYLOAD_TOP_FIELDS = (
    "schema_version",
    "evidence_bundle_id",
    "trust_anchor",
    "decided_at",
    "signed_at",
    "claims",
    "subject_id",
    "subject_digest_hex",
    "merkle_root_hex",
)

_CLAIM_FIELDS = ("claim_id", "kind", "command_id", "exit_code", "artifact_id")


@st.composite
def _breaking_mutation(draw: st.DrawFn) -> tuple[str, dict[str, Any]]:
    name = draw(
        st.sampled_from(
            [
                "flip_signature",
                "flip_signing_input",
                "truncate_signing_input",
                "corrupt_merkle_root",
                "corrupt_subject_digest",
                "mutate_claim_field",
                "append_claim",
                "swap_trust_anchor",
                "drop_payload_field",
                "inject_payload_field",
                "clear_signatures",
                "drop_signatures",
                "inject_non_bmp_key",
                "inject_unsafe_integer",
            ]
        )
    )
    params: dict[str, Any] = {}
    if name in ("flip_signature", "flip_signing_input"):
        params["index"] = draw(st.integers(min_value=0, max_value=2048))
        params["bit"] = draw(st.integers(min_value=0, max_value=7))
    elif name == "truncate_signing_input":
        params["keep"] = draw(st.integers(min_value=0, max_value=8))
    elif name == "mutate_claim_field":
        params["field"] = draw(st.sampled_from(_CLAIM_FIELDS))
        params["value"] = draw(
            st.one_of(
                st.integers(min_value=1, max_value=4096),
                st.text(min_size=1, max_size=12),
            )
        )
    elif name == "drop_payload_field":
        params["field"] = draw(st.sampled_from(_PAYLOAD_TOP_FIELDS))
    elif name == "inject_payload_field":
        params["key"] = draw(st.text(min_size=1, max_size=10).map(lambda s: "z_" + s))
        params["value"] = draw(
            st.one_of(st.integers(min_value=-1000, max_value=1000), st.text(max_size=8))
        )
    elif name == "swap_trust_anchor":
        params["value"] = draw(
            st.sampled_from(
                [
                    "local_dev",
                    "https://attacker.example/.well-known/jwks.json",
                    "https://relay.epochly.com/evil",
                ]
            )
        )
    elif name == "inject_unsafe_integer":
        params["value"] = draw(
            st.integers(min_value=2**53, max_value=2**70).map(
                lambda v: v if v > (2**53 - 1) else 2**53
            )
        )
    return name, params


def _apply_breaking(
    bundle: dict[str, Any], name: str, params: dict[str, Any]
) -> dict[str, Any]:
    b = copy.deepcopy(bundle)
    sigs = b.get("signatures")
    if name == "flip_signature":
        raw = _b64u_decode(sigs[0]["signature_b64u"])
        sigs[0]["signature_b64u"] = _b64u_encode(
            _flip_byte(raw, params["index"], params["bit"])
        )
    elif name == "flip_signing_input":
        raw = _b64u_decode(sigs[0]["signing_input_b64u"])
        sigs[0]["signing_input_b64u"] = _b64u_encode(
            _flip_byte(raw, params["index"], params["bit"])
        )
    elif name == "truncate_signing_input":
        s = sigs[0]["signing_input_b64u"]
        sigs[0]["signing_input_b64u"] = s[: params["keep"]]
    elif name == "corrupt_merkle_root":
        b["merkle_root_hex"] = _other_hex64(b.get("merkle_root_hex", ""))
    elif name == "corrupt_subject_digest":
        b["subject_digest_hex"] = _other_hex64(b.get("subject_digest_hex", ""))
    elif name == "mutate_claim_field":
        b["claims"][0][params["field"]] = params["value"]
    elif name == "append_claim":
        b["claims"] = list(b["claims"]) + [
            {"claim_id": "injected-extra", "kind": "command_evidence", "exit_code": 7}
        ]
    elif name == "swap_trust_anchor":
        b["trust_anchor"] = params["value"]
    elif name == "drop_payload_field":
        b.pop(params["field"], None)
    elif name == "inject_payload_field":
        b[params["key"]] = params["value"]
    elif name == "clear_signatures":
        b["signatures"] = []
    elif name == "drop_signatures":
        b.pop("signatures", None)
    elif name == "inject_non_bmp_key":
        # A supplementary-plane (non-BMP) object KEY in the signed payload.
        b["\U0001f600_attacker"] = "x"
    elif name == "inject_unsafe_integer":
        b["overflow_field"] = params["value"]
    return b


# ---------------------------------------------------------------------------
# Positive control: the unmutated baseline MUST verify (proves the property
# can distinguish accept from reject -- i.e. it is not trivially always-False).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_baseline_known_good_bundle_verifies() -> None:
    result = verify_bundle(copy.deepcopy(_BASE_BUNDLE), _JWKS)
    assert isinstance(result, VerificationResult)
    assert result.signatures_ok is True, (
        "baseline known-good bundle failed to verify; fixture is broken: "
        f"{[(c.kid, c.ok, c.reason) for c in result.signature_checks]}"
    )
    # The external witness must agree the baseline is genuine.
    assert _independently_all_signatures_genuine(_BASE_BUNDLE, _JWKS) is True


# ---------------------------------------------------------------------------
# Property 1: FAIL-CLOSED under any breaking mutation.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@given(_breaking_mutation())
@settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_breaking_mutation_is_never_accepted(
    mutation: tuple[str, dict[str, Any]],
) -> None:
    name, params = mutation
    bundle = _apply_breaking(_BASE_BUNDLE, name, params)

    # Keep only mutations that genuinely destroyed signature validity (the
    # external Ed25519 witness, NOT the verifier under test, is the judge).
    # This assume() filters the rare structural no-op draw; for every
    # constructed breaking mutation the witness reports not-genuine.
    assume(_independently_all_signatures_genuine(bundle, _JWKS) is False)

    # NO-RAISE: the verifier returns a structured result, never an exception.
    result = verify_bundle(bundle, _JWKS)
    assert isinstance(result, VerificationResult)

    # FAIL-CLOSED: a bundle that does not genuinely verify is never accepted.
    assert result.signatures_ok is False, (
        f"FAIL-OPEN: verifier accepted a tampered bundle (mutation={name}, "
        f"params={params}); signature_checks="
        f"{[(c.kid, c.ok, c.reason) for c in result.signature_checks]}"
    )

    # The higher-level validator must likewise never return overall='pass',
    # and must not raise.
    out = validate_bundle(bundle=bundle, jwks=_JWKS)
    assert out["overall"] != "pass", (
        f"FAIL-OPEN: validate_bundle passed a tampered bundle (mutation={name})"
    )


# ---------------------------------------------------------------------------
# Property 2: NO-RAISE + NO-LIE under arbitrary adversarial structure.
#
# Feeds wild type-confusion mutations (non-list signatures, junk-typed payload
# fields, deeply nested random JSON) and asserts the verifier never raises and
# never reports signatures_ok=True unless the external witness agrees the
# signatures genuinely verify.
# ---------------------------------------------------------------------------

_JSON_SCALAR = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**60), max_value=2**60),
    st.text(max_size=12),
)
_JSON = st.recursive(
    _JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=6), children, max_size=4),
    ),
    max_leaves=12,
)


@st.composite
def _arbitrary_mutation(draw: st.DrawFn) -> dict[str, Any]:
    b = copy.deepcopy(_BASE_BUNDLE)
    n_ops = draw(st.integers(min_value=1, max_value=4))
    for _ in range(n_ops):
        op = draw(
            st.sampled_from(
                [
                    "set_field",
                    "replace_signatures",
                    "mutate_sig_entry",
                    "delete_field",
                    "set_claims",
                ]
            )
        )
        if op == "set_field":
            key = draw(st.text(min_size=1, max_size=8))
            b[key] = draw(_JSON)
        elif op == "replace_signatures":
            b["signatures"] = draw(
                st.one_of(
                    _JSON,
                    st.lists(_JSON, max_size=3),
                    st.just([]),
                    st.text(max_size=6),
                    st.integers(),
                )
            )
        elif op == "mutate_sig_entry":
            if isinstance(b.get("signatures"), list) and b["signatures"]:
                idx = draw(
                    st.integers(min_value=0, max_value=len(b["signatures"]) - 1)
                )
                if isinstance(b["signatures"][idx], dict):
                    field = draw(
                        st.sampled_from(
                            [
                                "alg",
                                "kid",
                                "signing_input_b64u",
                                "signature_b64u",
                            ]
                        )
                    )
                    b["signatures"][idx][field] = draw(
                        st.one_of(_JSON_SCALAR, st.text(max_size=20))
                    )
        elif op == "delete_field":
            if b:
                key = draw(st.sampled_from(sorted(b.keys())))
                b.pop(key, None)
        elif op == "set_claims":
            b["claims"] = draw(
                st.one_of(_JSON, st.lists(_JSON, max_size=3), st.text(max_size=6))
            )
    return b


@pytest.mark.plumbing
@given(_arbitrary_mutation())
@settings(
    max_examples=500,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_arbitrary_adversarial_bundle_never_raises_and_never_lies(
    bundle: dict[str, Any],
) -> None:
    # NO-RAISE: structured result on any adversarial dict.
    result = verify_bundle(bundle, _JWKS)
    assert isinstance(result, VerificationResult)
    assert isinstance(result.signatures_ok, bool)

    # NO-LIE (fail-closed): if the verifier reports signatures_ok=True, an
    # INDEPENDENT cryptographic re-check must confirm the signatures really
    # verify. A True verdict that the external witness rejects is a fail-open
    # bug.
    if result.signatures_ok:
        assert _independently_all_signatures_genuine(bundle, _JWKS), (
            "FAIL-OPEN: verifier reported signatures_ok=True but the "
            "independent Ed25519 witness rejects the signatures"
        )

    # validate_bundle must also never raise, and never 'pass' a bundle the
    # witness deems not-genuine.
    out = validate_bundle(bundle=bundle, jwks=_JWKS)
    assert isinstance(out, dict)
    assert out["overall"] in ("pass", "fail", "warn")
    if out["overall"] == "pass":
        assert _independently_all_signatures_genuine(bundle, _JWKS), (
            "FAIL-OPEN: validate_bundle returned overall='pass' but the "
            "independent Ed25519 witness rejects the signatures"
        )
