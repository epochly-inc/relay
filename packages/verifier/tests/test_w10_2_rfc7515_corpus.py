"""W10.2 RFC 7515 conformance corpus tests (VAL-W10-010, VAL-W10-015).

Loads ``tests/conformance/jws/rfc7515_corpus.json`` (the canonical
cross-language corpus) and asserts:

  * VAL-W10-010 -- every case yields the expected verdict, with zero
    failures across the corpus.
  * VAL-W10-015 -- the verdict envelope this Python verifier emits is
    JCS-canonicalised and hashed; the digest is captured under
    ``parity_records`` so the TypeScript test
    (``packages/verifier-typescript/test/w10_2_corpus.test.ts``) can
    compare digest-by-digest. A mismatch on any case fails CI.

The parity scheme is deliberately byte-equal: both verifiers MUST emit
the same canonical-JSON envelope per case, then the SHA-256 digests
match. We do NOT compare the SignatureCheck dataclass directly because
the dataclass field order is implementation-defined; the canonical-JSON
envelope (sorted keys, compact separators) is the cross-language
contract.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from relay_verifier import (
    RELAY_EVID_014,
    RELAY_VERIFY_ALG_MISMATCH,
    RELAY_VERIFY_UNSUPPORTED_ALG,
    SignatureCheck,
    canonical_json_bytes,
    verify_detached_claim_signature,
    verify_jws_compact,
    verify_multi_signatures,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "jws"
    / "rfc7515_corpus.json"
)


def _load_corpus() -> dict[str, Any]:
    if not CORPUS_PATH.is_file():
        raise AssertionError(
            f"VAL-W10-010 corpus missing at {CORPUS_PATH}; "
            "regenerate with `uv run python scripts/generate-jws-rfc7515-corpus.py`"
        )
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _verdict_envelope(case_name: str, kind: str, sc: SignatureCheck) -> dict[str, Any]:
    """Project a verifier outcome into the cross-language verdict envelope.

    Schema (frozen for VAL-W10-015):

        {
          "name": <case name>,
          "kind": <case kind>,
          "ok": bool,
          "kid": str,
          "alg": str,
          "code": str       # empty when ok=True
        }

    The ``reason`` field is intentionally OMITTED from the envelope --
    reasons are human-readable and may differ in wording between
    runtimes; the ``code`` field is the structured cross-language
    contract token.
    """
    return {
        "name": case_name,
        "kind": kind,
        "ok": bool(sc.ok),
        "kid": str(sc.kid),
        "alg": str(sc.alg),
        "code": str(sc.code),
    }


def _multi_envelope(
    case_name: str, ok: bool, aggregate: str, checks: list[SignatureCheck]
) -> dict[str, Any]:
    return {
        "name": case_name,
        "kind": "multisig",
        "ok": bool(ok),
        "aggregate": aggregate,
        "verdicts": [
            {"kid": str(c.kid), "alg": str(c.alg), "ok": bool(c.ok), "code": str(c.code)}
            for c in checks
        ],
    }


def _run_case(case: dict[str, Any], jwks: dict[str, Any]) -> dict[str, Any]:
    """Dispatch a single corpus case and return its verdict envelope."""
    name = case["name"]
    kind = case["kind"]
    if kind == "compact":
        sc = verify_jws_compact(case["input"], jwks)
        return _verdict_envelope(name, kind, sc)
    if kind == "detached":
        inp = case["input"]
        sc = verify_detached_claim_signature(
            protected_b64u=inp["protected_b64u"],
            signature_b64u=inp["signature_b64u"],
            claim=inp["claim"],
            jwks=jwks,
        )
        return _verdict_envelope(name, kind, sc)
    if kind == "multisig":
        inp = case["input"]
        result = verify_multi_signatures(
            payload=inp["payload"],
            signatures=inp["signatures"],
            jwks=jwks,
        )
        return _multi_envelope(
            name, result.ok, result.aggregate, result.signatures_checked
        )
    raise AssertionError(f"unknown corpus case kind: {kind!r}")


# -----------------------------------------------------------------------------
# VAL-W10-010: 100% corpus pass with verdict-by-verdict assertion
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-010")
def test_corpus_loads_with_minimum_case_count() -> None:
    """The corpus MUST contain at least 12 cases per the feature spec."""
    corpus = _load_corpus()
    assert corpus["schema"] == "relay.conformance.jws.v1"
    assert isinstance(corpus["cases"], list)
    assert len(corpus["cases"]) >= 12, (
        f"VAL-W10-010 requires >= 12 corpus cases; got {len(corpus['cases'])}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-010")
def test_corpus_every_case_matches_expected_ok_verdict() -> None:
    """Every case's ``ok`` boolean matches the corpus expectation."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    failures: list[str] = []
    for case in corpus["cases"]:
        actual = _run_case(case, jwks)
        expected_ok = bool(case["expected"].get("ok"))
        if actual["ok"] != expected_ok:
            failures.append(
                f"{case['name']}: expected ok={expected_ok}, "
                f"got ok={actual['ok']}"
            )
    assert not failures, (
        "VAL-W10-010 corpus failures: " + "; ".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-010")
def test_corpus_positive_cases_carry_correct_kid_and_alg() -> None:
    """Positive cases MUST report the corpus-declared kid and alg."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    for case in corpus["cases"]:
        if not case["expected"].get("ok"):
            continue
        actual = _run_case(case, jwks)
        # Multi-sig cases declare per-signature verdicts; single-sig cases
        # declare top-level kid/alg.
        if case["kind"] == "multisig":
            for verdict, expected_v in zip(
                actual["verdicts"], case["expected"]["verdicts"], strict=True
            ):
                assert verdict["kid"] == expected_v["kid"]
                assert verdict["alg"] == expected_v["alg"]
                assert verdict["ok"] is True
        else:
            assert actual["kid"] == case["expected"]["kid"]
            assert actual["alg"] == case["expected"]["alg"]


# -----------------------------------------------------------------------------
# VAL-W10-011: alg-substitution attacks (none + HS256 over asymmetric kid)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-011")
def test_alg_none_rejected_without_signature_compute() -> None:
    """Both alg=none vectors yield RELAY-VERIFY-011 with no signature
    primitive invocation. The corpus generator embedded a garbage and
    an empty signature segment; both reject identically."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    for name in ("neg-alg-none-empty-sig", "neg-alg-none-garbage-sig"):
        case = next(c for c in corpus["cases"] if c["name"] == name)
        actual = _run_case(case, jwks)
        assert actual["ok"] is False, name
        assert actual["code"] == RELAY_VERIFY_UNSUPPORTED_ALG, name
        assert actual["alg"] == "none", name


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-011")
def test_hs256_over_asymmetric_public_key_rejected() -> None:
    """HS256 with a kid pointing at an RSA / EdDSA public JWK is the
    classic RFC 8725 sec 3.2 substitution attack. MUST reject before
    invoking any HMAC primitive."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    for name in (
        "neg-alg-hs256-over-rsa-public-key",
        "neg-alg-hs256-over-eddsa-public-key",
    ):
        case = next(c for c in corpus["cases"] if c["name"] == name)
        actual = _run_case(case, jwks)
        assert actual["ok"] is False, name
        assert actual["code"] == RELAY_VERIFY_UNSUPPORTED_ALG, name
        assert actual["alg"] == "HS256", name


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-011")
def test_alg_mismatch_when_jwk_kty_disagrees_with_alg() -> None:
    """A JWK whose kty disagrees with an in-allow-list alg yields
    RELAY-VERIFY-010 (alg-mismatch). Synthesises the case in-test
    because the corpus does not ship an alg-mismatch positive vector
    -- the corpus's HS256 vectors are caught at the allow-list step
    BEFORE alg-mismatch triggers."""
    # Build a JWKS where kid 'mismatch' points at an RSA key but the
    # signature header claims alg=ES256. Use the corpus's RSA JWK.
    corpus = _load_corpus()
    rsa_jwk = next(
        k for k in corpus["jwks"]["keys"]
        if k["kty"] == "RSA"
    )
    forged_jwks = {
        "keys": [
            {
                **rsa_jwk,
                "kid": "kid-mismatch",
                "alg": "ES256",  # JWK alg field also lies
            }
        ]
    }
    # Compact-form JWS with header alg=ES256, kid=kid-mismatch, garbage sig
    import base64

    header = json.dumps(
        {"alg": "ES256", "kid": "kid-mismatch", "typ": "JWT"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    payload = b'{"x":1}'
    sig = b"\x00" * 64
    h_b64 = base64.urlsafe_b64encode(header).rstrip(b"=").decode("ascii")
    p_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    s_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    token = f"{h_b64}.{p_b64}.{s_b64}"
    sc = verify_jws_compact(token, forged_jwks)
    assert sc.ok is False
    assert sc.code == RELAY_VERIFY_ALG_MISMATCH
    assert "alg-mismatch" in sc.reason


# -----------------------------------------------------------------------------
# VAL-W10-012: detached JWS payload binding
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-012")
def test_detached_positive_passes() -> None:
    corpus = _load_corpus()
    case = next(c for c in corpus["cases"] if c["name"] == "detached-positive-eddsa")
    actual = _run_case(case, corpus["jwks"])
    assert actual["ok"] is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-012")
def test_detached_tampered_claim_emits_relay_evid_014() -> None:
    """Tampered detached claim MUST surface RELAY-EVID-014 -- the public-
    facing evidence-bundle integrity error code."""
    corpus = _load_corpus()
    case = next(
        c for c in corpus["cases"] if c["name"] == "detached-negative-tampered-claim"
    )
    actual = _run_case(case, corpus["jwks"])
    assert actual["ok"] is False
    assert actual["code"] == RELAY_EVID_014


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-012")
def test_detached_payload_sha256_mismatch_in_header() -> None:
    """If the protected header declares ``payload_sha256`` and the
    recomputed digest disagrees, reject with RELAY-EVID-014 BEFORE
    invoking the signature verifier."""
    import base64

    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(b"x" * 32)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]
        ).Encoding.Raw,
        format=__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]
        ).PublicFormat.Raw,
    )
    kid = "kid-test-claim-binding"
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "alg": "EdDSA",
                "use": "sig",
                "x": base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii"),
            }
        ]
    }
    claim = {"claim_id": "c-1", "value": "original"}
    canonical = canonical_json_bytes(claim)
    actual_digest = hashlib.sha256(canonical).hexdigest()
    forged_digest = "0" * 64  # deliberately wrong
    header = {
        "alg": "EdDSA",
        "kid": kid,
        "payload_sha256": forged_digest,
    }
    header_bytes = canonical_json_bytes(header)
    header_b64 = base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode("ascii")
    sig = priv.sign(header_b64.encode("ascii") + b"." + canonical)
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    sc = verify_detached_claim_signature(
        protected_b64u=header_b64,
        signature_b64u=sig_b64,
        claim=claim,
        jwks=jwks,
    )
    assert sc.ok is False
    assert sc.code == RELAY_EVID_014
    assert actual_digest in sc.reason
    assert forged_digest in sc.reason


# -----------------------------------------------------------------------------
# VAL-W10-013: multi-signature bundle reports per-signature verdicts
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-013")
def test_multisig_n2_both_valid_yields_all_valid_aggregate() -> None:
    corpus = _load_corpus()
    case = next(c for c in corpus["cases"] if c["name"] == "multisig-n2-both-valid")
    actual = _run_case(case, corpus["jwks"])
    assert actual["ok"] is True
    assert actual["aggregate"] == "all_valid"
    assert len(actual["verdicts"]) == 2
    assert all(v["ok"] for v in actual["verdicts"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-013")
def test_multisig_n2_mixed_reports_per_signature_verdicts() -> None:
    corpus = _load_corpus()
    case = next(c for c in corpus["cases"] if c["name"] == "multisig-n2-mixed")
    actual = _run_case(case, corpus["jwks"])
    assert actual["ok"] is False
    assert actual["aggregate"] == "mixed"
    assert len(actual["verdicts"]) == 2
    # First sig (EdDSA) verifies; second (ES256) does not.
    assert actual["verdicts"][0]["ok"] is True
    assert actual["verdicts"][0]["alg"] == "EdDSA"
    assert actual["verdicts"][1]["ok"] is False
    assert actual["verdicts"][1]["alg"] == "ES256"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-013")
def test_multisig_n6_all_valid_no_hard_cap() -> None:
    """N=6 cross-signing case proves the verifier does not hard-cap
    cardinality below 6."""
    corpus = _load_corpus()
    case = next(c for c in corpus["cases"] if c["name"] == "multisig-n6-all-valid")
    actual = _run_case(case, corpus["jwks"])
    assert actual["ok"] is True
    assert actual["aggregate"] == "all_valid"
    assert len(actual["verdicts"]) == 6
    assert all(v["ok"] for v in actual["verdicts"])


# -----------------------------------------------------------------------------
# VAL-W10-014: algorithm allow-list enforcement
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-014")
def test_allow_list_rejects_disallowed_algs_with_structured_code() -> None:
    """Every disallowed-alg corpus case yields RELAY-VERIFY-011 BEFORE
    any signature primitive is invoked."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    disallowed_cases = [
        ("neg-alg-rs1-disallowed", "RS1"),
        ("neg-alg-vendor-disallowed", "vendor.custom-1"),
        ("neg-alg-missing", "<unknown>"),
        ("neg-alg-none-empty-sig", "none"),
        ("neg-alg-hs256-over-rsa-public-key", "HS256"),
    ]
    for name, expected_alg in disallowed_cases:
        case = next(c for c in corpus["cases"] if c["name"] == name)
        actual = _run_case(case, jwks)
        assert actual["ok"] is False, name
        assert actual["code"] == RELAY_VERIFY_UNSUPPORTED_ALG, (
            f"{name}: expected code RELAY-VERIFY-011, got {actual['code']!r}"
        )
        assert actual["alg"] == expected_alg, name


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-014")
def test_allow_list_accepts_three_canonical_algs() -> None:
    """ES256, EdDSA, RS256 positive vectors each pass with structure
    intact -- proves the allow-list does not over-reject."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    positive_algs = {
        "positive-eddsa": "EdDSA",
        "positive-es256": "ES256",
        "positive-rs256": "RS256",
    }
    for name, expected_alg in positive_algs.items():
        case = next(c for c in corpus["cases"] if c["name"] == name)
        actual = _run_case(case, jwks)
        assert actual["ok"] is True, name
        assert actual["alg"] == expected_alg
        assert actual["code"] == ""


# -----------------------------------------------------------------------------
# VAL-W10-015: cross-language verdict parity (Python side captures the
# digest table; the TS test must produce the same digests)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-015")
def test_verdict_digests_are_deterministic_across_runs() -> None:
    """Run the corpus twice and assert the digest table is byte-equal.
    A non-deterministic verifier (e.g. one that read the wall clock
    or a PRNG) would diverge."""
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    digests_a: dict[str, str] = {}
    digests_b: dict[str, str] = {}
    for case in corpus["cases"]:
        env_a = _run_case(case, jwks)
        env_b = _run_case(case, jwks)
        digests_a[case["name"]] = hashlib.sha256(
            canonical_json_bytes(env_a)
        ).hexdigest()
        digests_b[case["name"]] = hashlib.sha256(
            canonical_json_bytes(env_b)
        ).hexdigest()
    assert digests_a == digests_b, (
        "VAL-W10-015: verifier output is non-deterministic; "
        f"divergent cases: {[k for k in digests_a if digests_a[k] != digests_b[k]]}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-015")
def test_python_verdict_digest_table_written_for_ts_parity() -> None:
    """Emit a digest table to ``tests/conformance/jws/py_verdict_digests.json``.

    The TypeScript corpus test (W10.2 TS package) reads the same corpus,
    canonicalises its verdict the same way, hashes, and compares
    digest-by-digest. A divergent digest table means Python and TS
    disagree on at least one case -- VAL-W10-015 fails CI.
    """
    corpus = _load_corpus()
    jwks = corpus["jwks"]
    table: dict[str, str] = {}
    for case in corpus["cases"]:
        env = _run_case(case, jwks)
        table[case["name"]] = hashlib.sha256(canonical_json_bytes(env)).hexdigest()

    out = (
        Path(__file__).resolve().parents[3]
        / "tests"
        / "conformance"
        / "jws"
        / "py_verdict_digests.json"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    body = (
        json.dumps(
            {
                "schema": "relay.conformance.jws.py_verdict_digests.v1",
                "digests": table,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    # Test fixture write -- exempt from atomic-primitives rule per
    # boundaries.md section 3 paragraph 4 (test files are exempt for
    # fixture preparation).
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(out)
    # Sanity: the table is non-empty and stable.
    assert len(table) >= 12
