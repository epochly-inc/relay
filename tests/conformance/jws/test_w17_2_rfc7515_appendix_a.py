"""W17.2 RFC 7515 Appendix A conformance corpus tests.

Pinned-vector conformance suite that exercises:

  * The test-only HS verifier helper (HMAC-SHA256 / HMAC-SHA512 math)
    against RFC 7515 Appendix A.1's literal HS256 vector and the
    constructed HS512 vector. VAL-W17-007a.
  * The production Relay verifier (packages/verifier/) against every
    corpus vector, asserting:
      - HS256/HS512/none/ES512 are rejected with
        RELAY-VERIFY-UNSUPPORTED-ALG (the alg-allow-list reject path
        runs BEFORE primitive dispatch, so the rejection holds even
        for cryptographically valid HMAC signatures). VAL-W17-007b,
        VAL-W17-008.
      - Kid-augmented RS256 / ES256 vectors VERIFY against the
        constructed JWKS via the production verifier. VAL-W17-007b.
      - Tampered (one payload bit / one signature bit) asymmetric
        variants FAIL with `signature did not verify`. VAL-W17-007b.
      - Detached-payload variants (RFC 7797 b64u-ascii-payload form,
        equivalent to RFC 7515 detached) verify when supplied
        externally. VAL-W17-009.
  * The corpus is pinned to RFC 7515 by SHA-256 of an inline transcript
    of the normative subsections. VAL-W17-006.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

import pytest
from relay_verifier import (
    SignatureCheck,
    verify_jws_compact,
    verify_jws_detached,
)
from relay_verifier.errors import RELAY_VERIFY_UNSUPPORTED_ALG

# Load the test-only HS verifier helper by file path. The helper lives
# under tests/conformance/jws/ which is not a Python package (no
# __init__.py), and we deliberately do NOT add an __init__.py here so
# the test-only helper cannot be imported from anywhere outside this
# directory (defense-in-depth for VAL-W17-023).
_HS_HELPER_PATH = Path(__file__).resolve().parent / "_test_only_hs_verifier.py"
_hs_spec = importlib.util.spec_from_file_location(
    "_test_only_hs_verifier", _HS_HELPER_PATH
)
assert _hs_spec is not None and _hs_spec.loader is not None
_hs_module = importlib.util.module_from_spec(_hs_spec)
_hs_spec.loader.exec_module(_hs_module)
UnsupportedHsAlgError = _hs_module.UnsupportedHsAlgError
verify_hs_compact = _hs_module.verify_hs_compact

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / "rfc7515_appendix_a.json"
)
PINS_PATH = (
    REPO_ROOT / "tests" / "conformance" / "jws" / ".upstream-pins.json"
)

SCHEMA_ID = "relay.conformance.jws.rfc7515-appendix-a.v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IETF_DATATRACKER_URL = "https://datatracker.ietf.org/doc/html/rfc7515"

# Minimum coverage floors -- updating these floors requires updating
# the corpus generator AND this test in the same commit.
_MIN_RFC_LITERAL_CASES = 5      # A.1, A.2 literal, A.3 literal, A.4 literal, A.5
_MIN_HS_MATH_CASES = 2          # HS256 (A.1) + HS512 (constructed)
_MIN_KID_AUGMENTED_PASS_CASES = 2  # RS256 + ES256 (compact) MUST pass production
_MIN_DETACHED_CASES = 2         # RS256 detached + ES256 detached (VAL-W17-009)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_corpus() -> dict[str, Any]:
    if not CORPUS_PATH.is_file():
        raise AssertionError(
            f"W17.2 corpus missing at {CORPUS_PATH}; regenerate via "
            "`uv run python scripts/generate-jws-rfc7515-appendix-a-corpus.py`."
        )
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _load_pins() -> dict[str, Any]:
    if not PINS_PATH.is_file():
        raise AssertionError(
            f"W17.2 pins missing at {PINS_PATH}; regenerate via "
            "`uv run python scripts/generate-jws-rfc7515-appendix-a-corpus.py`."
        )
    return json.loads(PINS_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Per-vector diff formatter (VAL-W17-022 -- applies to w17.2 via Also-covers)
# ---------------------------------------------------------------------------


def _format_diff(
    *,
    vector_input: str | dict[str, Any],
    expected: dict[str, Any],
    py_output: dict[str, Any],
    ts_output: dict[str, Any] | None,
    diff_payload: str,
) -> str:
    """Format the VAL-W17-022 per-vector diff. The TS half is filled in
    by the vitest mirror; the Python half emits a placeholder so a
    Python-only failure is still actionable."""
    import hashlib

    digest = hashlib.sha256(diff_payload.encode("utf-8")).hexdigest()
    lines = [
        "VAL-W17-022 per-vector diff:",
        f"  vector_input        = {vector_input!r}",
        f"  expected            = {expected!r}",
        f"  py_output           = {py_output!r}",
        f"  ts_output           = {ts_output!r}",
        f"  diff_payload_sha256 = {digest}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# VAL-W17-006: corpus pinned to RFC 7515 Appendix A by SHA-256
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-006")
def test_corpus_schema_and_minimum_coverage() -> None:
    """The corpus declares the v1 schema and meets per-category floors."""
    corpus = _load_corpus()
    assert corpus["schema"] == SCHEMA_ID, (
        f"VAL-W17-006 schema mismatch: expected {SCHEMA_ID!r}, "
        f"got {corpus.get('schema')!r}"
    )
    counts = corpus["case_counts"]
    assert counts["rfc_literal"] >= _MIN_RFC_LITERAL_CASES, (
        f"VAL-W17-006 too few rfc_literal cases: {counts['rfc_literal']}"
    )
    assert counts["hs_math"] >= _MIN_HS_MATH_CASES, (
        f"VAL-W17-007a too few hs_math cases: {counts['hs_math']}"
    )
    assert counts["detached"] >= _MIN_DETACHED_CASES, (
        f"VAL-W17-009 too few detached cases: {counts['detached']}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-006")
def test_corpus_pinned_to_ietf_datatracker() -> None:
    """The corpus + pins pin to the IETF datatracker text of RFC 7515
    by SHA-256 over an inline transcript of the normative paragraphs."""
    pins = _load_pins()
    assert pins["source_url"] == _IETF_DATATRACKER_URL, (
        f"VAL-W17-006 source URL not pinned to IETF datatracker: "
        f"got {pins.get('source_url')!r}"
    )
    assert pins["rfc"] == "RFC 7515"
    assert _HEX_64.match(pins["transcript_sha256"]), (
        f"VAL-W17-006 transcript_sha256 not 64-char hex: "
        f"{pins.get('transcript_sha256')!r}"
    )
    assert isinstance(pins["transcript_byte_length"], int)
    assert pins["transcript_byte_length"] > 0
    corpus = _load_corpus()
    assert corpus["source"]["url"] == _IETF_DATATRACKER_URL
    # Appendix subsections we depend on are enumerated in pins.
    sections = pins["appendix_subsections_covered"]
    expected_subsections = {"A.1 HS256", "A.2 RS256", "A.3 ES256", "A.4 ES512"}
    assert expected_subsections.issubset(set(sections)), (
        f"VAL-W17-006 expected appendix subsections {expected_subsections} "
        f"not fully present in pins.appendix_subsections_covered={sections}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-006")
def test_corpus_case_names_unique() -> None:
    """Generator drift guard: every case name MUST be unique."""
    corpus = _load_corpus()
    seen: set[str] = set()
    for case in corpus["cases"]:
        name = case["name"]
        assert name not in seen, f"duplicate case name in corpus: {name}"
        seen.add(name)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-006")
def test_corpus_includes_literal_rfc_appendix_a_vectors() -> None:
    """Every literal Appendix A vector named in the contract MUST be
    present in the corpus with `_source` prefixed `rfc7515-appendix-`."""
    corpus = _load_corpus()
    literal_names = {
        c["name"]
        for c in corpus["cases"]
        if c.get("_source", "").startswith("rfc7515-appendix-")
    }
    required = {
        "appendix-a1-hs256",
        "appendix-a2-rs256-literal",
        "appendix-a3-es256-literal",
        "appendix-a4-es512-literal",
        "appendix-a5-unsecured-none",
    }
    missing = required - literal_names
    assert not missing, (
        f"VAL-W17-006: missing literal RFC Appendix A vectors: {missing}"
    )


# ---------------------------------------------------------------------------
# VAL-W17-007a: HS256/HS512 vectors verify under the test-only HS helper
# ---------------------------------------------------------------------------


def _hs_cases() -> list[dict[str, Any]]:
    return [
        c
        for c in _load_corpus()["cases"]
        if "expected_hs_math" in c and c["kind"] == "compact"
    ]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007a")
def test_hs_helper_verifies_appendix_a1_hs256_and_constructed_hs512() -> None:
    """Both the A.1 HS256 literal vector and the constructed HS512
    vector MUST verify TRUE under the test-only HS helper. Failure here
    indicates a corpus transcription error OR an HMAC primitive bug."""
    import base64

    cases = _hs_cases()
    assert len(cases) >= _MIN_HS_MATH_CASES, (
        f"VAL-W17-007a expected >= {_MIN_HS_MATH_CASES} HS-math cases; "
        f"got {len(cases)}"
    )
    failures: list[str] = []
    for case in cases:
        key_b64u = case["hs_shared_key_b64u"]
        pad = "=" * (-len(key_b64u) % 4)
        shared_key = base64.urlsafe_b64decode(key_b64u + pad)
        ok = verify_hs_compact(case["input"], shared_key)
        if not ok:
            failures.append(
                _format_diff(
                    vector_input=case["input"],
                    expected=case["expected_hs_math"],
                    py_output={"ok": ok},
                    ts_output=None,
                    diff_payload=case["input"],
                )
            )
    assert not failures, (
        f"VAL-W17-007a: {len(failures)} HS-math vector(s) failed:\n\n"
        + "\n\n".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007a")
def test_hs_helper_rejects_non_hs_algs() -> None:
    """The HS helper refuses to verify RS256/ES256/EdDSA inputs.

    This is the structural enforcement of VAL-W17-023's boundary --
    the helper deliberately does NOT delegate to production code.
    """
    # Build a minimal RS256 token shell (header alg=RS256, junk sig).
    # The helper should refuse BEFORE attempting any signature work.
    import base64

    header = json.dumps({"alg": "RS256", "kid": "x"}, sort_keys=True).encode()
    header_b64u = base64.urlsafe_b64encode(header).rstrip(b"=").decode("ascii")
    payload_b64u = "eyJ4IjoxfQ"
    sig_b64u = "AAAA"
    bad_token = f"{header_b64u}.{payload_b64u}.{sig_b64u}"
    with pytest.raises(UnsupportedHsAlgError) as excinfo:
        verify_hs_compact(bad_token, b"any-key")
    assert "RS256" in str(excinfo.value)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007a")
def test_hs_helper_rejects_tampered_hmac() -> None:
    """A bit-flip in the HS256 signature segment MUST cause the helper
    to return False (proves HMAC verify is wired, not stubbed)."""
    import base64

    cases = _hs_cases()
    # Pick the HS256 vector explicitly.
    hs256 = next(c for c in cases if c["alg"] == "HS256")
    header_b64u, payload_b64u, sig_b64u = hs256["input"].split(".")
    sig_bytes = bytearray(
        base64.urlsafe_b64decode(sig_b64u + "=" * (-len(sig_b64u) % 4))
    )
    sig_bytes[-1] ^= 0x01
    tampered_sig = base64.urlsafe_b64encode(bytes(sig_bytes)).rstrip(b"=").decode()
    tampered_token = f"{header_b64u}.{payload_b64u}.{tampered_sig}"
    key_pad = "=" * (-len(hs256["hs_shared_key_b64u"]) % 4)
    shared_key = base64.urlsafe_b64decode(hs256["hs_shared_key_b64u"] + key_pad)
    assert verify_hs_compact(tampered_token, shared_key) is False, (
        "VAL-W17-007a: HS verifier did not reject a bit-flipped signature"
    )


# ---------------------------------------------------------------------------
# VAL-W17-007b: production verifier behavior on Appendix A vectors
# ---------------------------------------------------------------------------


def _verify_compact_case(case: dict[str, Any], jwks: dict[str, Any]) -> SignatureCheck:
    return verify_jws_compact(case["input"], jwks)


def _verify_detached_case(
    case: dict[str, Any], jwks: dict[str, Any]
) -> SignatureCheck:
    """Verify a detached vector. The detached payload is the
    base64url-encoded ASCII bytes of the payload (RFC 7515 sec 3.1
    signing input convention -- the signature was computed over
    ``header_b64 || '.' || payload_b64``).
    """
    inp = case["input"]
    return verify_jws_detached(
        protected_b64u=inp["protected_b64u"],
        payload_bytes=inp["payload_b64u"].encode("ascii"),
        signature_b64u=inp["signature_b64u"],
        jwks=jwks,
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_hs256_appendix_a1() -> None:
    """A.1 HS256 literal MUST be rejected by the production verifier
    with RELAY-VERIFY-UNSUPPORTED-ALG."""
    corpus = _load_corpus()
    case = next(c for c in corpus["cases"] if c["name"] == "appendix-a1-hs256")
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert result.code == RELAY_VERIFY_UNSUPPORTED_ALG, (
        f"VAL-W17-007b: HS256 vector returned code {result.code!r}, "
        f"expected RELAY-VERIFY-UNSUPPORTED-ALG"
    )
    assert "unsupported alg" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_hs512_constructed() -> None:
    """The constructed HS512 vector MUST be rejected with the same
    canonical code."""
    corpus = _load_corpus()
    case = next(
        c for c in corpus["cases"] if c["name"] == "appendix-a2-hs512-constructed"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert result.code == RELAY_VERIFY_UNSUPPORTED_ALG
    assert "unsupported alg" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_accepts_kid_augmented_rs256() -> None:
    """RS256 IS in Relay's allow-list. The kid-augmented vector MUST
    verify successfully."""
    corpus = _load_corpus()
    case = next(
        c for c in corpus["cases"] if c["name"] == "appendix-a2-rs256-kid-augmented"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is True, (
        f"VAL-W17-007b: kid-augmented RS256 should verify; got "
        f"ok={result.ok}, code={result.code!r}, reason={result.reason!r}"
    )
    assert result.alg == "RS256"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_accepts_kid_augmented_es256() -> None:
    """ES256 IS in Relay's allow-list. The kid-augmented vector MUST
    verify successfully."""
    corpus = _load_corpus()
    case = next(
        c for c in corpus["cases"] if c["name"] == "appendix-a3-es256-kid-augmented"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is True
    assert result.alg == "ES256"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_tampered_rs256_payload() -> None:
    """Bit-flipped payload MUST cause asymmetric signature failure."""
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a2-rs256-kid-augmented-tampered-payload"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert "signature did not verify" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_tampered_rs256_signature() -> None:
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a2-rs256-kid-augmented-tampered-signature"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert "signature did not verify" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_tampered_es256_payload() -> None:
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a3-es256-kid-augmented-tampered-payload"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert "signature did not verify" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-007b")
def test_production_verifier_rejects_tampered_es256_signature() -> None:
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a3-es256-kid-augmented-tampered-signature"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert "signature did not verify" in result.reason


# ---------------------------------------------------------------------------
# VAL-W17-008: algorithm restriction enforced (RFC 7515 sec 4.1.1)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-008")
def test_alg_none_rejected_literal_appendix_a5() -> None:
    """The literal A.5 unsecured JWS MUST be rejected."""
    corpus = _load_corpus()
    case = next(
        c for c in corpus["cases"] if c["name"] == "appendix-a5-unsecured-none"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert result.code == RELAY_VERIFY_UNSUPPORTED_ALG
    assert "unsupported alg" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-008")
def test_alg_none_rejected_when_forged_with_attacker_payload() -> None:
    """A constructed alg=none JWS with attacker-supplied payload MUST
    be rejected (the allow-list check fires BEFORE payload inspection)."""
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a5-forged-alg-none-attacker-payload"
    )
    result = _verify_compact_case(case, corpus["jwks"])
    assert result.ok is False
    assert result.code == RELAY_VERIFY_UNSUPPORTED_ALG


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-008")
def test_alg_es512_rejected_by_allow_list() -> None:
    """ES512 is NOT in Relay's allow-list. The literal A.4 vector and
    the kid-augmented A.4 vector MUST both be rejected with the
    canonical unsupported-alg code BEFORE primitive dispatch."""
    corpus = _load_corpus()
    for name in (
        "appendix-a4-es512-literal",
        "appendix-a4-es512-kid-augmented",
    ):
        case = next(c for c in corpus["cases"] if c["name"] == name)
        result = _verify_compact_case(case, corpus["jwks"])
        assert result.ok is False, f"{name} should be rejected"
        assert result.code == RELAY_VERIFY_UNSUPPORTED_ALG, (
            f"{name}: code {result.code!r} != RELAY_VERIFY_UNSUPPORTED_ALG"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-008")
def test_every_non_allow_listed_alg_vector_is_rejected() -> None:
    """Aggregate guard: EVERY corpus vector whose alg is not in Relay's
    allow-list MUST be rejected with RELAY-VERIFY-UNSUPPORTED-ALG.
    Failing this aggregate test catches a regression where an attacker
    alg slipped through unrejected."""
    corpus = _load_corpus()
    disallowed = {"HS256", "HS512", "ES512", "none"}
    failures: list[str] = []
    for case in corpus["cases"]:
        if case["kind"] != "compact":
            continue
        if case.get("alg") not in disallowed:
            continue
        result = _verify_compact_case(case, corpus["jwks"])
        if result.ok or result.code != RELAY_VERIFY_UNSUPPORTED_ALG:
            failures.append(
                f"{case['name']}: alg={case['alg']!r} ok={result.ok} "
                f"code={result.code!r} reason={result.reason!r}"
            )
    assert not failures, (
        f"VAL-W17-008: {len(failures)} disallowed-alg vector(s) NOT rejected "
        f"with RELAY-VERIFY-UNSUPPORTED-ALG:\n  " + "\n  ".join(failures)
    )


# ---------------------------------------------------------------------------
# VAL-W17-009: detached-payload JWS verification matches RFC 7515 vectors
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-009")
def test_detached_rs256_kid_augmented_verifies() -> None:
    """The detached form of the kid-augmented A.2 RS256 vector MUST
    verify when the payload is supplied externally."""
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a2-rs256-kid-augmented-detached"
    )
    assert case["kind"] == "detached"
    result = _verify_detached_case(case, corpus["jwks"])
    assert result.ok is True, (
        f"VAL-W17-009: detached RS256 must verify; got "
        f"ok={result.ok}, reason={result.reason!r}"
    )
    assert result.alg == "RS256"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-009")
def test_detached_es256_kid_augmented_verifies() -> None:
    """The detached form of the kid-augmented A.3 ES256 vector MUST
    verify when the payload is supplied externally."""
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a3-es256-kid-augmented-detached"
    )
    assert case["kind"] == "detached"
    result = _verify_detached_case(case, corpus["jwks"])
    assert result.ok is True
    assert result.alg == "ES256"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-009")
def test_detached_payload_tamper_fails() -> None:
    """If the detached payload bytes are tampered (one byte flipped),
    the verifier MUST report signature failure -- proving the detached
    payload IS bound to the signature."""
    corpus = _load_corpus()
    case = next(
        c
        for c in corpus["cases"]
        if c["name"] == "appendix-a2-rs256-kid-augmented-detached"
    )
    inp = case["input"]
    bad_payload = bytearray(inp["payload_b64u"].encode("ascii"))
    bad_payload[-1] ^= 0x01
    result = verify_jws_detached(
        protected_b64u=inp["protected_b64u"],
        payload_bytes=bytes(bad_payload),
        signature_b64u=inp["signature_b64u"],
        jwks=corpus["jwks"],
    )
    assert result.ok is False, (
        "VAL-W17-009: tampered detached payload must NOT verify; "
        f"got ok={result.ok}"
    )
    assert "signature did not verify" in result.reason


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-009")
def test_compact_and_detached_use_same_signature_bytes() -> None:
    """Cross-form invariant: the compact JWS's signature segment is
    byte-identical to its detached twin's signature_b64u. Catches a
    generator drift where compact + detached produce different signatures."""
    corpus = _load_corpus()
    pairs = [
        ("appendix-a2-rs256-kid-augmented", "appendix-a2-rs256-kid-augmented-detached"),
        ("appendix-a3-es256-kid-augmented", "appendix-a3-es256-kid-augmented-detached"),
    ]
    for compact_name, detached_name in pairs:
        compact = next(c for c in corpus["cases"] if c["name"] == compact_name)
        detached = next(c for c in corpus["cases"] if c["name"] == detached_name)
        compact_sig = compact["input"].split(".")[-1]
        detached_sig = detached["input"]["signature_b64u"]
        assert compact_sig == detached_sig, (
            f"VAL-W17-009: signature drift between {compact_name!r} and "
            f"{detached_name!r}: compact_sig={compact_sig!r} "
            f"detached_sig={detached_sig!r}"
        )


# ---------------------------------------------------------------------------
# VAL-W17-022 (Also-covers w17.2): per-vector full diff on failure
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-022")
def test_diff_formatter_emits_required_fields() -> None:
    """The _format_diff helper emits all five required fields per the
    C-GAP-005 reconciliation: vector_input, expected, py_output,
    ts_output, diff_payload_sha256."""
    msg = _format_diff(
        vector_input="header.payload.sig",
        expected={"ok": True},
        py_output={"ok": False, "reason": "x"},
        ts_output=None,
        diff_payload="some diff payload",
    )
    assert "vector_input" in msg
    assert "expected" in msg
    assert "py_output" in msg
    assert "ts_output" in msg
    assert "diff_payload_sha256" in msg
    # SHA-256 hex digest is 64 chars. Use an unanchored finder because
    # _HEX_64 (^...$) anchors the entire string; we want to match a
    # substring within the multi-line diff message.
    assert re.search(r"\b[0-9a-f]{64}\b", msg), (
        "diff_payload_sha256 hex missing from diff message"
    )


# ---------------------------------------------------------------------------
# Generator drift guard
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W17-006")
def test_corpus_matches_generator_output() -> None:
    """Run the generator's --check mode in-process. Catches a hand-edit
    to the corpus that would silently drift from the generator."""
    import subprocess  # noqa: PLC0415  -- test-only

    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "scripts/generate-jws-rfc7515-appendix-a-corpus.py",
            "--check",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"VAL-W17-006 generator drift detected:\n"
        f"  stdout: {result.stdout}\n"
        f"  stderr: {result.stderr}"
    )
