"""W10.3 RFC 8785 JCS conformance tests (VAL-W10-016, -017, -018, -019).

Loads ``tests/conformance/jcs/rfc8785_corpus.json`` and asserts:

  * VAL-W10-016 -- every value-kind case canonicalises byte-for-byte
    to the corpus-pinned UTF-8 bytes (and corpus-pinned SHA-256 digest).
  * VAL-W10-017 -- numeric edge cases (negative zero, whole-valued
    float, large decimal float, fractional float, large integer,
    negative integer) match the corpus golden bytes; reject cases
    (NaN / +Inf / -Inf) raise :class:`JCSEncodeError`.
  * VAL-W10-018 -- key ordering by UTF-16 code unit produces the
    pinned canonical bytes for vectors with multiple BMP key sets.
  * VAL-W10-019 -- the SHA-256 digest of every value-kind case equals
    the digest checked into the corpus, asserting stability across
    Python 3.12 / 3.13 / 3.14 (the CI matrix). Drift on ANY case
    fails this test.

The corpus is generated from a reference implementation (the contracts
package's ``jcs_canonicalize``) and the verifier package re-derives
the canonical bytes here. The dual-source pattern catches regression
in either the verifier OR the corpus generator.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from relay_verifier.canonical import (
    JCSEncodeError,
    bundle_digest,
    jcs_canonicalize,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "conformance"
    / "jcs"
    / "rfc8785_corpus.json"
)

CORPUS_SCHEMA = "relay.conformance.jcs.v1"
MIN_VALUE_KIND_CASES = 12


def _load_corpus() -> dict[str, Any]:
    if not CORPUS_PATH.is_file():
        raise AssertionError(
            f"VAL-W10-016 corpus missing at {CORPUS_PATH}; "
            "run scripts/generate-jcs-rfc8785-corpus.py to regenerate."
        )
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# VAL-W10-016: corpus loads and reaches case-count threshold
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-016")
def test_corpus_schema_and_minimum_case_count() -> None:
    """Corpus declares the v1 schema and contains >= 12 value-kind cases."""
    corpus = _load_corpus()
    assert corpus["schema"] == CORPUS_SCHEMA
    value_cases = [c for c in corpus["cases"] if c["kind"] == "value"]
    assert len(value_cases) >= MIN_VALUE_KIND_CASES, (
        f"VAL-W10-016 requires >= {MIN_VALUE_KIND_CASES} value-kind cases; "
        f"got {len(value_cases)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-016")
def test_corpus_every_value_case_canonicalises_byte_for_byte() -> None:
    """Every value-kind case canonicalises to the corpus-pinned bytes."""
    corpus = _load_corpus()
    failures: list[str] = []
    for case in corpus["cases"]:
        if case["kind"] != "value":
            continue
        actual_bytes = jcs_canonicalize(case["input"])
        expected_bytes = base64.b64decode(case["expected_canonical_b64"])
        if actual_bytes != expected_bytes:
            failures.append(
                f"{case['name']}: expected={expected_bytes!r} "
                f"got={actual_bytes!r}"
            )
        # Defence in depth: the JSON-stored UTF-8 string MUST match
        # the bytes when re-encoded; this catches an editor that
        # accidentally normalised the corpus file.
        if actual_bytes != case["expected_canonical_utf8"].encode("utf-8"):
            failures.append(
                f"{case['name']}: utf8-string mirror diverges from b64 bytes"
            )
    assert not failures, (
        "VAL-W10-016 corpus mismatches: " + "; ".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-016")
def test_corpus_zero_failures_summary() -> None:
    """Single-line summary assertion -- corpus pass count == case count,
    fail count == 0. Mirrors the assertion's evidence requirement."""
    corpus = _load_corpus()
    pass_count = 0
    fail_count = 0
    for case in corpus["cases"]:
        if case["kind"] != "value":
            continue
        try:
            actual_bytes = jcs_canonicalize(case["input"])
        except (JCSEncodeError, TypeError):
            fail_count += 1
            continue
        if actual_bytes == base64.b64decode(case["expected_canonical_b64"]):
            pass_count += 1
        else:
            fail_count += 1
    assert fail_count == 0, (
        f"VAL-W10-016: fail_count must be 0; got {fail_count} "
        f"(pass_count={pass_count})"
    )
    assert pass_count >= MIN_VALUE_KIND_CASES


# ---------------------------------------------------------------------------
# VAL-W10-017: numeric edge cases (IEEE 754 + negative zero)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_negative_zero_collapses_to_unsigned_zero() -> None:
    """RFC 8785 sec 3.2.2 ECMA-262 ToString collapses -0 to '0'."""
    assert jcs_canonicalize(-0.0) == b"0"
    assert jcs_canonicalize(0.0) == b"0"
    assert jcs_canonicalize(0) == b"0"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_whole_valued_float_emits_without_trailing_dot_zero() -> None:
    """1.0 emits as '1', not '1.0' -- ECMA-262 ToString form."""
    assert jcs_canonicalize(1.0) == b"1"
    assert jcs_canonicalize(2.0) == b"2"
    assert jcs_canonicalize(-1.0) == b"-1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_fractional_float_round_trips_via_repr() -> None:
    """Non-whole floats use repr's shortest round-trip form."""
    assert jcs_canonicalize(0.5) == b"0.5"
    assert jcs_canonicalize(-0.5) == b"-0.5"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_large_decimal_float_emits_decimal_not_scientific() -> None:
    """1e10 fits below the 1e21 boundary and emits as '10000000000'."""
    assert jcs_canonicalize(1e10) == b"10000000000"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_large_integer_preserves_precision() -> None:
    """Python int has arbitrary precision; encoder uses str(int)."""
    assert jcs_canonicalize(12345678901234) == b"12345678901234"
    assert jcs_canonicalize(-12345678901234) == b"-12345678901234"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_nan_rejected_with_jcs_encode_error() -> None:
    """RFC 8785 forbids NaN at canonicalisation time."""
    with pytest.raises(JCSEncodeError):
        jcs_canonicalize(float("nan"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_positive_infinity_rejected_with_jcs_encode_error() -> None:
    """RFC 8785 forbids +Inf at canonicalisation time."""
    with pytest.raises(JCSEncodeError):
        jcs_canonicalize(float("inf"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_negative_infinity_rejected_with_jcs_encode_error() -> None:
    """RFC 8785 forbids -Inf at canonicalisation time."""
    with pytest.raises(JCSEncodeError):
        jcs_canonicalize(float("-inf"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-017")
def test_corpus_reject_cases_present_for_each_non_finite() -> None:
    """The corpus's reject_cases list documents NaN/+Inf/-Inf rejection."""
    corpus = _load_corpus()
    reject_names = {c["name"] for c in corpus["reject_cases"]}
    assert "reject_nan" in reject_names
    assert "reject_positive_infinity" in reject_names
    assert "reject_negative_infinity" in reject_names


# ---------------------------------------------------------------------------
# VAL-W10-018: key ordering by UTF-16 code units
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-018")
def test_keys_sort_by_code_unit_ascii_then_cyrillic() -> None:
    """ASCII 'A' (U+0041) sorts before Cyrillic 'A' (U+0410)."""
    out = jcs_canonicalize({"A": "ascii", "А": "cyr"})
    # 'A' = 0x41 < 0x410 'A' (Cyr); ASCII key comes first.
    assert out == '{"A":"ascii","А":"cyr"}'.encode()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-018")
def test_keys_sort_by_code_unit_uppercase_before_lowercase() -> None:
    """ASCII 'A' (0x41) < 'B' (0x42) < 'a' (0x61) < 'b' (0x62)."""
    out = jcs_canonicalize({"b": 1, "B": 2, "a": 3, "A": 4})
    assert out == b'{"A":4,"B":2,"a":3,"b":1}'


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-018")
def test_keys_sort_via_corpus_vector() -> None:
    """The corpus vectors covering BMP key sort match the verifier output."""
    corpus = _load_corpus()
    bmp_cases = [
        c for c in corpus["cases"]
        if c.get("category") == "key_sort_utf16"
    ]
    assert bmp_cases, "corpus must contain at least one key_sort_utf16 case"
    for case in bmp_cases:
        actual = jcs_canonicalize(case["input"])
        expected = base64.b64decode(case["expected_canonical_b64"])
        assert actual == expected, (
            f"VAL-W10-018: case {case['name']} key-sort mismatch: "
            f"expected={expected!r} got={actual!r}"
        )


# ---------------------------------------------------------------------------
# VAL-W10-019: digest stability across runtime versions
# ---------------------------------------------------------------------------


_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-019")
def test_every_corpus_digest_is_lowercase_hex_64() -> None:
    """The golden-digest column MUST be lowercase 64-character hex."""
    corpus = _load_corpus()
    for case in corpus["cases"]:
        digest = case["expected_sha256"]
        assert _HEX_RE.match(digest), (
            f"VAL-W10-019: case {case['name']} digest is not 64-char hex: "
            f"{digest!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-019")
def test_every_value_case_digest_matches_corpus_golden() -> None:
    """SHA-256 of canonical bytes equals the corpus golden digest.

    Drift on ANY case across Python 3.12 / 3.13 / 3.14 fails this
    test. Drift means either: (a) the runtime's int-to-string or
    float-to-string changed; (b) the verifier's encoder changed
    without updating the corpus; (c) the corpus was tampered with.
    """
    corpus = _load_corpus()
    failures: list[str] = []
    for case in corpus["cases"]:
        if case["kind"] != "value":
            continue
        actual_digest = hashlib.sha256(jcs_canonicalize(case["input"])).hexdigest()
        if actual_digest != case["expected_sha256"]:
            failures.append(
                f"{case['name']}: expected_sha256={case['expected_sha256']!r} "
                f"actual_sha256={actual_digest!r}"
            )
    assert not failures, (
        "VAL-W10-019 digest drift: " + "; ".join(failures)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-019")
def test_inline_known_digest_is_independent_of_corpus_file() -> None:
    """A hand-pinned vector keeps VAL-W10-019 honest if the corpus is lost.

    Input: {"name":"relay","ok":true,"count":3,"items":[1,2,3]}
    Canonical bytes (sorted keys, ECMA-262 numbers, no whitespace):
        {"count":3,"items":[1,2,3],"name":"relay","ok":true}
    """
    payload = {"name": "relay", "ok": True, "count": 3, "items": [1, 2, 3]}
    canonical = jcs_canonicalize(payload)
    assert canonical == b'{"count":3,"items":[1,2,3],"name":"relay","ok":true}'
    expected = hashlib.sha256(
        b'{"count":3,"items":[1,2,3],"name":"relay","ok":true}'
    ).hexdigest()
    assert hashlib.sha256(canonical).hexdigest() == expected


# ---------------------------------------------------------------------------
# Cross-package parity guard: relay_contracts.canonical and
# relay_verifier.canonical MUST produce identical bytes for every case.
# This guards the duplication tax we accept by mirroring the encoder.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-016")
def test_verifier_canonical_matches_contracts_canonical() -> None:
    """The verifier's JCS encoder MUST byte-equal the contracts encoder
    for every corpus case. If this fails, one encoder drifted and the
    duplication needs reconciliation BEFORE merge."""
    from relay_contracts.canonical import jcs_canonicalize as contracts_jcs

    corpus = _load_corpus()
    failures: list[str] = []
    for case in corpus["cases"]:
        if case["kind"] != "value":
            continue
        v_bytes = jcs_canonicalize(case["input"])
        c_bytes = contracts_jcs(case["input"])
        if v_bytes != c_bytes:
            failures.append(
                f"{case['name']}: verifier={v_bytes!r} contracts={c_bytes!r}"
            )
    assert not failures, (
        "Cross-package JCS drift: " + "; ".join(failures)
    )


# ---------------------------------------------------------------------------
# bundle_digest helper smoke tests (used by VAL-W10-020 in detail)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-019")
def test_bundle_digest_returns_lowercase_hex() -> None:
    digest = bundle_digest({"a": 1})
    assert _HEX_RE.match(digest)
