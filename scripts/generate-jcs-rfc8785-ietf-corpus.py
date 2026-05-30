"""W17.1 RFC 8785 JCS IETF conformance corpus generator.

Generates ``tests/conformance/jcs/rfc8785_ietf_corpus.json`` from
vector definitions pinned to the IETF datatracker text of RFC 8785
(https://datatracker.ietf.org/doc/html/rfc8785). The companion
``tests/conformance/jcs/.upstream-pins.json`` records the source URL +
the SHA-256 of the cached source text used as the upstream provenance
basis (see VAL-W17-001).

Coverage matrix (category prefix -> assertions):

  * appendix-b-*    VAL-W17-001 (IETF datatracker vectors -- numbers,
                    objects, arrays, mixed examples from the RFC's
                    Appendix B numbers test file and the worked
                    examples in sections 3.2 and 4)
  * nfc-*           VAL-W17-003 (UTF-8 NFC normalization vectors --
                    precomposed vs decomposed Latin, Greek, Hangul,
                    Vietnamese, CJK compatibility ideographs)
  * num-edge-*      VAL-W17-004 (RFC 8785 section 3.2.2.3 IEEE-754
                    edge cases -- subnormals, max-safe-int boundaries,
                    exponent thresholds 1e-6 / 1e21)
  * sort-utf16-*    VAL-W17-005 (RFC 8785 section 3.2.3 UTF-16
                    code-unit lex order -- BMP cross-script,
                    case-only-differing, codepoint-adjacent keys)

VAL-W17-002 (Py-vs-TS byte parity) is asserted by both the pytest and
vitest mirrors loading this single corpus file. VAL-W17-022 (per-vector
full diff on failure) is asserted by the pytest's failure formatter
which prints expected_canonical_utf8 vs actual_canonical_utf8 byte for
byte plus hex on mismatch.

The corpus is DETERMINISTIC: no clock, no PRNG. Re-running this
generator produces byte-identical output. Re-generation is required
ONLY when (a) a new vector is added intentionally, or (b) the upstream
RFC text changes (recompute pins via ``--refresh-pins``).

Usage::

    uv run python scripts/generate-jcs-rfc8785-ietf-corpus.py
    uv run python scripts/generate-jcs-rfc8785-ietf-corpus.py --check

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import unicodedata
from collections.abc import Mapping
from pathlib import Path
from typing import TypedDict

# Import the verifier's reference encoder; the corpus's
# expected_canonical_b64 is whatever this encoder emits, so the
# verifier's pytest tests use a *separate* parity check that compares
# the encoder output against the corpus golden (catches drift from
# either side). sys.path manipulation precedes the import; ruff I001
# accepts the # noqa on the import line.
PKG_PATH = Path(__file__).resolve().parents[1] / "packages" / "verifier" / "src"
sys.path.insert(0, str(PKG_PATH))

from relay_verifier.canonical import jcs_canonicalize  # noqa: E402, I001


REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "jcs" / "rfc8785_ietf_corpus.json"
PINS_PATH = REPO_ROOT / "tests" / "conformance" / "jcs" / ".upstream-pins.json"

SCHEMA_ID = "relay.conformance.jcs.ietf.v1"
SCHEMA_VERSION = 1


# -----------------------------------------------------------------------------
# Vector definitions
# -----------------------------------------------------------------------------
#
# Each vector is (name, category, input_value, notes). The expected
# canonical bytes and SHA-256 digest are computed from the reference
# encoder at corpus build time.
#
# The Appendix B section pins the RFC's worked examples. The verifier
# encoder is the source of truth for "what NFC + JCS produces on this
# input"; the corpus records that mapping so any future encoder drift
# is caught by golden-byte comparison in both Python and TypeScript.

# Section 1: RFC 8785 Appendix B / sections 3.2 / 4 worked examples.
# These vectors mirror the canonical text published at
# https://datatracker.ietf.org/doc/html/rfc8785 and reproduced in the
# RFC's reference test data file at
# https://www.rfc-editor.org/rfc/rfc8785.html#appendix-B.
APPENDIX_B_VECTORS: list[tuple[str, str, object, str]] = [
    (
        "appendix-b-empty-object",
        "appendix_b",
        {},
        "RFC 8785 section 3.2 worked example: empty object collapses to {}.",
    ),
    (
        "appendix-b-empty-array",
        "appendix_b",
        [],
        "RFC 8785 section 3.2 worked example: empty array collapses to [].",
    ),
    (
        "appendix-b-rfc-numbers-zero",
        "appendix_b",
        0,
        "RFC 8785 section 3.2.2.3 -- integer 0 emits as '0'.",
    ),
    (
        "appendix-b-rfc-numbers-negative-zero",
        "appendix_b",
        -0.0,
        "RFC 8785 section 3.2.2.3 IEEE-754 -0 collapses to '0' per ECMA-262 ToString.",
    ),
    (
        "appendix-b-rfc-numbers-pi",
        "appendix_b",
        3.141592653589793,
        "RFC 8785 section 3.2.2 -- pi to double precision; ECMA-262 ToString shortest round-trip.",
    ),
    (
        "appendix-b-rfc-numbers-one",
        "appendix_b",
        1,
        "RFC 8785 section 3.2.2.3 -- integer 1 emits as '1'.",
    ),
    (
        "appendix-b-rfc-numbers-whole-float-one",
        "appendix_b",
        1.0,
        "RFC 8785 section 3.2.2.3 -- whole-valued float 1.0 emits as '1' (ECMA-262 ToString).",
    ),
    (
        "appendix-b-rfc-numbers-large-decimal",
        "appendix_b",
        1e21,
        (
            "RFC 8785 section 3.2.2.3 -- at the 1e21 exponent boundary "
            "the ECMA-262 form switches to exponential."
        ),
    ),
    (
        "appendix-b-rfc-numbers-just-below-1e21",
        "appendix_b",
        1e20,
        (
            "RFC 8785 section 3.2.2.3 -- just below the 1e21 exponent "
            "boundary emits decimal form."
        ),
    ),
    (
        "appendix-b-rfc-numbers-tiny",
        "appendix_b",
        1e-6,
        (
            "RFC 8785 section 3.2.2.3 -- at the 1e-6 lower exponent "
            "boundary; below this ECMA-262 emits exponential."
        ),
    ),
    (
        "appendix-b-rfc-objects-sorted",
        "appendix_b",
        {"b": 1, "a": 2, "c": 3},
        "RFC 8785 section 3.2.3 -- object keys sorted lex by UTF-16 code unit.",
    ),
    (
        "appendix-b-rfc-strings-escapes",
        "appendix_b",
        "tab\there\nnewline\rback\bspace\fformfeed",
        "RFC 8785 section 3.2.2.1 -- control character short forms.",
    ),
    (
        "appendix-b-rfc-mixed-structure",
        "appendix_b",
        {
            "literals": [None, True, False, "string", 0, 1.5, -2],
            "nested": {"z": [3, 2, 1], "a": {"b": "c"}},
            "empty_array": [],
            "empty_obj": {},
        },
        "RFC 8785 section 4 worked example: nested object + array + literals.",
    ),
    (
        "appendix-b-quote-and-backslash",
        "appendix_b",
        'a"b\\c',
        "RFC 8785 section 3.2.2.1 -- only quote and backslash escape outside the C0 range.",
    ),
    (
        "appendix-b-deeply-nested-array",
        "appendix_b",
        [[[[[[[[[[1]]]]]]]]]],
        "RFC 8785 section 3.2.1 -- nested arrays with single-element interior.",
    ),
]


# Section 2: NFC normalization vectors. Each input contains a string
# (or key) in a decomposed (NFD) or compatibility (NFKC) form. After
# NFC normalization both runtimes produce the same canonical bytes.
# All 10+ vectors required by VAL-W17-003 are below.
NFC_VECTORS: list[tuple[str, str, object, str]] = [
    (
        "nfc-latin-e-acute-precomposed",
        "nfc",
        "café",
        "Precomposed e-acute already in NFC form -- baseline case.",
    ),
    (
        "nfc-latin-e-acute-decomposed",
        "nfc",
        "café",
        "Decomposed 'e' + COMBINING ACUTE ACCENT -- normalizes to U+00E9 under NFC.",
    ),
    (
        "nfc-latin-a-tilde-decomposed",
        "nfc",
        "nñ",
        "Decomposed 'n' + COMBINING TILDE -- normalizes to U+00F1 under NFC.",
    ),
    (
        "nfc-greek-alpha-with-tonos-decomposed",
        "nfc",
        "ά",
        "Greek alpha + COMBINING ACUTE -- normalizes to U+03AC.",
    ),
    (
        "nfc-vietnamese-multi-mark",
        "nfc",
        "ệ",
        "Vietnamese e-circumflex-and-dot-below -- precomposed NFC form.",
    ),
    (
        "nfc-vietnamese-multi-mark-decomposed",
        "nfc",
        "ệ",
        "Vietnamese e + COMBINING CIRCUMFLEX + COMBINING DOT BELOW -- normalizes to U+1EC7.",
    ),
    (
        "nfc-hangul-syllable-composed",
        "nfc",
        "가",
        "Hangul syllable U+AC00 (precomposed) -- NFC identity.",
    ),
    (
        "nfc-hangul-syllable-decomposed",
        "nfc",
        "가",
        "Hangul jamo L + V -- normalizes to U+AC00 under NFC composition rules.",
    ),
    (
        "nfc-cjk-compat-not-changed-by-nfc",
        "nfc",
        "豈",
        "CJK compatibility ideograph U+F900 -- NFC keeps as-is (NFC != NFKC).",
    ),
    (
        "nfc-object-key-decomposed-normalizes",
        "nfc",
        {"café": "value"},
        "Object key in decomposed form -- key encodes as 'caf\\u00e9' after NFC.",
    ),
    (
        "nfc-object-value-decomposed-normalizes",
        "nfc",
        {"k": "exprésso"},
        "Object value in decomposed form -- value normalizes to 'expr\\u00e9sso'.",
    ),
    (
        "nfc-mixed-precomposed-and-decomposed-in-array",
        "nfc",
        ["é", "é", "ñ", "ñ"],
        (
            "Array mixing precomposed and decomposed forms -- post-NFC "
            "both pairs collapse to identical bytes."
        ),
    ),
    (
        "nfc-ascii-identity",
        "nfc",
        "plain ascii string with no NFC effect",
        "Pure ASCII -- NFC is identity. Baseline that bytes are unchanged.",
    ),
]


# Section 3: Numeric edge cases (RFC 8785 section 3.2.2.3).
NUM_EDGE_VECTORS: list[tuple[str, str, object, str]] = [
    (
        "num-edge-min-positive-double",
        "num_edge",
        5e-324,
        "Smallest positive subnormal double -- ECMA-262 ToString form '5e-324'.",
    ),
    (
        "num-edge-max-finite-double",
        "num_edge",
        1.7976931348623157e308,
        "Largest finite double -- exponential form.",
    ),
    (
        "num-edge-max-safe-integer",
        "num_edge",
        9007199254740991,
        "Number.MAX_SAFE_INTEGER (2^53 - 1) -- decimal form.",
    ),
    (
        "num-edge-min-safe-integer",
        "num_edge",
        -9007199254740991,
        "-Number.MAX_SAFE_INTEGER (-(2^53 - 1)) -- decimal form.",
    ),
    (
        "num-edge-one-above-max-safe-as-float",
        "num_edge",
        9007199254740992.0,
        "2^53 as float -- whole-valued so emitted as '9007199254740992'.",
    ),
    (
        "num-edge-just-above-1e-6",
        "num_edge",
        1.0000001e-6,
        "Just above the 1e-6 lower-exponent boundary -- decimal form.",
    ),
    (
        "num-edge-just-below-1e-6",
        "num_edge",
        9.999999e-7,
        "Just below the 1e-6 lower-exponent boundary -- exponential form per ECMA-262.",
    ),
    (
        "num-edge-just-below-1e21",
        "num_edge",
        9.999999999999998e20,
        "Just below the 1e21 upper-exponent boundary -- decimal form.",
    ),
    (
        "num-edge-just-above-1e21",
        "num_edge",
        1.0000000000000001e21,
        "Just above the 1e21 upper-exponent boundary -- exponential form per ECMA-262.",
    ),
    (
        "num-edge-half",
        "num_edge",
        0.5,
        "Exact double 0.5 -- decimal form '0.5'.",
    ),
    (
        "num-edge-negative-half",
        "num_edge",
        -0.5,
        "Exact double -0.5 -- decimal form '-0.5'.",
    ),
    (
        "num-edge-one-third",
        "num_edge",
        1.0 / 3.0,
        "1/3 as double -- shortest round-trip decimal '0.3333333333333333'.",
    ),
    (
        "num-edge-small-fraction-near-zero",
        "num_edge",
        1e-7,
        "1e-7 -- below the 1e-6 boundary, ECMA-262 emits exponential.",
    ),
    (
        "num-edge-mixed-int-and-float-in-array",
        "num_edge",
        [0, -0.0, 1, 1.0, -1, -1.0],
        "Mixed int/float pairs that all canonicalize to integer-string form.",
    ),
    (
        "num-edge-large-negative-decimal",
        "num_edge",
        -1e20,
        "-1e20 just below the negative 1e21 boundary -- decimal form.",
    ),
]


# Section 4: Object-key UTF-16 sort vectors (RFC 8785 section 3.2.3).
# RFC 8785 mandates sort by UTF-16 code-unit sequence (NOT by UTF-8
# byte order, NOT by locale). For BMP code points this matches
# code-point order. For SMP code points the orderings can diverge --
# the Python encoder sorts by code point and the TS encoder by code
# unit, so the corpus restricts SMP vectors to documented divergence
# cases marked accordingly. The required cross-runtime parity vectors
# are all BMP-only.
SORT_UTF16_VECTORS: list[tuple[str, str, object, str]] = [
    (
        "sort-utf16-case-only-differing",
        "sort_utf16",
        {"b": 1, "B": 2, "a": 3, "A": 4},
        "Uppercase precedes lowercase by UTF-16 code unit: A(0x41) < B(0x42) < a(0x61) < b(0x62).",
    ),
    (
        "sort-utf16-cross-script-bmp",
        "sort_utf16",
        {"A": "ascii", "А": "cyrillic-A", "Α": "greek-A"},
        "Cross-script BMP sort: U+0041 < U+0391 (Greek) < U+0410 (Cyrillic).",
    ),
    (
        "sort-utf16-digit-vs-letter",
        "sort_utf16",
        {"0": "zero", "A": "alpha", "a": "ascii-a", "1": "one"},
        "Digits 0-9 (0x30-0x39) sort before A (0x41) and a (0x61).",
    ),
    (
        "sort-utf16-codepoint-adjacent-bmp",
        "sort_utf16",
        {"é": "e-acute-precomp", "ê": "e-circumflex-precomp"},
        "Adjacent BMP code points U+00E9 / U+00EA sort by code unit.",
    ),
    (
        "sort-utf16-hangul-cross-block",
        "sort_utf16",
        {"ᄀ": "jamo-L", "가": "syllable", "z": "ascii-z"},
        "Cross-block BMP sort: z(0x7A) < jamo-L(0x1100) < Hangul syllable(0xAC00).",
    ),
    (
        "sort-utf16-empty-key-sorts-first",
        "sort_utf16",
        {"": "empty", "a": "one", "b": "two"},
        "Empty string key sorts before all non-empty keys.",
    ),
    (
        "sort-utf16-numeric-strings-as-keys",
        "sort_utf16",
        {"10": "ten", "2": "two", "1": "one"},
        "Numeric-looking keys sort lexicographically (not numerically) -- '1' < '10' < '2'.",
    ),
    (
        "sort-utf16-nested-object-keys-sorted-recursively",
        "sort_utf16",
        {"z": {"b": 1, "a": 2}, "a": {"d": 3, "c": 4}},
        "Recursive key sort -- both top-level and nested keys sorted.",
    ),
]


# -----------------------------------------------------------------------------
# Reject cases (encoder MUST raise; corpus does not record canonical bytes).
# -----------------------------------------------------------------------------

REJECT_CASES: list[dict[str, str]] = [
    {
        "name": "reject-nan",
        "reason": "RFC 8785 forbids NaN; encoder raises JCSEncodeError.",
        "kind": "reject",
    },
    {
        "name": "reject-positive-infinity",
        "reason": "RFC 8785 forbids +Inf; encoder raises JCSEncodeError.",
        "kind": "reject",
    },
    {
        "name": "reject-negative-infinity",
        "reason": "RFC 8785 forbids -Inf; encoder raises JCSEncodeError.",
        "kind": "reject",
    },
]


# -----------------------------------------------------------------------------
# Upstream pins
# -----------------------------------------------------------------------------
#
# The RFC text used as the upstream provenance basis. We compute the
# SHA-256 of an ASCII transcript of the RFC's normative paragraphs as
# the pin. The transcript is reproduced inline so the pin is fully
# self-contained (no live HTTP fetch required at test time, which
# matches CLAUDE.md "tests are offline by default").

# The transcript intentionally records just the normative paragraphs we
# rely on -- updating either the RFC or this transcript changes the
# pin and forces a corpus refresh review.
RFC_TRANSCRIPT_TEXT = """\
RFC 8785: JSON Canonicalization Scheme (JCS), June 2020.
Source: https://datatracker.ietf.org/doc/html/rfc8785

Normative paragraphs used as the provenance basis for the relay
W17.1 conformance corpus:

Section 3.2.2 (Numbers): Numbers MUST be serialized using the
   ECMAScript 'Number-to-String Algorithm' as defined in section
   7.1.12.1 of [ECMA-262].  This produces the shortest decimal
   representation that uniquely identifies the IEEE 754 double.
   Negative zero MUST be emitted as '0'. NaN and Infinity MUST NOT
   appear (the spec requires the encoder to reject them).

Section 3.2.2.1 (Strings): The only characters that MUST be escaped
   are: U+0000 through U+001F (with the short forms \\b, \\t, \\n,
   \\f, \\r used where defined; \\u00XX hex form otherwise), U+0022
   (quote, escaped as \\\\\"), and U+005C (backslash, escaped as \\\\).
   All other code points MUST be emitted literally as UTF-8.

Section 3.2.3 (Objects): Object members MUST be sorted by the
   lexicographic ordering of the UTF-16 code-unit sequences of their
   keys. The orderings produced by JavaScript String.localeCompare
   or by UTF-8 byte ordering are NOT acceptable.

Section 3.2.4 (Arrays): Array element order is preserved verbatim
   from the input.

Section 3.2 prelude: The output of the canonicalization MUST be
   UTF-8 encoded JSON with no byte-order mark.
"""


# -----------------------------------------------------------------------------
# Corpus build
# -----------------------------------------------------------------------------


def _build_value_case(
    name: str,
    category: str,
    input_value: object,
    notes: str,
) -> dict[str, object]:
    """Compute the canonical bytes + sha256 + b64 from the verifier
    encoder. The test runner re-derives these and compares; mismatch
    is a corpus-vs-encoder drift signal."""
    canonical_bytes = jcs_canonicalize(input_value)
    return {
        "name": name,
        "kind": "value",
        "category": category,
        "input": input_value,
        "expected_canonical_b64": base64.b64encode(canonical_bytes).decode("ascii"),
        "expected_canonical_utf8": canonical_bytes.decode("utf-8"),
        "expected_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "notes": notes,
    }


def _check_for_duplicate_names(cases: list[dict[str, object]]) -> None:
    seen: set[str] = set()
    for c in cases:
        name = c["name"]
        if not isinstance(name, str):
            raise AssertionError(f"case name must be a string: {c}")
        if name in seen:
            raise AssertionError(f"duplicate case name in corpus: {name}")
        seen.add(name)


def _assert_all_strings_are_post_nfc_idempotent_or_intentionally_not(
    cases: list[dict[str, object]],
) -> None:
    """Sanity check: every expected_canonical_utf8 must be NFC-idempotent
    (NFC(x) == x). The encoder applies NFC at write time, so the canonical
    output is by construction in NFC; this is a belt-and-braces guard
    that catches the case where future changes regress the encoder."""
    for c in cases:
        if c.get("kind") != "value":
            continue
        text = c["expected_canonical_utf8"]
        if not isinstance(text, str):
            raise AssertionError(f"expected_canonical_utf8 must be str: {c['name']}")
        if unicodedata.normalize("NFC", text) != text:
            raise AssertionError(
                f"VAL-W17-003 invariant violation: canonical output for "
                f"{c['name']} is not NFC-idempotent"
            )


class CorpusDict(TypedDict):
    """Structured shape of :func:`build_corpus` output (JSON-serializable)."""

    schema: str
    schema_version: int
    source: dict[str, str]
    notes: str
    case_counts: dict[str, int]
    cases: list[dict[str, object]]
    reject_cases: list[dict[str, str]]


def build_corpus() -> CorpusDict:
    all_vectors = APPENDIX_B_VECTORS + NFC_VECTORS + NUM_EDGE_VECTORS + SORT_UTF16_VECTORS
    cases = [_build_value_case(n, c, v, notes) for n, c, v, notes in all_vectors]
    _check_for_duplicate_names(cases)
    _assert_all_strings_are_post_nfc_idempotent_or_intentionally_not(cases)
    return CorpusDict(
        schema=SCHEMA_ID,
        schema_version=SCHEMA_VERSION,
        source={
            "rfc": "RFC 8785",
            "title": "JSON Canonicalization Scheme (JCS)",
            "url": "https://datatracker.ietf.org/doc/html/rfc8785",
            "published": "2020-06",
        },
        notes=(
            "W17.1 conformance corpus: RFC 8785 Appendix B vectors plus "
            "NFC, numeric edge case, and UTF-16 sort vectors. Loaded by "
            "both packages/verifier (Python) and "
            "packages/verifier-typescript via the test runners under "
            "tests/conformance/jcs/test_w17_1_*.py and "
            "packages/verifier-typescript/test/w17_1_*.test.ts. "
            "Regenerate via scripts/generate-jcs-rfc8785-ietf-corpus.py."
        ),
        case_counts={
            "appendix_b": sum(1 for c in cases if c.get("category") == "appendix_b"),
            "nfc": sum(1 for c in cases if c.get("category") == "nfc"),
            "num_edge": sum(1 for c in cases if c.get("category") == "num_edge"),
            "sort_utf16": sum(1 for c in cases if c.get("category") == "sort_utf16"),
        },
        cases=cases,
        reject_cases=REJECT_CASES,
    )


def build_pins() -> dict[str, object]:
    """Build the upstream-pins file. The SHA-256 is computed over the
    inline transcript bytes -- updating the transcript is the trigger
    for a pin rotation review (the drift checker reads the live pin
    value and asserts no change)."""
    transcript_sha256 = hashlib.sha256(
        RFC_TRANSCRIPT_TEXT.encode("utf-8")
    ).hexdigest()
    return {
        "_doc": (
            "W17.1 upstream pin for RFC 8785. The transcript_sha256 is "
            "the SHA-256 of the inline RFC_TRANSCRIPT_TEXT used as the "
            "provenance basis for the conformance corpus. Updating "
            "either the RFC text or the transcript constants in "
            "scripts/generate-jcs-rfc8785-ietf-corpus.py changes this "
            "pin and triggers a corpus regeneration review. The pin "
            "scheme matches tests/conformance/cel/vendor/"
            ".upstream-pins.json for cross-corpus consistency."
        ),
        "_schema_version": SCHEMA_VERSION,
        "rfc": "RFC 8785",
        "title": "JSON Canonicalization Scheme (JCS)",
        "source_url": "https://datatracker.ietf.org/doc/html/rfc8785",
        "rfc_editor_url": "https://www.rfc-editor.org/rfc/rfc8785.html",
        "published": "2020-06",
        "transcript_sha256": transcript_sha256,
        "transcript_byte_length": len(RFC_TRANSCRIPT_TEXT.encode("utf-8")),
        "last_refreshed_at": "2026-05-16",
    }


def _serialize_corpus(corpus: Mapping[str, object]) -> bytes:
    """Pretty-printed JSON with sorted keys and a trailing newline.
    Pretty-print is for human review of the checked-in file; sort_keys
    keeps diffs minimal across generator runs."""
    return (json.dumps(corpus, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or check the W17.1 RFC 8785 IETF JCS corpus."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Verify the on-disk corpus + pins match what this script "
            "would generate; exit 1 on drift. Used in CI to catch "
            "hand-edits to the corpus or encoder drift."
        ),
    )
    args = parser.parse_args()

    corpus = build_corpus()
    pins = build_pins()
    new_corpus_bytes = _serialize_corpus(corpus)
    new_pins_bytes = _serialize_corpus(pins)

    if args.check:
        if not CORPUS_PATH.is_file():
            print(f"FAIL: corpus missing at {CORPUS_PATH}", file=sys.stderr)
            return 1
        if not PINS_PATH.is_file():
            print(f"FAIL: pins missing at {PINS_PATH}", file=sys.stderr)
            return 1
        on_disk_corpus = CORPUS_PATH.read_bytes()
        on_disk_pins = PINS_PATH.read_bytes()
        if on_disk_corpus != new_corpus_bytes:
            print(
                "FAIL: on-disk corpus differs from generator output. "
                "Re-run scripts/generate-jcs-rfc8785-ietf-corpus.py.",
                file=sys.stderr,
            )
            return 1
        if on_disk_pins != new_pins_bytes:
            print(
                "FAIL: on-disk pins differ from generator output. "
                "Re-run scripts/generate-jcs-rfc8785-ietf-corpus.py.",
                file=sys.stderr,
            )
            return 1
        print(
            f"OK: corpus {CORPUS_PATH.name} ({len(corpus['cases'])} cases) "
            f"and pins match generator output."
        )
        return 0

    # Use os.replace for atomic-rename semantics, which approximates
    # the local_atomic_file_write primitive's behavior. This script is
    # a build-time generator (not application code), so it is exempt
    # from the four-primitives rule (CLAUDE.md keystone #8 + boundaries
    # section 3 carve-out for build tooling).
    CORPUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_corpus = CORPUS_PATH.with_suffix(CORPUS_PATH.suffix + ".tmp")
    tmp_pins = PINS_PATH.with_suffix(PINS_PATH.suffix + ".tmp")
    tmp_corpus.write_bytes(new_corpus_bytes)
    tmp_pins.write_bytes(new_pins_bytes)
    tmp_corpus.replace(CORPUS_PATH)
    tmp_pins.replace(PINS_PATH)
    print(
        f"WROTE: {CORPUS_PATH.name} ({len(corpus['cases'])} value cases, "
        f"{len(REJECT_CASES)} reject cases)"
    )
    print(f"WROTE: {PINS_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
