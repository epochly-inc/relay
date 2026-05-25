"""Regression tests for the cel-spec corpus generator's pure functions.

scripts/build-celspec-corpus.py re-derives the W17.3 conformance corpus
from upstream google/cel-spec. Its profile classifier, string-literal
stripper, textproto unescaper, and value decoder are the load-bearing
correctness surface (a wrong classifier silently includes/excludes
vectors; a wrong unescaper mangles unicode goldens). These tests pin that
behavior so review-found edge cases (uppercase/raw bytes prefixes,
patterns inside string bodies, SMP-unicode reassembly, uint/bytes
rejection) cannot regress.

The generator is a hyphenated script (not an importable module), so it is
loaded via importlib. Only PURE functions are exercised -- no network,
no subprocess, no cel runtime.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GEN_PATH = _REPO_ROOT / "scripts" / "build-celspec-corpus.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("build_celspec_corpus", _GEN_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_celspec_corpus"] = mod
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()


# ---------------------------------------------------------------------------
# _expr_in_profile: profile classification (string-aware)
# ---------------------------------------------------------------------------

_IN_PROFILE = [
    "1 + 2",
    "'abc' == 'abc'",
    '"b"',          # string whose body is just b -- NOT a bytes literal
    "'web'",        # body ends in b
    "'webB'",       # body ends in B
    "'5u'",         # uint-looking text inside a string body
    "'dyn('",       # function-call text inside a string body
    'r"raw"',       # raw STRING (not bytes) is in profile
    'R"raw"',
    "size('hello')",
]

_OUT_OF_PROFILE = [
    "b\"x\"",       # bytes literal, lowercase
    "B\"x\"",       # bytes literal, uppercase
    "b'x'",
    "br\"x\"",      # raw bytes, b then r
    "bR'x'",
    "rb\"x\"",      # raw bytes, r then b
    "Rb'x'",
    "5u",           # uint literal
    "0U",
    "dyn(0)",
    "timestamp('2009-02-13T23:31:30Z')",
    "duration('1s')",
    "bytes('x')",
    "uint(5)",
]


@pytest.mark.plumbing
@pytest.mark.parametrize("expr", _IN_PROFILE)
def test_expr_in_profile_accepts(expr: str) -> None:
    assert gen._expr_in_profile(expr) is True, f"{expr!r} should be in profile"


@pytest.mark.plumbing
@pytest.mark.parametrize("expr", _OUT_OF_PROFILE)
def test_expr_in_profile_rejects(expr: str) -> None:
    assert gen._expr_in_profile(expr) is False, f"{expr!r} should be out of profile"


# ---------------------------------------------------------------------------
# _strip_string_bodies
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_strip_string_bodies_keeps_quotes_drops_content() -> None:
    assert gen._strip_string_bodies('b"xy"') == 'b""'
    assert gen._strip_string_bodies('"dyn("') == '""'
    assert gen._strip_string_bodies("'ab' + 'cd'") == "'' + ''"
    # escaped quote inside the body must not end the string early
    assert gen._strip_string_bodies(r"'a\'b'") == "''"
    # code outside strings is preserved
    assert gen._strip_string_bodies("1 + 2") == "1 + 2"


# ---------------------------------------------------------------------------
# _unescape: textproto byte-escape reassembly as UTF-8
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_unescape_reassembles_utf8_byte_escapes() -> None:
    # cat emoji U+1F431 is encoded in textproto as four \xHH UTF-8 bytes.
    assert gen._unescape(r"\xf0\x9f\x90\xb1") == "\U0001f431"
    # mixed literal + escape: 'a' + U+00FF (y with diaeresis, utf-8 c3 bf).
    # chr(...) keeps this source file ASCII-only per CLAUDE.md.
    assert gen._unescape(r"a\xc3\xbf") == "a" + chr(0xFF)
    # the cat emoji again, as the single decoded code point
    assert gen._unescape(r"\xf0\x9f\x90\xb1") == chr(0x1F431)
    # simple escapes + plain text
    assert gen._unescape(r"line\none") == "line\none"
    # a literal non-ASCII char in the input round-trips unchanged
    assert gen._unescape(chr(0xE9)) == chr(0xE9)


# ---------------------------------------------------------------------------
# _decode_value: profile-safe kinds accepted, others rejected
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_decode_value_accepts_profile_kinds() -> None:
    assert gen._decode_value({"int64_value": 7}) == 7
    assert gen._decode_value({"bool_value": True}) is True
    assert gen._decode_value({"string_value": "x"}) == "x"
    assert gen._decode_value({"null_value": "NULL_VALUE"}) is None
    assert gen._decode_value({"double_value": 1.5}) == 1.5
    assert gen._decode_value(
        {"list_value": {"values": [{"int64_value": 1}, {"int64_value": 2}]}}
    ) == [1, 2]
    assert gen._decode_value(
        {"map_value": {"entries": [{"key": {"string_value": "a"},
                                    "value": {"int64_value": 1}}]}}
    ) == {"a": 1}


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "value",
    [
        {"uint64_value": 5},
        {"bytes_value": "x"},
        {"type_value": "int"},
        {"double_value": float("inf")},
        {"double_value": float("nan")},
    ],
)
def test_decode_value_rejects_out_of_profile(value: dict) -> None:
    with pytest.raises(gen._Unsafe):
        gen._decode_value(value)


@pytest.mark.plumbing
def test_vector_id_format() -> None:
    vid = gen._vector_id({"file": "basic.textproto", "section": "sec", "test": "t"})
    assert vid == "basic/sec/t"
