"""G5/G7/G8: lexer literal parsing (cel-rust-relay fork), driven through the wasm.

These three gaps live in the vendored fork's literal-token decoder
(`vendor/cel/src/parser/{parse.rs,parser.rs}`) and are fixed to match cel-go
v0.28.1 exactly (the conformance oracle). All edits are marked `Relay fork (G5)`
/ `(G7)` / `(G8)`.

  G5 -- number-literal parsing.
    * Negative radix-prefixed ints: `-0x55555555` parses to -1431655765. The
      previous decoder ran `ctx.get_text().strip_prefix("0x")` on `-0x...`
      (text starts with `-`), the strip failed, and `"-0x...".parse::<i64>()`
      errored -> `invalid int literal`. The fork mirrors cel-go VisitInt: take
      the NUM_INT token text, strip `0x` -> base 16, THEN prepend the sign.
    * Repeated unary minus composes by parity: `--------19` (even) -> 19,
      `---19` (odd) -> -19. The previous visit_Negate visited the member then
      ALWAYS wrapped in one NEGATE, folding even chains to a single negate.
      The fork mirrors cel-go VisitNegate/VisitLogicalNot: an even op count
      returns the member directly.

  G7 -- triple-quoted string/bytes keep the inner delimiters.
    * `b'''hello'''` -> bytes 68656c6c6f (`hello`), not 2727...2727. The fork
      strips the full triple-quote delimiter span (cel-go value[3:n-3]) before
      decoding, for strings AND bytes (incl. raw r'''/br'''). The byte caller
      previously pre-stripped only one trailing quote (string[2..len-1]),
      embedding the inner '' / "".

  G8 -- string escape handling.
    * The CEL escape set is quote-context independent: backslash-?,
      backslash-doublequote, backslash-singlequote, and backslash-backtick all
      decode to the bare character regardless of the opening quote.
      backslash-X (upper-case hex) is a valid byte escape alongside
      backslash-x. For bytes, hex/octal escapes denote raw byte values and
      backslash-u / backslash-U are rejected; for strings they denote unicode
      code points.

Ground truth for every expected value below is the cel-go oracle
(github.com/google/cel-go v0.28.1) run directly on the same expression.

Control-char expected values are written with explicit Python escape sequences
(\\x07, \\n, \\x7f, ...) so this source file stays ASCII-clean (no embedded
control/NUL bytes), per CLAUDE.md directive 3.

Tier-1 plumbing; runs against the actual release wasm.
Run:  pytest packages/cel-wasm/tests -v
(requires `cargo build --release --target wasm32-unknown-unknown` in crate/)
"""
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "python"))

from relay_cel_wasm import RelayCel  # noqa: E402

pytestmark = pytest.mark.plumbing


@pytest.fixture(scope="module")
def cel():
    wasm = os.path.normpath(
        os.path.join(
            _HERE,
            "..",
            "crate",
            "target",
            "wasm32-unknown-unknown",
            "release",
            "relay_cel_wasm.wasm",
        )
    )
    return RelayCel(wasm)


def _val(cel, expr):
    r = cel.eval(expr)
    assert r["ok"], f"{expr!r} unexpectedly rejected: {r}"
    return r["value"]


def _int(cel, expr):
    v = _val(cel, expr)
    assert v["t"] == "int", f"{expr!r} -> {v}"
    return int(v["v"])


def _uint(cel, expr):
    v = _val(cel, expr)
    assert v["t"] == "uint", f"{expr!r} -> {v}"
    return int(v["v"])


def _str(cel, expr):
    v = _val(cel, expr)
    assert v["t"] == "string", f"{expr!r} -> {v}"
    return v["v"]


def _bytes_hex(cel, expr):
    v = _val(cel, expr)
    assert v["t"] == "bytes", f"{expr!r} -> {v}"
    return v["v"]


# ---------------------------------------------------------------------------
# G5 -- number-literal parsing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr,expected", [
    # negative hex int (the headline G5 case)
    ("-0x55555555", -1431655765),
    ("0x55555555", 1431655765),
    # hex boundary, signed
    ("-0x7FFFFFFFFFFFFFFF", -9223372036854775807),
    ("-0xFFFFFFFFFFFFFFF", -1152921504606846975),
    # uppercase / lowercase hex digits both decode
    ("0xABCDEF", 0xABCDEF),
    ("-0xabcdef", -0xABCDEF),
    # leading-zero decimal is decimal, not octal (CEL has no 0o/0b)
    ("017", 17),
    ("-017", -17),
    # plain decimals still work
    ("19", 19),
    ("-19", -19),
])
def test_g5_int_radix_and_sign(cel, expr, expected):
    assert _int(cel, expr) == expected


@pytest.mark.parametrize("expr,expected", [
    # uint hex + decimal, with the u/U designator
    ("0xFu", 15),
    ("0xFU", 15),
    ("15u", 15),
    ("0u", 0),
])
def test_g5_uint_radix(cel, expr, expected):
    assert _uint(cel, expr) == expected


@pytest.mark.parametrize("expr,expected", [
    # repeated unary minus composes by parity (cel-go VisitNegate)
    ("-19", -19),
    ("--19", 19),
    ("---19", -19),
    ("----19", 19),
    ("--------------------------------19", 19),    # 32 minuses -> even -> 19
    ("-------------------------------19", -19),     # 31 minuses -> odd  -> -19
])
def test_g5_repeated_unary_minus(cel, expr, expected):
    assert _int(cel, expr) == expected


@pytest.mark.parametrize("expr", [
    "9223372036854775808",          # i64::MAX + 1 -> overflow -> parse error
    "0xFFFFFFFFFFFFFFFFF",          # too many hex digits for i64
    "18446744073709551616u",        # u64::MAX + 1 -> overflow -> parse error
])
def test_g5_out_of_range_literals_error(cel, expr):
    r = cel.eval(expr)
    assert r["ok"] is False, f"{expr!r} should be a parse error, got {r}"


# ---------------------------------------------------------------------------
# G7 -- triple-quoted string/bytes strip the delimiters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr,expected", [
    ("'''hello'''", "hello"),
    ('"""hello"""', "hello"),
    # unescaped punctuation inside triple quotes; delimiter stripped
    ("''' ? \" ' ` '''", " ? \" ' ` "),
    ('""" ? " \' ` """', " ? \" ' ` "),
])
def test_g7_triple_quoted_strings(cel, expr, expected):
    assert _str(cel, expr) == expected


@pytest.mark.parametrize("expr,expected_hex", [
    # b'''hello''' -> 68656c6c6f (NOT 2727...2727 with embedded inner quotes)
    ("b'''hello'''", "68656c6c6f"),
    ('b"""hello"""', "68656c6c6f"),
    # unescaped punctuation: ' ? " ' ` ' -> 20 3f 20 22 20 27 20 60 20
    ("b''' ? \" ' ` '''", "203f20222027206020"),
    ('b""" ? " \' ` """', "203f20222027206020"),
    # newline + control escapes inside triple-quoted bytes
    ("b''' \\n '''", "200a20"),
    ("b''' \\x00 \\x0A \\x7F \\xFF '''", "2000200a207f20ff20"),
    ("b''' \\000 \\012 \\177 \\377 '''", "2000200a207f20ff20"),
])
def test_g7_triple_quoted_bytes(cel, expr, expected_hex):
    assert _bytes_hex(cel, expr) == expected_hex


# ---------------------------------------------------------------------------
# G8 -- escape-sequence set + quote-context rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("expr,expected", [
    # \? -> ? in both quote contexts
    ("'\\?'", "?"),
    ('"\\?"', "?"),
    # the full punctuation set, quote-context independent:
    #   \\ -> \   \? -> ?   \" -> "   \' -> '   \` -> `
    ("' \\\\ \\? \\\" \\' \\` '", " \\ ? \" ' ` "),
    ('" \\\\ \\? \\" \\\' \\` "', " \\ ? \" ' ` "),
    # the classic ascii escape sequence string:
    #   \a \b \f \n \r \t \v \" \' \\  ->  07 08 0c 0a 0d 09 0b 22 27 5c
    ('"\\a\\b\\f\\n\\r\\t\\v\\"\\\'\\\\"',
     "\x07\x08\x0c\n\r\t\x0b\"'\\"),
])
def test_g8_string_escape_set(cel, expr, expected):
    assert _str(cel, expr) == expected


@pytest.mark.parametrize("expr,expected", [
    # \X (upper) hex escape alongside \x (lower):
    #   \X00 -> NUL(0x00)   \X0A -> LF(0x0a)   \X7F -> DEL(0x7f)
    ("' \\X00 \\X0A \\X7F '", " \x00 \n \x7f "),
    ("' \\x4a \\x4B \\X4c \\X4D '", " J K L M "),
    # unicode escapes (strings only): \\u01aB and \\U000001aB both -> U+01AB.
    # The expected glyph (U+01AB LATIN SMALL LETTER T WITH PALATAL HOOK) is
    # written as a Python \\u escape so this source stays ASCII (CLAUDE.md 3).
    ("' \\u01aB \\U000001aB '", " \u01ab \u01ab "),
])
def test_g8_hex_and_unicode_escapes(cel, expr, expected):
    assert _str(cel, expr) == expected


@pytest.mark.parametrize("expr,expected_hex", [
    # bytes punctuation escapes: \\ \? \" \' \`
    ("b' \\\\ \\? \\\" \\' \\` '", "205c203f20222027206020"),
    # bytes control escapes: \a \b \f \t \v
    ("b' \\a \\b \\f \\t \\v '", "20072008200c2009200b20"),
    # \X upper hex in bytes is a raw byte
    ("b' \\X00 \\X0A \\X7F \\XFF '", "2000200a207f20ff20"),
])
def test_g8_bytes_escape_set(cel, expr, expected_hex):
    assert _bytes_hex(cel, expr) == expected_hex


@pytest.mark.parametrize("expr", [
    # \u / \U are NOT valid in bytes literals (cel-go rejects)
    "b'\\u0041'",
    "b'\\U00000041'",
])
def test_g8_bytes_reject_unicode_escapes(cel, expr):
    r = cel.eval(expr)
    assert r["ok"] is False, f"{expr!r} should reject \\u/\\U in bytes, got {r}"


@pytest.mark.parametrize("expr,expected", [
    # raw strings (r/R) preserve escape sequences verbatim
    ("r'Hello \\n'", "Hello \\n"),
    ("R\"Hello \\n\"", "Hello \\n"),
    # raw triple-quoted string: delimiter stripped, escapes preserved
    ("r''' \\\\ \\? '''", " \\\\ \\? "),
])
def test_g8_raw_strings_preserve_escapes(cel, expr, expected):
    assert _str(cel, expr) == expected
