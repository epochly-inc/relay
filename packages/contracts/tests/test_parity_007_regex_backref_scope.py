"""VAL-PARITY-007: regex-backreference profile screen scope parity.

The legacy Python regex-backreference screen used to only
inspect the FIRST string literal inside a ``.matches()`` call's exprlist
(and ``break`` after it), so a backreference that lived anywhere else --
in a sibling sub-expression, in a non-first ``.matches()`` argument, or in
a concatenated string operand -- slipped through (fail-open). The TS
mirror (``checkRegexBackref`` in
``packages/contracts-typescript/src/evaluator.ts``) scans the ENTIRE raw
expression text for ANY string literal containing ``\\<digit>`` and
rejects it (fail-closed). The two runtimes therefore accepted/rejected
DIFFERENT sets of expressions, breaking the cross-runtime contract: an
RE2-illegal backreference could be published as a valid behavioral
assertion on the Python host while the TS host rejected the same expression.

The pinned scope is the broader fail-closed whole-expression scan: any
string literal anywhere in the expression that contains ``\\<digit>``
raises ``RelayCelRegexBackreferenceError`` / ``RELAY-CEL-007`` at compile
time on BOTH runtimes. These tests pin the Python side. The TS
side is pinned by
``packages/contracts-typescript/test/parity_007_regex_backref_scope.test.ts``
and the cross-runtime corpus parity loop in
``tests/conformance/cel/relay_cel_corpus.json``.

RED at base commit c911607 / 5030e9cb (the Python screen ACCEPTED the non-first
and sibling backref expressions); GREEN after the screen is widened to the
whole-expression scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_contracts import WasmCelEvaluator
from relay_contracts.errors import (
    SUBTYPE_PROFILE_REGEX_BACKREF,
    RelayCelRegexBackreferenceError,
)

# A regex backreference (capture group `(b)` then `\1`) embedded in a
# string literal. CEL parses the single backslash literally, so the regex
# engine would see `\1`, which RE2 forbids.
_BACKREF_BODY = r"a(b)\\1"

# Non-ASCII digit codepoints (Unicode Nd category) built at RUNTIME so the
# source file stays ASCII (CLAUDE.md "ASCII-Safe Source"). A real regex
# backreference is ASCII `\1`..`\9` only; `\` followed by a NON-ASCII digit
# (e.g. fullwidth zero U+FF10, Arabic-Indic zero U+0660) is NOT a backref.
# RE2 -- and the TS mirror screen `/\\\d/` (no `u` flag, JS `\d` is
# ASCII-only) -- accept it. the legacy `_BACKREF_PATTERN = re.compile(r"\\\d")`
# carried NO `re.ASCII` flag, so Python's `\d` matched the FULL Unicode Nd
# category and REJECTED `\`+non-ASCII-digit -- a cross-runtime divergence
# (VAL-PARITY-007) widened by parity-007's first-arg->all-literals widening.
_FULLWIDTH_ZERO = chr(0xFF10)  # U+FF10 FULLWIDTH DIGIT ZERO (Nd category)
_ARABIC_ZERO = chr(0x0660)  # U+0660 ARABIC-INDIC DIGIT ZERO (Nd category)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_in_sibling_subexpression_rejected() -> None:
    """A backreference in a sibling sub-expression (NOT inside the
    ``.matches()`` exprlist) MUST be rejected. the legacy screen used to accept
    this because the screen only looked inside the ``.matches()`` args."""

    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'req.matches("ok") && note == "{_BACKREF_BODY}"')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_in_bare_string_no_matches_rejected() -> None:
    """A backreference in a bare string literal with NO ``.matches()``
    call at all MUST still be rejected -- the screen is whole-expression,
    not scoped to a regex method."""

    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'note == "{_BACKREF_BODY}"')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_in_concatenated_matches_arg_rejected() -> None:
    """A backreference in a CONCATENATED ``.matches()`` argument (where a
    non-backref literal is the first operand) MUST be rejected. The Python screen
    used to accept this because it broke after the first string literal
    (`"a"`), never inspecting `"...\\1"`."""

    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'req.matches("a" + "{_BACKREF_BODY}")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_as_first_matches_arg_still_rejected() -> None:
    """Regression guard: the original (first-arg) case MUST keep being
    rejected after the screen is widened."""

    evaluator = WasmCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'req.matches("{_BACKREF_BODY}")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_re2_shorthand_classes_not_treated_as_backref() -> None:
    """`\\d`, `\\w`, `\\s` are RE2-legal shorthand classes (backslash
    followed by a LETTER, not a digit). They MUST NOT be flagged as
    backreferences -- the screen only rejects `\\<digit>`. Matches the
    TS-mirror rule so legitimate regexes stay accepted on both runtimes."""

    evaluator = WasmCelEvaluator()
    # No top-level `.matches()` so the screen leaves the literal
    # directly; the point is the backref screen must NOT fire.
    compiled = evaluator.compile(r'note == "[a-z]+\\d\\w\\s"')
    assert compiled is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_clean_matches_pattern_still_accepted() -> None:
    """Baseline: a backref-free RE2-safe pattern still compiles cleanly
    after the screen is widened (no false positive)."""

    evaluator = WasmCelEvaluator()
    compiled = evaluator.compile(r'"hello".matches("h.*o")')
    assert compiled is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backslash_fullwidth_digit_not_treated_as_backref() -> None:
    """`\\` followed by a NON-ASCII digit (fullwidth zero U+FF10) is NOT a
    regex backreference -- a real backref is ASCII `\\1`..`\\9`. RE2 and the
    TS mirror screen (JS `\\d` is ASCII-only) both ACCEPT it. The legacy screen
    used to REJECT it because `_BACKREF_PATTERN = re.compile(r"\\\\d")` had no
    `re.ASCII` flag and Python's `\\d` matched the full Unicode Nd category --
    a cross-runtime divergence (VAL-PARITY-007). After the ASCII pin it is
    ACCEPTED on both runtimes.

    The non-ASCII digit is built at runtime via ``chr`` so the source stays
    ASCII; the runtime expression carries the actual codepoint.
    """

    evaluator = WasmCelEvaluator()
    # Raw expression text: a string literal whose body is backslash +
    # fullwidth-zero. RED at base (the Python screen rejected); GREEN after pin.
    expr = 'note == "' + "\\" + _FULLWIDTH_ZERO + '"'
    compiled = evaluator.compile(expr)
    assert compiled is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backslash_arabic_digit_not_treated_as_backref() -> None:
    """`\\` followed by Arabic-Indic zero (U+0660, Unicode Nd) is NOT a
    backreference. Same rationale as the fullwidth-zero case: ASCII-only
    `\\d` semantics accept it on both runtimes after the pin."""

    evaluator = WasmCelEvaluator()
    expr = 'note == "' + "\\" + _ARABIC_ZERO + '"'
    compiled = evaluator.compile(expr)
    assert compiled is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_ascii_backref_still_rejected_after_ascii_pin() -> None:
    """Regression guard for the ASCII pin: a genuine ASCII backreference
    `\\1` MUST stay rejected on both runtimes. Pinning `_BACKREF_PATTERN`
    to ASCII digits must not widen the accepted set to include real
    backrefs."""

    evaluator = WasmCelEvaluator()
    expr = 'note == "' + "\\1" + '"'
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(expr)
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF
