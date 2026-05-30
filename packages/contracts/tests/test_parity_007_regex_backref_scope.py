"""VAL-PARITY-007: regex-backreference profile screen scope parity.

The cel-python ``_check_profile`` regex-backreference screen used to only
inspect the FIRST string literal inside a ``.matches()`` call's exprlist
(and ``break`` after it), so a backreference that lived anywhere else --
in a sibling sub-expression, in a non-first ``.matches()`` argument, or in
a concatenated string operand -- slipped through (fail-open). The cel-js
mirror (``checkRegexBackref`` in
``packages/contracts-typescript/src/evaluator.ts``) scans the ENTIRE raw
expression text for ANY string literal containing ``\\<digit>`` and
rejects it (fail-closed). The two runtimes therefore accepted/rejected
DIFFERENT sets of expressions, breaking the cross-runtime contract: an
RE2-illegal backreference could be published as a valid behavioral
assertion against cel-python while cel-js rejected the same expression.

The pinned scope is the broader fail-closed whole-expression scan: any
string literal anywhere in the expression that contains ``\\<digit>``
raises ``RelayCelRegexBackreferenceError`` / ``RELAY-CEL-007`` at compile
time on BOTH runtimes. These tests pin the cel-python side. The cel-js
side is pinned by
``packages/contracts-typescript/test/parity_007_regex_backref_scope.test.ts``
and the cross-runtime corpus parity loop in
``tests/conformance/cel/relay_cel_corpus.json``.

RED at base commit c911607 / 5030e9cb (cel-python ACCEPTED the non-first
and sibling backref expressions); GREEN after the screen is widened to the
whole-expression scope.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_contracts import RelayCelEvaluator
from relay_contracts.errors import (
    SUBTYPE_PROFILE_REGEX_BACKREF,
    RelayCelRegexBackreferenceError,
)

# A regex backreference (capture group `(b)` then `\1`) embedded in a
# string literal. CEL parses the single backslash literally, so the regex
# engine would see `\1`, which RE2 forbids.
_BACKREF_BODY = r"a(b)\\1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_in_sibling_subexpression_rejected() -> None:
    """A backreference in a sibling sub-expression (NOT inside the
    ``.matches()`` exprlist) MUST be rejected. cel-python used to accept
    this because the screen only looked inside the ``.matches()`` args."""

    evaluator = RelayCelEvaluator()
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

    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'note == "{_BACKREF_BODY}"')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_in_concatenated_matches_arg_rejected() -> None:
    """A backreference in a CONCATENATED ``.matches()`` argument (where a
    non-backref literal is the first operand) MUST be rejected. cel-python
    used to accept this because it broke after the first string literal
    (`"a"`), never inspecting `"...\\1"`."""

    evaluator = RelayCelEvaluator()
    with pytest.raises(RelayCelRegexBackreferenceError) as ctx:
        evaluator.compile(f'req.matches("a" + "{_BACKREF_BODY}")')
    assert ctx.value.code == "RELAY-CEL-007"
    assert ctx.value.subtype == SUBTYPE_PROFILE_REGEX_BACKREF


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_backref_as_first_matches_arg_still_rejected() -> None:
    """Regression guard: the original (first-arg) case MUST keep being
    rejected after the screen is widened."""

    evaluator = RelayCelEvaluator()
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
    cel-js rule so legitimate regexes stay accepted on both runtimes."""

    evaluator = RelayCelEvaluator()
    # No top-level `.matches()` so cel-python compiles the literal
    # directly; the point is the backref screen must NOT fire.
    compiled = evaluator.compile(r'note == "[a-z]+\\d\\w\\s"')
    assert compiled is not None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-PARITY-007")
def test_clean_matches_pattern_still_accepted() -> None:
    """Baseline: a backref-free RE2-safe pattern still compiles cleanly
    after the screen is widened (no false positive)."""

    evaluator = RelayCelEvaluator()
    compiled = evaluator.compile(r'"hello".matches("h.*o")')
    assert compiled is not None
