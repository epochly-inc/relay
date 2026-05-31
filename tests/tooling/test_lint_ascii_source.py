"""Plumbing-tier tests for scripts/lint-ascii-source.py JS/TS regex-literal
lexing (Gate-2 G4-F4 remediation).

The ASCII-Safe Source lint strips JS/TS comments and string/template
literals to a whitespace-preserving residual, then flags any non-ASCII
byte left in a *code* token (CLAUDE.md "ASCII-Safe Source"; the hazard is
a homoglyph or smart-quote smuggled into an identifier/operator).

Bug under remediation: the single-pass lexer
`_strip_js_comments_and_strings` recognized `//`, `/* */`, `'`, `"`, and
backtick, but NOT JS/TS *regex literals*. A regex containing a quote --
e.g. `const re = /['"]/;` -- flipped the lexer into string state at the
quote inside the regex and consumed all subsequent real code as "string"
until the next matching quote (or EOF). A non-ASCII homoglyph in a real
code token inside that swallowed span was blanked out and never flagged:
a vacuous pass, the exact failure the guard exists to catch.

These tests lock in regex-literal recognition:

  * A regex literal that contains quotes must NOT desync string state, so
    a non-ASCII identifier on a later line is STILL flagged (the RED case
    before the fix).
  * A `/` that is a division operator (previous significant token is an
    identifier / number / `)` / `]`) must NOT be treated as a regex.
  * Non-ASCII INSIDE a regex literal, a string, or a comment is exempt
    (the guard targets code tokens only, per the script's documented
    classification).
  * The live repo tree must still lint clean (no new false positives).

The test loads the hyphenated script via importlib (a plain `import` does
not work) and exercises the real `scan_js` / `_strip_js_comments_and_strings`
/ `main` codepaths.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

# Repo root: this file lives at relay/tests/tooling/test_lint_ascii_source.py.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "lint-ascii-source.py"

# Cyrillic small letter 'a' (U+0430) -- a homoglyph for ASCII 'a'. Used to
# smuggle a non-ASCII byte into a real identifier token.
CYRILLIC_A = "а"


def _load_lint_module():
    """Load scripts/lint-ascii-source.py as a module under a safe name."""
    spec = importlib.util.spec_from_file_location(
        "lint_ascii_source_under_test", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["lint_ascii_source_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def lint_module():
    """Fresh load per-test so REPO_ROOT monkeypatching is hermetic."""
    return _load_lint_module()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Regex-literal desync: the core finding.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_regex_with_quotes_does_not_mask_later_homoglyph(
    tmp_path: Path, lint_module, monkeypatch
):
    """A regex literal with a quote must NOT swallow later code tokens.

    `const re = /['"]/;` is a regex whose char class holds both a single
    and a double quote. Before the fix, the lexer treated the first quote
    inside the regex as the start of a string literal and consumed every
    subsequent byte -- including a non-ASCII homoglyph identifier on a
    later line -- as exempt "string" content. This is the RED case: the
    later homoglyph MUST be flagged.
    """
    bad_ident = "p" + CYRILLIC_A + "ss"  # 'pаss' -- Cyrillic 'a'
    src = "const re = /['\"]/;\n" f"const {bad_ident} = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "regex.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert vios, (
        "regex literal masked the later homoglyph identifier "
        f"(vacuous pass); residual scan found no violations. src={src!r}"
    )
    # The flagged byte must be the Cyrillic 'a' on line 2 (the identifier),
    # not anything inside the regex on line 1.
    assert any(
        v["line"] == 2 and v["detail"].endswith("in code token")
        for v in vios
    ), vios


@pytest.mark.plumbing
def test_regex_contents_not_flagged(
    tmp_path: Path, lint_module, monkeypatch
):
    """A non-ASCII char INSIDE a regex literal is exempt (not a code token).

    The guard targets code tokens; a regex body is a literal, like a
    string. A homoglyph inside the regex must NOT be flagged, and -- the
    important half -- it must not desync the lexer either.
    """
    # Cyrillic 'a' lives inside the regex literal only; surrounding code
    # is pure ASCII.
    src = "const re = /[" + CYRILLIC_A + "'\"]/;\n" "const ok = re.test('x');\n"
    target = tmp_path / "packages" / "demo" / "src" / "regex_body.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert vios == [], (
        "non-ASCII inside a regex literal must be exempt (regex body is "
        f"not a code token); got {vios!r}"
    )


@pytest.mark.plumbing
def test_division_operator_not_treated_as_regex(
    tmp_path: Path, lint_module, monkeypatch
):
    """A `/` after a value (identifier/number/`)`/`]`) is division.

    `const x = a / b;` and `const y = (a) / 2;` must NOT start a regex --
    otherwise the lexer would swallow the rest of the line/file. With the
    `/` correctly classified as division, a non-ASCII identifier later in
    the same file is still a code token and MUST be flagged.
    """
    bad_ident = "v" + CYRILLIC_A + "l"  # 'vаl'
    src = (
        "const x = a / b;\n"
        "const y = (a) / 2;\n"
        "const z = arr[0] / 3;\n"
        f"const {bad_ident} = x + y + z;\n"
    )
    target = tmp_path / "packages" / "demo" / "src" / "division.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert any(v["line"] == 4 for v in vios), (
        "division operators were misread as regex starts, masking the "
        f"line-4 homoglyph identifier; got {vios!r}"
    )


@pytest.mark.plumbing
def test_regex_char_class_with_slash_is_single_token(
    tmp_path: Path, lint_module, monkeypatch
):
    """A `/` inside a regex char class does NOT terminate the regex.

    `/[/'"]/` -- the `/` inside `[...]` is a literal slash, not the regex
    terminator. The lexer must consume to the closing `/` after the char
    class, then resume code. A later homoglyph identifier MUST be flagged.
    """
    bad_ident = "f" + CYRILLIC_A + "n"  # 'fаn'
    src = "const re = /[/'\"]/;\n" f"const {bad_ident} = 0;\n"
    target = tmp_path / "packages" / "demo" / "src" / "charclass.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert any(v["line"] == 2 for v in vios), (
        "a `/` inside a regex char class prematurely terminated the "
        f"regex, desyncing the lexer; got {vios!r}"
    )


@pytest.mark.plumbing
def test_escaped_slash_in_regex_does_not_terminate(
    tmp_path: Path, lint_module, monkeypatch
):
    r"""An escaped `\/` inside a regex does NOT terminate it.

    `/a\/b/` is one regex matching `a/b`. The escaped slash must be
    consumed as regex content; a later homoglyph identifier MUST still be
    flagged.
    """
    bad_ident = "g" + CYRILLIC_A + "p"  # 'gаp'
    src = "const re = /a\\/b'/;\n" f"const {bad_ident} = 0;\n"
    target = tmp_path / "packages" / "demo" / "src" / "escaped.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert any(v["line"] == 2 for v in vios), (
        "an escaped slash inside the regex terminated it early or the "
        f"embedded quote desynced string state; got {vios!r}"
    )


# ---------------------------------------------------------------------------
# Negative cases: existing exemptions must continue to hold.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_nonascii_in_string_still_exempt(
    tmp_path: Path, lint_module, monkeypatch
):
    """Non-ASCII inside a string literal remains exempt after the change."""
    src = "const msg = 'h" + CYRILLIC_A + "i';\nconst ok = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "strlit.ts"
    _write(target, src)
    assert lint_module.scan_js(target) == []


@pytest.mark.plumbing
def test_nonascii_in_comment_still_exempt(
    tmp_path: Path, lint_module, monkeypatch
):
    """Non-ASCII inside a comment remains exempt after the change."""
    src = "// comment with " + CYRILLIC_A + "\nconst ok = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "comment.ts"
    _write(target, src)
    assert lint_module.scan_js(target) == []


@pytest.mark.plumbing
def test_plain_code_homoglyph_still_flagged(
    tmp_path: Path, lint_module, monkeypatch
):
    """A homoglyph in a code token with no regex present is still flagged."""
    bad_ident = "c" + CYRILLIC_A + "t"  # 'cаt'
    src = f"const {bad_ident} = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "plain.ts"
    _write(target, src)
    vios = lint_module.scan_js(target)
    assert any(v["line"] == 1 for v in vios), vios


# ---------------------------------------------------------------------------
# Template-literal ${...} interpolation: code, not string (codex P3).
#
# A template literal `...${EXPR}...` is part string (the literal TEXT
# between interpolations, exempt) and part CODE (the EXPR inside each
# ${...}). The earlier lexer blanked the ENTIRE backtick literal including
# the interpolation expressions, so a non-ASCII homoglyph in a real code
# token inside ${...} was hidden -> a vacuous pass.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_nonascii_inside_template_interpolation_is_flagged(
    tmp_path: Path, lint_module, monkeypatch
):
    """A non-ASCII CODE token inside ${...} interpolation MUST be flagged.

    `const s = `hi ${pXss}`;` where X is a Cyrillic 'a' homoglyph: the
    identifier `pаss` is a CODE token inside the interpolation, not string
    text. Before the fix the whole template literal was blanked and the
    homoglyph was hidden (the RED case). It must be flagged on line 1.
    """
    bad_ident = "p" + CYRILLIC_A + "ss"  # 'pаss' -- Cyrillic 'a'
    src = "const s = `hi ${" + bad_ident + "}`;\nconst ok = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "interp.ts"
    _write(target, src)

    vios = lint_module.scan_js(target)
    assert vios, (
        "non-ASCII code token inside ${...} interpolation was masked "
        f"(vacuous pass); src={src!r}"
    )
    assert any(
        v["line"] == 1 and v["detail"].endswith("in code token")
        for v in vios
    ), vios


@pytest.mark.plumbing
def test_nonascii_in_template_literal_text_still_exempt(
    tmp_path: Path, lint_module, monkeypatch
):
    """Non-ASCII in the literal TEXT of a template (not interpolation) stays
    exempt -- it is string content, like a quoted string."""
    src = "const s = `h" + CYRILLIC_A + "i`;\nconst ok = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "tpltext.ts"
    _write(target, src)
    assert lint_module.scan_js(target) == [], (
        "non-ASCII in template-literal TEXT must remain exempt (string "
        "content)"
    )


@pytest.mark.plumbing
def test_nonascii_in_template_text_with_clean_interpolation_exempt(
    tmp_path: Path, lint_module, monkeypatch
):
    """A template literal with non-ASCII only in TEXT and a CLEAN (ASCII)
    interpolation expression stays exempt; the interpolation is re-entered
    as code but contains no non-ASCII."""
    src = (
        "const s = `gr" + CYRILLIC_A + "y ${count} items`;\n"
        "const ok = 1;\n"
    )
    target = tmp_path / "packages" / "demo" / "src" / "mixed.ts"
    _write(target, src)
    assert lint_module.scan_js(target) == [], (
        "clean interpolation + non-ASCII literal text must remain exempt"
    )


@pytest.mark.plumbing
def test_clean_template_literal_passes(
    tmp_path: Path, lint_module, monkeypatch
):
    """A fully ASCII template literal with interpolation produces no
    violations."""
    src = "const s = `hi ${name} ok ${a + b}`;\nconst ok = 1;\n"
    target = tmp_path / "packages" / "demo" / "src" / "clean_tpl.ts"
    _write(target, src)
    assert lint_module.scan_js(target) == [], (
        "a clean ASCII template literal must not be flagged"
    )


@pytest.mark.plumbing
def test_nested_template_in_interpolation_handles_braces(
    tmp_path: Path, lint_module, monkeypatch
):
    """A nested template literal (and brace objects) inside ${...} must be
    handled: brace counting must not exit the interpolation early.

    `const s = `outer ${ {k: `in ${vXl}`} }`;` -- the object literal `{...}`
    inside the interpolation introduces braces, and a nested template
    `in ${vXl}` carries its own interpolation with a homoglyph code token.
    The homoglyph must be flagged and the surrounding literal text exempt.
    """
    bad_ident = "v" + CYRILLIC_A + "l"  # 'vаl'
    src = (
        "const s = `outer ${ {k: `in ${" + bad_ident + "}`} } end`;\n"
        "const ok = 1;\n"
    )
    target = tmp_path / "packages" / "demo" / "src" / "nested.ts"
    _write(target, src)
    vios = lint_module.scan_js(target)
    assert any(v["line"] == 1 for v in vios), (
        "nested-template interpolation hid the homoglyph (brace counting or "
        f"nested-template re-entry is wrong); got {vios!r}"
    )


# ---------------------------------------------------------------------------
# Whole-tree: the live repo must still lint clean (no new false positives).
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_live_repo_tree_lints_clean(lint_module):
    """`main()` against the real repo tree returns 0.

    Guards against the fix introducing false positives: a real `/` that
    is division (or a real regex with code-like contents) must not be
    misclassified into flagging genuine ASCII code.
    """
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = lint_module.main(["--json"])
    report = json.loads(buf.getvalue())
    assert rc == 0, (
        f"live repo tree no longer lints clean: "
        f"{report.get('total_violations')} violation(s): "
        f"{report.get('files')!r}"
    )
    assert report["total_violations"] == 0
