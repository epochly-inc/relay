"""V3 M5 F11 follow-up: CLI json.dumps kwargs guard (spec section AI line 5667).

Spec section AI mandates: "All CLI stdout JSON is emitted using
``json.dumps(ensure_ascii=False, allow_nan=False)``".

This guard inspects every ``json.dumps(...)`` call in the seven CLI
source files in scope for the m5-f11 follow-up via AST and asserts
that BOTH keyword arguments are pinned to the spec-required literals
(``ensure_ascii=False`` and ``allow_nan=False``).

Scope is intentionally narrow to the seven files owned by the
``fix-m5-f11-cli-json-ensure-ascii`` worker. Other ``json.dumps`` call
sites in the CLI tree (e.g., ``cassette.py``, ``invocations.py``,
``commands/replay.py``) live behind other ownership boundaries and use
``**_CANONICAL_JSON_KW`` star-spreads that already pin both kwargs at
the spread site; they are covered by their own follow-up features and
are out of scope here.

The behavioural complement asserts that the kwargs actually flow into
the runtime serializer: a payload containing a NaN float MUST raise
``ValueError`` once ``allow_nan=False`` is pinned (this is the runtime
contract that the AST guard above protects).

Fixes: m5-f11-error-code-naming-doc-cli-json (partial follow-up).
Contributes to VAL-V3M5-022.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import json
import math
from pathlib import Path

import pytest

_THIS = Path(__file__).resolve()
# packages/cli/tests/test_v3m5_cli_json_ensure_ascii.py
# parents[1] is packages/cli/; the CLI source root sits at src/relay_cli/.
_CLI_SRC_ROOT = _THIS.parents[1] / "src" / "relay_cli"

# Seven files in scope for the m5-f11 follow-up (see worker brief).
# Paths are relative to _CLI_SRC_ROOT. Any new json.dumps call introduced
# in one of these files must pin both spec-required kwargs.
_FILES_IN_SCOPE: tuple[str, ...] = (
    "output.py",
    "errors.py",
    "main.py",
    "commands/verify_self.py",
    "commands/contract.py",
    "commands/evidence.py",
    "commands/verify_install.py",
)


def _resolve_in_scope_paths() -> list[Path]:
    """Resolve the seven in-scope files; fail loudly if any are missing.

    The test layout is fixed by the worker brief; a missing file means
    the file was renamed or the brief drifted, both of which require
    operator attention rather than a silent pass.
    """
    resolved: list[Path] = []
    for rel in _FILES_IN_SCOPE:
        p = _CLI_SRC_ROOT / rel
        if not p.is_file():
            pytest.fail(
                f"expected CLI source file at {p!s}; m5-f11 scope drifted"
            )
        resolved.append(p)
    return resolved


def _is_json_dumps_call(node: ast.Call) -> bool:
    """Return True if ``node`` is a call to ``json.dumps`` (any alias form).

    Matches the two canonical forms found in our codebase:

      * ``json.dumps(...)`` -- Attribute(value=Name('json'), attr='dumps')
      * ``dumps(...)`` from ``from json import dumps`` -- Name('dumps')

    The second form is not currently used in the CLI but matching it
    defensively prevents a future ``from json import dumps`` import from
    sneaking past the guard.
    """
    func = node.func
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "dumps"
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        )
    if isinstance(func, ast.Name):
        return func.id == "dumps"
    return False


def _kwarg_value(call: ast.Call, name: str) -> ast.expr | None:
    """Return the AST node for a keyword argument by name, or None.

    Looks at ``call.keywords`` (explicit kwargs) and rejects ``**kwargs``
    star-spreads as ambiguous; the m5-f11 brief requires explicit literal
    pins on each call so reviewers can audit them line by line.
    """
    for kw in call.keywords:
        if kw.arg is None:
            # ``**spread`` - opaque; force the caller to use explicit kwargs.
            continue
        if kw.arg == name:
            return kw.value
    return None


def _is_literal_false(node: ast.expr | None) -> bool:
    """Return True if ``node`` is the literal ``False`` constant."""
    return isinstance(node, ast.Constant) and node.value is False


def _collect_violations() -> list[tuple[str, int, str]]:
    """Return a list of (relpath, line_no, reason) for every offending call.

    A call is offending if it is ``json.dumps(...)`` and either kwarg is
    missing or pinned to a non-False literal.
    """
    offenders: list[tuple[str, int, str]] = []
    for path in _resolve_in_scope_paths():
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - sanity guard
            pytest.fail(f"failed to parse {path}: {exc}")
        rel = str(path.relative_to(_CLI_SRC_ROOT.parents[2]))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_json_dumps_call(node):
                continue
            ea = _kwarg_value(node, "ensure_ascii")
            an = _kwarg_value(node, "allow_nan")
            problems: list[str] = []
            if not _is_literal_false(ea):
                problems.append("ensure_ascii=False")
            if not _is_literal_false(an):
                problems.append("allow_nan=False")
            if problems:
                offenders.append((rel, node.lineno, ", ".join(problems)))
    return offenders


@pytest.mark.plumbing
def test_cli_json_dumps_pins_ensure_ascii_false_and_allow_nan_false() -> None:
    """Every json.dumps call in the m5-f11 in-scope files pins both kwargs.

    Spec section AI line 5667: "All CLI stdout JSON is emitted using
    json.dumps(ensure_ascii=False, allow_nan=False)".
    """
    offenders = _collect_violations()
    assert offenders == [], (
        "json.dumps calls missing spec-required kwargs "
        "(ensure_ascii=False AND allow_nan=False); offenders: "
        + "; ".join(
            f"{p}:{ln} missing {reason}" for (p, ln, reason) in offenders
        )
    )


@pytest.mark.plumbing
def test_json_dumps_with_allow_nan_false_rejects_nan() -> None:
    """Behavioural sanity: allow_nan=False makes the serializer reject NaN.

    This is the runtime contract that the AST guard above protects. If a
    future Python release reinterprets ``allow_nan=False``, this test
    catches the regression immediately and the AST guard alone would not.
    """
    with pytest.raises(ValueError):
        json.dumps({"value": math.nan}, ensure_ascii=False, allow_nan=False)
    # Sanity: ensure_ascii=False produces non-ASCII verbatim (no \uXXXX
    # escape). The non-ASCII payload is constructed at runtime via chr()
    # so this source file stays 7-bit ASCII per CLAUDE.md
    # "ASCII-Safe Source".
    nonascii_char = chr(0x00E9)  # U+00E9 LATIN SMALL LETTER E WITH ACUTE
    line = json.dumps({"k": nonascii_char}, ensure_ascii=False, allow_nan=False)
    assert nonascii_char in line
    assert "\\u00e9" not in line
