"""w6.3 -- Relay UDF registration is gated on pure=True.

VAL-W6-020: relay.coverage declared pure
VAL-W6-021: relay.tool_arg declared pure
VAL-W6-022: relay.schema_match declared pure

Each test pins one assertion. The grep guard tests confirm:
  - the UDF is registered exactly once in packages/contracts/ source
  - its registration call passes pure=True
  - no test-only register_udf(..., pure=False) leaks into production
    paths

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from relay_contracts import (
    RELAY_COVERAGE_NAME,
    RELAY_SCHEMA_MATCH_NAME,
    RELAY_TOOL_ARG_NAME,
    RELAY_UDFS,
    PureUdf,
    RelayCelEvaluator,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_SRC = REPO_ROOT / "packages" / "contracts" / "src" / "relay_contracts"
PKG_INIT = PKG_SRC / "__init__.py"


def _grep_register_calls() -> list[tuple[Path, str, str]]:
    """Return (file, name, pure_value) tuples for every register_udf
    call in packages/contracts/src/relay_contracts/. Tests assert
    against this collection.
    """

    # Match the multi-line register_udf(name=..., fn=..., pure=...,
    # arity=...) call. Names ours kwargs explicitly; we expect every
    # production-side call to use the kwarg form (positional purity
    # is rejected by register_udf at runtime).
    pattern = re.compile(
        r"register_udf\s*\(\s*"
        r"name\s*=\s*([A-Z_][A-Z0-9_]*|\"[^\"]+\")\s*,\s*"
        r"fn\s*=\s*[a-zA-Z_][a-zA-Z0-9_]*\s*,\s*"
        r"pure\s*=\s*(True|False)",
        re.MULTILINE,
    )
    out: list[tuple[Path, str, str]] = []
    for py in PKG_SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for m in pattern.finditer(text):
            out.append((py, m.group(1), m.group(2)))
    return out


# ---------------------------------------------------------------------------
# VAL-W6-020: relay.coverage declared pure
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-020")
def test_relay_coverage_registered_in_relay_udfs() -> None:
    names = [u.name for u in RELAY_UDFS]
    assert names.count(RELAY_COVERAGE_NAME) == 1, (
        f"VAL-W6-020: expected exactly one relay.coverage in RELAY_UDFS; "
        f"got {names}"
    )
    udf = next(u for u in RELAY_UDFS if u.name == RELAY_COVERAGE_NAME)
    assert isinstance(udf, PureUdf)
    # PureUdf instances exist only via register_udf(..., pure=True);
    # constructor docstring (udf.py:60-71) makes any other path raise.
    assert udf.arity == 2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-020")
def test_relay_coverage_register_call_uses_pure_true_in_source() -> None:
    """Grep packages/contracts/ source: the register_udf call for
    relay.coverage MUST pass pure=True. Catches any future PR that
    flips purity at the registration site.
    """

    calls = _grep_register_calls()
    coverage_calls = [
        (path, name, pure) for (path, name, pure) in calls
        # The init call uses RELAY_COVERAGE_NAME constant; match on it.
        if name == "RELAY_COVERAGE_NAME"
    ]
    assert len(coverage_calls) == 1, (
        f"VAL-W6-020: expected exactly one production register_udf call "
        f"for RELAY_COVERAGE_NAME in packages/contracts/; got {coverage_calls}"
    )
    assert coverage_calls[0][2] == "True", (
        f"VAL-W6-020: relay.coverage register_udf must use pure=True; "
        f"got pure={coverage_calls[0][2]} at {coverage_calls[0][0]}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-020")
def test_relay_coverage_evaluator_accepts_registration() -> None:
    """The wired-up evaluator MUST accept RELAY_UDFS without error."""

    evaluator = RelayCelEvaluator(udfs=RELAY_UDFS)
    # Compile-only check; cel-python's dotted-identifier resolution is
    # exercised by VAL-W6-029 -- here we only confirm registration is
    # not rejected.
    assert evaluator is not None


# ---------------------------------------------------------------------------
# VAL-W6-021: relay.tool_arg declared pure
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-021")
def test_relay_tool_arg_registered_in_relay_udfs() -> None:
    names = [u.name for u in RELAY_UDFS]
    assert names.count(RELAY_TOOL_ARG_NAME) == 1
    udf = next(u for u in RELAY_UDFS if u.name == RELAY_TOOL_ARG_NAME)
    assert isinstance(udf, PureUdf)
    assert udf.arity == 2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-021")
def test_relay_tool_arg_register_call_uses_pure_true_in_source() -> None:
    calls = _grep_register_calls()
    tool_arg_calls = [
        (path, name, pure) for (path, name, pure) in calls
        if name == "RELAY_TOOL_ARG_NAME"
    ]
    assert len(tool_arg_calls) == 1
    assert tool_arg_calls[0][2] == "True"


# ---------------------------------------------------------------------------
# VAL-W6-022: relay.schema_match declared pure
# ---------------------------------------------------------------------------

@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-022")
def test_relay_schema_match_registered_in_relay_udfs() -> None:
    names = [u.name for u in RELAY_UDFS]
    assert names.count(RELAY_SCHEMA_MATCH_NAME) == 1
    udf = next(u for u in RELAY_UDFS if u.name == RELAY_SCHEMA_MATCH_NAME)
    assert isinstance(udf, PureUdf)
    assert udf.arity == 2


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-022")
def test_relay_schema_match_register_call_uses_pure_true_in_source() -> None:
    calls = _grep_register_calls()
    schema_calls = [
        (path, name, pure) for (path, name, pure) in calls
        if name == "RELAY_SCHEMA_MATCH_NAME"
    ]
    assert len(schema_calls) == 1
    assert schema_calls[0][2] == "True"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-020", "VAL-W6-021", "VAL-W6-022")
def test_no_pure_false_in_production_register_udf_calls() -> None:
    """No production register_udf call may set pure=False. Tests are
    permitted (test_w6_1_evaluator.py exercises the rejection path),
    but the guard scope is packages/contracts/src/, not tests/.
    """

    calls = _grep_register_calls()
    bad = [(path, name, pure) for (path, name, pure) in calls if pure == "False"]
    assert bad == [], (
        f"VAL-W6-020..022: production register_udf must use pure=True; "
        f"found pure=False at: {bad}"
    )
