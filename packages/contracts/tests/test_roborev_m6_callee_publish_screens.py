"""ROBOREV M6 findings B (HIGH) + C (MED): publish-time screens must catch
leading-dot root-qualified calls and reserved-word-named calls.

Finding B: CEL permits LEADING-DOT absolute (root-qualified) global calls --
``.dyn(...)``, ``.unknown(...)``. The callee parser treated ANY identifier
preceded by ``.`` as member access, so those calls produced NO callee and
both publish-time screens (the disabled-builtin profile screen and the
unregistered-UDF screen) were BYPASSED. ``probe_compile`` cannot catch them
either: empirically probed against the PINNED wasm, ``.dyn(1)`` COMPILES and
fails only at exec (``RELAY-CEL-004 UndeclaredReference(".dyn")``), an
exec-cause envelope probe_compile deliberately defers -- and a
short-circuited ``false && .dyn(1)`` even evaluates to ``false`` without ANY
error. Publish was therefore accepting contracts the profile forbids.

Finding C: the parser's reserved-word exclusion covered the future-reserved
words (``if``, ``for``, ...) which the actual engine grammar tokenizes as
ORDINARY identifiers: ``if(1)`` compiles and fails only at exec
(``UndeclaredReference("if")``), so a contract calling ``if(x)`` bypassed
the unregistered-UDF screen at publish. The engine-matched exclusion set is
exactly ``true`` / ``false`` / ``null`` / ``in`` -- probed: those four are
COMPILE-rejected (``RELAY-CEL-001`` parse error), which probe_compile
already surfaces at publish as a structured RELAY-CONTRACT-004.

These tests pin the END-TO-END publish behavior (VAL-W6-042: reject at
publish, not at first evaluation) and the eval-time compile screen.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any

import pytest
from relay_contracts.dsl_parser import (
    ContractParseError,
    parse_contract,
)
from relay_contracts.errors import (
    SUBTYPE_PROFILE_DYN_DISABLED,
    RelayCelProfileError,
)
from relay_contracts.pipeline import publish_contract

pytestmark = pytest.mark.plumbing


def _behavioral_doc(assertion_id: str, expression: str) -> dict[str, Any]:
    return {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": assertion_id,
        "kind": "behavioral",
        "severity": "p0",
        "expression": expression,
        "owner_email": "a@b.example",
        "lifecycle_state": "active",
    }


# ---------------------------------------------------------------------------
# finding B end-to-end: leading-dot calls are rejected AT PUBLISH
# ---------------------------------------------------------------------------


def test_publish_rejects_leading_dot_dyn() -> None:
    parsed = parse_contract(
        _behavioral_doc("VAL-BAD-ROOT-DYN", ".dyn(1) == 1")
    )
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    assert ctx.value.payload["assertion_id"] == "VAL-BAD-ROOT-DYN"
    # The profile screen classifies it as the dyn-disabled violation.
    assert ctx.value.payload["cel_token"] == SUBTYPE_PROFILE_DYN_DISABLED


def test_publish_rejects_short_circuited_leading_dot_dyn() -> None:
    # Probe-verified: the engine evaluates `false && .dyn(1)` to `false`
    # WITHOUT any error (short-circuit), so the static publish screen is the
    # ONLY thing standing between this contract and a silent profile bypass.
    parsed = parse_contract(
        _behavioral_doc("VAL-BAD-SC-ROOT-DYN", "false && .dyn(1)")
    )
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    assert ctx.value.payload["cel_token"] == SUBTYPE_PROFILE_DYN_DISABLED


def test_publish_rejects_leading_dot_unregistered_udf() -> None:
    parsed = parse_contract(
        _behavioral_doc("VAL-BAD-ROOT-UDF", ".unknownUdf(1) == 1")
    )
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    assert ctx.value.payload["assertion_id"] == "VAL-BAD-ROOT-UDF"
    assert "unknownUdf" in ctx.value.payload.get("unknown_callees", [])


# ---------------------------------------------------------------------------
# finding B at eval: the compile-time static screen catches the
# root-qualified disabled builtin BEFORE the engine (incl. short-circuit)
# ---------------------------------------------------------------------------


def test_evaluator_compile_screen_rejects_leading_dot_dyn() -> None:
    from relay_contracts import RELAY_UDFS, make_cel_evaluator

    ev = make_cel_evaluator(udfs=RELAY_UDFS)
    with pytest.raises(RelayCelProfileError) as ctx:
        ev.evaluate(".dyn(1)")
    assert ctx.value.subtype == SUBTYPE_PROFILE_DYN_DISABLED
    with pytest.raises(RelayCelProfileError):
        ev.evaluate("false && .dyn(1)")


# ---------------------------------------------------------------------------
# finding C end-to-end: a future-reserved-word call is an unregistered UDF
# at publish (the engine tokenizes it as an ordinary identifier)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("word", ["if", "for", "while"])
def test_publish_rejects_future_reserved_word_call(word: str) -> None:
    parsed = parse_contract(
        _behavioral_doc(f"VAL-BAD-{word.upper()}-CALL", f"{word}(x) == 1")
    )
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"
    assert word in ctx.value.payload.get("unknown_callees", [])


def test_publish_rejects_grammar_keyword_call_via_engine_probe() -> None:
    # `in(1)` is COMPILE-rejected by the engine grammar (probe-verified
    # RELAY-CEL-001), so probe_compile rejects it at publish even though the
    # parser excludes `in` from the callee set. This pins the
    # engine-matched division of labor: parser-excluded words MUST be
    # compile-rejected by the engine.
    parsed = parse_contract(
        _behavioral_doc("VAL-BAD-IN-CALL", "in(1) == 1")
    )
    with pytest.raises(ContractParseError) as ctx:
        publish_contract(parsed)
    assert ctx.value.code == "RELAY-CONTRACT-004"


# ---------------------------------------------------------------------------
# non-regression: genuine member calls still publish (no false callees)
# ---------------------------------------------------------------------------


def test_publish_accepts_member_calls_with_receivers() -> None:
    parsed = parse_contract(
        _behavioral_doc(
            "VAL-OK-MEMBER", '"abc".startsWith("a") && "z".matches("z")'
        )
    )
    publish_contract(parsed)  # must not raise


def test_publish_accepts_relay_udf_member_form() -> None:
    parsed = parse_contract(
        _behavioral_doc(
            "VAL-OK-RELAY-UDF", 'relay.coverage(trace, "s") >= 0.5'
        )
    )
    publish_contract(parsed)  # must not raise (engine validates at eval)
