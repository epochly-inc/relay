"""W9.3 LLM-judge stub plumbing tests.

Covers VAL-W9-016 .. VAL-W9-020 per the W9.3 contract block in
``/Users/chandlervaughn/.ops-runtime/relay-v0.1-oss-wedge/contract.md``.

The W9.3 surface ships ONLY a stub: the public symbol exists at the
documented import path, its signature accepts the canonical
``relay.assertion.eval.v1`` payload shape, and invocation raises
``NotImplementedError`` with a stable deferred-to-month-4+ message. The
stub is NOT registered as an active evaluator -- the active-evaluator
introspection surface returns an empty set in v0.1.

Tier-1 plumbing only -- the stub is pure, deterministic, offline. No
LLM calls, no network, no fakes.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import inspect
import logging
from pathlib import Path
from typing import Any

import pytest
from relay_evals import (
    ACTIVE_EVALUATORS,
    EVAL_ASSERTION_SCHEMA_ID,
    LLM_JUDGE_DEFERRED_MESSAGE,
    LLM_JUDGE_EVALUATOR_KIND,
    REGISTERED_TEMPLATES,
    RelayTemplateInputError,
    list_active_evaluator_kinds,
    llm_judge_evaluator,
)
from relay_evals import llm_judge as llm_judge_module
from relay_schemas.error_codes import RelayErrorCode

pytestmark = pytest.mark.plumbing


# -----------------------------------------------------------------------------
# Fixture: a minimal valid EvalAssertion payload shape per spec D.5.
#
# Spec D.5 EvalAssertion at line 3860 defines the structure customers
# build for an evaluator. The stub binds to ``evaluator.kind`` and a
# small set of required top-level fields; full schema enforcement lands
# with the real evaluator in month 4+ alongside the LLM-judge runtime.
# -----------------------------------------------------------------------------


def _valid_eval_assertion(*, kind: str = "llm_judge") -> dict[str, Any]:
    return {
        "schema_version": EVAL_ASSERTION_SCHEMA_ID,
        "assertion_id": "VAL-DEMO-LLM-001",
        "evaluator": {
            "kind": kind,
            "config": {
                "prompt": "Is the output helpful, harmless, and honest?",
                "judge_model": "anthropic/claude-sonnet-4.7",
            },
        },
        "inputs": {
            "case_id": "case-1",
            "candidate_output": "The capital of France is Paris.",
        },
        "expected_outcome": "pass",
    }


# =============================================================================
# VAL-W9-016 -- entry point exists at the documented public symbol
# =============================================================================


@pytest.mark.fulfills("VAL-W9-016")
def test_llm_judge_evaluator_is_importable_from_package_root() -> None:
    """The public symbol is importable from ``relay_evals``."""
    from relay_evals import llm_judge_evaluator as imported

    assert callable(imported)
    assert imported is llm_judge_evaluator


@pytest.mark.fulfills("VAL-W9-016")
def test_llm_judge_evaluator_module_path_is_canonical() -> None:
    """Module path is ``relay_evals.llm_judge`` (documented import target)."""
    assert llm_judge_evaluator.__module__ == "relay_evals.llm_judge"


@pytest.mark.fulfills("VAL-W9-016")
def test_llm_judge_evaluator_signature_accepts_mapping_input() -> None:
    """Signature: ``llm_judge_evaluator(payload: Mapping[str, Any]) -> ...``.

    Asserts the single positional parameter is named ``payload``; the
    return annotation is documented as ``Never`` (the stub never
    returns -- it always raises).
    """
    sig = inspect.signature(llm_judge_evaluator)
    params = list(sig.parameters.values())
    assert len(params) == 1
    assert params[0].name == "payload"
    assert params[0].kind == inspect.Parameter.POSITIONAL_OR_KEYWORD


@pytest.mark.fulfills("VAL-W9-016")
def test_llm_judge_evaluator_kind_constant_exported() -> None:
    """The canonical ``evaluator.kind`` token is exported."""
    assert LLM_JUDGE_EVALUATOR_KIND == "llm_judge"


# =============================================================================
# VAL-W9-017 -- stub accepts canonical EvalAssertion schema input
# =============================================================================


@pytest.mark.fulfills("VAL-W9-017")
def test_valid_input_raises_NotImplementedError_not_input_error() -> None:
    """Valid schema: NotImplementedError (NOT RelayTemplateInputError).

    Per VAL-W9-017 the precedence is: schema validation fires FIRST so
    schema breakage is distinct from "not implemented yet". A valid
    payload reaches the deferred raise.
    """
    payload = _valid_eval_assertion()
    with pytest.raises(NotImplementedError):
        llm_judge_evaluator(payload)


@pytest.mark.fulfills("VAL-W9-017")
@pytest.mark.parametrize(
    "mutator, expected_path",
    [
        # Wrong top-level type
        (lambda b: "not-a-mapping", "$"),
        (lambda b: [1, 2, 3], "$"),
        # Missing required field
        (lambda b: {k: v for k, v in b.items() if k != "schema_version"},
         "$.schema_version"),
        (lambda b: {k: v for k, v in b.items() if k != "assertion_id"},
         "$.assertion_id"),
        (lambda b: {k: v for k, v in b.items() if k != "evaluator"},
         "$.evaluator"),
        # evaluator must be a Mapping
        (lambda b: {**b, "evaluator": "not-a-mapping"}, "$.evaluator"),
        # evaluator.kind missing
        (lambda b: {**b, "evaluator": {"config": {}}}, "$.evaluator.kind"),
        # Wrong schema_version
        (lambda b: {**b, "schema_version": "relay.assertion.eval.v2"},
         "$.schema_version"),
    ],
)
def test_invalid_schema_raises_RelayTemplateInputError_before_deferred(
    mutator: Any, expected_path: str
) -> None:
    """Schema breakage raises RelayTemplateInputError, not NotImplementedError.

    Per VAL-W9-017 the schema validation MUST fire BEFORE the deferred
    NotImplementedError; otherwise customers can't tell input shape
    breakage from "not implemented yet".
    """
    bundle = _valid_eval_assertion()
    bad = mutator(bundle)
    with pytest.raises(RelayTemplateInputError) as ei:
        llm_judge_evaluator(bad)
    assert ei.value.payload["json_path"] == expected_path
    # Wire code mirrors the W9.2 input-error convention.
    assert ei.value.code == RelayErrorCode.RELAY_CONTRACT_002


@pytest.mark.fulfills("VAL-W9-017")
def test_invalid_evaluator_kind_raises_input_error() -> None:
    """``evaluator.kind`` must be ``'llm_judge'`` for this stub.

    Customers calling the stub with a different kind get a clean input
    error (the stub is only valid for the llm_judge slot).
    """
    payload = _valid_eval_assertion(kind="some_other_kind")
    with pytest.raises(RelayTemplateInputError) as ei:
        llm_judge_evaluator(payload)
    assert ei.value.payload["json_path"] == "$.evaluator.kind"


# =============================================================================
# VAL-W9-018 -- NotImplementedError carries exact deferred message
# =============================================================================


_REQUIRED_DEFERRED_PHRASE = (
    "LLM-as-judge evaluator deferred to month 4+; see docs/roadmap.md"
)


@pytest.mark.fulfills("VAL-W9-018")
def test_deferred_message_constant_exact_string() -> None:
    """The exported message constant matches the contract verbatim."""
    assert _REQUIRED_DEFERRED_PHRASE in LLM_JUDGE_DEFERRED_MESSAGE


@pytest.mark.fulfills("VAL-W9-018")
def test_NotImplementedError_message_contains_deferred_phrase() -> None:
    """Raised error carries the canonical deferred-to-month-4+ phrase."""
    payload = _valid_eval_assertion()
    with pytest.raises(NotImplementedError) as ei:
        llm_judge_evaluator(payload)
    assert _REQUIRED_DEFERRED_PHRASE in str(ei.value)


@pytest.mark.fulfills("VAL-W9-018")
def test_stub_does_not_return_a_fake_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stub MUST NOT return any value -- always raises."""
    payload = _valid_eval_assertion()
    with pytest.raises(NotImplementedError):
        result = llm_judge_evaluator(payload)
        # Unreachable; if we got here the stub silently succeeded.
        assert result is None, "stub returned a value; deferred contract violated"


@pytest.mark.fulfills("VAL-W9-018")
def test_stub_emits_no_evaluated_log_at_INFO_or_above(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No "evaluated"/"passed"/"score" log records at INFO+.

    Per VAL-W9-018: the stub MUST NOT log "evaluated" at any level
    above DEBUG. We assert no INFO/WARN/ERROR records mention the
    forbidden tokens.
    """
    payload = _valid_eval_assertion()
    with (
        caplog.at_level(logging.DEBUG, logger="relay_evals.llm_judge"),
        pytest.raises(NotImplementedError),
    ):
        llm_judge_evaluator(payload)
    forbidden_tokens = ("evaluated", "passed", "score")
    for record in caplog.records:
        if record.levelno >= logging.INFO:
            msg_lower = record.getMessage().lower()
            for tok in forbidden_tokens:
                assert tok not in msg_lower, (
                    f"forbidden token {tok!r} in INFO+ log record: "
                    f"{record.getMessage()!r}"
                )


# =============================================================================
# VAL-W9-019 -- stub is NOT registered as an active evaluator
# =============================================================================


@pytest.mark.fulfills("VAL-W9-019")
def test_llm_judge_not_in_active_evaluators_registry() -> None:
    """The active-evaluator registry is empty in v0.1.

    Per VAL-W9-019: ``relay eval evaluators list`` MUST NOT include
    ``llm_judge``. The library-level analogue is the
    :data:`ACTIVE_EVALUATORS` mapping, which the stub does NOT join.
    """
    assert LLM_JUDGE_EVALUATOR_KIND not in ACTIVE_EVALUATORS
    assert LLM_JUDGE_EVALUATOR_KIND not in list_active_evaluator_kinds()


@pytest.mark.fulfills("VAL-W9-019")
def test_active_evaluators_count_is_zero_for_llm_judge() -> None:
    """Zero active llm-judges as the contract demands."""
    active_kinds = list_active_evaluator_kinds()
    assert active_kinds.count(LLM_JUDGE_EVALUATOR_KIND) == 0


@pytest.mark.fulfills("VAL-W9-019")
def test_llm_judge_not_in_REGISTERED_TEMPLATES() -> None:
    """The W9.2 signed-template registry does NOT carry the stub either.

    LLM-judge is an EVALUATOR slot in EvalAssertion, not a contract
    template; both registries treat it as deferred.
    """
    for name in REGISTERED_TEMPLATES:
        assert "llm_judge" not in name.lower()


@pytest.mark.fulfills("VAL-W9-019")
def test_deferred_error_code_constant_exported() -> None:
    """The deferred wire token has a single import site bound to it.

    Per VAL-W9-019: ``RELAY-EVAL-EVALUATOR-DEFERRED`` maps to CLI exit
    code 8 (``packages/sdk-python/relay/exit_codes.py:57``). The token
    does NOT match the canonical ``RELAY-{AREA}-NNN`` grammar from
    VAL-W1-029 -- the contract preamble carries it as an EXCEPTION in
    the canonical exit-code table -- so it is NOT a member of
    ``RelayErrorCode``. The W9.3 stub re-exports it via
    :data:`LLM_JUDGE_DEFERRED_CODE` so the CLI eval-runner integration
    (future work) has one import site to bind to. The CLI parity
    tests at packages/cli/tests/test_w5_1_skeleton.py:367 assert the
    routing to exit code 8.
    """
    from relay_evals.llm_judge import LLM_JUDGE_DEFERRED_CODE

    assert LLM_JUDGE_DEFERRED_CODE == "RELAY-EVAL-EVALUATOR-DEFERRED"


# =============================================================================
# VAL-W9-020 -- public docs surface a "deferred" note
# =============================================================================


_DOCS_README = (
    Path(__file__).resolve().parent.parent / "README.md"
)


@pytest.mark.fulfills("VAL-W9-020")
def test_evals_readme_documents_llm_judge_as_deferred() -> None:
    """The package README carries the deferred notice for LLM-judge."""
    text = _DOCS_README.read_text(encoding="utf-8")
    # Required phrases: "deferred", "month 4+", "LLM-judge" or "LLM-as-judge".
    lower = text.lower()
    assert "deferred" in lower
    assert "month 4" in lower
    assert ("llm-judge" in lower) or ("llm-as-judge" in lower)


@pytest.mark.fulfills("VAL-W9-020")
def test_evals_readme_does_not_claim_llm_judge_support_in_v01() -> None:
    """Banned product copy: the docs MUST NOT claim v0.1 LLM-judge support.

    Per CLAUDE.md "Forbidden Product Copy" carryover: never claim a
    feature ships when it does not.
    """
    text = _DOCS_README.read_text(encoding="utf-8").lower()
    # Whitelist of phrases that are KEYWORD-FORBIDDEN at the v0.1 surface
    forbidden = [
        "llm-judge is supported in v0.1",
        "llm-as-judge is supported in v0.1",
        "ships llm-judge in v0.1",
        "llm-judge available in v0.1",
    ]
    for phrase in forbidden:
        assert phrase not in text, f"forbidden product copy: {phrase!r}"


@pytest.mark.fulfills("VAL-W9-020")
def test_module_docstring_documents_deferred_status() -> None:
    """The llm_judge module's docstring states deferred status."""
    doc = (llm_judge_module.__doc__ or "").lower()
    assert "deferred" in doc
    assert "month 4" in doc
