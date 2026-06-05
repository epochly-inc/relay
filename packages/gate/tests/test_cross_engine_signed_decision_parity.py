"""Cross-engine signed-decision byte parity (VAL-CWC-P2TSGATE-012, P0).

Keystone invariant #11 (Py<->wasm byte-parity) applied to the gate engine's
signed decision: building the SAME ``GateDecisionDraft`` + ``GatePolicy`` and
running it through ``GateEvaluator.evaluate`` then
``signed_decision.canonical_decision_payload`` / ``canonical_json_bytes`` under
BOTH CEL engines (``RELAY_CEL_ENGINE=celpy`` and ``RELAY_CEL_ENGINE=wasm``)
MUST produce byte-identical canonical signing payloads -- and therefore
identical signed bytes for a fixed Ed25519 key.

Why this matters
----------------
The control plane signs the canonical JSON of a gate_decision row before the
transaction commits (signed_decision.sign_payload over canonical_json_bytes).
The signing input is derived from the ``DraftOutcome`` the gate evaluator
produces -- ``action``, ``failed_assertion_ids``, and ``unmet_conditions``
(which carry the per-condition ``error_code`` / ``error_message`` for any
condition that errored). If the celpy and wasm CEL engines disagreed on a
condition verdict OR on a condition error_code, the canonical payload bytes
would diverge and the SAME logical decision would carry DIFFERENT signatures
under the two engines. During the M4 dual-run bake (both engines live) that is
a P0: a verifier would see two different signatures for one decision.

Design constraints honored (load-bearing)
------------------------------------------
* PLAIN CEL conditions / assertions ONLY -- no dotted ``relay.*`` UDF calls.
  cel-python cannot evaluate a dotted ``relay.coverage(...)`` through CEL (the
  user-adjudicated VAL-CWC-P1HOST-015 gap this cutover exists to close), so a
  relay.*-bearing condition would make the celpy path diverge/raise. Every
  condition here is comparisons / boolean logic / arithmetic / ``in`` / string
  ops / ternary -- evaluated IDENTICALLY by both engines.
* The policy exercises a MIX so the parity covers the met / unmet / error_code
  paths: a passing condition, a failing condition, an erroring condition (the
  regex-backreference HOST guard, which fires host-side BEFORE the engine call
  and produces the SAME RELAY-CEL-007 code+message on both engines), plus a
  passing / failing / erroring assertion (all p2 so no p0 cascade short-
  circuits any assertion -- both engines evaluate every assertion).
* The Ed25519 key is TEST-ONLY: minted from a FIXED 32-byte seed via
  ``Ed25519PrivateKey.from_private_bytes`` so the same private key is used for
  both engines (signature bytes are then directly comparable). NO real / KMS /
  trust-anchor key material is committed (CLAUDE.md banned pattern #14).
* The two runs differ ONLY in the engine. Same draft, same policy, same key,
  same ``decided_*`` constants, same evidence. Each engine is constructed via
  the contracts factory under its own ``RELAY_CEL_ENGINE`` setting and injected
  through the ``GateEvaluator(cel_evaluator=...)`` param so engine selection is
  the only difference -- and a non-vacuous guard asserts the two evaluators are
  DIFFERENT classes (RelayCelEvaluator vs WasmCelEvaluator), so a no-op
  double-celpy run can never pass this test.

If the wasm and celpy paths produced different canonical bytes for this
plain-CEL policy, that would be a REAL P0 cutover defect; this test surfaces it
as a byte diff rather than masking it.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from _w8_1_helpers import (
    ACTOR_HASH,
    COMMAND_HASH_CLEAN,
    GATE_ID_SCRUTINY,
    MANIFEST_HASH,
    InMemoryEvidenceProvider,
    InMemoryManifestResolver,
    make_draft,
    make_gate,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from relay_contracts import (
    RELAY_UDFS,
    RelayCelEvaluator,
    WasmCelEvaluator,
    make_cel_evaluator,
)
from relay_gate_engine import (
    GateAssertion,
    GateEvaluator,
    SigningKey,
    canonical_decision_payload,
    canonical_json_bytes,
    sign_payload,
)

# ---------------------------------------------------------------------------
# Test-only fixed Ed25519 key (deterministic seed; NOT real key material).
# ---------------------------------------------------------------------------
#
# A FIXED 32-byte seed so both engines sign with the IDENTICAL private key and
# the resulting signature bytes are directly comparable. This is a throwaway
# test key generated in-process; it is never a real / KMS-backed / trust-anchor
# signing key (CLAUDE.md banned pattern #14 -- no signing key material in the
# repo). The seed value is arbitrary but stable so the test is reproducible.
_FIXED_ED25519_SEED: bytes = bytes(range(32))  # 0x00..0x1f
_FIXED_KID: str = "test-cwc-p2tsgate-012-fixed"


def _fixed_signing_key() -> SigningKey:
    """Return a deterministic test-only Ed25519 ``SigningKey``."""
    private = ed25519.Ed25519PrivateKey.from_private_bytes(_FIXED_ED25519_SEED)
    return SigningKey(private_key=private, key_id=_FIXED_KID)


# ---------------------------------------------------------------------------
# Plain-CEL policy that exercises the pass / fail / error verdict mix.
# ---------------------------------------------------------------------------
#
# A host-side regex-backreference guard (RELAY-CEL-007) fires BEFORE the engine
# evaluates, so its code AND message are identical across celpy and wasm. That
# makes it the only error path that is byte-stable across engines (a runtime
# engine error such as division-by-zero is NOT: celpy raises RELAY-CEL-002 and
# the wasm raises RELAY-CEL-009, a real engine difference that is out of scope
# for the plain-CEL parity contract). We therefore drive the error path through
# the host guard, which both engines hit identically.
_REGEX_BACKREF_EXPR: str = '"x".matches("(a)\\1")'

# A condition tuple mixing a PASS, a FAIL, and an ERROR (host-guard) verdict.
_CONDITIONS: tuple[str, ...] = (
    "2 + 2 == 4",  # PASS
    "1 == 2",  # FAIL (unmet_condition)
    _REGEX_BACKREF_EXPR,  # ERROR (condition_evaluation_error, RELAY-CEL-007)
)

# Assertions: all p2 so no p0 cascade short-circuits any of them -- both
# engines evaluate every assertion, and the pass / fail / error mix lands in
# failed_assertion_ids identically.
_ASSERTIONS: tuple[GateAssertion, ...] = (
    GateAssertion(
        assertion_id="VAL-PARITY-PASS-001",
        priority="p2",
        expression='"abc".size() == 3',  # PASS
    ),
    GateAssertion(
        assertion_id="VAL-PARITY-FAIL-002",
        priority="p2",
        expression="10 in [1, 2, 3]",  # FAIL
    ),
    GateAssertion(
        assertion_id="VAL-PARITY-ERROR-003",
        priority="p2",
        expression=_REGEX_BACKREF_EXPR,  # ERROR (RELAY-CEL-007)
    ),
)

# Fixed signing-input constants shared by both engine runs (the ONLY thing
# that differs between the two payloads must be the engine; these are equal).
_DECIDED_AT: str = "2026-05-14T12:00:30Z"
_DECIDED_BY: str = "gate_engine"
_SCHEMA_VERSION: str = "relay.gate_decision.v1"
_GATE_DECISION_ID: str = "dec-cwc-p2tsgate-012"
_EVIDENCE_BUNDLE_ID: str = "bundle-cwc-p2tsgate-012"

# ``now`` is 30 seconds after the draft's default ``submitted_at``
# (``datetime(2026, 5, 14, 12, 0, 0)`` per ``_w8_1_helpers.make_draft``) so the
# draft is well inside the 900s TTL and the gate evaluates rather than
# short-circuiting on expiry (VAL-W8-006).
_NOW: datetime = datetime(2026, 5, 14, 12, 0, 30, tzinfo=UTC)


@contextmanager
def _engine_env(engine: str):
    """Temporarily set ``RELAY_CEL_ENGINE`` for the factory read, then restore.

    The contracts factory is the SINGLE site that reads ``RELAY_CEL_ENGINE``;
    we set it only around the ``make_cel_evaluator`` call and restore the prior
    value so the env does not leak between the two engine constructions.
    """
    sentinel = object()
    prior: Any = os.environ.get("RELAY_CEL_ENGINE", sentinel)
    os.environ["RELAY_CEL_ENGINE"] = engine
    try:
        yield
    finally:
        if prior is sentinel:
            os.environ.pop("RELAY_CEL_ENGINE", None)
        else:
            os.environ["RELAY_CEL_ENGINE"] = prior  # type: ignore[assignment]


def _build_evaluator(engine: str) -> GateEvaluator:
    """Construct a ``GateEvaluator`` whose CEL backend is ``engine``.

    The CEL evaluator is built through the contracts factory under the engine
    env, then injected via the ``cel_evaluator`` param so the gate src stays
    env-free (the only env read is inside the factory). All other gate
    collaborators (evidence provider, manifest resolver) are identical across
    the two engine runs so the ONLY difference is the CEL backend.
    """
    with _engine_env(engine):
        cel = make_cel_evaluator(udfs=RELAY_UDFS)
    return GateEvaluator(
        evidence_provider=InMemoryEvidenceProvider(),
        manifest_resolver=InMemoryManifestResolver(
            {COMMAND_HASH_CLEAN: "uv run pytest -m plumbing"}
        ),
        cel_evaluator=cel,
    )


def _make_policy_and_draft():
    """Return the SAME (gate, draft) used for both engine runs."""
    gate = make_gate(
        gate_id=GATE_ID_SCRUTINY,
        gate_name="scrutiny",
        assertions=_ASSERTIONS,
        conditions=_CONDITIONS,
        cascade_on_block=True,
    )
    draft = make_draft(gate_id=GATE_ID_SCRUTINY)
    return gate, draft


def _payload_for_engine_outcome(gate, outcome) -> Mapping[str, Any]:
    """Build the canonical signing payload from a pre-computed outcome.

    Every non-CEL field is a fixed constant identical across engines, so any
    byte difference in the result is attributable to a CEL-engine verdict /
    error_code divergence (the only inputs that change are ``action``,
    ``failed_assertion_ids``, and ``unmet_conditions``).
    """
    return canonical_decision_payload(
        gate_decision_id=_GATE_DECISION_ID,
        schema_version=_SCHEMA_VERSION,
        gate_id=str(gate.gate_id),
        scope_type=outcome.scope_type,
        scope_id=outcome.scope_id,
        round_=outcome.round,
        action=outcome.action,
        strict_pass=(outcome.action == "accept"),
        failed_assertion_ids=list(outcome.failed_assertion_ids),
        unmet_conditions=list(outcome.unmet_conditions),
        evidence_bundle_id=_EVIDENCE_BUNDLE_ID,
        cascade_on_block=gate.cascade_on_block,
        decided_by=_DECIDED_BY,
        decided_at=_DECIDED_AT,
        manifest_commit_hash=MANIFEST_HASH,
        actor_identity_hash=ACTOR_HASH,
    )


def _condition_error_codes(
    unmet_conditions: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Return the per-condition ``error_code`` list in surface order.

    Only ``condition_evaluation_error`` entries carry an ``error_code``; a
    plain ``unmet_condition`` (boolean-false) does not. Preserving surface
    order makes the cross-engine list comparison position-sensitive.
    """
    return [
        str(u["error_code"])
        for u in unmet_conditions
        if u.get("kind") == "condition_evaluation_error"
    ]


# ---------------------------------------------------------------------------
# Non-vacuous guard: the two engines are genuinely different backends.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-012")
def test_two_engines_are_distinct_backend_classes() -> None:
    """celpy and wasm resolve to DIFFERENT evaluator classes.

    Without this, a misconfigured factory could hand back two celpy
    evaluators and the byte-parity assertion would pass vacuously (celpy ==
    celpy). Asserting RelayCelEvaluator vs WasmCelEvaluator proves the parity
    test below actually crosses the engine boundary.
    """
    celpy_eval = _build_evaluator("celpy")
    wasm_eval = _build_evaluator("wasm")
    assert isinstance(celpy_eval._cel, RelayCelEvaluator)  # noqa: SLF001
    assert isinstance(wasm_eval._cel, WasmCelEvaluator)  # noqa: SLF001
    assert type(celpy_eval._cel) is not type(wasm_eval._cel)  # noqa: SLF001


# ---------------------------------------------------------------------------
# The verdict mix is real: this policy exercises pass / fail / error paths.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-012")
def test_policy_exercises_pass_fail_and_error_paths() -> None:
    """Sanity-check the fixture covers met, unmet, and error_code verdicts.

    Guards against a future edit that accidentally makes every condition pass
    (which would still produce byte-equal payloads but stop testing the error
    path that is the parity risk). Verified on the celpy reference engine.
    """
    gate, draft = _make_policy_and_draft()
    outcome = _build_evaluator("celpy").evaluate(gate=gate, draft=draft, now=_NOW)

    # A FAIL condition surfaces as a plain unmet_condition.
    assert any(
        u.get("kind") == "unmet_condition" and u.get("expression") == "1 == 2"
        for u in outcome.unmet_conditions
    ), outcome.unmet_conditions
    # An ERROR condition surfaces as a condition_evaluation_error with 007.
    err_codes = _condition_error_codes(outcome.unmet_conditions)
    assert err_codes == ["RELAY-CEL-007"], outcome.unmet_conditions
    # A FAIL and an ERROR assertion both land in failed_assertion_ids; the
    # PASS assertion does not.
    assert "VAL-PARITY-FAIL-002" in outcome.failed_assertion_ids
    assert "VAL-PARITY-ERROR-003" in outcome.failed_assertion_ids
    assert "VAL-PARITY-PASS-001" not in outcome.failed_assertion_ids
    # A failing-but-not-p0 mix yields "remediate".
    assert outcome.action == "remediate", outcome.action


# ---------------------------------------------------------------------------
# The keystone assertion: byte-identical canonical payload + error_code list +
# signature bytes across celpy and wasm.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-012")
def test_cross_engine_signed_decision_byte_parity() -> None:
    """Same draft+gate -> byte-identical signed decision under celpy and wasm.

    1. canonical_json_bytes(payload_celpy) == canonical_json_bytes(payload_wasm)
    2. per-condition error_code lists are EQUAL (a divergence here would change
       the signed bytes)
    3. sign_payload(...) yields IDENTICAL signature bytes under a shared fixed
       Ed25519 key

    Any difference is a REAL P0 cutover defect (a plain-CEL verdict / error_code
    divergence between the two engines) and is surfaced as a byte diff, never
    masked.
    """
    gate, draft = _make_policy_and_draft()

    celpy_eval = _build_evaluator("celpy")
    wasm_eval = _build_evaluator("wasm")
    # Non-vacuous: the two evaluators are genuinely different engine backends.
    assert isinstance(celpy_eval._cel, RelayCelEvaluator)  # noqa: SLF001
    assert isinstance(wasm_eval._cel, WasmCelEvaluator)  # noqa: SLF001

    outcome_celpy = celpy_eval.evaluate(gate=gate, draft=draft, now=_NOW)
    outcome_wasm = wasm_eval.evaluate(gate=gate, draft=draft, now=_NOW)

    payload_celpy = _payload_for_engine_outcome(gate, outcome_celpy)
    payload_wasm = _payload_for_engine_outcome(gate, outcome_wasm)

    # (2) Per-condition error_code lists are equal across engines. Asserted
    # FIRST so a divergence here reports the offending codes directly rather
    # than as an opaque byte diff.
    codes_celpy = _condition_error_codes(outcome_celpy.unmet_conditions)
    codes_wasm = _condition_error_codes(outcome_wasm.unmet_conditions)
    assert codes_celpy == codes_wasm, (
        f"per-condition error_code divergence: celpy={codes_celpy!r} "
        f"wasm={codes_wasm!r}"
    )

    # (1) Byte-identical canonical signing payload.
    bytes_celpy = canonical_json_bytes(payload_celpy)
    bytes_wasm = canonical_json_bytes(payload_wasm)
    assert bytes_celpy == bytes_wasm, (
        "canonical signing payload bytes diverge between celpy and wasm:\n"
        f"  celpy = {bytes_celpy!r}\n"
        f"  wasm  = {bytes_wasm!r}"
    )

    # (3) Identical signature bytes under the SAME fixed Ed25519 key.
    key = _fixed_signing_key()
    sig_celpy, kid_celpy = sign_payload(payload_celpy, key)
    sig_wasm, kid_wasm = sign_payload(payload_wasm, key)
    assert kid_celpy == kid_wasm == _FIXED_KID
    assert sig_celpy == sig_wasm, (
        "signature bytes diverge between celpy and wasm despite a shared "
        f"fixed key: celpy={sig_celpy!r} wasm={sig_wasm!r}"
    )
