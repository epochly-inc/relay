"""Signed-decision byte determinism on the single wasm engine
(VAL-CWC-P2TSGATE-012, P0 -- M6 WS-I port of the cross-engine parity gate).

Keystone invariant #11 (cross-host byte-parity) applied to the gate engine's
signed decision: building the SAME ``GateDecisionDraft`` + ``GatePolicy`` and
running it through ``GateEvaluator.evaluate`` then
``signed_decision.canonical_decision_payload`` / ``canonical_json_bytes``
across INDEPENDENT evaluator constructions MUST produce byte-identical
canonical signing payloads -- and therefore identical signed bytes for a
fixed Ed25519 key.

History: through M1-M5 this file asserted celpy-vs-wasm cross-engine byte
parity (the M4 dual-run de-risk). M6 WS-I removed the legacy engine, so the
cross-engine axis is resolved BY CONSTRUCTION; the surviving protected
behavior is the determinism of the signed bytes across independent wasm
evaluator instances (fresh Engine/Store state must never leak into the
signing input) plus the per-condition ``error_code`` stability the signed
payload binds (a condition_evaluation_error's code is part of the signed
bytes -- ADR Revisions section 2).

Design constraints honored (load-bearing)
------------------------------------------
* The policy exercises a MIX so the determinism covers the met / unmet /
  error_code paths: a passing condition, a failing condition, an erroring
  condition (the regex-backreference HOST guard, which fires host-side BEFORE
  the engine call and produces the stable RELAY-CEL-007 code+message), plus a
  passing / failing / erroring assertion (all p2 so no p0 cascade short-
  circuits any assertion).
* The Ed25519 key is TEST-ONLY: minted from a FIXED 32-byte seed via
  ``Ed25519PrivateKey.from_private_bytes`` so the same private key is used for
  both runs (signature bytes are then directly comparable). NO real / KMS /
  trust-anchor key material is committed (CLAUDE.md banned pattern #14).
* The two runs differ ONLY in evaluator instance identity. Same draft, same
  policy, same key, same ``decided_*`` constants, same evidence. Each
  evaluator is constructed via the contracts factory and injected through the
  ``GateEvaluator(cel_evaluator=...)`` param.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
    WasmCelEvaluator,
    make_cel_evaluator,
)
from relay_contracts.evaluator import MAX_TIMEOUT_MS
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
# evaluates, so its code AND message are deterministic host-owned strings --
# the byte-stable error path the signed payload binds (a runtime engine error
# message could legitimately evolve with the engine build; the host guard
# cannot).
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


def _build_evaluator() -> GateEvaluator:
    """Construct a fresh ``GateEvaluator`` over a factory-built CEL backend.

    The CEL evaluator is built through the contracts factory (the single
    ``RELAY_CEL_ENGINE`` read site; the default engine IS the wasm engine),
    then injected via the ``cel_evaluator`` param so the gate src stays
    env-free. All other gate collaborators (evidence provider, manifest
    resolver) are identical across the two runs so the ONLY difference is the
    evaluator INSTANCE (fresh wasm Engine/Module/Store state).

    Built with ``timeout_ms=MAX_TIMEOUT_MS``: this is a value/error-class
    DETERMINISM assertion (byte-identical signed payload across independent
    evaluations), not a timeout-behavior test, so it is decoupled from the
    50 ms wall-clock to avoid host-thread jitter under concurrent load (a
    spurious RELAY-CEL-003 in ONE run's outcome but not the other would break
    the byte determinism). Production 50 ms default (CQ1) unchanged; root
    cause resolved by M7 P7EDGE fuel metering.
    """
    cel = make_cel_evaluator(udfs=RELAY_UDFS, timeout_ms=MAX_TIMEOUT_MS)
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
def test_independent_evaluations_use_distinct_wasm_instances() -> None:
    """The two runs use genuinely INDEPENDENT wasm evaluator instances.

    Without this, a shared/cached evaluator could make the byte-determinism
    assertion below vacuous (same object == same object). Both backends are
    the single wasm engine class, but DIFFERENT instances (fresh per-run
    Engine/Module/Store state).
    """
    eval_a = _build_evaluator()
    eval_b = _build_evaluator()
    assert isinstance(eval_a._cel, WasmCelEvaluator)  # noqa: SLF001
    assert isinstance(eval_b._cel, WasmCelEvaluator)  # noqa: SLF001
    assert eval_a._cel is not eval_b._cel  # noqa: SLF001


# ---------------------------------------------------------------------------
# The verdict mix is real: this policy exercises pass / fail / error paths.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P2TSGATE-012")
def test_policy_exercises_pass_fail_and_error_paths() -> None:
    """Sanity-check the fixture covers met, unmet, and error_code verdicts.

    Guards against a future edit that accidentally makes every condition pass
    (which would still produce byte-equal payloads but stop testing the error
    path that is the determinism risk). Verified on the single wasm engine.
    """
    gate, draft = _make_policy_and_draft()
    outcome = _build_evaluator().evaluate(gate=gate, draft=draft, now=_NOW)

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
def test_signed_decision_byte_determinism_across_independent_evaluations() -> None:
    """Same draft+gate -> byte-identical signed decision across two
    INDEPENDENT wasm evaluator instances (M6 WS-I port of the cross-engine
    byte-parity keystone; the cross-engine axis is resolved by construction).

    1. canonical_json_bytes(payload_a) == canonical_json_bytes(payload_b)
    2. per-condition error_code lists are EQUAL and carry the expected
       host-guard code (a divergence here would change the signed bytes)
    3. sign_payload(...) yields IDENTICAL signature bytes under a shared fixed
       Ed25519 key

    Any difference is a REAL P0 defect (nondeterministic engine/host state
    leaking into the signing input) and is surfaced as a byte diff, never
    masked.
    """
    gate, draft = _make_policy_and_draft()

    eval_a = _build_evaluator()
    eval_b = _build_evaluator()
    # Non-vacuous: two genuinely independent evaluator instances.
    assert eval_a._cel is not eval_b._cel  # noqa: SLF001

    outcome_a = eval_a.evaluate(gate=gate, draft=draft, now=_NOW)
    outcome_b = eval_b.evaluate(gate=gate, draft=draft, now=_NOW)

    payload_a = _payload_for_engine_outcome(gate, outcome_a)
    payload_b = _payload_for_engine_outcome(gate, outcome_b)

    # (2) Per-condition error_code lists are equal AND the expected stable
    # host-guard code. Asserted FIRST so a divergence here reports the
    # offending codes directly rather than as an opaque byte diff.
    codes_a = _condition_error_codes(outcome_a.unmet_conditions)
    codes_b = _condition_error_codes(outcome_b.unmet_conditions)
    assert codes_a == codes_b == ["RELAY-CEL-007"], (
        f"per-condition error_code divergence: a={codes_a!r} b={codes_b!r}"
    )

    # (1) Byte-identical canonical signing payload.
    bytes_a = canonical_json_bytes(payload_a)
    bytes_b = canonical_json_bytes(payload_b)
    assert bytes_a == bytes_b, (
        "canonical signing payload bytes diverge across independent "
        "evaluations:\n"
        f"  a = {bytes_a!r}\n"
        f"  b = {bytes_b!r}"
    )

    # (3) Identical signature bytes under the SAME fixed Ed25519 key.
    key = _fixed_signing_key()
    sig_a, kid_a = sign_payload(payload_a, key)
    sig_b, kid_b = sign_payload(payload_b, key)
    assert kid_a == kid_b == _FIXED_KID
    assert sig_a == sig_b, (
        "signature bytes diverge across independent evaluations despite a "
        f"shared fixed key: a={sig_a!r} b={sig_b!r}"
    )
