"""VAL-CWC-P1HOST-015: typed-canonical is the SINGLE contract for
udf_outputs_jcs -- both engines emit byte-identical bytes for the same logical
UDF outputs.

The ``udf_outputs_jcs`` field feeds a cryptographic digest, so its BYTES (not
just its structure) must match across engines. The unification makes
typed-canonical (``{"t":...,"v":...}``) the single encoding both paths feed into
the JCS canonicalizer, eliminating the prior celpy-raw-objects vs
wasm-typed-canonical digest divergence.

Two complementary assertions:

  1. The wasm pipeline path (driven end-to-end via the contracts factory under
     ``RELAY_CEL_ENGINE=wasm``) produces ``udf_outputs_jcs`` whose bytes equal
     the bytes the SAME logical UDF outputs serialize to via the celpy-side
     typed-canonical codec (``py_to_typed`` of the direct relay.* UDF results,
     run through the SAME ``jcs_canonicalize``). This proves the two engines
     feed IDENTICAL typed-canonical structures into one JCS encoder.

  2. The celpy pipeline path emits typed-canonical bytes for a bare-name UDF
     (the only UDF form cel-python can evaluate through CEL), byte-identical to
     the typed-canonical encoding of the SAME logical output. This proves the
     celpy path was migrated OFF raw-celpy-object JСS onto the single
     typed-canonical contract.

Why not run the SAME dotted relay.* expression through BOTH engines? cel-python
cannot evaluate a dotted ``relay.coverage(...)`` call through CEL -- it parses
it as a member-method call needing ``relay`` bound as a variable, and any
method-leaf adapter diverges on short-circuit and chained logical ops. That is
the provably-unbounded two-engine gap the single-wasm-engine cutover exists to
eliminate (the same gap the known-failing ``test_w17_4_*`` tests track). The
byte-parity CONTRACT is the typed-canonical ENCODING; this test proves that
encoding is byte-identical for identical logical outputs across the engines.

CLAUDE.md keystone invariant 16 (typed-canonical cross-host byte parity, a P0).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from relay_contracts import (
    RELAY_COVERAGE_NAME,
    register_udf,
)
from relay_contracts.canonical import jcs_canonicalize
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import evaluate_assertion
from relay_contracts.udfs import relay_coverage
from relay_contracts.wasm_codec import py_to_typed

# --- worker that drives the WASM pipeline path end-to-end ------------------

# Run the relay.coverage assertion through the contracts factory under
# RELAY_CEL_ENGINE=wasm (the factory reads the env once at construction;
# pipeline.py never reads it). Print the envelope udf_outputs_jcs string.
_WASM_WORKER = r"""
import json
from relay_contracts import RELAY_UDFS
from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import evaluate_assertion

doc = {
    "schema_version": "relay.assertion.behavioral.v1",
    "assertion_id": "VAL-RT-PARITY-COVERAGE",
    "kind": "behavioral",
    "expression": 'relay.coverage(t, "step1") && relay.coverage(t, "missing")',
    "severity": "p0",
    "owner_email": "test@example.com",
    "lifecycle_state": "active",
}
parsed = parse_contract(doc)
bindings = {"t": {"steps": [{"name": "step1"}]}}
envelope = evaluate_assertion(parsed, bindings=bindings, extra_udfs=RELAY_UDFS)
print(json.dumps({
    "udf_outputs_jcs": envelope["udf_outputs_jcs"],
    "udfs_invoked": envelope["udfs_invoked"],
}))
"""


def _run_wasm_pipeline() -> dict[str, object]:
    env = dict(os.environ)
    env["RELAY_CEL_ENGINE"] = "wasm"
    proc = subprocess.run(
        [sys.executable, "-c", _WASM_WORKER],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, (
        f"wasm pipeline worker failed (rc={proc.returncode}):\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _celpy_side_typed_canonical_jcs() -> bytes:
    """The typed-canonical JCS bytes the celpy SIDE produces for the SAME
    logical relay.coverage outputs.

    The pipeline's celpy path encodes captured UDF results via ``py_to_typed``
    then ``jcs_canonicalize`` -- exactly this sequence. We compute the same
    bytes from the direct relay.coverage results (the celtypes-equivalent
    logical values) to assert the wasm pipeline bytes equal the celpy-side
    encoding of identical logical outputs.
    """
    import celpy.celtypes as celtypes

    trace = celtypes.MapType({
        celtypes.StringType("steps"): celtypes.ListType([
            celtypes.MapType({celtypes.StringType("name"): celtypes.StringType("step1")})
        ])
    })
    # Two calls in expression order: match (step1) -> True, miss (missing) -> False.
    r1 = relay_coverage(trace, celtypes.StringType("step1"))
    r2 = relay_coverage(trace, celtypes.StringType("missing"))
    udf_outputs = {RELAY_COVERAGE_NAME: [py_to_typed(r1), py_to_typed(r2)]}
    return jcs_canonicalize(udf_outputs)


@pytest.mark.plumbing
def test_wasm_pipeline_udf_outputs_jcs_matches_typed_canonical_encoding() -> None:
    """The wasm pipeline's udf_outputs_jcs bytes equal the celpy-side
    typed-canonical encoding of the SAME logical relay.coverage outputs."""
    wasm = _run_wasm_pipeline()
    wasm_bytes = wasm["udf_outputs_jcs"].encode("utf-8")  # type: ignore[union-attr]
    celpy_side_bytes = _celpy_side_typed_canonical_jcs()

    assert wasm_bytes == celpy_side_bytes, (
        "typed-canonical udf_outputs_jcs byte divergence:\n"
        f"  wasm pipeline : {wasm['udf_outputs_jcs']!r}\n"
        f"  celpy codec   : {celpy_side_bytes.decode('utf-8')!r}"
    )
    # The single typed-canonical contract: per-name call-order list of {t,v}.
    assert json.loads(wasm["udf_outputs_jcs"]) == {  # type: ignore[arg-type]
        "relay.coverage": [
            {"t": "bool", "v": True},
            {"t": "bool", "v": False},
        ]
    }
    assert wasm["udfs_invoked"] == ["relay.coverage"], wasm["udfs_invoked"]


@pytest.mark.plumbing
@pytest.mark.skipif(
    os.environ.get("RELAY_CEL_ENGINE", "").strip() == "wasm",
    reason="bare-name custom UDF (is_pos); the wasm engine rejects non-allowlist "
    "UDFs. This asserts the celpy-path typed-canonical encoding.",
)
def test_celpy_pipeline_emits_typed_canonical_not_raw() -> None:
    """The celpy pipeline path emits TYPED-CANONICAL udf_outputs_jcs (the single
    contract), not raw cel-python objects.

    Uses a bare-name UDF (the only UDF form cel-python can evaluate through
    CEL). The emitted bytes MUST equal the typed-canonical encoding of the same
    logical outputs -- proving the celpy path was migrated off raw-object JCS.
    """
    def is_pos(n: int) -> bool:
        return n > 0

    udf = register_udf("is_pos", is_pos, pure=True, arity=1)
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-RT-CELPY-TYPED",
        "kind": "behavioral",
        "expression": "is_pos(x) && !is_pos(y)",
        "severity": "p0",
        "owner_email": "test@example.com",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    envelope = evaluate_assertion(
        parsed, bindings={"x": 5, "y": -3}, extra_udfs=[udf]
    )

    # is_pos(5)=True, is_pos(-3)=False -> captured [True, False].
    expected = jcs_canonicalize({"is_pos": [py_to_typed(True), py_to_typed(False)]})
    assert envelope["udf_outputs_jcs"].encode("utf-8") == expected, (
        f"celpy path did not emit typed-canonical bytes:\n"
        f"  got     : {envelope['udf_outputs_jcs']!r}\n"
        f"  expected: {expected.decode('utf-8')!r}"
    )
    # Raw-object form would have been {"is_pos":[true,false]} -- assert we are
    # NOT emitting that (the divergence the unification eliminates).
    assert envelope["udf_outputs_jcs"] != '{"is_pos":[true,false]}'
    assert json.loads(envelope["udf_outputs_jcs"]) == {
        "is_pos": [{"t": "bool", "v": True}, {"t": "bool", "v": False}]
    }
