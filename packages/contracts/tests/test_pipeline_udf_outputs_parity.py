"""VAL-CWC-P1HOST-015: typed-canonical is the SINGLE contract for
udf_outputs_jcs -- the pipeline emits byte-identical bytes to the direct
typed-canonical encoding of the same logical UDF outputs.

The ``udf_outputs_jcs`` field feeds a cryptographic digest, so its BYTES (not
just its structure) must match across hosts. Typed-canonical
(``{"t":...,"v":...}``) is the single encoding the pipeline feeds into the
JCS canonicalizer -- the M1 unification that eliminated the raw-objects vs
typed-canonical digest divergence, preserved unchanged by the M6 WS-I
type-layer move (the codec now decodes to native Python classes, but the
WIRE/encoding bytes are identical).

Two complementary assertions:

  1. The pipeline path (driven end-to-end via the contracts factory in a
     fresh subprocess with the default engine) produces ``udf_outputs_jcs``
     whose bytes equal the bytes the SAME logical UDF outputs serialize to
     via the host codec (``py_to_typed`` of the direct relay.* UDF results,
     run through the SAME ``jcs_canonicalize``). This proves the engine
     ``udf_trace`` and the host codec feed IDENTICAL typed-canonical
     structures into one JCS encoder.

  2. The emitted form is the typed-canonical per-name call-order list of
     ``{"t","v"}`` entries -- NEVER the raw-object form
     (``{"name":[true,false]}``) whose digest diverged pre-unification.

CLAUDE.md keystone invariant 16 (typed-canonical cross-host byte parity, a P0).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from relay_contracts import RELAY_COVERAGE_NAME
from relay_contracts.canonical import jcs_canonicalize
from relay_contracts.udfs import relay_coverage
from relay_contracts.wasm_codec import py_to_typed

# --- worker that drives the pipeline path end-to-end ------------------------

# Run the relay.coverage assertion through the contracts factory in a FRESH
# subprocess (default engine; the factory reads RELAY_CEL_ENGINE once at
# construction; pipeline.py never reads it). Print the envelope
# udf_outputs_jcs string.
_PIPELINE_WORKER = r"""
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


def _run_pipeline_subprocess() -> dict[str, object]:
    env = dict(os.environ)
    # The default engine (env unset) IS the wasm engine as of M5/M6; assert
    # the production default path, not an explicit override.
    env.pop("RELAY_CEL_ENGINE", None)
    proc = subprocess.run(
        [sys.executable, "-c", _PIPELINE_WORKER],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, (
        f"pipeline worker failed (rc={proc.returncode}):\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}"
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _direct_typed_canonical_jcs() -> bytes:
    """The typed-canonical JCS bytes the host codec produces for the SAME
    logical relay.coverage outputs.

    The pipeline encodes the engine's ``udf_trace`` entries (already
    typed-canonical) via ``jcs_canonicalize``; the direct side computes
    ``py_to_typed`` of the direct relay.coverage results (native Python
    logical values) through the SAME canonicalizer.
    """
    trace = {"steps": [{"name": "step1"}]}
    # Two calls in expression order: match (step1) -> True, miss (missing) -> False.
    r1 = relay_coverage(trace, "step1")
    r2 = relay_coverage(trace, "missing")
    udf_outputs = {RELAY_COVERAGE_NAME: [py_to_typed(r1), py_to_typed(r2)]}
    return jcs_canonicalize(udf_outputs)


@pytest.mark.plumbing
def test_pipeline_udf_outputs_jcs_matches_typed_canonical_encoding() -> None:
    """The pipeline's udf_outputs_jcs bytes equal the host-codec
    typed-canonical encoding of the SAME logical relay.coverage outputs."""
    result = _run_pipeline_subprocess()
    pipeline_bytes = result["udf_outputs_jcs"].encode("utf-8")  # type: ignore[union-attr]
    direct_bytes = _direct_typed_canonical_jcs()

    assert pipeline_bytes == direct_bytes, (
        "typed-canonical udf_outputs_jcs byte divergence:\n"
        f"  pipeline    : {result['udf_outputs_jcs']!r}\n"
        f"  host codec  : {direct_bytes.decode('utf-8')!r}"
    )
    # The single typed-canonical contract: per-name call-order list of {t,v}.
    assert json.loads(result["udf_outputs_jcs"]) == {  # type: ignore[arg-type]
        "relay.coverage": [
            {"t": "bool", "v": True},
            {"t": "bool", "v": False},
        ]
    }
    assert result["udfs_invoked"] == ["relay.coverage"], result["udfs_invoked"]


@pytest.mark.plumbing
def test_pipeline_emits_typed_canonical_not_raw() -> None:
    """The pipeline emits TYPED-CANONICAL udf_outputs_jcs (the single
    contract), never the raw-object form whose digest diverged
    pre-unification (``{"relay.coverage":[true,false]}``)."""
    result = _run_pipeline_subprocess()
    raw_form = jcs_canonicalize(
        {RELAY_COVERAGE_NAME: [True, False]}
    ).decode("utf-8")
    assert result["udf_outputs_jcs"] != raw_form, (
        "pipeline emitted the RAW-object encoding the typed-canonical "
        "unification eliminated"
    )
    decoded = json.loads(result["udf_outputs_jcs"])  # type: ignore[arg-type]
    for entry in decoded[RELAY_COVERAGE_NAME]:
        assert set(entry.keys()) == {"t", "v"}, entry
        assert entry["t"] == "bool", entry
