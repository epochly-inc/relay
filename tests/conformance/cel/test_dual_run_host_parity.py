"""VAL-CWC-P4DUALRUN-004: dual-run host-integration parity (celpy vs wasm).

This is the M5-flip de-risk gate. It asserts ZERO celpy-vs-wasm divergence on
the cel-js-reachable, flat-schema subset of the main Relay-CEL corpus
(``tests/conformance/cel/relay_cel_corpus.json``): for EVERY reachable case it
evaluates the contract through the REAL host evaluate path -- the
``packages/contracts`` factory ``make_cel_evaluator`` driven by
``relay_contracts.pipeline.evaluate_assertion`` -- once under
``RELAY_CEL_ENGINE=celpy`` and again under ``RELAY_CEL_ENGINE=wasm``, and
asserts IDENTICAL verdict (the pipeline outcome) AND IDENTICAL
``udf_outputs_jcs`` / canonical bytes. Any divergence fails with a structured
diff naming the exact case and both verdicts/bytes.

How both engines are driven via the factory (the REAL host path)
----------------------------------------------------------------
Engine selection is read ONLY in the contracts factory (``engine.py``), and
the factory reads ``RELAY_CEL_ENGINE`` at construction time (no import-time
caching). To drive the SAME corpus case through both engines via the genuine
host path -- not a hand-rolled re-implementation -- this test spawns one
Python subprocess per engine with ``RELAY_CEL_ENGINE`` set in that process's
environment, and inside each subprocess calls ``parse_contract`` +
``evaluate_assertion`` (the production pipeline). Subprocess isolation is the
faithful and robust choice: the wasm evaluator keeps a per-thread wasmtime
``Store`` (VAL-CWC-P1HOST-008), and one clean process per engine matches how
the CI engine-axis matrix (VAL-CWC-P4DUALRUN-001) exports the selector.

The reachable subset (the cel-js-reachable flat-schema cases)
-------------------------------------------------------------
A corpus case is "reachable" for this dual-run iff BOTH engines can evaluate
it through CEL:

  - it carries a CEL ``expression`` string (the ``eval_value`` and
    ``eval_error`` kinds -- NOT the ``udf_value`` kind, which is a direct
    Python-callable invocation with no CEL expression and is therefore not
    driven THROUGH CEL by either engine), AND
  - its expression does NOT reference a dotted ``relay.*`` UDF. cel-python's
    CEL CANNOT drive a dotted ``relay.*`` call (parsed as a member-method with
    no matching overload) -- the provably-unbounded two-engine gap this
    cutover exists to eliminate (cf. the known-failing ``test_w17_4_*`` and
    VAL-CWC-P1HOST-015). Including such a case would compare a celpy error
    path against a wasm success path -- not a parity claim. Full dotted-CEL
    Py-vs-wasm ``udf_outputs_jcs`` byte-parity is delivered BY CONSTRUCTION at
    M3/M4 once both hosts run the SAME wasm (VAL-CWC-P3CORPUS-* /
    VAL-CWC-P4DUALRUN-005, the cross-host driver).

The main Relay-CEL corpus is flat-schema by construction (no ``engines`` fence
field; that fence lives only on the separate UDF-via-CEL corpus). The reachable
predicate above selects exactly the plain-CEL cases both engines accept.

Binding form
------------
Bindings are converted to cel-python ``celtypes`` -- the canonical host binding
form the W6.5 corpus runner uses (``packages/contracts/tests/test_w6_5_corpus.py``
``_convert_bindings``) and the form the corpus ``py_jcs_b64`` goldens were
recorded with. Both engines accept this form: the celpy evaluator consumes
celtypes directly; the wasm path round-trips them via ``py_to_typed``
(bool-before-int, VAL-CWC-P1HOST-001). Feeding raw Python ``bool``/``dict``
instead would error ONLY on the celpy side -- a harness artifact, not an engine
divergence -- so the canonical celtypes form is used to make the parity claim
unambiguous.

Verdict + bytes compared, and the re-homed runtime-error taxonomy item
----------------------------------------------------------------------
The compared signature is the pipeline outcome envelope's engine-agnostic
fields: ``outcome`` (the verdict: ``pass`` / ``fail`` / ``error``),
``udfs_invoked``, and ``udf_outputs_jcs`` (the canonical bytes). The pipeline
envelope carries NO engine-specific ``error_code``, so this test is inherently
unaffected by the separately-tracked, re-homed cross-engine RUNTIME-ERROR
``error_code`` taxonomy difference (celpy host-code vs wasm RELAY-CEL-009 for an
expression that ERRORS at runtime, e.g. ``1/0``). That difference is a
documented engine-taxonomy item owned by a sibling fix feature, NOT a
verdict-parity defect; it does not gate the M5 flip. The reachable subset here
contains no division-by-zero / runtime-error case anyway -- its 17 ``eval_error``
cases are host-guard rejections (profile / regex-backref / numeric-OOB) that
BOTH engines map to ``outcome == "error"`` with an empty ``udf_outputs_jcs``.

A real divergence on a VALID expression here would be a P0 that BLOCKS the M5
flip; this test must NOT be weakened to go green.

Tool: pytest (plumbing tier). ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"

# The two engine tokens the contracts factory (engine.py) accepts. The dual-run
# drives the SAME reachable cases through BOTH, asserting zero divergence.
_ENGINES: tuple[str, ...] = ("celpy", "wasm")

# Subprocess worker: reads {"cases":[{id, expression, bindings}, ...]} on stdin,
# drives EACH case through the production host path
# (parse_contract + evaluate_assertion) under whatever RELAY_CEL_ENGINE the
# parent set in this process's environment, and emits one outcome record per
# case on stdout. Bindings are converted to celtypes (the canonical host
# binding form) before evaluation. Engine selection is NOT read here -- it is
# read solely inside make_cel_evaluator (engine.py), reached transitively via
# evaluate_assertion; this worker only sets the env in the PARENT.
_HOST_WORKER = r"""
import json
import sys

import celpy.celtypes as celtypes

from relay_contracts.dsl_parser import parse_contract
from relay_contracts.pipeline import evaluate_assertion


def _to_celtype(value):
    # bool MUST be classified before int (bool is a subclass of int), matching
    # the host's py_to_typed bool-before-int rule (VAL-CWC-P1HOST-001) and the
    # W6.5 corpus runner's _convert_bindings.
    if isinstance(value, bool):
        return celtypes.BoolType(value)
    if isinstance(value, int):
        return celtypes.IntType(value)
    if isinstance(value, float):
        return celtypes.DoubleType(value)
    if isinstance(value, str):
        return celtypes.StringType(value)
    if isinstance(value, (list, tuple)):
        return celtypes.ListType([_to_celtype(v) for v in value])
    if isinstance(value, dict):
        return celtypes.MapType(
            {celtypes.StringType(k): _to_celtype(v) for k, v in value.items()}
        )
    return value


payload = json.loads(sys.stdin.read())
records = []
for case in payload["cases"]:
    doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-CWC-P4DUALRUN-004-" + case["id"],
        "kind": "behavioral",
        "expression": case["expression"],
        "severity": "p0",
        "owner_email": "dual-run@relay.test",
        "lifecycle_state": "active",
    }
    parsed = parse_contract(doc)
    bindings = {
        k: _to_celtype(v) for k, v in (case.get("bindings") or {}).items()
    }
    try:
        envelope = evaluate_assertion(parsed, bindings=bindings, extra_udfs=())
        records.append(
            {
                "id": case["id"],
                "ok": True,
                "outcome": envelope["outcome"],
                "udfs_invoked": envelope["udfs_invoked"],
                "udf_outputs_jcs": envelope["udf_outputs_jcs"],
            }
        )
    except Exception as exc:  # noqa: BLE001 -- want exhaustive per-case diagnostics
        records.append(
            {
                "id": case["id"],
                "ok": False,
                "error": type(exc).__name__ + ": " + str(exc),
            }
        )
print(json.dumps({"records": records}))
"""


def _load_corpus_cases() -> list[dict[str, Any]]:
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = data["cases"]
    assert isinstance(cases, list)
    return cases


def _is_reachable(case: dict[str, Any]) -> bool:
    """A corpus case is reachable for the celpy-vs-wasm dual-run iff BOTH
    engines can drive it THROUGH CEL: it has a CEL ``expression`` string and
    does NOT reference a dotted ``relay.*`` UDF (cel-python cannot drive a
    dotted relay.* call through CEL -- the provably-unbounded gap)."""
    expression = case.get("expression")
    if not isinstance(expression, str) or expression == "":
        # udf_value kind (direct callable, no CEL expression) is excluded.
        return False
    # Exclude dotted relay.* UDF expressions: cel-python cannot drive them
    # through CEL, so they are not reachable by BOTH engines.
    return "relay." not in expression


def _reachable_subset() -> list[dict[str, Any]]:
    return [c for c in _load_corpus_cases() if _is_reachable(c)]


def _comparable(record: dict[str, Any]) -> dict[str, Any]:
    """The engine-agnostic parity signature: the verdict (outcome), the
    invoked UDFs, the canonical udf_outputs_jcs bytes, and the ok-status.

    Deliberately excludes ``wall_time_ms`` (timing, non-deterministic) and any
    engine-specific error_code -- the pipeline envelope carries none, so the
    separately-tracked runtime-error error_code taxonomy difference cannot
    perturb this comparison."""
    return {
        "ok": record.get("ok"),
        "outcome": record.get("outcome"),
        "udfs_invoked": record.get("udfs_invoked"),
        "udf_outputs_jcs": record.get("udf_outputs_jcs"),
        "error": record.get("error"),
    }


def _run_host_under_engine(
    engine: str, cases: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Spawn a Python subprocess with ``RELAY_CEL_ENGINE=<engine>`` that drives
    every case through the production host path (parse_contract +
    evaluate_assertion). Returns ``{case_id: record}``."""
    env = dict(os.environ)
    env["RELAY_CEL_ENGINE"] = engine
    payload = json.dumps(
        {
            "cases": [
                {
                    "id": c["id"],
                    "expression": c["expression"],
                    "bindings": c.get("bindings") or {},
                }
                for c in cases
            ]
        }
    )
    proc = subprocess.run(
        [sys.executable, "-c", _HOST_WORKER],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: host worker under RELAY_CEL_ENGINE={engine!r} "
            f"exited {proc.returncode} (the engine could not drive the reachable "
            f"subset through the production pipeline):\n"
            f"  stderr: {proc.stderr[-3000:]}\n"
            f"  stdout: {proc.stdout[-1500:]}"
        )
    try:
        records = json.loads(proc.stdout.strip().splitlines()[-1])["records"]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: host worker under "
            f"RELAY_CEL_ENGINE={engine!r} produced unparseable output: {exc}\n"
            f"  stdout: {proc.stdout[-2000:]}"
        )
    return {rec["id"]: rec for rec in records}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-004")
def test_dual_run_host_parity_reachable_subset_is_non_empty() -> None:
    """Guard: the cel-js-reachable flat-schema subset MUST be non-empty, so the
    dual-run parity assertion below is non-vacuous (the contract requires the
    reachable-subset case count > 0)."""
    subset = _reachable_subset()
    assert len(subset) > 0, (
        "VAL-CWC-P4DUALRUN-004: reachable subset is EMPTY; the dual-run host "
        f"parity test would be vacuous. Corpus: {CORPUS_PATH}"
    )
    # No reachable case may reference a dotted relay.* UDF (cel-python cannot
    # drive those through CEL); the subset must be plain CEL only.
    bad = [c["id"] for c in subset if "relay." in c["expression"]]
    assert bad == [], (
        "VAL-CWC-P4DUALRUN-004: reachable subset must contain only plain-CEL "
        f"cases (no dotted relay.* UDFs); offenders: {bad}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-004")
def test_dual_run_host_parity_celpy_vs_wasm_zero_divergence() -> None:
    """For EVERY cel-js-reachable flat-schema case: the production host path
    (parse_contract + evaluate_assertion via the make_cel_evaluator factory)
    MUST produce the IDENTICAL verdict AND IDENTICAL udf_outputs_jcs / canonical
    bytes under RELAY_CEL_ENGINE=celpy and under RELAY_CEL_ENGINE=wasm. Any
    divergence on a valid expression is a P0 that blocks the M5 flip and fails
    here with a structured diff -- this test must NOT be weakened to pass."""
    subset = _reachable_subset()
    assert len(subset) > 0, "reachable subset must be non-empty (see guard test)"

    results: dict[str, dict[str, dict[str, Any]]] = {}
    for engine in _ENGINES:
        results[engine] = _run_host_under_engine(engine, subset)

    celpy_results = results["celpy"]
    wasm_results = results["wasm"]

    # Every reachable case must appear in BOTH engine result maps (a missing
    # case is itself a divergence -- one engine silently dropped a case).
    subset_ids = [c["id"] for c in subset]
    missing_celpy = [cid for cid in subset_ids if cid not in celpy_results]
    missing_wasm = [cid for cid in subset_ids if cid not in wasm_results]
    assert missing_celpy == [] and missing_wasm == [], (
        "VAL-CWC-P4DUALRUN-004: host worker dropped reachable cases "
        f"(celpy missing={missing_celpy}, wasm missing={missing_wasm})."
    )

    divergences: list[dict[str, Any]] = []
    for cid in subset_ids:
        celpy_cmp = _comparable(celpy_results[cid])
        wasm_cmp = _comparable(wasm_results[cid])
        if celpy_cmp != wasm_cmp:
            divergences.append(
                {
                    "case_id": cid,
                    "expression": next(
                        c["expression"] for c in subset if c["id"] == cid
                    ),
                    "celpy": celpy_cmp,
                    "wasm": wasm_cmp,
                }
            )

    if divergences:
        for diff in divergences:
            print(
                "[dual-run-host-parity-diff]",
                json.dumps(diff, sort_keys=True),
            )
        rendered = "\n".join(
            json.dumps(diff, sort_keys=True, indent=2) for diff in divergences
        )
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: {len(divergences)} celpy-vs-wasm host "
            f"parity divergence(s) on the reachable subset of "
            f"{len(subset_ids)} cases. A divergence on a VALID expression is a "
            f"P0 that BLOCKS the M5 flip; do NOT weaken this test. Full diff "
            f"(no counts elided):\n{rendered}"
        )

    # Reaching here means zero divergence across the whole reachable subset.
    # Print the satisfied de-risk summary so the evidence shows the case count.
    print(
        "[dual-run-host-parity] PASS: "
        f"{len(subset_ids)} reachable cases, zero celpy-vs-wasm divergences."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-004")
def test_dual_run_host_parity_comparator_detects_divergence() -> None:
    """Negative-control: the comparator MUST flag a verdict difference, so the
    zero-divergence result above is a real assertion (not a vacuous one that
    would pass even if the engines disagreed)."""
    same = _comparable(
        {"ok": True, "outcome": "pass", "udfs_invoked": [], "udf_outputs_jcs": "{}"}
    )
    differ_verdict = _comparable(
        {"ok": True, "outcome": "fail", "udfs_invoked": [], "udf_outputs_jcs": "{}"}
    )
    differ_bytes = _comparable(
        {
            "ok": True,
            "outcome": "pass",
            "udfs_invoked": [],
            "udf_outputs_jcs": '{"x":1}',
        }
    )
    assert same != differ_verdict, "comparator must detect a verdict divergence"
    assert same != differ_bytes, (
        "comparator must detect a udf_outputs_jcs byte divergence"
    )
    # Identical signatures must compare equal (no spurious divergence).
    same_again = _comparable(
        {"ok": True, "outcome": "pass", "udfs_invoked": [], "udf_outputs_jcs": "{}"}
    )
    assert same == same_again
