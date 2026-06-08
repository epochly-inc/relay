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

Verdict + bytes compared -- and the runtime-error error_code taxonomy note
--------------------------------------------------------------------------
The compared signature is the pipeline outcome envelope's engine-agnostic
fields: ``outcome`` (the verdict: ``pass`` / ``fail`` / ``error``),
``udfs_invoked``, and ``udf_outputs_jcs`` (the canonical bytes). The pipeline
envelope carries NO engine-specific ``error_code``, so this test is structurally
immune to the cross-engine RUNTIME-ERROR ``error_code`` taxonomy difference.

RUNTIME-ERROR error_code taxonomy (documented disposition, NOT a defect):
--------------------------------------------------------------------------
For a CEL expression that ERRORS AT RUNTIME (e.g. ``1/0``), the two engines in
the M4 dual-run period classify the failure under DIFFERENT error codes: the
cel-python host raises under its own host error code, while the wasm engine maps
the same failure to ``RELAY-CEL-009`` (``RelayCelEngineError``) per the WS-A
engine-error taxonomy (VAL-CWC-P1HOST-007). This is NOT a verdict-parity defect:
both engines produce ``outcome == "error"`` (the same verdict); only the
engine-specific error_code inside the host exception differs. Because the
pipeline outcome envelope carries no engine-specific error_code field, the
divergence is invisible to this parity test by construction.

This difference is ELIMINATED BY CONSTRUCTION at M6 when cel-python is removed
and the wasm engine (RELAY-CEL-009) is the only evaluator. During the M5 bake
window, gate decision payloads for RUNTIME-ERRORING conditions will carry
``RELAY-CEL-009`` as the error code (the wasm default). This is expected and
documented behavior for the bake -- NOT a regression. See the M5 flip section of
``packages/cel-wasm/README.md`` for the full runtime-error policy note.

The reachable subset in this test contains no division-by-zero / runtime-error
cases: its 17 ``eval_error`` cases are host-guard rejections (profile /
regex-backref / numeric-OOB) that BOTH engines map to ``outcome == "error"``
with an empty ``udf_outputs_jcs``.

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


# Subprocess worker for the VALUE comparison (FINDING-1 strengthening). The
# pipeline outcome envelope's ``_classify_outcome`` collapses ANY non-boolean
# evaluation result to ``outcome == "error"`` and an empty ``udf_outputs_jcs``
# (pipeline.py:191-207), so the ~178 arithmetic / string / list / map
# ``eval_value`` cases ALL collapse to the SAME envelope on both engines and
# would compare VACUOUSLY -- a real celpy-vs-wasm VALUE divergence (one engine
# returns 5, the other 6 for "1 + 2") would pass UNDETECTED. This worker
# evaluates the EXPRESSION DIRECTLY through each engine's evaluator
# (``make_cel_evaluator(udfs=()).evaluate(...)`` -- the RelayCelEvaluator on
# celpy, the WasmCelEvaluator on wasm, selected by RELAY_CEL_ENGINE in the
# PARENT) and emits the typed-canonical JCS bytes of the RAW result, so the
# actual computed value is compared byte-for-byte. The single canonical codec
# ``py_to_typed`` (the SAME codec that makes the two engines' udf_outputs_jcs
# byte-identical, VAL-CWC-P1HOST-001/015) normalizes celpy ``celtypes`` results
# and wasm plain-Python results into the identical ``{"t":...,"v":...}`` form,
# then ``jcs_canonicalize`` produces the comparable bytes. A raised evaluation
# (the host-guard ``eval_error`` cases) is recorded as ``raised=True`` with the
# error CLASS name only -- the engine-specific error_code taxonomy difference
# (host code vs RELAY-CEL-009, documented disposition) is deliberately NOT
# compared; the meaningful parity is "both raised" + identical value bytes when
# not raised.
_VALUE_WORKER = r"""
import base64
import json
import sys

import celpy.celtypes as celtypes

from relay_contracts.canonical import jcs_canonicalize
from relay_contracts.engine import make_cel_evaluator
from relay_contracts.wasm_codec import py_to_typed


def _to_celtype(value):
    # bool BEFORE int (bool is an int subclass) -- the canonical host binding
    # form (W6.5 _convert_bindings / py_to_typed bool-before-int rule,
    # VAL-CWC-P1HOST-001). Raw dicts/bools cause spurious celpy "no matching
    # overload" divergences, so bindings are converted to celtypes for both
    # engines (the wasm path round-trips celtypes via py_to_typed unchanged).
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
# One evaluator per process (RELAY_CEL_ENGINE in the env selects the engine via
# the factory -- the ONLY read site). udfs=() so no relay.* UDF is registered;
# the reachable subset is plain-CEL only.
evaluator = make_cel_evaluator(udfs=())
records = []
for case in payload["cases"]:
    bindings = {
        k: _to_celtype(v) for k, v in (case.get("bindings") or {}).items()
    }
    try:
        raw = evaluator.evaluate(case["expression"], bindings)
    except Exception as exc:  # noqa: BLE001 -- exhaustive per-case diagnostics
        records.append(
            {
                "id": case["id"],
                "raised": True,
                # CLASS name only; the engine-specific error CODE taxonomy
                # difference (host vs RELAY-CEL-009) is NOT part of the parity
                # claim (documented disposition).
                "error_class": type(exc).__name__,
            }
        )
        continue
    # py_to_typed is the SINGLE canonical Python<->wasm codec: it maps the
    # celpy celtypes result AND the wasm plain-Python result into the IDENTICAL
    # typed-canonical {"t","v"} form, so JCS bytes are byte-identical for the
    # same logical value across engines.
    typed = py_to_typed(raw)
    value_jcs_b64 = base64.b64encode(jcs_canonicalize(typed)).decode("ascii")
    records.append(
        {
            "id": case["id"],
            "raised": False,
            "value_jcs_b64": value_jcs_b64,
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


def _run_worker_under_engine(
    engine: str, cases: list[dict[str, Any]], worker_src: str, what: str
) -> dict[str, dict[str, Any]]:
    """Spawn a Python subprocess with ``RELAY_CEL_ENGINE=<engine>`` running
    ``worker_src`` over ``cases``. ``what`` names the path for diagnostics.
    Returns ``{case_id: record}``."""
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
        [sys.executable, "-c", worker_src],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: {what} worker under "
            f"RELAY_CEL_ENGINE={engine!r} exited {proc.returncode} (the engine "
            f"could not drive the reachable subset):\n"
            f"  stderr: {proc.stderr[-3000:]}\n"
            f"  stdout: {proc.stdout[-1500:]}"
        )
    try:
        records = json.loads(proc.stdout.strip().splitlines()[-1])["records"]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: {what} worker under "
            f"RELAY_CEL_ENGINE={engine!r} produced unparseable output: {exc}\n"
            f"  stdout: {proc.stdout[-2000:]}"
        )
    return {rec["id"]: rec for rec in records}


def _run_host_under_engine(
    engine: str, cases: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Spawn a Python subprocess with ``RELAY_CEL_ENGINE=<engine>`` that drives
    every case through the production host path (parse_contract +
    evaluate_assertion). Returns ``{case_id: record}``."""
    return _run_worker_under_engine(engine, cases, _HOST_WORKER, "host")


def _run_value_under_engine(
    engine: str, cases: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Spawn a Python subprocess with ``RELAY_CEL_ENGINE=<engine>`` that
    evaluates each EXPRESSION directly through ``make_cel_evaluator().evaluate``
    and returns the typed-canonical JCS bytes of the RAW result (FINDING-1: the
    actual VALUE, not the _classify_outcome-collapsed verdict). Returns
    ``{case_id: record}``."""
    return _run_worker_under_engine(engine, cases, _VALUE_WORKER, "value")


def _value_comparable(record: dict[str, Any]) -> dict[str, Any]:
    """The engine-agnostic RAW-VALUE parity signature: whether evaluation
    raised, and the typed-canonical JCS bytes of the result when it did NOT.

    Deliberately EXCLUDES the error CLASS / code -- the runtime-error /
    host-guard error_code taxonomy differs by design (host code vs
    RELAY-CEL-009, documented disposition). The meaningful VALUE parity is:
    both engines either raised OR returned the byte-identical typed-canonical
    result. Comparing the value bytes is what makes the ~178 non-boolean
    eval_value cases NON-vacuous (vs the collapsed-to-error verdict)."""
    return {
        "raised": record.get("raised"),
        "value_jcs_b64": record.get("value_jcs_b64"),
    }


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
def test_dual_run_value_parity_celpy_vs_wasm_zero_divergence() -> None:
    """FINDING-1 fix: ACTUALLY compare the computed VALUE celpy-vs-wasm.

    The verdict-level test above compares the pipeline outcome envelope, whose
    ``_classify_outcome`` (pipeline.py:191-207) collapses ANY non-boolean
    result to ``outcome == "error"`` + empty ``udf_outputs_jcs``. So the ~178
    non-boolean ``eval_value`` arithmetic / string / list / map cases ALL
    collapse to the SAME envelope on both engines and are compared VACUOUSLY --
    a real value divergence (one engine returns 5, the other 6 for ``1 + 2``)
    would pass UNDETECTED there.

    This test evaluates the EXPRESSION DIRECTLY through each engine's evaluator
    (``make_cel_evaluator(udfs=()).evaluate`` -- RelayCelEvaluator on celpy,
    WasmCelEvaluator on wasm, selected by RELAY_CEL_ENGINE) and compares the
    typed-canonical (``py_to_typed``) JCS bytes of the RAW result. For the
    non-boolean cases this is the ONLY non-vacuous parity check. A divergence on
    a VALID expression is a P0 that BLOCKS the M5 flip; this test must NOT be
    weakened to pass."""
    subset = _reachable_subset()
    assert len(subset) > 0, "reachable subset must be non-empty (see guard test)"

    results: dict[str, dict[str, dict[str, Any]]] = {}
    for engine in _ENGINES:
        results[engine] = _run_value_under_engine(engine, subset)

    celpy_results = results["celpy"]
    wasm_results = results["wasm"]

    subset_ids = [c["id"] for c in subset]
    missing_celpy = [cid for cid in subset_ids if cid not in celpy_results]
    missing_wasm = [cid for cid in subset_ids if cid not in wasm_results]
    assert missing_celpy == [] and missing_wasm == [], (
        "VAL-CWC-P4DUALRUN-004: value worker dropped reachable cases "
        f"(celpy missing={missing_celpy}, wasm missing={missing_wasm})."
    )

    # Count the cases where BOTH engines returned a NON-RAISED value AND that
    # value is a non-empty-map / actual computed value -- these are the cases
    # the verdict-level test compares vacuously, and that this test compares for
    # real. This is the "value-compared" count the contract requires to be > 0.
    value_compared = 0
    divergences: list[dict[str, Any]] = []
    for cid in subset_ids:
        celpy_cmp = _value_comparable(celpy_results[cid])
        wasm_cmp = _value_comparable(wasm_results[cid])
        # A case is "value-compared" (non-vacuous) when both engines returned a
        # concrete value (raised == False) -- the actual computed bytes are then
        # compared. The host-guard eval_error cases (raised == True on both) are
        # status-compared, not value-compared.
        if celpy_cmp.get("raised") is False and wasm_cmp.get("raised") is False:
            value_compared += 1
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
                "[dual-run-value-parity-diff]",
                json.dumps(diff, sort_keys=True),
            )
        rendered = "\n".join(
            json.dumps(diff, sort_keys=True, indent=2) for diff in divergences
        )
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-004: {len(divergences)} celpy-vs-wasm VALUE "
            f"parity divergence(s) on the reachable subset of "
            f"{len(subset_ids)} cases ({value_compared} value-compared). A VALUE "
            f"divergence on a VALID expression is a P0 that BLOCKS the M5 flip; "
            f"do NOT weaken this test. Full diff (no counts elided):\n{rendered}"
        )

    # The value comparison is only non-vacuous if it actually compared concrete
    # VALUES for the non-boolean cases. Require the value-compared count > 0 so a
    # future refactor that accidentally collapses every case to raised/error is
    # caught (this is the exact failure mode FINDING-1 reported in the verdict
    # test).
    assert value_compared > 0, (
        "VAL-CWC-P4DUALRUN-004: the dual-run VALUE comparison compared ZERO "
        "concrete values (every reachable case raised on both engines). The "
        "value parity assertion would be vacuous -- this is the FINDING-1 "
        f"collapse failure mode. subset size={len(subset_ids)}."
    )

    print(
        "[dual-run-value-parity] PASS: "
        f"{len(subset_ids)} reachable cases, {value_compared} value-compared, "
        "zero celpy-vs-wasm VALUE divergences."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-004")
def test_dual_run_value_comparator_detects_value_divergence() -> None:
    """Negative-control for the VALUE comparator: it MUST flag a difference in
    the raw-result bytes (so the zero-VALUE-divergence result above is a real
    assertion, not a vacuous one that would pass if the engines computed
    different values)."""
    five = _value_comparable({"raised": False, "value_jcs_b64": "FIVE"})
    six = _value_comparable({"raised": False, "value_jcs_b64": "SIX"})
    raised = _value_comparable({"raised": True, "error_class": "RelayCelProfileError"})
    assert five != six, "value comparator must detect a raw-value byte divergence"
    assert five != raised, (
        "value comparator must detect a raised-vs-returned divergence"
    )
    # Identical raw-value signatures compare equal (no spurious divergence); the
    # error CLASS is excluded so the taxonomy difference does not perturb it.
    raised_other = _value_comparable(
        {"raised": True, "error_class": "RelayCelEngineError"}
    )
    assert raised == raised_other, (
        "value comparator must EXCLUDE the error class/code (taxonomy "
        "difference is a documented disposition, not a value divergence)"
    )
    five_again = _value_comparable({"raised": False, "value_jcs_b64": "FIVE"})
    assert five == five_again


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
