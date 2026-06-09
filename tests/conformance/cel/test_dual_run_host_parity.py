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

KNOWN cel-python backslash-escape lexer non-conformance (adjudicated carve-out)
------------------------------------------------------------------------------
The strengthened VALUE comparison (``test_dual_run_value_parity_*``) is RED on
EXACTLY TWO reachable corpus cases -- ``regex_backslash_fullwidth_digit_accepted``
(the CEL string literal ``"\\<U+FF10>"``) and ``regex_backslash_arabic_digit_accepted``
(``"\\<U+0660>"``). For both, cel-python's LENIENT lexer returns the literal
2-character string, while the wasm (cel-rust) engine correctly RAISES a compile
error (RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE, "token recognition error").

Per the CEL spec (langdef.md:115 and 318-320), a backslash that does NOT begin a
recognized escape sequence is a LEXICAL ERROR -- so the wasm is SPEC-CORRECT and
cel-python is NON-CONFORMANT. This was user-adjudicated: wasm is correct, the
corpus golden recorded cel-python's wrong (lenient) behavior. These two cases are
carved out of the STRICT value comparison via the module-level
``KNOWN_CELPY_NONCONFORMANCE`` set, under a STRONG guard -- the carve-out set is
asserted EXACTLY equal to those two labels, each is asserted to STILL diverge in
the expected direction (celpy returns / wasm raises), and EVERY OTHER reachable
case must still compare byte-for-byte. A new value divergence on any other case
still fails the test; a future cel-python fix or corpus change that makes a
carved-out case converge fails the stale-carve-out guard.

The M5 default flip IMPROVES these two expressions from cel-python's lenient
string to the spec-correct compile error -- a CORRECTNESS IMPROVEMENT documented
for the M5 bake (see the M5 P5FLIP section of ``packages/cel-wasm/README.md``).
At M6 (cel-python removal) the divergence is eliminated BY CONSTRUCTION; the two
corpus cases should then be reclassified ``eval_value`` -> ``eval_error`` (see
the M6 migration note in that README section). The corpus is NOT mutated here:
the legacy ``test_w17_4_*`` cross-runtime / release-block runners still expect
cel-python's current lenient behavior, so reclassification is M6 scope.

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

# ---------------------------------------------------------------------------
# KNOWN cel-python lexer non-conformance (adjudicated; wasm is SPEC-CORRECT)
# ---------------------------------------------------------------------------
# These EXACTLY-TWO corpus cases are a documented, user-adjudicated divergence
# where cel-python is NON-CONFORMANT and the wasm (cel-rust) engine is
# SPEC-CORRECT. Each expression is a double-quoted CEL string literal whose only
# content is a single backslash followed by a non-ASCII digit that is NOT a
# valid CEL escape sequence:
#
#   regex_backslash_fullwidth_digit_accepted -> "\<U+FF10>"  (backslash + FULLWIDTH DIGIT ZERO)
#   regex_backslash_arabic_digit_accepted    -> "\<U+0660>"  (backslash + ARABIC-INDIC DIGIT ZERO)
#
# Per the CEL spec (langdef.md:115 and 318-320), a backslash that does NOT begin
# a recognized escape sequence is a LEXICAL ERROR. The wasm engine correctly
# RAISES a compile error (RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE,
# "token recognition error"); cel-python has a LENIENT lexer that instead
# returns the literal 2-character string. The wasm behavior is the spec-correct
# one. The corpus golden recorded cel-python's wrong (lenient) result.
#
# DISPOSITION (adjudicated -- do NOT re-litigate, do NOT "fix" the wasm, do NOT
# patch cel-python here): these two cases are carved out of the STRICT
# celpy-vs-wasm VALUE comparison below. The carve-out is GUARDED -- the test
# asserts (a) the carve-out set is EXACTLY these two labels, (b) these two cases
# STILL diverge celpy-vs-wasm (so a future cel-python fix or corpus change that
# makes them converge flags this carve-out as stale), and (c) NO OTHER reachable
# case diverges. So the guard stays strong: any NEW value divergence still fails.
#
# At the M5 default flip these two expressions IMPROVE from cel-python's lenient
# 2-char string to the spec-correct compile error -- a CORRECTNESS IMPROVEMENT
# documented for the M5 bake (see packages/cel-wasm/README.md M5 P5FLIP section).
# At M6 (cel-python removal) the divergence is eliminated BY CONSTRUCTION, and
# these two corpus cases should be reclassified eval_value -> eval_error (see the
# M6 migration note in that README section). The corpus is NOT mutated here: the
# legacy w17 cross-runtime / release-block runners still expect cel-python's
# current lenient behavior, so reclassification is deferred to M6 scope.
KNOWN_CELPY_NONCONFORMANCE: frozenset[str] = frozenset(
    {
        "regex_backslash_fullwidth_digit_accepted",
        "regex_backslash_arabic_digit_accepted",
    }
)

# The EXACT corpus expression each carved-out case MUST carry. Pinning the
# expression here (asserted equal to the live relay_cel_corpus.json value before
# the case is excluded) means a future corpus edit that changes one of these
# expressions to something OTHER than the adjudicated backslash + non-ASCII-digit
# string literal can no longer be silently absorbed by the carve-out -- the
# carve-out is legitimate ONLY for these precise two expressions. The values are
# a double-quoted CEL string literal: a single backslash followed by FULLWIDTH
# DIGIT ZERO (U+FF10) / ARABIC-INDIC DIGIT ZERO (U+0660). Written with explicit
# backslash-u escapes so this source stays pure ASCII (CLAUDE.md "ASCII-Safe Source").
KNOWN_CELPY_NONCONFORMANCE_EXPRESSIONS: dict[str, str] = {
    # Each value is '"' + '\\' (one literal backslash) + the non-ASCII digit +
    # '"', built with backslash-u escapes so this source is pure ASCII.
    "regex_backslash_fullwidth_digit_accepted": '"\\\uff10"',
    "regex_backslash_arabic_digit_accepted": '"\\\u0660"',
}

# The wasm engine's DOCUMENTED error for these expressions: the cel-rust lexer
# correctly RAISES a compile error (a backslash that does not begin a recognized
# escape is a LEXICAL ERROR per the CEL spec). The host wasm-backed evaluator
# maps that to RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE (errors.py:201-225,
# _WASM_CODE_TO_ENGINE_SUBTYPE["RELAY-CEL-001"] = SUBTYPE_ENGINE_COMPILE), and
# the engine's own RELAY-CEL-001 compile code plus the "token recognition error"
# lexer diagnostic are preserved in the message. The carve-out asserts ALL of
# these so a wasm regression that raises a DIFFERENT error (a panic, an exec
# failure, a profile rejection, or a bare non-Relay exception) is NOT silently
# absorbed -- it falls through as a normal divergence and fails the test.
_EXPECTED_WASM_CARVEOUT_ERROR_CLASS = "RelayCelEngineError"
_EXPECTED_WASM_CARVEOUT_ERROR_CODE = "RELAY-CEL-009"
_EXPECTED_WASM_CARVEOUT_ERROR_SUBTYPE = "RELAY-CEL-ENGINE-COMPILE"
# Substrings the documented compile-error message MUST contain (the engine's own
# RELAY-CEL-001 code, and the cel-rust lexer's "token recognition error" text).
_EXPECTED_WASM_CARVEOUT_MESSAGE_SUBSTRINGS = (
    "[RELAY-CEL-001]",
    "token recognition error",
)

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
        # The error CLASS name is recorded for diagnostics. The engine-specific
        # error CODE / SUBTYPE / message are ALSO recorded (when the exception is
        # a structured RelayCelError) -- NOT to feed the parity signature (the
        # host-vs-RELAY-CEL-009 taxonomy difference is a documented disposition,
        # excluded from _value_comparable), but so the carve-out guard can PIN
        # the wasm error to the documented backslash-lexer compile error rather
        # than tolerating ANY raise. Bare (non-Relay) exceptions carry no
        # code/subtype, so those fields stay None and the carve-out guard's
        # exact-match assertion will REJECT them (fall through to a divergence).
        code = getattr(exc, "code", None)
        subtype = getattr(exc, "subtype", None)
        records.append(
            {
                "id": case["id"],
                "raised": True,
                "error_class": type(exc).__name__,
                "error_code": code if isinstance(code, str) else None,
                "error_subtype": subtype if isinstance(subtype, str) else None,
                "error_message": str(exc),
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


def _carveout_rejection_reason(
    cid: str,
    case_expr: str,
    celpy_record: dict[str, Any],
    wasm_record: dict[str, Any],
) -> str | None:
    """Decide whether a divergent case legitimately matches the documented
    cel-python backslash-lexer carve-out (FINDING B). Returns ``None`` when the
    case IS the documented divergence (so it may be carved out), otherwise a
    human-readable REASON string explaining why it does NOT qualify (so the
    caller routes it to the normal-divergence failure path).

    The carve-out is legitimate ONLY when ALL of these hold:
      1. the corpus expression is EXACTLY the pinned adjudicated literal for
         this id (KNOWN_CELPY_NONCONFORMANCE_EXPRESSIONS) -- a corpus drift to a
         different expression is NOT covered;
      2. cel-python RETURNED a value (raised is False) -- the lenient path;
      3. the wasm RAISED (raised is True);
      4. the wasm error is the documented RelayCelEngineError / RELAY-CEL-009 /
         RELAY-CEL-ENGINE-COMPILE carrying the engine's own ``[RELAY-CEL-001]``
         code and the cel-rust ``token recognition error`` lexer diagnostic.

    Any other wasm error (a panic, an exec failure, a profile rejection, or a
    bare non-Relay exception that carries no code/subtype) is REJECTED so a wasm
    regression that raises for a DIFFERENT reason is surfaced as a divergence,
    never silently absorbed by the carve-out.
    """
    expected_expr = KNOWN_CELPY_NONCONFORMANCE_EXPRESSIONS.get(cid)
    if expected_expr is None:
        return f"id {cid!r} is not in KNOWN_CELPY_NONCONFORMANCE_EXPRESSIONS"
    if case_expr != expected_expr:
        return (
            "corpus expression drifted from the pinned adjudicated literal: "
            f"expected {expected_expr!r}, got {case_expr!r}"
        )
    if celpy_record.get("raised") is not False:
        return (
            "cel-python did NOT return a value (expected the lenient path); "
            f"celpy.raised={celpy_record.get('raised')!r}"
        )
    if wasm_record.get("raised") is not True:
        return (
            "wasm did NOT raise (expected the spec-correct compile error); "
            f"wasm.raised={wasm_record.get('raised')!r}"
        )
    error_class = wasm_record.get("error_class")
    if error_class != _EXPECTED_WASM_CARVEOUT_ERROR_CLASS:
        return (
            "wasm error class is not the documented compile error: "
            f"expected {_EXPECTED_WASM_CARVEOUT_ERROR_CLASS!r}, "
            f"got {error_class!r}"
        )
    error_code = wasm_record.get("error_code")
    if error_code != _EXPECTED_WASM_CARVEOUT_ERROR_CODE:
        return (
            "wasm error code is not the documented compile code: "
            f"expected {_EXPECTED_WASM_CARVEOUT_ERROR_CODE!r}, got {error_code!r}"
        )
    error_subtype = wasm_record.get("error_subtype")
    if error_subtype != _EXPECTED_WASM_CARVEOUT_ERROR_SUBTYPE:
        return (
            "wasm error subtype is not the documented compile subtype: "
            f"expected {_EXPECTED_WASM_CARVEOUT_ERROR_SUBTYPE!r}, "
            f"got {error_subtype!r}"
        )
    message = wasm_record.get("error_message") or ""
    missing = [
        s for s in _EXPECTED_WASM_CARVEOUT_MESSAGE_SUBSTRINGS if s not in message
    ]
    if missing:
        return (
            "wasm error message is missing the documented compile diagnostic "
            f"substring(s) {missing!r}; message={message!r}"
        )
    return None


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
    weakened to pass.

    The ONLY tolerated VALUE divergences are the EXACTLY-TWO adjudicated
    cel-python lexer non-conformance cases in ``KNOWN_CELPY_NONCONFORMANCE``
    (module-level; see its comment). They are a documented carve-out where wasm
    is SPEC-CORRECT (raises a compile error on a backslash that is not a valid
    escape) and cel-python is lenient. The carve-out is STRONGLY GUARDED below:
    the set is asserted to be EXACTLY those two labels, each carved-out case is
    asserted to STILL diverge (so a future convergence flags a stale carve-out),
    and EVERY OTHER reachable case must still compare byte-for-byte identical."""
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

    # --- Strong carve-out guard (do NOT loosen) -------------------------------
    # The carve-out set must be EXACTLY the two adjudicated labels, and each must
    # actually be in the reachable subset (so a corpus rename/removal that drops
    # a carved-out case is caught rather than silently tolerated).
    assert sorted(KNOWN_CELPY_NONCONFORMANCE) == [
        "regex_backslash_arabic_digit_accepted",
        "regex_backslash_fullwidth_digit_accepted",
    ], (
        "VAL-CWC-P4DUALRUN-004: KNOWN_CELPY_NONCONFORMANCE carve-out drifted; it "
        "must be EXACTLY the two adjudicated backslash-escape lexer cases. "
        f"observed={sorted(KNOWN_CELPY_NONCONFORMANCE)}"
    )
    carveout_not_reachable = sorted(KNOWN_CELPY_NONCONFORMANCE - set(subset_ids))
    assert carveout_not_reachable == [], (
        "VAL-CWC-P4DUALRUN-004: carved-out case(s) not in the reachable subset "
        f"(corpus rename/removal?): {carveout_not_reachable}. The carve-out is "
        "stale -- reconcile with relay_cel_corpus.json."
    )

    # Count the cases where BOTH engines returned a NON-RAISED value AND that
    # value is a non-empty-map / actual computed value -- these are the cases
    # the verdict-level test compares vacuously, and that this test compares for
    # real. This is the "value-compared" count the contract requires to be > 0.
    value_compared = 0
    divergences: list[dict[str, Any]] = []
    carved_out_divergences: dict[str, dict[str, Any]] = {}
    for cid in subset_ids:
        celpy_cmp = _value_comparable(celpy_results[cid])
        wasm_cmp = _value_comparable(wasm_results[cid])
        # A case is "value-compared" (non-vacuous) when both engines returned a
        # concrete value (raised == False) -- the actual computed bytes are then
        # compared. The host-guard eval_error cases (raised == True on both) are
        # status-compared, not value-compared.
        if celpy_cmp.get("raised") is False and wasm_cmp.get("raised") is False:
            value_compared += 1
        if celpy_cmp == wasm_cmp:
            continue
        case_expr = next(c["expression"] for c in subset if c["id"] == cid)
        diff = {
            "case_id": cid,
            "expression": case_expr,
            "celpy": celpy_cmp,
            "wasm": wasm_cmp,
        }
        # A case is carved out ONLY when it is BOTH in the adjudicated set AND it
        # matches the documented backslash-lexer compile-error fingerprint:
        #   (a) the corpus expression is EXACTLY the pinned adjudicated literal,
        #   (b) cel-python returned a value while the wasm RAISED, and
        #   (c) the wasm error is the documented RELAY-CEL-009 /
        #       RELAY-CEL-ENGINE-COMPILE (RelayCelEngineError) carrying the
        #       engine's own RELAY-CEL-001 compile code + the cel-rust
        #       "token recognition error" lexer diagnostic.
        # If the cid is adjudicated but ANY of (a)-(c) fails -- a corpus
        # expression drift, or a wasm regression that raises a DIFFERENT error
        # (panic / exec / profile / bare exception) -- the case is NOT carved out
        # and falls through as a normal divergence (which fails the test). This
        # is the FINDING-B strengthening: the carve-out no longer suppresses ANY
        # mismatch for the two ids; it pins the expression and the wasm error.
        carveout_reason = _carveout_rejection_reason(
            cid, case_expr, celpy_results[cid], wasm_results[cid]
        )
        if cid in KNOWN_CELPY_NONCONFORMANCE and carveout_reason is None:
            # Adjudicated, expression-pinned, documented-compile-error divergence:
            # recorded for the stale-carve-out guard below, NOT a failure.
            carved_out_divergences[cid] = diff
        else:
            if cid in KNOWN_CELPY_NONCONFORMANCE:
                # Adjudicated id but the fingerprint did NOT match -- annotate
                # WHY so the failure diff explains the unexpected carve-out shape.
                diff = {**diff, "carveout_rejected_because": carveout_reason}
            divergences.append(diff)

    # The carve-out is only legitimate while EACH carved-out case ACTUALLY still
    # diverges AS the documented backslash-lexer compile error (celpy returns the
    # lenient value, wasm raises the RELAY-CEL-009 / ENGINE-COMPILE "token
    # recognition error"). A carved-out id that no longer diverges at all (a
    # cel-python fix or an M6 reclassification made the engines CONVERGE) is a
    # STALE carve-out and fails here. A carved-out id that diverges for the WRONG
    # reason (fingerprint rejected) already landed in ``divergences`` above and
    # fails the divergence assertion below -- so it is intentionally NOT counted
    # as "still legitimately carved out" here.
    legitimately_carved = set(carved_out_divergences)
    converged_carveouts = sorted(KNOWN_CELPY_NONCONFORMANCE - legitimately_carved)
    rejected_carveout_ids = sorted(
        cid
        for d in divergences
        if (cid := d.get("case_id")) in KNOWN_CELPY_NONCONFORMANCE
    )
    # Only flag as STALE/converged the adjudicated ids that did NOT appear as a
    # divergence at all (neither legitimately carved out nor fingerprint-rejected);
    # a fingerprint-rejected id is reported by the divergence failure with its
    # precise reason, not mislabeled here as "converged".
    truly_converged = [c for c in converged_carveouts if c not in rejected_carveout_ids]
    assert truly_converged == [], (
        "VAL-CWC-P4DUALRUN-004: carved-out case(s) no longer diverge "
        f"celpy-vs-wasm: {truly_converged}. The KNOWN_CELPY_NONCONFORMANCE "
        "carve-out is now STALE -- cel-python converged on (or the corpus was "
        "reclassified to) the spec-correct behavior. Remove these from the "
        "carve-out set (likely the M6 cel-python-removal reclassification)."
    )
    for diff in carved_out_divergences.values():
        print("[dual-run-value-parity-carveout]", json.dumps(diff, sort_keys=True))

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
            f"{len(subset_ids)} cases ({value_compared} value-compared), beyond "
            f"the {len(KNOWN_CELPY_NONCONFORMANCE)} documented carve-out(s). A "
            f"VALUE divergence on a VALID expression is a P0 that BLOCKS the M5 "
            f"flip; do NOT weaken this test. Full diff (no counts elided):\n"
            f"{rendered}"
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
        f"{len(carved_out_divergences)} carved-out documented "
        "celpy-non-conformance (wasm spec-correct), zero OTHER celpy-vs-wasm "
        "VALUE divergences."
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
def test_carveout_fingerprint_pins_expression_and_documented_wasm_error() -> None:
    """FINDING-B negative control: the strengthened carve-out guard
    (``_carveout_rejection_reason``) must ACCEPT only the documented
    backslash-lexer compile divergence and REJECT every other shape.

    Without this the carve-out suppressed ANY mismatch for the two adjudicated
    ids as long as celpy returned and wasm raised, so a corpus expression drift
    or a wasm regression that raised for a DIFFERENT reason (panic / exec /
    profile / bare exception) would be silently hidden. Each REJECT branch below
    is a regression that must surface as a normal divergence (a non-None reason),
    and the single ACCEPT branch is the legitimate documented case (None)."""
    cid = "regex_backslash_fullwidth_digit_accepted"
    good_expr = KNOWN_CELPY_NONCONFORMANCE_EXPRESSIONS[cid]
    celpy_returned = {"raised": False, "value_jcs_b64": "WHATEVER"}

    def wasm_compile_error(**overrides: Any) -> dict[str, Any]:
        base = {
            "raised": True,
            "error_class": _EXPECTED_WASM_CARVEOUT_ERROR_CLASS,
            "error_code": _EXPECTED_WASM_CARVEOUT_ERROR_CODE,
            "error_subtype": _EXPECTED_WASM_CARVEOUT_ERROR_SUBTYPE,
            "error_message": (
                "[RELAY-CEL-001] compile: token recognition error at: ..."
            ),
        }
        base.update(overrides)
        return base

    # ACCEPT: the documented compile error with the pinned expression.
    assert (
        _carveout_rejection_reason(
            cid, good_expr, celpy_returned, wasm_compile_error()
        )
        is None
    )

    # REJECT: an unknown id (not in the pinned expression map).
    assert (
        _carveout_rejection_reason(
            "not_a_carveout_id", good_expr, celpy_returned, wasm_compile_error()
        )
        is not None
    )

    # REJECT: corpus expression drifted from the pinned literal.
    assert (
        _carveout_rejection_reason(
            cid, '"\\n"', celpy_returned, wasm_compile_error()
        )
        is not None
    )

    # REJECT: cel-python ALSO raised (no longer the lenient path -> converged).
    assert (
        _carveout_rejection_reason(
            cid, good_expr, {"raised": True}, wasm_compile_error()
        )
        is not None
    )

    # REJECT: wasm did NOT raise (it returned a value -> converged).
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            {"raised": False, "value_jcs_b64": "X"},
        )
        is not None
    )

    # REJECT: wasm raised a DIFFERENT class (a regression, not the compile error).
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            wasm_compile_error(error_class="RelayCelProfileError"),
        )
        is not None
    )

    # REJECT: wasm raised the wrong 009 SUBTYPE (e.g. a panic, not a compile).
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            wasm_compile_error(error_subtype="RELAY-CEL-ENGINE-PANIC"),
        )
        is not None
    )

    # REJECT: wasm raised a different CODE entirely (host 007, not engine 009).
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            wasm_compile_error(error_code="RELAY-CEL-007"),
        )
        is not None
    )

    # REJECT: the message lacks the documented lexer diagnostic substrings.
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            wasm_compile_error(error_message="some unrelated failure"),
        )
        is not None
    )

    # REJECT: a bare non-Relay exception (no code/subtype captured -> None fields).
    assert (
        _carveout_rejection_reason(
            cid,
            good_expr,
            celpy_returned,
            {
                "raised": True,
                "error_class": "ValueError",
                "error_code": None,
                "error_subtype": None,
                "error_message": "boom",
            },
        )
        is not None
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
