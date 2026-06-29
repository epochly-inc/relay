"""W6.5 -- Relay-CEL Conformance Corpus runner (Python side).

Loads ``tests/conformance/cel/relay_cel_corpus.json`` and asserts the
contract for VAL-W6-050..055:

  * VAL-W6-050: corpus exists at the documented path; case count >= 200;
    paired Py/TS test runners cover the same case-ID set.
  * VAL-W6-051: each ``eval_value`` and ``udf_value`` case's Python
    output (JCS-canonical bytes) equals the recorded ``py_jcs_b64``
    field byte-for-byte. The TypeScript mirror at
    ``packages/contracts-typescript/test/w6_5_corpus.test.ts`` asserts
    cel-js produces the same bytes.
  * VAL-W6-052: per-UDF case-count floor (>= 5: 3 happy + 2 edge); the
    five edge categories (null, empty, unicode, large, nested) each
    appear at least once across the udf_value cases.
  * VAL-W6-053: the CEL-language idiom matrix used in production
    contracts (arithmetic, string, list, map, comparison, ternary,
    logical, in, indexing, member-access, null, type-coercion, unary,
    profile-rejection, regex) each appears >= 2 times in the corpus.
  * VAL-W6-054: the corpus runner is invoked under the tier-2 smoke
    marker on every PR. Test functions in this file carry the
    ``@pytest.mark.smoke`` AND ``@pytest.mark.fulfills`` markers per
    contract preamble convention.
  * VAL-W6-055: the cel-spec drift checker
    (``scripts/check-cel-spec-drift.py``) exits 0 against the current
    corpus; any vendored vector references a real corpus case.

A corpus regeneration is invoked via:

    uv run python scripts/generate-relay-cel-corpus.py

Plumbing tier guards (structure, drift, idiom matrix) run on every
commit; the byte-for-byte parity loop runs in tier-2 smoke (one case
per pytest test function so failures localise per case).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from relay_contracts import (
    RELAY_UDFS,
    WasmCelEvaluator,
    jcs_canonicalize,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)
from relay_contracts.errors import (
    SUBTYPE_ENGINE_COMPILE,
    RelayCelEngineError,
)
from relay_contracts.evaluator import MAX_TIMEOUT_MS

REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"
VENDOR_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "vendor" / "cel_spec_vectors.json"
GENERATOR_PATH = REPO_ROOT / "scripts" / "generate-relay-cel-corpus.py"
DRIFT_CHECKER_PATH = REPO_ROOT / "scripts" / "check-cel-spec-drift.py"

# Idioms named in VAL-W6-053; each MUST appear in the corpus at least
# this many times.
REQUIRED_IDIOMS_MIN_COUNT: dict[str, int] = {
    "arithmetic": 2,
    "string": 2,
    "list": 2,
    "map": 2,
    "comparison": 2,
    "ternary": 2,
    "logical": 2,
    "in": 2,
    "indexing": 2,
    "member-access": 2,
    "null": 2,
    "type-coercion": 2,
    "unary": 2,
    "profile-rejection": 2,
    "regex": 2,
    "udf": 2,
}

# Per-UDF case-count floor (VAL-W6-052).
REQUIRED_PER_UDF_MIN: int = 5

# Edge categories required across the udf_value cases (VAL-W6-052).
REQUIRED_EDGE_CATEGORIES: set[str] = {
    "null",
    "empty",
    "unicode",
    "large",
    "nested",
}

# Minimum case count (VAL-W6-050).
REQUIRED_MIN_CASES: int = 200


# ---------------------------------------------------------------------------
# Module-level loader (cached)
# ---------------------------------------------------------------------------


def _load_corpus() -> dict[str, Any]:
    if not CORPUS_PATH.exists():
        raise FileNotFoundError(
            f"Relay-CEL corpus missing at {CORPUS_PATH}; regenerate via "
            f"`uv run python scripts/generate-relay-cel-corpus.py`."
        )
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


_CORPUS = _load_corpus()
_CASES: list[dict[str, Any]] = _CORPUS["cases"]
_CASES_BY_ID: dict[str, dict[str, Any]] = {c["id"]: c for c in _CASES}


# ---------------------------------------------------------------------------
# Plumbing-tier structure guards (always run; offline; budget per
# scripts/tier_budget_gate.py)
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-050")
def test_corpus_file_exists_and_well_formed() -> None:
    assert CORPUS_PATH.exists(), f"Relay-CEL corpus missing at {CORPUS_PATH}"
    assert isinstance(_CORPUS, dict), "corpus root must be an object"
    assert _CORPUS.get("schema_version") == 1, (
        f"corpus schema_version must be 1; got {_CORPUS.get('schema_version')!r}"
    )
    assert isinstance(_CASES, list), "corpus.cases must be a list"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-050")
def test_corpus_has_minimum_case_count() -> None:
    assert len(_CASES) >= REQUIRED_MIN_CASES, (
        f"VAL-W6-050: corpus must contain >= {REQUIRED_MIN_CASES} cases; "
        f"got {len(_CASES)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-050")
def test_corpus_case_ids_are_unique_and_well_formed() -> None:
    ids = [c["id"] for c in _CASES]
    duplicates = [cid for cid, n in Counter(ids).items() if n > 1]
    assert duplicates == [], f"duplicate case IDs: {duplicates!r}"
    for c in _CASES:
        cid = c.get("id")
        assert isinstance(cid, str) and cid, f"case missing id: {c!r}"
        kind = c.get("kind")
        assert kind in ("eval_value", "eval_error", "udf_value"), (
            f"case {cid}: kind {kind!r} not in (eval_value, eval_error, udf_value)"
        )
        assert isinstance(c.get("idiom"), str) and c["idiom"], (
            f"case {cid}: missing idiom"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-052")
def test_corpus_per_udf_case_count_floor() -> None:
    udf_value_cases = [c for c in _CASES if c.get("kind") == "udf_value"]
    by_udf = Counter(c.get("udf") for c in udf_value_cases)
    for udf_name in ("relay.coverage", "relay.tool_arg", "relay.schema_match"):
        n = by_udf.get(udf_name, 0)
        assert n >= REQUIRED_PER_UDF_MIN, (
            f"VAL-W6-052: {udf_name} has {n} cases; need >= "
            f"{REQUIRED_PER_UDF_MIN} (3 happy + 2 edge)."
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-052")
def test_corpus_per_udf_happy_and_edge_split() -> None:
    """Each UDF MUST contribute >= 3 happy-path cases (no
    edge_category) and >= 2 edge cases (any edge_category)."""

    udf_value_cases = [c for c in _CASES if c.get("kind") == "udf_value"]
    for udf_name in ("relay.coverage", "relay.tool_arg", "relay.schema_match"):
        cases = [c for c in udf_value_cases if c.get("udf") == udf_name]
        happy = [c for c in cases if "edge_category" not in c]
        edge = [c for c in cases if "edge_category" in c]
        assert len(happy) >= 3, (
            f"VAL-W6-052: {udf_name} has {len(happy)} happy-path cases; need >= 3"
        )
        assert len(edge) >= 2, (
            f"VAL-W6-052: {udf_name} has {len(edge)} edge cases; need >= 2"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-052")
def test_corpus_edge_category_coverage_complete() -> None:
    udf_value_cases = [c for c in _CASES if c.get("kind") == "udf_value"]
    edge_cats = {c["edge_category"] for c in udf_value_cases if "edge_category" in c}
    missing = REQUIRED_EDGE_CATEGORIES - edge_cats
    assert missing == set(), (
        f"VAL-W6-052: edge categories missing from udf_value cases: {missing!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-053")
def test_corpus_idiom_matrix_coverage() -> None:
    by_idiom = Counter(c["idiom"] for c in _CASES)
    for idiom, min_count in REQUIRED_IDIOMS_MIN_COUNT.items():
        n = by_idiom.get(idiom, 0)
        assert n >= min_count, (
            f"VAL-W6-053: idiom {idiom!r} appears {n} times; need >= {min_count}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-053")
def test_corpus_eval_error_idiom_categories_present() -> None:
    """The corpus MUST cover Relay-profile-rejected idioms via
    ``eval_error`` cases. Specifically: dyn / timestamp / duration
    rejection (profile-rejection) and regex backreference
    (regex)."""

    eval_errors = [c for c in _CASES if c.get("kind") == "eval_error"]
    by_idiom = Counter(c["idiom"] for c in eval_errors)
    assert by_idiom.get("profile-rejection", 0) >= 2, (
        "VAL-W6-053: need >= 2 profile-rejection eval_error cases "
        f"(dyn / timestamp / duration); got {by_idiom.get('profile-rejection', 0)}"
    )
    assert by_idiom.get("regex", 0) >= 1, (
        "VAL-W6-053: need >= 1 regex backreference eval_error case; "
        f"got {by_idiom.get('regex', 0)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-050")
# Re-runs the corpus generator in a subprocess (evaluating every case through
# the wasm) and byte-compares -- ~20s locally, but 2-3x slower on the shared CI
# runners under the full plumbing tier, which trips the global --timeout=60.
# Override with a generous per-test timeout (the marker takes precedence over
# the CLI value); the test stays in the plumbing TIER (its runtime fits well
# within the 1380s tier budget), only its per-test hang-guard is relaxed.
@pytest.mark.timeout(300)
def test_corpus_is_not_stale_vs_generator() -> None:
    """A re-run of the generator MUST produce byte-identical output.
    A divergence means a contributor edited the corpus by hand or a
    UDF behavior changed without regenerating."""

    result = subprocess.run(
        [sys.executable, str(GENERATOR_PATH), "--check"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, (
        f"corpus is stale; regenerate via "
        f"`uv run python scripts/generate-relay-cel-corpus.py`.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Smoke-tier corpus runner (tier-2; one test per case for localisation)
# ---------------------------------------------------------------------------


def _to_python(value: Any) -> Any:
    """Mirror of scripts/generate-relay-cel-corpus.py:_to_python --
    collapse evaluator result types to JSON-roundtrippable Python. The wasm
    codec already decodes to native classes; the int branch also covers the
    CelUint marker subclass."""

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, str):
        return str(value)
    if isinstance(value, list | tuple):
        return [_to_python(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            kk = str(k) if not isinstance(k, str) else k
            out[kk] = _to_python(v)
        return out
    raise TypeError(f"unsupported evaluator result type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# M6 WS-I: the user-adjudicated legacy-lexer carve-out, mirrored from
# scripts/generate-relay-cel-corpus.py. EXACTLY TWO frozen eval_value cases
# record the REMOVED legacy engine's lenient (spec-INCORRECT) lexing of a
# backslash + non-ASCII digit string literal; the wasm correctly raises
# RELAY-CEL-009 / RELAY-CEL-ENGINE-COMPILE for them (a lexical error per the
# CEL spec). The per-case runner asserts the DOCUMENTED wasm behavior for
# those two ids -- strongly guarded (the pinned expression must match) so a
# corpus edit or a wasm regression cannot hide behind the carve-out.
# ---------------------------------------------------------------------------
_ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS: dict[str, str] = {
    # '"' + one literal backslash + the non-ASCII digit + '"', built with
    # backslash-u escapes so this source stays pure ASCII (U+FF10 / U+0660).
    "regex_backslash_fullwidth_digit_accepted": '"\\\uff10"',
    "regex_backslash_arabic_digit_accepted": '"\\\u0660"',
}


# Build the parametrize lists at import time so each case is its own
# pytest test function (per VAL-W6-051 requirement: each mismatch is
# addressable as a per-case pytest failure, not a collapsed list).

_EVAL_VALUE_CASES = [c for c in _CASES if c.get("kind") == "eval_value"]
_EVAL_ERROR_CASES = [c for c in _CASES if c.get("kind") == "eval_error"]
_UDF_VALUE_CASES = [c for c in _CASES if c.get("kind") == "udf_value"]


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-W6-051")
@pytest.mark.parametrize(
    "case",
    _EVAL_VALUE_CASES,
    ids=[c["id"] for c in _EVAL_VALUE_CASES],
)
def test_eval_value_python_byte_match(case: dict[str, Any]) -> None:
    ev = WasmCelEvaluator(udfs=RELAY_UDFS, timeout_ms=MAX_TIMEOUT_MS)
    if case["id"] in _ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS:
        # M6 WS-I adjudicated carve-out (see the module constant): the FROZEN
        # golden records the removed legacy engine's lenient lexing; the wasm
        # correctly raises the documented compile error. Assert the pinned
        # expression AND the documented structured error -- the case is still
        # exercised, with the spec-correct expectation.
        assert case["expression"] == _ADJUDICATED_LEGACY_LENIENT_EXPRESSIONS[case["id"]], (
            f"adjudicated case {case['id']!r} expression drifted from the pinned form"
        )
        with pytest.raises(RelayCelEngineError) as ctx:
            ev.evaluate(case["expression"], case.get("bindings", {}))
        assert ctx.value.code == "RELAY-CEL-009"
        assert ctx.value.subtype == SUBTYPE_ENGINE_COMPILE
        return
    raw = ev.evaluate(case["expression"], case.get("bindings", {}))
    py_value = _to_python(raw)
    actual = base64.b64encode(jcs_canonicalize(py_value)).decode("ascii")
    expected = case["py_jcs_b64"]
    assert actual == expected, (
        f"VAL-W6-051: Python-host bytes diverged from corpus golden for case {case['id']!r}\n"
        f"  expression: {case['expression']!r}\n"
        f"  bindings: {case.get('bindings')!r}\n"
        f"  expected (b64): {expected!r}\n"
        f"  actual   (b64): {actual!r}"
    )


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-W6-051")
@pytest.mark.parametrize(
    "case",
    _EVAL_ERROR_CASES,
    ids=[c["id"] for c in _EVAL_ERROR_CASES],
)
def test_eval_error_python_raises(case: dict[str, Any]) -> None:
    ev = WasmCelEvaluator(udfs=RELAY_UDFS, timeout_ms=MAX_TIMEOUT_MS)
    raised = False
    try:
        ev.evaluate(case["expression"], case.get("bindings", {}))
    except Exception:
        raised = True
    assert raised, (
        f"VAL-W6-051: the Python host did NOT raise for eval_error case {case['id']!r}"
        f" (expression={case['expression']!r}, bindings={case.get('bindings')!r})"
    )


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-W6-051")
@pytest.mark.parametrize(
    "case",
    _UDF_VALUE_CASES,
    ids=[c["id"] for c in _UDF_VALUE_CASES],
)
def test_udf_value_python_byte_match(case: dict[str, Any]) -> None:
    udf_name = case["udf"]
    args = case["args"]
    if udf_name == "relay.coverage":
        result = relay_coverage(*args)
    elif udf_name == "relay.tool_arg":
        result = relay_tool_arg(*args)
    elif udf_name == "relay.schema_match":
        result = relay_schema_match(*args)
    else:
        pytest.fail(f"unknown UDF in corpus case {case['id']!r}: {udf_name!r}")
    actual = base64.b64encode(jcs_canonicalize(result)).decode("ascii")
    expected = case["py_jcs_b64"]
    assert actual == expected, (
        f"VAL-W6-051: UDF {udf_name} bytes diverged from corpus golden "
        f"for case {case['id']!r}\n"
        f"  args: {args!r}\n"
        f"  expected (b64): {expected!r}\n"
        f"  actual   (b64): {actual!r}"
    )


# ---------------------------------------------------------------------------
# Drift detection (smoke; calls scripts/check-cel-spec-drift.py)
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.fulfills("VAL-W6-055")
def test_cel_spec_drift_checker_exits_zero() -> None:
    assert DRIFT_CHECKER_PATH.exists(), (
        f"drift checker missing at {DRIFT_CHECKER_PATH}"
    )
    result = subprocess.run(
        [sys.executable, str(DRIFT_CHECKER_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, (
        f"VAL-W6-055: cel-spec drift detected.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-055")
def test_cel_spec_vendor_file_present_and_non_empty() -> None:
    assert VENDOR_PATH.exists(), (
        f"VAL-W6-055: vendored cel-spec vectors missing at {VENDOR_PATH}"
    )
    vendor = json.loads(VENDOR_PATH.read_text(encoding="utf-8"))
    assert vendor.get("_schema_version") == 1
    vectors = vendor.get("vectors", [])
    assert isinstance(vectors, list) and len(vectors) >= 10, (
        f"VAL-W6-055: vendor cel_spec_vectors.json must contain >= 10 "
        f"vectors; got {len(vectors)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-055")
def test_cel_spec_vendor_vectors_resolve_in_corpus() -> None:
    vendor = json.loads(VENDOR_PATH.read_text(encoding="utf-8"))
    missing: list[str] = []
    for v in vendor.get("vectors", []):
        case_id = v.get("corpus_case_id")
        if not isinstance(case_id, str):
            missing.append(f"{v.get('vector_id', '<unknown>')}: missing corpus_case_id")
            continue
        if case_id not in _CASES_BY_ID:
            missing.append(
                f"{v.get('vector_id', '<unknown>')}: unresolved corpus_case_id={case_id!r}"
            )
    assert missing == [], (
        f"VAL-W6-055: {len(missing)} vendored cel-spec vectors do not "
        f"resolve in corpus:\n  " + "\n  ".join(missing)
    )


# ---------------------------------------------------------------------------
# VAL-W6-054: tier-2 smoke wiring guard
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-054")
def test_w6_5_smoke_tier_invocation_documented_in_manifest() -> None:
    """The manifest's tier-2 smoke command MUST invoke the pytest
    ``smoke`` marker (which collects this file's smoke tests) AND the
    npm vitest workspace runner (which collects the TS mirror in
    ``packages/contracts-typescript/test/w6_5_corpus.test.ts``).

    The contract preamble names ``test-tier-2`` as the canonical
    tier-2 command; this test reads the manifest and asserts the
    command's ``cmd`` field invokes both runners.
    """

    manifest_path = REPO_ROOT / ".ops" / "manifest.yaml"
    if not manifest_path.exists():
        pytest.skip(
            "RELAY-EVAL-MANIFEST-ABSENT: .ops/manifest.yaml not present in this "
            "checkout; tier-2 wiring assertion deferred."
        )
    text = manifest_path.read_text(encoding="utf-8")
    # The manifest declares `test-tier-2` with a cmd containing both
    # `pytest -m smoke` and `npm test --workspaces --if-present`.
    # We do not parse YAML here (avoid a tomllib-style dep); a
    # substring search is precise enough for the assertion.
    assert "test-tier-2" in text, (
        "VAL-W6-054: manifest is missing the test-tier-2 command"
    )
    assert "pytest -m smoke" in text, (
        "VAL-W6-054: manifest test-tier-2 command does not invoke "
        "`pytest -m smoke`; the W6.5 corpus runner would not run "
        "in tier-2 smoke"
    )
    assert "npm test" in text, (
        "VAL-W6-054: manifest test-tier-2 command does not invoke "
        "the npm vitest workspace runner; the W6.5 TS mirror would "
        "not run in tier-2 smoke"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W6-050")
def test_ts_mirror_test_file_exists() -> None:
    """VAL-W6-050: paired Py/TS test runners. The TS mirror MUST
    exist alongside this Python file; without it the corpus's parity
    contract is a one-sided assertion."""

    ts_mirror = (
        REPO_ROOT
        / "packages"
        / "contracts-typescript"
        / "test"
        / "w6_5_corpus.test.ts"
    )
    assert ts_mirror.exists(), (
        f"VAL-W6-050: TypeScript corpus runner missing at {ts_mirror}; "
        "the corpus parity contract is unenforced on the cel-js side."
    )
