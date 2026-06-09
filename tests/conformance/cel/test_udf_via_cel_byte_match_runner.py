"""WS-E per-case UDF-via-CEL byte-match runner (M3 P3CORPUS).

This runner locks VAL-CWC-P3CORPUS-005:

  A per-case pytest runner drives EACH
  ``tests/conformance/cel/relay_udf_via_cel_corpus.json`` case through the BUILT
  wasm via the Python loader (``relay_profile=True``) and asserts the produced
  typed-canonical JCS bytes BYTE-MATCH the stored golden (``py_jcs_b64``) for
  that case. There is exactly ONE parametrized test PER corpus case; every case
  passes; a deliberately-corrupted golden makes EXACTLY that case fail (the
  assertion is real, not vacuous).

This is DISTINCT from the structure / engines-fence / cross-anchor / determinism
GUARD tests in ``test_udf_via_cel_corpus.py`` (which lock
VAL-CWC-P3CORPUS-001..004). Those compare typed VALUES and recompute classifier
flags; THIS runner compares the JCS BYTES (base64 of ``jcs_canonicalize(value)``)
the BUILT wasm produces against the recorded ``py_jcs_b64`` golden, one node per
case.

Selection contract: the per-case parametrized node IDs carry ``py_byte_match``
(via the parametrize ids ``py_byte_match-<label>`` and the per-case function
name) while this file's name does NOT, so ``-k 'udf_via_cel and py_byte_match'``
collects EXACTLY the 15 per-case nodes (one per corpus case) and deselects every
prior guard AND the non-vacuity guard below. The ``udf_via_cel`` half of the
selection is satisfied by this file's name; the ``py_byte_match`` half is
satisfied only by the per-case node IDs.

The wasm path is the ``CEL_WASM`` env var when set (the evidence command sets
it), else the loader default
(``packages/cel-wasm/crate/target/wasm32-unknown-unknown/release/relay_cel_wasm.wasm``).

All tests are tier-1 plumbing. ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

# Repo root: this file lives at relay/tests/conformance/cel/test_*.py
REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_udf_via_cel_corpus.json"

# Make the JCS encoder + the typed-canonical codec + the wasm loader importable.
# These mirror the import surface the generator used to RECORD the golden, so
# the runner recomputes the byte form through the identical path.
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))
sys.path.insert(0, str(REPO_ROOT / "packages" / "cel-wasm" / "python"))

from relay_contracts import jcs_canonicalize  # noqa: E402  -- after sys.path
from relay_contracts.wasm_codec import py_to_typed  # noqa: E402  -- after sys.path


def _make_cel() -> Any:
    """Construct the wasm CEL handle.

    The loader ``relay_cel_wasm`` lives at
    ``packages/cel-wasm/python/relay_cel_wasm.py`` and is NOT an installed
    package; it is reachable only via the runtime ``sys.path`` insert above
    (identical to how the prior corpus guard and the WS-E generator reach it).
    It is imported here at runtime (not as a static top-level import) so the
    runtime-valid, statically-unresolvable loader import does not trip pyright
    -- mirroring the existing cel-wasm execution-environment convention without
    a new pyproject root. The returned handle honors ``$CEL_WASM`` (the evidence
    command sets it), else the loader default crate/target path.
    """
    import importlib  # noqa: PLC0415  -- runtime loader import, see docstring

    relay_cel_wasm = importlib.import_module("relay_cel_wasm")
    return relay_cel_wasm.RelayCel()


@pytest.fixture(scope="module")
def cel() -> Any:
    """One shared wasm handle for the module.

    Construction is DEFERRED to fixture-setup time (not module import) so that
    pytest *collection* of this file -- and, more importantly, of the sibling
    files under ``tests/conformance/cel`` -- never touches the wasm. On a clean
    checkout where the built wasm / ``$CEL_WASM`` artifact is absent, unrelated
    deselected collection must NOT error: this fixture is only set up when a
    selected test actually requests it, and a missing artifact yields a clear
    SKIP with a regenerate hint rather than a ``FileNotFoundError`` collection
    error.

    The loader is single-Store-per-instance and these tests run sequentially in
    one thread, so a single module-scoped handle is correct (and matches how the
    generator recorded the goldens with one ``RelayCel()``).
    """
    try:
        return _make_cel()
    except FileNotFoundError as exc:
        pytest.skip(
            "VAL-CWC-P3CORPUS-005: built CEL wasm artifact not found "
            f"({exc.filename!r}); build it via "
            "`bash packages/cel-wasm/conformance/build.sh build` (or set "
            "$CEL_WASM to a built relay_cel_wasm.wasm) and re-run."
        )


def _load_cases() -> list[dict[str, Any]]:
    assert CORPUS_PATH.exists(), (
        f"VAL-CWC-P3CORPUS-005: missing UDF-via-CEL corpus at {CORPUS_PATH}; "
        "regenerate via `uv run python scripts/generate-relay-udf-via-cel-corpus.py`."
    )
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = data.get("cases")
    assert isinstance(cases, list) and cases, "corpus must carry a non-empty 'cases' list"
    return cases


# Load the corpus ONCE at collection time so there is exactly one parametrized
# node per case (collected count == case count == 15). This is pure JSON I/O and
# does NOT touch the wasm, so it is safe at module import.
_CASES: list[dict[str, Any]] = _load_cases()


def _wasm_jcs_b64(cel: Any, case: dict[str, Any]) -> str:
    """Drive ``case['input_expression']`` (+ its plain-Python ``bindings``)
    THROUGH the built wasm with ``relay_profile=True`` and return the base64 of
    the JCS-canonicalized typed-canonical ``value`` -- the SAME byte form the
    generator recorded as ``py_jcs_b64``.
    """
    typed_bindings = {
        name: py_to_typed(value) for name, value in case["bindings"].items()
    }
    response = cel.eval(
        case["input_expression"], typed_bindings or None, relay_profile=True
    )
    assert response.get("ok"), (
        f"VAL-CWC-P3CORPUS-005: wasm returned non-ok for case "
        f"{case.get('label')!r}: {json.dumps(response)}"
    )
    value = response["value"]
    return base64.b64encode(jcs_canonicalize(value)).decode("ascii")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P3CORPUS-005")
@pytest.mark.parametrize(
    "case",
    _CASES,
    ids=[f"py_byte_match-{c['label']}" for c in _CASES],
)
def test_udf_via_cel_py_byte_match_per_case(cel: Any, case: dict[str, Any]) -> None:
    """One node PER corpus case: the JCS bytes the BUILT wasm produces for this
    case BYTE-MATCH the stored ``py_jcs_b64`` golden.

    Each node id carries ``py_byte_match`` so ``-k 'udf_via_cel and
    py_byte_match'`` collects exactly the per-case runner (one node per case).
    """
    produced_b64 = _wasm_jcs_b64(cel, case)
    stored_b64 = case["py_jcs_b64"]
    assert produced_b64 == stored_b64, (
        f"VAL-CWC-P3CORPUS-005: case {case.get('label')!r} JCS byte mismatch.\n"
        f"  expr     : {case['input_expression']!r}\n"
        f"  produced : {produced_b64}\n"
        f"  golden   : {stored_b64}\n"
        f"  produced(json): "
        f"{base64.b64decode(produced_b64).decode('utf-8', 'backslashreplace')}\n"
        f"  golden(json)  : "
        f"{base64.b64decode(stored_b64).decode('utf-8', 'backslashreplace')}"
    )


# NOTE: this non-vacuity test is DELIBERATELY named WITHOUT the ``py_byte_match``
# keyword so the evidence selection ``-k 'udf_via_cel and py_byte_match'``
# collects EXACTLY the per-case nodes (collected count == case count == 15) and
# does NOT also collect this guard. It still runs under the plain
# ``tests/conformance/cel -m plumbing`` regression sweep.
@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P3CORPUS-005")
def test_corrupted_golden_makes_exactly_that_case_fail(cel: Any) -> None:
    """Non-vacuity: a deliberately-corrupted golden makes EXACTLY that one case
    fail, proving the per-case byte-match assertion is real (it is not trivially
    satisfied by, e.g., comparing a value to itself).

    The corruption is purely in-memory (a copy of the first case with a single
    flipped golden byte); the on-disk corpus is NEVER mutated.
    """
    assert _CASES, "corpus must have at least one case"
    victim = dict(_CASES[0])  # shallow copy; we only rebind py_jcs_b64

    # Flip the stored golden to a value that cannot equal the produced bytes.
    # Decode -> mutate the inner JSON -> re-encode so it is still valid base64
    # but a DIFFERENT byte string from what the wasm produces.
    good_b64 = victim["py_jcs_b64"]
    corrupted_bytes = base64.b64decode(good_b64) + b" CORRUPTED"
    victim["py_jcs_b64"] = base64.b64encode(corrupted_bytes).decode("ascii")

    # The corrupted golden cannot match the freshly produced wasm bytes.
    assert victim["py_jcs_b64"] != good_b64, "corruption must change the golden"
    with pytest.raises(AssertionError):
        test_udf_via_cel_py_byte_match_per_case(cel, victim)

    # And the UNCORRUPTED first case still passes (the failure is specific to
    # the corrupted golden, not a blanket failure of the runner).
    test_udf_via_cel_py_byte_match_per_case(cel, dict(_CASES[0]))
