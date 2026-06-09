"""VAL-CWC-P4DUALRUN-005: dual-run CROSS-HOST parity (Py-wasm vs Node-wasm).

This is the keystone-#16 cross-host gate: it asserts ZERO Py-wasm-vs-Node-wasm
divergence over the FULL main Relay-CEL corpus
(``tests/conformance/cel/relay_cel_corpus.json``, 224 cases). For EVERY corpus
case that carries a CEL ``expression`` it evaluates the expression through

  (a) the PYTHON wasm host -- ``relay_cel_wasm.RelayCel`` (the wasmtime loader),
      ``relay_profile=True``, bindings encoded with ``py_to_typed``; and
  (b) the NODE wasm host -- the ``.mjs`` ``RelayCel`` loader driven by the
      sibling harness ``packages/cel-wasm/conformance/harness/cel_corpus_cross_host.mjs``,
      ``{relayProfile:true}``, bindings encoded with ``nativeToTyped``;

and asserts BYTE-IDENTICAL typed-canonical output: identical
``sha256(jcs_canonicalize(value))`` hex on success, identical engine error
``code``+``subtype`` on failure. Any divergence FAILS with a structured diff
naming EVERY divergent case (id, expression, the two hex values / the two error
classifications) -- not just the first mismatch.

Why expected divergence is EXACTLY zero (no carve-outs)
-------------------------------------------------------
BOTH hosts load the SAME pinned ``relay_cel_wasm.wasm`` bytes and call its SAME
``eval`` export. The wasm PRODUCES the typed-canonical value (and the error
``code``/``subtype``) as JSON; each host merely marshals memory in/out. So a
same-wasm asymmetry is possible ONLY through a HOST-MARSHALLING bug -- a binding
encoder that classifies an int/uint/double/bool differently, a JCS encoder that
sorts map keys differently, a duration/timestamp codec that fails open on one
host, etc. This test is PRECISELY the guard for that host-marshalling codec. The
celpy-vs-wasm backslash-lexer carve-out (``KNOWN_CELPY_NONCONFORMANCE`` in
``test_dual_run_host_parity.py``) is celpy-ONLY and IRRELEVANT here: there is no
celpy in this comparison. Expected Py-wasm-vs-Node-wasm divergence count is 0,
full stop. A NON-zero count is a P0.

Covered vs excluded cases (nothing is silently dropped)
-------------------------------------------------------
A corpus case is COVERED iff it carries a non-empty CEL ``expression`` string
(the ``eval_value`` and ``eval_error`` kinds). The ``udf_value`` kind carries NO
``expression`` -- it is a direct Python-callable UDF invocation (``udf`` +
``args``) with no CEL surface, so NEITHER host's wasm ``eval(expr, ...)`` can
drive it (there is no expression to compile). Those cases are EXCLUDED
IDENTICALLY on both hosts. The exclusion is GUARDED: this test asserts the
excluded id set equals EXACTLY the set of ``udf_value``-kind ids, so a future
corpus change that drops a CEL case (or mis-tags one) is caught rather than
silently absorbed. The covered/excluded/divergence counts are printed in the
evidence output, and ``corpus_total == covered + excluded == len(corpus.cases)``
is asserted on both the Python and Node sides.

All tests are tier-1 plumbing. ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Repo root: this file lives at relay/tests/conformance/cel/test_*.py
REPO_ROOT = Path(__file__).resolve().parents[3]
CORPUS_PATH = REPO_ROOT / "tests" / "conformance" / "cel" / "relay_cel_corpus.json"

# The Node cross-host harness that drives the FULL corpus through the .mjs wasm
# loader and emits the per-case digest map. The Python runner here invokes it
# once as a subprocess and compares its output against the Python wasm host.
NODE_HARNESS = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "conformance"
    / "harness"
    / "cel_corpus_cross_host.mjs"
)

# The wasm artifact BOTH hosts must load (the SAME bytes -- byte-parity is void
# otherwise). Resolution precedence is encoded in ``_wasm_path()`` below:
#   1. $CEL_WASM   -- explicit CI override (vendored elsewhere);
#   2. the COMMITTED, git-tracked PACKAGE-DATA wasm shipped as data of
#      ``relay_contracts`` (``_wasm/relay_cel_wasm.wasm``), resolved via the
#      canonical resolver ``relay_contracts.wasm_artifact.resolve_packaged_wasm_path``
#      -- ALWAYS present on a clean checkout (no build), and byte-identical to
#      ``WASM_PINNED_SHA256`` (a guard test enforces that on-disk hash), so the
#      test loads EXACTLY what the installed package loads;
#   3. the (gitignored) crate/target build -- a local-dev convenience only.
# Step 2 is why the global tier-1 ``pytest -m plumbing`` runs this keystone
# cross-host parity gate on a CLEAN checkout WITHOUT building the crate/target
# wasm -- a skip-if-absent guard would silently drop the gate, which is
# unacceptable (keystone invariant #16).
CRATE_TARGET_WASM = (
    REPO_ROOT
    / "packages"
    / "cel-wasm"
    / "crate"
    / "target"
    / "wasm32-unknown-unknown"
    / "release"
    / "relay_cel_wasm.wasm"
)

# Make the wasm loader + the JCS encoder + the typed-canonical codec importable.
# These mirror the byte-match runner (test_udf_via_cel_byte_match_runner.py) and
# the dual-run host-parity test: the loader at
# packages/cel-wasm/python/relay_cel_wasm.py is NOT an installed package and is
# reachable only via this runtime sys.path insert; relay_contracts IS installed
# (editable) but the explicit insert keeps the import robust to invocation cwd.
sys.path.insert(0, str(REPO_ROOT / "packages" / "contracts" / "src"))
sys.path.insert(0, str(REPO_ROOT / "packages" / "cel-wasm" / "python"))

from relay_contracts import jcs_canonicalize  # noqa: E402  -- after sys.path
from relay_contracts.wasm_artifact import (  # noqa: E402  -- after sys.path
    WASM_PINNED_SHA256,
    resolve_packaged_wasm_path,
    sha256_of_path,
)
from relay_contracts.wasm_codec import py_to_typed  # noqa: E402  -- after sys.path


def _wasm_path() -> str:
    """The wasm BOTH hosts load, returned as a string for the loader + the Node
    env. Resolution precedence (see CRATE_TARGET_WASM):

      1. $CEL_WASM when set -- the explicit CI override.
      2. The COMMITTED, git-tracked PACKAGE-DATA wasm of ``relay_contracts``,
         resolved through the CANONICAL resolver
         (``relay_contracts.wasm_artifact.resolve_packaged_wasm_path``). This is
         ALWAYS present on a clean checkout (no build) and is byte-identical to
         ``WASM_PINNED_SHA256`` (an on-disk-hash guard test enforces that), so
         this test loads EXACTLY what the installed package loads and runs on a
         clean tier-1 ``pytest -m plumbing`` with no crate build.
      3. The (gitignored) crate/target build -- a LOCAL-DEV fallback only.

    Defense-in-depth: when the package-data path is used, its sha256 MUST equal
    ``WASM_PINNED_SHA256`` -- a wrong/stale vendored wasm FAILS LOUD here rather
    than producing a misleading cross-host "parity" pass on the wrong bytes.
    """
    override = os.environ.get("CEL_WASM")
    if override:
        return override
    packaged = resolve_packaged_wasm_path()
    if packaged is not None:
        actual = sha256_of_path(packaged)
        assert actual == WASM_PINNED_SHA256, (
            "VAL-CWC-P4DUALRUN-005: the committed package-data wasm at "
            f"{packaged} hashes to {actual}, NOT the pinned "
            f"{WASM_PINNED_SHA256}. Cross-host parity on the wrong bytes would "
            "be a misleading pass; refusing to run on a stale/tampered wasm. "
            "Rebuild via the deterministic recipe and re-vendor the package "
            "data, or set $CEL_WASM to the correct artifact."
        )
        return str(packaged)
    # Local-dev fallback: the gitignored crate/target build. If that is also
    # absent the loader raises FileNotFoundError -- LOUD, not a silent skip.
    return str(CRATE_TARGET_WASM)


def _load_corpus() -> dict[str, Any]:
    assert CORPUS_PATH.exists(), (
        f"VAL-CWC-P4DUALRUN-005: missing Relay-CEL corpus at {CORPUS_PATH}."
    )
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = data.get("cases")
    assert isinstance(cases, list) and cases, (
        "VAL-CWC-P4DUALRUN-005: corpus must carry a non-empty 'cases' list."
    )
    return data


def _is_covered(case: dict[str, Any]) -> bool:
    """A case is COVERED (driven through both wasm hosts) iff it carries a
    non-empty CEL ``expression`` string. The ``udf_value`` kind carries none
    (direct Python-callable UDF; no CEL surface) and is EXCLUDED identically on
    both hosts."""
    expr = case.get("expression")
    return isinstance(expr, str) and expr != ""


def _make_python_cel() -> Any:
    """Construct the PYTHON wasm host handle (relay_cel_wasm.RelayCel). The wasm
    it loads is resolved by ``_wasm_path()`` (precedence: $CEL_WASM > the
    committed package-data wasm > the crate/target build), so on a CLEAN checkout
    with neither $CEL_WASM set nor a crate build it loads the committed
    package-data wasm. Imported at runtime so collection of sibling files on a
    checkout without the built wasm does not error at import time."""
    import importlib  # noqa: PLC0415  -- runtime loader import (cel-wasm convention)

    relay_cel_wasm = importlib.import_module("relay_cel_wasm")
    return relay_cel_wasm.RelayCel(_wasm_path())


def _python_signature(response: dict[str, Any]) -> dict[str, Any]:
    """The engine-agnostic CROSS-HOST parity signature for ONE Python wasm host
    response. On success: the sha256 hex of the JCS-canonicalized typed-canonical
    ``value`` (the SAME byte form the Node harness emits). On failure: the
    structured engine error ``code``+``subtype`` (both hosts load the SAME wasm,
    so these are byte-identical across hosts; a difference is the
    host-marshalling bug this gate catches)."""
    if response.get("ok") is True:
        value = response["value"]
        digest = hashlib.sha256(jcs_canonicalize(value)).hexdigest()
        return {"hex": digest}
    code = response.get("code")
    subtype = response.get("subtype")
    return {
        "error_code": code if isinstance(code, str) else None,
        "error_subtype": subtype if isinstance(subtype, str) else None,
    }


def _run_python_host(covered: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Drive every COVERED case through the PYTHON wasm host and return the
    per-case parity signature map ``{id: signature}``."""
    cel = _make_python_cel()
    out: dict[str, dict[str, Any]] = {}
    for case in covered:
        typed = {
            name: py_to_typed(value)
            for name, value in (case.get("bindings") or {}).items()
        }
        response = cel.eval(case["expression"], typed or None, relay_profile=True)
        out[case["id"]] = _python_signature(response)
    return out


def _run_node_host() -> dict[str, Any]:
    """Invoke the Node cross-host harness once over the FULL corpus and return its
    parsed JSON envelope ``{corpus_total, covered_ids, excluded_ids, results}``.

    The harness fails LOUD (non-zero) on a missing dist/corpus/loader/wasm; a
    non-zero exit therefore fails this test with the harness diagnostics rather
    than being silently tolerated -- a silent skip would let a cross-host byte
    divergence ship undetected (keystone invariant #16)."""
    env = dict(os.environ)
    env["CEL_WASM"] = _wasm_path()
    proc = subprocess.run(
        ["node", str(NODE_HARNESS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "VAL-CWC-P4DUALRUN-005: Node cross-host harness exited "
            f"{proc.returncode} (it could not drive the corpus through the .mjs "
            "wasm host). The harness fails loud on a missing dist/corpus/wasm; "
            "build the dist via `npm run build --workspace=packages/"
            "contracts-typescript` and the wasm via `make -C packages/cel-wasm "
            f"build`.\n  stderr: {proc.stderr[-3000:]}\n"
            f"  stdout: {proc.stdout[-1500:]}"
        )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        pytest.fail(
            "VAL-CWC-P4DUALRUN-005: Node cross-host harness produced unparseable "
            f"output: {exc}\n  stdout: {proc.stdout[-2000:]}"
        )
    raise AssertionError("unreachable")  # pragma: no cover -- pytest.fail raises


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-005")
def test_dual_run_cross_host_wasm_corpus_coverage_is_well_formed() -> None:
    """Guard: the covered subset (CEL-expression cases) MUST be non-empty so the
    cross-host parity assertion is non-vacuous, and the excluded set MUST be
    EXACTLY the udf_value-kind ids (no CEL surface) so nothing is silently
    dropped from the full-corpus claim."""
    data = _load_corpus()
    cases = data["cases"]
    covered = [c["id"] for c in cases if _is_covered(c)]
    excluded = [c["id"] for c in cases if not _is_covered(c)]

    assert len(covered) > 0, (
        "VAL-CWC-P4DUALRUN-005: the covered (CEL-expression) subset is EMPTY; the "
        f"cross-host parity test would be vacuous. Corpus: {CORPUS_PATH}"
    )

    # The excluded set MUST be exactly the cases with NO CEL expression, and those
    # MUST be exactly the udf_value kind (the direct Python-callable UDFs). A
    # corpus case of any OTHER kind that lacks an expression would be a silent
    # drop -- this guard catches it.
    no_expr_kinds = sorted({c.get("kind") for c in cases if not _is_covered(c)})
    assert no_expr_kinds == ["udf_value"], (
        "VAL-CWC-P4DUALRUN-005: the EXCLUDED set (cases with no CEL expression) "
        "must be EXACTLY the udf_value kind (direct Python-callable UDFs with no "
        f"CEL surface); observed kinds without an expression: {no_expr_kinds}. A "
        "case of any other kind without an expression would be a silent drop."
    )
    # And conversely every udf_value case must indeed lack an expression (so the
    # covered set never accidentally includes one).
    udf_with_expr = sorted(
        c["id"] for c in cases if c.get("kind") == "udf_value" and _is_covered(c)
    )
    assert udf_with_expr == [], (
        "VAL-CWC-P4DUALRUN-005: udf_value case(s) unexpectedly carry a CEL "
        f"expression and would be driven through the wasm: {udf_with_expr}."
    )
    assert len(covered) + len(excluded) == len(cases), (
        "VAL-CWC-P4DUALRUN-005: covered + excluded must partition the corpus."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-005")
def test_dual_run_cross_host_wasm_parity_zero_divergence() -> None:
    """For EVERY covered corpus case: the PYTHON wasm host and the NODE wasm host
    (the .mjs loader, driven by the sibling harness) MUST produce BYTE-IDENTICAL
    typed-canonical output -- identical sha256(jcs_canonicalize(value)) hex on
    success, identical engine error code+subtype on failure. Both hosts load the
    SAME pinned wasm, so the expected divergence count is EXACTLY zero (no
    carve-outs); a non-zero count is a host-marshalling-codec P0 and fails here
    with a structured diff listing EVERY divergent case."""
    data = _load_corpus()
    cases = data["cases"]
    covered = [c for c in cases if _is_covered(c)]
    covered_ids = [c["id"] for c in covered]
    excluded_ids = [c["id"] for c in cases if not _is_covered(c)]

    assert covered, "covered subset must be non-empty (see coverage guard test)"

    # (a) PYTHON wasm host signatures.
    py_sigs = _run_python_host(covered)

    # (b) NODE wasm host signatures (one subprocess over the full corpus).
    node_envelope = _run_node_host()
    node_results = node_envelope.get("results")
    assert isinstance(node_results, dict), (
        "VAL-CWC-P4DUALRUN-005: Node harness envelope missing a 'results' object; "
        f"got keys {sorted(node_envelope)}."
    )

    # The two hosts MUST agree on the FULL corpus partition: same total, same
    # covered ids, same excluded ids. A mismatch here is itself a cross-host
    # divergence (one host drove a case the other excluded).
    assert node_envelope.get("corpus_total") == len(cases), (
        "VAL-CWC-P4DUALRUN-005: Node harness reports corpus_total="
        f"{node_envelope.get('corpus_total')} but the corpus has {len(cases)} "
        "cases (the two hosts read different corpora?)."
    )
    node_covered = sorted(node_envelope.get("covered_ids") or [])
    node_excluded = sorted(node_envelope.get("excluded_ids") or [])
    assert node_covered == sorted(covered_ids), (
        "VAL-CWC-P4DUALRUN-005: covered-id set differs across hosts "
        f"(python_only={sorted(set(covered_ids) - set(node_covered))}, "
        f"node_only={sorted(set(node_covered) - set(covered_ids))})."
    )
    assert node_excluded == sorted(excluded_ids), (
        "VAL-CWC-P4DUALRUN-005: excluded-id set differs across hosts "
        f"(python_only={sorted(set(excluded_ids) - set(node_excluded))}, "
        f"node_only={sorted(set(node_excluded) - set(excluded_ids))})."
    )

    # Every covered case must appear in BOTH signature maps (a missing case is a
    # divergence -- a host silently dropped a covered case).
    missing_py = [cid for cid in covered_ids if cid not in py_sigs]
    missing_node = [cid for cid in covered_ids if cid not in node_results]
    assert missing_py == [] and missing_node == [], (
        "VAL-CWC-P4DUALRUN-005: a host dropped covered case(s) "
        f"(python missing={missing_py}, node missing={missing_node})."
    )

    # Per-case byte-identity comparison; collect EVERY divergence (do not stop at
    # the first mismatch) so the failure diff is complete.
    divergences: list[dict[str, Any]] = []
    value_compared = 0
    error_compared = 0
    for case in covered:
        cid = case["id"]
        py_sig = py_sigs[cid]
        node_sig = node_results[cid]
        if "hex" in py_sig and "hex" in node_sig:
            value_compared += 1
        elif "error_code" in py_sig and "error_code" in node_sig:
            error_compared += 1
        if py_sig != node_sig:
            divergences.append(
                {
                    "case_id": cid,
                    "expression": case["expression"],
                    "python_wasm": py_sig,
                    "node_wasm": node_sig,
                }
            )

    if divergences:
        for diff in divergences:
            print(
                "[dual-run-cross-host-wasm-parity-diff]",
                json.dumps(diff, sort_keys=True),
            )
        rendered = "\n".join(
            json.dumps(diff, sort_keys=True, indent=2) for diff in divergences
        )
        pytest.fail(
            f"VAL-CWC-P4DUALRUN-005: {len(divergences)} Py-wasm-vs-Node-wasm "
            f"CROSS-HOST divergence(s) on the {len(covered_ids)} covered cases of "
            f"the {len(cases)}-case corpus. BOTH hosts load the SAME wasm, so ANY "
            "divergence is a host-marshalling-codec P0 (typed-canonical key sort, "
            "int/uint/double/bool classification, duration fail-closed, etc.). "
            f"Full diff (no counts elided):\n{rendered}"
        )

    # The value comparison must be non-vacuous: at least one covered case must
    # have compared CONCRETE typed-canonical bytes on both hosts (a refactor that
    # collapses every case to an error signature would make the byte claim hollow
    # -- this catches it).
    assert value_compared > 0, (
        "VAL-CWC-P4DUALRUN-005: ZERO covered cases compared concrete value bytes "
        "(every covered case errored on both hosts). The cross-host VALUE parity "
        f"claim would be vacuous. covered={len(covered_ids)}."
    )

    print(
        "[dual-run-cross-host-wasm-parity] PASS: corpus_total="
        f"{len(cases)}, covered={len(covered_ids)}, excluded={len(excluded_ids)}, "
        f"value-compared={value_compared}, error-compared={error_compared}, "
        "Py-wasm-vs-Node-wasm divergences=0."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-CWC-P4DUALRUN-005")
def test_cross_host_signature_comparator_detects_divergence() -> None:
    """Negative-control: the parity signature comparison MUST flag a hex byte
    difference AND an error code/subtype difference, so the zero-divergence result
    above is a real assertion (not a vacuous one that would pass even if the two
    hosts produced different bytes)."""
    val_a = _python_signature({"ok": True, "value": {"t": "int", "v": "3"}})
    val_b = _python_signature({"ok": True, "value": {"t": "int", "v": "4"}})
    assert "hex" in val_a and "hex" in val_b
    assert val_a != val_b, (
        "comparator must detect a typed-canonical VALUE byte divergence (3 vs 4)"
    )

    # An identical value yields an identical signature (no spurious divergence).
    val_a_again = _python_signature({"ok": True, "value": {"t": "int", "v": "3"}})
    assert val_a == val_a_again

    # Error classification is compared by code+subtype; a different code or a
    # different subtype is a divergence; identical code+subtype is not.
    err_dyn = _python_signature(
        {"ok": False, "code": "RELAY-CEL-002", "subtype": "RELAY-CEL-PROFILE-DYN-DISABLED"}
    )
    err_dur = _python_signature(
        {"ok": False, "code": "RELAY-CEL-002", "subtype": "RELAY-CEL-PROFILE-DUR-DISABLED"}
    )
    err_exec = _python_signature({"ok": False, "code": "RELAY-CEL-004", "subtype": None})
    assert err_dyn != err_dur, "comparator must detect an error SUBTYPE divergence"
    assert err_dyn != err_exec, "comparator must detect an error CODE divergence"
    assert err_dyn != val_a, "a raised signature must differ from a returned one"
    err_dyn_again = _python_signature(
        {"ok": False, "code": "RELAY-CEL-002", "subtype": "RELAY-CEL-PROFILE-DYN-DISABLED"}
    )
    assert err_dyn == err_dyn_again
