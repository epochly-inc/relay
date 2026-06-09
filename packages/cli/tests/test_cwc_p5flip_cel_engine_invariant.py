"""M5 P5FLIP (WS-H) plumbing tests: the ``cel_engine`` verify-self checker.

Encodes VAL-CWC-P5FLIP-001 .. VAL-CWC-P5FLIP-005 (and the runner-registration
half of VAL-CWC-P5FLIP-006) as plumbing-tier tests bound to their assertion via
``@pytest.mark.fulfills(...)``.

The ``cel_engine`` check is a RUNTIME probe checker (unlike the grep-only
invariant checkers): it loads the packaged ``.wasm`` via ``WasmCelEvaluator``
(through the ``relay_contracts.wasm_artifact`` package-data resolver, the SAME
one the cross-host test uses), probes the three Relay UDFs through CEL, probes a
fenced ``dyn()`` under the Relay profile, compares the loaded-wasm sha to the
pinned manifest sha, and fails CLOSED when the artifact is absent / unloadable.

The check is PURE (only reads/parses under ``repo_root`` + the imported
``relay_contracts`` package data; no mutation, no network). It loads the wasm
DIRECTLY via ``WasmCelEvaluator`` -- independent of ``RELAY_CEL_ENGINE`` (the
default-flip is a LATER M5 feature; this check stays engine-selection-agnostic).

Per CLAUDE.md test discipline:

  * Every test exercises the real surface (the real packaged wasm on disk),
    never a mock of the engine. Fault injection for the negative branches uses
    ``monkeypatch`` to perturb the probe inputs / pinned sha / resolver -- not a
    mock of the production code path.
  * Tier-1 plumbing, offline, deterministic, no network.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from relay_cli.invariants import cel_engine
from relay_cli.invariants.runner import (
    _CHECK_DISPATCH,
    CHECK_ORDER,
    run_all_checks,
)
from relay_cli.invariants.util import Finding
from verify_self.finding_codes import FINDING_CODES

pytestmark = pytest.mark.plumbing

# Repository root (relay/), four parents up from this test file.
REPO_ROOT = Path(__file__).resolve().parents[3]


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-001: checker contract (CHECK_NAME first; iterable of Finding)
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-001")
def test_cel_engine_checker_contract() -> None:
    """``run(repo_root)`` returns ``(CHECK_NAME, findings)`` with the module's
    own CHECK_NAME first and an iterable of Finding second.

    Mirrors the canonical checker contract the runner dispatch asserts
    (``check_name == name``). Also asserts the module file exists on disk.
    """
    # CHECK_NAME is a non-empty str.
    assert isinstance(cel_engine.CHECK_NAME, str)
    assert cel_engine.CHECK_NAME

    # The module file exists on disk at the contract-mandated path.
    module_path = (
        REPO_ROOT
        / "packages"
        / "cli"
        / "src"
        / "relay_cli"
        / "invariants"
        / "cel_engine.py"
    )
    assert module_path.is_file(), f"cel_engine module not found at {module_path!r}"

    # run() returns a 2-tuple whose [0] == CHECK_NAME and [1] is an iterable of
    # Finding.
    result = cel_engine.run(REPO_ROOT)
    assert isinstance(result, tuple)
    assert len(result) == 2
    name, findings = result
    assert name == cel_engine.CHECK_NAME
    assert isinstance(findings, Iterable)
    findings_list = list(findings)
    for finding in findings_list:
        assert isinstance(finding, Finding)
        # Every emitted finding code is a member of the closed enum.
        assert finding.code in FINDING_CODES

    # The runner dispatch asserts checker-name match: the module CHECK_NAME is a
    # key of the dispatch map and maps to the module's run().
    assert cel_engine.CHECK_NAME in _CHECK_DISPATCH
    assert _CHECK_DISPATCH[cel_engine.CHECK_NAME] is cel_engine.run


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-002: probes the 3 Relay UDFs through CEL; zero findings healthy
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-002")
def test_cel_engine_probes_three_udfs() -> None:
    """On a healthy install the check loads the packaged wasm via
    ``WasmCelEvaluator``, probes all three Relay UDFs through CEL with
    known-correct verdicts, and yields ZERO findings.

    Asserts the check exercises all three UDF names via its public probe set
    (``cel_engine.PROBED_UDF_NAMES``).
    """
    name, findings = cel_engine.run(REPO_ROOT)
    assert name == cel_engine.CHECK_NAME
    assert len(findings) == 0, [
        (f.file, f.code, f.suggested_fix) for f in findings
    ]

    # The check exercises all three relay.* UDF names.
    assert set(cel_engine.PROBED_UDF_NAMES) == {
        "relay.coverage",
        "relay.tool_arg",
        "relay.schema_match",
    }

    # The probe verdicts are actually correct (the check's own probe runner,
    # called directly, returns the three known-correct verdicts and no finding).
    probe_findings = cel_engine._probe_three_udfs()
    assert probe_findings == [], probe_findings


@pytest.mark.fulfills("VAL-CWC-P5FLIP-002")
def test_cel_engine_probes_three_udfs_wrong_verdict_emits_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong UDF verdict (fault-injected by perturbing the EXPECTED verdict)
    causes the probe to emit a finding (fail)."""
    # Perturb one of the expected verdicts so the real wasm verdict no longer
    # matches -> the probe must emit a finding. ``_UDF_PROBES`` is a tuple of
    # ``_UdfProbe`` NamedTuples; capture the original then rebuild a flipped
    # variant. monkeypatch restores the original automatically at teardown.
    original = cel_engine._UDF_PROBES
    bad = []
    for probe in original:
        # Flip the expected verdict of the relay.coverage probe.
        if probe.udf_name == "relay.coverage":
            bad.append(probe._replace(expected=not probe.expected))
        else:
            bad.append(probe)
    monkeypatch.setattr(cel_engine, "_UDF_PROBES", tuple(bad))

    probe_findings = cel_engine._probe_three_udfs()
    assert len(probe_findings) >= 1
    assert all(f.code in FINDING_CODES for f in probe_findings)
    assert any(
        f.code == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG
        for f in probe_findings
    )


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-003: fenced dyn() probe; fails if not fenced
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-003")
def test_cel_engine_dyn_fence_probe() -> None:
    """On a correctly-built wasm the fenced ``dyn()`` probe produces zero
    findings (the engine surfaces RELAY-CEL-002 / PROFILE-DYN-DISABLED)."""
    findings = cel_engine._probe_dyn_fence()
    assert findings == [], [(f.code, f.suggested_fix) for f in findings]


@pytest.mark.fulfills("VAL-CWC-P5FLIP-003")
def test_cel_engine_dyn_fence_probe_unfenced_emits_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fault-injected evaluator whose ``dyn()`` probe SUCCEEDS (no fence)
    causes the dyn-fence probe to emit exactly one finding whose code
    identifies the missing dyn fence."""

    class _UnfencedEvaluator:
        """Stand-in evaluator whose dyn() probe evaluates instead of fencing."""

        def __init__(self, **_kwargs: object) -> None:
            pass

        def evaluate(self, expression: str, bindings: object = None) -> object:
            # No profile fence: dyn(1) "evaluates" to 1 instead of raising.
            return 1

    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _UnfencedEvaluator()
    )

    findings = cel_engine._probe_dyn_fence()
    assert len(findings) == 1, findings
    assert (
        findings[0].code
        == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED
    )


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-004: loaded-wasm sha == pinned manifest sha
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-004")
def test_cel_engine_sha_match() -> None:
    """When the loaded-wasm sha equals the pinned-manifest sha, the sha probe
    yields zero findings."""
    findings = cel_engine._probe_sha_match()
    assert findings == [], [(f.code, f.suggested_fix) for f in findings]


@pytest.mark.fulfills("VAL-CWC-P5FLIP-004")
def test_cel_engine_sha_match_mismatch_emits_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the pinned-manifest sha is monkeypatched to a DIFFERENT hex digest,
    the sha probe yields exactly one finding (sha-mismatch code). A
    tampered/mismatched wasm must fail the check."""
    # Monkeypatch the pinned sha (as the check reads it) to a different digest.
    tampered = "0" * 64
    monkeypatch.setattr(cel_engine, "_pinned_wasm_sha256", lambda: tampered)

    findings = cel_engine._probe_sha_match()
    assert len(findings) == 1, findings
    assert (
        findings[0].code
        == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_SHA_MISMATCH
    )


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-005: fail closed when the wasm is missing / unloadable
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_missing_wasm_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the packaged ``.wasm`` cannot be resolved (resolver monkeypatched to
    return None), ``run()`` returns NORMALLY (does not raise) with status fail
    (>=1 finding) describing the missing/unloadable artifact.

    This proves the runner records a FAIL, not an internal-error envelope from a
    Python traceback (VAL-CWC-P5FLIP-005)."""
    # Point the check's wasm path resolver at a missing artifact.
    monkeypatch.setattr(
        cel_engine, "_resolve_loaded_wasm_path", lambda: None
    )

    # run() MUST NOT raise.
    name, findings = cel_engine.run(REPO_ROOT)
    assert name == cel_engine.CHECK_NAME
    assert len(findings) >= 1
    codes = {f.code for f in findings}
    assert cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE in codes
    for finding in findings:
        assert finding.code in FINDING_CODES
        # A clear structured reason (suggested_fix is non-empty).
        assert finding.suggested_fix


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_unloadable_wasm_fails_closed_no_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the wasm load itself raises an engine error mid-probe, ``run()``
    still returns normally with a fail finding (the load/probe guard converts
    any load/parse failure into a structured finding, never an unhandled
    exception)."""
    from relay_contracts.errors import RelayCelEngineError

    def _boom() -> object:
        raise RelayCelEngineError(
            "simulated unloadable wasm", subtype="RELAY-CEL-ENGINE-REQUEST"
        )

    monkeypatch.setattr(cel_engine, "_build_wasm_evaluator", _boom)

    name, findings = cel_engine.run(REPO_ROOT)
    assert name == cel_engine.CHECK_NAME
    assert len(findings) >= 1
    assert cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE in {
        f.code for f in findings
    }


# -----------------------------------------------------------------------------
# VAL-CWC-P5FLIP-006 (runner-registration half): cel_engine in CHECK_ORDER
# -----------------------------------------------------------------------------


@pytest.mark.fulfills("VAL-CWC-P5FLIP-006")
def test_cel_engine_registered_in_check_order() -> None:
    """The cel_engine check is registered in ``CHECK_ORDER`` at its correct
    alphabetic slot and in ``_CHECK_DISPATCH``; ``run_all_checks`` executes it
    and counts it; ``CHECK_ORDER`` remains sorted."""
    assert cel_engine.CHECK_NAME in CHECK_ORDER
    # Alphabetic determinism (VAL-W5-038).
    assert tuple(sorted(CHECK_ORDER)) == CHECK_ORDER
    # The name is a dispatch key.
    assert cel_engine.CHECK_NAME in _CHECK_DISPATCH

    # run_all_checks includes a check entry with that name, status pass, on the
    # real (healthy) checkout.
    result = run_all_checks(REPO_ROOT)
    names = [c.name for c in result.checks]
    assert cel_engine.CHECK_NAME in names
    entry = next(c for c in result.checks if c.name == cel_engine.CHECK_NAME)
    assert entry.status == "pass", entry.to_dict()
    assert result.invariants_checked == len(CHECK_ORDER)
