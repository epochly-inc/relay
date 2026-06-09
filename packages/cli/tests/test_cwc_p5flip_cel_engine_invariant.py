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


# -----------------------------------------------------------------------------
# roborev MED: lazy wasm-load failure during evaluate() -> WASM-UNLOADABLE,
# never misclassified as UDF-WRONG / DYN-NOT-FENCED (VAL-CWC-P5FLIP-005 contract)
# -----------------------------------------------------------------------------
#
# ``WasmCelEvaluator`` loads the wasm LAZILY: construction validates only the
# timeout + (native) UDF set; the wasm module compiles on the FIRST ``evaluate()``
# call (``_ensure_shared`` -> ``RelayCelEngineError`` / RELAY-CEL-009 on any load
# failure -- see packages/contracts/.../wasm_backed_evaluator.py). A PRESENT-but-
# corrupt / unloadable wasm therefore raises a LOAD error from ``evaluate()``,
# NOT from construction. The probes MUST classify that as the fail-closed
# WASM-UNLOADABLE reason, not as a UDF wrong-verdict / unfenced-dyn, so VAL-005's
# structured fail-closed contract is not weakened into a UDF/dyn finding.


class _LazyLoadFailEvaluator:
    """Stand-in evaluator whose CONSTRUCTION succeeds but ``evaluate()`` raises a
    wasm LOAD/engine error -- exactly the lazy-load failure surface.

    Mirrors the real ``WasmCelEvaluator`` shape: ``RelayCelEngineError`` (the
    RELAY-CEL-009 engine-error class the lazy ``_ensure_shared`` load raises) is
    surfaced from ``evaluate()``, never at ``__init__``.
    """

    def __init__(self, **_kwargs: object) -> None:
        # Construction succeeds (the real evaluator only validates timeout/UDFs).
        pass

    def evaluate(self, expression: str, bindings: object = None) -> object:
        from relay_contracts.errors import RelayCelEngineError

        raise RelayCelEngineError(
            "simulated lazy wasm load failure (corrupt/unloadable module)",
            subtype="RELAY-CEL-ENGINE-REQUEST",
        )


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_udf_probe_lazy_load_failure_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lazy wasm-LOAD error raised from ``evaluate()`` in the 3-UDF probe is a
    WASM-UNLOADABLE finding, NOT a UDF-WRONG misclassification.

    Construction succeeds; the FIRST ``evaluate()`` raises the
    ``RelayCelEngineError`` the real lazy ``_ensure_shared`` raises. The probe
    must emit exactly one WASM-UNLOADABLE finding and zero UDF-WRONG findings
    (the load failed -- no verdict was ever produced)."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _LazyLoadFailEvaluator()
    )

    findings = cel_engine._probe_three_udfs()
    codes = [f.code for f in findings]
    # The probe evaluates each of the 6 UDF probes; each lazy evaluate() raises
    # the load error, so EVERY finding is the fail-closed WASM-UNLOADABLE reason
    # and NONE is UDF-WRONG (the load failed -- no verdict was ever produced).
    assert findings, "a lazy load failure must produce at least one finding"
    assert all(
        c == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE
        for c in codes
    ), codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG not in codes
    ), "lazy load failure must NOT be misclassified as UDF-WRONG"


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_dyn_probe_lazy_load_failure_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lazy wasm-LOAD error raised from ``evaluate()`` in the dyn-fence probe is
    a WASM-UNLOADABLE finding, NOT a DYN-NOT-FENCED misclassification.

    The dyn-fence probe calls ``evaluate('dyn(1)')``; if THAT raises the lazy
    load error (engine never loaded), the absence of a profile-fence exception
    must NOT be read as "dyn evaluated / fence missing" -- the engine never even
    evaluated. The probe must emit one WASM-UNLOADABLE finding and zero
    DYN-NOT-FENCED findings."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _LazyLoadFailEvaluator()
    )

    findings = cel_engine._probe_dyn_fence()
    codes = [f.code for f in findings]
    assert codes == [
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE
    ], codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED not in codes
    ), "lazy load failure must NOT be misclassified as DYN-NOT-FENCED"


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_run_lazy_load_failure_fails_closed_single_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a lazy wasm-load failure makes ``run()`` fail closed with
    ONLY WASM-UNLOADABLE findings (no UDF-WRONG / DYN-NOT-FENCED), and never
    raises.

    Both the UDF probe and the dyn probe hit the lazy load error (each builds its
    own evaluator), so ``run`` yields one WASM-UNLOADABLE finding per probe; the
    sha probe is independent of the lazy load (it hashes bytes on disk) so it
    does not add a UDF/dyn finding. The check status is FAIL with a clean
    fail-closed classification."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _LazyLoadFailEvaluator()
    )

    # run() MUST NOT raise.
    name, findings = cel_engine.run(REPO_ROOT)
    assert name == cel_engine.CHECK_NAME
    codes = {f.code for f in findings}
    assert cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE in codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG not in codes
    ), "lazy load failure must NOT be misclassified as UDF-WRONG"
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED not in codes
    ), "lazy load failure must NOT be misclassified as DYN-NOT-FENCED"
    for finding in findings:
        assert finding.code in FINDING_CODES


# -----------------------------------------------------------------------------
# roborev LOW: a non-boolean UDF result must NOT pass -- it is a wrong verdict
# (VAL-CWC-P5FLIP-002: the engine MUST produce the correct BOOLEAN verdict)
# -----------------------------------------------------------------------------
#
# ``bool(raw)`` truthiness-coerces a NON-boolean engine result, so a broken value
# codec/engine returning ``1`` / ``0`` / a string for a boolean expression could
# silently PASS the UDF verdict probes. The probe must instead assert the decoded
# result is an ACTUAL boolean type (Python ``bool`` OR the CEL ``BoolType``,
# mirroring pipeline ``_classify_outcome``) and emit UDF-WRONG on ANY non-boolean.


class _NonBooleanResultEvaluator:
    """Stand-in evaluator whose ``evaluate()`` returns a non-boolean TRUTHY value
    (the integer ``1``) for every probe expression.

    A truthiness coercion (``bool(1) is True``) would FALSELY pass the probes
    whose ``expected`` is ``True``; a strict boolean-TYPE check must reject it."""

    def __init__(self, **_kwargs: object) -> None:
        pass

    def evaluate(self, expression: str, bindings: object = None) -> object:
        # A non-boolean truthy value: a broken codec returning the int 1 instead
        # of a CEL boolean. ``bool(1) is True`` -> would falsely pass a
        # ``expected=True`` probe under truthiness coercion.
        return 1


@pytest.mark.fulfills("VAL-CWC-P5FLIP-002")
def test_cel_engine_udf_probe_non_boolean_result_is_wrong_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-boolean TRUTHY probe result (int ``1``) must emit UDF-WRONG, not pass.

    Under the old ``bool(raw)`` coercion the ``expected=True`` probes would
    silently pass on ``1``; the strict boolean-type check must reject every
    non-boolean result with a UDF-WRONG finding."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _NonBooleanResultEvaluator()
    )

    findings = cel_engine._probe_three_udfs()
    assert len(findings) >= 1, (
        "a non-boolean UDF result must NOT pass the verdict probe"
    )
    assert all(
        f.code == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG
        for f in findings
    ), [f.code for f in findings]
    # Every probe (all 6) produced a non-boolean result, so each is a wrong
    # verdict -- none silently passed via truthiness coercion.
    assert len(findings) == len(cel_engine._UDF_PROBES), (
        f"expected one UDF-WRONG per probe; got {len(findings)} for "
        f"{len(cel_engine._UDF_PROBES)} probes"
    )


@pytest.mark.fulfills("VAL-CWC-P5FLIP-002")
def test_cel_engine_udf_probe_accepts_cel_booltype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine CEL ``BoolType`` result (the type the wasm codec returns) is
    accepted by the strict boolean-type check -- the fix must NOT regress the
    healthy path that returns ``celtypes.BoolType`` (an int subclass that is NOT
    a Python ``bool``).

    Guards against an over-strict ``isinstance(value, bool)``-only check that
    would falsely reject every healthy wasm verdict (``typed_to_py`` returns
    ``celtypes.BoolType`` for a CEL boolean)."""
    from celpy import celtypes

    class _BoolTypeEvaluator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def evaluate(self, expression: str, bindings: object = None) -> object:
            # Return the CORRECT verdict for each probe as a CEL BoolType (the
            # real wasm codec's type), so a healthy-but-BoolType engine passes.
            for probe in cel_engine._UDF_PROBES:
                if probe.expression == expression:
                    return celtypes.BoolType(probe.expected)
            raise AssertionError(f"unexpected probe expression {expression!r}")

    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", lambda: _BoolTypeEvaluator()
    )

    findings = cel_engine._probe_three_udfs()
    assert findings == [], [(f.code, f.pattern) for f in findings]


# -----------------------------------------------------------------------------
# roborev MED (defense-in-depth): a BARE loader / import / OS / wasmtime error
# escaping lazy load must STILL classify as WASM-UNLOADABLE -- never UDF-WRONG /
# DYN-NOT-FENCED (VAL-CWC-P5FLIP-005 fail-closed contract).
# -----------------------------------------------------------------------------
#
# The wasm facade (wasm_backed_evaluator.py) is DESIGNED to wrap every lazy-load
# surface (absent loader module, in-repo / package-data source, the shared-engine
# wasmtime instantiation in ``_ensure_shared``) into ``RelayCelEngineError``
# (RELAY-CEL-009). Investigation confirms the cel_engine probe's load path
# (``_build_wasm_evaluator().evaluate()`` -> ``_ensure_shared``) correctly
# surfaces a corrupt-but-present wasm as ``RelayCelEngineError`` (the
# try/except wrap at ``wasm_backed_evaluator._ensure_shared`` re-wraps the bare
# ``wasmtime.WasmtimeError``).
#
# DEFENSE IN DEPTH: the probe classifier must NOT depend on the facade never
# drifting. A bare ``ImportError`` / ``ModuleNotFoundError`` / ``FileNotFoundError``
# / ``OSError`` / wasmtime instantiation error escaping ``evaluate()`` is STILL a
# load failure -- it MUST map to WASM-UNLOADABLE, not to a UDF wrong-verdict / an
# unfenced dyn. These tests fault-inject each bare-error surface and assert the
# fail-closed classification holds.


def _bare_error_evaluator_factory(exc: BaseException):
    """Build a stand-in evaluator whose ``evaluate()`` raises ``exc`` (bare).

    Construction succeeds (the real evaluator only validates timeout/UDFs); the
    FIRST ``evaluate()`` raises the supplied BARE exception -- modelling a lazy
    load surface the facade FAILED to wrap into ``RelayCelEngineError``.
    """

    class _BareErrorEvaluator:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def evaluate(self, expression: str, bindings: object = None) -> object:
            raise exc

    return lambda: _BareErrorEvaluator()


_BARE_LOAD_ERRORS: tuple[BaseException, ...] = (
    ImportError("simulated bare ImportError from lazy wasm load"),
    ModuleNotFoundError("simulated bare ModuleNotFoundError"),
    FileNotFoundError("simulated bare FileNotFoundError (absent wasm)"),
    OSError("simulated bare OSError reading the wasm artifact"),
)


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
@pytest.mark.parametrize(
    "exc",
    _BARE_LOAD_ERRORS,
    ids=lambda e: type(e).__name__,
)
def test_cel_engine_udf_probe_bare_load_error_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    """A BARE import / OS / file-not-found error from ``evaluate()`` in the UDF
    probe is a WASM-UNLOADABLE finding, NOT a UDF-WRONG misclassification.

    Defense-in-depth: even if the facade fails to wrap a lazy-load surface into
    ``RelayCelEngineError``, the probe must fail closed (a load failure means no
    verdict was produced)."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", _bare_error_evaluator_factory(exc)
    )

    findings = cel_engine._probe_three_udfs()
    codes = [f.code for f in findings]
    assert findings, "a bare load failure must produce at least one finding"
    assert all(
        c == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE
        for c in codes
    ), codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG not in codes
    ), "bare load failure must NOT be misclassified as UDF-WRONG"


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
@pytest.mark.parametrize(
    "exc",
    _BARE_LOAD_ERRORS,
    ids=lambda e: type(e).__name__,
)
def test_cel_engine_dyn_probe_bare_load_error_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    """A BARE import / OS / file-not-found error from ``evaluate()`` in the
    dyn-fence probe is a WASM-UNLOADABLE finding, NOT a DYN-NOT-FENCED
    misclassification.

    The absence of a profile-fence exception when the engine never even loaded
    must NOT be read as 'dyn evaluated / fence missing'."""
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", _bare_error_evaluator_factory(exc)
    )

    findings = cel_engine._probe_dyn_fence()
    codes = [f.code for f in findings]
    assert codes == [
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE
    ], codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED not in codes
    ), "bare load failure must NOT be misclassified as DYN-NOT-FENCED"


def _wasmtime_error_or_skip() -> BaseException:
    """Return a real ``wasmtime.WasmtimeError`` instance, or skip if absent.

    The wasmtime instantiation error is a BARE ``Exception`` subclass (NOT an
    ``OSError`` / ``ImportError``), so the probe classifier must recognize it
    explicitly. This is the exact bare type a corrupt-but-present wasm surfaces
    from the one-shot-handle load path (``evaluate_with_wasm_path``)."""
    try:
        from wasmtime import WasmtimeError
    except Exception:  # noqa: BLE001 -- wasmtime not installed -> skip
        pytest.skip("wasmtime not importable in this environment")
    return WasmtimeError("simulated bare wasmtime instantiation failure")


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_udf_probe_bare_wasmtime_error_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A BARE ``wasmtime.WasmtimeError`` from ``evaluate()`` in the UDF probe is a
    WASM-UNLOADABLE finding, NOT a UDF-WRONG misclassification.

    ``WasmtimeError`` is a plain ``Exception`` subclass (not ``OSError`` /
    ``ImportError``), so the classifier must recognize the wasmtime error type
    explicitly -- the corrupt-but-present wasm surfaces exactly this type from the
    one-shot-handle load path."""
    exc = _wasmtime_error_or_skip()
    monkeypatch.setattr(
        cel_engine, "_build_wasm_evaluator", _bare_error_evaluator_factory(exc)
    )

    findings = cel_engine._probe_three_udfs()
    codes = [f.code for f in findings]
    assert findings, "a bare wasmtime load failure must produce a finding"
    assert all(
        c == cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE
        for c in codes
    ), codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG not in codes
    ), "bare wasmtime load failure must NOT be misclassified as UDF-WRONG"


@pytest.mark.fulfills("VAL-CWC-P5FLIP-005")
def test_cel_engine_corrupt_but_present_wasm_is_wasm_unloadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A CORRUPT-but-present wasm (a real file of GARBAGE bytes pointed at by the
    shared-engine resolver) makes ``run()`` fail closed with WASM-UNLOADABLE
    findings only -- it does NOT raise and does NOT misclassify.

    This exercises the REAL lazy-load path end to end: a present file whose bytes
    are not a valid wasm module. ``_ensure_shared`` instantiates wasmtime against
    those bytes; the bare ``WasmtimeError`` is wrapped into ``RelayCelEngineError``
    by the facade and the probe classifies it as WASM-UNLOADABLE. Investigation
    finding: the corrupt-but-present wasm surfaces WRAPPED (RelayCelEngineError)
    through the shared-engine evaluate() path; the defensive classifier also
    covers the BARE surface should that ever drift."""
    import relay_contracts.wasm_backed_evaluator as wbe

    garbage = tmp_path / "corrupt.wasm"
    garbage.write_bytes(b"not a valid wasm module \x00\x01\x02\x03" * 32)

    # Point the shared-engine resolver at the garbage file so the LAZY
    # _ensure_shared bootstrap instantiates wasmtime against corrupt bytes.
    monkeypatch.setattr(
        wbe, "_resolve_wasm_path_or_none", lambda override=None: str(garbage)
    )

    # run() MUST NOT raise.
    name, findings = cel_engine.run(REPO_ROOT)
    assert name == cel_engine.CHECK_NAME
    codes = {f.code for f in findings}
    assert cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE in codes
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG not in codes
    ), "corrupt-but-present wasm must NOT be misclassified as UDF-WRONG"
    assert (
        cel_engine.RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED not in codes
    ), "corrupt-but-present wasm must NOT be misclassified as DYN-NOT-FENCED"
    for finding in findings:
        assert finding.code in FINDING_CODES
