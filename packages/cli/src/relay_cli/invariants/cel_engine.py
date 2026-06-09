"""Single-CEL-engine runtime invariant checker (M5 P5FLIP / WS-H).

Per CLAUDE.md keystone invariant #11 (the trust anchor) + the cel-wasm cutover
operation: Relay evaluates EVERY CEL expression through a SINGLE reproducible
wasm engine (``relay_cel_wasm.wasm``) so the Python and TypeScript hosts produce
byte-identical verdicts by construction. ``rly verify-self`` must therefore be
able to prove, on the local install, that the packaged wasm engine is present,
hashes to the pinned record, and behaves correctly.

This ``cel_engine`` check is a RUNTIME PROBE (unlike the grep-only invariant
checkers in this package). It is PURE in the verify-self sense: it only reads /
parses under ``repo_root`` and the imported ``relay_contracts`` package data; it
performs NO mutation, NO network, and NO filesystem write. It loads the wasm
DIRECTLY via :class:`relay_contracts.WasmCelEvaluator`, independent of the
``RELAY_CEL_ENGINE`` env selection (the default-flip is a LATER M5 feature; this
check stays engine-selection-agnostic so it validates the wasm engine whether or
not it is the active default).

Four probes, each mapping a failure cause to a distinct finding code:

  1. **3-UDF verdict probe** (VAL-CWC-P5FLIP-002): evaluate the three Relay UDFs
     (``relay.coverage`` / ``relay.tool_arg`` / ``relay.schema_match``) THROUGH
     CEL with inputs whose correct verdicts are known. A healthy engine yields
     ZERO findings; a wrong verdict -> ``RELAY-VERIFY-SELF-CEL-ENGINE-UDF-WRONG``.
  2. **Fenced-dyn probe** (VAL-CWC-P5FLIP-003): evaluate ``dyn(1)`` under the
     Relay profile and assert the engine surfaces the profile fence
     (:class:`RelayCelProfileError` with subtype
     ``RELAY-CEL-PROFILE-DYN-DISABLED``) rather than EVALUATING it. An unfenced
     ``dyn()`` -> ``RELAY-VERIFY-SELF-CEL-ENGINE-DYN-NOT-FENCED``.
  3. **Pinned-sha probe** (VAL-CWC-P5FLIP-004): hash the ACTUALLY-LOADED packaged
     ``.wasm`` and compare to the pinned ``WASM_PINNED_SHA256`` manifest record.
     A mismatch (tampered / stale artifact) ->
     ``RELAY-VERIFY-SELF-CEL-ENGINE-SHA-MISMATCH``.
  4. **Fail-closed guard** (VAL-CWC-P5FLIP-005): when the packaged ``.wasm`` is
     ABSENT or UNLOADABLE, the check emits
     ``RELAY-VERIFY-SELF-CEL-ENGINE-WASM-UNLOADABLE`` with a clear structured
     reason and does NOT raise -- the runner records a FAIL, never an
     internal-error envelope from a Python traceback. Every load / probe is
     wrapped so any load / parse failure becomes a structured finding.

The packaged wasm is resolved via the ``relay_contracts.wasm_artifact``
package-data resolver (``resolve_packaged_wasm_path()``) -- the SAME resolver the
cross-host package-data test uses -- so a fresh-installed wheel is validated the
same way the dev tree is.

Findings sort by ``(file, line, code)`` for determinism (VAL-W5-038); the
runtime probes carry no source file/line, so a stable synthetic ``file`` token
keeps the sort total and the JSON envelope informative.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Final, NamedTuple

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED,
    RELAY_VERIFY_SELF_CEL_ENGINE_SHA_MISMATCH,
    RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG,
    RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
)

from .util import Finding, suggested_fix_for

CHECK_NAME: Final[str] = "cel-engine-single-wasm"

# Synthetic ``file`` token for runtime-probe findings (no real source location).
# Stable so the deterministic ``(file, line, code)`` sort is total and the JSON
# envelope identifies the probe surface.
_PROBE_FILE: Final[str] = "<cel-engine-probe>"

# A short host wall-clock timeout (ms) for every probe evaluation: the probes are
# trivial expressions, so a tight bound keeps the check well within the tier-1
# 60 s budget even if the engine wedges. Mirrors the small bounds the wasm
# evaluator unit tests use.
_PROBE_TIMEOUT_MS: Final[int] = 250

# The Relay-profile fence subtype the wasm engine MUST surface for ``dyn()``.
_DYN_FENCE_SUBTYPE: Final[str] = "RELAY-CEL-PROFILE-DYN-DISABLED"


class _UdfProbe(NamedTuple):
    """One CEL-through-wasm probe of a Relay UDF.

    ``expression`` is a boolean CEL expression that evaluates to ``True`` on a
    healthy engine (the UDF call is wrapped in a comparison so the decoded result
    is always a CEL boolean, avoiding type-coercion fragility across the wasm
    value codec). ``bindings`` are plain-Python binding values (encoded by the
    evaluator's value codec). ``expected`` is the known-correct boolean verdict.
    """

    udf_name: str
    label: str
    expression: str
    bindings: dict[str, Any]
    expected: bool


# The three UDF probes with KNOWN-correct verdicts (semantics confirmed against
# packages/contracts/src/relay_contracts/udfs/{coverage,tool_arg,schema_match}.py
# and the CEL-through-wasm trace test
# packages/contracts/tests/test_pipeline_wasm_udf_trace.py):
#
#   * relay.coverage(t, "step1") with t.steps containing {"name": "step1"} -> True
#   * relay.coverage(t, "absent")                                          -> False
#   * relay.tool_arg(c, "case_id") == "abc" when c.args.case_id == "abc"   -> True
#   * relay.tool_arg(c, "missing") == null                                 -> True
#   * relay.schema_match("hi", {"type":"string"})                          -> True
#   * relay.schema_match(1,    {"type":"string"})                          -> False
#
# Each probe is a BOOLEAN expression so the decoded verdict is a CEL bool; the
# probe runner converts to a Python ``bool`` and compares to ``expected``.
_UDF_PROBES: tuple[_UdfProbe, ...] = (
    _UdfProbe(
        udf_name="relay.coverage",
        label="coverage-hit",
        expression='relay.coverage(t, "step1")',
        bindings={"t": {"steps": [{"name": "step1"}]}},
        expected=True,
    ),
    _UdfProbe(
        udf_name="relay.coverage",
        label="coverage-miss",
        expression='relay.coverage(t, "absent")',
        bindings={"t": {"steps": [{"name": "step1"}]}},
        expected=False,
    ),
    _UdfProbe(
        udf_name="relay.tool_arg",
        label="tool_arg-present",
        expression='relay.tool_arg(c, "case_id") == "abc"',
        bindings={"c": {"args": {"case_id": "abc"}}},
        expected=True,
    ),
    _UdfProbe(
        udf_name="relay.tool_arg",
        label="tool_arg-missing",
        expression='relay.tool_arg(c, "missing") == null',
        bindings={"c": {"args": {"case_id": "abc"}}},
        expected=True,
    ),
    _UdfProbe(
        udf_name="relay.schema_match",
        label="schema_match-pass",
        expression='relay.schema_match("hi", s)',
        bindings={"s": {"type": "string"}},
        expected=True,
    ),
    _UdfProbe(
        udf_name="relay.schema_match",
        label="schema_match-fail",
        expression="relay.schema_match(1, s)",
        bindings={"s": {"type": "string"}},
        expected=False,
    ),
)

# The set of UDF names the check exercises (every Relay UDF must be probed).
PROBED_UDF_NAMES: Final[tuple[str, ...]] = (
    "relay.coverage",
    "relay.tool_arg",
    "relay.schema_match",
)


# -----------------------------------------------------------------------------
# Resolver / pin indirection (monkeypatch seams for the negative-branch tests)
# -----------------------------------------------------------------------------


def _resolve_loaded_wasm_path() -> Path | None:
    """Resolve the packaged ``.wasm`` to a concrete on-disk path, else ``None``.

    Delegates to the ``relay_contracts.wasm_artifact`` package-data resolver --
    the SAME one the cross-host package-data test uses -- so a fresh-installed
    wheel is validated the same way the dev tree is. Returns ``None`` for an
    absent / non-materializable artifact (the resolver never raises); the caller
    maps ``None`` to a fail-closed finding.
    """
    from relay_contracts.wasm_artifact import resolve_packaged_wasm_path

    return resolve_packaged_wasm_path()


def _pinned_wasm_sha256() -> str:
    """Return the pinned manifest sha256 (the WS-G pinned record)."""
    from relay_contracts.wasm_artifact import WASM_PINNED_SHA256

    return WASM_PINNED_SHA256


def _build_wasm_evaluator() -> Any:
    """Construct a :class:`WasmCelEvaluator` over the packaged wasm engine.

    The evaluator is built with the three native Relay UDFs (``RELAY_UDFS``) so
    the UDF probes resolve. The wasm engine is loaded lazily on first evaluation;
    this constructor itself only validates the timeout + the (native) UDF set.

    Any failure to import / construct surfaces to the caller, which wraps it into
    a structured fail-closed finding (the check never lets an exception escape
    ``run``).
    """
    from relay_contracts import RELAY_UDFS, WasmCelEvaluator

    return WasmCelEvaluator(timeout_ms=_PROBE_TIMEOUT_MS, udfs=RELAY_UDFS)


# -----------------------------------------------------------------------------
# Finding constructor helper
# -----------------------------------------------------------------------------


def _finding(code: str, detail: str) -> Finding:
    """Build a runtime-probe :class:`Finding`.

    Runtime probes have no source location, so ``file`` is the stable synthetic
    probe token and ``line`` is 0. ``pattern`` carries the short probe detail so
    the JSON envelope identifies WHICH probe failed without narrative.
    """
    return Finding(
        file=_PROBE_FILE,
        line=0,
        code=code,
        suggested_fix=suggested_fix_for(code),
        pattern=detail,
    )


# -----------------------------------------------------------------------------
# Probe 1: the three Relay UDFs through CEL (VAL-CWC-P5FLIP-002)
# -----------------------------------------------------------------------------


def _probe_three_udfs() -> list[Finding]:
    """Probe the three Relay UDFs through CEL; return findings (empty = healthy).

    Loads the wasm evaluator once and evaluates each boolean UDF probe. A wrong
    verdict (decoded boolean != expected) OR any structured evaluation error is a
    ``RELAY-VERIFY-SELF-CEL-ENGINE-UDF-WRONG`` finding. The load/probe is wrapped
    so an unloadable engine becomes a fail-closed finding rather than an escaping
    exception.
    """
    try:
        evaluator = _build_wasm_evaluator()
    except Exception as exc:  # noqa: BLE001 -- fail-closed on any load failure
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                f"udf-probe load failed: {type(exc).__name__}: {exc}",
            )
        ]

    findings: list[Finding] = []
    for probe in _UDF_PROBES:
        try:
            raw = evaluator.evaluate(probe.expression, probe.bindings)
        except Exception as exc:  # noqa: BLE001 -- a probe error is a wrong verdict
            findings.append(
                _finding(
                    RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG,
                    f"{probe.udf_name} [{probe.label}] raised "
                    f"{type(exc).__name__}: {exc}",
                )
            )
            continue
        # The probe expressions are boolean; the wasm returns a CEL boolean
        # (celtypes.BoolType, a non-bool int subclass) -- convert to a plain
        # Python bool for an unambiguous comparison.
        verdict = bool(raw)
        if verdict != probe.expected:
            findings.append(
                _finding(
                    RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG,
                    f"{probe.udf_name} [{probe.label}] expected "
                    f"{probe.expected} got {verdict}",
                )
            )
    return findings


# -----------------------------------------------------------------------------
# Probe 2: fenced dyn() (VAL-CWC-P5FLIP-003)
# -----------------------------------------------------------------------------


def _probe_dyn_fence() -> list[Finding]:
    """Probe a fenced ``dyn()`` under the Relay profile; return findings.

    A healthy engine surfaces :class:`RelayCelProfileError` with subtype
    ``RELAY-CEL-PROFILE-DYN-DISABLED`` (or, equivalently, RELAY-CEL-002) rather
    than EVALUATING ``dyn(1)``. If the engine EVALUATES it (no exception) the
    fence is missing -> one ``RELAY-VERIFY-SELF-CEL-ENGINE-DYN-NOT-FENCED``
    finding. An engine that cannot even load is reported as fail-closed.
    """
    from relay_contracts.errors import RelayCelError, RelayCelProfileError

    try:
        evaluator = _build_wasm_evaluator()
    except Exception as exc:  # noqa: BLE001 -- fail-closed on any load failure
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                f"dyn-fence-probe load failed: {type(exc).__name__}: {exc}",
            )
        ]

    try:
        evaluator.evaluate("dyn(1)")
    except RelayCelProfileError as err:
        # Correct fence: assert the structured subtype identifies the dyn fence.
        if err.subtype == _DYN_FENCE_SUBTYPE:
            return []
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED,
                f"dyn() fenced with unexpected subtype {err.subtype!r}",
            )
        ]
    except RelayCelError as err:
        # The engine rejected dyn() but NOT via the profile fence -- still a
        # divergence from the expected fence behavior.
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED,
                f"dyn() rejected by non-profile error {err.code}/{err.subtype}",
            )
        ]
    # No exception -> the engine EVALUATED dyn(1): the fence is missing.
    return [
        _finding(
            RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED,
            "dyn(1) evaluated instead of surfacing the Relay profile fence",
        )
    ]


# -----------------------------------------------------------------------------
# Probe 3: loaded-wasm sha == pinned manifest sha (VAL-CWC-P5FLIP-004)
# -----------------------------------------------------------------------------


def _probe_sha_match() -> list[Finding]:
    """Compare the loaded-wasm sha256 to the pinned manifest sha; return findings.

    Resolves the packaged ``.wasm`` (via the package-data resolver), hashes its
    bytes, and compares to ``WASM_PINNED_SHA256``. An absent artifact is reported
    fail-closed; a mismatch is one
    ``RELAY-VERIFY-SELF-CEL-ENGINE-SHA-MISMATCH`` finding.
    """
    try:
        wasm_path = _resolve_loaded_wasm_path()
    except Exception as exc:  # noqa: BLE001 -- fail-closed on any resolve failure
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                f"sha-probe resolve failed: {type(exc).__name__}: {exc}",
            )
        ]
    if wasm_path is None:
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                "packaged wasm not resolvable for sha comparison",
            )
        ]

    try:
        loaded_sha = hashlib.sha256(wasm_path.read_bytes()).hexdigest()
    except OSError as exc:
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                f"packaged wasm unreadable for sha comparison: {exc}",
            )
        ]

    pinned = _pinned_wasm_sha256()
    if loaded_sha != pinned:
        return [
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_SHA_MISMATCH,
                f"loaded sha {loaded_sha} != pinned sha {pinned}",
            )
        ]
    return []


# -----------------------------------------------------------------------------
# Public checker entry point (VAL-CWC-P5FLIP-001 / -005)
# -----------------------------------------------------------------------------


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the cel-engine single-wasm invariant check.

    Returns ``(CHECK_NAME, findings)`` sorted by ``(file, line, code)``. The
    function is the canonical checker contract the runner dispatch requires
    (``check_name == name``).

    Fail-closed (VAL-CWC-P5FLIP-005): the wasm load / probes are guarded so any
    load / parse / probe failure becomes a structured FAIL finding -- ``run``
    NEVER raises an unhandled exception, so the runner records a fail, not an
    internal-error envelope from a Python traceback.

    ``repo_root`` is accepted for the canonical checker signature; this runtime
    probe resolves the wasm via the imported ``relay_contracts`` package data
    (anchored at the IMPORTED package root), not a ``repo_root``-relative path,
    so it validates a wheel install the same way it validates the dev tree.
    """
    findings: list[Finding] = []
    try:
        findings.extend(_probe_three_udfs())
        findings.extend(_probe_dyn_fence())
        findings.extend(_probe_sha_match())
    except Exception as exc:  # noqa: BLE001 -- absolute fail-closed backstop
        # Defense in depth: every probe already converts its own failures to
        # findings, but a wholly-unexpected error MUST still become a fail
        # finding rather than an escaping exception (the runner would otherwise
        # emit an internal-error envelope). VAL-CWC-P5FLIP-005.
        findings.append(
            _finding(
                RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE,
                f"cel-engine check failed closed: {type(exc).__name__}: {exc}",
            )
        )
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = [
    "CHECK_NAME",
    "PROBED_UDF_NAMES",
    "RELAY_VERIFY_SELF_CEL_ENGINE_DYN_NOT_FENCED",
    "RELAY_VERIFY_SELF_CEL_ENGINE_SHA_MISMATCH",
    "RELAY_VERIFY_SELF_CEL_ENGINE_UDF_WRONG",
    "RELAY_VERIFY_SELF_CEL_ENGINE_WASM_UNLOADABLE",
    "run",
]
