"""``rly verify-self`` invariant runner (W5.5 VAL-W5-031..040).

Aggregates the four invariant checkers into the canonical stdout JSON
shape declared by VAL-W5-031:

    {
      "schema_version": "relay.cli.verify_self.v1",
      "overall": "pass" | "fail",
      "checks": [{name, status, details}, ...],
      "invariants_checked": <int>,
      "failures": <int>,
      "duration_ms": <int>
    }

Per VAL-W5-031: exit 0 iff ``overall == "pass"`` AND ``failures == 0``.
The runner is pure (no side effects beyond timing); the caller
(``rly verify-self``) handles process exit, evidence-bundle generation,
and stderr envelope emission.

Determinism (VAL-W5-038): every checker sorts its findings by
``(file, line, code)``; the runner emits checks in the fixed alphabetic
order declared in :data:`CHECK_ORDER` so two runs against the same
checkout produce byte-identical ``checks`` arrays. ``duration_ms`` is
deliberately excluded from the equality comparison the determinism test
performs (the contract narrative makes determinism about ``checks``,
not the timing field).

Internal-failure envelope (VAL-W5-039): a checker that raises is
caught here and converted into a synthetic check entry
``{name, status: "error", details: [], error_envelope: {...}}`` so the
runner never propagates a Python traceback. The CLI command then maps
the internal-error envelope to ``RELAY-CLI-VERIFY-SELF-INTERNAL`` on
stderr with exit code 70.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from .atomic_primitives import CHECK_NAME as ATOMIC_PRIMITIVES_CHECK
from .atomic_primitives import run as run_atomic_primitives
from .banned_patterns import CHECK_NAME as BANNED_PATTERNS_CHECK
from .banned_patterns import run as run_banned_patterns
from .control_plane_writes import CHECK_NAME as CONTROL_PLANE_CHECK
from .control_plane_writes import run as run_control_plane_writes
from .mocks_in_source import CHECK_NAME as MOCKS_IN_SOURCE_CHECK
from .mocks_in_source import run as run_mocks_in_source
from .util import Finding, finding_to_dict

# -----------------------------------------------------------------------------
# Schema version + canonical check ordering
# -----------------------------------------------------------------------------

VERIFY_SELF_RESULT_SCHEMA: Final[str] = "relay.cli.verify_self.v1"

# Canonical check ordering (alphabetic). Pinned so the JSON envelope is
# byte-stable across runs (VAL-W5-038). Adding a new check requires
# inserting it in the correct alphabetic position so the snapshot
# fixtures track.
CHECK_ORDER: Final[tuple[str, ...]] = (
    ATOMIC_PRIMITIVES_CHECK,
    BANNED_PATTERNS_CHECK,
    CONTROL_PLANE_CHECK,
    MOCKS_IN_SOURCE_CHECK,
)

# Map of canonical check name -> runner function.
_CHECK_DISPATCH: Final[
    dict[str, Any]
] = {
    ATOMIC_PRIMITIVES_CHECK: run_atomic_primitives,
    BANNED_PATTERNS_CHECK: run_banned_patterns,
    CONTROL_PLANE_CHECK: run_control_plane_writes,
    MOCKS_IN_SOURCE_CHECK: run_mocks_in_source,
}

# -----------------------------------------------------------------------------
# Result types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one invariant check.

    ``status`` is one of:
      * ``pass``  -- the check ran successfully and produced zero findings
      * ``fail``  -- the check ran successfully and produced >=1 findings
      * ``error`` -- the check itself raised; ``error_envelope`` carries the
                     stderr-bound RELAY-CLI-VERIFY-SELF-INTERNAL details
    """

    name: str
    status: str  # "pass" | "fail" | "error"
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    error_envelope: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Project to canonical JSON dict shape used in stdout."""
        out: dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "details": [finding_to_dict(f) for f in self.findings],
        }
        if self.error_envelope is not None:
            out["error_envelope"] = self.error_envelope
        return out


@dataclass(frozen=True)
class RunnerResult:
    """Aggregate result of running every invariant check."""

    schema_version: str
    overall: str  # "pass" | "fail"
    checks: tuple[CheckResult, ...]
    invariants_checked: int
    failures: int
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        """Project to the canonical stdout JSON envelope shape."""
        return {
            "schema_version": self.schema_version,
            "overall": self.overall,
            "checks": [c.to_dict() for c in self.checks],
            "invariants_checked": int(self.invariants_checked),
            "failures": int(self.failures),
            "duration_ms": int(self.duration_ms),
        }


# -----------------------------------------------------------------------------
# Internal-failure envelope (VAL-W5-039)
# -----------------------------------------------------------------------------


def _build_internal_envelope(
    *, check_name: str, exception_class: str, message: str
) -> dict[str, Any]:
    """Construct the per-check internal-failure envelope.

    The envelope is intentionally narrow: ``code`` is the canonical wire
    token; ``message`` is short and prescriptive; ``details`` lists the
    failing check's name plus the exception class. The runner does NOT
    embed a Python traceback; per VAL-W5-039 the CLI must never emit
    ``Traceback (most recent call last):`` on stderr.
    """
    return {
        "code": "RELAY-CLI-VERIFY-SELF-INTERNAL",
        "message": (
            f"verify-self check {check_name!r} raised {exception_class}: "
            f"{message}"
        ),
        "details": {
            "check_name": check_name,
            "exception_class": exception_class,
        },
    }


# -----------------------------------------------------------------------------
# Public runner entry point
# -----------------------------------------------------------------------------


def run_all_checks(repo_root: Path) -> RunnerResult:
    """Run every invariant check against ``repo_root`` and aggregate results.

    The runner does NOT raise on per-check failures; failed checks
    contribute to ``failures`` count and flip ``overall`` to ``fail``.
    A check that raises is converted to a synthetic ``status: error``
    entry; that also counts as a failure (so the runner exits non-zero
    on any internal error per VAL-W5-039).
    """
    start_ns = time.perf_counter_ns()
    results: list[CheckResult] = []
    for name in CHECK_ORDER:
        runner = _CHECK_DISPATCH[name]
        try:
            check_name, findings = runner(repo_root)
            assert (
                check_name == name
            ), f"checker name mismatch: expected {name!r}, got {check_name!r}"
            status = "pass" if len(findings) == 0 else "fail"
            results.append(
                CheckResult(
                    name=name,
                    status=status,
                    findings=tuple(findings),
                )
            )
        except Exception as exc:  # noqa: BLE001 - VAL-W5-039 envelope wrap
            envelope = _build_internal_envelope(
                check_name=name,
                exception_class=type(exc).__name__,
                message=str(exc),
            )
            results.append(
                CheckResult(
                    name=name,
                    status="error",
                    findings=tuple(),
                    error_envelope=envelope,
                )
            )
    end_ns = time.perf_counter_ns()
    duration_ms = (end_ns - start_ns) // 1_000_000
    failures = sum(1 for r in results if r.status != "pass")
    overall = "pass" if failures == 0 else "fail"
    return RunnerResult(
        schema_version=VERIFY_SELF_RESULT_SCHEMA,
        overall=overall,
        checks=tuple(results),
        invariants_checked=len(CHECK_ORDER),
        failures=failures,
        duration_ms=duration_ms,
    )


__all__ = [
    "CHECK_ORDER",
    "CheckResult",
    "RunnerResult",
    "VERIFY_SELF_RESULT_SCHEMA",
    "run_all_checks",
]
