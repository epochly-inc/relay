#!/usr/bin/env python3
"""Scoped mutation-testing harness for Relay (the LOOP's measured convergence signal).

Mutation testing is the PRIMARY objective signal for the shakedown loop: it
mutates a target module and checks whether the module's tests KILL each mutant.
A SURVIVING mutant is a behavior the tests do not pin down -- i.e. a real test
gap (and often a latent bug). The loop drives surviving mutants to zero: each
survivor is either killed by a new TDD test or justified in writing as an
equivalent mutant / out of scope.

This wraps ``cosmic-ray`` (chosen over mutmut 3.x: cleaner standalone-TOML,
mutate-in-place model that works with the uv editable workspace) and runs ONE
target at a time with that module's targeted tests, so a pass is fast (seconds-
to-minutes) and the kill-rate is attributable.

Targets are the parity-critical + control-plane modules per the shakedown goal.
Each target declares its module path and the test files that exercise it; the
test selection must be broad enough that a real behavior is killed by SOME
listed test (otherwise the harness reports false survivors).

Usage::

    python scripts/run-mutation.py --list                 # list targets
    python scripts/run-mutation.py --target network_policy # run one target
    python scripts/run-mutation.py --target network_policy --json
    python scripts/run-mutation.py --baseline-only --target network_policy

Exit codes: 0 = ran (see kill-rate / survivors in output); 2 = invocation or
baseline error (target tests do not pass on un-mutated source -- fix that
first). NOTE: a nonzero survivor count does NOT fail the process; triage is a
human/loop decision, surfaced in the report, not a hard gate here.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]

# Parity-critical + control-plane targets. module = path to mutate (relative to
# REPO_ROOT); test_groups = lists of test files, each GROUP run in its OWN
# pytest process and chained with `&&` so a mutant is killed if ANY group fails.
# Separate processes are required because cross-package test files do not
# always compose in one process (different conftests / module-global state); a
# mutant must be exercised by the UNION of all groups for an accurate kill-rate.
# Extend as the loop widens coverage; every group must pass on un-mutated source.
TARGETS: Final[dict[str, dict[str, object]]] = {
    "network_policy": {
        "module": "packages/sdk-python/relay/network_policy.py",
        "test_groups": [
            [
                "packages/sdk-python/tests/test_audit_r3_ssrf.py",
                "packages/sdk-python/tests/test_ssrf_numeric_and_transition_forms.py",
                "packages/sdk-python/tests/test_ssrf_decorated_host_normalization.py",
                "packages/sdk-python/tests/test_iso018_ssrf_ipv4_mapped_ipv6.py",
                "packages/sdk-python/tests/test_v3m5_idn_homograph_sdk.py",
            ],
            # Separate process: this hardening file fails 5 SSRF tests if run in
            # the SAME process (cross-package conftest/state pollution -- a real
            # test-isolation finding) but composes fine on its own.
            ["tests/hardening/test_v2m08_ai_hardening.py"],
        ],
        "why": "SSRF egress classifier + manifest homograph guard; Py<->TS parity-critical.",
    },
}

# Per-mutant wall budget (s). Mutants that hang (infinite loop) are killed by
# this timeout and scored as killed-by-timeout.
_MUTANT_TIMEOUT_S: Final[float] = 30.0


_PYTEST_BASE: Final[str] = "python -m pytest -x -q --no-header -p no:cacheprovider"


def _pytest_cmd(test_groups: list[list[str]]) -> str:
    """One `&&`-chained command: each group is its own pytest process, so a
    mutant survives only if EVERY group passes (killed if any fails)."""
    return " && ".join(f"{_PYTEST_BASE} {' '.join(g)}" for g in test_groups)


def _baseline_ok(test_groups: list[list[str]]) -> tuple[bool, str]:
    """Every group MUST pass on un-mutated source (each in its own process,
    mirroring how cosmic-ray runs the chained command)."""
    for group in test_groups:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "-q", "--no-header",
             "-p", "no:cacheprovider", *group],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if proc.returncode != 0:
            tail = "\n".join(proc.stdout.strip().splitlines()[-3:])
            return False, f"group {group}:\n{tail}"
    return True, "all groups green"


def _write_config(
    module: str, test_groups: list[list[str]], cfg_path: Path
) -> None:
    body = (
        "[cosmic-ray]\n"
        f'module-path = "{module}"\n'
        f"timeout = {_MUTANT_TIMEOUT_S}\n"
        "excluded-modules = []\n"
        f'test-command = "{_pytest_cmd(test_groups)}"\n\n'
        "[cosmic-ray.distributor]\n"
        'name = "local"\n'
    )
    cfg_path.write_text(body, encoding="utf-8")


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )


def run_target(name: str, *, emit_json: bool, baseline_only: bool) -> int:
    target = TARGETS[name]
    module = str(target["module"])
    test_groups = [list(g) for g in target["test_groups"]]  # type: ignore[union-attr]

    ok, tail = _baseline_ok(test_groups)
    if not ok:
        print(
            f"FAIL: baseline tests for target {name!r} do not pass on un-mutated "
            f"source -- fix first.\n{tail}",
            file=sys.stderr,
        )
        return 2
    if baseline_only:
        print(f"PASS: baseline green for {name} ({module}).\n{tail}")
        return 0

    tmp = Path(tempfile.mkdtemp(prefix=f"cr-{name}-"))
    cfg = tmp / "config.toml"
    session = tmp / "session.sqlite"
    _write_config(module, test_groups, cfg)

    init = _run(["cosmic-ray", "init", str(cfg), str(session)])
    if init.returncode != 0:
        print(f"FAIL: cosmic-ray init: {init.stderr.strip()}", file=sys.stderr)
        return 2
    _run(["cosmic-ray", "exec", str(cfg), str(session)])

    # cr-rate prints the survival rate; cr-report lists per-mutant outcomes.
    rate = _run(["cr-rate", "--estimate", "--confidence", "95.0", str(session)])
    report = _run(["cr-report", "--show-output", str(session)])

    survivors = [
        ln for ln in report.stdout.splitlines() if "survived" in ln.lower()
    ]
    total = sum(
        1 for ln in report.stdout.splitlines() if "test outcome:" in ln.lower()
    )
    result = {
        "target": name,
        "module": module,
        "survival_rate_pct": rate.stdout.strip(),
        "total_mutants_reported": total,
        "survivors": survivors,
        "session_dir": str(tmp),
    }
    if emit_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"TARGET {name} ({module})")
        print(f"  survival rate: {rate.stdout.strip()}")
        print(f"  surviving mutants ({len(survivors)}):")
        for s in survivors[:200]:
            print(f"    {s}")
        print(f"  session: {tmp} (cr-report {session} for full detail)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list", action="store_true", help="list targets")
    p.add_argument("--target", choices=sorted(TARGETS), help="run one target")
    p.add_argument("--all", action="store_true", help="run every target")
    p.add_argument("--json", action="store_true", dest="emit_json")
    p.add_argument(
        "--baseline-only",
        action="store_true",
        help="only verify the target's tests pass on un-mutated source",
    )
    args = p.parse_args(argv)

    if args.list or (not args.target and not args.all):
        for name, t in sorted(TARGETS.items()):
            print(f"{name:24s} {t['module']}")
            print(f"{'':24s} -> {t['why']}")
        return 0

    names = sorted(TARGETS) if args.all else [args.target]
    rc = 0
    for name in names:
        rc = run_target(name, emit_json=args.emit_json, baseline_only=args.baseline_only) or rc
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
