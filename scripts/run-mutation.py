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
import ast
import json
import shlex
import sqlite3
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
    "redaction": {
        "module": "packages/sdk-python/relay/redaction.py",
        "test_groups": [
            [
                "packages/sdk-python/tests/test_redaction.py",
                "packages/sdk-python/tests/test_redaction_parity.py",
                "packages/sdk-python/tests/test_v2m08_redaction.py",
                "packages/sdk-python/tests/test_json_pointer_null_leaf_parity.py",
                "packages/sdk-python/tests/test_v3m5_hosted_default_policy.py",
                "packages/sdk-python/tests/test_v3m5_json_path_matcher.py",
            ],
            ["tests/hardening/test_v2m08_ai_hardening.py"],
        ],
        "why": "Redaction policy engine; Py<->TS byte-parity P0 (HMAC/JCS over intervals).",
    },
    "compare_and_set": {
        "module": "apps/local-sidecar/relay_sidecar/state_engine/compare_and_set.py",
        "test_groups": [
            [
                "apps/local-sidecar/tests/test_compare_and_set_state.py",
                "apps/local-sidecar/tests/test_state_engine_writes_only.py",
                "apps/local-sidecar/tests/test_state_transition_coverage.py",
                "apps/local-sidecar/tests/test_three_anchor_handoff.py",
                "apps/local-sidecar/tests/test_event_log_append_only.py",
                "apps/local-sidecar/tests/test_invalid_transition_secondary_error.py",
                "apps/local-sidecar/tests/test_iso028_invalid_transition_forensic_durable.py",
                "apps/local-sidecar/tests/test_iso029_handoff_guard_authenticated_actor.py",
                "apps/local-sidecar/tests/test_state_engine_event_log.py",
                "apps/local-sidecar/tests/test_state_engine_serializable.py",
                "apps/local-sidecar/tests/test_v2m03_state_guards.py",
                # Mutation-gap tests authored to kill real survivors (this loop):
                "apps/local-sidecar/tests/test_cas_gaps_main.py",
                "apps/local-sidecar/tests/test_cas_gaps_init_on_conn.py",
                "apps/local-sidecar/tests/test_cas_gaps_idempotency.py",
            ],
        ],
        "why": "compare_and_set_state -- keystone #1 (control plane writes the result).",
        # Logic-equivalent mutants justified in docs/architecture/mutation-equivalents.md
        # (class B). Each entry excludes survivors on `lines` whose operator
        # contains `op_contains`. See the doc for the per-class reasoning.
        "justified_equivalents": [
            {"lines": [678, 681, 684], "op_contains": "",
             "reason": "dead rowcount!=1 defensive block (single-writer in-txn)"},
            {"lines": [667], "op_contains": "NotEq_Gt", "reason": "rowcount==1: 1!=1==1>1"},
            {"lines": [667], "op_contains": "NotEq_Lt", "reason": "rowcount==1: 1!=1==1<1"},
            {"lines": [560, 767], "op_contains": "NumberReplacer",
             "reason": "dead else-0 arm of COALESCE-MAX seq read"},
            {"lines": [201, 585], "op_contains": "ExceptionReplacer",
             "reason": "defensive except BaseException (KeyboardInterrupt mid-txn)"},
            {"lines": [725, 309], "op_contains": "Eq_Is",
             "reason": "==/is identity equivalence (assigned-constant / small-int cache)"},
            {"lines": [266], "op_contains": "Mul_Div",
             "reason": "keyword-only * marker, no runtime arithmetic"},
        ],
    },
    "guards": {
        "module": "apps/local-sidecar/relay_sidecar/state_engine/guards.py",
        "test_groups": [
            [
                "apps/local-sidecar/tests/test_v2m03_state_guards.py",
                "apps/local-sidecar/tests/test_three_anchor_handoff.py",
                "apps/local-sidecar/tests/test_iso029_handoff_guard_authenticated_actor.py",
                "apps/local-sidecar/tests/test_http_boundary_handoff.py",
                "apps/local-sidecar/tests/test_gate_decision_draft_handoff.py",
                "apps/local-sidecar/tests/test_audit_r4_actors_kind_alignment.py",
                "apps/local-sidecar/tests/test_audit_v3_manifest_side_effect_binding.py",
            ],
            # Direct-unit suites: call each _guard_* predicate directly across
            # every internal branch (the transition-level tests above only
            # observe pass/fail at the CAS boundary, leaving the lenient /
            # mismatch / expired arms unpinned). Own pytest process.
            [
                "apps/local-sidecar/tests/test_guards_pred_registry.py",
                "apps/local-sidecar/tests/test_guards_pred_idem_manifest.py",
                "apps/local-sidecar/tests/test_guards_pred_settle_contracts_gates.py",
                "apps/local-sidecar/tests/test_guards_pred_handoff_draft_actions.py",
                "apps/local-sidecar/tests/test_guards_pred_sandbox_digest.py",
                "apps/local-sidecar/tests/test_guards_pred_signing_retention_round_admin.py",
            ],
        ],
        "why": "transition guards -- keystone #4 (three-anchor handoff) + actor/manifest binding.",
        # Logic equivalents triaged in writing (docs/architecture/mutation-equivalents.md
        # Class C). Each surviving mutant here changes the source but produces no
        # test-observable behavior; the killable +1 NumberReplacer siblings (row[1]
        # IndexError) ARE killed by the predicate tests, so only the unobservable
        # variant survives. The annotation `|`-mutants are auto-classified (Class A).
        "justified_equivalents": [
            {"lines": [243, 244, 277, 373, 409, 514, 515, 746, 783],
             "op_contains": "NumberReplacer",
             "reason": "single-column SELECT row[-1]==row[0], OR dead `else 0` arm "
                       "of `int(row[0]) if row is not None else 0` over COUNT(*)/"
                       "single-row fetchone (never None). +1 sibling row[1] raises "
                       "IndexError and is killed by existing tests; only the "
                       "unobservable -1/dead-arm variant survives."},
            {"lines": [278, 410, 747], "op_contains": "Eq_LtE",
             "reason": "`count/total == 0` vs `<= 0` over a non-negative COUNT(*) "
                       "result -- the operators cannot diverge for any input."},
            {"lines": [376], "op_contains": "Sub_BitXor",
             "reason": "set(required) - evaluated == set(required) ^ evaluated: "
                       "evaluated is always a subset of required (built from the "
                       "WHERE contract_id IN (required) projection)."},
            {"lines": [91], "op_contains": "Mul_Div",
             "reason": "bare `*` keyword-only marker in def register_guard(...,*,"
                       "override=...) is syntactic, not arithmetic; no runtime effect."},
        ],
    },
}

# Per-mutant wall budget (s). Mutants that hang (infinite loop) are killed by
# this timeout and scored as killed-by-timeout.
_MUTANT_TIMEOUT_S: Final[float] = 30.0


_PYTEST_BASE: Final[str] = "python -m pytest -x -q --no-header -p no:cacheprovider"


def _pytest_cmd(test_groups: list[list[str]]) -> str:
    """One command run as ``bash -c '<chained>'``: each group is its own pytest
    process (process isolation prevents cross-package conftest pollution), and a
    mutant survives only if EVERY group passes (killed if any group fails).

    The ``bash -c`` wrapper is REQUIRED, not cosmetic. cosmic-ray runs the
    test-command via ``shlex.split(command)`` with NO shell
    (cosmic_ray/testing.py:46), so a bare ``a && b`` would hand ``&&`` (and
    everything after it) to the FIRST pytest as literal argv tokens -- pytest
    then errors on every mutant and cosmic-ray records a FALSE 100% kill rate
    for ANY multi-group target. Routing through ``bash -c`` makes bash
    interpret the ``&&`` as a real shell operator. Group paths contain no
    single quotes, so single-quoting the inner command is safe under
    ``shlex.split`` (which yields ``['bash', '-c', '<chained>']``)."""
    inner = " && ".join(f"{_PYTEST_BASE} {' '.join(g)}" for g in test_groups)
    return f"bash -c '{inner}'"


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


def _remove_worktree(wt: Path) -> None:
    subprocess.run(  # noqa: S603
        ["git", "worktree", "remove", "--force", str(wt)],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )


def _make_worktree(name: str) -> Path:
    """Create an isolated git worktree at HEAD with its OWN uv venv.

    cosmic-ray mutates the source file IN PLACE (apply -> test -> revert per
    mutant), so running it in the main working tree races any concurrent
    test/git activity and leaves the tree transiently dirty. Running it in a
    throwaway worktree (the worktree's editable install points at the
    worktree's source) keeps the main tree pristine and lets runs parallelize.
    The uv venv is created from uv's global cache in ~1.5s."""
    wt = Path(tempfile.mkdtemp(prefix=f"relay-mut-wt-{name}-"))
    add = subprocess.run(  # noqa: S603
        ["git", "worktree", "add", "--detach", str(wt), "HEAD"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    if add.returncode != 0:
        raise RuntimeError(f"git worktree add failed: {add.stderr.strip()}")
    sync = subprocess.run(  # noqa: S603
        ["uv", "sync", "--all-packages", "--all-extras"],
        cwd=wt, capture_output=True, text=True, check=False, timeout=1200,
    )
    if sync.returncode != 0:
        _remove_worktree(wt)
        raise RuntimeError(f"uv sync in worktree failed: {sync.stderr[-400:]}")
    return wt


def _run_wt(wt: Path, cmd: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a venv command (cosmic-ray, cr-rate) inside the worktree via its own
    venv (uv run --project), so the mutated file is the worktree's, not the
    main tree's. The cosmic-ray test-command subprocess inherits the worktree
    venv on PATH."""
    return subprocess.run(  # noqa: S603
        ["uv", "run", "--project", str(wt), *cmd],
        cwd=wt, capture_output=True, text=True, check=False,
    )


def _worktree_baseline_ok(
    wt: Path, test_groups: list[list[str]]
) -> tuple[bool, str]:
    """Run cosmic-ray's EXACT test-command on UNMUTATED source INSIDE the worktree.

    cosmic-ray records a mutant KILLED whenever the test-command exits non-zero
    for ANY reason -- including a test that fails on unmutated source in the
    worktree's own environment (different venv, different cwd, or a cross-file
    event-loop/conftest interaction that the main tree does not exhibit). If that
    happens, EVERY mutant is scored KILLED and the run reports a FALSE 100% kill
    rate. The main-tree _baseline_ok CANNOT catch a worktree-only baseline
    failure, so we re-validate here, replicating cosmic-ray's own invocation
    exactly: ``shlex.split(test_command)`` run with no shell (the bash -c wrapper
    inside _pytest_cmd is what re-introduces shell semantics for the && chain).
    A run whose worktree baseline is red MUST abort and emit NO survival numbers."""
    proc = _run_wt(wt, shlex.split(_pytest_cmd(test_groups)))
    if proc.returncode != 0:
        tail = "\n".join(
            (proc.stdout + proc.stderr).strip().splitlines()[-10:]
        )
        return False, tail
    return True, "worktree baseline green"


def _annotation_binop_rows(module_path: str) -> set[int]:
    """Line numbers of every ``ast.BinOp`` that lives inside a type annotation
    (parameter ``annotation`` or function ``returns``). A bit-operator mutation
    on such a node (e.g. the ``|`` in ``str | None``) is an EQUIVALENT mutant:
    annotations carry no runtime behavior the tests can observe (and under
    ``from __future__ import annotations`` are not even evaluated), so the
    mutant survives by construction, not because of a test gap."""
    try:
        tree = ast.parse((REPO_ROOT / module_path).read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    anno_ids: set[int] = set()
    for node in ast.walk(tree):
        for field in ("annotation", "returns"):
            a = getattr(node, field, None)
            if a is not None:
                for sub in ast.walk(a):
                    anno_ids.add(id(sub))
    return {
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.BinOp) and id(n) in anno_ids
    }


def _classify_survivors(
    module: str,
    session: Path,
    justified: list[dict[str, object]] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return (real_survivors, equivalent_survivors) from a cosmic-ray session.

    Equivalent = a bit-operator mutation on a type-annotation line (auto-
    justified per _annotation_binop_rows) OR a survivor matching one of the
    target's ``justified_equivalents`` entries (logic equivalents justified in
    writing in docs/architecture/mutation-equivalents.md). Everything else is a
    REAL survivor that must be killed by a new TDD test."""
    justified = justified or []
    anno_rows = _annotation_binop_rows(module)
    real: list[dict[str, object]] = []
    equiv: list[dict[str, object]] = []
    con = sqlite3.connect(str(session))
    try:
        rows = con.execute(
            "SELECT ms.start_pos_row, ms.operator_name, ms.definition_name "
            "FROM mutation_specs ms JOIN work_results wr ON ms.job_id = wr.job_id "
            "WHERE wr.test_outcome = 'SURVIVED'"
        ).fetchall()
    finally:
        con.close()
    for row, op, defn in sorted(rows):
        rec: dict[str, object] = {"line": row, "operator": op, "function": defn}
        is_bitop = any(b in op for b in ("BitOr", "BitAnd", "BitXor"))
        match = next(
            (
                j
                for j in justified
                if row in j["lines"]  # type: ignore[operator]
                and str(j["op_contains"]) in op
            ),
            None,
        )
        if is_bitop and row in anno_rows:
            rec["reason"] = "annotation bit-op (PEP 563, no runtime effect)"
            equiv.append(rec)
        elif match is not None:
            rec["reason"] = str(match["reason"])
            equiv.append(rec)
        else:
            real.append(rec)
    return real, equiv


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

    # Run cosmic-ray inside an isolated worktree so it never mutates the main
    # working tree. config + session live outside the worktree (absolute paths);
    # the relative module-path / test paths in the config resolve against the
    # worktree (cwd) so the worktree's copy is mutated and its venv runs tests.
    wt = _make_worktree(name)
    try:
        wt_ok, wt_tail = _worktree_baseline_ok(wt, test_groups)
        if not wt_ok:
            print(
                f"FAIL: WORKTREE baseline for {name!r} is RED on un-mutated source. "
                f"Running anyway would score EVERY mutant KILLED and report a FALSE "
                f"100% kill rate. Aborting -- emitting no survival numbers. Fix the "
                f"worktree baseline (env mismatch or cross-file test interaction) "
                f"first.\n{wt_tail}",
                file=sys.stderr,
            )
            return 3
        init = _run_wt(wt, ["cosmic-ray", "init", str(cfg), str(session)])
        if init.returncode != 0:
            print(f"FAIL: cosmic-ray init: {init.stderr.strip()}", file=sys.stderr)
            return 2
        _run_wt(wt, ["cosmic-ray", "exec", str(cfg), str(session)])
        # cr-rate prints the raw survival rate (counts equivalent mutants too).
        rate = _run_wt(wt, ["cr-rate", str(session)])
    finally:
        _remove_worktree(wt)
    justified = target.get("justified_equivalents")  # type: ignore[union-attr]
    real, equiv = _classify_survivors(
        module, session, justified if isinstance(justified, list) else None
    )
    result = {
        "target": name,
        "module": module,
        "raw_survival_rate_pct": rate.stdout.strip(),
        "real_survivors": real,
        "real_survivor_count": len(real),
        "equivalent_survivors": equiv,
        "equivalent_survivor_count": len(equiv),
        "session_dir": str(tmp),
    }
    if emit_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"TARGET {name} ({module})")
        print(f"  raw survival rate: {rate.stdout.strip()}")
        print(
            f"  equivalent survivors (auto-justified, annotation bit-ops): "
            f"{len(equiv)}"
        )
        print(f"  REAL survivors needing triage ({len(real)}):")
        for s in real[:300]:
            print(f"    L{s['line']:<5} {s['function']}  [{s['operator']}]")
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
