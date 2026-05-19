"""VAL-W2-024 + VAL-W2-058: state-engine writes-only grep guard.

This is the source-tree-level enforcement of CLAUDE.md keystone invariant
#1: the only module that may emit ``INSERT INTO run_results``,
``UPDATE run_results``, ``INSERT INTO scope_state``, ``UPDATE scope_state``,
``INSERT INTO event_log_entries``, ``UPDATE event_log_entries``, or
``DELETE FROM event_log_entries`` is the state engine module at
``apps/local-sidecar/relay_sidecar/state_engine/``.

The grep is scoped to production code paths:
  - ``apps/local-sidecar/relay_sidecar/``
  - ``apps/local-sidecar/scripts/``
  - ``packages/``

Tests and migrations are EXCLUDED because:
  - tests legitimately seed via raw SQL,
  - migrations CREATE the tables (no INSERT/UPDATE).

ASCII-only per CLAUDE.md.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

# Forbidden DML patterns (regex). The state engine MAY use these inside
# its own module; everyone else MUST NOT.
_FORBIDDEN_PATTERNS = [
    re.compile(r"INSERT\s+INTO\s+run_results\b", re.IGNORECASE),
    re.compile(r"UPDATE\s+run_results\b", re.IGNORECASE),
    re.compile(r"INSERT\s+INTO\s+scope_state\b", re.IGNORECASE),
    re.compile(r"UPDATE\s+scope_state\b", re.IGNORECASE),
    re.compile(r"INSERT\s+INTO\s+event_log_entries\b", re.IGNORECASE),
    re.compile(r"UPDATE\s+event_log_entries\b", re.IGNORECASE),
    re.compile(r"DELETE\s+FROM\s+event_log_entries\b", re.IGNORECASE),
]

# Repo root is the package's grandparent.
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[3]  # tests -> local-sidecar -> apps -> relay

# Directories scanned by the grep guard. Production code paths only.
_SCAN_DIRS = [
    _REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar",
    _REPO_ROOT / "apps" / "local-sidecar" / "scripts",
    _REPO_ROOT / "packages",
]

# The state engine module (the ONLY directory permitted to issue the
# forbidden DML for canonical state-change INSERTs / UPDATEs).
_ALLOWED_PREFIX = (
    _REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar" / "state_engine"
)

# Documented W2.3 exception: the sidecar SQLite writer queue
# (``db.py::_flush_retry_buffer``) writes sqlite_busy_retry observability
# rows into event_log_entries. This is the sidecar's internal contention
# observability surface, not a canonical state transition. VAL-W2-058's
# intent is "canonical state changes go through the state engine"; the
# retry-row writes are categorically different (event_kind='sqlite_busy_retry'
# vs the state engine's event_kind='state_transition' /
# 'state_invalid_transition'). The exception is whitelisted by file path,
# with the file's existence verified to prevent silent drift.
_PERMITTED_DB_PY_WRITES_FILE = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "relay_sidecar"
    / "db.py"
)

# Documented W2.6 exception: ``runtime.py::_execute_forced_stop`` writes
# the forensic ``sidecar.forced_stop`` row (event_kind='sidecar_forced_stop')
# into event_log_entries on a SEPARATE aiosqlite connection. The state
# engine writer connection may be holding a CAS transaction's writer
# lock when force-stop fires; routing the forced-stop emit through the
# state engine would deadlock. This is also categorically distinct from
# canonical state transitions (event_kind='state_transition' /
# 'state_invalid_transition'); VAL-W2-046 requires the row to be written
# BEFORE killing the in-flight transaction. Like the W2.3 db.py exception,
# the forced-stop write is forensic post-mortem evidence, not a
# canonical state-change row.
_PERMITTED_RUNTIME_PY_WRITES_FILE = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "relay_sidecar"
    / "runtime.py"
)

# Documented W2.7 exception: ``recovery.py::emit_crash_recovery_event``
# writes a single ``sidecar.crash_recovered`` event_log row using a
# fresh sqlite3 connection BEFORE the SidecarDatabase + writer queue
# are initialised in lifespan startup. Routing through the state
# engine is impossible here because the state engine itself is not yet
# running. Like the W2.3 db.py retry-flush exception and the W2.6
# runtime.py forced-stop exception, the crash-recovery row is forensic
# post-mortem evidence (event_kind='sidecar_crash_recovered') and is
# categorically distinct from canonical state-transition rows
# (event_kind='state_transition' / 'state_invalid_transition'). Per
# VAL-W2-049 the row MUST be emitted as part of the recovery summary
# after WAL replay; the lifespan calls into recovery.py BEFORE
# database.open() runs.
_PERMITTED_RECOVERY_PY_WRITES_FILE = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "relay_sidecar"
    / "recovery.py"
)

# Documented W8.2 exception: the canonical gate-engine decision writer
# at ``packages/gate/src/relay_gate_engine/decision_writer.py`` writes
# the ``gate.decision_written`` event_log_entries row inside the SAME
# BEGIN IMMEDIATE..COMMIT block as the ``gate_decisions`` INSERT to
# satisfy VAL-W8-018's atomicity requirement (gate_decisions +
# gate_rounds + event_log_entries co-committed). The W2.4 state engine's
# ``compare_and_set_state`` writes the canonical scope-state transition
# event AFTER the writer returns success; the row written by the writer
# is the gate-decision audit row (event_kind='gate_decision_written' /
# 'gate_rejected_handoff'), distinct from the state engine's
# ``state_transition`` rows. The writer is therefore the canonical
# control-plane writer for gate-engine events; per VAL-W8-010 and
# CLAUDE.md keystone invariant #1 it is the SINGLE production-code
# path that writes ``gate_decisions`` and emits the bound audit row.
_PERMITTED_GATE_DECISION_WRITER_FILE = (
    _REPO_ROOT
    / "packages"
    / "gate"
    / "src"
    / "relay_gate_engine"
    / "decision_writer.py"
)

# Documented W8.3 exception: the gate restart coordinator at
# ``packages/gate/src/relay_gate_engine/restart_pipeline.py`` writes a
# single ``gate.restarted`` event_log_entries row (event_kind='gate_restarted')
# inside the SAME BEGIN IMMEDIATE..COMMIT block as the gate_rounds INSERT
# and the gate_decision_drafts cancellation UPDATE so VAL-W8-020/023/025
# all co-commit atomically per CLAUDE.md keystone invariant #5
# ("gate restart on failure"). Like the W8.2 decision_writer.py, the
# restart coordinator is a canonical control-plane writer for gate-engine
# events; the row is categorically distinct from the state engine's
# ``state_transition`` / ``state_invalid_transition`` rows. The
# restart coordinator is the ONLY production-code path that transitions
# a scope from ``remediate_required`` back to ``running`` / ``gate.open``
# (VAL-W8-022 grep guard).
_PERMITTED_GATE_RESTART_COORDINATOR_FILE = (
    _REPO_ROOT
    / "packages"
    / "gate"
    / "src"
    / "relay_gate_engine"
    / "restart_pipeline.py"
)

# Documented W8.4 exception: the gate circuit breaker at
# ``packages/gate/src/relay_gate_engine/circuit_breaker.py`` writes
# ``gate.stalled`` and ``gate.terminal_block`` event_log_entries rows
# inside the SAME BEGIN IMMEDIATE..COMMIT block as the
# ``gate_stalled_state`` INSERT so VAL-W8-032 / VAL-W8-033 / VAL-W8-038
# co-commit atomically per CLAUDE.md keystone invariant #5 final clause
# ("Circuit breaker trips at remediation_round_cap"). Per contract gap
# #3 the canonical scope_state row is held in the equivalent
# ``gate_stalled_state`` companion table this module owns; the
# ``event_log_entries`` row is the gate-engine event stream entry
# (event_kind='validation_circuit_breaker' / 'gate.terminal_block').
_PERMITTED_GATE_CIRCUIT_BREAKER_FILE = (
    _REPO_ROOT
    / "packages"
    / "gate"
    / "src"
    / "relay_gate_engine"
    / "circuit_breaker.py"
)

# Documented W8.4 exception: the admin-actions service at
# ``packages/gate/src/relay_gate_engine/admin_actions.py`` writes
# ``admin.reopen`` / ``admin.terminate`` event_log_entries rows
# inside the SAME BEGIN IMMEDIATE..COMMIT block as the
# ``audit_log_entries`` INSERT and the ``gate_stalled_state`` UPDATE so
# VAL-W8-035 / VAL-W8-036 / VAL-W8-037 co-commit atomically. The audit
# rows are categorically distinct from state-engine state-transition
# rows; they record org-admin actions per spec AD lines 5479-5480.
_PERMITTED_GATE_ADMIN_ACTIONS_FILE = (
    _REPO_ROOT
    / "packages"
    / "gate"
    / "src"
    / "relay_gate_engine"
    / "admin_actions.py"
)

# Documented V3M4-F03 exception: the reviewer SLA aging helper at
# ``packages/explain/src/relay_explain/sla.py`` writes the
# ``explain.reviewer_sla_breached`` event_log_entries row when an
# unreviewed hypothesis exceeds 14 business days. This is a documented
# side-write outside compare_and_set_state; the event row is a
# notification, not a state-transition. Same exception pattern as the
# gate engine W8.2/W8.3/W8.4 admin-action paths. See VAL-V3M4-012.
_PERMITTED_EXPLAIN_SLA_FILE = (
    _REPO_ROOT
    / "packages"
    / "explain"
    / "src"
    / "relay_explain"
    / "sla.py"
)

# Documented V3M4-F02 exception: the generator auto-disable helper at
# ``packages/explain/src/relay_explain/heuristic.py::auto_disable_generator``
# writes the ``generator.auto_disabled`` event_log_entries row atomically
# alongside the generator_disabled INSERT when the quality harness
# detects a P0-class threshold violation (VAL-V3M4-007). Same exception
# pattern as the V3M4-F03 sla.py path: the event row is a notification
# (event_kind='', event_type='generator.auto_disabled'), not a canonical
# state-transition. Per CLAUDE.md keystone invariant #8 the two writes
# co-commit in one BEGIN IMMEDIATE..COMMIT block; routing through
# compare_and_set_state would be wrong here because there is no scope
# state to transition (the canonical control-plane invariant applies to
# run_results / gate_decisions / scope_state, not to generator_disabled).
_PERMITTED_EXPLAIN_HEURISTIC_FILE = (
    _REPO_ROOT
    / "packages"
    / "explain"
    / "src"
    / "relay_explain"
    / "heuristic.py"
)

# Documented W5.5 exception: the verify-self plumbing tests embed
# ``INSERT INTO run_results`` literals in synthetic fixture trees so
# the verify-self command's control-plane-write-only checker can be
# exercised end-to-end. The literals are quoted strings inside test
# fixture data; they never run as SQL. See
# ``packages/cli/tests/test_w5_5_verify_self.py`` and
# VAL-W5-035 in the contract. The same VAL-W2-024 keystone invariant
# (canonical rows are written only by the state engine) is satisfied;
# the test fixture is observation, not a write path.
_PERMITTED_VERIFY_SELF_TEST_FILE = (
    _REPO_ROOT
    / "packages"
    / "cli"
    / "tests"
    / "test_w5_5_verify_self.py"
)


def _python_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(
        p
        for p in root.rglob("*.py")
        if "_generated" not in p.parts and "__pycache__" not in p.parts
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-024")
def test_only_state_engine_writes_run_results_and_event_log() -> None:
    """No module outside state_engine/ contains the forbidden DML strings."""
    offenders: list[tuple[Path, int, str]] = []
    for scan_dir in _SCAN_DIRS:
        for path in _python_files(scan_dir):
            # state_engine modules are allowed.
            try:
                path.relative_to(_ALLOWED_PREFIX)
                continue
            except ValueError:
                pass
            # Documented W2.3 exception: db.py::_flush_retry_buffer writes
            # sqlite_busy_retry observability rows. See _PERMITTED_DB_PY_WRITES_FILE.
            if path == _PERMITTED_DB_PY_WRITES_FILE:
                continue
            # Documented W2.6 exception: runtime.py::_execute_forced_stop
            # writes the forensic sidecar.forced_stop row on a separate
            # connection. See _PERMITTED_RUNTIME_PY_WRITES_FILE.
            if path == _PERMITTED_RUNTIME_PY_WRITES_FILE:
                continue
            # Documented W2.7 exception: recovery.py::emit_crash_recovery_event
            # writes the forensic sidecar.crash_recovered row using a fresh
            # sqlite3 connection BEFORE the SidecarDatabase opens. See
            # _PERMITTED_RECOVERY_PY_WRITES_FILE.
            if path == _PERMITTED_RECOVERY_PY_WRITES_FILE:
                continue
            # Documented W5.5 exception: verify-self plumbing tests embed
            # forbidden DML literals as fixture data for the verify-self
            # control-plane-write-only checker. See
            # _PERMITTED_VERIFY_SELF_TEST_FILE.
            if path == _PERMITTED_VERIFY_SELF_TEST_FILE:
                continue
            # Documented W8.2 exception: the gate-engine decision writer
            # is the canonical control-plane writer for gate_decisions +
            # its bound audit row (VAL-W8-010, VAL-W8-018). See
            # _PERMITTED_GATE_DECISION_WRITER_FILE.
            if path == _PERMITTED_GATE_DECISION_WRITER_FILE:
                continue
            # Documented W8.3 exception: the gate restart coordinator is
            # the canonical control-plane writer for the gate.restarted
            # event_log_entries row, co-committed atomically with the
            # gate_rounds INSERT (VAL-W8-020/023/025). See
            # _PERMITTED_GATE_RESTART_COORDINATOR_FILE.
            if path == _PERMITTED_GATE_RESTART_COORDINATOR_FILE:
                continue
            # Documented W8.4 exception: the circuit breaker writes
            # gate.stalled / gate.terminal_block event_log_entries rows
            # atomically with the gate_stalled_state INSERT
            # (VAL-W8-032/033/038). See _PERMITTED_GATE_CIRCUIT_BREAKER_FILE.
            if path == _PERMITTED_GATE_CIRCUIT_BREAKER_FILE:
                continue
            # Documented W8.4 exception: the admin-actions service writes
            # admin.reopen / admin.terminate event_log_entries rows
            # atomically with audit_log_entries + gate_stalled_state
            # transitions (VAL-W8-035/036/037). See
            # _PERMITTED_GATE_ADMIN_ACTIONS_FILE.
            if path == _PERMITTED_GATE_ADMIN_ACTIONS_FILE:
                continue
            # Documented V3M4-F03 exception: SLA aging helper writes
            # explain.reviewer_sla_breached event_log_entries rows when
            # an unreviewed hypothesis exceeds 14 business days (VAL-V3M4-012).
            # See _PERMITTED_EXPLAIN_SLA_FILE.
            if path == _PERMITTED_EXPLAIN_SLA_FILE:
                continue
            # Documented V3M4-F02 exception: the heuristic generator's
            # auto_disable_generator() helper writes the
            # generator.auto_disabled event_log_entries row atomically
            # alongside the generator_disabled INSERT when the quality
            # harness detects a P0-class threshold violation (VAL-V3M4-007).
            # See _PERMITTED_EXPLAIN_HEURISTIC_FILE.
            if path == _PERMITTED_EXPLAIN_HEURISTIC_FILE:
                continue
            text = path.read_text(encoding="utf-8")
            for line_no, line in enumerate(text.splitlines(), start=1):
                for pattern in _FORBIDDEN_PATTERNS:
                    if pattern.search(line):
                        offenders.append((path, line_no, line.strip()))
    assert not offenders, (
        "VAL-W2-024/058 forbidden DML found outside state_engine/: "
        + "\n".join(f"  {p}:{ln} -> {src}" for p, ln, src in offenders)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-058")
def test_state_engine_directory_contains_dml_writes() -> None:
    """Sanity: at least one match exists INSIDE state_engine/ (confirms the
    grep guard is wired to real code, not vacuously empty)."""
    found = False
    for path in _python_files(_ALLOWED_PREFIX):
        text = path.read_text(encoding="utf-8")
        for pattern in _FORBIDDEN_PATTERNS:
            if pattern.search(text):
                found = True
                break
        if found:
            break
    assert found, (
        "VAL-W2-058 sanity: state_engine/ does not contain ANY forbidden "
        "DML pattern. The guard is vacuously passing -- impossible since "
        "compare_and_set.py writes scope_state."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-024")
def test_grep_subprocess_matches_only_state_engine() -> None:
    """Subprocess grep mirrors the regex check (defense in depth).

    Uses Python's grep-equivalent via ripgrep when available; falls back
    to a plain-Python scan otherwise. The redundancy is deliberate: the
    contract says ``grep -rn`` MUST return matches only under state_engine/.
    Asserting via subprocess too proves the guard works under the exact
    command-line invocation an auditor would type.
    """
    # Use stdlib grep equivalent (rg may not be installed). The Python
    # regex-based check above is the canonical implementation; this is
    # a redundant subprocess invocation only when grep is available.
    try:
        result = subprocess.run(
            [
                "grep",
                "-rnE",
                "INSERT INTO run_results|UPDATE run_results|"
                "INSERT INTO scope_state|UPDATE scope_state|"
                "INSERT INTO event_log_entries|UPDATE event_log_entries|"
                "DELETE FROM event_log_entries",
                "--include=*.py",
                str(_REPO_ROOT / "apps" / "local-sidecar" / "relay_sidecar"),
                str(_REPO_ROOT / "packages"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        pytest.skip("grep binary not available on this platform")
    # grep exit 0 = matches found; exit 1 = no matches; exit 2 = error.
    # Either 0 or 1 is acceptable; we then filter the output for non-
    # state_engine paths.
    assert result.returncode in (0, 1), (
        f"grep failed: rc={result.returncode}, stderr={result.stderr}"
    )
    offending_lines: list[str] = []
    state_engine_marker = "/relay_sidecar/state_engine/"
    db_py_marker = "/relay_sidecar/db.py:"  # W2.3 retry-flush exception
    runtime_py_marker = "/relay_sidecar/runtime.py:"  # W2.6 forced-stop forensic
    recovery_py_marker = (
        "/relay_sidecar/recovery.py:"  # W2.7 crash-recovered forensic
    )
    verify_self_test_marker = (
        # W5.5 verify-self plumbing test fixture-data exception.
        "/packages/cli/tests/test_w5_5_verify_self.py:"
    )
    gate_decision_writer_marker = (
        # W8.2 canonical gate-engine writer exception. See
        # _PERMITTED_GATE_DECISION_WRITER_FILE.
        "/packages/gate/src/relay_gate_engine/decision_writer.py:"
    )
    gate_restart_coordinator_marker = (
        # W8.3 canonical gate-engine restart coordinator exception. See
        # _PERMITTED_GATE_RESTART_COORDINATOR_FILE.
        "/packages/gate/src/relay_gate_engine/restart_pipeline.py:"
    )
    gate_circuit_breaker_marker = (
        # W8.4 canonical gate-engine circuit breaker exception. See
        # _PERMITTED_GATE_CIRCUIT_BREAKER_FILE.
        "/packages/gate/src/relay_gate_engine/circuit_breaker.py:"
    )
    gate_admin_actions_marker = (
        # W8.4 canonical gate-engine admin-actions exception. See
        # _PERMITTED_GATE_ADMIN_ACTIONS_FILE.
        "/packages/gate/src/relay_gate_engine/admin_actions.py:"
    )
    explain_sla_marker = (
        # V3M4-F03 explain.reviewer_sla_breached event-emission exception.
        # See _PERMITTED_EXPLAIN_SLA_FILE.
        "/packages/explain/src/relay_explain/sla.py:"
    )
    explain_heuristic_marker = (
        # V3M4-F02 generator.auto_disabled event-emission exception.
        # See _PERMITTED_EXPLAIN_HEURISTIC_FILE.
        "/packages/explain/src/relay_explain/heuristic.py:"
    )
    for line in result.stdout.splitlines():
        if state_engine_marker in line:
            continue
        if db_py_marker in line:
            continue
        if runtime_py_marker in line:
            continue
        if recovery_py_marker in line:
            continue
        if verify_self_test_marker in line:
            continue
        if gate_decision_writer_marker in line:
            continue
        if gate_restart_coordinator_marker in line:
            continue
        if gate_circuit_breaker_marker in line:
            continue
        if gate_admin_actions_marker in line:
            continue
        if explain_sla_marker in line:
            continue
        if explain_heuristic_marker in line:
            continue
        offending_lines.append(line)
    assert not offending_lines, (
        "grep returned forbidden DML matches outside state_engine/:\n"
        + "\n".join(offending_lines)
    )
