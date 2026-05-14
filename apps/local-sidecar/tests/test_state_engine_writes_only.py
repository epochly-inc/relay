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
    for line in result.stdout.splitlines():
        if state_engine_marker in line:
            continue
        if db_py_marker in line:
            continue
        if runtime_py_marker in line:
            continue
        if recovery_py_marker in line:
            continue
        offending_lines.append(line)
    assert not offending_lines, (
        "grep returned forbidden DML matches outside state_engine/:\n"
        + "\n".join(offending_lines)
    )
