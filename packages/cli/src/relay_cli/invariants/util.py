"""Shared helpers for the ``rly verify-self`` invariant checkers.

Owns:

  * :class:`Finding` -- the canonical per-finding dataclass shape
    (VAL-W5-036 ``{file, line, code, suggested_fix}`` plus an optional
    ``pattern`` field carrying the matched literal so the JSON envelope
    is informative without being narrative).
  * :func:`iter_source_files` -- deterministic file enumeration over
    ``packages/``, ``services/`` (when present), ``apps/``. Filters
    excluded subtrees (``__pycache__``, codegen output, the verifier's
    own source files, tests, vendored ``node_modules``, generated
    schema typescript trees).
  * :func:`iter_canonical_source_files` -- variant of
    ``iter_source_files`` that does NOT exclude the verifier's own
    source files; used by the canonical-write check (VAL-W5-035) since
    the verifier never writes ``run_results`` itself but still needs a
    grep over the broader tree.
  * :func:`suggested_fix_for` -- canonical suggested-fix string per
    finding code. Stable; included in every finding row so machine
    consumers can render remediation guidance without hardcoding.
  * :func:`finding_to_dict` -- project a :class:`Finding` into the
    canonical JSON dict shape used in stdout.

Determinism rules:

  * File enumeration is sorted by relative POSIX path.
  * Excluded paths are matched on the relative path's POSIX form so
    Windows backslashes do not perturb ordering.
  * No wall-clock or random sources are referenced.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from verify_self.finding_codes import (
    FINDING_CODES,
    RELAY_VERIFY_SELF_BANNED_COPY,
    RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP,
    RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING,
    RELAY_VERIFY_SELF_KILL_BY_NAME,
    RELAY_VERIFY_SELF_MOCK_IN_SOURCE,
    RELAY_VERIFY_SELF_PRIMITIVE_BYPASS,
    RELAY_VERIFY_SELF_PYTEST_SKIP,
    RELAY_VERIFY_SELF_TODO_FIXME,
)

# -----------------------------------------------------------------------------
# Source-tree roots scanned by the verifier
# -----------------------------------------------------------------------------
#
# Per VAL-W5-032/033/034/035 the scan covers ``packages/``, ``services/``,
# and ``apps/``. ``services/`` is currently absent from the relay/ repo
# (the OSS profile ships only sidecar + CLI + sdk packages); a missing
# root contributes zero files but is NOT a verifier failure -- the
# tree may grow into ``services/`` in later milestones without breaking
# the runner.

SCAN_ROOTS: Final[tuple[str, ...]] = ("packages", "services", "apps")

# -----------------------------------------------------------------------------
# Source-file extensions
# -----------------------------------------------------------------------------
#
# The verifier targets text source. JSON / YAML schemas are scanned for
# banned product copy (mirrors the ``lint-banned-copy.py`` surface set)
# but NOT for TODO/FIXME or pytest markers because those fire only in
# code. To keep the scan single-pass and deterministic we use one
# extension allowlist for all checks; per-checker code-vs-pattern logic
# is enforced at the regex layer (e.g., the pytest-skip regex never
# matches outside .py source even if a JSON file happens to contain the
# substring).

SOURCE_EXTS: Final[frozenset[str]] = frozenset(
    {".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yaml", ".yml"}
)

# -----------------------------------------------------------------------------
# Excluded subtrees (path-prefix matches on POSIX-form relative path)
# -----------------------------------------------------------------------------
#
# The verifier excludes:
#   * Test paths (``tests/``, ``**/tests/``, ``test_*.py``,
#     ``**/test/`` for vitest, conformance harness fixtures).
#   * Generated codegen output trees.
#   * Vendored node_modules and Python virtualenvs.
#   * The verifier's OWN source files (this module's tree + the
#     verify-self command module + the banned-copy lint script): they
#     legitimately mention every banned token in their docs and regexes.
#   * The CLI's verify-self plumbing tests (test_w5_5_*.py): they
#     embed banned tokens in fixture data on purpose.
#
# The matcher tests EITHER:
#   * the relative path equals an excluded prefix exactly, OR
#   * the relative path starts with ``<prefix>/`` (POSIX-form).
#
# This avoids partial-name collisions ("packages/cli/tests" excludes
# "packages/cli/tests" and "packages/cli/tests/foo.py" but NOT
# "packages/cli/testsfoo.py").

# Subtree prefixes excluded from EVERY check.
_BASE_EXCLUDED_PREFIXES: Final[tuple[str, ...]] = (
    # Tests
    "tests",
    "packages/cli/tests",
    "packages/sdk-python/tests",
    "packages/sdk-typescript/test",
    "packages/sdk-typescript/.api",
    "packages/schemas/python/tests",
    "packages/evals/tests",
    "apps/local-sidecar/tests",
    "apps/replay-proxy/tests",
    # Generated codegen
    "packages/sdk-python/relay/_generated",
    "packages/schemas/python/relay_schemas/_generated",
    "packages/schemas/typescript",
    # Vendored / build dirs
    "node_modules",
    ".venv",
    "__pycache__",
    "packages/cli/node_modules",
    "packages/sdk-typescript/node_modules",
    "packages/schemas/typescript/node_modules",
)

# Subtree prefixes excluded ONLY from the "self-mention" checks
# (banned-patterns + mocks-in-source + atomic-primitives). These trees
# legitimately mention every banned literal (the verifier's own source
# is the obvious example; the lint script also spells every banned
# token in its regexes and documentation).
_SELF_MENTION_EXCLUDED_PREFIXES: Final[tuple[str, ...]] = (
    "packages/cli/src/verify_self",
    "packages/cli/src/relay_cli/invariants",
    "packages/cli/src/relay_cli/commands/verify_self.py",
    "packages/cli/src/relay_cli/evidence_bundle.py",
    "packages/cli/src/relay_cli/anti_bypass.py",
    "scripts/lint-banned-copy.py",
    # The sidecar's anti-bypass module also enumerates banned literals.
    "apps/local-sidecar/relay_sidecar/anti_bypass.py",
)


@dataclass(frozen=True)
class Finding:
    """One reported violation. VAL-W5-036 binding shape.

    ``pattern`` carries the matched literal substring (e.g. the actual
    ``TODO`` token in source). It is informational; the load-bearing
    machine fields are ``file``, ``line``, ``code``, and
    ``suggested_fix``.
    """

    file: str
    line: int
    code: str
    suggested_fix: str
    pattern: str = ""

    def __post_init__(self) -> None:
        # Defensive: every finding's code MUST be in the closed enum.
        # This keeps ad-hoc strings from leaking into the JSON envelope.
        if self.code not in FINDING_CODES:
            raise ValueError(
                f"finding code {self.code!r} not in closed enum FINDING_CODES"
            )


# -----------------------------------------------------------------------------
# Suggested-fix strings (one per finding code)
# -----------------------------------------------------------------------------
#
# Each finding code maps to one stable suggested-fix string. The strings
# are deliberately short and prescriptive; remediation prose lives in
# docs/.
#
# Codes outside this map fall back to a generic "see CLAUDE.md banned
# patterns" string -- but the closed enum + constructor guard mean every
# finding has a known code at construction time, so the fallback is dead
# in well-formed code paths.

_SUGGESTED_FIX_BY_CODE: Final[dict[str, str]] = {
    RELAY_VERIFY_SELF_TODO_FIXME: (
        "Remove the TODO/FIXME/XXX/HACK marker. Track the work in beads "
        "or a follow-up PR; do not ship the marker."
    ),
    RELAY_VERIFY_SELF_KILL_BY_NAME: (
        "Replace pkill/killall with PID-based signaling read from the "
        "sidecar lockfile (see apps/local-sidecar/relay_sidecar/lockfile.py)."
    ),
    RELAY_VERIFY_SELF_PYTEST_SKIP: (
        "Do not use pytest.mark.skip in non-test source. Evaluate "
        "applicability or move the marker to a properly placed test."
    ),
    RELAY_VERIFY_SELF_BANNED_COPY: (
        "Replace banned product copy (compliant/certified/AI Act-approved/"
        "guaranteed AI Act compliance) with the spec-permitted vocabulary "
        "(AI Act readiness evidence, evidence coverage, gaps, ready for "
        "auditor review). See spec section J.5."
    ),
    RELAY_VERIFY_SELF_MOCK_IN_SOURCE: (
        "Remove the mock import from production source. Mocks are "
        "test-only (CLAUDE.md banned pattern #4)."
    ),
    RELAY_VERIFY_SELF_PRIMITIVE_BYPASS: (
        "Route the persistent write through one of the four atomic "
        "primitives (transactional_db_write, object_put_with_digest, "
        "queue_publish_with_idempotency, local_atomic_file_write). See "
        "spec section H + CLAUDE.md keystone invariant #8."
    ),
    RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP: (
        "Canonical rows (run_results, gate_decisions) are written ONLY by "
        "the result-writer / gate-engine services. Submit a draft envelope "
        "via the SDK and let the control plane resolve it (CLAUDE.md "
        "keystone invariant #1)."
    ),
    RELAY_VERIFY_SELF_GATE_INVARIANT_MISSING: (
        "The W8.2 gate-engine SQL migration is missing one of the required "
        "triggers (gate_decisions_role_check, gate_decisions_no_update, "
        "gate_decisions_no_delete, gate_decisions_evidence_fk, "
        "gate_decisions_signature_required, "
        "gate_decisions_bundle_manifest_match). Re-run the migration or "
        "restore the trigger declaration in "
        "apps/local-sidecar/migrations/0009_gate_decision_writer.sql."
    ),
}


def suggested_fix_for(code: str) -> str:
    """Return the canonical suggested-fix string for a finding code."""
    return _SUGGESTED_FIX_BY_CODE.get(
        code,
        "See CLAUDE.md banned patterns + spec section S for remediation.",
    )


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Project a :class:`Finding` into the canonical JSON dict shape.

    Field order: ``file``, ``line``, ``code``, ``suggested_fix``,
    ``pattern``. ``pattern`` is omitted when empty so the envelope stays
    minimal for findings whose match identity is captured wholly by
    ``code``.
    """
    out: dict[str, object] = {
        "file": finding.file,
        "line": int(finding.line),
        "code": finding.code,
        "suggested_fix": finding.suggested_fix,
    }
    if finding.pattern:
        out["pattern"] = finding.pattern
    return out


# -----------------------------------------------------------------------------
# File enumeration
# -----------------------------------------------------------------------------


def _to_posix(path: Path, repo_root: Path) -> str:
    """Return the POSIX-form relative path of ``path`` under ``repo_root``."""
    return str(PurePosixPath(path.relative_to(repo_root)))


def _is_excluded(rel_posix: str, excluded_prefixes: tuple[str, ...]) -> bool:
    """Return whether ``rel_posix`` matches any excluded subtree prefix.

    Matching rule: exact-equality OR ``rel_posix.startswith(prefix + "/")``.
    Avoids partial-name collisions like ``tests`` matching ``testsfoo``.
    """
    for prefix in excluded_prefixes:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return True
    return False


def _walk_root(root: Path, repo_root: Path) -> Iterator[Path]:
    """Yield candidate source files under ``root`` deterministically.

    Walks the tree top-down with sorted entries so ordering is identical
    on every platform. Skips ``__pycache__`` directories at descent
    time for performance (the per-file exclusion check would also
    handle them, but pruning the descent avoids reading metadata for
    thousands of generated .pyc files on cold caches).
    """
    if not root.exists():
        return
    # rglob returns an unordered iterator; we sort by POSIX path string
    # for deterministic ordering.
    candidates = [p for p in root.rglob("*") if p.is_file()]
    candidates.sort(key=lambda p: _to_posix(p, repo_root))
    for path in candidates:
        if path.suffix not in SOURCE_EXTS:
            continue
        # Drop __pycache__ early.
        if "__pycache__" in path.parts:
            continue
        yield path


def iter_source_files(
    repo_root: Path,
    *,
    include_self: bool = False,
) -> Iterator[Path]:
    """Yield production source files under ``repo_root`` deterministically.

    ``include_self=False`` (default) excludes the verifier's own source
    files plus the banned-copy lint script -- those legitimately mention
    every banned token in their docs / regexes.

    ``include_self=True`` includes the verifier's own source files; used
    by the canonical-write check (VAL-W5-035) which never matches the
    verifier's own source anyway (the verifier never writes
    ``run_results``) but should not silently skip any tree.

    File extensions are filtered to :data:`SOURCE_EXTS`. Tests, generated
    codegen output, vendored node_modules, and ``__pycache__`` are
    always excluded.
    """
    excluded = list(_BASE_EXCLUDED_PREFIXES)
    if not include_self:
        excluded.extend(_SELF_MENTION_EXCLUDED_PREFIXES)
    excluded_t = tuple(excluded)

    for root_name in SCAN_ROOTS:
        root = repo_root / root_name
        for path in _walk_root(root, repo_root):
            rel = _to_posix(path, repo_root)
            if _is_excluded(rel, excluded_t):
                continue
            yield path


def iter_canonical_source_files(repo_root: Path) -> Iterator[Path]:
    """Variant of :func:`iter_source_files` for the canonical-write check.

    Behaves exactly like ``iter_source_files(repo_root, include_self=True)``
    -- the verifier's own source files are included so the grep is
    exhaustive across the tree. The check itself filters
    ``services/result-writer/`` and ``services/gate-engine/`` per
    VAL-W5-035.
    """
    return iter_source_files(repo_root, include_self=True)


__all__ = [
    "Finding",
    "SCAN_ROOTS",
    "SOURCE_EXTS",
    "finding_to_dict",
    "iter_canonical_source_files",
    "iter_source_files",
    "suggested_fix_for",
]
