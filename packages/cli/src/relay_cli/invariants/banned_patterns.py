"""Banned-pattern checker (VAL-W5-032).

Scans ``packages/``, ``services/`` (when present), and ``apps/`` for the
banned patterns enumerated in CLAUDE.md "BANNED COMMANDS AND PATTERNS"
plus the v0.1 mandatory validation protocol:

  1. ``TODO`` / ``FIXME`` / ``XXX`` / ``HACK`` markers
     (CLAUDE.md banned pattern #5 indirectly via "MANDATORY VALIDATION
     PROTOCOL"; contract VAL-W5-032).
  2. ``pkill`` / ``killall`` (CLAUDE.md banned pattern #1).
  3. ``pytest.mark.skip`` (CLAUDE.md banned pattern #7) outside test
     paths -- the assertion only catches non-test source paths so
     legitimate test-fixture skips remain possible (workers MUST still
     evaluate applicability per boundaries.md sec 7.5).
  4. Customer-facing banned product copy
     (``compliant`` / ``certified`` / ``AI Act-approved`` /
     ``guaranteed AI Act compliance``) per spec section J.5 +
     CLAUDE.md banned pattern #9.

Per VAL-W5-036 every finding carries
``{file, line, code, suggested_fix, pattern}``; the ``code`` is one of
the closed enum values from
:mod:`verify_self.finding_codes`.

The check is non-skippable. There is no ``--skip no-todo-fixme`` flag and
none MUST exist (VAL-W5-032 last sentence).

Determinism: file enumeration sorts by relative path; per-file scans walk
lines in order; final ``details`` are sorted by ``(file, line, code)``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_BANNED_COPY,
    RELAY_VERIFY_SELF_KILL_BY_NAME,
    RELAY_VERIFY_SELF_PYTEST_SKIP,
    RELAY_VERIFY_SELF_TODO_FIXME,
)

from .util import (
    Finding,
    iter_source_files,
    suggested_fix_for,
)

CHECK_NAME: Final[str] = "no-todo-fixme"

# Code-file extensions that the TODO/FIXME, kill-by-name, and pytest-skip
# detectors target. YAML/JSON files often hold canonical lists of banned
# tokens (e.g., the sidecar's anti-bypass marker enum at
# ``packages/schemas/raw/sidecar-config.yaml``); scanning them line-by-line
# would produce false positives. The contract VAL-W5-032 explicitly
# excludes ``*.md`` for the same reason.
_CODE_EXTS: Final[frozenset[str]] = frozenset(
    {".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
)

# Banned-copy detector is scoped to customer-facing CLI surfaces only,
# matching ``scripts/lint-banned-copy.py``'s ``cli-source-tree`` scope.
# Technical comments elsewhere in the codebase legitimately use words
# like "compliant" in the strict pattern-matching sense ("W1-compliant
# wire token") which is NOT the customer-facing marketing claim the
# spec section J.5 prohibits.
_BANNED_COPY_PREFIX: Final[str] = "packages/cli/src"

# -----------------------------------------------------------------------------
# Pattern detectors
# -----------------------------------------------------------------------------
# Each detector receives a single file's text plus its relative path string
# and yields zero-or-more (line_index_1based, code, raw_match) tuples. We
# scan line-by-line so the line numbers are stable; matches per line are
# deduplicated by (line, code) so a line containing both TODO and FIXME
# emits at most one finding per code.
#
# The detectors deliberately avoid matching in:
#   * ``# noqa: VERIFY-SELF-...`` directives (none defined; all marker
#     codes are non-skippable)
#   * ``__pycache__`` / generated trees (filtered upstream by the file
#     iterator)
#   * The verifier's own source files (``packages/cli/src/verify_self/``,
#     ``packages/cli/src/relay_cli/invariants/``, the verify-self command
#     module, the verify-self tests, and the lint-banned-copy script)
#     because they LEGITIMATELY mention every banned token in their docs
#     and patterns. The exempt set is enforced via path filtering in
#     :func:`iter_source_files`.

# Word-boundary markers for TODO/FIXME/XXX/HACK. Hash-prefix variants
# ("# TODO:", "// FIXME") and bare uppercase tokens both match.
_TODO_FIXME_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(TODO|FIXME|XXX|HACK)\b"
)

# Process-control banned-by-name patterns.  Matches ``pkill`` and
# ``killall`` as standalone tokens (word boundary on either side).
_KILL_BY_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\b(pkill|killall)\b")

# ``@pytest.mark.skip`` decorator (with optional ``(...)``).  The check
# only fires inside non-test source paths, so a well-formed test fixture
# that needs to skip a case still can; production code reaching for
# ``pytest.mark.skip`` is the violation.
_PYTEST_SKIP_RE: Final[re.Pattern[str]] = re.compile(
    r"@pytest\.mark\.skip\b"
)

# Banned product copy regex.  Mirrors the regex used by
# ``scripts/lint-banned-copy.py`` so the verify-self surface and the
# CI lint surface report identical violations.
_BANNED_COPY_RE: Final[re.Pattern[str]] = re.compile(
    r"\bcompliant\b|\bcertified\b|AI[. ]Act[. \-]approved|guaranteed[. ]AI[. ]Act",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Detector:
    code: str
    pattern: re.Pattern[str]


_DETECTORS: Final[tuple[_Detector, ...]] = (
    _Detector(RELAY_VERIFY_SELF_TODO_FIXME, _TODO_FIXME_RE),
    _Detector(RELAY_VERIFY_SELF_KILL_BY_NAME, _KILL_BY_NAME_RE),
    _Detector(RELAY_VERIFY_SELF_PYTEST_SKIP, _PYTEST_SKIP_RE),
    _Detector(RELAY_VERIFY_SELF_BANNED_COPY, _BANNED_COPY_RE),
)


def _detector_applies(detector_code: str, suffix: str, rel_posix: str) -> bool:
    """Return whether ``detector_code`` should fire for the given file.

    Per-detector scope rules:
      * TODO/FIXME/XXX/HACK   -- code files only (``_CODE_EXTS``)
      * pkill / killall       -- code files only (``_CODE_EXTS``)
      * @pytest.mark.skip     -- Python source only (``.py`` / ``.pyi``)
      * banned product copy   -- restricted to ``packages/cli/src/``
                                 (matches ``lint-banned-copy.py``'s
                                 ``cli-source-tree`` surface)
    """
    if detector_code == RELAY_VERIFY_SELF_BANNED_COPY:
        return rel_posix == _BANNED_COPY_PREFIX or rel_posix.startswith(
            _BANNED_COPY_PREFIX + "/"
        )
    if detector_code == RELAY_VERIFY_SELF_PYTEST_SKIP:
        return suffix in (".py", ".pyi")
    # TODO/FIXME and kill-by-name target code files only.
    return suffix in _CODE_EXTS


def _scan_lines(rel_path: str, text: str, suffix: str) -> Iterable[Finding]:
    """Yield findings for one file's text, line-by-line."""
    rel_posix = str(PurePosixPath(rel_path))
    # Pre-filter detectors to those whose scope applies to this file.
    applicable = tuple(
        det for det in _DETECTORS if _detector_applies(det.code, suffix, rel_posix)
    )
    if not applicable:
        return
    for line_no_minus_one, line in enumerate(text.split("\n")):
        line_no = line_no_minus_one + 1
        seen_on_line: set[str] = set()
        for det in applicable:
            if det.code in seen_on_line:
                continue
            m = det.pattern.search(line)
            if m is None:
                continue
            seen_on_line.add(det.code)
            yield Finding(
                file=rel_path,
                line=line_no,
                code=det.code,
                suggested_fix=suggested_fix_for(det.code),
                pattern=m.group(0),
            )


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the banned-pattern check against ``repo_root``.

    Returns a 2-tuple ``(check_name, findings)``. ``findings`` is sorted by
    ``(file, line, code)`` for byte-stable JSON output (VAL-W5-038).
    """
    findings: list[Finding] = []
    for path in iter_source_files(repo_root):
        rel = str(path.relative_to(repo_root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(_scan_lines(rel, text, path.suffix))
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
