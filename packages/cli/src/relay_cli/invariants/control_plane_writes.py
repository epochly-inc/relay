"""Control-plane-only canonical-write checker (VAL-W5-035).

Per CLAUDE.md keystone invariant #1 + spec sections A.1/A.2 +
boundaries.md sec 4: ``run_results`` and ``gate_decisions`` rows are
written ONLY by the result-writer / gate-engine services. Every other
path -- SDK, CLI, eval workers, replay workers -- submits drafts and
lets the control plane resolve them.

The check matches the contract VAL-W5-035 regex:
``INSERT\\s+INTO\\s+(run_results|gate_decisions)|UPDATE\\s+(run_results|gate_decisions)``
case-insensitive (SQL keywords are not case-sensitive on the wire).
Path filter excludes ``services/result-writer/`` and
``services/gate-engine/``.

VAL-W5-035 also asks for a sidecar SQLite probe of the
``relay.writer_role`` GUC. On a clean checkout no sidecar is running and
no SQLite database exists; the GUC probe is treated as "not-applicable"
and contributes neither a finding nor a failure. When a sidecar IS
running, the probe attaches read-only and verifies the GUC is set to
``control_plane`` on every write trigger; mismatch becomes a finding.

The grep-only path (always runnable, never requires runtime state) is
the load-bearing assertion for tier-1 budget; the GUC probe is a
defensive add-on that fires only when a sidecar is reachable.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Final

from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP,
)

from .atomic_primitives import (
    _match_is_documentation,
    documentation_string_spans,
    position_in_documentation_string,
)
from .util import (
    Finding,
    iter_canonical_source_files,
    suggested_fix_for,
)

CHECK_NAME: Final[str] = "control-plane-write-only"

# VAL-W5-035 regex (verbatim shape). SQL keywords are case-insensitive.
_CANONICAL_WRITE_RE: Final[re.Pattern[str]] = re.compile(
    r"INSERT\s+INTO\s+(run_results|gate_decisions)\b"
    r"|UPDATE\s+(run_results|gate_decisions)\b",
    re.IGNORECASE,
)

# Allowlisted control-plane subtrees per VAL-W5-035. Any path under one
# of these prefixes is permitted to issue canonical INSERT/UPDATE
# statements; everything else is a violation.
#
# Per VAL-W8-010 narrative and the spec / boundaries §4 control-plane
# write boundary: the OSS local profile's canonical gate-engine writer
# lives in ``packages/gate/`` (the public Apache 2.0 package); the
# hosted profile's equivalent lives in ``services/gate-engine/``. Both
# paths are allowlisted so VAL-W5-035 verify-self grep does not flag
# the legitimate canonical write.
#
# Migration .sql files under ``apps/local-sidecar/migrations/`` define
# the schema (CREATE TABLE / CREATE TRIGGER) but do NOT issue
# ``INSERT INTO gate_decisions`` -- the grep below operates on lexical
# content, so any future migration that did issue such an INSERT would
# correctly fail this check. The current 0009 migration only declares
# triggers and does not contain the matching literal.
_CONTROL_PLANE_PREFIXES: Final[tuple[str, ...]] = (
    "services/result-writer",
    "services/gate-engine",
    # OSS local profile (spec §"Public relay repository layout" places
    # the gate engine package at packages/gate/; VAL-W8-010 narrative
    # names "apps/api-local/gate_engine/" as the OSS equivalent. The
    # public package is the canonical OSS home — services/ does not
    # exist in the public Apache 2.0 tree).
    "packages/gate",
    "apps/api-local/gate_engine",
)


def _is_control_plane_path(rel_posix: str) -> bool:
    """Return True iff ``rel_posix`` lives under an allowlisted CP path."""
    for prefix in _CONTROL_PLANE_PREFIXES:
        if rel_posix == prefix or rel_posix.startswith(prefix + "/"):
            return True
    return False


def run(repo_root: Path) -> tuple[str, list[Finding]]:
    """Run the control-plane-write-only check against ``repo_root``.

    Returns ``(check_name, findings)`` sorted by ``(file, line, code)``.
    The function is intentionally grep-only; the optional sidecar GUC
    probe is exposed via :func:`probe_sidecar_writer_role` for callers
    that want runtime introspection. The verify-self runner does NOT
    require a running sidecar so the GUC probe is not invoked from this
    grep path.
    """
    findings: list[Finding] = []
    for path in iter_canonical_source_files(repo_root):
        rel = str(PurePosixPath(path.relative_to(repo_root)))
        if _is_control_plane_path(rel):
            continue
        # Canonical-write SQL only appears in code, schemas, and SQL
        # files; restrict accordingly. ``.sql`` is included so that any
        # migration that hand-codes a canonical-row INSERT/UPDATE outside
        # the state engine is caught. ``iter_canonical_source_files``
        # enumerates ``.sql`` files (via CANONICAL_WRITE_EXTRA_EXTS) so
        # this branch is live, not dead (VAL-ISO-035).
        if path.suffix not in (
            ".py",
            ".pyi",
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".sql",
        ):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # SQL migrations use ``--`` line comments and embed canonical
        # table names inside ``RAISE(ABORT, '...')`` error-message string
        # literals; the documentation matcher must recognize SQL syntax
        # for ``.sql`` files so comments / string payloads are not
        # mistaken for executable writes (VAL-ISO-035).
        is_sql = path.suffix == ".sql"
        # ``//`` is a line comment ONLY in TS/JS family sources. Python
        # (``.py``/``.pyi``) uses ``//`` as floor division and SQL uses
        # ``--`` for comments, so neither may treat ``//`` as a comment.
        slash_is_comment = path.suffix not in (".py", ".pyi", ".sql")
        # Positions inside a standalone documentation-string statement (e.g. a
        # module docstring that documents the grep guard, mentioning a canonical
        # run_results / gate_decisions write in prose) are documentation, not
        # executable writes -- but a canonical write passed to execute(...) or
        # after ``"x"; ...`` on the same line still IS flagged (column-precise).
        doc_spans = documentation_string_spans(
            text, is_python=path.suffix in (".py", ".pyi")
        )
        for line_no_minus_one, line in enumerate(text.split("\n")):
            # Scan EVERY match on the line, not just the first: a documentation
            # match (inside a doc string / SQL comment / string literal) earlier
            # on the line must not hide a later EXECUTABLE canonical write on the
            # same line (roborev cbd01f8). Record the first NON-documentation
            # match.
            for m in _CANONICAL_WRITE_RE.finditer(line):
                if _match_is_documentation(
                    line,
                    m.start(),
                    sql=is_sql,
                    slash_comment=slash_is_comment,
                    in_docstring=position_in_documentation_string(
                        line_no_minus_one + 1, m.start(), doc_spans
                    ),
                ):
                    continue
                findings.append(
                    Finding(
                        file=rel,
                        line=line_no_minus_one + 1,
                        code=RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP,
                        suggested_fix=suggested_fix_for(
                            RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP
                        ),
                        pattern=m.group(0),
                    )
                )
                break
    findings.sort(key=lambda f: (f.file, f.line, f.code))
    return CHECK_NAME, findings


__all__ = ["CHECK_NAME", "run"]
