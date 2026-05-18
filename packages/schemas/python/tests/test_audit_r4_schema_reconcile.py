"""Audit-R4 (2026-05-18) schema reconcile regression tests.

BUG-G1: the audit-R3 batch dropped the wire-level ``schema_version``
literal from the ``PUT /v1/gates`` and ``POST /v1/eval-runs`` responses
(see ``apps/local-sidecar/relay_sidecar/runtime.py:2731`` and
``runtime.py:3597``) on the rationale that Gate and EvalRun are internal
objects and not canonical persisted envelopes -- neither literal is
present in ``KNOWN_SCHEMA_IDS`` (``packages/evals/src/relay_evals/
templates/schema_match.py``), nor in ``envelopes.yaml``, nor in
``openapi.yaml``. The SAME audit-R3 batch nonetheless pinned the
literals as DDL ``CHECK (schema_version = '<literal>')`` on canonical
Postgres tables at:

    - ``packages/schemas/sql/0000_v2_parent_tables.sql:103-104`` (gates)
    - ``packages/evals/migrations/0001_eval_runs.sql:40-41``    (eval_runs)

That left ``relay.gate.v1`` and ``relay.eval_run.v1`` stranded as
DDL-only literals contradicting the wire-level decision and violating
CLAUDE.md keystone invariant #10 ("Engines refuse unknown versions on
write" -- the authoritative ``KNOWN_SCHEMA_IDS`` frozenset does not
contain these values, so an engine that consults it would refuse rows
the DDL was forcing it to write).

Audit-R4 resolution: drop both CHECK pins. This module is the regression
test: scan every ``.sql`` file under the relay repo, strip SQL line
comments, and assert that no ``CHECK`` clause anywhere persists either
forbidden literal.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[4]

# Sweep every .sql file under packages/ and apps/. The CLI / SDK /
# schemas / migrations / sidecar / evals / contracts surface all live
# under these two trees in the public relay/ repo.
_SQL_ROOTS: tuple[Path, ...] = (
    _REPO_ROOT / "packages",
    _REPO_ROOT / "apps",
)

# Forbidden literals per audit-R4. Both are stranded -- neither appears
# in KNOWN_SCHEMA_IDS, envelopes.yaml, or openapi.yaml. See the module
# docstring for the full rationale.
_FORBIDDEN_LITERALS: tuple[str, ...] = (
    "relay.gate.v1",
    "relay.eval_run.v1",
)


def _iter_sql_files() -> list[Path]:
    out: list[Path] = []
    for root in _SQL_ROOTS:
        if not root.is_dir():
            continue
        out.extend(sorted(root.rglob("*.sql")))
    return out


def _strip_sql_line_comments(text: str) -> list[tuple[int, str]]:
    """Return ``(lineno, content)`` tuples with ``--``-prefixed comment
    sections stripped.

    SQL line comments begin with ``--`` and run to end-of-line. Block
    comments (``/* ... */``) are uncommon in the relay codebase and
    are not stripped here; if a forbidden literal appears inside a
    block comment, the test reports it (a comment that mentions the
    forbidden literal is fine in non-CHECK contexts -- we only flag
    occurrences inside CHECK clauses, see below).
    """
    out: list[tuple[int, str]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        # Find the first ``--`` not inside a string literal. For the
        # SQL in this codebase strings are single-quoted; a naive scan
        # for ``--`` is sufficient because no string contains ``--``.
        comment_at = line.find("--")
        code = line if comment_at == -1 else line[:comment_at]
        out.append((idx, code))
    return out


# CHECK ( ... 'literal' ... ) -- non-greedy across the parenthesised
# CHECK expression. SQLite + Postgres both accept multi-line CHECK
# clauses, so we re-flatten the source before regex matching.
_CHECK_PATTERN = re.compile(
    r"CHECK\s*\(([^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)


def _check_clauses_in(code: str) -> list[str]:
    """Return the bodies of every ``CHECK ( ... )`` clause in ``code``.

    ``code`` is the SQL source with line comments stripped (block
    comments not stripped -- see ``_strip_sql_line_comments`` notes).
    """
    return _CHECK_PATTERN.findall(code)


@pytest.mark.plumbing
@pytest.mark.parametrize("forbidden", _FORBIDDEN_LITERALS)
def test_no_stranded_schema_version_check_literal(forbidden: str) -> None:
    """No ``CHECK`` clause anywhere may persist a forbidden literal.

    A literal is "forbidden" when it is NOT in ``KNOWN_SCHEMA_IDS``,
    NOT in ``envelopes.yaml``, and NOT in ``openapi.yaml``. The
    audit-R4 batch reconciles two such literals (``relay.gate.v1`` and
    ``relay.eval_run.v1``). This test fails with file:line context
    when a future PR re-introduces either literal in a CHECK.
    """
    offenders: list[str] = []
    for sql_path in _iter_sql_files():
        text = sql_path.read_text(encoding="utf-8")
        # Strip line comments BEFORE concatenating so a comment that
        # mentions the literal doesn't trigger the regex.
        code_lines = _strip_sql_line_comments(text)
        # Rebuild line offsets so we can report a meaningful lineno.
        # We scan one full file at a time joining with newline so
        # multi-line CHECK clauses are matched.
        joined = "\n".join(line for _, line in code_lines)
        for body in _check_clauses_in(joined):
            if forbidden in body:
                # Find the first line that actually contains the
                # forbidden literal post-comment-strip for reporting.
                for lineno, line in code_lines:
                    if forbidden in line:
                        rel = sql_path.relative_to(_REPO_ROOT)
                        offenders.append(f"{rel}:{lineno}: CHECK("
                                         f"... {forbidden!r} ...)")
                        break
    assert not offenders, (
        f"audit-R4 regression: forbidden literal {forbidden!r} found "
        f"inside CHECK clause(s):\n  " + "\n  ".join(offenders)
    )


@pytest.mark.plumbing
@pytest.mark.parametrize("forbidden", _FORBIDDEN_LITERALS)
def test_no_stranded_schema_version_default_literal(forbidden: str) -> None:
    """No persisted column may DEFAULT to a forbidden literal.

    Some legacy migrations declared a column with both
    ``DEFAULT '<literal>'`` AND a CHECK. The audit-R4 fix drops the
    column entirely, so neither the DEFAULT nor the CHECK should
    remain. Older migrations that created the column then later
    DROPped it are out of scope: this test does NOT flag historical
    DEFAULT clauses inside migrations whose terminal-state schema no
    longer has the column.

    We approximate "terminal state" by scanning only files whose name
    does NOT match a known historical-then-dropped pattern. The
    sidecar 0011_gate_circuit_breaker.sql created a gates table with
    schema_version DEFAULT 'relay.gate.v1' that 0023 later DROPs --
    that historical state is admissible and excluded here.
    """
    # Files that historically declare a column with the literal as a
    # DEFAULT but whose terminal state (after later migrations) has
    # the column DROPped. Reported once in the audit-R3 / R4 history
    # and not re-checked by this test.
    historical_then_dropped = {
        "apps/local-sidecar/migrations/0011_gate_circuit_breaker.sql",
    }
    offenders: list[str] = []
    default_pattern = re.compile(
        rf"DEFAULT\s+'{re.escape(forbidden)}'",
        re.IGNORECASE,
    )
    for sql_path in _iter_sql_files():
        rel = sql_path.relative_to(_REPO_ROOT).as_posix()
        if rel in historical_then_dropped:
            continue
        text = sql_path.read_text(encoding="utf-8")
        for lineno, code in _strip_sql_line_comments(text):
            if default_pattern.search(code):
                offenders.append(
                    f"{rel}:{lineno}: DEFAULT '{forbidden}'"
                )
    assert not offenders, (
        f"audit-R4 regression: forbidden literal {forbidden!r} found "
        f"as column DEFAULT:\n  " + "\n  ".join(offenders)
    )
