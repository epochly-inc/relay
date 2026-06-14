"""ISO-035 regression: control-plane-write check must enumerate .sql files.

Reproduces VAL-ISO-035. The control-plane-write checker
(``relay_cli.invariants.control_plane_writes.run``) documents a ``.sql``
branch in its per-file suffix allowlist and claims to scan migration
``.sql`` files for direct ``run_results`` / ``gate_decisions`` writes
outside the control-plane prefixes. But the file enumerator
(``util.iter_canonical_source_files`` -> ``iter_source_files`` ->
``_walk_root``) filters candidate paths to ``util.SOURCE_EXTS``, which
does NOT include ``.sql``. So no ``.sql`` file is ever yielded to the
check and the ``.sql`` branch is dead: a forbidden canonical write in a
``.sql`` migration is silently passed.

RED at base commit (no finding produced); GREEN after ``.sql`` is added
to the enumeration extension set.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from relay_cli.invariants import control_plane_writes
from relay_cli.invariants.util import (
    CANONICAL_WRITE_EXTRA_EXTS,
    iter_canonical_source_files,
)
from verify_self.finding_codes import (
    RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP,
)


def _make_clean_tree(root: Path) -> None:
    """Create a minimal relay-like tree with one clean python file."""
    src = root / "packages" / "okpkg" / "src"
    src.mkdir(parents=True)
    (src / "module.py").write_text(
        '"""Clean module."""\n\n\ndef helper() -> int:\n    return 42\n',
        encoding="utf-8",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_canonical_write_in_sql_outside_cp_is_detected(tmp_path: Path) -> None:
    """A forbidden canonical write in a .sql file outside CP prefixes fails.

    This is the load-bearing regression: prior to the fix the .sql file
    is never enumerated, so the check returns zero findings and silently
    passes. After the fix the .sql file is scanned and the direct
    ``INSERT INTO gate_decisions`` is reported.
    """
    _make_clean_tree(tmp_path)
    mig_dir = tmp_path / "packages" / "okpkg" / "migrations"
    mig_dir.mkdir(parents=True)
    (mig_dir / "0001_bad.sql").write_text(
        "-- a migration that hand-codes a canonical write\n"
        "INSERT INTO gate_decisions (id, status) VALUES (1, 'accepted');\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert any(
        f.file.endswith("0001_bad.sql")
        and f.code == RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP
        for f in findings
    ), (
        "expected a canonical-write finding on the .sql migration; got "
        + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_sql_extension_is_enumerated(tmp_path: Path) -> None:
    """The canonical iterator MUST yield .sql files for the check to scan."""
    _make_clean_tree(tmp_path)
    mig_dir = tmp_path / "packages" / "okpkg" / "migrations"
    mig_dir.mkdir(parents=True)
    sql_path = mig_dir / "0001_schema.sql"
    sql_path.write_text("CREATE TABLE t (id INTEGER);\n", encoding="utf-8")

    yielded = list(iter_canonical_source_files(tmp_path))
    assert any(p.name == "0001_schema.sql" for p in yielded), (
        "iter_canonical_source_files must yield .sql files; got "
        + repr([p.name for p in yielded])
    )
    assert ".sql" in CANONICAL_WRITE_EXTRA_EXTS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_canonical_write_in_sql_inside_cp_is_exempt(tmp_path: Path) -> None:
    """A canonical write in a .sql file UNDER a CP prefix stays exempt.

    Guards against the fix becoming over-broad: the legitimate gate-engine
    migration may legitimately hand-code the canonical INSERT.
    """
    _make_clean_tree(tmp_path)
    cp_dir = tmp_path / "packages" / "gate" / "migrations"
    cp_dir.mkdir(parents=True)
    (cp_dir / "0001_writer.sql").write_text(
        "INSERT INTO gate_decisions (id, status) VALUES (1, 'accepted');\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert not any(f.file.endswith("0001_writer.sql") for f in findings), (
        "canonical write under packages/gate/ must remain exempt; got "
        + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_clean_sql_produces_no_finding(tmp_path: Path) -> None:
    """A .sql file with no canonical write produces no false positive."""
    _make_clean_tree(tmp_path)
    mig_dir = tmp_path / "packages" / "okpkg" / "migrations"
    mig_dir.mkdir(parents=True)
    (mig_dir / "0001_schema.sql").write_text(
        "CREATE TABLE replay_cases (id INTEGER PRIMARY KEY);\n"
        "INSERT INTO replay_cases (id) VALUES (1);\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert findings == [], (
        "clean .sql must not produce a finding; got " + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_sql_comment_and_string_literal_are_not_false_positives(
    tmp_path: Path,
) -> None:
    """Canonical table names in SQL ``--`` comments and string literals
    (e.g. a ``RAISE(ABORT, '...')`` error message) MUST NOT be flagged.

    Enabling .sql scanning would otherwise surface these non-executable
    mentions as false positives; the documentation matcher recognizes
    SQL line comments and string-literal payloads.
    """
    _make_clean_tree(tmp_path)
    mig_dir = tmp_path / "packages" / "okpkg" / "migrations"
    mig_dir.mkdir(parents=True)
    (mig_dir / "0001_triggers.sql").write_text(
        "-- a CHECK trigger on INSERT INTO gate_decisions documented here\n"
        "CREATE TRIGGER t BEFORE INSERT ON gate_decisions\n"
        "BEGIN\n"
        "    SELECT RAISE(ABORT, 'only the writer may INSERT INTO "
        "gate_decisions');\n"
        "END;\n"
        "CREATE TABLE x (id INTEGER); -- trailing INSERT INTO run_results note\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert findings == [], (
        "SQL comments / string literals must not be false positives; got "
        + repr(findings)
    )


# ---------------------------------------------------------------------------
# Docstring-region suppression must NOT mask an executable triple-quoted SQL
# write (roborev a2adc74). A string passed to execute() is a Call ARGUMENT, not
# a docstring -- suppressing every multi-line Python string would let an
# unauthorized canonical write hide inside a triple-quoted SQL literal. Only
# true docstrings / bare string-expression statements are prose.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_canonical_write_in_triple_quoted_py_string_is_detected(
    tmp_path: Path,
) -> None:
    """A canonical write inside a TRIPLE-QUOTED SQL string passed to execute()
    (a Call argument, NOT a docstring) MUST be flagged -- docstring suppression
    must not skip it."""
    _make_clean_tree(tmp_path)
    src = tmp_path / "packages" / "okpkg" / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "writer.py").write_text(
        '"""Module docstring (prose)."""\n'
        "\n"
        "\n"
        "def write(conn) -> None:\n"
        "    conn.execute(\n"
        '        """\n'
        "        INSERT INTO run_results (id, status) VALUES (1, 'accepted')\n"
        '        """\n'
        "    )\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert any(
        f.file.endswith("writer.py")
        and f.code == RELAY_VERIFY_SELF_CANONICAL_WRITE_OUTSIDE_CP
        for f in findings
    ), (
        "an executable triple-quoted INSERT passed to execute() MUST be flagged; "
        "got " + repr(findings)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-035")
def test_canonical_write_in_module_docstring_is_not_flagged(
    tmp_path: Path,
) -> None:
    """A canonical-write pattern mentioned in a MULTI-LINE module docstring
    (prose, a bare string-expression statement) MUST NOT be flagged."""
    _make_clean_tree(tmp_path)
    src = tmp_path / "packages" / "okpkg" / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "doc.py").write_text(
        '"""Module.\n'
        "\n"
        "This module is the only writer; a grep guard enforces that no other\n"
        "module emits INSERT INTO run_results or UPDATE gate_decisions.\n"
        '"""\n'
        "\n"
        "\n"
        "def helper() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )

    _name, findings = control_plane_writes.run(tmp_path)

    assert not any(f.file.endswith("doc.py") for f in findings), (
        "a canonical-write pattern mentioned in a module docstring must NOT be "
        "flagged; got " + repr(findings)
    )
