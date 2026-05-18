"""Audit R3 P1 misc fix -- ``rly contract check`` YAML support.

Covers:
  * BUG-E7  ``cmd_contract_check`` MUST scan *.yaml and *.yml in addition
            to *.json. Previously YAML contract files were silently
            skipped, producing false-PASS coverage reports.

The fix wires a single ``parse_contract`` path through both JSON and
YAML serializations. YAML parse failures emit ``RELAY-CONTRACT-PARSE-001``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

import pytest
import typer
import yaml
from relay_cli.commands.contract import cmd_contract_check


def _capture_stdout(callable_fn, *args, **kwargs) -> tuple[int, str]:
    """Run ``callable_fn`` and capture stdout + the exit code.

    cmd_contract_check raises ``typer.Exit`` to signal a non-zero exit.
    """
    buf = StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    code = 0
    try:
        callable_fn(*args, **kwargs)
    except typer.Exit as exc:
        code = exc.exit_code if hasattr(exc, "exit_code") else 1
    finally:
        sys.stdout = old_stdout
    return code, buf.getvalue()


@pytest.mark.plumbing
def test_contract_check_scans_yaml_files(tmp_path: Path) -> None:
    """A directory with only YAML contracts MUST be parsed (not silently
    skipped). The pre-fix code returned files_checked=0 / pass; the
    post-fix code parses each YAML and reports coverage_valid based on
    actual content.
    """
    yaml_doc = {
        "schema_version": "relay.assertion.behavioral.v1",
        "assertion_id": "VAL-AUDIT-R3-001",
        "kind": "behavioral",
        "severity": "P2",
        "expression": "true",
        "owner_email": "audit-r3@example.com",
        "lifecycle_state": "active",
    }
    (tmp_path / "a.yaml").write_text(yaml.safe_dump(yaml_doc))
    code, out = _capture_stdout(cmd_contract_check, str(tmp_path), False)
    payload = json.loads(out.splitlines()[-1]) if out.strip() else {}
    # files_checked > 0 proves the YAML was scanned (pre-fix would be 0).
    assert payload.get("files_checked", 0) >= 1, (
        f"YAML file was silently skipped; payload={payload}"
    )


@pytest.mark.plumbing
def test_contract_check_yaml_parse_error_surfaces_code(tmp_path: Path) -> None:
    """An unparseable YAML file MUST emit a parse_error violation tagged
    with code RELAY-CONTRACT-PARSE-001 (not silently pass).
    """
    (tmp_path / "broken.yaml").write_text("foo: [unclosed\n")
    code, out = _capture_stdout(cmd_contract_check, str(tmp_path), False)
    # cmd_contract_check writes the result via emit_json; the JSON payload
    # is on the last non-empty line.
    payload_line = next(
        (line for line in reversed(out.splitlines()) if line.strip()),
        "",
    )
    payload = json.loads(payload_line) if payload_line else {}
    violations = payload.get("violations", [])
    assert any(
        v.get("code") == "RELAY-CONTRACT-PARSE-001"
        for v in violations
    ), f"expected RELAY-CONTRACT-PARSE-001 violation; got: {violations}"


@pytest.mark.plumbing
def test_contract_check_yml_extension_also_scanned(tmp_path: Path) -> None:
    """``.yml`` (single-l variant) MUST be scanned alongside ``.yaml``."""
    yaml_doc = {
        "schema_version": "relay.assertion.v1",
        "assertion_id": "VAL-AUDIT-R3-002",
        "expression": "true",
        "owner_email": "audit-r3@example.com",
        "priority": "P2",
        "status": "active",
        "title": "audit r3 yml fixture",
        "rationale": "test .yml suffix",
    }
    (tmp_path / "b.yml").write_text(yaml.safe_dump(yaml_doc))
    code, out = _capture_stdout(cmd_contract_check, str(tmp_path), False)
    payload_line = next(
        (line for line in reversed(out.splitlines()) if line.strip()),
        "",
    )
    payload = json.loads(payload_line) if payload_line else {}
    assert payload.get("files_checked", 0) >= 1, (
        f"YML file was silently skipped; payload={payload}"
    )
