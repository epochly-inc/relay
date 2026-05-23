"""Plumbing-tier tests for ``scripts/docs/audit-codebase-alignment.py``.

Binds VAL-DOCS-M1-013 (m1-f01-audit-script): the 4-layer codebase-
alignment audit script that gates every later milestone in the
relay-docs-v1-20260522 operation.

Layer coverage:
- Layer 1: identifier / file-path / CLI / error-code / HTTP-route / spec-
  citation extraction + grep verification
- Layer 2: executable snippet verification (python imports, bash syntax,
  yaml + json schema validation)
- Layer 3: STUB (orchestrator-spawned LLM review at gate time)
- Layer 4: page-footer spec citation existence + banned-copy lint

Tests deliberately operate offline (no HTTP probes); the audit script is
read-only over the repo tree.

ASCII-only source per CLAUDE.md "ASCII-Safe Source"; the section-marker
glyph used in fixture page bodies is written as the ``\\u00a7`` escape so
no non-ASCII byte appears in the test source itself.

Spec citations:
- plan.md "Codebase-alignment audit (mandatory per-wave gate)" section.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "docs" / "audit-codebase-alignment.py"


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the audit script with the active interpreter."""
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
        env=env,
        timeout=120,
    )


def _make_page(tmp_path: Path, name: str, body: str) -> Path:
    """Write a fixture markdown page rooted at ``tmp_path`` and return its path."""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def _load_audit_module() -> ModuleType:
    """Load the audit script as a module for focused unit checks."""
    spec = importlib.util.spec_from_file_location("audit_codebase_alignment", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_help_exits_zero() -> None:
    """``--help`` exits 0 and prints usage text on stdout."""
    cp = _run(["--help"])
    assert cp.returncode == 0, f"--help non-zero: rc={cp.returncode} stderr={cp.stderr}"
    assert "audit" in cp.stdout.lower() or "audit" in cp.stderr.lower()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_json_output_is_valid_json(tmp_path: Path) -> None:
    """``--json`` emits a parseable JSON document with a ``findings`` key."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/page.md",
        "# Empty\n\nNo references.\n",
    )
    cp = _run(["--files", str(page), "--layers", "1,2,4", "--json"])
    # Parseable JSON either way (exit 0 or 1):
    payload = json.loads(cp.stdout)
    assert "findings" in payload, f"missing findings key: {payload!r}"
    assert isinstance(payload["findings"], list)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_negative_bad_filepath(tmp_path: Path) -> None:
    """A page citing a non-existent ``packages/...`` path is a P0 failure."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/bad.md",
        "# Title\n\nSee `packages/fake/nonexistent.py` for details.\n",
    )
    cp = _run(["--files", str(page), "--layers", "1", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    sev = {f["severity"] for f in payload["findings"]}
    assert "P0" in sev, f"expected at least one P0 finding, saw {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_negative_bad_identifier(tmp_path: Path) -> None:
    """A page citing a non-existent backticked identifier is a P0 failure.

    The "missing identifier" is generated at runtime via uuid4 so the
    literal cannot be folded into this test module's compiled bytecode
    (the prior `"definitely_missing_" + "symbol_xyz"` form was folded
    by CPython at compile time into the .pyc which rg could match in
    some environments; see scripts/docs/audit-codebase-alignment.py
    `_verify_identifier_via_rg` comment block for the full context).
    A uuid4 hex is unique per test invocation and cannot pre-exist
    anywhere in the repo or build artifacts.
    """
    import uuid as _uuid

    # Prefix ensures the symbol starts with a letter (rg/regex
    # identifier rules) and is unambiguously synthetic.
    missing_identifier = "audit_test_missing_" + _uuid.uuid4().hex
    page = _make_page(
        tmp_path,
        "docs/getting-started/badidentifier.md",
        f"# Title\n\nThe implementation calls `{missing_identifier}`.\n",
    )
    # Temporary diagnostic: enable RELAY_AUDIT_DEBUG and include stderr
    # in the failure message so CI logs reveal what the audit's Layer-1
    # extraction sees. Will revert once CI / local divergence is
    # diagnosed.
    env = dict(os.environ)
    env["RELAY_AUDIT_DEBUG"] = "1"
    cp = subprocess.run(
        [sys.executable, str(SCRIPT), "--files", str(page), "--layers", "1", "--json"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=120,
    )
    assert cp.returncode == 1, (
        f"expected exit 1, got {cp.returncode}\n"
        f"missing_identifier={missing_identifier!r}\n"
        f"stdout={cp.stdout!r}\n"
        f"stderr={cp.stderr!r}"
    )
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "identifier not found" in msgs, f"expected identifier finding, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_positive_real_filepath(tmp_path: Path) -> None:
    """A page citing only real source paths must NOT P0-fail Layer 1."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/good.md",
        "# Title\n\n"
        "The CLI entrypoint is `packages/cli/src/relay_cli/main.py`.\n"
        "\nSpec: A.1\n",
    )
    cp = _run(["--files", str(page), "--layers", "1", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, f"expected exit 0, got {cp.returncode}: {payload}"
    assert not p0, f"expected no P0 findings, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_negative_bad_spec_citation(tmp_path: Path) -> None:
    """A page footer citing a non-existent spec section P0-fails Layer 4."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/badspec.md",
        "# Title\n\nBody.\n\nSpec: \u00a7FAKE.9\n",
    )
    cp = _run(["--files", str(page), "--layers", "1,4", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "FAKE" in msgs, f"expected FAKE.9 in findings, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_negative_bad_python_import(tmp_path: Path) -> None:
    """A ``run``-tagged python fenced block importing a non-existent module is P0.

    Per Fix B (bare-snippet demotion) only ``run``-tagged python blocks remain
    P0 on import failure; bare reference snippets are demoted to P2 because
    they cannot import in isolation by design.
    """
    body = (
        "# Title\n\n"
        "```python title=\"badimport.py\" run\n"
        "from relay_does_not_exist_xyz import nope\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/badpy.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    sev = {f["severity"] for f in payload["findings"]}
    assert "P0" in sev, f"expected P0 finding, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_bare_python_syntax_error_is_p0(tmp_path: Path) -> None:
    """Fix #4: bare python with a SyntaxError must stay P0 (not demote to P2).

    A doc author who pastes malformed Python into a reference page would
    silently pass the audit gate under the prior overly-broad demotion. The
    demotion is now narrowed to ImportError; everything else (syntax, runtime,
    infrastructure) stays P0.
    """
    body = (
        "# Title\n\n"
        "```python\n"
        "def f(:\n"  # SyntaxError: invalid syntax
        "    pass\n"
        "```\n\n"
        f"Spec: §A.1\n"
    )
    page = _make_page(tmp_path, "docs/contracts/syntax-error.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    p0_findings = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert p0_findings, f"expected P0 finding for SyntaxError, got: {payload}"
    assert any("syntax" in f["actual"].lower() for f in p0_findings), (
        f"expected syntax-related actual, got: {p0_findings}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_bare_python_runtime_error_is_p0(tmp_path: Path) -> None:
    """Fix #4: bare python with a runtime exception must stay P0.

    NameError / AttributeError / TypeError on bare snippets are real bugs in
    the documented example, not import-isolation artefacts. They stay P0.
    """
    body = (
        "# Title\n\n"
        "```python\n"
        "x = undefined_global_xyz  # NameError\n"
        "```\n\n"
        f"Spec: §A.1\n"
    )
    page = _make_page(tmp_path, "docs/contracts/runtime-error.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    p0_findings = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert p0_findings, f"expected P0 finding for runtime error, got: {payload}"
    assert any("runtime" in f["actual"].lower() for f in p0_findings), (
        f"expected runtime-classified actual, got: {p0_findings}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_bare_python_import_error_demotes_to_p2(tmp_path: Path) -> None:
    """Fix #4: bare-snippet ImportError keeps the documented P2 demotion.

    Reference snippets like ``from relay import RelayClient`` legitimately
    fail to import in an isolated `python -c` because the package is not
    installed in the audit's subprocess. That specific failure mode demotes.
    """
    body = (
        "# Title\n\n"
        "```python\n"
        "from relay_pkg_that_does_not_exist_xyz import nope\n"
        "```\n\n"
        f"Spec: §A.1\n"
    )
    page = _make_page(tmp_path, "docs/contracts/import-error.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    payload = json.loads(cp.stdout)
    severities = {f["severity"] for f in payload["findings"]}
    # Should be exit 0 (P2 only, no P0/P1) since this is a documented demotion.
    assert "P0" not in severities, (
        f"bare-snippet import error must demote to P2 (not P0): {payload}"
    )
    assert cp.returncode == 0, f"expected exit 0 (P2-only), got {cp.returncode}: {cp.stdout}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_negative_bad_bash_without_rly(tmp_path: Path) -> None:
    """A bash fenced block without ``rly`` is still syntax-checked."""
    body = (
        "# Title\n\n"
        "```bash\n"
        "if true; then\n"
        "  echo hi\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/badbash.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "bash fenced block failed verification" in msgs, (
        f"expected bash syntax finding, got: {payload}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_run_bash_without_rly_is_syntax_only(tmp_path: Path) -> None:
    """A non-rly bash run block is syntax-checked, not executed."""
    body = (
        "# Title\n\n"
        "```bash run\n"
        "exit 42\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/runbash.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, f"expected exit 0, got {cp.returncode}: {payload}"
    assert not p0, f"expected no P0 findings, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_run_bash_incidental_rly_text_is_syntax_only(tmp_path: Path) -> None:
    """Incidental ``rly`` text in a run block does not make the block execute."""
    body = (
        "# Title\n\n"
        "```bash run\n"
        "# rly replay run\n"
        "echo 'rly replay run'\n"
        "cat <<EOF\n"
        "rly replay run\n"
        "EOF\n"
        "exit 42\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/incidental-rly.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, f"expected exit 0, got {cp.returncode}: {payload}"
    assert not p0, f"expected no P0 findings, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_bash_run_filter_executes_only_allowed_commands() -> None:
    """The run filter excludes unrelated and compound shell commands."""
    audit = _load_audit_module()
    commands = audit._bash_run_commands(
        "# rly replay run\n"
        "echo 'rly replay run'\n"
        "uv run rly replay run\n"
        "exit 42\n"
    )
    assert commands == ["uv run rly replay run"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
@pytest.mark.parametrize(
    "block",
    [
        "if false; then\nrly replay run\nfi\n",
        "for target in a; do\nrly replay run\n done\n",
        "run_docs() {\nrly replay run\n}\n",
        "(\nrly replay run\n)\n",
        "rly replay run && curl https://example.invalid\n",
        "rly replay run |& tee out.log\n",
        "rly replay run &> out.log\n",
        "rly replay run >& out.log\n",
        "false &&\nrly replay run\n",
        "cmd |\nrly replay run\n",
    ],
)
def test_bash_run_filter_skips_control_syntax_blocks(block: str) -> None:
    """The run filter does not execute commands from shell syntax blocks."""
    audit = _load_audit_module()
    assert audit._bash_run_commands(block) == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_positive_valid_python(tmp_path: Path) -> None:
    """A python fenced block doing only ``print`` parses + imports cleanly."""
    body = (
        "# Title\n\n"
        "```python\n"
        "print('hi')\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/okpy.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, f"expected exit 0, got {cp.returncode}: {payload}"
    assert not p0, f"expected no P0 findings, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_catalog_indexes_schema_version_const() -> None:
    """The catalog maps schemas by the declared ``schema_version`` const."""
    audit = _load_audit_module()
    catalog = audit._load_catalog_index(audit.AuditState())
    assert "relay.manifest.v1" in catalog
    assert catalog["relay.manifest.v1"].name == "manifest.v1.schema.json"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_unknown_schema_version_is_unverifiable(tmp_path: Path) -> None:
    """An unmapped ``schema_version`` records a P2 and promotes under strict."""
    body = (
        "# Title\n\n"
        "```json\n"
        "{\"schema_version\": \"relay.unknown.v1\", \"value\": true}\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/unknownschema.md", body)
    cp_default = _run(["--files", str(page), "--layers", "2", "--json"])
    payload_default = json.loads(cp_default.stdout)
    assert cp_default.returncode == 0, (
        f"non-strict run should not fail on P2 findings, got: {payload_default}"
    )
    assert "P2" in [f["severity"] for f in payload_default["findings"]], (
        f"expected P2 finding, got: {payload_default}"
    )

    cp_strict = _run(["--files", str(page), "--layers", "2", "--json", "--strict"])
    payload_strict = json.loads(cp_strict.stdout)
    assert cp_strict.returncode == 2, (
        f"strict mode should fail on promoted P2 findings, got: {payload_strict}"
    )
    assert "P1" in [f["severity"] for f in payload_strict["findings"]], (
        f"expected promoted P1 finding, got: {payload_strict}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer3_is_stub(tmp_path: Path) -> None:
    """Layer 3 is a no-op stub: a broken fixture passes when only L3 is asked."""
    body = (
        "# Title\n\n"
        "Reference to `packages/fake/nonexistent.py`.\n"
        "\n```python\nfrom relay_does_not_exist_xyz import nope\n```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/broken.md", body)
    cp = _run(["--files", str(page), "--layers", "3", "--json"])
    payload = json.loads(cp.stdout)
    assert cp.returncode == 0, (
        f"Layer 3 must be a stub and not fail, got rc={cp.returncode}: {payload}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_negative_missing_spec_footer(tmp_path: Path) -> None:
    """A page without a valid ``Spec:`` footer P0-fails Layer 4."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/nospec.md",
        "# Title\n\nBody.\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "missing or malformed Spec footer" in msgs, f"expected footer finding, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_negative_malformed_spec_footer(tmp_path: Path) -> None:
    """A page with ``Spec: A.1`` P0-fails Layer 4 as malformed."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/malformedspec.md",
        "# Title\n\nBody.\n\nSpec: A.1\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "missing or malformed Spec footer" in msgs, f"expected footer finding, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_accepts_val_spec_footer(tmp_path: Path) -> None:
    """Generated reference docs may carry VAL assertion footers."""
    page = _make_page(
        tmp_path,
        "docs/reference/cli/rly.md",
        "# Title\n\nBody.\n\nSpec: VAL-DOCS-M1-008\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, f"expected exit 0, got {cp.returncode}: {payload}"
    assert not p0, f"expected no P0 findings, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_rejects_val_spec_footer_outside_cli_reference(tmp_path: Path) -> None:
    """Hand-written docs must cite spec sections instead of VAL assertions."""
    page = _make_page(
        tmp_path,
        "docs/getting-started/valspec.md",
        "# Title\n\nBody.\n\nSpec: VAL-BOGUS-999\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    assert cp.returncode == 1, f"expected exit 1, got {cp.returncode}: {cp.stdout}"
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "missing or malformed Spec footer" in msgs, f"expected footer finding, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_wave1_empty_tree_passes() -> None:
    """Wave 1 against the current docs tree (no M1 pages yet) exits 0."""
    cp = _run(["--wave", "1", "--layers", "1,2,4", "--json"])
    payload = json.loads(cp.stdout)
    assert cp.returncode == 0, (
        f"empty Wave 1 must pass, got rc={cp.returncode}: {payload}"
    )
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert not p0, f"unexpected P0 findings on empty tree: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_skips_usage_skeleton_placeholders(tmp_path: Path) -> None:
    """CLI usage-skeleton lines (``[OPTIONS]``/``[ARGS]...``) are not real
    invocations and must not produce P0 findings.

    The generated CLI reference pages reproduce help-output usage lines such
    as ``rly contract [OPTIONS] COMMAND [ARGS]...``. These are placeholders,
    not commands; the live ``rly`` rejects them because the chain is not
    resolvable. The audit must skip these without recording a P0.
    """
    body = (
        "# `rly contract`\n\n"
        "> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.\n\n"
        "## Usage\n\n"
        "```\n"
        "rly contract [OPTIONS] COMMAND [ARGS]...\n"
        "```\n\n"
        "Spec: VAL-DOCS-M1-008\n"
    )
    page = _make_page(tmp_path, "docs/reference/cli/contract.md", body)
    cp = _run(["--files", str(page), "--layers", "1", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert cp.returncode == 0, (
        f"usage-skeleton placeholder must not P0, got rc={cp.returncode}: {payload}"
    )
    assert not p0, f"expected no P0 findings from usage skeleton, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_strips_trailing_punctuation_from_routes(tmp_path: Path) -> None:
    """HTTP route extraction strips trailing ``[,.;]+`` before openapi lookup.

    Without the strip, ``POST /v1/gates/{gate_id}/drafts,`` (sentence-comma)
    is recorded as path ``/v1/gates/{gate_id}/drafts,`` and the openapi
    lookup misses. The route exists in openapi.yaml as
    ``/v1/gates/{gate_id}/drafts`` -- a single comma at sentence end must
    not turn it into a P0.
    """
    body = (
        "# Title\n\n"
        "Submits a draft via POST /v1/gates/{gate_id}/drafts, polls await_url.\n\n"
        "Spec: §B.1\n"
    )
    page = _make_page(tmp_path, "docs/reference/cli/gate.md", body)
    cp = _run(["--files", str(page), "--layers", "1", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P0"
        and "HTTP route" in f.get("message", "")
    ]
    assert not p0, (
        f"trailing-comma route must not P0 (path exists in openapi.yaml), got: {p0}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_docs_index_footer_passes_layer4() -> None:
    """``docs/index.md`` carries a valid Layer 4 ``Spec:`` footer."""
    index_path = REPO_ROOT / "docs" / "index.md"
    assert index_path.is_file(), f"docs/index.md missing: {index_path}"
    cp = _run(["--files", str(index_path), "--layers", "4", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P0"
        and "Spec footer" in f.get("message", "")
    ]
    assert not p0, f"docs/index.md must have a valid Spec footer, got: {p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_strict_promotes_unverifiable_to_p1(tmp_path: Path) -> None:
    """A P2-class ``unverifiable`` finding is promoted to P1 under ``--strict``.

    Triggers an unverifiable finding by referring to a CLI subcommand whose
    validation path is currently unavailable (the ``--dry-run-parse-only``
    flag does not exist on the live CLI, per plan.md "Open items").
    Without ``--strict`` the run exits 0; with ``--strict`` it exits 2.
    """
    # A CLI invocation with a flag the live CLI does not implement triggers
    # the "unverifiable" classification (flag-level validation requires the
    # missing --dry-run-parse-only flag; subcommand-level validation cannot
    # see flag-level drift).
    body = (
        "# Title\n\n"
        "```bash\n"
        "$ rly contract publish --some-flag-that-might-not-exist value\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/cli.md", body)
    cp_default = _run(["--files", str(page), "--layers", "1,2", "--json"])
    payload_default = json.loads(cp_default.stdout)
    assert cp_default.returncode == 0, (
        f"non-strict run should not fail on unverifiable findings, "
        f"got rc={cp_default.returncode}: {payload_default}"
    )
    # At least one unverifiable severity-P2 finding should be recorded.
    sevs = [f["severity"] for f in payload_default["findings"]]
    assert "P2" in sevs, (
        f"expected at least one P2 (unverifiable) finding, got: {payload_default}"
    )

    cp_strict = _run(["--files", str(page), "--layers", "1,2", "--json", "--strict"])
    payload_strict = json.loads(cp_strict.stdout)
    assert cp_strict.returncode == 2, (
        f"strict mode should exit 2 on promoted unverifiable findings, "
        f"got rc={cp_strict.returncode}: {payload_strict}"
    )


# ---------------------------------------------------------------------------
# Fix A -- Layer 4 spec-footer exemption for generated reference pages
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
@pytest.mark.parametrize(
    "rel_path",
    [
        "docs/reference/cli/contract.md",
        "docs/reference/errors/RELAY-FAKE-001/index.md",
        "docs/reference/schemas/manifest.md",
        "docs/reference/python-sdk/client.md",
        "docs/reference/typescript-sdk/index.md",
        "docs/reference/http-api/index.md",
        "docs/reference/adapters/openai.md",
        "docs/guards/INDEX.md",
    ],
)
def test_layer4_exempts_generated_reference_pages(tmp_path: Path, rel_path: str) -> None:
    """Generated / index reference pages are exempt from the Spec-footer check.

    These pages enumerate the API surface and carry a ``Generated from ...``
    banner (or are top-level index pages) rather than a ``Spec: §...`` footer.
    The Layer 4 check must skip them and not record P0 footer findings.

    Fix A: exempt the listed glob roots from the strict footer regex.
    """
    page = _make_page(
        tmp_path,
        rel_path,
        "# Title\n\n> Generated from packages/cli/src/relay_cli/main.py. Do not edit by hand.\n\nBody.\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    payload = json.loads(cp.stdout)
    footer_p0 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P0" and "Spec footer" in f.get("message", "")
    ]
    assert cp.returncode == 0, (
        f"exempt path {rel_path} must not P0, got rc={cp.returncode}: {payload}"
    )
    assert not footer_p0, (
        f"exempt path {rel_path} must not produce footer P0, got: {footer_p0}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_exempts_non_canonical_spec_footer_on_error_page(tmp_path: Path) -> None:
    """Error reference pages carry non-canonical ``Spec: §L line 4479`` footers.

    The generator emits ``Spec: §L line 4479; AI lines 5651-5670`` which does
    not match the strict ``Spec: §<SECTION>`` regex. The Layer 4 check must
    not record a P0 finding for these pages.
    """
    body = (
        "# RELAY-FAKE-001\n\n"
        "> Generated from packages/schemas/raw/error-codes.yaml. Do not edit by hand.\n\n"
        "Description.\n\n"
        "Spec: §L line 4479; AI lines 5651-5670\n"
    )
    page = _make_page(tmp_path, "docs/reference/errors/RELAY-FAKE-001/index.md", body)
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    payload = json.loads(cp.stdout)
    footer_p0 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P0" and "Spec footer" in f.get("message", "")
    ]
    assert cp.returncode == 0, (
        f"exempt error page must not P0, got rc={cp.returncode}: {payload}"
    )
    assert not footer_p0, f"exempt error page must not produce footer P0: {footer_p0}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer4_still_enforces_footer_on_handauthored_pages(tmp_path: Path) -> None:
    """Non-exempt hand-authored pages must still require a canonical footer.

    Regression guard for Fix A: only the explicit exempt globs are skipped;
    every other page under docs/ continues to enforce ``Spec: §<SECTION>``.
    """
    page = _make_page(
        tmp_path,
        "docs/getting-started/handauthored.md",
        "# Title\n\nBody only, no footer.\n",
    )
    cp = _run(["--files", str(page), "--layers", "4", "--json"])
    assert cp.returncode == 1, (
        f"hand-authored page without footer must P0, got rc={cp.returncode}: {cp.stdout}"
    )
    payload = json.loads(cp.stdout)
    msgs = " | ".join(f.get("message", "") for f in payload["findings"])
    assert "missing or malformed Spec footer" in msgs, (
        f"expected footer P0 on hand-authored page, got: {payload}"
    )


# ---------------------------------------------------------------------------
# Fix B -- Layer 2 bare-snippet demotion
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_bare_python_snippet_without_run_tag_is_p2(tmp_path: Path) -> None:
    """A python block lacking a ``run`` tag demotes import failures to P2.

    Bare reference snippets (class/signature excerpts) cannot import in
    isolation. They are documentation, not runnable code; ``run``-tagged
    blocks remain P0 on import failure.
    """
    body = (
        "# Title\n\n"
        "```python\n"
        "from relay_does_not_exist_xyz import nope\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/baresnippet.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    p2 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P2" and "python fenced block" in f.get("message", "")
    ]
    assert cp.returncode == 0, (
        f"bare snippet should not P0, got rc={cp.returncode}: {payload}"
    )
    assert not p0, f"expected no P0 findings on bare snippet, got: {p0}"
    assert p2, f"expected demoted P2 finding for bare snippet, got: {payload}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer2_run_tagged_python_snippet_failing_import_is_p0(tmp_path: Path) -> None:
    """A python block tagged ``run`` keeps P0 on import failure.

    Regression guard for Fix B: only un-tagged blocks are demoted.
    """
    body = (
        "# Title\n\n"
        "```python title=\"sample.py\" run\n"
        "from relay_does_not_exist_xyz import nope\n"
        "```\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/runpy.md", body)
    cp = _run(["--files", str(page), "--layers", "2", "--json"])
    assert cp.returncode == 1, (
        f"run-tagged failing snippet must P0, got rc={cp.returncode}: {cp.stdout}"
    )
    payload = json.loads(cp.stdout)
    p0 = [f for f in payload["findings"] if f["severity"] == "P0"]
    assert p0, f"expected P0 on run-tagged failing snippet, got: {payload}"


# ---------------------------------------------------------------------------
# Fix C -- Layer 1 CLI verifier accepts real multi-word commands
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-013")
def test_layer1_strips_trailing_punctuation_from_cli_chain(tmp_path: Path) -> None:
    """The CLI extractor strips trailing punctuation before the verifier check.

    Sentence-ending ``.``, ``,``, ``;``, ``)`` after a CLI invocation must
    not turn a valid command into a P0. Fix C tightens the extractor.
    """
    body = (
        "# Title\n\n"
        "Run `rly evidence verify`.\n\n"
        "Or invoke as:\n\n"
        "```bash\n"
        "rly evidence verify bundle.json;\n"
        "```\n\n"
        "Spec: §K\n"
    )
    page = _make_page(tmp_path, "docs/getting-started/cli-punct.md", body)
    cp = _run(["--files", str(page), "--layers", "1", "--json"])
    payload = json.loads(cp.stdout)
    cli_p0 = [
        f
        for f in payload["findings"]
        if f["severity"] == "P0" and "CLI command" in f.get("message", "")
    ]
    assert not cli_p0, f"trailing punctuation must not turn valid CLI into P0: {cli_p0}"
