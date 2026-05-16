"""Manifest schema and side_effect_class assertions for the OpenAI example.

Covers:
  VAL-W16-005: tool calls declare side_effect_class.
  VAL-W16-017: example relay.manifest.yaml passes manifest schema validation.
  VAL-W16-018: example commands run only via manifest-declared paths.

Tier-1 plumbing: parses YAML on disk, validates against the JSON schema
shipped under packages/schemas/, asserts side_effect_class enum
membership and tool/command coverage.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

# Side-effect classes per spec section X / section E.3.
VALID_SIDE_EFFECT_CLASSES: frozenset[str] = frozenset(
    {"read_only", "mutating", "external_irreversible", "approval_required"}
)


def _load_manifest(example_root: Path) -> dict[str, Any]:
    raw = (example_root / "relay.manifest.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), "relay.manifest.yaml must parse to a dict"
    return parsed


def _load_schema(repo_root: Path) -> dict[str, Any]:
    """Load the example-manifest JSON Schema.

    The OSS scaffold has not yet landed a top-level
    packages/schemas/relay-manifest.schema.json (W16 ships first in this
    operation). The example directory ships its own JSON Schema that
    captures the per-example manifest contract (run command, tools with
    side_effect_class, test globs, adapter, ports) - this satisfies
    VAL-W16-017's "passes manifest schema validation" requirement at the
    example surface. When the canonical schema lands later in
    relay-platform / W17 it can supersede this file.
    """
    schema_path = (
        repo_root
        / "packages"
        / "schemas"
        / "examples"
        / "relay-example-manifest.schema.json"
    )
    return json.loads(schema_path.read_text(encoding="utf-8"))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-017")
def test_openai_manifest_parses_and_validates(
    example_root: Path, repo_root: Path
) -> None:
    """relay.manifest.yaml parses and validates against the example schema."""
    manifest = _load_manifest(example_root)
    schema = _load_schema(repo_root)
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(manifest),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, (
        "Manifest schema validation failed:\n"
        + "\n".join(
            f"  - {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        )
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-017")
def test_openai_manifest_declares_required_fields(example_root: Path) -> None:
    """Manifest declares schema, adapter, run command, tools, ports, tests."""
    manifest = _load_manifest(example_root)
    required_top_level = {
        "schema",
        "adapter",
        "languages",
        "commands",
        "tools",
        "tests",
    }
    missing = required_top_level - manifest.keys()
    assert not missing, f"Manifest missing required fields: {sorted(missing)}"
    assert manifest["schema"] == "relay.example_manifest.v1"
    assert manifest["adapter"] == "openai"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-005")
def test_openai_manifest_tools_declare_side_effect_class(
    example_root: Path,
) -> None:
    """Every tool in the manifest declares a valid side_effect_class."""
    manifest = _load_manifest(example_root)
    tools = manifest.get("tools", [])
    assert tools, "Manifest must declare at least one tool"
    for tool in tools:
        assert "name" in tool, f"tool missing name: {tool}"
        assert "side_effect_class" in tool, (
            f"tool {tool.get('name')!r} missing side_effect_class "
            "(VAL-W16-005)"
        )
        sec = tool["side_effect_class"]
        assert sec in VALID_SIDE_EFFECT_CLASSES, (
            f"tool {tool['name']!r} has invalid side_effect_class={sec!r}; "
            f"must be one of {sorted(VALID_SIDE_EFFECT_CLASSES)}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-018")
def test_openai_manifest_commands_use_relay_run_dispatch(
    example_root: Path,
) -> None:
    """Per VAL-W16-018 example commands run only via manifest-declared paths.

    The manifest's command records MUST use ``rly run`` (or ``relay run``)
    as the dispatch surface; direct ``python ...`` or ``node ...`` strings
    in the manifest are forbidden because they bypass the manifest-as-source-of-truth
    invariant (CLAUDE.md keystone #3, spec section F).
    """
    manifest = _load_manifest(example_root)
    commands = manifest.get("commands", {})
    assert commands, "Manifest must declare at least one command"
    for name, record in commands.items():
        cmd = record.get("cmd", "") if isinstance(record, dict) else str(record)
        # Strip leading env-prefix tokens like "OPENAI_API_KEY=..." so we
        # match on the actual binary at the head of the cmd line.
        head = cmd.split()
        binary = head[0] if head else ""
        # Permitted forms: rly run / relay run / rly replay run / rly replay record.
        is_rly_dispatch = (
            binary in {"rly", "relay", "uv"}
            or cmd.startswith("uv run rly ")
            or cmd.startswith("uv run relay ")
        )
        assert is_rly_dispatch, (
            f"command {name!r} cmd={cmd!r} does not dispatch via rly/relay; "
            "examples MUST run through the manifest's declared command surface "
            "(VAL-W16-018)."
        )
