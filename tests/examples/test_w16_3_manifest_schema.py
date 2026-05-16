"""Manifest schema assertions for the Vercel AI tool-agent example.

Covers:
  VAL-W16-005: tool calls declare side_effect_class (cross-cutting via
               W16.1 also-covers).
  VAL-W16-017: example relay.manifest.yaml passes manifest schema
               validation.
  VAL-W16-018: example commands run only via manifest-declared paths.
  VAL-W16-019: live-mode smoke tests carry @requires-openai (the Vercel
               AI SDK's default backing provider in this example);
               cassette-mode tests do NOT.

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

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def vercel_example_root() -> Path:
    return REPO_ROOT / "examples" / "vercel-ai-tool-agent"


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
def test_vercel_manifest_parses_and_validates(
    vercel_example_root: Path,
) -> None:
    """relay.manifest.yaml parses and validates against the example schema."""
    manifest = _load_manifest(vercel_example_root)
    schema = _load_schema(REPO_ROOT)
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
def test_vercel_manifest_declares_required_fields(
    vercel_example_root: Path,
) -> None:
    """Manifest declares schema, adapter, languages, commands, tools, tests."""
    manifest = _load_manifest(vercel_example_root)
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
    # Per the example-manifest schema's adapter enum, the Vercel AI
    # example MUST declare adapter=vercel_ai. The Vercel AI SDK is
    # TS-native; spec section S P0 adapter placement lists it under the
    # TS surface.
    assert manifest["adapter"] == "vercel_ai"
    # TS-only example per VAL-W16-009.
    assert manifest["languages"] == ["typescript"], (
        "Vercel AI example is TypeScript-only (per VAL-W16-009); "
        f"got languages={manifest['languages']}."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-005")
def test_vercel_manifest_tools_declare_side_effect_class(
    vercel_example_root: Path,
) -> None:
    """Every tool in the manifest declares a valid side_effect_class."""
    manifest = _load_manifest(vercel_example_root)
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
def test_vercel_manifest_commands_use_relay_run_dispatch(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-018 example commands run only via manifest-declared paths.

    The manifest's command records MUST use ``rly run`` (or ``relay run``,
    or ``uv run rly``) as the dispatch surface; direct ``node ...`` /
    ``tsx ...`` strings in the manifest are forbidden because they bypass
    the manifest-as-source-of-truth invariant.
    """
    manifest = _load_manifest(vercel_example_root)
    commands = manifest.get("commands", {})
    assert commands, "Manifest must declare at least one command"
    for name, record in commands.items():
        cmd = record.get("cmd", "") if isinstance(record, dict) else str(record)
        head = cmd.split()
        binary = head[0] if head else ""
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


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-019")
def test_vercel_smoke_tests_have_correct_annotations(
    vercel_example_root: Path,
) -> None:
    """Per VAL-W16-019: live smoke tests carry @requires-openai (the
    Vercel AI SDK example's default backing provider in this example);
    cassette tests do NOT.
    """
    manifest = _load_manifest(vercel_example_root)
    tests = manifest.get("tests", {})
    assert "live_smoke" in tests, "manifest.tests.live_smoke missing"
    assert "cassette_replay" in tests, "manifest.tests.cassette_replay missing"
    live = tests["live_smoke"]
    cassette = tests["cassette_replay"]
    assert isinstance(live, dict) and isinstance(cassette, dict)
    live_anns = set(live.get("annotations", []) or [])
    cassette_anns = set(cassette.get("annotations", []) or [])
    assert "@requires-openai" in live_anns, (
        "live_smoke must carry @requires-openai (VAL-W16-019); the "
        "Vercel AI SDK example defaults to the OpenAI provider for "
        "tier-2 smoke."
    )
    assert "@requires-openai" not in cassette_anns, (
        "cassette_replay MUST NOT carry @requires-openai "
        "(cassette mode is offline; VAL-W16-019)."
    )
    assert live.get("tier") in {"smoke", "tier-2"}, (
        "live_smoke tier must be smoke / tier-2"
    )
    assert cassette.get("tier") in {"smoke", "tier-2", "plumbing", "tier-1"}, (
        "cassette_replay tier must be smoke / plumbing"
    )
