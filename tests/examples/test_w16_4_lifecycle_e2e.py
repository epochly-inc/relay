"""End-to-end lifecycle assertions for the MCP tool-agent example.

Covers (W16.4 primary):
  VAL-W16-013: MCP example captures tool calls via MCP protocol. The
               example exposes an entry point that emits at least one
               tool_call span whose tool_name follows the MCP
               ``server.tool`` form, with redacted args, args_hash,
               result_hash, status, and duration populated per spec
               section B.1 tool-call flight recorder.
  VAL-W16-014: MCP example replays from cassette deterministically with
               zero network egress and without spawning an MCP server
               process. Trace digest equality is provable from the
               cassette's recorded kind sequence.

Covers (W16.4 cross-cutting share):
  VAL-W16-022: example traces bind to manifest_commit_hash (three-anchor
               handoff per spec section C.5).

Per the W16 contract notes (gap #1) live-mode tier-2 assertions only
run on the upstream repo's CI where provider keys are available, so
this tier-1 plumbing surface exercises the structural and SDK-level
invariants. The cassette-mode entry point is exercised directly here
(no provider key required, no MCP server spawned per VAL-W16-014); the
live entry point is asserted to exist and to reference the MCP client
adapter surface.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def mcp_example_root() -> Path:
    return REPO_ROOT / "examples" / "mcp-tool-agent"


def _load_main_module(python_dir: Path) -> Any:
    """Import examples/mcp-tool-agent/python/main.py as a module.

    Uses importlib.util so the example does not need to be a package
    on the workspace path. Mirrors the W16.1 / W16.2 lifecycle test
    helper.
    """
    main_py = python_dir / "main.py"
    spec = importlib.util.spec_from_file_location(
        "mcp_tool_agent_example_main", main_py
    )
    assert spec is not None and spec.loader is not None, (
        f"could not load spec for {main_py}"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_python_main_module_loads_and_has_expected_callables(
    mcp_example_root: Path,
) -> None:
    """The example's main.py is importable and exposes the cassette-mode
    entry point + an MCP-tool-call builder.
    """
    python_dir = mcp_example_root / "python"
    assert python_dir.is_dir(), "examples/mcp-tool-agent/python/ missing"
    module = _load_main_module(python_dir)
    assert hasattr(module, "run_cassette_mode"), (
        "examples/mcp-tool-agent/python/main.py must expose "
        "run_cassette_mode() (VAL-W16-014 cassette path)."
    )
    assert hasattr(module, "run_live_mode"), (
        "examples/mcp-tool-agent/python/main.py must expose run_live_mode()"
    )
    # Manual instrumentation exposes a tool_call-span builder. Per
    # VAL-W16-013 the example MUST be able to produce a tool_call span
    # whose tool_name follows the MCP server.tool form; exposing a
    # callable that builds the span attribute dict makes the assertion
    # testable offline.
    assert hasattr(module, "build_mcp_tool_call_span"), (
        "main.py must expose build_mcp_tool_call_span() -- manual "
        "instrumentation helper per VAL-W16-013."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_build_tool_call_span_produces_required_fields(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the MCP tool_call span MUST carry tool_name (in
    ``server.tool`` form), args_hash, result_hash, status, duration_ms,
    side_effect_marker, and the redacted args payload per spec section
    B.1 tool-call flight recorder + redaction_policy_version binding.
    """
    module = _load_main_module(mcp_example_root / "python")
    span = module.build_mcp_tool_call_span()
    assert isinstance(span, dict), "build_mcp_tool_call_span must return a dict"
    # Spec section B.1 tool-call required fields + MCP-specific fields.
    required_fields = {
        "span_id",
        "kind",
        "tool_name",
        "args_hash",
        "result_hash",
        "status",
        "duration_ms",
        "side_effect_marker",
        "redacted_args",
        "redaction_policy_version",
    }
    missing = required_fields - span.keys()
    assert not missing, (
        f"MCP tool_call span missing required fields: {sorted(missing)}. "
        f"Required: {sorted(required_fields)} (spec B.1 + VAL-W16-013)."
    )
    assert span["kind"] == "tool_call", (
        f"span kind must be 'tool_call'; got {span['kind']!r}"
    )
    # tool_name MUST follow MCP ``server.tool`` form (dotted namespace).
    tool_name = span["tool_name"]
    assert isinstance(tool_name, str) and "." in tool_name, (
        f"tool_name {tool_name!r} must follow MCP server.tool form "
        "(dotted namespace separator); VAL-W16-013."
    )
    # args_hash and result_hash MUST be sha256-prefixed digests so the
    # MCP envelope is bound to the span without persisting cleartext.
    for hash_field in ("args_hash", "result_hash"):
        value = span[hash_field]
        assert isinstance(value, str) and value.startswith("sha256-"), (
            f"{hash_field}={value!r} must be a sha256-prefixed digest "
            "(spec B.1)."
        )
    # status MUST be a non-empty string.
    assert isinstance(span["status"], str) and span["status"], (
        "status must be a non-empty string (spec B.1)"
    )
    # duration_ms MUST be a non-negative integer.
    duration = span["duration_ms"]
    assert isinstance(duration, int) and duration >= 0, (
        f"duration_ms={duration!r} must be a non-negative int"
    )
    # side_effect_marker is False for read_only MCP tools (the example's
    # canonical read-only tool); a mutating MCP tool would set this
    # True and require an audited replay policy override.
    assert span["side_effect_marker"] is False, (
        "example's MCP tool is read_only; side_effect_marker must be False"
    )
    # redaction_policy_version is bound to the span so the run's
    # redaction policy can be reproduced offline.
    assert span["redaction_policy_version"] == "v1", (
        "redaction_policy_version must equal 'v1' (the example's pinned "
        "policy version; spec section G)."
    )
    # redacted_args MUST be a dict (not None) so the redaction pipeline
    # produced an envelope; raw cleartext would violate spec section G
    # default-deny raw capture.
    assert isinstance(span["redacted_args"], dict), (
        "redacted_args must be a dict (redacted MCP envelope); raw "
        "cleartext violates spec G default-deny."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_run_cassette_mode_returns_zero(
    mcp_example_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Cassette-mode entry point runs end-to-end without a provider key
    and exits 0; stdout contains the deterministic summary including
    the MCP tool_name so the smoke harness can verify the "expected
    output snippet" from the README.

    Per VAL-W16-014: zero network egress, no MCP server process spawned
    during replay. The entry point MUST be pure-compute over the
    recorded cassette.
    """
    module = _load_main_module(mcp_example_root / "python")
    rc = module.run_cassette_mode()
    assert rc == 0, f"run_cassette_mode exit code {rc} != 0"
    captured = capsys.readouterr()
    assert "tool_call" in captured.out.lower() or "tool call" in captured.out.lower(), (
        "cassette mode stdout must mention 'tool_call' / 'tool call' "
        "(VAL-W16-013 MCP tool-call surface)."
    )
    # The cassette mode MUST surface the MCP tool name (server.tool
    # form) in stdout so the offline replay proves the MCP-protocol
    # invariant without requiring a live MCP server.
    assert "mcp" in captured.out.lower(), (
        "cassette mode stdout must reference 'mcp' (VAL-W16-014 / "
        "VAL-W16-013 protocol identification)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_run_cassette_mode_does_not_spawn_subprocess(
    mcp_example_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per VAL-W16-014: cassette replay MUST NOT spawn any MCP server
    child process. We monkey-patch ``subprocess.Popen`` and
    ``subprocess.run`` to detect any process spawn during the cassette
    entry point; an attempt to spawn surfaces as an immediate test
    failure.
    """
    import subprocess

    spawn_log: list[str] = []

    real_popen = subprocess.Popen
    real_run = subprocess.run

    def _trapped_popen(*args: Any, **kwargs: Any) -> Any:
        spawn_log.append(f"Popen({args!r}, {kwargs!r})")
        # Defer to the real constructor only so the test trace shows
        # the spawn attempt; this branch is unreachable under a
        # well-behaved cassette path.
        return real_popen(*args, **kwargs)

    def _trapped_run(*args: Any, **kwargs: Any) -> Any:
        spawn_log.append(f"run({args!r}, {kwargs!r})")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", _trapped_popen)
    monkeypatch.setattr(subprocess, "run", _trapped_run)

    module = _load_main_module(mcp_example_root / "python")
    rc = module.run_cassette_mode()
    assert rc == 0, f"run_cassette_mode exit code {rc} != 0"
    assert not spawn_log, (
        "Cassette mode spawned a subprocess; VAL-W16-014 forbids any MCP "
        "server child process during replay. Spawns observed:\n"
        + "\n".join(spawn_log)
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-014")
def test_mcp_run_cassette_mode_surfaces_mcp_tool_name(
    mcp_example_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Per VAL-W16-013 + VAL-W16-014 the cassette-mode stdout MUST
    contain the canonical MCP tool name (``server.tool`` form) so the
    offline replay proves the MCP-protocol invariant.
    """
    module = _load_main_module(mcp_example_root / "python")
    rc = module.run_cassette_mode()
    assert rc == 0
    captured = capsys.readouterr()
    # The example's pinned MCP tool name is a dotted namespace; we
    # assert that at least one dotted-form token appears in stdout. A
    # bare "echo" or "get_current_weather" without a dotted namespace
    # would not satisfy the MCP server.tool convention.
    lines = captured.out.splitlines()
    seen_dotted_tool = False
    for line in lines:
        # Look for tokens like "everything.echo" or "weather.get_current"
        # (the example's pinned MCP tool name). The check is lenient on
        # surrounding context but strict on the dotted-namespace form.
        for token in line.split():
            stripped = token.strip("()[]{}.,;:\"'<>")
            if "." not in stripped:
                continue
            head, _, tail = stripped.partition(".")
            head_alnum = head.replace("_", "").isalnum()
            tail_alnum = tail.replace("_", "").replace(".", "").isalnum()
            if head and tail and head_alnum and tail_alnum:
                seen_dotted_tool = True
                break
        if seen_dotted_tool:
            break
    assert seen_dotted_tool, (
        "cassette mode stdout must surface an MCP tool name in "
        "``server.tool`` dotted form (VAL-W16-013 / VAL-W16-014 protocol "
        "identification)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_mcp_python_main_carries_manifest_commit_hash(
    mcp_example_root: Path,
) -> None:
    """The example main.py computes manifest_commit_hash from the
    manifest file and passes it as the third anchor in the Relay
    handoff (spec section C.5 / VAL-W16-022).
    """
    python_dir = mcp_example_root / "python"
    main_text = (python_dir / "main.py").read_text(encoding="utf-8")
    assert "manifest_commit_hash" in main_text, (
        "main.py must reference manifest_commit_hash (VAL-W16-022)"
    )
    assert "relay.manifest.yaml" in main_text, (
        "main.py must read relay.manifest.yaml to compute manifest_commit_hash"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_mcp_compute_manifest_commit_hash_matches_file_sha256(
    mcp_example_root: Path,
) -> None:
    """compute_manifest_commit_hash() MUST equal sha256(manifest bytes).

    Per spec section C.5 the third anchor in the three-anchor handoff
    is the SHA-256 of the example's on-disk relay.manifest.yaml. The
    test computes the expected digest directly and compares.
    """
    import hashlib

    module = _load_main_module(mcp_example_root / "python")
    manifest_path = mcp_example_root / "relay.manifest.yaml"
    expected = (
        "sha256-" + hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )
    actual = module.compute_manifest_commit_hash()
    assert actual == expected, (
        f"compute_manifest_commit_hash() returned {actual!r}; "
        f"expected {expected!r} (sha256 of relay.manifest.yaml bytes; "
        "VAL-W16-022)."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-013")
def test_mcp_python_main_references_mcp_client_surface(
    mcp_example_root: Path,
) -> None:
    """Per VAL-W16-013 the example MUST exercise the MCP client surface.
    The live-mode entry point MUST reference the MCP client transport
    primitives (ClientSession + stdio_client or equivalent) so the
    adapter surface is exercised at the example boundary.
    """
    main_text = (
        mcp_example_root / "python" / "main.py"
    ).read_text(encoding="utf-8")
    # The example MUST import from the Model Context Protocol Python
    # SDK (``mcp`` package). The reference SDK exposes ClientSession
    # and stdio_client primitives.
    has_mcp_client = (
        "ClientSession" in main_text
        or "stdio_client" in main_text
        or "from mcp" in main_text
        or "import mcp" in main_text
    )
    assert has_mcp_client, (
        "main.py must import from the MCP client SDK (mcp.ClientSession "
        "/ mcp.client.stdio.stdio_client). VAL-W16-013 requires the "
        "example to exercise the MCP client surface."
    )
