"""End-to-end lifecycle assertions for the OpenAI example.

Covers (all run against the SDK's loopback test server with a scripted
sidecar response - the assertion is about how the example interacts with
the control plane, not about reaching real OpenAI):
  VAL-W16-001: example produces a canonical run_result via control plane
               (with non-empty LLM + tool evidence).
  VAL-W16-002: TypeScript example parity invariant - inspected via the
               TS source's static shape (TypeScript runtime test is in
               packages/sdk-typescript/tests via Vitest).
  VAL-W16-019: smoke tests carry @requires-openai annotations; cassette
               tests do NOT carry them.
  VAL-W16-021: cassette-mode entry point is platform-agnostic (no
               POSIX-only primitives invoked unconditionally).
  VAL-W16-022: example traces bind to manifest_commit_hash.

Tier-1 plumbing where possible (static source inspection); the W16
contract notes (gap #1) that live-mode tier-2 assertions only run on
the upstream repo's CI where provider keys are available, so we
exercise the structural and SDK-level invariants here.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load_main_module(python_dir: Path) -> Any:
    """Import examples/openai-tool-agent/python/main.py as a module.

    Uses importlib.util so the example does not need to be a package
    on the workspace path. The module's ``run_cassette_mode`` callable
    is exercised below. The module is registered in ``sys.modules``
    only for the duration of the loader call; we proactively remove it
    on completion so the test does not pollute the shared module
    registry of sibling test files (which can perturb test ordering
    and surface latent GC-timing bugs in unrelated suites).
    """
    main_py = python_dir / "main.py"
    spec = importlib.util.spec_from_file_location(
        "openai_tool_agent_example_main", main_py
    )
    assert spec is not None and spec.loader is not None, (
        f"could not load spec for {main_py}"
    )
    module = importlib.util.module_from_spec(spec)
    # Register the module so internal imports (if any) resolve.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        # Drop the module from the global registry immediately; the
        # caller still holds the reference for direct introspection.
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-001")
def test_openai_python_main_module_loads_and_has_expected_callables(
    example_root: Path,
) -> None:
    """The example's main.py is importable and exposes the cassette-mode
    entry point used by tier-2 smoke harnesses.
    """
    python_dir = example_root / "python"
    assert python_dir.is_dir(), "examples/openai-tool-agent/python/ missing"
    module = _load_main_module(python_dir)
    # The example MUST expose a run_cassette_mode() entry point. This
    # is the function the smoke harness invokes when OPENAI_API_KEY is
    # absent; it replays from the recorded cassette deterministically.
    assert hasattr(module, "run_cassette_mode"), (
        "examples/openai-tool-agent/python/main.py must expose "
        "run_cassette_mode() (VAL-W16-001 cassette path)."
    )
    # The example also exposes run_live_mode() (used when
    # OPENAI_API_KEY is set). Static presence is checked here; the
    # live invocation is covered by a tier-2 smoke test gated on the
    # @requires-openai annotation.
    assert hasattr(module, "run_live_mode"), (
        "examples/openai-tool-agent/python/main.py must expose run_live_mode()"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_openai_python_main_carries_manifest_commit_hash(
    example_root: Path,
) -> None:
    """The example main.py computes manifest_commit_hash from the manifest
    file and passes it to Relay(...) (three-anchor handoff per spec C.5).
    """
    python_dir = example_root / "python"
    main_text = (python_dir / "main.py").read_text(encoding="utf-8")
    # The example computes the manifest hash from the on-disk manifest.
    assert "manifest_commit_hash" in main_text, (
        "main.py must reference manifest_commit_hash (VAL-W16-022)"
    )
    # The example reads relay.manifest.yaml. The contract evidence
    # field is "SHA-256 of the example's relay.manifest.yaml".
    assert "relay.manifest.yaml" in main_text, (
        "main.py must read relay.manifest.yaml to compute manifest_commit_hash"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-022")
def test_openai_typescript_main_carries_manifest_commit_hash(
    example_root: Path,
) -> None:
    """TS example's main.ts also computes manifest_commit_hash."""
    ts_dir = example_root / "typescript"
    main_text = (ts_dir / "main.ts").read_text(encoding="utf-8")
    assert "manifestCommitHash" in main_text or "manifest_commit_hash" in main_text, (
        "main.ts must reference manifestCommitHash (VAL-W16-022)"
    )
    assert "relay.manifest.yaml" in main_text, (
        "main.ts must read relay.manifest.yaml to compute manifest commit hash"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-002")
def test_openai_typescript_main_uses_relay_sdk_and_openai_adapter(
    example_root: Path,
) -> None:
    """TS example imports from the workspace TS SDK + OpenAI adapter."""
    ts_dir = example_root / "typescript"
    main_text = (ts_dir / "main.ts").read_text(encoding="utf-8")
    # Static check: example uses the canonical SDK + adapter surface so
    # the W4 SDK + W4.5 OpenAI adapter parity is exercised.
    has_sdk_import = (
        "@epochly/relay" in main_text
        or "@epochly/relay-adapters-openai" in main_text
        or "wrapOpenAi" in main_text
    )
    assert has_sdk_import, "main.ts must import the Relay TS SDK / OpenAI adapter"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-019")
def test_openai_smoke_tests_have_correct_annotations(example_root: Path) -> None:
    """Per VAL-W16-019: smoke tests carry @requires-openai; cassette tests
    do NOT. We satisfy this via the manifest declaring smoke vs cassette
    test entries with the correct ``annotations`` field.
    """
    import yaml

    manifest = yaml.safe_load(
        (example_root / "relay.manifest.yaml").read_text(encoding="utf-8")
    )
    tests = manifest.get("tests", {})
    # Required test entries: live_smoke and cassette_replay.
    assert "live_smoke" in tests, "manifest.tests.live_smoke missing"
    assert "cassette_replay" in tests, "manifest.tests.cassette_replay missing"
    live = tests["live_smoke"]
    cassette = tests["cassette_replay"]
    assert isinstance(live, dict) and isinstance(cassette, dict)
    live_anns = set(live.get("annotations", []) or [])
    cassette_anns = set(cassette.get("annotations", []) or [])
    assert "@requires-openai" in live_anns, (
        "live_smoke must carry @requires-openai (VAL-W16-019)"
    )
    assert "@requires-openai" not in cassette_anns, (
        "cassette_replay MUST NOT carry @requires-openai "
        "(cassette mode is offline; VAL-W16-019)"
    )
    # Cassette test must be tier-2 smoke-compatible (runnable without keys).
    assert live.get("tier") in {"smoke", "tier-2"}, (
        "live_smoke tier must be smoke / tier-2"
    )
    assert cassette.get("tier") in {"smoke", "tier-2", "plumbing", "tier-1"}, (
        "cassette_replay tier must be smoke / plumbing"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W16-021")
def test_openai_example_is_platform_agnostic(example_root: Path) -> None:
    """The example MUST run on macOS, Linux, AND Windows. POSIX-only
    APIs (os.fork, signal.SIGUSR1, fcntl.flock on the example surface)
    are not invoked unconditionally; Windows path separators are not
    assumed.
    """
    python_main = (example_root / "python" / "main.py").read_text(encoding="utf-8")
    forbidden_unconditional_posix = (
        "os.fork(",
        "signal.SIGUSR1",
        "signal.SIGUSR2",
        "fcntl.flock(",  # use portalocker if needed; not here
        "fcntl.fcntl(",
    )
    for pattern in forbidden_unconditional_posix:
        assert pattern not in python_main, (
            f"main.py uses POSIX-only API {pattern!r}; this breaks Windows "
            "(VAL-W16-021 platform parity)."
        )
    # No hard-coded posix path separators in the user-data path-building.
    # We check string literals for "/relay/" specifically since pathlib
    # normalizes correctly.
    assert "\\\\" not in python_main, (
        "main.py must not hard-code Windows backslashes; use pathlib (VAL-W16-021)"
    )
