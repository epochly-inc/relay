"""Shared fixtures for the W16 example apps test suite.

The W16 examples ship as runnable example apps under ``examples/<name>/``
and the tests in this directory validate their structural invariants
(directory layout, manifest schema, README sections, cassette format,
absence of banned product copy and TODO/FIXME/HACK).

The live-mode end-to-end assertions (VAL-W16-001, 002) are exercised
through the SDK's loopback test server with a scripted control-plane
response so the assertion ("control plane writes a row with
written_by = control_plane") can be verified without a real OpenAI key
or a real sidecar process.

A module-scoped GC sweep runs at suite teardown so any imports done by
``test_w16_1_lifecycle_e2e`` (which loads the example's ``main.py`` via
importlib) do not leave deferred warnings (ResourceWarning, etc.) that
later get attributed to unrelated tests under Python 3.14's strict
``filterwarnings = ["error", ...]`` regime.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import gc
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo_root() -> Path:
    """Return the relay/ repo root regardless of pytest invocation cwd."""
    return REPO_ROOT


@pytest.fixture
def example_root(repo_root: Path) -> Path:
    """Return the openai-tool-agent example root."""
    return repo_root / "examples" / "openai-tool-agent"


@pytest.fixture(autouse=True)
def _gc_sweep_after_each_test() -> Iterator[None]:
    """Force a GC sweep at every test teardown.

    The W16 lifecycle test loads ``examples/openai-tool-agent/python/main.py``
    via ``importlib.util.spec_from_file_location``. Even with lazy
    imports inside the entry-point functions, the module-load can
    transitively pin objects (httpx pools, requests Sessions) whose
    deferred ``__del__`` may emit ResourceWarning under Python 3.14's
    strict ``filterwarnings = ["error", ...]`` regime. Forcing a GC
    sweep at each test boundary keeps deferred cleanup contained to
    the W16 test that triggered the import, preventing the warning
    from being attributed to a downstream test (which would surface
    as a confusing failure in an unrelated suite).
    """
    yield
    gc.collect()
