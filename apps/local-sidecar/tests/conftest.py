"""Shared pytest fixtures for the local-sidecar W2.1 test suite.

Every test that touches ``RELAY_HOME`` MUST use a per-test temp directory
so we never write to the developer's real ``~/.relay``. The
``relay_home_tmp`` fixture sets ``RELAY_HOME`` to a fresh tmpdir for the
duration of one test and restores the prior value on teardown.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def relay_home_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Set RELAY_HOME to a fresh tmpdir for the test; yield the path.

    The directory itself is created (so callers can immediately resolve
    paths under it). RELAY_HOME is restored to its prior value on
    teardown via ``monkeypatch.setenv`` semantics.
    """
    home = tmp_path / "relay-home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("RELAY_HOME", str(home))
    yield home
    # monkeypatch handles the env restore automatically.


@pytest.fixture
def isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Change to an isolated cwd for the test; restore on teardown.

    Used by VAL-W2-001 to prove the sidecar never writes a cwd-relative
    ``./sidecar.lock``.
    """
    cwd = tmp_path / "cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(cwd)
    yield cwd


# Suppress unused-import / unused-symbol warnings for fixtures.
_ = os
