"""VAL-W2-001: Lockfile path is ``${RELAY_HOME:-~/.relay}/sidecar.lock``.

Tests:
  - RELAY_HOME-set path resolves to ``<RELAY_HOME>/sidecar.lock``.
  - RELAY_HOME-unset path resolves to ``~/.relay/sidecar.lock``.
  - No /tmp/relay-sidecar.lock fallback after spawn.
  - No ``./sidecar.lock`` cwd-relative spawn.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from relay_sidecar.lockfile import resolve_lockfile_path
from relay_sidecar.spawn import acquire_or_attach


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-001")
def test_lockfile_path_uses_relay_home_env(relay_home_tmp: Path) -> None:
    """RELAY_HOME is honored verbatim."""
    expected = relay_home_tmp / "sidecar.lock"
    assert resolve_lockfile_path() == expected


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-001")
def test_lockfile_path_default_relay_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without RELAY_HOME the default is ``~/.relay/sidecar.lock``."""
    monkeypatch.delenv("RELAY_HOME", raising=False)
    # Redirect HOME so we don't depend on the developer's real home.
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    resolved = resolve_lockfile_path()
    assert resolved == fake_home / ".relay" / "sidecar.lock"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W2-001")
def test_spawn_writes_lockfile_under_relay_home_only(
    relay_home_tmp: Path,
    isolated_cwd: Path,
) -> None:
    """After spawn the lockfile lives ONLY under RELAY_HOME.

    Specifically asserts: no /tmp/relay-sidecar.lock fallback file is
    created; no cwd-relative ./sidecar.lock is created.
    """
    expected = relay_home_tmp / "sidecar.lock"
    assert not expected.exists()

    decision = acquire_or_attach(
        home=relay_home_tmp,
        process_runner=lambda: (os.getpid(), 49999),
    )
    assert decision.action == "spawned"
    assert expected.is_file()

    # Negative paths.
    assert not Path("/tmp/relay-sidecar.lock").exists() or not Path(
        "/tmp/relay-sidecar.lock"
    ).is_file()
    assert not (isolated_cwd / "sidecar.lock").exists()
