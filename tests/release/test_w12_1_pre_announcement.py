"""W12.1 tests for the pre-announcement gate (VAL-W12-046).

Plumbing-tier tests against ``scripts/check-pre-announcement.py``.
Tests use ``--repo-root tmp_path`` and ``--now`` to inject a frozen
timestamp so the 7-day-lead-time logic is deterministic and offline.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
ANN_SCRIPT: Path = REPO_ROOT / "scripts" / "check-pre-announcement.py"


def _load_module():
    """Import the script. Register in sys.modules before exec_module so
    Python 3.14's dataclass machinery can resolve ``cls.__module__``."""
    name = "_check_pre_announcement"
    spec = importlib.util.spec_from_file_location(name, ANN_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ANN_MOD = _load_module()


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _make_announcement(
    repo: Path,
    *,
    name: str,
    target_version: str,
    breaking: bool,
    published_at: str,
) -> Path:
    """Write an announcement file under <repo>/docs/release/announcements/."""
    ann_dir = repo / "docs" / "release" / "announcements"
    ann_dir.mkdir(parents=True, exist_ok=True)
    path = ann_dir / name
    body = textwrap.dedent(
        f"""\
        ---
        target_version: {target_version}
        breaking: {"true" if breaking else "false"}
        published_at: {published_at}
        ---

        # Test announcement for {target_version}
        """
    )
    path.write_text(body, encoding="utf-8")
    return path


def _run_gate(
    *,
    tag: str,
    message: str,
    repo: Path,
    now: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(ANN_SCRIPT),
        "--tag",
        tag,
        "--message",
        message,
        "--repo-root",
        str(repo),
    ]
    if now is not None:
        cmd += ["--now", now]
    return subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, check=False, timeout=30
    )


# ---------------------------------------------------------------------------
# In-memory tests against the breaking-token detector.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_breaking_token_detected_only_on_own_line() -> None:
    msg = "Header\n\nRELAY-BREAKING-CHANGE\n\nBody mentions RELAY-BREAKING-CHANGE inline."
    assert ANN_MOD._is_breaking(msg) is True


@pytest.mark.plumbing
def test_breaking_token_inline_does_not_count() -> None:
    msg = (
        "v0.2.0\n\n"
        "This is not a `RELAY-BREAKING-CHANGE` since the token is backticked.\n"
    )
    assert ANN_MOD._is_breaking(msg) is False


@pytest.mark.plumbing
def test_breaking_token_with_leading_whitespace_still_counts() -> None:
    msg = "Header\n   RELAY-BREAKING-CHANGE   \nBody"
    assert ANN_MOD._is_breaking(msg) is True


@pytest.mark.plumbing
def test_parse_frontmatter_rejects_missing_delimiter(tmp_path: Path) -> None:
    bad = tmp_path / "bad.md"
    bad.write_text("No frontmatter at all\nbody", encoding="utf-8")
    with pytest.raises(ValueError):
        ANN_MOD._parse_announcement(bad)


@pytest.mark.plumbing
def test_parse_frontmatter_rejects_naive_timestamp(tmp_path: Path) -> None:
    bad = tmp_path / "naive.md"
    bad.write_text(
        textwrap.dedent(
            """\
            ---
            target_version: 1.0.0
            breaking: true
            published_at: 2026-01-01T00:00:00
            ---
            body
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        ANN_MOD._parse_announcement(bad)


# ---------------------------------------------------------------------------
# Subprocess tests against the full gate.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_non_breaking_tag_passes_without_announcement(tmp_path: Path) -> None:
    """A non-breaking tag exits 0 even when no announcements exist."""
    (tmp_path / "docs" / "release" / "announcements").mkdir(
        parents=True, exist_ok=True
    )
    proc = _run_gate(
        tag="v0.1.5",
        message="v0.1.5 routine release",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"
    assert "non-breaking" in proc.stdout


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_breaking_tag_rejected_without_any_announcement(tmp_path: Path) -> None:
    (tmp_path / "docs" / "release" / "announcements").mkdir(
        parents=True, exist_ok=True
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n\nDrops Python 3.11.",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 1
    assert "RELAY-RELEASE-046" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_breaking_tag_rejected_when_announcement_too_recent(tmp_path: Path) -> None:
    """An announcement less than 7 days old does NOT satisfy the gate."""
    _make_announcement(
        tmp_path,
        name="2026-05-28-drop-py311.md",
        target_version="1.0.0",
        breaking=True,
        # 4 days before 'now'.
        published_at="2026-05-28T00:00:00Z",
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 1
    assert "RELAY-RELEASE-046" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_breaking_tag_accepted_when_announcement_old_enough(tmp_path: Path) -> None:
    _make_announcement(
        tmp_path,
        name="2026-05-15-drop-py311.md",
        target_version="1.0.0",
        breaking=True,
        # 17 days before 'now'.
        published_at="2026-05-15T00:00:00Z",
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"
    assert "qualifying announcement" in proc.stdout


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_breaking_tag_rejected_when_announcement_targets_different_version(
    tmp_path: Path,
) -> None:
    """An old announcement for v2.0.0 does NOT cover a v1.0.0 breaking release."""
    _make_announcement(
        tmp_path,
        name="2026-04-01-drop-py312.md",
        target_version="2.0.0",
        breaking=True,
        published_at="2026-04-01T00:00:00Z",
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 1
    assert "RELAY-RELEASE-046" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_breaking_tag_rejected_when_announcement_marked_non_breaking(
    tmp_path: Path,
) -> None:
    """A non-breaking announcement does not satisfy a breaking release gate."""
    _make_announcement(
        tmp_path,
        name="2026-04-01-changelog.md",
        target_version="1.0.0",
        breaking=False,  # <-- explicitly marked non-breaking
        published_at="2026-04-01T00:00:00Z",
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 1
    assert "RELAY-RELEASE-046" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_announcement_published_exactly_7_days_ago_is_accepted(
    tmp_path: Path,
) -> None:
    """Boundary condition: published_at == now - 7d is accepted (inclusive)."""
    _make_announcement(
        tmp_path,
        name="2026-05-25-drop-py311.md",
        target_version="1.0.0",
        breaking=True,
        published_at="2026-05-25T00:00:00Z",
    )
    proc = _run_gate(
        tag="v1.0.0",
        message="v1.0.0\n\nRELAY-BREAKING-CHANGE\n",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-046")
def test_readme_in_announcements_dir_is_ignored(tmp_path: Path) -> None:
    """A README.md in the announcements directory must NOT be parsed as an announcement."""
    ann_dir = tmp_path / "docs" / "release" / "announcements"
    ann_dir.mkdir(parents=True, exist_ok=True)
    (ann_dir / "README.md").write_text(
        "# Not an announcement, no frontmatter here.\n", encoding="utf-8"
    )
    # Non-breaking tag exits 0 without ever attempting to parse README.md.
    proc = _run_gate(
        tag="v0.1.5",
        message="routine",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"


@pytest.mark.plumbing
def test_pre_announcement_gate_emits_ascii_only_output(tmp_path: Path) -> None:
    (tmp_path / "docs" / "release" / "announcements").mkdir(
        parents=True, exist_ok=True
    )
    proc = _run_gate(
        tag="v0.1.5",
        message="routine",
        repo=tmp_path,
        now="2026-06-01T00:00:00Z",
    )
    combined = proc.stdout + proc.stderr
    non_ascii = [c for c in combined if ord(c) > 127]
    assert not non_ascii, f"non-ASCII: {non_ascii[:5]!r}"
