"""W12.1 tests for the SemVer monotonicity gate (VAL-W12-040).

These are pure unit tests against the in-memory SemVer comparator AND
subprocess-level tests that invoke ``scripts/check-semver-monotonic.py``
with ``--published`` injection so no network call is made.

The gate enforces: a proposed release version MUST be strictly greater
than every prior published version of ``epochly-relay`` under SemVer
2.0.0 precedence ordering. Equality is forbidden (rollback via
version increment per VAL-W12-039).
"""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
SEMVER_SCRIPT: Path = REPO_ROOT / "scripts" / "check-semver-monotonic.py"


def _load_semver_module():
    """Import the script as a module so we can unit-test the in-memory API.

    Python 3.14's ``dataclasses`` module calls
    ``sys.modules.get(cls.__module__).__dict__`` during ``@dataclass``
    decoration, so the module MUST be registered in ``sys.modules``
    before ``exec_module`` runs (the script defines a ``@dataclass``
    at module scope). Without registration ``sys.modules.get(...)``
    returns ``None`` and dataclass decoration crashes.
    """
    name = "_check_semver_monotonic"
    spec = importlib.util.spec_from_file_location(name, SEMVER_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


SEMVER_MOD = _load_semver_module()


# ---------------------------------------------------------------------------
# Unit tests against the in-memory SemVer comparator.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
def test_parse_semver_accepts_canonical_release() -> None:
    v = SEMVER_MOD.parse_semver("0.1.0")
    assert (v.major, v.minor, v.patch) == (0, 1, 0)
    assert v.prerelease == ()
    assert v.raw == "0.1.0"


@pytest.mark.plumbing
def test_parse_semver_accepts_prerelease_identifiers() -> None:
    v = SEMVER_MOD.parse_semver("1.0.0-alpha.1")
    assert (v.major, v.minor, v.patch) == (1, 0, 0)
    assert v.prerelease == ("alpha", "1")


@pytest.mark.plumbing
def test_parse_semver_rejects_missing_patch() -> None:
    with pytest.raises(ValueError):
        SEMVER_MOD.parse_semver("0.1")


@pytest.mark.plumbing
def test_parse_semver_rejects_leading_zero_in_numeric_field() -> None:
    with pytest.raises(ValueError):
        SEMVER_MOD.parse_semver("0.01.0")


@pytest.mark.plumbing
def test_parse_semver_accepts_build_metadata_but_discards_it() -> None:
    v = SEMVER_MOD.parse_semver("1.2.3+build.5")
    assert (v.major, v.minor, v.patch) == (1, 2, 3)
    # Build metadata MUST be ignored for precedence (SemVer 2.0.0 rule 10).
    same = SEMVER_MOD.parse_semver("1.2.3+build.6")
    assert SEMVER_MOD.compare_semver(v, same) == 0


@pytest.mark.plumbing
@pytest.mark.parametrize(
    "a_raw, b_raw, expected",
    [
        ("0.1.0", "0.1.0", 0),
        ("0.1.0", "0.1.1", -1),
        ("0.2.0", "0.1.999", 1),
        ("1.0.0", "0.99.99", 1),
        # Pre-release < release.
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-rc.1", "1.0.0", -1),
        # Pre-release ordering.
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha.2", -1),
        ("1.0.0-alpha.2", "1.0.0-beta", -1),
        ("1.0.0-rc.1", "1.0.0-rc.2", -1),
        # Numeric vs alphanumeric: numeric is lower precedence.
        ("1.0.0-1", "1.0.0-alpha", -1),
        # Build metadata ignored.
        ("1.0.0+build.1", "1.0.0+build.2", 0),
    ],
)
def test_compare_semver_matches_spec_precedence(
    a_raw: str, b_raw: str, expected: int
) -> None:
    a = SEMVER_MOD.parse_semver(a_raw)
    b = SEMVER_MOD.parse_semver(b_raw)
    assert SEMVER_MOD.compare_semver(a, b) == expected, (
        f"{a_raw} vs {b_raw}: expected {expected}, got {SEMVER_MOD.compare_semver(a, b)}"
    )
    # Anti-symmetry.
    assert SEMVER_MOD.compare_semver(b, a) == -expected


# ---------------------------------------------------------------------------
# Subprocess tests: invoke the CLI with --published injection (offline).
# ---------------------------------------------------------------------------


def _run_gate(
    *,
    version: str,
    published: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SEMVER_SCRIPT), "--version", version]
    if published is not None:
        cmd += ["--published", published]
    return subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, check=False, timeout=30
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_accepts_first_release_against_empty_published() -> None:
    proc = _run_gate(version="0.1.0", published="")
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"
    assert "monotonic per SemVer" in proc.stdout


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
# The pytest unraisable-exception hook (Python 3.14) catches benign GC
# noise from test-scope tempfiles AND from HTTPError responses being
# implicitly cleaned up, then escalates under the repo-wide
# `filterwarnings = ["error"]`. Suppress only those two specific known
# unraisable forms; any other PytestUnraisableExceptionWarning still
# fails the test.
@pytest.mark.filterwarnings(
    "ignore:Exception ignored while calling deallocator"
    ":pytest.PytestUnraisableExceptionWarning"
)
@pytest.mark.filterwarnings(
    "ignore:Implicitly cleaning up"
    ":pytest.PytestUnraisableExceptionWarning"
)
def test_fetch_published_versions_treats_pypi_404_as_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The FIRST publish to PyPI hits a 404 because the package has
    never been published. The gate must treat that as "no prior
    versions" -- not as a fetch error -- otherwise it permanently
    blocks every first release at the precheck step."""
    import urllib.error

    mod = _load_semver_module()

    def _raise_404(*_a, **_kw):
        raise urllib.error.HTTPError(
            url=mod.PYPI_JSON_URL,
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b""),
        )

    monkeypatch.setattr(mod.urllib.request, "urlopen", _raise_404)
    assert mod._fetch_published_versions() == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
# Same unraisable-hook escalation as the 404 test sibling: any HTTPError
# constructed in-test can emit a benign ResourceWarning during GC under
# Python 3.14 + pytest, which the repo-wide filterwarnings=error promotes
# to a failure. Suppress only that specific known noise.
@pytest.mark.filterwarnings(
    "ignore:Implicitly cleaning up"
    ":pytest.PytestUnraisableExceptionWarning"
)
@pytest.mark.filterwarnings(
    "ignore:Exception ignored while calling deallocator"
    ":pytest.PytestUnraisableExceptionWarning"
)
def test_fetch_published_versions_aborts_on_non_404_http_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Any non-404 HTTP error (5xx, etc.) is a real fetch failure and
    MUST abort with exit 4 -- not silently fall through as if there
    were no prior versions."""
    import urllib.error

    mod = _load_semver_module()

    def _raise_503(*_a, **_kw):
        raise urllib.error.HTTPError(
            url=mod.PYPI_JSON_URL,
            code=503,
            msg="Service Unavailable",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b""),
        )

    monkeypatch.setattr(mod.urllib.request, "urlopen", _raise_503)
    with pytest.raises(SystemExit) as excinfo:
        mod._fetch_published_versions()
    assert excinfo.value.code == 4


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_accepts_strictly_greater_version() -> None:
    proc = _run_gate(version="0.2.0", published="0.1.0,0.1.1,0.1.2")
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_rejects_equal_version() -> None:
    """Republishing an existing version is forbidden (no destructive rollback)."""
    proc = _run_gate(version="0.1.0", published="0.1.0,0.1.1")
    assert proc.returncode == 1
    assert "RELAY-RELEASE-040" in proc.stderr
    assert "already published" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_rejects_lesser_version() -> None:
    proc = _run_gate(version="0.1.0", published="0.1.5,0.2.0")
    assert proc.returncode == 1
    assert "RELAY-RELEASE-040" in proc.stderr
    assert "not strictly greater" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_strips_leading_v_from_proposed_version() -> None:
    proc = _run_gate(version="v0.2.0", published="0.1.0")
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_rejects_malformed_version_string() -> None:
    proc = _run_gate(version="0.1", published="")
    assert proc.returncode == 2
    assert "valid SemVer" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_rejects_prerelease_when_release_already_published() -> None:
    """1.0.0-rc.1 < 1.0.0 per SemVer; if 1.0.0 is already published, gate fails."""
    proc = _run_gate(version="1.0.0-rc.1", published="1.0.0")
    assert proc.returncode == 1
    assert "RELAY-RELEASE-040" in proc.stderr


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W12-040")
def test_gate_accepts_release_when_prereleases_published() -> None:
    proc = _run_gate(version="1.0.0", published="1.0.0-alpha.1,1.0.0-rc.1")
    assert proc.returncode == 0, f"stderr={proc.stderr!r}"


@pytest.mark.plumbing
def test_gate_emits_ascii_only_output() -> None:
    proc = _run_gate(version="0.1.0", published="")
    combined = proc.stdout + proc.stderr
    non_ascii = [c for c in combined if ord(c) > 127]
    assert not non_ascii, f"non-ASCII output: {non_ascii[:5]!r}"
