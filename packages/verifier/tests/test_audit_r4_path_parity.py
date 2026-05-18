"""AUDIT-R4 BUG-H2: Python/TS parity for check_artifact_path.

The 2026-05-18 R4 audit found that
``packages/verifier/src/relay_verifier/bundle_paths.py::check_artifact_path``
diverged from its TS port at
``packages/verifier-typescript/src/bundle_paths.ts::checkArtifactPath``.
TS rejected three categories that Python did NOT:

* NUL byte (``\\x00``) embedded in the path.
* Empty / leading-or-trailing whitespace.
* UTF-8 byte length > 1024.

R3 commit ``91b9d88`` claimed "match Python line-for-line"; the
hardening was tightened on the TS side but not on the Python side,
leaving a real parity gap. This module locks in the post-fix Python
behavior: each of the three new categories is rejected with
``path_violation = "invalid_utf8_name"`` and the existing
``RELAY-EVID-024`` wire code.

Positive cases (clean relative paths) MUST still be accepted -- this
is a tightening, not a relaxation, so backward compatibility for
legitimate inputs is preserved.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay_verifier.bundle_paths import (
    MAX_ARTIFACT_PATH_BYTES,
    RELAY_EVID_024,
    check_artifact_path,
)


@pytest.mark.plumbing
def test_check_artifact_path_rejects_nul_byte() -> None:
    """Embedded NUL byte rejection (TS parity)."""
    result = check_artifact_path("foo\x00bar")
    assert result is not None
    assert result["code"] == RELAY_EVID_024
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_nul_byte_at_start() -> None:
    """NUL byte at the start (would truncate to empty on C-string APIs)."""
    result = check_artifact_path("\x00foo")
    assert result is not None
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_empty_string() -> None:
    """Empty string is not a valid artifact path."""
    result = check_artifact_path("")
    assert result is not None
    assert result["code"] == RELAY_EVID_024
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_whitespace_only() -> None:
    """Whitespace-only string strips to empty -> rejected."""
    for path in ("   ", "\t", "\n", " \t\n "):
        result = check_artifact_path(path)
        assert result is not None, f"expected reject for {path!r}"
        assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_leading_whitespace() -> None:
    """Leading whitespace is a path-collision attack vector."""
    result = check_artifact_path("  artifacts/foo.txt")
    assert result is not None
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_trailing_whitespace() -> None:
    """Trailing whitespace is a path-collision attack vector."""
    result = check_artifact_path("artifacts/foo.txt  ")
    assert result is not None
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_rejects_over_1024_utf8_bytes() -> None:
    """A path > 1024 UTF-8 bytes is rejected (TS parity)."""
    long_path = "a" * (MAX_ARTIFACT_PATH_BYTES + 1)
    result = check_artifact_path(long_path)
    assert result is not None
    assert result["code"] == RELAY_EVID_024
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_accepts_exactly_1024_utf8_bytes() -> None:
    """Boundary: exactly 1024 bytes is allowed (strict greater-than)."""
    boundary = "a" * MAX_ARTIFACT_PATH_BYTES
    # 1024 chars of ASCII = 1024 UTF-8 bytes; clean relative path.
    result = check_artifact_path(boundary)
    # No path violation -- boundary value is accepted.
    assert result is None, result


@pytest.mark.plumbing
def test_check_artifact_path_rejects_multibyte_over_cap() -> None:
    """Multi-byte chars count by UTF-8 byte length, not char length."""
    # Each "é" is 2 UTF-8 bytes; 600 chars = 1200 bytes > 1024.
    multibyte_long = "é" * 600  # NFC-form "é"
    result = check_artifact_path(multibyte_long)
    assert result is not None
    assert result["path_violation"] == "invalid_utf8_name"


@pytest.mark.plumbing
def test_check_artifact_path_accepts_clean_relative_paths() -> None:
    """Backward compatibility: legitimate inputs are still accepted."""
    for path in (
        "artifacts/test.log",
        "nested/dir/file.txt",
        "my.file.txt",
        # ".." as a literal substring inside a segment (not standalone) is OK.
        "my..file.txt",
        "artifacts/run-001/output.json",
    ):
        result = check_artifact_path(path)
        assert result is None, f"unexpected reject for {path!r}: {result}"


@pytest.mark.plumbing
def test_check_artifact_path_existing_categories_still_work() -> None:
    """Pre-existing categories (absolute, traversal, NFC) still fire
    after the new checks were inserted before them in the pipeline."""
    # Absolute.
    result = check_artifact_path("/etc/passwd")
    assert result is not None and result["path_violation"] == "absolute_path"

    # Relative traversal.
    result = check_artifact_path("../../etc/passwd")
    assert result is not None and result["path_violation"] == "relative_traversal"

    # NFC.
    import unicodedata

    nfd_path = "artifacts/" + unicodedata.normalize("NFD", "café.txt")
    result = check_artifact_path(nfd_path)
    assert result is not None and result["path_violation"] == "non_nfc_name"


__all__ = []
