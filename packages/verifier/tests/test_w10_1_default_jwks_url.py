"""W10.1 VAL-W10-001: compiled-in default JWKS URL string-equality guard.

VAL-W10-001 requires that:

  * The default JWKS URL constant equals the exact spec-pinned literal.
  * A source grep over ``packages/verifier/**/*.py`` (excluding test
    paths) returns exactly one occurrence of the literal.

The post-build artifact grep (Python wheel, TS dist, npm tarball) is
exercised in CI by ``scripts/check-codegen-drift.py`` and the release
pipeline; this plumbing-tier test covers the source-side guarantee.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from relay_verifier.constants import DEFAULT_JWKS_URL

# The exact literal the spec mandates (AO.4 line 6165). Hardcoded here
# so the test does not transitively read DEFAULT_JWKS_URL to assert
# DEFAULT_JWKS_URL.
_EXACT_DEFAULT_URL: str = "https://relay.epochly.com/.well-known/jwks.json"


def _verifier_package_root() -> Path:
    """Return ``packages/verifier`` regardless of pytest cwd."""
    here = Path(__file__).resolve()
    # tests/test_w10_1_default_jwks_url.py -> tests -> packages/verifier
    return here.parent.parent


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-001")
def test_default_jwks_url_is_spec_pinned_literal() -> None:
    """The compiled-in constant equals the spec-pinned URL byte-for-byte."""
    assert DEFAULT_JWKS_URL == _EXACT_DEFAULT_URL


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-001")
def test_default_jwks_url_has_single_canonical_occurrence_in_python_source() -> None:
    """Source-grep over ``packages/verifier/src/**/*.py`` returns exactly one hit.

    Per VAL-W10-001 the default URL literal must appear ONCE in the
    verifier package's Python source outside the test tree. This test
    walks the package's src/ tree (excluding tests) and counts byte
    occurrences of the literal URL in *.py files.
    """
    pkg_root = _verifier_package_root()
    src_root = pkg_root / "src"
    assert src_root.is_dir(), f"verifier src not found at {src_root!s}"

    hits: list[tuple[Path, int, str]] = []
    for path in sorted(src_root.rglob("*.py")):
        # Skip nothing under src/ -- tests live outside src/.
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _EXACT_DEFAULT_URL in line:
                hits.append((path, lineno, line.strip()))

    assert len(hits) == 1, (
        f"VAL-W10-001 grep guard: expected exactly 1 occurrence of "
        f"{_EXACT_DEFAULT_URL!r} in packages/verifier/src/**/*.py; got "
        f"{len(hits)} at: {hits!r}. Per CLAUDE.md banned pattern #13 the "
        "default trust-anchor URL must have a single canonical "
        "occurrence; if a new module needs the URL, import the constant."
    )

    # And the one hit must live on the DEFAULT_JWKS_URL assignment line.
    only_path, _only_line, only_text = hits[0]
    assert only_path.name == "constants.py", (
        f"VAL-W10-001: the canonical URL occurrence must live in "
        f"constants.py; found in {only_path!s}"
    )
    assert "DEFAULT_JWKS_URL" in only_text


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-001")
def test_default_jwks_url_has_no_forbidden_variants_in_python_source() -> None:
    """Mutated URL variants must not appear anywhere in the package source.

    The post-build artifact check (run in CI) defends against build-time
    rewrites, tree-shaking that drops the constant, and silent envar
    overrides. The plumbing-tier source check below catches the most
    common mistake -- a contributor copy-pasting a near-identical URL
    string (trailing slash, http scheme, wrong subdomain) into source.
    """
    pkg_root = _verifier_package_root()
    src_root = pkg_root / "src"

    forbidden_variants = [
        "http://relay.epochly.com/.well-known/jwks.json",  # http scheme
        "https://relay.epochly.com/.well-known/jwks.json/",  # trailing slash
        "https://www.relay.epochly.com/.well-known/jwks.json",  # www subdomain
        "https://staging.relay.epochly.com/.well-known/jwks.json",  # staging
    ]
    bad_hits: list[tuple[str, Path, int]] = []
    for path in sorted(src_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for variant in forbidden_variants:
                if variant in line:
                    bad_hits.append((variant, path, lineno))
    assert not bad_hits, (
        f"VAL-W10-001: forbidden URL variant(s) appear in source: {bad_hits!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-001")
def test_default_jwks_url_uses_https_and_well_known_path() -> None:
    """Structural assertion: scheme is https, path is RFC 5785 .well-known."""
    assert DEFAULT_JWKS_URL.startswith("https://")
    assert "/.well-known/jwks.json" in DEFAULT_JWKS_URL
    # No accidental whitespace / null / control chars.
    assert not re.search(r"[\s\x00-\x1f]", DEFAULT_JWKS_URL)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W10-001")
def test_default_jwks_url_visible_in_installed_package_metadata() -> None:
    """The installed package exposes DEFAULT_JWKS_URL through its public surface.

    Verifies that the post-install consumer can import the constant
    without depending on src layout. ``uv pip show`` would confirm the
    distribution is installed; we check the import path instead, which
    is the binding the spec actually requires.
    """
    completed = subprocess.run(
        [
            "python",
            "-c",
            (
                "import relay_verifier; "
                "import sys; "
                "sys.exit(0 if relay_verifier.DEFAULT_JWKS_URL "
                f"== {_EXACT_DEFAULT_URL!r} else 1)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, (
        f"installed relay_verifier.DEFAULT_JWKS_URL drift: stdout="
        f"{completed.stdout!r} stderr={completed.stderr!r}"
    )
