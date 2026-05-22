"""Plumbing-tier tests for ``scripts/docs/build-error-reference.py``.

Binds VAL-DOCS-M1-009 (m1-f04-error-reference-generator): the error-code
reference generator reads the canonical machine-readable registry at
``packages/schemas/raw/error-codes.yaml`` and writes one Markdown page per
``RELAY-*`` code under ``docs/reference/errors/<CODE>/index.md``.

Slug shape is locked to the directory-style ``<CODE>/index.md`` form so
GitHub Pages serves the page at ``epochly-inc.github.io/relay/errors/<CODE>/``
which is byte-equivalent to the CLI/SDK default error-URL prefix
``https://relay.epochly.com/docs/errors/<CODE>`` (with trailing slash). The
prefix lives in ``packages/sdk-typescript/src/errors.ts`` as
``DEFAULT_DOC_URL_PREFIX``.

Test coverage (per feature dispatch directive):
- ``test_help_exits_zero``
- ``test_yaml_loads`` -- canonical YAML loads under ``yaml.safe_load`` with
  at least 5 entries (the real registry has 50+)
- ``test_yaml_codes_match_pattern`` -- every code matches
  ``RELAY-[A-Z][A-Z0-9_]*-[A-Z0-9_]+``
- ``test_generates_one_page_per_code`` -- invocation on a fixture YAML
  produces one directory per code under ``--out``
- ``test_pages_have_banner`` -- every emitted page has the "Generated from"
  banner pointing back at the YAML source
- ``test_pages_have_slug_matching_url_prefix`` -- the SDK's default
  error-URL prefix concatenated with each code resolves to the generated
  directory slug
- ``test_idempotent`` -- two consecutive generator runs produce
  byte-identical output
- ``test_check_mode_exit_0_no_drift`` -- ``--check`` returns 0 when the
  on-disk output matches the regenerated body
- ``test_check_mode_exit_1_on_drift`` -- ``--check`` returns 1 when a
  page has drifted from the registry
- ``test_no_internal_only_codes_leaked`` -- documents the assumption that
  all codes in the registry are user-facing wire tokens (no
  ``internal_only`` / ``hidden`` flag in source); confirmed by
  inspecting ``docs/internal/error-codes.md`` (the convention doc) and
  the existing wire-token registry, both of which contain no
  internal-only markers.

ASCII-only source per CLAUDE.md "ASCII-Safe Source".

Spec citations:
- plan.md "Wave 1 deliverable 6" (error-code reference auto-generator).
- contract.md VAL-DOCS-M1-009.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "docs" / "build-error-reference.py"
CANONICAL_YAML = REPO_ROOT / "packages" / "schemas" / "raw" / "error-codes.yaml"
SDK_ERRORS_TS = REPO_ROOT / "packages" / "sdk-typescript" / "src" / "errors.ts"

BANNER_FRAGMENT = (
    "Generated from packages/schemas/raw/error-codes.yaml. Do not edit by hand."
)

CODE_PATTERN = re.compile(r"^RELAY-[A-Z][A-Z0-9_]*-[A-Z0-9_]+$")


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the generator script with the active interpreter."""
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or REPO_ROOT),
        env=env,
        timeout=120,
    )


def _write_fixture_yaml(tmp_path: Path) -> Path:
    """Write a minimal fixture YAML with three codes; return its path."""
    body = dedent(
        """\
        schema_version: relay.error_registry.v1
        codes:
          - code: RELAY-ING-031
            domain: ingest
            severity: error
            description: |
              Control-plane ownership violation: the SDK attempted to write a
              canonical run_results.status value.
            triggers: |
              Submitting an ingest envelope whose payload sets a terminal
              ``status`` field instead of leaving the canonical column to the
              control plane.
            how_to_fix: |
              Submit lifecycle metadata only; let the control plane write the
              canonical status row.
            spec_section: "B.4"
            introduced_in: v0.1.0
          - code: RELAY-GATE-021
            domain: gate
            severity: error
            description: |
              Three-anchor handoff is stale: one of scope_id,
              actor_identity_hash, or manifest_commit_hash is missing or
              mismatched.
            triggers: |
              CI submission carrying a manifest_commit_hash outside the
              active or grace window, or a revoked actor identity.
            how_to_fix: |
              Refresh the manifest commit hash and the actor identity; do not
              bypass.
            spec_section: "C.5"
            introduced_in: v0.1.0
          - code: RELAY-FUTURE-999
            domain: future
            severity: informational
            description: |
              Forward-compat fallback for an unknown sidecar code the SDK
              does not recognise.
            triggers: |
              Sidecar emitted a code with a namespace the SDK has not yet
              been updated to map.
            how_to_fix: |
              Upgrade the SDK to a version that recognises the new code.
            introduced_in: v0.1.0
        """
    )
    fixture = tmp_path / "fixture-error-codes.yaml"
    fixture.write_text(body, encoding="utf-8")
    return fixture


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_help_exits_zero() -> None:
    """``--help`` exits 0 and prints usage mentioning ``--check`` and ``--out``."""
    result = _run(["--help"])
    assert result.returncode == 0, (
        f"--help exit={result.returncode}; stderr={result.stderr!r}"
    )
    combined = result.stdout + result.stderr
    assert "--check" in combined, "help text must mention --check flag"
    assert "--out" in combined, "help text must mention --out flag"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_yaml_loads() -> None:
    """Canonical YAML loads under ``yaml.safe_load`` and has >=5 codes."""
    assert CANONICAL_YAML.exists(), (
        f"canonical error-codes YAML missing: {CANONICAL_YAML}"
    )
    data = yaml.safe_load(CANONICAL_YAML.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "YAML top-level must be a mapping"
    assert data.get("schema_version") == "relay.error_registry.v1", (
        "canonical YAML must declare schema_version: relay.error_registry.v1"
    )
    codes = data.get("codes")
    assert isinstance(codes, list), "YAML 'codes' must be a list"
    assert len(codes) >= 5, (
        f"expected at least 5 codes in canonical registry; got {len(codes)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_yaml_codes_match_pattern() -> None:
    """Every code in the canonical YAML matches the RELAY-{DOMAIN}-{TAIL} grammar."""
    data = yaml.safe_load(CANONICAL_YAML.read_text(encoding="utf-8"))
    codes = data["codes"]
    for entry in codes:
        assert isinstance(entry, dict), f"each code entry must be a mapping; got {entry!r}"
        code = entry.get("code")
        assert isinstance(code, str), f"each entry needs a string 'code' field; got {entry!r}"
        assert CODE_PATTERN.match(code), (
            f"code {code!r} does not match RELAY-[A-Z][A-Z0-9_]*-[A-Z0-9_]+ grammar"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_generates_one_page_per_code(tmp_path: Path) -> None:
    """Generator emits one directory per code; each directory has ``index.md``."""
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    result = _run(["--input", str(fixture), "--out", str(out)])
    assert result.returncode == 0, (
        f"generator exit={result.returncode}; stderr={result.stderr!r}; "
        f"stdout={result.stdout!r}"
    )
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    expected_codes = {entry["code"] for entry in data["codes"]}
    seen = set()
    for child in sorted(out.iterdir()):
        if child.is_dir():
            seen.add(child.name)
            assert (child / "index.md").is_file(), (
                f"directory {child} missing index.md"
            )
    assert seen == expected_codes, (
        f"directory set {sorted(seen)} != expected codes {sorted(expected_codes)}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_pages_have_banner(tmp_path: Path) -> None:
    """Every emitted page contains the BANNER_FRAGMENT."""
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    result = _run(["--input", str(fixture), "--out", str(out)])
    assert result.returncode == 0, f"generator failed: {result.stderr!r}"
    pages = list(out.rglob("index.md"))
    assert pages, "generator produced no pages"
    for p in pages:
        body = p.read_text(encoding="utf-8")
        assert BANNER_FRAGMENT in body, (
            f"page {p} missing banner fragment {BANNER_FRAGMENT!r}"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_pages_have_slug_matching_url_prefix(tmp_path: Path) -> None:
    """Generated slug pattern matches the SDK default error-URL prefix shape.

    The SDK builds documentation URLs as
    ``${DEFAULT_DOC_URL_PREFIX}${code}``. The default prefix is
    ``https://relay.epochly.com/docs/errors/`` (note trailing slash). When
    GitHub Pages serves the staging site at
    ``epochly-inc.github.io/relay/errors/<CODE>/`` the directory-style
    ``<CODE>/index.md`` layout produces the same path component.
    """
    # Extract DEFAULT_DOC_URL_PREFIX literal from the SDK source.
    src = SDK_ERRORS_TS.read_text(encoding="utf-8")
    m = re.search(
        r"DEFAULT_DOC_URL_PREFIX\s*=\s*\"(?P<url>[^\"]+)\"",
        src,
    )
    assert m, "could not locate DEFAULT_DOC_URL_PREFIX in errors.ts"
    prefix = m.group("url")
    assert prefix.endswith("/"), (
        f"SDK error-URL prefix must end with '/'; got {prefix!r}"
    )
    # The path component after the prefix is the code itself. We assert the
    # generator places each code at <out>/<CODE>/index.md so the slug shape
    # after prefix is exactly /<CODE>/ (or /<CODE> with a redirect).
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    result = _run(["--input", str(fixture), "--out", str(out)])
    assert result.returncode == 0, f"generator failed: {result.stderr!r}"
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    for entry in data["codes"]:
        code = entry["code"]
        sdk_url = f"{prefix}{code}"
        # Slug component after the prefix base must be the same code token
        # the generator wrote on disk.
        assert sdk_url.endswith(f"/{code}"), (
            f"SDK URL {sdk_url!r} does not terminate in /{code}"
        )
        page = out / code / "index.md"
        assert page.is_file(), (
            f"generated slug {code}/index.md missing; "
            f"would break {sdk_url}/"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_idempotent(tmp_path: Path) -> None:
    """Two consecutive runs against the same fixture produce identical output."""
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    r1 = _run(["--input", str(fixture), "--out", str(out)])
    assert r1.returncode == 0, f"first run failed: {r1.stderr!r}"
    snapshot_first = {
        p.relative_to(out): p.read_bytes() for p in sorted(out.rglob("*"))
        if p.is_file()
    }
    r2 = _run(["--input", str(fixture), "--out", str(out)])
    assert r2.returncode == 0, f"second run failed: {r2.stderr!r}"
    snapshot_second = {
        p.relative_to(out): p.read_bytes() for p in sorted(out.rglob("*"))
        if p.is_file()
    }
    assert snapshot_first == snapshot_second, (
        "generator is not idempotent: byte content differs between runs"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_check_mode_exit_0_no_drift(tmp_path: Path) -> None:
    """``--check`` returns 0 when on-disk matches generated output."""
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    r1 = _run(["--input", str(fixture), "--out", str(out)])
    assert r1.returncode == 0, f"initial generate failed: {r1.stderr!r}"
    r2 = _run(["--check", "--input", str(fixture), "--out", str(out)])
    assert r2.returncode == 0, (
        f"--check on clean tree returned {r2.returncode}; "
        f"stderr={r2.stderr!r}; stdout={r2.stdout!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_check_mode_exit_1_on_drift(tmp_path: Path) -> None:
    """``--check`` returns 1 when on-disk content has drifted from the YAML."""
    fixture = _write_fixture_yaml(tmp_path)
    out = tmp_path / "errors"
    r1 = _run(["--input", str(fixture), "--out", str(out)])
    assert r1.returncode == 0, f"initial generate failed: {r1.stderr!r}"
    # Drift a page: overwrite the body with text the generator would never
    # produce.
    target = out / "RELAY-ING-031" / "index.md"
    target.write_text("# tampered\n", encoding="utf-8")
    r2 = _run(["--check", "--input", str(fixture), "--out", str(out)])
    assert r2.returncode == 1, (
        f"--check on drifted tree returned {r2.returncode}; "
        f"expected exit 1; stderr={r2.stderr!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-DOCS-M1-009")
def test_no_internal_only_codes_leaked() -> None:
    """Document the assumption that every code in the registry is user-facing.

    Neither ``docs/internal/error-codes.md`` (the naming-convention doc)
    nor the canonical wire-token registry at
    ``packages/schemas/raw/relay-error-codes.yaml`` carries an
    ``internal_only`` / ``hidden`` flag. Codes flagged
    ``[OUT-OF-SCOPE-PRIVATE]`` describe the *enforcement* path living in
    private ``relay-platform`` -- the wire token itself is still user-
    visible (the CLI/SDK can decode an envelope produced by the hosted
    surface), so those codes belong in the user-facing reference.

    This test asserts the assumption is still true: no entry in the
    canonical YAML carries a truthy ``internal_only`` / ``hidden``
    boolean. If a future entry adds such a flag, the generator must be
    updated to skip it and this assertion will fail loudly.
    """
    data = yaml.safe_load(CANONICAL_YAML.read_text(encoding="utf-8"))
    codes = data.get("codes", [])
    leaked: list[str] = []
    for entry in codes:
        if not isinstance(entry, dict):
            continue
        if entry.get("internal_only") or entry.get("hidden"):
            leaked.append(entry.get("code", "<unknown>"))
    assert not leaked, (
        f"codes flagged internal_only/hidden present in user-facing registry: "
        f"{leaked}; update the generator to skip them"
    )
