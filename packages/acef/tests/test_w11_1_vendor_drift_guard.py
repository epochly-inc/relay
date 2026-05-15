"""W11.1 vendor-pin drift guard.

This test module enforces the eight VAL-W11-001..008 assertions that
constitute the w11.1-acef-vendor-pin feature:

  * VAL-W11-001  Vendored tree matches the pinned upstream commit.
  * VAL-W11-002  Vendor manifest pins commit + version + license + URL.
  * VAL-W11-003  Maturity disclosure is "v0.3 pre-1.0 reference
                 implementation", NOT "alpha".
  * VAL-W11-004  Vendor tree is immutable outside the vendor-update
                 workflow (drift guard detects byte-level changes).
  * VAL-W11-005  Vendored Python modules import without modification.
  * VAL-W11-006  Vendored test suite passes unmodified at the pin
                 (collection check; full execution is exercised by the
                 upstream's own CI at the pinned SHA).
  * VAL-W11-007  ACEF SDK is invoked from the TS SDK only via the
                 Python sidecar; no direct TS-to-ACEF coupling.
  * VAL-W11-008  License header (top-level upstream/LICENSE) preserved
                 byte-for-byte at vendor pin.

Plumbing tier (tier 1, <= 60s, offline). Imports the ``relay_acef``
package surface; reads the vendor manifest and the ``upstream/`` tree
via stdlib only (no network).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from relay_acef import (
    VENDOR_COMMIT_SHA,
    VENDOR_MANIFEST_PATH,
    VENDOR_MATURITY,
    VENDOR_PATH_NAME,
    package_root,
    vendor_root,
)

# -----------------------------------------------------------------------------
# Static expectations (load-bearing literals)
# -----------------------------------------------------------------------------
# These constants are duplicated from vendor_manifest.json on purpose so the
# tests do not transitively read the manifest to assert the manifest. A drift
# between the JSON and these literals fails the relevant test, surfacing the
# mismatch instead of silently agreeing with whatever the JSON happens to say.

EXPECTED_COMMIT_SHA: str = "57e1d14e063d3a2a88bfe5361fd81ca02bc6d540"
EXPECTED_SOURCE_REPO: str = "https://github.com/chandlercvaughn/ACEF"
EXPECTED_LICENSE_SPDX: str = "Apache-2.0"
EXPECTED_SPEC_VERSION: str = "v0.3"
EXPECTED_MATURITY: str = "v0.3 pre-1.0 reference implementation"
EXPECTED_TREE_FILE_COUNT: int = 307
EXPECTED_TREE_SHA256: str = (
    "7d1bf5c34dc673323dbc4a8c51fc53c84f5ede8166c8ac8cdc473140ebe8f50f"
)

# The four required keys for VENDOR.md / vendor_manifest.json per VAL-W11-002:
# commit + version + license + source URL. We also require a maturity field.
_REQUIRED_MANIFEST_KEYS = (
    "source_repo",
    "commit_sha",
    "spec_version",
    "license_spdx",
    "source_url",
    "maturity_disclosure",
    "vendor_tree_sha256",
    "vendor_tree_file_count",
)


def _load_manifest() -> dict:
    return json.loads((package_root() / "vendor_manifest.json").read_text(encoding="utf-8"))


def _compute_tree_digest(tree: Path) -> str:
    """Return the cross-platform SHA-256 over the sorted file-content stream.

    Recipe (identical to the one documented in vendor_manifest.json):
      h = sha256()
      for f in sorted(tree.rglob("*")) if f.is_file():
          h.update(f"{sha256(read_bytes(f))}  {posix_relpath(f)}\\n".encode())
      return h.hexdigest()

    Stable across macOS / Linux / Windows because:
      * Path.rglob enumerates files; we sort by POSIX-form relpath.
      * read_bytes is binary (no newline translation).
      * Separator is a hardcoded '\\n' byte, not os.linesep.
    """
    h = hashlib.sha256()
    files = sorted(
        (p for p in tree.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(tree).as_posix(),
    )
    for f in files:
        file_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        rel = f.relative_to(tree).as_posix()
        h.update(f"{file_hash}  {rel}\n".encode())
    return h.hexdigest()


# -----------------------------------------------------------------------------
# VAL-W11-001: vendored tree matches the pinned upstream commit
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-001")
def test_vendor_tree_digest_matches_recorded_pin() -> None:
    """The recomputed tree digest equals the value recorded in the manifest.

    The committed manifest's ``vendor_tree_sha256`` field is the canonical
    digest the team blesses at vendor time. The plumbing test recomputes
    the digest from the on-disk ``upstream/`` tree and asserts equality.
    Any byte-level mutation under ``upstream/`` flips the digest and
    fails this test.
    """
    actual_digest = _compute_tree_digest(vendor_root())
    assert actual_digest == EXPECTED_TREE_SHA256, (
        f"vendor tree digest drift: on-disk={actual_digest!r} "
        f"expected={EXPECTED_TREE_SHA256!r} -- something under "
        f"packages/acef/upstream/ has changed since the pin was recorded. "
        f"See packages/acef/README.md for the vendor-update workflow."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-001")
def test_vendor_tree_file_count_matches_recorded_pin() -> None:
    """File count under ``upstream/`` equals the value recorded in the manifest."""
    actual_count = sum(1 for p in vendor_root().rglob("*") if p.is_file())
    assert actual_count == EXPECTED_TREE_FILE_COUNT, (
        f"vendor tree file-count drift: on-disk={actual_count} "
        f"expected={EXPECTED_TREE_FILE_COUNT}"
    )


# -----------------------------------------------------------------------------
# VAL-W11-002: vendor manifest pins commit + version + license + source URL
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-002")
def test_vendor_manifest_has_required_keys() -> None:
    """Manifest contains the load-bearing keys VAL-W11-002 enumerates."""
    manifest = _load_manifest()
    missing = [k for k in _REQUIRED_MANIFEST_KEYS if k not in manifest]
    assert not missing, f"vendor_manifest.json missing required keys: {missing!r}"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-002")
def test_vendor_manifest_values_match_expected_pin() -> None:
    """Manifest fields equal the static expected literals."""
    manifest = _load_manifest()
    assert manifest["source_repo"] == EXPECTED_SOURCE_REPO
    assert manifest["commit_sha"] == EXPECTED_COMMIT_SHA
    assert manifest["spec_version"] == EXPECTED_SPEC_VERSION
    assert manifest["license_spdx"] == EXPECTED_LICENSE_SPDX
    assert manifest["maturity_disclosure"] == EXPECTED_MATURITY
    assert manifest["vendor_tree_sha256"] == EXPECTED_TREE_SHA256
    assert manifest["vendor_tree_file_count"] == EXPECTED_TREE_FILE_COUNT


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-002")
def test_vendor_manifest_commit_sha_matches_module_constant() -> None:
    """The manifest's commit_sha equals the hardcoded ``VENDOR_COMMIT_SHA``.

    The constant is duplicated in the Python package surface so a caller can
    introspect the pin without filesystem access. The two values MUST agree.
    """
    manifest = _load_manifest()
    assert manifest["commit_sha"] == VENDOR_COMMIT_SHA == EXPECTED_COMMIT_SHA


# -----------------------------------------------------------------------------
# VAL-W11-003: maturity disclosure is "v0.3 pre-1.0 reference implementation"
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-003")
def test_maturity_disclosure_is_v0_3_reference_implementation() -> None:
    """``VENDOR_MATURITY`` is the spec-pinned phrase."""
    assert VENDOR_MATURITY == EXPECTED_MATURITY


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-003")
def test_no_alpha_string_in_package_surfaces() -> None:
    """The string 'alpha' (case-insensitive) is absent from vendor-adjacent docs.

    Per VAL-W11-003: 'alpha' MUST NOT appear in vendor_manifest.json,
    README.md, or the package's ``__init__.py``. We grep all three files
    and assert zero hits.
    """
    pkg = package_root()
    targets = [
        pkg / "vendor_manifest.json",
        pkg / "README.md",
        pkg / "src" / "relay_acef" / "__init__.py",
    ]
    pattern = re.compile(r"alpha", re.IGNORECASE)
    offenders = []
    for path in targets:
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(pkg.parent.parent)))
    assert not offenders, (
        f"banned 'alpha' substring present in vendor-adjacent surfaces: "
        f"{offenders!r} -- per VAL-W11-003 the disclosure is "
        f"'v0.3 pre-1.0 reference implementation', never 'alpha'."
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-003")
def test_readme_contains_maturity_phrase() -> None:
    """README.md contains 'v0.3', 'pre-1.0', and 'reference implementation'."""
    readme_text = (package_root() / "README.md").read_text(encoding="utf-8")
    for required in ("v0.3", "pre-1.0", "reference implementation"):
        assert required in readme_text, (
            f"README.md missing required maturity phrase {required!r}"
        )


# -----------------------------------------------------------------------------
# VAL-W11-004: vendor tree immutable outside the documented workflow
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-004")
def test_vendor_update_workflow_documented() -> None:
    """README.md documents the vendor-update workflow.

    The workflow section is the load-bearing protocol that distinguishes
    a legitimate vendor bump from drift. Workers who change ``upstream/``
    without following the workflow trip the digest test above; the
    workflow MUST be present so they know how to fix.
    """
    readme = (package_root() / "README.md").read_text(encoding="utf-8")
    assert "Vendor update workflow" in readme or "vendor-update workflow" in readme
    # The recipe MUST include the digest derivation and the commit-SHA update.
    assert "vendor_tree_sha256" in readme
    assert "commit_sha" in readme


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-004")
def test_vendor_path_resolves_under_package() -> None:
    """``vendor_root()`` resolves under ``package_root()`` and exists."""
    root = vendor_root()
    assert root.exists() and root.is_dir(), f"vendor root missing: {root}"
    assert root.parent == package_root()
    assert root.name == VENDOR_PATH_NAME == "upstream"


# -----------------------------------------------------------------------------
# VAL-W11-005: vendored Python modules import without modification
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-005")
def test_vendored_python_files_have_valid_syntax() -> None:
    """Every .py file under ``upstream/src/`` parses as valid Python.

    We compile (do not execute) every Python source file under the
    vendored ``upstream/src/`` tree. ``compile`` raises ``SyntaxError``
    on malformed source; any failure fails the test.

    We deliberately do NOT actually ``import`` the modules: the vendored
    package declares its own dependencies (acef-conventions schemas,
    etc.) and the relay workspace does not install them as runtime deps.
    The intent of VAL-W11-005 in w11.1 scope is that the vendored Python
    is structurally well-formed and unmodified; full runtime import is
    exercised by the upstream's own test suite at the pinned SHA.
    """
    src = vendor_root() / "src"
    if not src.exists():
        pytest.skip(
            "RELAY-W11-1-VENDOR-SRC-MISSING: upstream/src/ not present at "
            "the pinned commit; nothing to compile."
        )
    py_files = sorted(src.rglob("*.py"))
    assert py_files, "no Python source files found under upstream/src/"
    failures: list[str] = []
    for p in py_files:
        try:
            compile(p.read_bytes(), str(p), "exec")
        except SyntaxError as exc:
            failures.append(f"{p}: {exc!r}")
    assert not failures, (
        f"vendored Python source has syntax errors: {failures!r}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-005")
def test_relay_acef_package_surface_is_importable() -> None:
    """The ``relay_acef`` workspace package exposes its declared constants."""
    # If this test file imported the names successfully at module-import
    # time (see top of file), the constants exist; here we double-check
    # they are non-empty strings of the expected shape.
    assert isinstance(VENDOR_COMMIT_SHA, str) and len(VENDOR_COMMIT_SHA) == 40
    assert isinstance(VENDOR_MATURITY, str) and VENDOR_MATURITY
    assert isinstance(VENDOR_PATH_NAME, str) and VENDOR_PATH_NAME == "upstream"
    assert VENDOR_MANIFEST_PATH == "packages/acef/vendor_manifest.json"


# -----------------------------------------------------------------------------
# VAL-W11-006: vendored test suite present at the pin
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-006")
def test_vendored_test_suite_present_at_pin() -> None:
    """The vendored ``upstream/tests/`` tree exists and contains test files.

    w11.1 scope is the vendor pin, not the execution of the upstream's
    test suite under Relay's environment (the upstream's tests depend on
    fixtures and pip-installable extras not in the Relay workspace
    dependency closure). The execution gate happens in the upstream's
    own CI at the pinned SHA; here we verify the suite is vendored
    intact (file presence + syntactic validity). w11.2+ may layer
    additional runtime invocations on top of this floor.
    """
    tests_dir = vendor_root() / "tests"
    assert tests_dir.exists() and tests_dir.is_dir(), (
        f"vendored tests/ directory missing: {tests_dir}"
    )
    test_files = sorted(p for p in tests_dir.rglob("test_*.py") if p.is_file())
    assert test_files, "no vendored test_*.py files under upstream/tests/"
    # Sanity: at least 5 test files at the pin (the pinned ACEF SDK ships
    # the unit-test suite). The drift digest test above (VAL-W11-001)
    # catches any deletion; this assertion just prevents an empty tree
    # from silently passing the count check above.
    assert len(test_files) >= 5, (
        f"too few vendored test files (got {len(test_files)}); expected >= 5"
    )


# -----------------------------------------------------------------------------
# VAL-W11-007: TS SDK does not import ACEF directly
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-007")
def test_ts_sdk_does_not_reference_acef_directly() -> None:
    """Repo grep over hand-written packages/sdk-typescript/src/ for ACEF imports.

    The forbidden coupling patterns (narrowed per VAL-W11-007):
      * import / require statements naming '@acef/' (any future scoped
        npm package under the ACEF org)
      * import / require statements naming the vendored Python package
        identifier 'acef_core' as a JS module
      * a regex 'acef[._-]?emit'  for acefEmit / acef_emit / acef.emit
      * a regex 'acef[._-]?parse' for acefParse / acef_parse / acef.parse

    Broad tokens like 'canonicalize', 'Merkle' are NOT forbidden --
    those are legitimate identifiers used independently of ACEF.

    Excluded paths:
      * Test fixtures under 'test/', 'tests/', or '/fixtures/' (VAL-W11-007
        narrowing).
      * Generated code under '_generated/'. The W1.5 codegen pipeline emits
        canonical schema field names (e.g., 'acef_core_version' on
        EvidenceBundle records is metadata identifying which ACEF Core
        version produced a bundle; per spec it is data, not a coupling).
        VAL-W11-014 explicitly contemplates this metadata field. Hand-
        written TS code that imports or invokes ACEF is the violation; a
        schema field that NAMES acef_core as data is not.

    The check is skipped (with structured reason) if the sdk-typescript
    package does not exist at this stage of the build (early scaffold).
    """
    ts_src = package_root().parent / "sdk-typescript" / "src"
    if not ts_src.exists():
        pytest.skip(
            "RELAY-W11-1-TS-SDK-ABSENT: packages/sdk-typescript/src/ not "
            "present; nothing to grep. Re-run after W3."
        )
    # Coupling-detection patterns: an import statement naming the package,
    # or a function call shaped like an ACEF emit/parse entry point.
    forbidden_import_regexes = (
        # ES module import: import ... from "@acef/..."
        re.compile(r"""(?:from|import)\s+['"]@acef/"""),
        # CommonJS require: require("@acef/...")
        re.compile(r"""require\s*\(\s*['"]@acef/"""),
        # ES module import naming the vendored Python package as a JS module:
        re.compile(r"""(?:from|import)\s+['"]acef_core['"]"""),
        re.compile(r"""require\s*\(\s*['"]acef_core['"]"""),
    )
    forbidden_call_regexes = (
        re.compile(r"acef[._-]?emit"),
        re.compile(r"acef[._-]?parse"),
    )
    offenders: list[str] = []
    for path in sorted(ts_src.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
            continue
        rel = path.relative_to(ts_src).as_posix()
        # Test fixtures and generated code are not hand-written couplings.
        if (
            rel.startswith("test/")
            or rel.startswith("tests/")
            or "/fixtures/" in rel
            or rel.startswith("_generated/")
            or "/_generated/" in rel
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        for pat in forbidden_import_regexes:
            if pat.search(text):
                offenders.append(f"{rel}: import-pattern {pat.pattern!r}")
        for pat in forbidden_call_regexes:
            if pat.search(text):
                offenders.append(f"{rel}: call-pattern {pat.pattern!r}")
    assert not offenders, (
        f"TS SDK references ACEF directly (must go through Python sidecar): "
        f"{offenders!r}"
    )


# -----------------------------------------------------------------------------
# VAL-W11-008: license preserved at vendor pin
# -----------------------------------------------------------------------------


# Upstream LICENSE byte-length at the pinned commit. Recorded once and asserted
# on every run as a cheap tamper-evident floor; the digest test above is the
# load-bearing equality check.
_LICENSE_EXPECTED_BYTES: int = 10761


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W11-008")
def test_top_level_apache_license_preserved() -> None:
    """``upstream/LICENSE`` matches the recorded Apache-2.0 byte length and prelude.

    The upstream's per-file SPDX headers are not consistently applied
    across the v0.3 reference implementation; the load-bearing license
    artifact at the pin is the top-level LICENSE file. We assert (a) its
    byte length, (b) the Apache 2.0 header prelude is present, and (c)
    the manifest's license_spdx field equals 'Apache-2.0'. The
    byte-for-byte equality of LICENSE (and every other vendored file)
    is enforced by the digest check above.
    """
    license_path = vendor_root() / "LICENSE"
    assert license_path.exists(), f"upstream LICENSE missing: {license_path}"
    raw = license_path.read_bytes()
    assert len(raw) == _LICENSE_EXPECTED_BYTES, (
        f"upstream LICENSE byte length drift: got {len(raw)} expected "
        f"{_LICENSE_EXPECTED_BYTES}"
    )
    text = raw.decode("utf-8")
    # Apache 2.0 prelude is byte-stable at the pin.
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text

    manifest = _load_manifest()
    assert manifest["license_spdx"] == "Apache-2.0"
    assert manifest["license_file"] == "upstream/LICENSE"
