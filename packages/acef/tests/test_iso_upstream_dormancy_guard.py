"""ACEF upstream dormancy guard (VAL-ISO-004/012/013/031/032).

This module is a single fail-closed guard that makes a load-bearing fact
PROVABLE and ENFORCED: Relay's shipped ACEF path NEVER imports or invokes
the dormant vendored upstream ``acef`` package under
``packages/acef/upstream/src/acef/``. Five adversarially-verified findings
(VAL-ISO-004, -012, -013, -031, -032) describe real bugs in that vendored
tree. None of them can affect Relay because Relay's shipped path never
reaches the buggy code. This guard turns that "never reaches" from an
assumption into an enforced invariant: if a future change made any
Relay-owned module import one of the dormant upstream modules, the guard
fails closed and the regression is caught before it ships.

Why a guard instead of fixing the bugs
=======================================
``packages/acef/upstream/`` is a byte-immutable vendored tree (the W11.1
vendor-drift guard, :mod:`test_w11_1_vendor_drift_guard`, fails on any
byte-level mutation; see ``RELAY-LOCAL-CHANGES.md``). The vendored ``acef``
package is dormant in Relay: it is not installed in the workspace venv
(``import acef`` raises ``ModuleNotFoundError``), it is not in the shipped
wheel (``pyproject.toml`` ``only-include = ["src/relay_acef",
"relay_extensions"]``), and no Relay-owned module imports it. Relay's
shipped ACEF path performs ONLY:

  * JWS signature verification -- ``relay_acef.bundle_verifier``
    (``verify_acef_bundle``).
  * JCS canonicalization / parse -- ``relay_acef.roundtrip``
    (``emit_bundle`` / ``parse_bundle``).
  * x-relay extension STRUCTURAL validation via typed field / property-set
    checks -- ``relay_extensions.emission`` (``EmissionWriter``). It does
    NOT substring-match error messages, does NOT do per-record payload
    JSON-Schema validation, tar extraction, obligation/freshness rule
    evaluation, or bundle merge.

Because Relay's shipped path never invokes per-record payload schema
validation, tar extraction, freshness-rule evaluation, or bundle merge,
the five findings' code is unreachable from Relay. Implementing those four
missing subsystems in Relay-owned code would be banned DEAD CODE (no
shipped caller). The chosen remediation, per the user decision "GUARD THE
DORMANCY", is this enforcement guard.

Per-finding dormancy mapping (self-explaining)
==============================================
Each finding names a dormant upstream module that Relay's shipped path
never imports. The Relay-owned module that subsumes/omits the
corresponding responsibility is named alongside it.

  VAL-ISO-004  empty-payload skip in per-record payload schema validation
               DORMANT upstream module: acef/validation/schema_validator.py
               Relay does NOT do per-record payload JSON-Schema validation
               in its shipped path; structural validation lives in
               relay_extensions/emission.py (typed field / property-set
               checks). The buggy ``if record_type and payload`` guard is
               never reached.

  VAL-ISO-012  tar path-traversal guard misses backslash/drive-letter
               members on the <3.12 fallback path
               DORMANT upstream module: acef/loader.py
               Relay's shipped path performs NO tar extraction; it parses
               JSON bundles via relay_acef/roundtrip.py (parse_bundle) and
               verifies JWS via relay_acef/bundle_verifier.py. The buggy
               ``_validate_tar_safety`` is never reached.

  VAL-ISO-013  evidence_freshness silently passes (vacuous True) on a
               malformed reference timestamp
               DORMANT upstream module: acef/validation/operators.py
               Relay's shipped path performs NO obligation / freshness rule
               evaluation. The buggy ``op_evidence_freshness`` is never
               reached.

  VAL-ISO-031  merge keep_latest aborts the entire merge on one malformed
               timestamp
               DORMANT upstream module: acef/merge.py
               Relay's shipped path performs NO bundle merge. The buggy
               ``_timestamp_is_newer_or_equal`` / ``merge_packages`` is
               never reached.

  VAL-ISO-032  unknown-record-type detection relies on a fragile substring
               match of the error message
               DORMANT upstream module: acef/validation/schema_validator.py
               (same dormant module as VAL-ISO-004). Relay's structural
               validation in relay_extensions/emission.py branches on typed
               errors, never on ``"not found" in str(error.message)``. The
               buggy substring branch is never reached.

What this guard asserts (all fail-closed)
=========================================
1. Static import scan: NO Relay-owned source module under the shipped ACEF
   surface or its consumers contains an ``import acef`` / ``from acef ...``
   statement (or any reference to ``packages.acef.upstream``). The scan
   parses each file's AST so it cannot be fooled by an import hidden in a
   string or a comment, and it is anchored on the SAME ``vendor_root()`` /
   ``package_root()`` helpers the W11.1 drift guard uses.

2. At-import dormancy: importing the three shipped ACEF entry points
   (``relay_acef.bundle_verifier``, ``relay_acef.roundtrip``,
   ``relay_extensions.emission``) does NOT pull any dormant upstream module
   (``acef``, ``acef.validation.schema_validator``, ``acef.loader``,
   ``acef.validation.operators``, ``acef.merge``) into ``sys.modules``.

3. Subprocess fail-closed: the shipped entry points import successfully in
   a fresh interpreter in which the name ``acef`` is made UNIMPORTABLE (a
   meta-path finder raises on any ``acef`` import). If the shipped import
   graph touched upstream ``acef`` the subprocess would crash; it must not.

RED -> GREEN proof
==================
:func:`test_static_scan_catches_an_injected_dormant_import` proves the
static guard is not vacuous: it writes a scratch Relay-owned module that
DOES ``import acef.merge`` and asserts the scanner flags it. The guard is
therefore enforcement, not decoration.

Plumbing tier (tier 1, <= 60s, offline). stdlib + ast only; no network.
ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import ast
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from relay_acef import package_root, vendor_root

# -----------------------------------------------------------------------------
# Dormant upstream modules named by the five findings (load-bearing literals).
# -----------------------------------------------------------------------------
# Keyed by the canonical dotted module name of the dormant upstream module,
# valued by the findings it backs and the upstream source file (relative to
# upstream/src/) so a future reader can trace each finding to its dormant code.
DORMANT_UPSTREAM_MODULES: dict[str, dict[str, object]] = {
    "acef.validation.schema_validator": {
        "findings": ("VAL-ISO-004", "VAL-ISO-032"),
        "source": "acef/validation/schema_validator.py",
    },
    "acef.loader": {
        "findings": ("VAL-ISO-012",),
        "source": "acef/loader.py",
    },
    "acef.validation.operators": {
        "findings": ("VAL-ISO-013",),
        "source": "acef/validation/operators.py",
    },
    "acef.merge": {
        "findings": ("VAL-ISO-031",),
        "source": "acef/merge.py",
    },
}

# The five finding IDs this single guard satisfies.
COVERED_FINDINGS: tuple[str, ...] = (
    "VAL-ISO-004",
    "VAL-ISO-012",
    "VAL-ISO-013",
    "VAL-ISO-031",
    "VAL-ISO-032",
)

# The three shipped ACEF entry-point modules. Importing these must NOT drag
# any dormant upstream module into the process.
SHIPPED_ENTRY_POINT_MODULES: tuple[str, ...] = (
    "relay_acef.bundle_verifier",
    "relay_acef.roundtrip",
    "relay_extensions.emission",
)


def _relay_owned_scan_roots() -> list[Path]:
    """Return the Relay-OWNED source roots to statically scan for acef imports.

    Anchored on the W11.1 ``package_root()`` so this guard moves with the
    package, exactly like the vendor-drift guard. We scan:

      * ``packages/acef/src/relay_acef/``  -- shipped vendor-pin surface.
      * ``packages/acef/relay_extensions/`` -- shipped x-relay extensions.
      * ``packages/cli/src/relay_cli/``     -- the ACEF consumer (rly evidence).
      * ``apps/local-sidecar/relay_sidecar/`` -- sidecar (any ACEF usage).

    We deliberately do NOT scan ``packages/acef/upstream/`` (the dormant
    vendored tree is allowed to import itself; it just must never be reached
    from Relay) nor any ``tests/`` tree (tests may legitimately reference the
    upstream package by name to assert its dormancy -- as this very module
    does).
    """
    pkg = package_root()  # packages/acef
    packages_dir = pkg.parent  # packages/
    repo_root = packages_dir.parent  # relay/
    roots = [
        pkg / "src" / "relay_acef",
        pkg / "relay_extensions",
        packages_dir / "cli" / "src" / "relay_cli",
        repo_root / "apps" / "local-sidecar" / "relay_sidecar",
    ]
    return [r for r in roots if r.exists()]


def _is_test_or_cache_path(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if "__pycache__" in parts or ".pytest_cache" in parts:
        return True
    if "tests" in parts or "test" in parts:
        return True
    return rel_posix.endswith((".pyc", ".pyo"))


def _imports_upstream_acef(tree: ast.AST) -> list[str]:
    """Return AST-detected ``acef`` (upstream) imports in a parsed module.

    Detection rules (the upstream package's distribution name is ``acef``):

      * ``import acef`` / ``import acef.merge [as ...]`` -> the imported
        dotted name equals ``acef`` or starts with ``acef.``.
      * ``from acef import ...`` / ``from acef.loader import ...`` -> the
        module equals ``acef`` or starts with ``acef.``.
      * ``from packages.acef.upstream... import ...`` and
        ``import packages.acef.upstream...`` -> direct reach into the
        vendored tree by package path.

    ``relay_acef`` / ``relay_extensions`` / ``acef_conventions`` and any
    other identifier that merely *contains* the substring ``acef`` are NOT
    matched: we compare on dotted-name boundaries, never substrings.
    """
    offenders: list[str] = []

    def _is_upstream_name(dotted: str | None) -> bool:
        if not dotted:
            return False
        if dotted == "acef" or dotted.startswith("acef."):
            return True
        # Direct reach into the vendored tree by repo package path.
        return dotted == "packages.acef.upstream" or dotted.startswith(
            "packages.acef.upstream."
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_upstream_name(alias.name):
                    offenders.append(f"import {alias.name}")
        # ``from . import x`` has module=None (relative); never upstream.
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and _is_upstream_name(node.module)
        ):
            names = ", ".join(a.name for a in node.names)
            offenders.append(f"from {node.module} import {names}")
    return offenders


def _scan_root_for_upstream_imports(root: Path) -> list[str]:
    """AST-scan every non-test .py file under ``root`` for upstream acef imports.

    Offender labels are rendered relative to ``root`` (always a valid parent
    of every scanned path) so the helper works for both the real Relay-owned
    roots and the scratch root used by the RED->GREEN proof test.
    """
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        if _is_test_or_cache_path(rel):
            continue
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except SyntaxError as exc:  # pragma: no cover - surfaced as failure
            offenders.append(f"{rel}: unparseable ({exc!r})")
            continue
        for hit in _imports_upstream_acef(tree):
            offenders.append(f"{rel}: {hit}")
    return offenders


# -----------------------------------------------------------------------------
# Assertion 1 -- static import scan (no Relay-owned module imports upstream acef)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-004")
@pytest.mark.fulfills("VAL-ISO-012")
@pytest.mark.fulfills("VAL-ISO-013")
@pytest.mark.fulfills("VAL-ISO-031")
@pytest.mark.fulfills("VAL-ISO-032")
def test_no_relay_owned_module_imports_upstream_acef() -> None:
    """Zero Relay-owned source modules import the dormant upstream ``acef``.

    Statically (AST) scans the shipped ACEF surface and its consumers. If any
    module imported ``acef`` (or reached into ``packages.acef.upstream``), the
    five findings' buggy code could become reachable from Relay's shipped
    path; this guard fails closed and names the offender.
    """
    roots = _relay_owned_scan_roots()
    assert roots, (
        "no Relay-owned scan roots resolved under package_root(); the guard "
        "would be vacuous. Expected at least relay_acef + relay_extensions."
    )
    # The two shipped ACEF roots must always be present (they are the path
    # whose dormancy we are guarding); a missing root would make the scan
    # silently pass.
    shipped = {(package_root() / "src" / "relay_acef"), (package_root() / "relay_extensions")}
    assert shipped.issubset(set(roots)), (
        f"shipped ACEF roots missing from scan set: {shipped - set(roots)!r}"
    )

    offenders: list[str] = []
    for root in roots:
        offenders.extend(_scan_root_for_upstream_imports(root))
    assert not offenders, (
        "Relay-owned code imports the DORMANT vendored upstream 'acef' "
        "package. This would expose VAL-ISO-004/012/013/031/032 "
        "(empty-payload skip / tar traversal / vacuous freshness / merge "
        "abort / substring unknown-type) to Relay's shipped path. Offenders:\n"
        + "\n".join(f"  - {o}" for o in offenders)
    )


# -----------------------------------------------------------------------------
# Assertion 1 (RED->GREEN proof) -- the scanner catches an injected import
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-031")
def test_static_scan_catches_an_injected_dormant_import(tmp_path: Path) -> None:
    """The AST scanner flags a scratch module that imports a dormant module.

    Proves the static guard is enforcement, not decoration: a Relay-owned
    file that did ``import acef.merge`` (the VAL-ISO-031 dormant module) MUST
    be detected. We scan a scratch root containing such a file and assert a
    non-empty offender list, then assert a clean control file is NOT flagged.
    """
    scratch_root = tmp_path / "relay_scratch"
    scratch_root.mkdir()

    # A module that reaches into the dormant upstream tree -- must be flagged.
    bad = scratch_root / "consumes_dormant.py"
    bad.write_text(
        textwrap.dedent(
            """\
            from __future__ import annotations
            import acef.merge  # would expose VAL-ISO-031
            from acef.validation.schema_validator import validate_record_schemas

            def go() -> None:
                acef.merge.merge_packages([])
            """
        ),
        encoding="utf-8",
    )
    # A clean module referencing only the shipped surface -- must NOT be flagged.
    good = scratch_root / "shipped_only.py"
    good.write_text(
        textwrap.dedent(
            """\
            from __future__ import annotations
            from relay_acef.bundle_verifier import verify_acef_bundle
            from relay_extensions.emission import EmissionWriter

            # 'acef_core_version' is a data field name, not an import.
            ACEF_CORE_FIELD = "acef_core_version"
            """
        ),
        encoding="utf-8",
    )

    offenders = _scan_root_for_upstream_imports(scratch_root)
    bad_hits = [o for o in offenders if "consumes_dormant.py" in o]
    good_hits = [o for o in offenders if "shipped_only.py" in o]
    assert bad_hits, (
        "static scanner FAILED to detect an injected 'import acef.merge' in a "
        "Relay-owned module -- the dormancy guard would be vacuous."
    )
    # Both the bare import and the from-import should be caught.
    assert any("import acef.merge" in o for o in bad_hits)
    assert any("from acef.validation.schema_validator" in o for o in bad_hits)
    assert not good_hits, (
        "static scanner false-positived on a clean shipped-only module: "
        f"{good_hits!r}"
    )


# -----------------------------------------------------------------------------
# Assertion 2 -- at-import dormancy (sys.modules carries no upstream acef)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-004")
@pytest.mark.fulfills("VAL-ISO-012")
@pytest.mark.fulfills("VAL-ISO-013")
@pytest.mark.fulfills("VAL-ISO-031")
@pytest.mark.fulfills("VAL-ISO-032")
def test_importing_shipped_entry_points_pulls_no_upstream_acef() -> None:
    """Importing the shipped ACEF entry points loads no dormant upstream module.

    Runs in a fresh subprocess (so the assertion is not polluted by other
    tests that may have imported things first), imports the three shipped
    entry points, then asserts that neither the bare ``acef`` package nor any
    of the four dormant modules appears in ``sys.modules``.
    """
    dormant = sorted(DORMANT_UPSTREAM_MODULES.keys())
    program = textwrap.dedent(
        f"""\
        import sys
        # Import the shipped ACEF entry points exactly as Relay does.
        import relay_acef.bundle_verifier  # noqa: F401
        import relay_acef.roundtrip  # noqa: F401
        import relay_extensions.emission  # noqa: F401

        dormant = {dormant!r}
        leaked = [m for m in sys.modules if m == "acef" or m.startswith("acef.")]
        # Fail closed if any dormant module (or the bare package) is present.
        if leaked:
            print("LEAKED:" + ",".join(sorted(leaked)))
            sys.exit(3)
        # Sanity: the named dormant modules must each be absent.
        present = [d for d in dormant if d in sys.modules]
        if present:
            print("DORMANT_PRESENT:" + ",".join(present))
            sys.exit(4)
        print("OK")
        sys.exit(0)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        "importing the shipped ACEF entry points leaked a dormant upstream "
        f"module into sys.modules (exit={proc.returncode}).\n"
        f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
    assert proc.stdout.strip() == "OK", f"unexpected stdout: {proc.stdout!r}"


# -----------------------------------------------------------------------------
# Assertion 3 -- subprocess fail-closed: shipped path imports with acef BANNED
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-004")
@pytest.mark.fulfills("VAL-ISO-012")
@pytest.mark.fulfills("VAL-ISO-013")
@pytest.mark.fulfills("VAL-ISO-031")
@pytest.mark.fulfills("VAL-ISO-032")
def test_shipped_entry_points_import_with_upstream_acef_unimportable() -> None:
    """Shipped entry points import in an interpreter where ``acef`` is banned.

    Installs a meta-path finder that RAISES on any attempt to import a name
    that is ``acef`` or starts with ``acef.``. With upstream ``acef`` made
    unimportable, the three shipped entry points MUST still import cleanly --
    proving their import graph does not depend on the dormant upstream tree.
    A self-check confirms the ban is real (``import acef`` raises). If a
    shipped module did import upstream ``acef`` at module scope, the import of
    that entry point would raise and the subprocess would exit non-zero.
    """
    program = textwrap.dedent(
        """\
        import importlib.abc
        import importlib.machinery
        import sys


        class _BanAcef(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path, target=None):
                if fullname == "acef" or fullname.startswith("acef."):
                    raise ImportError(
                        "upstream 'acef' is banned in this interpreter: " + fullname
                    )
                return None


        sys.meta_path.insert(0, _BanAcef())

        # Self-check: the ban must actually take effect.
        try:
            import acef  # noqa: F401
        except ImportError:
            pass
        else:
            print("BAN_INEFFECTIVE")
            sys.exit(5)

        # The shipped entry points must import with upstream acef banned.
        import relay_acef.bundle_verifier  # noqa: F401
        import relay_acef.roundtrip  # noqa: F401
        import relay_extensions.emission  # noqa: F401

        # And the public entry-point callables must be present.
        from relay_acef.bundle_verifier import verify_acef_bundle  # noqa: F401
        from relay_acef.roundtrip import emit_bundle, parse_bundle  # noqa: F401
        from relay_extensions.emission import EmissionWriter  # noqa: F401

        print("OK")
        sys.exit(0)
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        "shipped ACEF entry points failed to import with upstream 'acef' made "
        "unimportable -- the shipped path DEPENDS on the dormant upstream tree "
        f"(exit={proc.returncode}).\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )
    assert proc.stdout.strip() == "OK", f"unexpected stdout: {proc.stdout!r}"


# -----------------------------------------------------------------------------
# Self-documentation guard -- the per-finding mapping is complete and accurate
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-004")
@pytest.mark.fulfills("VAL-ISO-012")
@pytest.mark.fulfills("VAL-ISO-013")
@pytest.mark.fulfills("VAL-ISO-031")
@pytest.mark.fulfills("VAL-ISO-032")
def test_per_finding_mapping_covers_all_five_and_sources_exist() -> None:
    """All five findings map to a dormant module whose upstream source exists.

    Keeps the guard self-explaining and honest: every covered finding appears
    in :data:`DORMANT_UPSTREAM_MODULES`, and every named dormant upstream
    source file actually exists under ``upstream/src/`` (so the mapping is not
    referencing a phantom module). This anchors the documentation in fact and
    fails if a future vendor bump renames or removes a dormant module without
    the mapping being updated.
    """
    mapped_findings: set[str] = set()
    src_root = vendor_root() / "src"
    missing_sources: list[str] = []
    for module, meta in DORMANT_UPSTREAM_MODULES.items():
        findings = meta["findings"]
        assert isinstance(findings, tuple) and findings, (
            f"dormant module {module!r} has no findings mapped"
        )
        mapped_findings.update(findings)
        source = src_root / str(meta["source"])
        if not source.exists():
            missing_sources.append(f"{module} -> {meta['source']}")
    assert not missing_sources, (
        "dormant upstream source file(s) named in the mapping do not exist "
        f"under upstream/src/: {missing_sources!r}"
    )
    assert mapped_findings == set(COVERED_FINDINGS), (
        "per-finding mapping does not cover exactly the five findings: "
        f"mapped={sorted(mapped_findings)!r} expected={sorted(COVERED_FINDINGS)!r}"
    )
