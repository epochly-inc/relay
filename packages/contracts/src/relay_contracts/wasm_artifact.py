"""Packaged wasm artifact resolution + pinned-sha guard (WS-G, M3 P3CORPUS).

The single CEL engine is a reproducible ``relay_cel_wasm.wasm`` produced by the
``packages/cel-wasm/conformance/build.sh`` deterministic recipe. WS-G ships that
artifact as PACKAGE DATA of ``relay_contracts`` so a fresh-installed wheel can
load the engine via :func:`importlib.resources.files` WITHOUT the (gitignored)
``crate/target/`` tree present.

This module is the single source of truth for:

  - :data:`WASM_PACKAGE_DATA_RELPATH` -- the data path of the vendored wasm
    relative to the imported ``relay_contracts`` package root, resolvable via
    ``importlib.resources.files('relay_contracts').joinpath(...)``;
  - :data:`WASM_PINNED_SHA256` -- the full sha256 of the build.sh
    deterministic-recipe artifact (the ``[repro] PASS`` sha). The shipped
    package-data wasm MUST hash to this value; a guard test
    (``test_wasm_pinned_sha_matches_packaged_artifact_on_disk``) fails on a
    tampered / stale vendored artifact;
  - :func:`resolve_packaged_wasm_path` -- resolve the package-data wasm to a
    concrete on-disk path (the wheel layout keeps it on the filesystem;
    ``importlib.resources.as_file`` would be required only for a zipped wheel,
    which Relay does not ship for this package).

This is NOT signing. M3 PINS the sha (a checked-in constant + an on-disk-hash
guard); the wasm is Apache-2.0-portable CODE, not trust-anchor key material.
Signing the artifact (KMS / transparency log) lives in ``relay-platform`` and is
explicitly out of scope here (CLAUDE.md banned pattern #14).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""
from __future__ import annotations

import hashlib
import importlib.resources
from pathlib import Path

# The vendored wasm's data path RELATIVE TO the imported ``relay_contracts``
# package root. Resolved via ``importlib.resources.files('relay_contracts')``,
# so it works from an installed wheel (no crate/target/ dependency). POSIX-style
# separator; ``importlib.resources`` joinpath normalizes per-platform.
WASM_PACKAGE_DATA_RELPATH: str = "_wasm/relay_cel_wasm.wasm"

# The vendored wasm LOADER module's data path RELATIVE TO the imported
# ``relay_contracts`` package root. The loader
# (``packages/cel-wasm/python/relay_cel_wasm.py``) is a loose module with no
# pyproject, so it is NOT importable as a top-level package in a wheel-only
# install. WS-G ships a git-tracked VENDORED COPY of the canonical loader here
# (``src/relay_contracts/_wasm/relay_cel_wasm.py``) and force-includes it into
# the wheel (``[tool.hatch.build.targets.wheel.force-include]``, the SAME
# mechanism + the SAME vendored-copy pattern the ``.wasm`` uses -- a git-tracked
# copy in ``src/_wasm/``), so a fresh-installed wheel can LOAD the wasm, not only
# locate it. Because the copy is a git-tracked DUPLICATE of the canonical
# source, a BYTE-IDENTITY drift guard
# (``test_wasm_loader_package_data.test_wasm_loader_vendored_copy_is_byte_identical_to_canonical``)
# fails CI if the two diverge -- no silent drift.
WASM_LOADER_PACKAGE_DATA_RELPATH: str = "_wasm/relay_cel_wasm.py"

# The full sha256 of the reproducible build.sh deterministic-recipe artifact
# (the ``[repro] PASS: byte-deterministic (<sha>)`` value). The shipped
# package-data wasm MUST hash to this. PINNED, not signed (see module docstring).
WASM_PINNED_SHA256: str = (
    "431d966b2818ef4539a4f6b78e2903a4d6911c6b6352e256e35531a44f992511"
)


def resolve_packaged_wasm_path() -> Path | None:
    """Resolve the package-data wasm to a concrete on-disk path.

    Uses ``importlib.resources.files('relay_contracts')`` so resolution is
    anchored to the IMPORTED package root, not a source-tree-relative path --
    a fresh-installed wheel locates the wasm the same way the dev tree does.

    Returns the :class:`pathlib.Path` to the wasm when it exists as a regular
    file, else ``None`` (so the caller can map a missing artifact to a
    structured engine error rather than letting a bare ``FileNotFoundError``
    escape). Never raises for an absent artifact.
    """
    try:
        resource = importlib.resources.files("relay_contracts").joinpath(
            WASM_PACKAGE_DATA_RELPATH
        )
    except (ModuleNotFoundError, FileNotFoundError):
        return None
    # ``Traversable.is_file`` works for both filesystem and zip-backed
    # resources; the Relay wheel is a regular (non-zipped) install, so the
    # resource is a real path. Guard against a zipped install by falling back
    # to ``None`` when the resource is not materializable as a filesystem path.
    try:
        if not resource.is_file():
            return None
        # ``importlib.resources.files`` returns a concrete path for a normal
        # (unzipped) wheel; ``Path(str(...))`` materializes it. For the rare
        # zipped-wheel case ``str(resource)`` is not a real path and the file
        # check below catches it.
        path = Path(str(resource))
    except (FileNotFoundError, OSError):
        return None
    if not path.is_file():
        return None
    return path


def resolve_packaged_wasm_loader_path() -> Path | None:
    """Resolve the package-data wasm LOADER module to a concrete on-disk path.

    Mirrors :func:`resolve_packaged_wasm_path` for the loader source: resolution
    is anchored to the IMPORTED ``relay_contracts`` package root via
    ``importlib.resources.files('relay_contracts')``, so a fresh-installed wheel
    locates the loader the same way it locates the ``.wasm`` -- WITHOUT the
    in-repo ``packages/cel-wasm/python`` tree present.

    Returns the :class:`pathlib.Path` to the loader ``.py`` when it exists as a
    regular file, else ``None`` (so the caller maps a missing loader to a
    structured engine error rather than letting a bare ``FileNotFoundError`` /
    ``ImportError`` escape). Never raises for an absent loader.
    """
    try:
        resource = importlib.resources.files("relay_contracts").joinpath(
            WASM_LOADER_PACKAGE_DATA_RELPATH
        )
    except (ModuleNotFoundError, FileNotFoundError):
        return None
    try:
        if not resource.is_file():
            return None
        path = Path(str(resource))
    except (FileNotFoundError, OSError):
        return None
    if not path.is_file():
        return None
    return path


def sha256_of_path(path: Path) -> str:
    """Return the hex sha256 of the bytes at ``path``."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


__all__ = [
    "WASM_LOADER_PACKAGE_DATA_RELPATH",
    "WASM_PACKAGE_DATA_RELPATH",
    "WASM_PINNED_SHA256",
    "resolve_packaged_wasm_loader_path",
    "resolve_packaged_wasm_path",
    "sha256_of_path",
]
