"""Relay ACEF vendor-pin workspace package.

This package vendors the ACEF reference SDK at a pinned upstream commit
under ``packages/acef/upstream/``. The vendored tree is byte-equal to
https://github.com/chandlercvaughn/ACEF at commit
``57e1d14e063d3a2a88bfe5361fd81ca02bc6d540`` (v0.3 pre-1.0 reference
implementation, per upstream's own stability declaration at the pin).

w11.1 scope is the vendor pin itself: vendor manifest, drift guard, and
license preservation. The ACEF emission service and the ten ``x-relay/*``
extension namespaces land in w11.2+ as separate features.

Public attributes:

  * :data:`VENDOR_MANIFEST_PATH` -- repo-relative POSIX path to
    ``vendor_manifest.json``. Useful for test harnesses that need to
    locate the manifest without depending on a working directory.
  * :data:`VENDOR_COMMIT_SHA` -- pinned upstream commit SHA, hardcoded
    here so a runtime caller can introspect the pin without reading the
    JSON file. The drift-guard test asserts equality with the manifest
    field.
  * :data:`VENDOR_MATURITY` -- maturity disclosure string, MUST equal
    "v0.3 pre-1.0 reference implementation" (VAL-W11-003).
  * :data:`VENDOR_PATH_NAME` -- name of the vendored subdirectory under
    this package, "upstream".

The vendored ``upstream/`` tree is NOT imported by this module. The TS
SDK NEVER imports ACEF symbols directly; all TS-side consumption goes
through the Python sidecar's HTTP surface (W11.1 boundary rule).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

# Pinned upstream commit; hardcoded here as well as in vendor_manifest.json
# so a runtime caller can introspect the pin without filesystem access.
# The drift-guard test asserts the two values agree.
VENDOR_COMMIT_SHA: Final[str] = "57e1d14e063d3a2a88bfe5361fd81ca02bc6d540"

# Maturity disclosure. The vendored upstream is a v0.3 pre-1.0 reference
# implementation; the disclosure phrase is locked by VAL-W11-003 and the
# drift guard rejects any pre-release-stage label here.
VENDOR_MATURITY: Final[str] = "v0.3 pre-1.0 reference implementation"

# Name of the vendored subdirectory under this package.
VENDOR_PATH_NAME: Final[str] = "upstream"

# Repo-relative POSIX path to the vendor manifest. Computed once at import
# time; the drift-guard test resolves it under the package root.
VENDOR_MANIFEST_PATH: Final[str] = "packages/acef/vendor_manifest.json"


def package_root() -> Path:
    """Return the on-disk root of the ``packages/acef/`` package directory."""
    # src/relay_acef/__init__.py -> src/relay_acef -> src -> packages/acef
    return Path(__file__).resolve().parent.parent.parent


def vendor_root() -> Path:
    """Return the on-disk root of the vendored upstream tree."""
    return package_root() / VENDOR_PATH_NAME


__all__ = [
    "VENDOR_COMMIT_SHA",
    "VENDOR_MANIFEST_PATH",
    "VENDOR_MATURITY",
    "VENDOR_PATH_NAME",
    "package_root",
    "vendor_root",
]
