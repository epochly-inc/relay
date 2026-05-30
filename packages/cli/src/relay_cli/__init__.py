"""Relay CLI package root.

The `rly` command-line interface (W5 milestone). Importing this package
is side-effect free: no sidecar spawn, no network call, no signal handler
install. All side effects are deferred to :func:`relay_cli.main.run`,
which is the entrypoint registered in pyproject.toml under
``[project.scripts] rly = "relay_cli.main:run"``.

Public surface:
  - :func:`run` -- CLI entrypoint (re-exported from :mod:`relay_cli.main`).
  - :data:`__version__` -- package version string used by ``rly --version``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations


# VAL-W5-001: ``rly --version`` reports a stable semver string. The version
# is mirrored from the package distribution metadata at runtime so a single
# source of truth (pyproject.toml [project] version) governs the wire form.
def _resolve_version() -> str:
    """Read the package version from installed distribution metadata.

    When the package is not installed (rare; source checkout used without
    ``pip install -e .``), fall back to a SemVer-valid local marker so
    ``rly --version`` still emits a valid version envelope.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("epochly-relay-cli")
    except PackageNotFoundError:
        return "0.0.0+local"


__version__: str = _resolve_version()

__all__ = ["__version__"]
