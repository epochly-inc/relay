"""Relay local-sidecar package (W2 milestone).

Public surface for the local-sidecar runtime. W2.1 exposes:

  - ``relay_sidecar.primitives.local_atomic_file_write`` (atomic primitive #4)
  - ``relay_sidecar.spawn.acquire_or_attach`` (sidecar startup classifier)
  - ``relay_sidecar.errors.RELAY_SIDECAR_*`` (numeric error code constants)

Per CLAUDE.md keystone invariant #8, ``local_atomic_file_write`` is one of
the four atomic-persistence primitives. Direct ``open(..., 'w')`` against
any sidecar-managed path is a banned pattern; the helper above is the
exclusive write path.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

__version__ = "0.0.0"
__all__ = ["__version__"]
