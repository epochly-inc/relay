"""Atomic-persistence primitives (W2.1: primitive #4).

Per CLAUDE.md keystone invariant #8 and spec section H, business logic
NEVER calls ``open(..., 'w')`` or any direct file-overwrite primitive
against sidecar-managed paths. Use ``local_atomic_file_write`` instead.

W2.1 lands the local file primitive; later W-features layer on the other
three (``transactional_db_write``, ``object_put_with_digest``,
``queue_publish_with_idempotency``).
"""

from __future__ import annotations

from .local_atomic_file_write import local_atomic_file_write

__all__ = ["local_atomic_file_write"]
