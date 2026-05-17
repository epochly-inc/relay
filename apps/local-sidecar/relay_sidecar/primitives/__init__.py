"""Atomic-persistence primitives (W2.1 + W3-atomic).

Per CLAUDE.md keystone invariant #8 and spec section H, business logic
NEVER calls ``open(..., 'w')`` or any direct file-overwrite primitive
against sidecar-managed paths. Use ``local_atomic_file_write`` or
``local_two_layer_locked_write`` (Local OSS profile) instead.

W2.1 landed ``local_atomic_file_write`` (primitive #4). W3-atomic lands
``local_two_layer_locked_write`` (Local-profile equivalent of
``transactional_db_write`` -- spec H lines 4163-4180). Later W-features
layer on the remaining two hosted primitives (``object_put_with_digest``,
``queue_publish_with_idempotency``).
"""

from __future__ import annotations

from .local_atomic_file_write import local_atomic_file_write
from .local_two_layer_locked_write import (
    PersistResult,
    local_two_layer_locked_write,
)

__all__ = [
    "PersistResult",
    "local_atomic_file_write",
    "local_two_layer_locked_write",
]
