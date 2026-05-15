"""Control-plane binding dataclass for Relay-emitted ACEF bundles.

Per VAL-W11-013, every ACEF bundle that Relay emits MUST carry seven
control-plane binding fields under ``bundle.namespaces["x-relay"]``:

  * ``manifest_commit_hash``      -- sha256 of the manifest at scope creation
  * ``scope_kind``                -- one of run|replay_case|gate_round|evidence_bundle
  * ``scope_id``                  -- uuid of the scope
  * ``actor_kind``                -- MUST equal "control_plane"
  * ``actor_identity_hash``       -- sha256 of the actor identity
  * ``written_by``                -- MUST equal "control_plane"
  * ``redaction_policy_version``  -- version string of active redaction policy

These bindings reference scope objects via content-addressed digests
and IDs only; nothing in this module references SQL identifiers,
psycopg/asyncpg, or db.execute calls (per VAL-W11-015).

CLAUDE.md keystone invariant #1: the control plane writes the result.
``actor_kind`` and ``written_by`` are both pinned to ``"control_plane"``;
any other value is a P0 bug surfaced as RELAY-ING-031 by the emission
writer (VAL-W11-013).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Final

from .errors import (
    RELAY_ING_031_CODE,
    RELAY_SCHEMA_023_CODE,
    ControlPlaneBindingError,
    SchemaVersionError,
)

# -----------------------------------------------------------------------------
# Format pins
# -----------------------------------------------------------------------------

# manifest_commit_hash and actor_identity_hash are sha256 hex strings.
# Format: 64 lowercase hex digits.
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

# scope_id is a UUID v4 string in 8-4-4-4-12 hex form.
_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# Permitted scope kinds. Mirrors PERMITTED_SCOPE_KINDS in __init__.
_PERMITTED_SCOPE_KINDS: Final[frozenset[str]] = frozenset(
    {"run", "replay_case", "gate_round", "evidence_bundle"}
)

# The pinned values for actor_kind and written_by.
_PINNED_ACTOR_KIND: Final[str] = "control_plane"
_PINNED_WRITTEN_BY: Final[str] = "control_plane"


@dataclass(frozen=True)
class ControlPlaneBindings:
    """Seven required control-plane binding fields (VAL-W11-013).

    Frozen dataclass so callers cannot mutate ``written_by`` or
    ``actor_kind`` post-construction. Use :meth:`to_dict` to serialise
    into the on-wire ``bundle.namespaces["x-relay"]`` form.
    """

    manifest_commit_hash: str
    scope_kind: str
    scope_id: str
    actor_kind: str
    actor_identity_hash: str
    written_by: str
    redaction_policy_version: str

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dict ready for nesting under ``namespaces["x-relay"]``."""
        return asdict(self)


def validate_control_plane_bindings(bindings: dict[str, Any]) -> None:
    """Validate a dict against the seven-field VAL-W11-013 contract.

    Raises:
        SchemaVersionError(RELAY-SCHEMA-023): if any required field is
            missing (parse-time-style failure).
        ControlPlaneBindingError(RELAY-ING-031): if ``written_by`` is
            present but not equal to ``"control_plane"``.
        ControlPlaneBindingError(RELAY-ING-031): if ``actor_kind`` is
            present but not equal to ``"control_plane"`` (CLAUDE.md
            keystone invariant #1).
        ControlPlaneBindingError(RELAY-ING-031): if any binding value
            fails its format check (non-hex sha256, malformed UUID,
            unknown scope_kind).
    """
    # Required-field check first (parse-style RELAY-SCHEMA-023).
    required = (
        "manifest_commit_hash",
        "scope_kind",
        "scope_id",
        "actor_kind",
        "actor_identity_hash",
        "written_by",
        "redaction_policy_version",
    )
    for field in required:
        if field not in bindings:
            raise SchemaVersionError(
                f"missing required control-plane binding: {field!r}",
                error_code=RELAY_SCHEMA_023_CODE,
                details={"missing_field": field},
            )
        if bindings[field] is None or bindings[field] == "":
            raise SchemaVersionError(
                f"control-plane binding {field!r} is empty",
                error_code=RELAY_SCHEMA_023_CODE,
                details={"missing_field": field},
            )

    # written_by MUST be the pinned value (CLAUDE.md keystone #1).
    if bindings["written_by"] != _PINNED_WRITTEN_BY:
        raise ControlPlaneBindingError(
            f"written_by must equal {_PINNED_WRITTEN_BY!r}; "
            f"got {bindings['written_by']!r}",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "written_by",
                "expected": _PINNED_WRITTEN_BY,
                "observed": bindings["written_by"],
            },
        )

    # actor_kind MUST equal control_plane per VAL-W11-013.
    if bindings["actor_kind"] != _PINNED_ACTOR_KIND:
        raise ControlPlaneBindingError(
            f"actor_kind must equal {_PINNED_ACTOR_KIND!r}; "
            f"got {bindings['actor_kind']!r}",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "actor_kind",
                "expected": _PINNED_ACTOR_KIND,
                "observed": bindings["actor_kind"],
            },
        )

    # Format checks (sha256 hex, UUID, scope_kind enum).
    if not _SHA256_HEX_RE.match(bindings["manifest_commit_hash"]):
        raise ControlPlaneBindingError(
            "manifest_commit_hash is not a 64-char lowercase hex sha256",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "manifest_commit_hash",
                "observed": bindings["manifest_commit_hash"],
            },
        )

    if not _SHA256_HEX_RE.match(bindings["actor_identity_hash"]):
        raise ControlPlaneBindingError(
            "actor_identity_hash is not a 64-char lowercase hex sha256",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "actor_identity_hash",
                "observed": bindings["actor_identity_hash"],
            },
        )

    if not _UUID_RE.match(bindings["scope_id"]):
        raise ControlPlaneBindingError(
            "scope_id is not a UUID v4 string",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "scope_id",
                "observed": bindings["scope_id"],
            },
        )

    if bindings["scope_kind"] not in _PERMITTED_SCOPE_KINDS:
        raise ControlPlaneBindingError(
            f"scope_kind must be one of {sorted(_PERMITTED_SCOPE_KINDS)!r}; "
            f"got {bindings['scope_kind']!r}",
            error_code=RELAY_ING_031_CODE,
            details={
                "field": "scope_kind",
                "expected": sorted(_PERMITTED_SCOPE_KINDS),
                "observed": bindings["scope_kind"],
            },
        )


__all__ = [
    "ControlPlaneBindings",
    "validate_control_plane_bindings",
]
