"""Salt registry for the OSS local-profile redaction engine (M08-W8).

Per spec G.1 + G.3 (planning/epochly-replay-spec.md lines 4135, 4148),
HMAC salts for the redaction engine are tenant-scoped secrets that
rotate periodically; rotation produces a new ``policy_version`` and
historical hashes remain stable for comparison within their policy era
(predecessor digests are NOT re-derived under the new salt).

Hosted Relay stores salts in the platform key registry (see private
``relay-platform/services/hosted-control-plane/``). For the OSS local
profile (CLAUDE.md "Public relay/ layout"), the salt registry lives at
``${RELAY_HOME:-~/.relay}/salts.json`` and is written via the
``local_atomic_file_write`` primitive (CLAUDE.md keystone invariant #8;
spec H).

Surface:

  - :class:`SaltRegistry` wraps an on-disk JSON file containing a
    versioned list of ``(salt_ref, salt_bytes_hex, created_at)`` entries
    plus a versioned list of ``(policy_id, policy_version, salt_ref)``
    bindings.
  - :meth:`SaltRegistry.put_salt` records a new salt under a given
    ``salt_ref`` (raises if the ref is already taken; salts are append-
    only).
  - :meth:`SaltRegistry.rotate` performs the canonical rotation
    operation defined in VAL-V2M08-027/028: it allocates a new
    ``salt_ref``, registers fresh random bytes (or the caller-supplied
    bytes), records a new ``policy_versions`` entry whose
    ``policy_version`` is strictly greater than the predecessor's, and
    returns the predecessor + successor binding rows for evidence.
  - :meth:`SaltRegistry.resolve` returns ``bytes`` for a salt_ref --
    suitable for use as the ``SaltProvider`` in :mod:`relay.redaction`.

Determinism guarantees: two registries loaded from the same on-disk
``salts.json`` resolve identical bytes for the same ``salt_ref``.
Predecessor salts are never overwritten; rotating a salt allocates a
new ref. This preserves spec G.3's "historical hashes are not
re-derivable but remain stable for comparison within their policy era"
invariant.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .errors import RelayPolicyError

# Schema version of the on-disk salts.json file. Bumped only on a
# breaking layout change; the loader refuses unknown versions.
_REGISTRY_SCHEMA_VERSION: Final[str] = "relay.salt_registry.v1"

# Default filename inside ``${RELAY_HOME}``. Constructors accept an
# explicit path so unit tests can use a tmp dir without touching the
# user's real registry.
_DEFAULT_FILENAME: Final[str] = "salts.json"

# Default salt length in bytes. 32 bytes = 256 bits = HMAC-SHA-256 key
# at the algorithm's natural width. Spec G.2's example salt_ref is
# opaque; we generate a high-entropy random salt and reference it by
# the caller-supplied ``salt_ref`` string.
DEFAULT_SALT_LEN_BYTES: Final[int] = 32


def _default_relay_home() -> Path:
    """Return ``$RELAY_HOME`` if set, else ``~/.relay``.

    Mirrors :func:`relay_sidecar.lockfile.relay_home` without importing
    from the sidecar package (the SDK MUST be importable on systems
    without the sidecar installed; the salt registry is callable from
    SDK paths).
    """
    override = os.environ.get("RELAY_HOME", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".relay"


def _parse_version_components(version: str) -> tuple[int, ...]:
    """Parse ``version`` into a tuple of integer components for ordering.

    Accepts the two formats observed in the wild on Relay policies:

      * ``v<N>`` / ``V<N>`` -- single integer, optionally prefixed
        (``v1``, ``v10``, ``v100``).
      * Dotted numeric / date-stamped versions where each ``.``-separated
        segment is an unsigned integer (``2026-05-12.001`` is
        decomposed by ``-`` and ``.`` -- ``2026, 5, 12, 1``).

    Returns a tuple of ints so that Python's natural tuple ordering
    gives semver-style comparison: ``(1, 10) > (1, 9)`` even though
    ``"v10" < "v9"`` under lexicographic compare.

    Raises ``ValueError`` if any segment is not an unsigned integer
    after stripping a leading ``v``/``V``. Callers should fall back to
    lexicographic compare in that case (preserving back-compat for
    unparseable / opaque version strings).
    """
    if not version:
        raise ValueError("empty version")
    stripped = version.lstrip("vV")
    if not stripped:
        raise ValueError(f"version {version!r} has no numeric body")
    # Split on both '.' and '-' so date-stamped versions like
    # 2026-05-12.001 decompose into (2026, 5, 12, 1).
    raw_parts: list[str] = []
    for chunk in stripped.split("-"):
        raw_parts.extend(chunk.split("."))
    components: list[int] = []
    for part in raw_parts:
        if not part:
            raise ValueError(f"version {version!r} has an empty segment")
        if not part.isdigit():
            raise ValueError(
                f"version {version!r} segment {part!r} is not an unsigned integer"
            )
        components.append(int(part))
    return tuple(components)


def _policy_version_greater(candidate: str, predecessor: str) -> bool:
    """Return True iff ``candidate`` is strictly greater than
    ``predecessor`` under semver-numeric ordering.

    Strategy: parse both into integer-component tuples and compare
    tuples. If EITHER side fails to parse, fall back to lexicographic
    string compare (preserving prior behavior for opaque version
    strings while fixing the ``v9`` vs ``v10`` and
    ``2026-05-12.001`` vs ``2026-05-12.010`` regressions).
    """
    try:
        cand_t = _parse_version_components(candidate)
        pred_t = _parse_version_components(predecessor)
    except ValueError:
        return candidate > predecessor
    return cand_t > pred_t


def _utcnow_iso() -> str:
    """Return current UTC time as RFC 3339 string with seconds precision.

    Used for the ``created_at`` field on salt + policy_version rows.
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class SaltEntry:
    """A single salt record stored in the registry."""

    salt_ref: str
    salt_hex: str
    created_at: str

    def as_bytes(self) -> bytes:
        return bytes.fromhex(self.salt_hex)


@dataclass(frozen=True)
class PolicyVersionEntry:
    """A salt-binding row tying a policy_version to a salt_ref."""

    policy_id: str
    policy_version: str
    salt_ref: str
    created_at: str


@dataclass(frozen=True)
class RotationResult:
    """Predecessor + successor binding rows returned by :meth:`rotate`.

    ``predecessor`` is None when the rotation creates the first version
    of a policy (no prior salt to roll over from). The caller can
    consult both rows for evidence linking the new policy_version row
    to its successor salt_ref.
    """

    predecessor: PolicyVersionEntry | None
    successor: PolicyVersionEntry


class SaltRegistry:
    """An on-disk salt registry for the OSS local profile.

    The registry is loaded eagerly on construction and rewritten via
    ``local_atomic_file_write`` on every mutation. Concurrent writers
    serialise on the primitive's portalocker; readers see the most
    recently committed bytes (no in-memory cache that outlives a single
    call).

    The registry intentionally does NOT mutate any historical salt or
    policy_version row: rotation only APPENDS. Spec G.3 explicitly
    permits historical hashes to remain valid for predecessor-era
    lookups; an in-place edit would silently break that guarantee.
    """

    def __init__(self, *, path: Path | None = None) -> None:
        self._path = path if path is not None else _default_relay_home() / _DEFAULT_FILENAME
        self._salts: dict[str, SaltEntry] = {}
        self._policy_versions: list[PolicyVersionEntry] = []
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def _load(self) -> None:
        """Read and parse ``salts.json`` if it exists; else start empty."""
        if not self._path.exists():
            self._salts = {}
            self._policy_versions = []
            return
        raw = self._path.read_bytes()
        if not raw:
            self._salts = {}
            self._policy_versions = []
            return
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RelayPolicyError(
                "salt registry file is not valid JSON; refusing to load "
                "(manual recovery required to avoid masking a tampered file)",
                details={"reason": "salts_json_invalid", "path": str(self._path)},
            ) from exc
        if not isinstance(body, dict):
            raise RelayPolicyError(
                "salt registry file must contain a JSON object at the root",
                details={"reason": "salts_root_wrong_type"},
            )
        schema_version = body.get("schema_version")
        if schema_version != _REGISTRY_SCHEMA_VERSION:
            raise RelayPolicyError(
                "salt registry schema_version unsupported; refusing to load",
                details={
                    "reason": "salts_schema_version_unknown",
                    "expected": _REGISTRY_SCHEMA_VERSION,
                    "received": schema_version,
                },
            )
        raw_salts = body.get("salts", [])
        if not isinstance(raw_salts, list):
            raise RelayPolicyError(
                "salt registry salts[] must be a list",
                details={"reason": "salts_wrong_type"},
            )
        salts: dict[str, SaltEntry] = {}
        for idx, row in enumerate(raw_salts):
            if not isinstance(row, dict):
                raise RelayPolicyError(
                    f"salt registry salts[{idx}] must be a dict",
                    details={"reason": "salt_row_wrong_type", "index": idx},
                )
            salt_ref = row.get("salt_ref")
            salt_hex = row.get("salt_hex")
            created_at = row.get("created_at", "")
            if not isinstance(salt_ref, str) or not salt_ref.strip():
                raise RelayPolicyError(
                    f"salt registry salts[{idx}].salt_ref must be a non-empty string",
                    details={"reason": "salt_ref_missing", "index": idx},
                )
            if not isinstance(salt_hex, str) or not salt_hex:
                raise RelayPolicyError(
                    f"salt registry salts[{idx}].salt_hex must be a non-empty string",
                    details={"reason": "salt_hex_missing", "index": idx},
                )
            try:
                bytes.fromhex(salt_hex)
            except ValueError as exc:
                raise RelayPolicyError(
                    f"salt registry salts[{idx}].salt_hex is not valid hex",
                    details={"reason": "salt_hex_invalid", "index": idx},
                ) from exc
            if salt_ref in salts:
                raise RelayPolicyError(
                    f"salt registry salts[{idx}] duplicates salt_ref {salt_ref!r}",
                    details={"reason": "salt_ref_duplicate", "index": idx},
                )
            salts[salt_ref] = SaltEntry(
                salt_ref=salt_ref,
                salt_hex=salt_hex,
                created_at=str(created_at),
            )
        raw_versions = body.get("policy_versions", [])
        if not isinstance(raw_versions, list):
            raise RelayPolicyError(
                "salt registry policy_versions[] must be a list",
                details={"reason": "policy_versions_wrong_type"},
            )
        versions: list[PolicyVersionEntry] = []
        for idx, row in enumerate(raw_versions):
            if not isinstance(row, dict):
                raise RelayPolicyError(
                    f"salt registry policy_versions[{idx}] must be a dict",
                    details={"reason": "policy_version_row_wrong_type", "index": idx},
                )
            policy_id = row.get("policy_id")
            policy_version = row.get("policy_version")
            salt_ref = row.get("salt_ref")
            created_at = row.get("created_at", "")
            if not (
                isinstance(policy_id, str)
                and policy_id.strip()
                and isinstance(policy_version, str)
                and policy_version.strip()
                and isinstance(salt_ref, str)
                and salt_ref.strip()
            ):
                raise RelayPolicyError(
                    f"salt registry policy_versions[{idx}] must have non-empty "
                    "policy_id, policy_version, salt_ref",
                    details={"reason": "policy_version_field_missing", "index": idx},
                )
            if salt_ref not in salts:
                raise RelayPolicyError(
                    f"salt registry policy_versions[{idx}] references unknown "
                    f"salt_ref {salt_ref!r}",
                    details={
                        "reason": "policy_version_salt_ref_unknown",
                        "index": idx,
                        "salt_ref": salt_ref,
                    },
                )
            versions.append(
                PolicyVersionEntry(
                    policy_id=policy_id,
                    policy_version=policy_version,
                    salt_ref=salt_ref,
                    created_at=str(created_at),
                )
            )
        self._salts = salts
        self._policy_versions = versions

    def _commit(self) -> None:
        """Write the current in-memory state to disk atomically."""
        # Local import: the SDK MUST be importable without the sidecar
        # package on the path. Wrap the import in a function-local scope
        # so a non-sidecar install only pays the dependency at write
        # time (rotation / put_salt), not at module import.
        from relay_sidecar.primitives.local_atomic_file_write import (
            local_atomic_file_write,
        )

        body: dict[str, Any] = {
            "schema_version": _REGISTRY_SCHEMA_VERSION,
            "salts": [
                {
                    "salt_ref": s.salt_ref,
                    "salt_hex": s.salt_hex,
                    "created_at": s.created_at,
                }
                # Sort by salt_ref for deterministic on-disk bytes.
                for s in sorted(self._salts.values(), key=lambda s: s.salt_ref)
            ],
            "policy_versions": [
                {
                    "policy_id": v.policy_id,
                    "policy_version": v.policy_version,
                    "salt_ref": v.salt_ref,
                    "created_at": v.created_at,
                }
                for v in self._policy_versions
            ],
        }
        payload = json.dumps(
            body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        local_atomic_file_write(self._path, payload, mode=0o600)

    def put_salt(
        self,
        *,
        salt_ref: str,
        salt_bytes: bytes | None = None,
    ) -> SaltEntry:
        """Register a new salt under ``salt_ref``.

        ``salt_bytes`` defaults to :data:`DEFAULT_SALT_LEN_BYTES` random
        bytes from :func:`secrets.token_bytes`. Raises
        :class:`relay.errors.RelayPolicyError` when ``salt_ref`` is
        already registered (salts are append-only; rotation MUST
        allocate a new ref).
        """
        if not isinstance(salt_ref, str) or not salt_ref.strip():
            raise RelayPolicyError(
                "put_salt: salt_ref must be a non-empty string",
                details={"reason": "salt_ref_missing"},
            )
        if salt_ref in self._salts:
            raise RelayPolicyError(
                f"put_salt: salt_ref {salt_ref!r} is already registered; "
                "salts are append-only -- allocate a new ref via rotate()",
                details={"reason": "salt_ref_duplicate", "salt_ref": salt_ref},
            )
        if salt_bytes is None:
            salt_bytes = secrets.token_bytes(DEFAULT_SALT_LEN_BYTES)
        if not isinstance(salt_bytes, bytes | bytearray):
            raise RelayPolicyError(
                "put_salt: salt_bytes must be bytes",
                details={"reason": "salt_bytes_wrong_type"},
            )
        entry = SaltEntry(
            salt_ref=salt_ref,
            salt_hex=bytes(salt_bytes).hex(),
            created_at=_utcnow_iso(),
        )
        self._salts[salt_ref] = entry
        self._commit()
        return entry

    def resolve(self, salt_ref: str) -> bytes:
        """Return the raw salt bytes for ``salt_ref``.

        Suitable for use as the :type:`SaltProvider` in
        :mod:`relay.redaction`.
        """
        if salt_ref not in self._salts:
            raise RelayPolicyError(
                f"resolve: salt_ref {salt_ref!r} is not registered",
                details={"reason": "salt_ref_unknown", "salt_ref": salt_ref},
            )
        return self._salts[salt_ref].as_bytes()

    def list_policy_versions(self, *, policy_id: str) -> list[PolicyVersionEntry]:
        """Return the policy-version bindings for ``policy_id`` in insertion order."""
        return [v for v in self._policy_versions if v.policy_id == policy_id]

    def latest_policy_version(
        self, *, policy_id: str
    ) -> PolicyVersionEntry | None:
        """Return the most-recently-appended binding for ``policy_id``, or None."""
        for entry in reversed(self._policy_versions):
            if entry.policy_id == policy_id:
                return entry
        return None

    def rotate(
        self,
        *,
        policy_id: str,
        new_salt_ref: str,
        new_policy_version: str,
        new_salt_bytes: bytes | None = None,
    ) -> RotationResult:
        """Allocate a fresh salt + record a new policy_version binding.

        This is the canonical rotation operation defined by
        VAL-V2M08-027 / VAL-V2M08-028:

          - ``new_salt_ref`` MUST NOT collide with an existing salt.
          - ``new_policy_version`` MUST be strictly greater than the
            predecessor binding's ``policy_version`` for the same
            ``policy_id`` under semver-numeric ordering (so ``v10`` is
            correctly greater than ``v9``, not less than). Versions
            that fail numeric parsing fall back to lexicographic
            compare. This enforces monotonicity at the registry
            layer; the redaction policy publish flow re-checks at
            insert time.
          - The predecessor binding is PRESERVED, never overwritten.
            Historical hashes computed under the predecessor salt remain
            valid for predecessor-era lookups (spec G.3).

        Returns the predecessor (or ``None`` when rotating into the first
        version of a brand-new policy) and the successor binding.
        """
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise RelayPolicyError(
                "rotate: policy_id must be a non-empty string",
                details={"reason": "policy_id_missing"},
            )
        if not isinstance(new_policy_version, str) or not new_policy_version.strip():
            raise RelayPolicyError(
                "rotate: new_policy_version must be a non-empty string",
                details={"reason": "new_policy_version_missing"},
            )
        if not isinstance(new_salt_ref, str) or not new_salt_ref.strip():
            raise RelayPolicyError(
                "rotate: new_salt_ref must be a non-empty string",
                details={"reason": "new_salt_ref_missing"},
            )
        predecessor = self.latest_policy_version(policy_id=policy_id)
        if predecessor is not None:
            if not _policy_version_greater(
                new_policy_version, predecessor.policy_version
            ):
                raise RelayPolicyError(
                    "rotate: new_policy_version MUST be strictly greater "
                    "than the predecessor's policy_version",
                    details={
                        "reason": "policy_version_not_monotonic",
                        "predecessor": predecessor.policy_version,
                        "candidate": new_policy_version,
                    },
                )
            if new_salt_ref == predecessor.salt_ref:
                raise RelayPolicyError(
                    "rotate: new_salt_ref MUST differ from the predecessor's "
                    "salt_ref (rotation produces a new salt by definition)",
                    details={
                        "reason": "salt_ref_unchanged",
                        "predecessor_salt_ref": predecessor.salt_ref,
                    },
                )
        # Build the successor state in memory and persist with a
        # SINGLE atomic ``_commit``. Pre-fix code called
        # ``put_salt`` (which committed) and then committed again
        # after appending the policy_version row: a crash between
        # those two writes would leave the registry with a salt
        # entry that no policy_version references, violating the
        # G.3 invariant that every active policy_version's salt is
        # registered exactly once and never re-derived.
        if not isinstance(new_salt_ref, str) or not new_salt_ref.strip():
            raise RelayPolicyError(
                "put_salt: salt_ref must be a non-empty string",
                details={"reason": "salt_ref_missing"},
            )
        if new_salt_ref in self._salts:
            raise RelayPolicyError(
                f"put_salt: salt_ref {new_salt_ref!r} is already registered; "
                "salts are append-only -- allocate a new ref via rotate()",
                details={
                    "reason": "salt_ref_duplicate",
                    "salt_ref": new_salt_ref,
                },
            )
        salt_bytes = new_salt_bytes
        if salt_bytes is None:
            salt_bytes = secrets.token_bytes(DEFAULT_SALT_LEN_BYTES)
        if not isinstance(salt_bytes, bytes | bytearray):
            raise RelayPolicyError(
                "put_salt: salt_bytes must be bytes",
                details={"reason": "salt_bytes_wrong_type"},
            )
        now = _utcnow_iso()
        new_salt_entry = SaltEntry(
            salt_ref=new_salt_ref,
            salt_hex=bytes(salt_bytes).hex(),
            created_at=now,
        )
        successor = PolicyVersionEntry(
            policy_id=policy_id,
            policy_version=new_policy_version,
            salt_ref=new_salt_ref,
            created_at=now,
        )
        # Mutate in-memory state, then commit. If ``_commit`` raises,
        # roll back the in-memory mutations so a retried rotate()
        # call observes the same pre-state. Predecessor entries are
        # left untouched throughout (G.3 invariant).
        self._salts[new_salt_ref] = new_salt_entry
        self._policy_versions.append(successor)
        try:
            self._commit()
        except Exception:
            # Roll back so the in-memory state matches what is on
            # disk. Callers can safely retry without observing a
            # half-applied rotation.
            self._salts.pop(new_salt_ref, None)
            with contextlib.suppress(ValueError):
                self._policy_versions.remove(successor)
            raise
        return RotationResult(predecessor=predecessor, successor=successor)


__all__ = [
    "DEFAULT_SALT_LEN_BYTES",
    "PolicyVersionEntry",
    "RotationResult",
    "SaltEntry",
    "SaltRegistry",
]
