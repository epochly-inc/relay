"""Manifest-driven enforcement helpers for sidecar ingest endpoints.

Enforces CLAUDE.md keystone invariant 3: workers run ONLY commands declared
in the active manifest, matched by ``command_hash``. Per spec F line 4100:

    A worker computes
    command_hash = sha256_canonical(argv ++ cwd ++ env ++ container_image)
    at submit time. The control plane refuses any submission whose
    command_hash does not match a declared command in the active
    manifest version.

This module exposes:

* :class:`ManifestRegistry` -- process-local registry mapping
  ``manifest_commit_hash`` -> set of declared ``command_hash`` values.
  Seeded at sidecar lifespan startup from the operation manifest;
  tests inject a fake registry.
* :func:`enforce_command_hash` -- HTTP-boundary check that rejects an
  ingest submission with a mismatched ``command_hash`` by returning a
  structured ``RELAY-GATE-021`` envelope.
* :func:`enforce_manifest_active_or_in_grace` -- HTTP-boundary check
  delegating to the existing :func:`validate_three_anchor_handoff`
  manifest-anchor lookup so the same grace-window semantics apply to
  ingest as to state transitions.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import aiosqlite

from .state_engine.handoff import (
    MANIFEST_NOT_ACTIVE,
    _manifest_is_active_or_in_grace,
)

# RELAY-GATE-021 wire-format error code (already declared in
# packages/schemas/raw/relay-error-codes.yaml; same envelope as the
# state-transition handler emits on failed three-anchor handoff).
RELAY_GATE_021_CODE: str = "RELAY-GATE-021"
RELAY_GATE_021_CLASS: str = "RELAY-GATE-021"


@dataclass
class ManifestRegistry:
    """Process-local registry of declared manifest command_hashes.

    Mapping: ``manifest_commit_hash`` -> ``set[command_hash]``.

    A registry instance is owned by the sidecar runtime; the lifespan
    startup hook is responsible for seeding it from the operation
    manifest. Tests construct an empty registry and call
    :meth:`register_commands` directly.

    Concurrency: read-only after seeding in production. The set
    operations are not protected by a lock; concurrent mutation during
    request serving is not supported (and not needed -- manifests rotate
    via an explicit register-then-rotate flow, not in-flight mutation).
    """

    _commands_by_manifest: dict[str, set[str]] = field(default_factory=dict)

    def register_commands(
        self,
        *,
        manifest_commit_hash: str,
        command_hashes: list[str] | tuple[str, ...] | set[str],
    ) -> None:
        """Bind a set of declared ``command_hash`` values to a manifest.

        Subsequent calls for the same ``manifest_commit_hash`` REPLACE
        the prior set (not merge) -- a manifest version is immutable, so
        a re-register signals the seeder is correcting its prior view.
        """
        if not isinstance(manifest_commit_hash, str):
            raise TypeError(
                "manifest_commit_hash must be str; got "
                f"{type(manifest_commit_hash).__name__}"
            )
        if not manifest_commit_hash.startswith("sha256-"):
            raise ValueError(
                "manifest_commit_hash must be sha256-<hex>; got "
                f"{manifest_commit_hash!r}"
            )
        cleaned: set[str] = set()
        for ch in command_hashes:
            if not isinstance(ch, str) or not ch.startswith("sha256-"):
                raise ValueError(
                    f"command_hash entries must be sha256-<hex>; got {ch!r}"
                )
            cleaned.add(ch)
        self._commands_by_manifest[manifest_commit_hash] = cleaned

    def is_command_declared(
        self, *, manifest_commit_hash: str, command_hash: str
    ) -> bool:
        """Return True iff ``command_hash`` is in the manifest's declared set.

        Returns False if the manifest is not registered OR the command_hash
        is not in its declared set. Callers MUST distinguish these via the
        separate :func:`enforce_manifest_active_or_in_grace` check -- this
        function answers only the second question.
        """
        declared = self._commands_by_manifest.get(manifest_commit_hash)
        if declared is None:
            return False
        return command_hash in declared

    def known_manifests(self) -> list[str]:
        """Return the list of registered manifest_commit_hashes (for tests)."""
        return list(self._commands_by_manifest.keys())


@dataclass(frozen=True)
class IngestRejection:
    """Structured rejection for a sidecar ingest submission.

    Attributes:
        http_status: HTTP status code (422 for command_hash mismatches per
            VAL-V2M03-012; the spec line 4686 example envelope shows
            ``RELAY-GATE-021`` with http_status=409, but the ingest path
            specifically uses 422 to signal "submission semantically
            invalid" rather than "state-machine conflict" -- matching the
            existing RELAY-ING-xxx envelope conventions for ingest).
        envelope: Wire-format error envelope to serialize as the response
            body.
    """

    http_status: int
    envelope: dict[str, Any]


def _gate_021_envelope(
    *,
    reason: str,
    details: dict[str, Any] | None = None,
    http_status: int = 422,
) -> dict[str, Any]:
    """Build a RELAY-GATE-021 envelope for an ingest rejection.

    Mirrors the state_engine.http_endpoint._gate_021_envelope shape but
    uses http_status=422 (ingest-context) instead of 409 (state-machine
    conflict). The ``reason`` is a structured code consumed by the
    forensic event_log row.
    """
    envelope: dict[str, Any] = {
        "code": RELAY_GATE_021_CODE,
        "error_class": RELAY_GATE_021_CLASS,
        "http_status": http_status,
        "message": "manifest-anchor enforcement rejected submission",
        "details": {"reason": reason, **(details or {})},
    }
    return envelope


async def enforce_manifest_active_or_in_grace(
    reader: aiosqlite.Connection,
    *,
    manifest_commit_hash: str,
    now: Any | None = None,
) -> IngestRejection | None:
    """Reject if ``manifest_commit_hash`` is neither active nor in grace.

    Per CLAUDE.md keystone invariant 3 + spec F line 4102: a manifest
    that has been rotated stays "in grace" for ``grace_window.seconds``
    so in-flight runs can settle. After the grace window expires, any
    submission carrying the rotated hash MUST be rejected with
    ``RELAY-GATE-021``.

    Delegates the actual lookup to the existing
    :func:`_manifest_is_active_or_in_grace` helper in
    ``relay_sidecar.state_engine.handoff`` (the same code path used by
    the three-anchor handoff for state transitions). Reuse keeps the
    grace-window semantics consistent across boundaries.

    Returns:
        ``None`` if the manifest is active or in grace -- proceed with
        ingest. An :class:`IngestRejection` otherwise.
    """
    from datetime import UTC, datetime

    if not isinstance(manifest_commit_hash, str):
        return IngestRejection(
            http_status=422,
            envelope=_gate_021_envelope(
                reason=MANIFEST_NOT_ACTIVE,
                details={"observed_manifest_commit_hash": None},
            ),
        )
    if not manifest_commit_hash.startswith("sha256-"):
        return IngestRejection(
            http_status=422,
            envelope=_gate_021_envelope(
                reason=MANIFEST_NOT_ACTIVE,
                details={
                    "observed_manifest_commit_hash": manifest_commit_hash
                },
            ),
        )
    now_dt = now if now is not None else datetime.now(tz=UTC)
    in_grace = await _manifest_is_active_or_in_grace(
        reader,
        manifest_commit_hash=manifest_commit_hash,
        now=now_dt,
    )
    if not in_grace:
        return IngestRejection(
            http_status=422,
            envelope=_gate_021_envelope(
                reason=MANIFEST_NOT_ACTIVE,
                details={
                    "observed_manifest_commit_hash": manifest_commit_hash
                },
            ),
        )
    return None


def enforce_command_hash(
    *,
    registry: ManifestRegistry,
    manifest_commit_hash: str,
    command_hash: str,
) -> IngestRejection | None:
    """Reject if ``command_hash`` is not declared in the manifest.

    Per CLAUDE.md keystone invariant 3 + spec F line 4100. A submission
    whose command_hash does not match a declared command in the active
    manifest version MUST be refused with ``RELAY-GATE-021``.

    Returns:
        ``None`` if the command_hash is declared -- proceed with ingest.
        An :class:`IngestRejection` otherwise.
    """
    if not isinstance(command_hash, str) or not command_hash.startswith("sha256-"):
        return IngestRejection(
            http_status=422,
            envelope=_gate_021_envelope(
                reason="COMMAND_HASH_MALFORMED",
                details={
                    "observed_command_hash": command_hash,
                    "manifest_commit_hash": manifest_commit_hash,
                },
            ),
        )
    if registry.is_command_declared(
        manifest_commit_hash=manifest_commit_hash, command_hash=command_hash
    ):
        return None
    return IngestRejection(
        http_status=422,
        envelope=_gate_021_envelope(
            reason="COMMAND_HASH_NOT_DECLARED",
            details={
                "observed_command_hash": command_hash,
                "manifest_commit_hash": manifest_commit_hash,
            },
        ),
    )


__all__ = [
    "IngestRejection",
    "ManifestRegistry",
    "RELAY_GATE_021_CLASS",
    "RELAY_GATE_021_CODE",
    "enforce_command_hash",
    "enforce_manifest_active_or_in_grace",
]
