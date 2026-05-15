"""Relay x-relay/* ACEF extension namespaces (W11.2).

This package declares the ten Relay-specific extension namespaces that
ride on top of an unmodified ACEF Core bundle. Per spec line 874 ("Relay
should not alter ACEF Core"), every Relay-specific evidence field lives
under ``bundle.namespaces["x-relay"]["<namespace>"]``; ACEF Core's
root-level keys are never touched.

The ten namespaces (spec lines 876-885) are:

  * ``agent-execution-trace``        -- TraceSpan extension (timing, parent, status)
  * ``tool-invocation-log``          -- ToolCall extension (args/result hash, side-effect policy)
  * ``replay-verification``          -- replay outcome (cassette mode, fixture digest, diff)
  * ``contract-gate-result``         -- gate decision binding (failed assertions, action, round)
  * ``eval-dataset-result``          -- eval run binding (dataset digest, score, thresholds)
  * ``human-oversight-event``        -- human-in-the-loop review (reviewer, decision)
  * ``incident-monitoring-event``    -- post-market monitoring / serious incident
  * ``data-quality-check``           -- input/training data governance
  * ``model-provider-compatibility`` -- provider/version/fingerprint compatibility evidence
  * ``rag-retrieval-diagnostics``    -- retrieval document set, k, scores

Public attributes (all immutable Final[...] constants, all ASCII):

  * :data:`RELAY_EXTENSION_NAMESPACES`   -- the canonical 10-tuple of namespace
    names (slash form per spec line 876, just the suffix after ``x-relay/``).
  * :data:`EXPECTED_TEN`                 -- frozenset alias used by VAL-W11-009.
  * :data:`X_RELAY_NAMESPACE_KEY`        -- on-wire top-level key
    (``"x-relay"``) under ``bundle.namespaces``.
  * :data:`RELAY_EXTENSIONS_SCHEMA_VERSION` -- the x-relay namespace's own
    schema_version, value ``"v1"`` at MVP (per VAL-W11-014).
  * :data:`ACEF_CORE_SCHEMA_VERSION_PIN` -- the ACEF Core ``bundle.schema_version``
    value the W11 vendor pin tracks (``"v0.3"``, per PW1-2 line 53).
  * :data:`REQUIRED_CONTROL_PLANE_BINDINGS` -- the seven mandatory fields
    (per VAL-W11-013) every emitted bundle MUST carry under
    ``bundle.namespaces["x-relay"]``.
  * :data:`REQUIRED_WRITTEN_BY` -- the only permitted ``written_by`` value
    (``"control_plane"``); CLAUDE.md keystone invariant #1.

Public functions:

  * :func:`namespace_schema_path(name)` -- on-disk path to the namespace's
    JSON Schema (``schemas/<name>.v1.json``).
  * :func:`namespace_golden_path(name)` -- on-disk path to the namespace's
    golden fixture (``golden/<name>.json``).
  * :func:`namespace_model_path(name)` -- on-disk path to the namespace's
    Python dataclass module (``models/<name>.py``).
  * :func:`load_namespace_schema(name)` -- parsed JSON Schema dict.
  * :func:`is_known_namespace(name)` -- membership test.
  * :func:`package_root()` -- repo-relative path to this package on disk.

The package surfaces no I/O against any database, no psycopg/asyncpg
imports, no SQL identifiers (per VAL-W11-015). Extension records reference
control-plane scope objects only via content-addressed digests and IDs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

# -----------------------------------------------------------------------------
# Namespace registry (load-bearing literals; spec lines 876-885)
# -----------------------------------------------------------------------------
# The ten x-relay extension namespaces, in the canonical slash-form suffix
# (the part after ``x-relay/``). Order is fixed by the spec; tests use
# set equality against EXPECTED_TEN, but the tuple form is what callers
# iterate when emitting a fully-populated bundle.

RELAY_EXTENSION_NAMESPACES: Final[tuple[str, ...]] = (
    "agent-execution-trace",
    "tool-invocation-log",
    "replay-verification",
    "contract-gate-result",
    "eval-dataset-result",
    "human-oversight-event",
    "incident-monitoring-event",
    "data-quality-check",
    "model-provider-compatibility",
    "rag-retrieval-diagnostics",
)

# Frozenset alias used by VAL-W11-009. Set equality against the literal
# expected ten ensures additions/removals require both an explicit tuple
# update AND an explicit schema_version bump (per the LOAD-BEARING comment
# in contract.md line 5223).
EXPECTED_TEN: Final[frozenset[str]] = frozenset(RELAY_EXTENSION_NAMESPACES)


# -----------------------------------------------------------------------------
# On-wire keys and version constants
# -----------------------------------------------------------------------------

# The top-level key under ``bundle.namespaces`` that holds every Relay
# extension. Spec K line 4421 example: ``namespaces.x-relay.schema_version``.
X_RELAY_NAMESPACE_KEY: Final[str] = "x-relay"

# Relay-managed schema_version of the entire x-relay namespace block.
# A bump here is required when the registered namespace count changes
# (VAL-W11-009 LOAD-BEARING comment) or any namespace's schema is
# breaking-changed.
RELAY_EXTENSIONS_SCHEMA_VERSION: Final[str] = "v1"

# Pinned ACEF Core bundle.schema_version. PW1-2 line 53 / VAL-W11-014:
# ``acef.bundle.schema_version == "v0.3"``. Bumping the vendor pin to a
# new ACEF Core minor requires a paired update here.
ACEF_CORE_SCHEMA_VERSION_PIN: Final[str] = "v0.3"


# -----------------------------------------------------------------------------
# Control-plane bindings (VAL-W11-013)
# -----------------------------------------------------------------------------
# Every ACEF bundle Relay emits MUST carry these seven fields under
# ``bundle.namespaces["x-relay"]``. CLAUDE.md keystone invariant #1
# ("the control plane writes the result"): ``written_by`` MUST equal the
# literal string ``"control_plane"``; mutation to anything else triggers
# the emission gate's RELAY-ING-031 surface.

REQUIRED_CONTROL_PLANE_BINDINGS: Final[tuple[str, ...]] = (
    "manifest_commit_hash",
    "scope_kind",
    "scope_id",
    "actor_kind",
    "actor_identity_hash",
    "written_by",
    "redaction_policy_version",
)

# Permitted values for ``scope_kind`` (per VAL-W11-013). This mirrors the
# four scope kinds the state engine recognises (run, replay_case,
# gate_round, evidence_bundle).
PERMITTED_SCOPE_KINDS: Final[frozenset[str]] = frozenset(
    {"run", "replay_case", "gate_round", "evidence_bundle"}
)

# The only permitted ``actor_kind`` for an emitted Relay bundle.
# Per VAL-W11-013 the value MUST be ``"control_plane"``; never
# ``"agent"``, ``"eval_worker"``, or ``"sdk"``.
REQUIRED_ACTOR_KIND: Final[str] = "control_plane"

# The only permitted ``written_by`` value. Mutation rejected with
# RELAY-ING-031 (the existing canonical-status-forbidden code).
REQUIRED_WRITTEN_BY: Final[str] = "control_plane"


# -----------------------------------------------------------------------------
# On-disk locations
# -----------------------------------------------------------------------------


def package_root() -> Path:
    """Return the on-disk root of ``packages/acef/relay_extensions/``."""
    return Path(__file__).resolve().parent


def namespace_schema_path(name: str) -> Path:
    """Return the on-disk path to ``schemas/<name>.v1.json``.

    Does NOT validate that the namespace is known. Callers that need to
    reject unknown namespaces should call :func:`is_known_namespace` first.
    """
    return package_root() / "schemas" / f"{name}.v1.json"


def namespace_golden_path(name: str) -> Path:
    """Return the on-disk path to ``golden/<name>.json``."""
    return package_root() / "golden" / f"{name}.json"


def namespace_model_path(name: str) -> Path:
    """Return the on-disk path to the Python dataclass module for ``name``.

    The on-wire namespace name is hyphenated (per spec lines 876-885,
    e.g. ``agent-execution-trace``); the Python module file is
    underscored (PEP 8, e.g. ``agent_execution_trace.py``). This helper
    performs the mapping so callers can use the canonical hyphen form.
    """
    return package_root() / "models" / f"{name.replace('-', '_')}.py"


def is_known_namespace(name: str) -> bool:
    """Return True iff ``name`` is one of the ten declared namespaces."""
    return name in EXPECTED_TEN


def load_namespace_schema(name: str) -> dict:
    """Load and parse the JSON Schema for namespace ``name``.

    Raises:
        ValueError: if ``name`` is not one of the ten declared namespaces.
        FileNotFoundError: if the schema file is missing on disk.
    """
    if not is_known_namespace(name):
        raise ValueError(
            f"unknown x-relay namespace: {name!r}; expected one of "
            f"{sorted(EXPECTED_TEN)!r}"
        )
    return json.loads(namespace_schema_path(name).read_text(encoding="utf-8"))


__all__ = [
    "ACEF_CORE_SCHEMA_VERSION_PIN",
    "EXPECTED_TEN",
    "PERMITTED_SCOPE_KINDS",
    "RELAY_EXTENSIONS_SCHEMA_VERSION",
    "RELAY_EXTENSION_NAMESPACES",
    "REQUIRED_ACTOR_KIND",
    "REQUIRED_CONTROL_PLANE_BINDINGS",
    "REQUIRED_WRITTEN_BY",
    "X_RELAY_NAMESPACE_KEY",
    "is_known_namespace",
    "load_namespace_schema",
    "namespace_golden_path",
    "namespace_model_path",
    "namespace_schema_path",
    "package_root",
]
