"""Emission writer for Relay-emitted ACEF bundles.

This module provides :class:`EmissionWriter`, the W11.2 surface that
takes an in-memory bundle dict (with ACEF Core fields plus the
Relay ``x-relay/*`` extension namespaces) and validates it against the
W11.2 contract before any persistence side effect is taken.

The writer enforces five contract surfaces:

  * VAL-W11-011 -- Relay-specific keys appear ONLY under
    ``bundle.namespaces["x-relay"]``; ACEF Core's root-level keys are
    untouched.
  * VAL-W11-012 -- Unknown ``x-relay/*`` namespaces or undeclared
    sub-fields are rejected with ``SchemaVersionError(RELAY-SCHEMA-011)``.
    No bundle is persisted to the object store after rejection.
  * VAL-W11-013 -- Every emitted bundle carries the seven required
    control-plane bindings; ``written_by`` and ``actor_kind`` MUST equal
    ``"control_plane"``.
  * VAL-W11-014 -- Both ``bundle.schema_version`` (ACEF Core, ``"v0.3"``)
    and ``bundle.namespaces["x-relay"].schema_version`` (Relay, ``"v1"``)
    are present; mutation to an unknown value fails parse with
    ``SchemaVersionError(RELAY-SCHEMA-014)``.
  * VAL-W11-015 -- This module references no SQL identifiers, no
    psycopg/asyncpg, no db.execute / session.query.

The writer is INTENTIONALLY decoupled from any persistent store. The
``write_bundle()`` method validates and returns the canonicalised dict;
actual persistence (R2 object PUT, control-plane row write) happens via
the four atomic-persistence primitives in W2 / W11.3+ and lives outside
this package. This boundary keeps the W11.2 surface pure and testable
under tier-1 plumbing (no I/O, no database, no network).

CLAUDE.md keystone invariant #1: the control plane writes the result.
This writer does NOT decide outcome; it surfaces emission rejections
typed so the caller (the control-plane evidence-emission service) can
either persist the validated bundle or surface a structured error.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any, Final

from . import (
    ACEF_CORE_SCHEMA_VERSION_PIN,
    EXPECTED_TEN,
    RELAY_EXTENSIONS_SCHEMA_VERSION,
    REQUIRED_CONTROL_PLANE_BINDINGS,
    X_RELAY_NAMESPACE_KEY,
    load_namespace_schema,
)
from .bindings import validate_control_plane_bindings
from .errors import (
    RELAY_SCHEMA_011_CODE,
    RELAY_SCHEMA_014_CODE,
    SchemaVersionError,
)

# -----------------------------------------------------------------------------
# Forbidden root-level prefixes (VAL-W11-011)
# -----------------------------------------------------------------------------
# ACEF Core bundle root keys MUST NOT contain any Relay-specific identifier.
# Per VAL-W11-011 a key starting with "relay_" or "x-relay" at the bundle
# root is a violation.

_FORBIDDEN_ROOT_PREFIXES: Final[tuple[str, ...]] = ("relay_", "x-relay")


def _audit_root_keys(bundle: dict[str, Any]) -> None:
    """VAL-W11-011: no Relay-specific key at the bundle root."""
    for key in bundle:
        for prefix in _FORBIDDEN_ROOT_PREFIXES:
            if key.startswith(prefix):
                raise SchemaVersionError(
                    f"bundle root key {key!r} is forbidden; Relay fields "
                    f"MUST live under bundle.namespaces[{X_RELAY_NAMESPACE_KEY!r}]",
                    error_code=RELAY_SCHEMA_011_CODE,
                    details={"violating_root_key": key},
                )


def _audit_namespace_block(bundle: dict[str, Any]) -> dict[str, Any]:
    """Verify ``bundle.namespaces["x-relay"]`` is structurally well-formed.

    Returns the x-relay block dict for downstream sub-field validation.
    """
    namespaces = bundle.get("namespaces")
    if not isinstance(namespaces, dict):
        raise SchemaVersionError(
            "bundle.namespaces missing or not a dict",
            error_code=RELAY_SCHEMA_011_CODE,
            details={"observed_type": type(namespaces).__name__},
        )
    x_relay = namespaces.get(X_RELAY_NAMESPACE_KEY)
    if not isinstance(x_relay, dict):
        raise SchemaVersionError(
            f"bundle.namespaces[{X_RELAY_NAMESPACE_KEY!r}] missing or not a dict",
            error_code=RELAY_SCHEMA_011_CODE,
            details={"observed_type": type(x_relay).__name__},
        )
    return x_relay


def _audit_namespace_keys(x_relay: dict[str, Any]) -> None:
    """VAL-W11-012: every key under x-relay must be either a control-plane
    binding name OR a declared namespace name OR ``schema_version``.
    """
    permitted = (
        EXPECTED_TEN
        | set(REQUIRED_CONTROL_PLANE_BINDINGS)
        | {"schema_version"}
    )
    for key in x_relay:
        if key not in permitted:
            raise SchemaVersionError(
                f"unknown key under bundle.namespaces[{X_RELAY_NAMESPACE_KEY!r}]: "
                f"{key!r}; expected one of the ten declared namespaces, "
                f"the seven control-plane bindings, or 'schema_version'",
                error_code=RELAY_SCHEMA_011_CODE,
                details={
                    "violating_key": key,
                    "permitted": sorted(permitted),
                },
            )


def _audit_namespace_subfields(x_relay: dict[str, Any]) -> None:
    """VAL-W11-012 (sub-field): each declared namespace's payload MUST
    contain only fields declared in the namespace's JSON Schema.

    For each present declared namespace, load the schema, read its
    top-level ``properties`` keys, and reject any payload key absent
    from the property set.
    """
    for ns in EXPECTED_TEN:
        payload = x_relay.get(ns)
        if payload is None:
            continue
        if not isinstance(payload, dict):
            raise SchemaVersionError(
                f"namespace {ns!r} payload must be an object; got "
                f"{type(payload).__name__}",
                error_code=RELAY_SCHEMA_011_CODE,
                details={"namespace": ns, "observed_type": type(payload).__name__},
            )
        schema = load_namespace_schema(ns)
        properties = schema.get("properties") or {}
        declared_props = set(properties.keys())
        if not declared_props:
            # Schema has no properties block; nothing to enforce. Defensive
            # path; the W11.2 schemas all declare properties.
            continue
        for field in payload:
            if field not in declared_props:
                raise SchemaVersionError(
                    f"undeclared sub-field {field!r} in namespace {ns!r}",
                    error_code=RELAY_SCHEMA_011_CODE,
                    details={
                        "namespace": ns,
                        "violating_subfield": field,
                        "declared_properties": sorted(declared_props),
                    },
                )

        # VAL-ISO-011: enforce the per-namespace payload schema_version
        # ``const`` declared by the namespace JSON Schema (e.g.
        # ``x-relay.<ns>.v1``). The key-level audit above does NOT validate
        # the VALUE, so a downgraded/unknown namespace schema_version (e.g.
        # ``x-relay.replay-verification.v2``) would otherwise be accepted.
        # Fail closed with RELAY-SCHEMA-014 on mismatch or absence, mirroring
        # the block-level schema_version check in ``_audit_schema_versions``.
        expected_version = (properties.get("schema_version") or {}).get("const")
        if expected_version is not None:
            observed_version = payload.get("schema_version")
            if observed_version != expected_version:
                raise SchemaVersionError(
                    f"namespace {ns!r} schema_version must equal "
                    f"{expected_version!r}; got {observed_version!r}",
                    error_code=RELAY_SCHEMA_014_CODE,
                    details={
                        "field": f"namespaces.{X_RELAY_NAMESPACE_KEY}.{ns}.schema_version",
                        "namespace": ns,
                        "expected": expected_version,
                        "observed": observed_version,
                    },
                )


def _audit_schema_versions(bundle: dict[str, Any], x_relay: dict[str, Any]) -> None:
    """VAL-W11-014: both schema_version fields present and pinned.

    ACEF Core ``bundle.schema_version`` MUST equal the pinned vendor
    value (``"v0.3"``). The x-relay block's ``schema_version`` MUST equal
    ``"v1"``. Either mismatch raises ``SchemaVersionError(RELAY-SCHEMA-014)``.
    """
    core_v = bundle.get("schema_version")
    if core_v != ACEF_CORE_SCHEMA_VERSION_PIN:
        raise SchemaVersionError(
            f"acef.bundle.schema_version must equal "
            f"{ACEF_CORE_SCHEMA_VERSION_PIN!r}; got {core_v!r}",
            error_code=RELAY_SCHEMA_014_CODE,
            details={
                "field": "bundle.schema_version",
                "expected": ACEF_CORE_SCHEMA_VERSION_PIN,
                "observed": core_v,
            },
        )

    x_v = x_relay.get("schema_version")
    if x_v != RELAY_EXTENSIONS_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"bundle.namespaces[{X_RELAY_NAMESPACE_KEY!r}].schema_version "
            f"must equal {RELAY_EXTENSIONS_SCHEMA_VERSION!r}; got {x_v!r}",
            error_code=RELAY_SCHEMA_014_CODE,
            details={
                "field": f"namespaces.{X_RELAY_NAMESPACE_KEY}.schema_version",
                "expected": RELAY_EXTENSIONS_SCHEMA_VERSION,
                "observed": x_v,
            },
        )


def _extract_bindings_from_x_relay(x_relay: dict[str, Any]) -> dict[str, Any]:
    """Pull the seven control-plane binding keys out of the x-relay block."""
    return {key: x_relay.get(key) for key in REQUIRED_CONTROL_PLANE_BINDINGS}


class EmissionWriter:
    """Validates and stages an ACEF bundle for emission.

    Per VAL-W11-012 and VAL-W11-013, ``write_bundle()`` is the single
    chokepoint where Relay's emission service rejects malformed bundles
    BEFORE any object-store side effect is taken. The method is pure:
    it returns the validated bundle on success and raises a structured
    ``SchemaVersionError`` / ``ControlPlaneBindingError`` on failure. No
    bundle is persisted by this class.

    Hosted persistence (R2 PUT, control-plane row write) is bound to the
    four atomic-persistence primitives in W2 and is the caller's
    responsibility -- this keeps W11.2 testable under tier-1 plumbing.
    """

    def write_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """Validate ``bundle`` and return it unchanged on success.

        Raises:
            SchemaVersionError: VAL-W11-011 / VAL-W11-012 / VAL-W11-014
                (root-key violation, unknown namespace/sub-field,
                schema_version mismatch).
            SchemaVersionError(RELAY-SCHEMA-023): VAL-W11-013 missing
                control-plane binding.
            ControlPlaneBindingError(RELAY-ING-031): VAL-W11-013
                ``written_by`` or ``actor_kind`` mutated, or binding
                value format invalid.
        """
        if not isinstance(bundle, dict):
            raise SchemaVersionError(
                "bundle must be a dict",
                error_code=RELAY_SCHEMA_011_CODE,
                details={"observed_type": type(bundle).__name__},
            )

        # VAL-W11-011: ACEF Core root must not carry any Relay-specific key.
        _audit_root_keys(bundle)

        # VAL-W11-012 / -013 / -014: descend into the x-relay namespace block.
        x_relay = _audit_namespace_block(bundle)
        _audit_schema_versions(bundle, x_relay)
        _audit_namespace_keys(x_relay)
        _audit_namespace_subfields(x_relay)

        # VAL-W11-013: control-plane bindings present + correct.
        bindings = _extract_bindings_from_x_relay(x_relay)
        validate_control_plane_bindings(bindings)

        return bundle


__all__ = [
    "EmissionWriter",
]
