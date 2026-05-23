"""Structured errors raised by the Relay x-relay extension layer.

Per CLAUDE.md keystone invariant #10 (schema_version on every canonical
envelope) and §B.7 line 3619 ("Engines refuse to write objects whose
schema_version is unknown"), the emission writer surfaces every
schema/version violation as a typed exception carrying the canonical
``RELAY-SCHEMA-NNN`` wire code (see
``packages/schemas/raw/relay-error-codes.yaml``).

Wire codes used by this layer (registered in the canonical YAML):

  * ``RELAY-SCHEMA-011`` -- unknown x-relay namespace or undeclared sub-field
                            (VAL-W11-012).
  * ``RELAY-SCHEMA-014`` -- unknown x-relay schema_version (VAL-W11-014).
  * ``RELAY-SCHEMA-017`` -- reserved wire-format constant for the ACEF
                            Core ``bundle.schema_version`` rejection
                            surface (VAL-W11-017). NOT currently emitted:
                            the W11.3 emission writer collapses both
                            ACEF Core and x-relay schema_version
                            mismatches into ``RELAY-SCHEMA-014`` (see
                            emission.py module docstring + line 171
                            docstring). Constant exists here so a future
                            split can land without a registry change.
  * ``RELAY-SCHEMA-018`` -- reserved wire-format constant for the
                            x-relay namespace block schema_version
                            rejection surface (VAL-W11-018). NOT
                            currently emitted; same routing-through-014
                            note as 017.
  * ``RELAY-SCHEMA-023`` -- bundle missing required control-plane bindings
                            (VAL-W11-023; w11.3+).
  * ``RELAY-ING-031``    -- ``written_by`` mutated to a value other than
                            ``"control_plane"`` (VAL-W11-013); the same
                            wire code the SDK already surfaces for
                            canonical-status forbidden writes (existing
                            spec §B.4 / W3 surface).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Any, Final

# -----------------------------------------------------------------------------
# Wire codes (Final[str]). Each token must satisfy ^RELAY-[A-Z]+-[0-9]{3}$
# (VAL-W1-029) and be present in
# packages/schemas/raw/relay-error-codes.yaml.
# -----------------------------------------------------------------------------

RELAY_SCHEMA_011_CODE: Final[str] = "RELAY-SCHEMA-011"  # unknown x-relay namespace / sub-field
RELAY_SCHEMA_014_CODE: Final[str] = "RELAY-SCHEMA-014"  # unknown x-relay schema_version
RELAY_SCHEMA_017_CODE: Final[str] = "RELAY-SCHEMA-017"  # unknown acef.bundle.schema_version
RELAY_SCHEMA_018_CODE: Final[str] = "RELAY-SCHEMA-018"  # unknown x-relay block schema_version
RELAY_SCHEMA_023_CODE: Final[str] = "RELAY-SCHEMA-023"  # missing required control-plane bindings
RELAY_ING_031_CODE: Final[str] = "RELAY-ING-031"  # written_by != control_plane


class RelayAcefExtensionError(Exception):
    """Root of the relay_extensions error hierarchy.

    Carries the wire code as ``error_code`` so callers can pattern-match
    on the structured RELAY-* token rather than the exception class. The
    ``details`` mapping is optional structured payload (offending field,
    observed value, etc.).
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: Final[str] = error_code
        self.details: dict[str, Any] = dict(details) if details else {}

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.args[0]!r}, "
            f"error_code={self.error_code!r}, details={self.details!r})"
        )


class SchemaVersionError(RelayAcefExtensionError):
    """A bundle was rejected for a schema/version violation.

    Used for:

      * RELAY-SCHEMA-011 -- unknown x-relay namespace, or undeclared
        sub-field inside a known namespace.
      * RELAY-SCHEMA-014 -- the x-relay block's ``schema_version`` is set
        to an unknown value.
      * RELAY-SCHEMA-017 -- reserved constant for the ACEF Core
        ``bundle.schema_version`` rejection surface; NOT currently
        emitted (the W11.3 writer routes both ACEF Core and x-relay
        schema_version mismatches through RELAY-SCHEMA-014).
      * RELAY-SCHEMA-018 -- reserved constant for the x-relay block
        ``schema_version`` rejection surface; NOT currently emitted
        (same routing-through-014 note as 017).
      * RELAY-SCHEMA-023 -- bundle missing one of the seven required
        control-plane bindings (raised by w11.3+ parse path).
    """


class ControlPlaneBindingError(RelayAcefExtensionError):
    """A bundle was rejected for failing the control-plane binding contract.

    Used for RELAY-ING-031 (``written_by`` mutated away from
    ``"control_plane"``) and any other case where the seven required
    bindings (per VAL-W11-013) are wrong-typed at write time. Missing
    bindings on parse use SchemaVersionError(RELAY-SCHEMA-023) per the
    contract.
    """


__all__ = [
    "RELAY_ING_031_CODE",
    "RELAY_SCHEMA_011_CODE",
    "RELAY_SCHEMA_014_CODE",
    "RELAY_SCHEMA_017_CODE",
    "RELAY_SCHEMA_018_CODE",
    "RELAY_SCHEMA_023_CODE",
    "ControlPlaneBindingError",
    "RelayAcefExtensionError",
    "SchemaVersionError",
]
