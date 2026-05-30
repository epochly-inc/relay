"""``relay.schema_match(payload, schema)`` UDF (Python).

Returns ``True`` iff ``payload`` conforms to a minimal JSON-Schema
subset declared by ``schema``. v0.1 supports the schema keywords
required to express the contract DSL's ``SchemaContract`` checks:

  - ``"type"``: one of ``"string"``, ``"number"``, ``"integer"``,
    ``"boolean"``, ``"object"``, ``"array"``, ``"null"`` (single string
    only; arrays-of-types and ``null`` unions are not in v0.1).
  - ``"required"``: list of property names that MUST be present (only
    meaningful when ``"type": "object"``).
  - ``"properties"``: mapping of property name to nested schema. Only
    properties named in this map are validated when ``additional`` is
    not specified; unknown keys are permitted (consistent with JSON
    Schema's default ``additionalProperties: true``).
  - ``"items"``: nested schema applied to every element of an array
    (only meaningful when ``"type": "array"``). ``items`` as a list
    (tuple validation) is not supported in v0.1.

Returns ``False`` on:
  - non-mapping ``schema``
  - unknown ``"type"`` value
  - type mismatch
  - missing required property
  - any nested ``properties[k]`` mismatch
  - any nested ``items`` mismatch on array elements

Returns ``True`` when ``schema`` is an empty mapping (matches anything,
consistent with JSON Schema).

Purity contract (CLAUDE.md banned pattern #16):
  - no wall clock
  - no network
  - no filesystem reads outside the inputs
  - no locale-dependent comparisons (string keys compared by exact
    equality only; no case folding, no collation)
  - no mutable process globals
  - no random sources
  - bounded recursion (depth-limited at MAX_DEPTH so a malicious
    nested schema cannot exceed Python's stack; the evaluator's
    50 ms wall-clock timeout is the upstream guard, this depth cap
    is defense-in-depth)

Cross-runtime contract: byte-identical JCS-canonical bytes vs the
TypeScript mirror at
``packages/contracts-typescript/src/udfs/schema_match.ts`` (corpus at
``tests/conformance/cel/relay_udfs_parity.json``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

RELAY_SCHEMA_MATCH_NAME: str = "relay.schema_match"
RELAY_SCHEMA_MATCH_ARITY: int = 2


def _is_finite_number(payload: Any) -> bool:
    """Return True iff ``payload`` is a JSON-Schema "number" value.

    Mirrors the TypeScript ``matchesType`` check at
    ``packages/contracts-typescript/src/udfs/schema_match.ts`` for
    ``typeName === "number"``:

      - booleans are NOT numbers (Python bool subclasses int; route out)
      - non-int / non-float are NOT numbers
      - float NaN / +Inf / -Inf are NOT finite -> rejected

    Cross-runtime parity: ``Number.isFinite`` in TS rejects NaN/Inf, so
    Python must too. Same input MUST yield the same boolean across both
    runtimes per the JCS byte-identity guarantee.
    """
    if isinstance(payload, bool):
        return False
    if not isinstance(payload, int | float):
        return False
    return not (isinstance(payload, float) and not math.isfinite(payload))


def _is_integer(payload: Any) -> bool:
    """Return True iff ``payload`` is a JSON-Schema "integer" value.

    Pinned cross-runtime definition (VAL-PARITY-002): a finite number
    whose value is integral is an integer. This mirrors the TypeScript
    mirror's ``Number.isInteger`` check at
    ``packages/contracts-typescript/src/udfs/schema_match.ts`` for
    ``typeName === "integer"``:

      - booleans are NOT integers (Python bool subclasses int; route out)
      - non-int / non-float are NOT integers
      - float NaN / +Inf / -Inf are NOT integers (Number.isInteger rejects
        them) -- screened out by ``_is_finite_number``
      - a finite float with an integral value (e.g. ``1.0``, produced by
        cel-python typing a CEL double literal as ``DoubleType``) IS an
        integer

    Cross-runtime parity: cel-python types a CEL double ``1.0`` as a
    ``float`` subclass, while cel-js represents it as the integral JS
    number ``1``. Without the ``float`` arm below, the same input yielded
    ``False`` in Python but ``True`` in TS -- breaking the byte-identical
    JCS parity guarantee. ``int`` values are integral by definition; a
    ``float`` is integral iff ``payload == int(payload)`` (safe only after
    the finiteness screen, since ``int(nan)`` / ``int(inf)`` raise).
    """
    if not _is_finite_number(payload):
        return False
    if isinstance(payload, float):
        return payload == int(payload)
    # Remaining case is a non-bool ``int`` (bools were screened out by
    # ``_is_finite_number``); every such value is integral.
    return True

# Defense-in-depth cap on recursive descent into nested schemas. The
# evaluator's wall-clock timeout (DEFAULT_TIMEOUT_MS = 50 ms) is the
# primary bound; this cap limits Python stack growth on pathological
# inputs to a value well below sys.getrecursionlimit().
MAX_DEPTH: int = 64

# Canonical type names. Listed as a frozenset constant so the lookup
# is hash-based and the set itself is immutable (no mutable global
# the function mutates between calls).
_VALID_TYPES: frozenset[str] = frozenset(
    {"string", "number", "integer", "boolean", "object", "array", "null"}
)


def _matches_type(payload: Any, type_name: str) -> bool:
    # Booleans are a subclass of int in Python; route them out first
    # so ``"type": "integer"`` does not silently accept ``True``.
    if type_name == "boolean":
        return isinstance(payload, bool)
    if type_name == "null":
        return payload is None
    if type_name == "string":
        return isinstance(payload, str)
    if type_name == "integer":
        # Pinned cross-runtime definition (VAL-PARITY-002): a finite
        # number whose value is integral is an "integer", matching the
        # TS mirror's ``Number.isInteger``. cel-python types a CEL double
        # ``1.0`` as ``float``; without this, ``1.0`` was rejected here
        # (Python False) while cel-js accepted it (TS True). Booleans and
        # NaN / +Inf / -Inf are excluded by ``_is_integer``.
        return _is_integer(payload)
    if type_name == "number":
        # JSON Schema "number" matches any FINITE numeric (int or float).
        # Booleans are excluded (they are not numbers in JSON Schema
        # parlance); NaN / +Inf / -Inf are excluded for cross-runtime
        # parity with the TS mirror's ``Number.isFinite`` gate.
        return _is_finite_number(payload)
    if type_name == "object":
        return isinstance(payload, Mapping)
    if type_name == "array":
        # Reject str / bytes which are sequences but not JSON arrays.
        return isinstance(payload, list | tuple)
    # Unknown type names are rejected by the caller before reaching
    # here; defensive False keeps the function total.
    return False  # pragma: no cover -- guarded by caller


def _validate(payload: Any, schema: Any, depth: int) -> bool:
    if depth > MAX_DEPTH:
        return False
    if not isinstance(schema, Mapping):
        return False
    # Empty schema validates anything. Mirrors JSON Schema's
    # ``true`` / ``{}`` "always-pass" semantics.
    if len(schema) == 0:
        return True
    type_name = schema.get("type")
    if type_name is not None:
        if not isinstance(type_name, str):
            return False
        if type_name not in _VALID_TYPES:
            return False
        if not _matches_type(payload, type_name):
            return False
    # Object-shape constraints (only consulted when payload is a
    # mapping; if "type": "object" is set the type check above has
    # already gated this).
    if isinstance(payload, Mapping):
        required = schema.get("required")
        if required is not None:
            if not isinstance(required, list | tuple):
                return False
            for name in required:
                if not isinstance(name, str):
                    return False
                if name not in payload:
                    return False
        properties = schema.get("properties")
        if properties is not None:
            if not isinstance(properties, Mapping):
                return False
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_name, str):
                    return False
                # Only validate properties that are present; missing
                # properties are validated by ``required``.
                if prop_name in payload and not _validate(
                    payload[prop_name], prop_schema, depth + 1
                ):
                    return False
    # Array-shape constraints (only consulted when payload is a
    # list/tuple; if "type": "array" is set the type check above has
    # already gated this).
    if isinstance(payload, list | tuple) and not isinstance(payload, str | bytes):
        items = schema.get("items")
        if items is not None:
            if not isinstance(items, Mapping):
                return False
            for element in payload:
                if not _validate(element, items, depth + 1):
                    return False
    return True


def relay_schema_match(payload: Any, schema: Any) -> bool:
    """Return ``True`` iff ``payload`` conforms to ``schema``.

    Pure, deterministic, depth-bounded. Returns ``False`` rather than
    raising on any malformed input (non-mapping schema, unknown type
    name, malformed required list, etc.) so contract authors can rely
    on a stable boolean result inside CEL expressions.
    """

    return _validate(payload, schema, depth=0)


__all__ = [
    "MAX_DEPTH",
    "RELAY_SCHEMA_MATCH_ARITY",
    "RELAY_SCHEMA_MATCH_NAME",
    "relay_schema_match",
]
