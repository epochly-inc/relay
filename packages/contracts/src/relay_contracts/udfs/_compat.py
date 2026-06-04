"""Shared helpers so the Relay UDFs are TOTAL + correct for BOTH plain Python
inputs (the direct-callable path) AND cel-python ``celtypes`` values (driven
THROUGH the CEL evaluator).

Empirically-confirmed cel-python quirks the UDFs must survive (these broke the
UDFs' documented "never raises / shape-tolerant" contract when driven through
CEL, which the single-engine wasm cutover standardizes on):

  - ``MapType.get(key)`` RAISES ``KeyError`` on a missing key (and even the
    two-argument ``.get(key, default)`` form raises) -- it models CEL
    map-index semantics, not ``dict.get``. So a UDF that did
    ``schema.get("type")`` raised on every schema lacking a ``type`` field.
    Use membership + indexing instead (both work on ``MapType``).
  - ``BoolType`` is an ``int`` subclass but NOT a ``bool`` subclass, so
    ``isinstance(x, bool)`` is ``False`` for a CEL boolean. That broke JSON
    Schema's "booleans are not numbers/integers" rule
    (``relay.schema_match(true, {"type": "integer"})`` wrongly matched). Detect
    a boolean by type name so the UDFs stay engine-agnostic (no celpy import).

These match the wasm port (``packages/cel-wasm`` ``relay_*``), which is the
single source of truth: all three engines now agree on the intended contract.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def field(m: Any, key: str) -> Any:
    """Total map-field access: the value stored for ``key``, or ``None`` when the
    key is absent. Works for a plain ``dict`` AND cel-python ``MapType`` (whose
    ``.get`` raises on a missing key). A present CEL null reads back as Python
    ``None``, so a missing-or-null schema field both yield ``None`` -- matching
    ``dict.get`` for schema-field reads."""
    if isinstance(m, Mapping) and key in m:
        return m[key]
    return None


def is_bool(x: Any) -> bool:
    """True for a plain Python ``bool`` OR a cel-python ``BoolType`` (an ``int``
    subclass that is NOT a ``bool`` subclass, so ``isinstance(x, bool)`` misses
    it). Type-name check keeps the UDFs free of a celpy import."""
    return isinstance(x, bool) or type(x).__name__ == "BoolType"


__all__ = ["field", "is_bool"]
