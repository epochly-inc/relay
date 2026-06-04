"""``relay.tool_arg(call, key)`` UDF (Python).

Returns the value of ``call["args"][key]`` when ``call`` is a mapping
with an ``args`` mapping field that contains ``key``. Returns ``None``
on any shape mismatch (non-mapping ``call``, non-mapping ``args``,
missing ``key``, non-string ``key``). Never raises -- contract authors
write expressions like
``relay.tool_arg(call, "case_id") != null`` and rely on a deterministic
shape-tolerant probe.

Purity contract (CLAUDE.md banned pattern #16):
  - no wall clock
  - no network
  - no filesystem reads outside the inputs
  - no locale-dependent comparisons (only ``in`` / ``[]`` on Python
    mappings, which dispatches to ``__hash__`` / ``__eq__`` on the
    key; Python ``str`` hashes and equality are codepoint-based, not
    locale-aware)
  - no mutable process globals
  - no random sources

Cross-runtime contract: byte-identical JCS-canonical bytes vs the
TypeScript mirror at
``packages/contracts-typescript/src/udfs/tool_arg.ts`` (corpus at
``tests/conformance/cel/relay_udfs_parity.json``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._compat import field

# Canonical CEL identifier the contract author writes:
# ``relay.tool_arg(call, "k")``.
RELAY_TOOL_ARG_NAME: str = "relay.tool_arg"

# Fixed positional arity (call, key).
RELAY_TOOL_ARG_ARITY: int = 2


def relay_tool_arg(call: Any, key: Any) -> Any:
    """Return ``call["args"][key]`` when present; otherwise ``None``.

    Purity-preserving lookups only:
      - reject non-mapping ``call`` -> None
      - reject non-string ``key`` -> None (CEL strings arrive as Python
        ``str`` / ``celtypes.StringType``)
      - reject non-mapping ``call["args"]`` -> None
      - missing ``key`` in args -> None

    The returned value is whatever the mapping holds for that key
    (string, number, bool, None, list, dict). Callers compare it with
    CEL operators; we do not coerce.
    """

    if not isinstance(call, Mapping):
        return None
    if not isinstance(key, str):
        return None
    # Total field access: cel-python MapType.get raises on a missing key, so use
    # the membership-guarded `field` helper (a missing "args" -> None).
    args = field(call, "args")
    if not isinstance(args, Mapping):
        return None
    # Mapping's __contains__ uses key __hash__/__eq__. For Python str
    # this is codepoint-based and locale-independent. cel-python's
    # StringType is a str subclass and shares the same hash/eq, so
    # parity holds across runtimes.
    if key not in args:
        return None
    return args[key]


__all__ = ["RELAY_TOOL_ARG_ARITY", "RELAY_TOOL_ARG_NAME", "relay_tool_arg"]
