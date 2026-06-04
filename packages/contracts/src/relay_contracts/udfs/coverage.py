"""``relay.coverage(trace, step_name)`` UDF (Python).

Returns ``True`` when ``trace`` is a mapping carrying a ``steps`` field
that is a list/tuple containing at least one item whose ``name`` field
equals ``step_name``. Returns ``False`` otherwise. Never raises on
shape variance: a missing ``steps`` field, a non-iterable ``steps``
field, a non-mapping element, or an absent ``name`` key all yield
``False``. This deterministic shape-tolerance keeps the UDF safe
to call against partial traces during early-stage replay.

Purity contract (CLAUDE.md banned pattern #16):
  - no wall clock (no ``time.*``, no ``datetime.now``)
  - no network (no ``socket``, ``urllib``, ``httpx``, ``requests``)
  - no filesystem reads outside the inputs (no ``open``, ``pathlib.read_*``)
  - no locale-dependent comparisons (only ``==`` on already-typed
    Python ``str`` objects, never ``str.lower()`` / ``casefold()`` /
    ``locale.strcoll`` / collation)
  - no mutable process globals (no ``os.environ``, no module-level
    mutable singletons; the constant ``RELAY_COVERAGE_NAME`` is a
    frozen literal)
  - no random sources (no ``random``, ``secrets``, ``os.urandom``)

Cross-runtime contract: byte-identical JCS-canonical bytes vs the
TypeScript mirror at
``packages/contracts-typescript/src/udfs/coverage.ts`` (corpus at
``tests/conformance/cel/relay_udfs_parity.json``).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._compat import field

# Canonical CEL identifier the contract author writes:
# ``relay.coverage(trace, "step")``. Registered as a single dotted name
# string in the evaluator's UDF map; the CEL parser treats the dotted
# form per the runtime's resolution rules (cel-python: function map
# keyed by exact name; cel-js: same).
RELAY_COVERAGE_NAME: str = "relay.coverage"

# Fixed positional arity (trace, step_name).
RELAY_COVERAGE_ARITY: int = 2


def relay_coverage(trace: Any, step_name: Any) -> bool:
    """Return ``True`` iff ``trace.steps`` contains an entry named ``step_name``.

    Purity-preserving lookups only:
      - reject non-mapping ``trace`` -> False
      - reject non-string ``step_name`` -> False (CEL strings arrive as
        ``str``; cel-python ``celtypes.StringType`` is a ``str`` subclass)
      - reject non-iterable / non-list ``trace["steps"]`` -> False
      - reject non-mapping step entry -> skip (does not match)
      - skip step entries whose ``name`` is not exactly equal (==) to
        ``step_name`` (no case folding, no locale-aware compare)
    """

    # Defensive: cel-python sometimes passes celtypes.MapType which is a
    # Mapping subclass; cel-js passes a plain JS object decoded as dict.
    if not isinstance(trace, Mapping):
        return False
    if not isinstance(step_name, str):
        return False
    # Total field access: cel-python MapType.get raises on a missing key, so use
    # the membership-guarded `field` helper (a missing "steps" -> None -> False).
    steps = field(trace, "steps")
    # Reject str / bytes which are iterable but not "lists of step
    # entries". A bare string in ``steps`` is a shape error; return
    # False rather than iterating its characters.
    if not isinstance(steps, list | tuple):
        return False
    for entry in steps:
        if not isinstance(entry, Mapping):
            continue
        name = field(entry, "name")
        # Strict ``==`` on Python ``str`` values is byte-wise (not
        # locale-aware). cel-python ``StringType`` is ``str`` subclass
        # so this comparison is identical across runtimes.
        if isinstance(name, str) and name == step_name:
            return True
    return False


__all__ = ["RELAY_COVERAGE_ARITY", "RELAY_COVERAGE_NAME", "relay_coverage"]
