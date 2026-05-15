"""Relay contract DSL evaluator (Python).

Public surface for w6.1:

- :class:`RelayCelEvaluator` -- the cel-python wrapper bound to the Relay
  profile (dyn / timestamp / duration disabled; RE2-only regex; wall-clock
  timeout-bounded; deterministic-only stdlib subset).
- :func:`register_udf` -- pure-only UDF registration; raises
  :class:`RelayUdfPurityError` at registration time when ``pure=False``.
- :func:`jcs_canonicalize` -- RFC 8785 JCS canonical-bytes serializer.
- :class:`RelayCelError` and its subclasses -- the structured error
  envelope carrying canonical ``RELAY-CEL-NNN`` codes plus stable
  subtype tokens for cross-runtime byte equality with the cel-js mirror
  (W6.2).

Spec anchors: D, AM.6.
Eng plan anchors: CQ1 lines 145-157, X4 line 216.
CLAUDE.md anchors: keystone invariant 6, banned pattern #16.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .canonical import jcs_canonicalize
from .errors import (
    RelayCelError,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelTimeoutError,
    RelayUdfPurityError,
)
from .evaluator import RelayCelEvaluator
from .udf import PureUdf, register_udf

__all__ = [
    "PureUdf",
    "RelayCelError",
    "RelayCelEvaluator",
    "RelayCelNumericOutOfBoundsError",
    "RelayCelProfileError",
    "RelayCelTimeoutError",
    "RelayUdfPurityError",
    "jcs_canonicalize",
    "register_udf",
]
