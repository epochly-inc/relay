"""Relay contract DSL evaluator (Python).

Public surface:

- :class:`WasmCelEvaluator` -- the single wasm-backed CEL evaluator bound to
  the Relay profile (dyn / timestamp / duration disabled; RE2-only regex;
  wall-clock timeout-bounded; deterministic-only stdlib subset). Constructed
  through :func:`make_cel_evaluator` (the single ``RELAY_CEL_ENGINE`` read
  site).
- :func:`register_udf` -- pure-only UDF registration; raises
  :class:`RelayUdfPurityError` at registration time when ``pure=False``.
- :func:`jcs_canonicalize` -- RFC 8785 JCS canonical-bytes serializer.
- :class:`RelayCelError` and its subclasses -- the structured error
  envelope carrying canonical ``RELAY-CEL-NNN`` codes plus stable
  subtype tokens for cross-runtime byte equality with the TS mirror
  (W6.2).

Spec anchors: D, AM.6.
Eng plan anchors: CQ1 lines 145-157, X4 line 216.
CLAUDE.md anchors: keystone invariant 6, banned pattern #16.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .canonical import jcs_canonicalize
from .engine import CelEvaluatorProtocol, make_cel_evaluator
from .errors import (
    RelayCelError,
    RelayCelNumericOutOfBoundsError,
    RelayCelProfileError,
    RelayCelTimeoutError,
    RelayUdfPurityError,
)
from .udf import PureUdf, register_udf
from .udfs import (
    RELAY_COVERAGE_NAME,
    RELAY_SCHEMA_MATCH_NAME,
    RELAY_TOOL_ARG_NAME,
    relay_coverage,
    relay_schema_match,
    relay_tool_arg,
)
from .udfs.coverage import RELAY_COVERAGE_ARITY
from .udfs.schema_match import RELAY_SCHEMA_MATCH_ARITY
from .udfs.tool_arg import RELAY_TOOL_ARG_ARITY
from .wasm_backed_evaluator import WasmCelEvaluator

# w6.3 production UDF registry: every Relay UDF that ships in v0.1.
# Constructed at import time via the pure-only register_udf entry
# point so the purity flag is enforced structurally (CLAUDE.md banned
# pattern #16). Workers passing this iterable to make_cel_evaluator(
# udfs=RELAY_UDFS) get a fully-wired evaluator with no risk of
# accidentally registering an impure callable. The NAMES double as the
# wasm engine's UDF allowlist (any other name is rejected fail-closed).
RELAY_UDFS: tuple[PureUdf, ...] = (
    register_udf(
        name=RELAY_COVERAGE_NAME,
        fn=relay_coverage,
        pure=True,
        arity=RELAY_COVERAGE_ARITY,
    ),
    register_udf(
        name=RELAY_TOOL_ARG_NAME,
        fn=relay_tool_arg,
        pure=True,
        arity=RELAY_TOOL_ARG_ARITY,
    ),
    register_udf(
        name=RELAY_SCHEMA_MATCH_NAME,
        fn=relay_schema_match,
        pure=True,
        arity=RELAY_SCHEMA_MATCH_ARITY,
    ),
)

__all__ = [
    "RELAY_COVERAGE_ARITY",
    "RELAY_COVERAGE_NAME",
    "RELAY_SCHEMA_MATCH_ARITY",
    "RELAY_SCHEMA_MATCH_NAME",
    "RELAY_TOOL_ARG_ARITY",
    "RELAY_TOOL_ARG_NAME",
    "RELAY_UDFS",
    "CelEvaluatorProtocol",
    "PureUdf",
    "RelayCelError",
    "RelayCelNumericOutOfBoundsError",
    "RelayCelProfileError",
    "RelayCelTimeoutError",
    "RelayUdfPurityError",
    "WasmCelEvaluator",
    "jcs_canonicalize",
    "make_cel_evaluator",
    "register_udf",
    "relay_coverage",
    "relay_schema_match",
    "relay_tool_arg",
]
