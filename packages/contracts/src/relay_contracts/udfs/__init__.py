"""Production Relay CEL UDFs (Python).

w6.3 ships three production UDFs that contract authors invoke from CEL
expressions in `BehavioralAssertion`, `SchemaContract`, and
`ToolArgContract` definitions:

  - ``relay.coverage(trace, step_name)`` -- VAL-W6-020
  - ``relay.tool_arg(call, key)`` -- VAL-W6-021
  - ``relay.schema_match(payload, schema)`` -- VAL-W6-022

All three MUST be pure (CLAUDE.md banned pattern #16): no wall clock, no
network, no filesystem reads outside the inputs, no locale-dependent
comparisons, no mutable process globals, no random sources. The
implementation modules import only ``typing`` / ``collections.abc`` --
nothing that could leak non-determinism. Registration is via
:func:`relay_contracts.register_udf` with ``pure=True``.

Cross-runtime contract: every UDF MUST produce byte-identical
JCS-canonical output bytes for the same input across cel-python
(this module) and cel-js (`packages/contracts-typescript/src/udfs/`).
The shared parity corpus lives at
``relay/tests/conformance/cel/relay_udfs_parity.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from .coverage import RELAY_COVERAGE_NAME, relay_coverage
from .schema_match import RELAY_SCHEMA_MATCH_NAME, relay_schema_match
from .tool_arg import RELAY_TOOL_ARG_NAME, relay_tool_arg

__all__ = [
    "RELAY_COVERAGE_NAME",
    "RELAY_SCHEMA_MATCH_NAME",
    "RELAY_TOOL_ARG_NAME",
    "relay_coverage",
    "relay_schema_match",
    "relay_tool_arg",
]
