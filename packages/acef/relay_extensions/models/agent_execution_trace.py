"""x-relay/agent-execution-trace dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/agent-execution-trace.v1.json``. Frozen dataclass; use
:meth:`to_dict` to serialise into the on-wire form for nesting under
``bundle.namespaces["x-relay"]["agent-execution-trace"]``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.agent-execution-trace.v1"


@dataclass(frozen=True)
class AgentExecutionTrace:
    """TraceSpan extension; spec table line 864."""

    span_id: str
    trace_id: str
    span_type: str
    status: str
    started_at: str
    ended_at: str
    parent_span_id: str | None = None
    duration_ms: int | None = None
    error_class: str | None = None
    redacted_metadata_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "AgentExecutionTrace"]
