"""x-relay/tool-invocation-log dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/tool-invocation-log.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.tool-invocation-log.v1"


@dataclass(frozen=True)
class ToolInvocationLog:
    """ToolCall extension; spec table line 865."""

    tool_name: str
    args_digest: str
    result_digest: str
    idempotency_key: str
    side_effect_class: str
    invoked_at: str
    pre_action_marker_digest: str | None = None
    post_success_proof_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "ToolInvocationLog"]
