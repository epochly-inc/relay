"""x-relay/human-oversight-event dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/human-oversight-event.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.human-oversight-event.v1"


@dataclass(frozen=True)
class HumanOversightEvent:
    """HumanOversightEvent extension; spec table line 869."""

    event_id: str
    reviewer_identity_hash: str
    reviewer_role: str
    decision: str
    occurred_at: str
    authority_basis: str | None = None
    linked_run_id: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "HumanOversightEvent"]
