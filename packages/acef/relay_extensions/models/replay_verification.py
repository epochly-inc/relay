"""x-relay/replay-verification dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/replay-verification.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.replay-verification.v1"


@dataclass(frozen=True)
class ReplayVerification:
    """ReplayResult extension; spec table line 866."""

    replay_case_id: str
    mode: str
    fixture_digest: str
    outcome: str
    completed_at: str
    model_signature: str | None = None
    result_diff_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "ReplayVerification"]
