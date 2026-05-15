"""x-relay/data-quality-check dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/data-quality-check.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.data-quality-check.v1"


@dataclass(frozen=True)
class DataQualityCheck:
    """DataQualityCheck extension; spec table line 870."""

    dataset_digest: str
    check_kind: str
    result: str
    checked_at: str
    limitations_digest: str | None = None
    metric_value: float | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "DataQualityCheck"]
