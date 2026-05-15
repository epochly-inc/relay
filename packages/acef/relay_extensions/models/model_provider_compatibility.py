"""x-relay/model-provider-compatibility dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/model-provider-compatibility.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.model-provider-compatibility.v1"


@dataclass(frozen=True)
class ModelProviderCompatibility:
    """Provider/model compatibility evidence; spec line 884."""

    provider: str
    model_id: str
    captured_at: str
    system_fingerprint: str | None = None
    compatibility_status: str = "unknown"
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "ModelProviderCompatibility"]
