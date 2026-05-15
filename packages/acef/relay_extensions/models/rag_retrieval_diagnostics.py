"""x-relay/rag-retrieval-diagnostics dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/rag-retrieval-diagnostics.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.rag-retrieval-diagnostics.v1"


@dataclass(frozen=True)
class RagRetrievalDiagnostics:
    """RAG retrieval diagnostics; spec line 885."""

    query_digest: str
    k: int
    retrieved_document_digests: tuple[str, ...]
    retrieved_at: str
    scores: tuple[float, ...] | None = None
    index_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "RagRetrievalDiagnostics"]
