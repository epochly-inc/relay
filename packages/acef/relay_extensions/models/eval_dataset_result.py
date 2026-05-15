"""x-relay/eval-dataset-result dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/eval-dataset-result.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.eval-dataset-result.v1"


@dataclass(frozen=True)
class EvalDatasetResult:
    """EvalRun extension; spec table line 867."""

    eval_run_id: str
    dataset_digest: str
    case_count: int
    score: float
    completed_at: str
    threshold: float | None = None
    failed_case_ids: tuple[str, ...] = ()
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "EvalDatasetResult"]
