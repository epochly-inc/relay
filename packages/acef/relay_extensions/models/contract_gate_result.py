"""x-relay/contract-gate-result dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/contract-gate-result.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.contract-gate-result.v1"


@dataclass(frozen=True)
class ContractGateResult:
    """GateDecision extension; spec table line 862."""

    gate_round_id: str
    round_index: int
    action: str
    decided_at: str
    failed_assertion_ids: tuple[str, ...] = ()
    contract_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # asdict() turns the tuple into a list, which is exactly the JSON
        # shape we want (JSON has no tuple primitive). No further coercion.
        return d


__all__ = ["SCHEMA_VERSION", "ContractGateResult"]
