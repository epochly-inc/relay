"""x-relay/incident-monitoring-event dataclass (W11.2 / VAL-W11-010).

Mirrors ``schemas/incident-monitoring-event.v1.json``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Final

SCHEMA_VERSION: Final[str] = "x-relay.incident-monitoring-event.v1"


@dataclass(frozen=True)
class IncidentMonitoringEvent:
    """Incident extension; spec table line 868."""

    incident_id: str
    severity: str
    detected_at: str
    status: str
    linked_run_ids: tuple[str, ...] = ()
    remediation_summary_digest: str | None = None
    notification_evidence_digest: str | None = None
    schema_version: str = field(default=SCHEMA_VERSION)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


__all__ = ["SCHEMA_VERSION", "IncidentMonitoringEvent"]
