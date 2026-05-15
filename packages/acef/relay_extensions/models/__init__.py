"""Python dataclasses for the ten Relay x-relay/* extension namespaces.

Each module under this package mirrors one ``schemas/<namespace>.v1.json``
schema with a frozen Python dataclass. Per VAL-W11-010, both the schema
and the dataclass carry ``schema_version = "x-relay.<namespace>.v1"``,
and the dataclass round-trips through the JSON Schema validator.

Module names use Python identifier form (underscores) while the on-wire
namespace name uses hyphens. The :func:`get_dataclass(namespace)` helper
resolves the hyphenated namespace to the correct dataclass class.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from typing import Final

from .agent_execution_trace import AgentExecutionTrace
from .contract_gate_result import ContractGateResult
from .data_quality_check import DataQualityCheck
from .eval_dataset_result import EvalDatasetResult
from .human_oversight_event import HumanOversightEvent
from .incident_monitoring_event import IncidentMonitoringEvent
from .model_provider_compatibility import ModelProviderCompatibility
from .rag_retrieval_diagnostics import RagRetrievalDiagnostics
from .replay_verification import ReplayVerification
from .tool_invocation_log import ToolInvocationLog

_NAMESPACE_TO_CLASS: Final[dict[str, type]] = {
    "agent-execution-trace": AgentExecutionTrace,
    "tool-invocation-log": ToolInvocationLog,
    "replay-verification": ReplayVerification,
    "contract-gate-result": ContractGateResult,
    "eval-dataset-result": EvalDatasetResult,
    "human-oversight-event": HumanOversightEvent,
    "incident-monitoring-event": IncidentMonitoringEvent,
    "data-quality-check": DataQualityCheck,
    "model-provider-compatibility": ModelProviderCompatibility,
    "rag-retrieval-diagnostics": RagRetrievalDiagnostics,
}


def get_dataclass(namespace: str) -> type:
    """Return the dataclass class bound to a hyphenated namespace name.

    Raises:
        KeyError: if ``namespace`` is not one of the ten declared.
    """
    if namespace not in _NAMESPACE_TO_CLASS:
        raise KeyError(
            f"unknown x-relay namespace: {namespace!r}; expected one of "
            f"{sorted(_NAMESPACE_TO_CLASS)!r}"
        )
    return _NAMESPACE_TO_CLASS[namespace]


def all_dataclasses() -> dict[str, type]:
    """Return a copy of the namespace-to-dataclass mapping."""
    return dict(_NAMESPACE_TO_CLASS)


__all__ = [
    "AgentExecutionTrace",
    "ContractGateResult",
    "DataQualityCheck",
    "EvalDatasetResult",
    "HumanOversightEvent",
    "IncidentMonitoringEvent",
    "ModelProviderCompatibility",
    "RagRetrievalDiagnostics",
    "ReplayVerification",
    "ToolInvocationLog",
    "all_dataclasses",
    "get_dataclass",
]
