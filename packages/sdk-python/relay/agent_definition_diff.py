"""Agent Definition Diff (spec section AM.2, lines 5818-5874).

Implements the SRP-SP P4 regression-explainability primitive adapted to
Relay's stateless production agents. Per spec AM.2 there is **no new
storage**: every input is sourced from existing primitives (prompt
versions, model call spans, manifest versions, retrieval spans, tool
call spans, redaction policies, assertion definitions). This module
exposes a pure, deterministic function that takes two snapshot dicts
(one per ``release_sha``) and returns a structured per-component diff.

Public API:

  - :class:`AgentDefinitionDiff` - the top-level dataclass.
  - :class:`ComponentDiff` - one entry per diffed component
    (prompt, model_config, manifest, retrieval, tools, redaction,
    contracts).
  - :func:`agent_definition_diff` - computes the diff from two snapshots.
  - :func:`canonicalize_diff` - JSON-canonical serializer used by
    determinism tests and (eventually) signed-diff evidence.

Determinism guarantees (load-bearing for VAL-V2M08-034):

  * No wall-clock timestamps, ``time.time()``, ``datetime.now()``, or
    random sources are read.
  * ``canonicalize_diff`` sorts every dict key and uses a stable list
    encoding (RFC 8785-style ``json.dumps(sort_keys=True,
    separators=(',', ':'))``).
  * Component fields preserve a fixed declaration order so two calls
    against unchanged inputs return byte-identical bytes.

Unobserved-from semantics (VAL-V2M08-035):

  * When ``from_snapshot is None``, every component reports
    ``from_digest=None``, ``changed=True``, and a human-readable
    ``summary`` of the form ``"first observed at <to_release_sha>"``.
  * The call MUST NOT raise on unobserved-from input.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Final

# Canonical component name order. Must remain stable across releases;
# changing the order is a contract-breaking change because consumers
# (Explain timeline, signed diff evidence) hash the canonical bytes.
COMPONENT_ORDER: Final[tuple[str, ...]] = (
    "prompt",
    "model_config",
    "manifest",
    "retrieval",
    "tools",
    "redaction",
    "contracts",
)


@dataclass(frozen=True)
class ComponentDiff:
    """One diffed component of the agent definition.

    Fields:

      * ``component`` - one of :data:`COMPONENT_ORDER`.
      * ``changed`` - True iff ``from_digest != to_digest``.
      * ``from_digest`` - the digest of the component in
        ``from_snapshot`` (None when unobserved).
      * ``to_digest`` - the digest of the component in ``to_snapshot``.
      * ``summary`` - human-readable single-line summary used by the
        Explain timeline. Never carries random or wall-clock fields.
    """

    component: str
    changed: bool
    from_digest: str | None
    to_digest: str | None
    summary: str


@dataclass(frozen=True)
class AgentDefinitionDiff:
    """Structured diff returned by :func:`agent_definition_diff`.

    Top-level fields preserve the spec AM.2 component order verbatim.
    The ``agent_id``, ``from_release_sha``, and ``to_release_sha`` fields
    are echoed back to the caller so downstream consumers (Explain
    timeline, signed-diff evidence) can confirm which snapshot pair the
    diff was computed against without a separate lookup.
    """

    agent_id: str
    from_release_sha: str
    to_release_sha: str
    prompt: ComponentDiff
    model_config: ComponentDiff
    manifest: ComponentDiff
    retrieval: ComponentDiff
    tools: ComponentDiff
    redaction: ComponentDiff
    contracts: ComponentDiff
    # Aggregate flag: True iff at least one component changed. Convenience
    # for callers that only need the boolean ("did anything drift?").
    any_changed: bool = field(default=False)


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _canonical_bytes(value: Any) -> bytes:
    """RFC 8785-style canonical JSON bytes for a Python value.

    Used for digesting component sub-views into a stable per-snapshot
    hash. Sorted keys + tight separators ensure deterministic output.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    """SHA-256 digest of the canonical bytes of ``value``.

    None is the canonical sentinel for "absent / unobserved" and is
    handled by the caller (returns digest ``None``, not a sha256 of the
    JSON literal ``null``).
    """
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _component_view(snapshot: dict[str, Any] | None, component: str) -> Any:
    """Project the per-component sub-view from a snapshot dict.

    Returns the exact subtree the diff component digests. Centralized so
    the projection rule is identical for ``from`` and ``to`` snapshots.
    Returns None when the snapshot itself is None (unobserved).
    """
    if snapshot is None:
        return None
    if component == "prompt":
        return {
            "prompt_hash": snapshot.get("prompt_hash"),
            "template_hash": snapshot.get("template_hash"),
        }
    if component == "model_config":
        return {
            "model": snapshot.get("model"),
            "model_signature": snapshot.get("model_signature"),
            "provider": snapshot.get("provider"),
        }
    if component == "manifest":
        return {"manifest_commit_hash": snapshot.get("manifest_commit_hash")}
    if component == "retrieval":
        # The retrieval sub-view may itself be None when the agent does
        # not use retrieval. We preserve that fidelity in the digest.
        return snapshot.get("retrieval")
    if component == "tools":
        # Sort tool list for digest stability; the order in which the
        # caller registered tools is not load-bearing for definition
        # identity.
        tools = snapshot.get("tools") or []
        return sorted(tools) if isinstance(tools, list) else tools
    if component == "redaction":
        return {"policy_version": snapshot.get("redaction_policy_version")}
    if component == "contracts":
        # Sort assertion definitions by id so reorder doesn't surface as
        # drift. Each entry's full content remains digested.
        defs = snapshot.get("assertion_definitions") or []
        if isinstance(defs, list):
            return sorted(
                (d for d in defs if isinstance(d, dict)),
                key=lambda d: d.get("id", ""),
            )
        return defs
    raise ValueError(f"unknown agent-definition component: {component!r}")


def _summary(
    component: str,
    from_view: Any,
    to_view: Any,
    *,
    from_release_sha: str,
    to_release_sha: str,
    unobserved_from: bool,
) -> str:
    """Single-line summary for the Explain timeline.

    Deterministic: never reads wall clock; never references the current
    process id; never includes a random nonce. The exact phrasing
    ``"first observed at <to_release_sha>"`` is contract-bound by
    VAL-V2M08-035.
    """
    if unobserved_from:
        return (
            f"component {component}: first observed at {to_release_sha} "
            f"(no record in {from_release_sha})"
        )
    if from_view == to_view:
        return f"component {component}: unchanged between {from_release_sha} and {to_release_sha}"
    return (
        f"component {component}: changed between {from_release_sha} and "
        f"{to_release_sha}"
    )


def _diff_component(
    component: str,
    from_snapshot: dict[str, Any] | None,
    to_snapshot: dict[str, Any],
    *,
    from_release_sha: str,
    to_release_sha: str,
) -> ComponentDiff:
    """Diff one named component between two snapshots.

    When ``from_snapshot is None`` the component is reported as
    ``from_digest=None`` (unobserved). The ``changed`` flag is True in
    that case because every value is "new" relative to no prior record.
    """
    unobserved_from = from_snapshot is None
    from_view = _component_view(from_snapshot, component)
    to_view = _component_view(to_snapshot, component)
    from_digest = None if unobserved_from else _digest(from_view)
    to_digest = _digest(to_view)
    changed = unobserved_from or (from_digest != to_digest)
    summary = _summary(
        component,
        from_view,
        to_view,
        from_release_sha=from_release_sha,
        to_release_sha=to_release_sha,
        unobserved_from=unobserved_from,
    )
    return ComponentDiff(
        component=component,
        changed=changed,
        from_digest=from_digest,
        to_digest=to_digest,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def agent_definition_diff(
    *,
    agent_id: str,
    from_release_sha: str,
    to_release_sha: str,
    from_snapshot: dict[str, Any] | None,
    to_snapshot: dict[str, Any],
) -> AgentDefinitionDiff:
    """Return a structured diff of every component of an agent definition.

    Args:
        agent_id: stable agent identifier (echoed into the result).
        from_release_sha: the older release_sha being compared from.
        to_release_sha: the newer release_sha being compared to.
        from_snapshot: per-component snapshot dict at ``from_release_sha``;
            None when the agent has no record at that release (handled by
            VAL-V2M08-035 - returns per-component from_digest=None).
        to_snapshot: per-component snapshot dict at ``to_release_sha``.
            Required (cannot be None; the diff has nothing to compare to).

    Returns:
        :class:`AgentDefinitionDiff` with per-component diffs in spec
        AM.2 order.

    Raises:
        TypeError: when ``to_snapshot`` is None.
        ValueError: when an unknown component name is requested by
            internal projection (should never happen for callers using
            the public API; defensive only).
    """
    if to_snapshot is None:
        raise TypeError("agent_definition_diff: to_snapshot must not be None")
    components: dict[str, ComponentDiff] = {}
    for component in COMPONENT_ORDER:
        components[component] = _diff_component(
            component,
            from_snapshot,
            to_snapshot,
            from_release_sha=from_release_sha,
            to_release_sha=to_release_sha,
        )
    any_changed = any(c.changed for c in components.values())
    return AgentDefinitionDiff(
        agent_id=agent_id,
        from_release_sha=from_release_sha,
        to_release_sha=to_release_sha,
        prompt=components["prompt"],
        model_config=components["model_config"],
        manifest=components["manifest"],
        retrieval=components["retrieval"],
        tools=components["tools"],
        redaction=components["redaction"],
        contracts=components["contracts"],
        any_changed=any_changed,
    )


def canonicalize_diff(diff: AgentDefinitionDiff) -> bytes:
    """Return RFC 8785-style canonical JSON bytes for ``diff``.

    Used by determinism tests (VAL-V2M08-034) and by future
    signed-diff evidence emission. The serialization is sorted-key,
    tight-separator, ASCII-only.
    """
    payload = asdict(diff)
    return _canonical_bytes(payload)


__all__ = [
    "AgentDefinitionDiff",
    "COMPONENT_ORDER",
    "ComponentDiff",
    "agent_definition_diff",
    "canonicalize_diff",
]
