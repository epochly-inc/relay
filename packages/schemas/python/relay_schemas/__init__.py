"""Relay canonical control-plane schemas.

This package exposes generated Pydantic v2 models for every canonical
control-plane envelope (run_results, gate_decisions, gate_decision_drafts,
gate_rounds, etc.). Schemas are generated from canonical YAML definitions
under ``packages/schemas/raw/`` as the single source of truth.

Per CLAUDE.md keystone invariant #1, the control plane writes the canonical
result; the model literal pins on ``written_by``/``decided_by`` enforce that
invariant at the wire-format layer in addition to the SQL CHECK constraints.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

__all__ = ["envelopes"]

from . import envelopes  # noqa: F401  (re-export for `from relay_schemas import envelopes`)
