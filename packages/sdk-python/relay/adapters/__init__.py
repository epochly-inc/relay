"""Relay adapter package (W3.5).

The adapter layer wraps provider SDKs (OpenAI, Anthropic, ...) so every
model call and embedded tool call is captured as a Relay :class:`Span`
on a :class:`SpanRecorder`. Adapters are duck-typed: they NEVER import
the provider package at module load, so installing the Apache-2.0 OSS
Relay SDK does not pull commercial provider SDKs as transitive
dependencies.

Public surface:

  * :func:`wrap_openai`     -- wrap an ``openai.OpenAI`` client.
  * :func:`wrap_anthropic`  -- wrap an ``anthropic.Anthropic`` client.
  * :func:`register_tool`   -- wrap a tool function so a
                               ``side_effect=True`` declaration emits
                               pre-action + post-success markers
                               (spec X / VAL-W3-047).
  * :func:`normalize_error` -- map a provider exception class to a
                               stable normalized Relay code
                               (VAL-W3-046).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from ._side_effects import (
    NonDeterministicIdempotencyKey,
    SideEffectEvent,
    SideEffectMarkerMissing,
    SideEffectRecorder,
    register_tool,
    validate_pairing,
)
from ._spans import Span, SpanRecorder
from .anthropic_adapter import wrap_anthropic
from .errors import (
    MODEL_CONTEXT_OVERFLOW,
    MODEL_RATE_LIMIT,
    MODEL_TIMEOUT,
    MODEL_UNKNOWN,
    TOOL_BAD_ARGUMENTS,
    NormalizedError,
    normalize_error,
)
from .openai_adapter import wrap_openai

__all__ = [
    "MODEL_CONTEXT_OVERFLOW",
    "MODEL_RATE_LIMIT",
    "MODEL_TIMEOUT",
    "MODEL_UNKNOWN",
    "NonDeterministicIdempotencyKey",
    "NormalizedError",
    "SideEffectEvent",
    "SideEffectMarkerMissing",
    "SideEffectRecorder",
    "Span",
    "SpanRecorder",
    "TOOL_BAD_ARGUMENTS",
    "normalize_error",
    "register_tool",
    "validate_pairing",
    "wrap_anthropic",
    "wrap_openai",
]
