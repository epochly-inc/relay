"""Adapter span recorder primitives (W3.5).

Adapters (OpenAI, Anthropic, ...) emit spans into a :class:`SpanRecorder`.
The recorder is the SDK-side staging buffer that the W3.2 lifecycle
ingest surface (``Run.capture``) consumes; it is NOT a canonical write
path -- canonical results are written by the control plane only
(CLAUDE.md keystone invariant #1).

A :class:`Span` carries:

  * ``span_id`` -- a fresh ULID per span.
  * ``kind``    -- one of ``"model_call"``, ``"tool_call"``,
                   ``"stream_chunk"``.
  * ``attributes`` -- the per-span attribute dict (provider/model/tokens
                   for ``model_call``; tool_name/args/result for
                   ``tool_call``; chunk_sequence/event_type for
                   ``stream_chunk``).

The recorder is in-memory only. The transport layer (relay.run) is the
component that ships these spans to the sidecar; the adapter does not
make HTTP calls itself.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from relay._ulid import new_ulid


@dataclass
class Span:
    """A single span emitted by an adapter.

    Attributes:
        span_id: A fresh ULID identifying this span; used as the
            ``parent_span_id`` reference for any child span.
        kind: One of ``"model_call"``, ``"tool_call"``, ``"stream_chunk"``.
        attributes: Span-kind-specific payload (free-form dict).
    """

    span_id: str
    kind: str
    attributes: dict[str, Any] = field(default_factory=dict)


class SpanRecorder:
    """In-memory list of spans produced by an adapter.

    Adapters call :meth:`new_span` to mint a fresh ULID-identified
    :class:`Span`, populate its attributes, and the recorder appends it.

    Thread-safe: a single recorder may be passed to multiple adapter
    invocations and concurrent ``record`` calls are serialised by an
    internal lock so the resulting list is consistent.
    """

    def __init__(self) -> None:
        self._spans: list[Span] = []
        self._lock = threading.Lock()

    def new_span(self, kind: str, **attributes: Any) -> Span:
        """Mint and append a fresh span. Returns the Span for further mutation."""
        if kind not in {"model_call", "tool_call", "stream_chunk"}:
            raise ValueError(f"unknown span kind: {kind!r}")
        span = Span(span_id=new_ulid(), kind=kind, attributes=dict(attributes))
        with self._lock:
            self._spans.append(span)
        return span

    @property
    def spans(self) -> list[Span]:
        """A snapshot copy of recorded spans, in insertion order."""
        with self._lock:
            return list(self._spans)

    def clear(self) -> None:
        with self._lock:
            self._spans.clear()


__all__ = ["Span", "SpanRecorder"]
