"""Anthropic adapter (W3.5).

Wraps an Anthropic Python SDK client (``anthropic.Anthropic`` instance)
so every ``client.messages.create(...)`` invocation emits Relay spans
describing the model call, embedded tool_use blocks, and (for streaming)
ordered chunk children.

Like :mod:`.openai_adapter` the adapter is duck-typed; it never imports
the ``anthropic`` package at module load. Apache 2.0 install of relay
does NOT pull commercial provider SDKs.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from typing import Any

from ..redaction import _canonical_json_stringify
from ._spans import Span, SpanRecorder
from .openai_adapter import _scrub  # reuse the same secret-scrubber

_ANTHROPIC_PROVIDER: str = "anthropic"

# Per-million pricing (USD per 1M tokens). Best-effort estimate.
_ANTHROPIC_PRICE_TABLE: dict[str, tuple[float, float]] = {
    "claude-opus-4-7": (15.00, 75.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-3-7-sonnet": (3.00, 15.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-5-haiku": (0.80, 4.00),
}


def _safe_anthropic_sdk_version() -> str:
    try:
        import importlib

        mod = importlib.import_module("anthropic")
        ver = getattr(mod, "__version__", None)
        if isinstance(ver, str) and ver:
            return f"anthropic@{ver}"
    except (ImportError, AttributeError, ValueError):
        pass
    return "anthropic@unknown"


def _model_signature(model: str, response_id: str | None = None) -> str:
    """``anthropic:<model>:<response.id-or-sha256(model)[:16]>`` (VAL-W4-033).

    Anthropic does not expose a ``system_fingerprint``; per the spec gap note
    the provider ``response.id`` is the drift surrogate. Byte-identical to the
    TS Anthropic adapter (``modelSignature``) and to the OpenAI sibling's
    ``provider:model:<discriminator-or-sha256(model)[:16]>`` form: the third
    segment is the response id when present, else a SHA-256 prefix of the model
    so the signature stays deterministic + drift-detectable. The caller also
    surfaces the id as its own ``response_id`` span attribute. Mirrors the TS
    guard (``responseId !== null && responseId !== ""``): an empty/absent id
    falls back to the hash.
    """
    if response_id:
        return f"{_ANTHROPIC_PROVIDER}:{model}:{response_id}"
    fallback = hashlib.sha256(model.encode("utf-8")).hexdigest()[:16]
    return f"{_ANTHROPIC_PROVIDER}:{model}:{fallback}"


def _estimate_cost_usd(
    model: str, input_tokens: int, output_tokens: int
) -> float:
    price = _ANTHROPIC_PRICE_TABLE.get(model)
    if price is None:
        return 0.0
    input_per_m, output_per_m = price
    return round(
        (input_tokens / 1_000_000.0) * input_per_m
        + (output_tokens / 1_000_000.0) * output_per_m,
        6,
    )


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _redact_tool_input(value: Any) -> tuple[Any, str]:
    """Redact Anthropic tool input and compute its args_hash.

    Serialises through the shared JCS canonicalizer (RFC 8785) so the bytes
    are byte-identical to the TypeScript adapter's ``canonicalStringify``
    (compact separators, ensure_ascii=False), keeping the Py/TS args_hash in
    lockstep (sdk-python-run-005). The prior
    ``json.dumps(..., sort_keys=True, default=str)`` diverged from TS on
    separators + non-ASCII escaping and silently coerced unsupported types.
    """
    redacted = _scrub(value)
    canon = _canonical_json_stringify(redacted).encode("utf-8")
    return redacted, hashlib.sha256(canon).hexdigest()


# ---------------------------------------------------------------------------
# Public wrapper
# ---------------------------------------------------------------------------


class _WrappedMessages:
    def __init__(
        self, inner: Any, recorder: SpanRecorder, sdk_version: str
    ) -> None:
        self._inner = inner
        self._recorder = recorder
        self._sdk_version = sdk_version

    def create(self, *args: Any, **kwargs: Any) -> Any:
        is_stream = bool(kwargs.get("stream", False))
        model = kwargs.get("model", "")
        parent = self._recorder.new_span(
            "model_call",
            provider=_ANTHROPIC_PROVIDER,
            model=model,
            sdk_version=self._sdk_version,
            input_tokens=0,
            output_tokens=0,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
            total_cost_usd=0.0,
            model_signature=_model_signature(model),
        )
        start_t = time.monotonic()

        if is_stream:
            iterator = self._inner.create(*args, **kwargs)
            return _StreamWrapper(iterator, self._recorder, parent, start_t, model)

        result = self._inner.create(*args, **kwargs)
        duration_ms = (time.monotonic() - start_t) * 1000.0
        _populate_parent_from_response(parent, result)
        parent.attributes["duration_ms"] = duration_ms
        _emit_tool_use_spans_from_response(self._recorder, parent, result)
        return result


class _WrappedAnthropicClient:
    def __init__(
        self, inner: Any, recorder: SpanRecorder, sdk_version: str
    ) -> None:
        self._inner = inner
        self._recorder = recorder
        self._sdk_version = sdk_version
        self.messages = _WrappedMessages(inner.messages, recorder, sdk_version)

    @property
    def recorder(self) -> SpanRecorder:
        return self._recorder

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def wrap_anthropic(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedAnthropicClient:
    """Wrap an Anthropic client so every call records Relay spans."""
    if recorder is None:
        recorder = SpanRecorder()
    if sdk_version is None:
        sdk_version = _safe_anthropic_sdk_version()
    return _WrappedAnthropicClient(client, recorder, sdk_version)


# ---------------------------------------------------------------------------
# Response -> span population
# ---------------------------------------------------------------------------


def _populate_parent_from_response(parent: Span, response: Any) -> None:
    model = _get(response, "model", parent.attributes.get("model", ""))
    usage = _get(response, "usage")
    input_tokens = int(_get(usage, "input_tokens", 0) or 0)
    output_tokens = int(_get(usage, "output_tokens", 0) or 0)
    cache_creation = int(_get(usage, "cache_creation_input_tokens", 0) or 0)
    cache_read = int(_get(usage, "cache_read_input_tokens", 0) or 0)
    parent.attributes["model"] = model
    parent.attributes["input_tokens"] = input_tokens
    parent.attributes["output_tokens"] = output_tokens
    parent.attributes["cache_creation_input_tokens"] = cache_creation
    parent.attributes["cache_read_input_tokens"] = cache_read
    parent.attributes["total_cost_usd"] = _estimate_cost_usd(
        model, input_tokens, output_tokens
    )
    # response.id seeds the model_signature drift surrogate + its own attribute,
    # mirroring the TS adapter (asString(response.id, "") || null). A non-string
    # or empty id collapses to None so the signature uses the sha256 fallback.
    _rid = _get(response, "id", "")
    response_id = _rid if isinstance(_rid, str) and _rid else None
    parent.attributes["model_signature"] = _model_signature(model, response_id)
    parent.attributes["response_id"] = response_id
    parent.attributes["stop_reason"] = _get(response, "stop_reason")


def _emit_tool_use_spans_from_response(
    recorder: SpanRecorder, parent: Span, response: Any
) -> None:
    content = _get(response, "content") or []
    for block in content:
        btype = _get(block, "type")
        if btype != "tool_use":
            continue
        tool_name = _get(block, "name", "")
        tool_input = _get(block, "input", {})
        args_red, args_hash = _redact_tool_input(tool_input)
        recorder.new_span(
            "tool_call",
            tool_name=str(tool_name),
            parent_span_id=parent.span_id,
            args_redacted=args_red,
            args_hash=args_hash,
            result_hash="",
            status="pending",
            duration_ms=0.0,
            retry_count=0,
            side_effect_marker=False,
            normalized_error_class=None,
        )


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


_STREAM_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
        "ping",
    }
)


class _StreamWrapper:
    def __init__(
        self,
        inner: Iterator[Any],
        recorder: SpanRecorder,
        parent: Span,
        start_t: float,
        model: str,
    ) -> None:
        self._inner = iter(inner)
        self._recorder = recorder
        self._parent = parent
        self._sequence = 0
        self._start_t = start_t
        self._model = model
        self._cum_input = 0
        self._cum_output = 0
        self._chunk_count = 0
        self._stop_reason: str | None = None
        # Captured from message_start (event.message.id); seeds the finalized
        # model_signature + response_id attribute, mirroring the TS finalizeStream.
        self._response_id: str | None = None
        # Streamed tool_use blocks arrive as a content_block_start (carrying the
        # tool name) followed by input_json_delta fragments (carrying the args
        # JSON in pieces). Aggregate per block index, mirroring the TS adapter's
        # toolUsesByIndex, and emit one tool_call span per block on finalize.
        self._tool_uses: dict[int, dict[str, Any]] = {}

    def __iter__(self) -> _StreamWrapper:
        return self

    def __next__(self) -> Any:
        try:
            event = next(self._inner)
        except StopIteration:
            duration_ms = (time.monotonic() - self._start_t) * 1000.0
            self._parent.attributes["duration_ms"] = duration_ms
            # Surface the resolved streamed model (TS finalizeStream sets
            # parent.attributes["model"] = state.model) so model + model_signature
            # agree with the non-stream path and the TS adapter.
            self._parent.attributes["model"] = self._model
            self._parent.attributes["input_tokens"] = self._cum_input
            self._parent.attributes["output_tokens"] = self._cum_output
            self._parent.attributes["total_cost_usd"] = _estimate_cost_usd(
                self._model, self._cum_input, self._cum_output
            )
            # Re-compute model_signature with the captured response id (TS
            # finalizeStream: modelSignature(model, state.responseId)) and surface
            # response_id, so a fixture/cassette recorded under either SDK carries
            # byte-identical span attributes.
            self._parent.attributes["model_signature"] = _model_signature(
                self._model, self._response_id
            )
            self._parent.attributes["response_id"] = self._response_id
            self._parent.attributes["chunk_count"] = self._chunk_count
            self._parent.attributes["stop_reason"] = self._stop_reason
            # Emit ONE tool_call span per aggregated streamed tool_use block
            # (VAL-W4-039), mirroring the TS finalizeStream. The args JSON was
            # streamed in input_json_delta fragments; parse the concatenation,
            # falling back to the raw string on a parse error and to the initial
            # block input when no fragments arrived.
            for agg in self._tool_uses.values():
                partial = agg.get("partial_json", "")
                parsed_input: Any = agg.get("input", {})
                if partial:
                    try:
                        parsed_input = json.loads(partial)
                    except (ValueError, TypeError):
                        parsed_input = partial
                args_red, args_hash = _redact_tool_input(parsed_input)
                self._recorder.new_span(
                    "tool_call",
                    tool_name=str(agg.get("name", "")),
                    parent_span_id=self._parent.span_id,
                    args_redacted=args_red,
                    args_hash=args_hash,
                    result_hash="",
                    status="pending",
                    duration_ms=0.0,
                    retry_count=0,
                    side_effect_marker=False,
                    normalized_error_class=None,
                )
            raise

        self._chunk_count += 1
        event_type = _get(event, "type", "")
        if not isinstance(event_type, str):
            event_type = ""

        # Usage aggregation MUST mirror the TypeScript adapter's
        # ``ingestEvent`` (VAL-ISO-020) exactly so Py/TS report identical
        # token counts. Anthropic's streaming usage is NOT a running sum:
        #
        #   * ``message_start`` carries usage on ``event.message.usage`` (the
        #     authoritative input token count plus a small initial output
        #     SEED). We read input from there and ASSIGN the output seed.
        #   * ``message_delta`` carries usage on ``event.usage`` whose
        #     ``output_tokens`` is the authoritative CUMULATIVE final output
        #     count, not a per-event increment. We ASSIGN it (never ``+=``)
        #     so the running total is not double-counted with the seed.
        #
        # Summing every event (the prior behaviour) inflated output and never
        # populated input (it read ``event.usage`` only, which is absent on
        # ``message_start``). Assigning cumulative snapshots is correct.
        if event_type == "message_start":
            message = _get(event, "message")
            # Capture the provider message id for the finalized model_signature
            # (TS: if (id !== "") state.responseId = id). Empty/non-string ids
            # leave the seed None so finalize uses the sha256 fallback.
            _mid = _get(message, "id", "")
            if isinstance(_mid, str) and _mid:
                self._response_id = _mid
            # Refresh the model from the streamed provider model so the finalized
            # model + model_signature reflect the RESOLVED model, not the request
            # arg (TS: if (model !== "") state.model = model). A resolved model
            # name or an empty request model would otherwise diverge from TS.
            _smodel = _get(message, "model", "")
            if isinstance(_smodel, str) and _smodel:
                self._model = _smodel
            usage = _get(message, "usage")
            if usage is not None:
                in_tok = _get(usage, "input_tokens")
                out_tok = _get(usage, "output_tokens")
                if isinstance(in_tok, int):
                    self._cum_input += in_tok
                if isinstance(out_tok, int):
                    self._cum_output = out_tok
        elif event_type == "content_block_start":
            block = _get(event, "content_block")
            if _get(block, "type") == "tool_use":
                idx = _get(event, "index", -1)
                if isinstance(idx, int) and idx >= 0:
                    self._tool_uses[idx] = {
                        "name": _get(block, "name", ""),
                        "partial_json": "",
                        "input": _get(block, "input", {}),
                    }
        elif event_type == "content_block_delta":
            idx = _get(event, "index", -1)
            if isinstance(idx, int) and idx >= 0:
                delta = _get(event, "delta")
                if _get(delta, "type") == "input_json_delta":
                    partial = _get(delta, "partial_json", "")
                    existing = self._tool_uses.get(idx)
                    if existing is not None and isinstance(partial, str):
                        existing["partial_json"] += partial
        elif event_type == "message_delta":
            usage = _get(event, "usage")
            if usage is not None:
                out_tok = _get(usage, "output_tokens")
                if isinstance(out_tok, int):
                    self._cum_output = out_tok
                # Only update input from a delta if it actually carries one;
                # never clobber the message_start seed to 0.
                in_tok = _get(usage, "input_tokens")
                if isinstance(in_tok, int) and in_tok != 0:
                    self._cum_input = in_tok
            delta = _get(event, "delta")
            stop_reason = _get(delta, "stop_reason")
            if isinstance(stop_reason, str) and stop_reason:
                self._stop_reason = stop_reason

        self._recorder.new_span(
            "stream_chunk",
            parent_span_id=self._parent.span_id,
            chunk_sequence=self._sequence,
            event_type=event_type,
        )
        self._sequence += 1
        return event


__all__ = ["wrap_anthropic"]
