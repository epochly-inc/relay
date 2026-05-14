"""OpenAI adapter (W3.5).

Wraps an OpenAI Python SDK client (``openai.OpenAI`` instance) so every
``client.chat.completions.create(...)`` invocation emits Relay spans
describing the model call, embedded tool calls, and (for streaming)
ordered chunk children.

The adapter is duck-typed: it never imports the ``openai`` package at
module-load time, so installing the relay OSS SDK does NOT pull
``openai`` (Apache 2.0 OSS install does not depend on commercial SDKs).
Callers pass any object whose ``client.chat.completions.create``
honours the OpenAI SDK shape.

Per CLAUDE.md keystone invariant #1 the adapter NEVER writes canonical
results -- it accumulates spans into a :class:`SpanRecorder` for the
W3.2 lifecycle ingest surface to ship to the sidecar.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from typing import Any

from ._spans import Span, SpanRecorder

# Sentinel: when system_fingerprint is None, we still emit a deterministic
# model_signature so the refresh policy can detect drift (VAL-W3-039
# fallback). Encoded as openai:<model>:sha256(<model>)[:16].
_OPENAI_PROVIDER: str = "openai"

# Per-million pricing for cost estimation (USD per 1M tokens). The hosted
# control plane is the authoritative cost source; SDK-side cost is a
# best-effort estimate so the span carries SOMETHING non-zero for the
# common models. Unknown models price at 0.0 (caller can override).
_OPENAI_PRICE_TABLE: dict[str, tuple[float, float]] = {
    "gpt-4o-2024-08-06": (2.50, 10.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
}


def _safe_openai_sdk_version() -> str:
    """Best-effort version detection for the host openai package.

    The adapter is duck-typed, so the ``openai`` package may or may not
    be installed. We import lazily inside a try/except so missing
    installs do NOT crash the wrapper.
    """
    try:
        import importlib

        mod = importlib.import_module("openai")
        ver = getattr(mod, "__version__", None)
        if isinstance(ver, str) and ver:
            return f"openai@{ver}"
    except (ImportError, AttributeError, ValueError):
        pass
    return "openai@unknown"


def _model_signature(model: str, system_fingerprint: str | None) -> str:
    """Build the model_signature per VAL-W3-039.

    Always returns ``openai:<model>:<token>`` where token is the
    provider's system_fingerprint when present, else a SHA-256 prefix
    of the model name so the signature is still drift-detectable.
    """
    if system_fingerprint:
        return f"{_OPENAI_PROVIDER}:{model}:{system_fingerprint}"
    fallback = hashlib.sha256(model.encode("utf-8")).hexdigest()[:16]
    return f"{_OPENAI_PROVIDER}:{model}:{fallback}"


def _estimate_cost_usd(
    model: str, input_tokens: int, output_tokens: int
) -> float:
    """Cheap per-token cost estimate for the well-known OpenAI models."""
    price = _OPENAI_PRICE_TABLE.get(model)
    if price is None:
        return 0.0
    input_per_m, output_per_m = price
    return round(
        (input_tokens / 1_000_000.0) * input_per_m
        + (output_tokens / 1_000_000.0) * output_per_m,
        6,
    )


# ---------------------------------------------------------------------------
# Helpers for shallow attribute extraction (duck typing).
# ---------------------------------------------------------------------------


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """``getattr(obj, key)`` or ``obj[key]``, whichever is supported."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _redact_tool_arguments(raw: str) -> tuple[Any, str]:
    """Redact a tool-call argument blob and compute its args_hash.

    ``raw`` is the provider's tool-call arguments string (OpenAI emits a
    JSON-encoded string per the Chat Completions tool-use shape). We
    parse + run through a minimal field-redactor for API-key-shaped
    values, then SHA-256 the canonical bytes.

    The full redaction policy is owned by :mod:`relay.redaction`; this
    helper performs the conservative "scrub anything that looks like a
    secret" pass at the adapter boundary so the args never leak into a
    span attribute even when the run-level redaction engine has not been
    configured.
    """
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        parsed = raw
    redacted = _scrub(parsed)
    canon = json.dumps(redacted, sort_keys=True, default=str).encode("utf-8")
    return redacted, hashlib.sha256(canon).hexdigest()


_SECRET_KEY_HINTS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "token",
        "password",
        "passphrase",
        "ssn",
        "credit_card",
    }
)


def _scrub(value: Any) -> Any:
    """Recursively replace secret-looking strings with ``"[REDACTED]"``."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            lk = str(k).lower()
            if lk in _SECRET_KEY_HINTS:
                out[k] = "[REDACTED]"
            else:
                out[k] = _scrub(v)
        return out
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, str) and (
        value.startswith("sk-") or value.startswith("sk-ant-")
    ):
        # Best-effort: OpenAI 'sk-' prefix, Anthropic 'sk-ant-' prefix.
        return "[REDACTED]"
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class _WrappedCompletions:
    """Replacement for ``client.chat.completions`` that records spans."""

    def __init__(
        self,
        inner: Any,
        recorder: SpanRecorder,
        sdk_version: str,
    ) -> None:
        self._inner = inner
        self._recorder = recorder
        self._sdk_version = sdk_version

    def create(self, *args: Any, **kwargs: Any) -> Any:
        # Determine streaming up front so we can intercept the iterator.
        is_stream = bool(kwargs.get("stream", False))
        # Construct the parent span BEFORE invoking the provider so any
        # exception during invocation can still attribute itself to a
        # known span_id via normalize_error context.
        model_in_kwargs = kwargs.get("model", "")
        parent = self._recorder.new_span(
            "model_call",
            provider=_OPENAI_PROVIDER,
            model=model_in_kwargs,
            sdk_version=self._sdk_version,
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            total_cost_usd=0.0,
            model_signature=_model_signature(model_in_kwargs, None),
        )
        start_t = time.monotonic()

        if is_stream:
            iterator = self._inner.create(*args, **kwargs)
            return _StreamWrapper(iterator, self._recorder, parent, start_t)

        result = self._inner.create(*args, **kwargs)
        duration_ms = (time.monotonic() - start_t) * 1000.0
        _populate_parent_from_response(parent, result)
        parent.attributes["duration_ms"] = duration_ms
        _emit_tool_call_spans_from_response(self._recorder, parent, result)
        return result


class _WrappedChat:
    def __init__(self, inner: Any, recorder: SpanRecorder, sdk_version: str) -> None:
        self.completions = _WrappedCompletions(
            inner.completions, recorder, sdk_version
        )


class _WrappedOpenAIClient:
    """Wrapper exposing the same ``.chat.completions`` surface as openai.OpenAI."""

    def __init__(
        self,
        inner: Any,
        recorder: SpanRecorder,
        sdk_version: str,
    ) -> None:
        self._inner = inner
        self._recorder = recorder
        self._sdk_version = sdk_version
        self.chat = _WrappedChat(inner.chat, recorder, sdk_version)

    @property
    def recorder(self) -> SpanRecorder:
        return self._recorder

    def __getattr__(self, name: str) -> Any:
        # Forward any other attribute lookups to the underlying client.
        return getattr(self._inner, name)


def wrap_openai(
    client: Any,
    *,
    recorder: SpanRecorder | None = None,
    sdk_version: str | None = None,
) -> _WrappedOpenAIClient:
    """Wrap an OpenAI client so every call records Relay spans.

    Args:
        client: An object exposing ``.chat.completions.create(**kwargs)``.
            In production this is an ``openai.OpenAI`` instance; tests
            pass any duck-typed stand-in.
        recorder: Optional :class:`SpanRecorder` to record into. When
            ``None`` a fresh recorder is created and made available via
            ``wrapper.recorder``.
        sdk_version: Override the auto-detected SDK version string.

    Returns:
        A wrapped client mirroring the OpenAI client surface.
    """
    if recorder is None:
        recorder = SpanRecorder()
    if sdk_version is None:
        sdk_version = _safe_openai_sdk_version()
    return _WrappedOpenAIClient(client, recorder, sdk_version)


# ---------------------------------------------------------------------------
# Response -> span population
# ---------------------------------------------------------------------------


def _populate_parent_from_response(parent: Span, response: Any) -> None:
    """Fill the model_call parent span from a non-stream OpenAI response."""
    model = _get(response, "model", parent.attributes.get("model", ""))
    fingerprint = _get(response, "system_fingerprint")
    usage = _get(response, "usage")
    input_tokens = int(_get(usage, "prompt_tokens", 0) or 0)
    output_tokens = int(_get(usage, "completion_tokens", 0) or 0)
    total_tokens = int(_get(usage, "total_tokens", input_tokens + output_tokens) or 0)
    parent.attributes["model"] = model
    parent.attributes["input_tokens"] = input_tokens
    parent.attributes["output_tokens"] = output_tokens
    parent.attributes["total_tokens"] = total_tokens
    parent.attributes["total_cost_usd"] = _estimate_cost_usd(
        model, input_tokens, output_tokens
    )
    parent.attributes["model_signature"] = _model_signature(model, fingerprint)
    parent.attributes["finish_reason"] = _first_finish_reason(response)


def _first_finish_reason(response: Any) -> str | None:
    choices = _get(response, "choices") or []
    if not choices:
        return None
    first = choices[0]
    val = _get(first, "finish_reason")
    return str(val) if isinstance(val, str) else None


def _emit_tool_call_spans_from_response(
    recorder: SpanRecorder, parent: Span, response: Any
) -> None:
    """Emit a tool_call span per tool call embedded in the response."""
    choices = _get(response, "choices") or []
    for choice in choices:
        message = _get(choice, "message")
        if message is None:
            continue
        tool_calls = _get(message, "tool_calls") or []
        for tc in tool_calls:
            fn = _get(tc, "function")
            if fn is None:
                continue
            tool_name = _get(fn, "name", "")
            raw_args = _get(fn, "arguments", "")
            if not isinstance(raw_args, str):
                try:
                    raw_args = json.dumps(raw_args)
                except (TypeError, ValueError):
                    raw_args = str(raw_args)
            args_red, args_hash = _redact_tool_arguments(raw_args)
            # result_hash is "" at emission time: the adapter records the
            # tool-call span when the model emits the call. The tool
            # function execution happens outside the adapter; the
            # downstream tool wrapper updates the result_hash via the
            # side-effect markers in :mod:`._side_effects`.
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


class _StreamWrapper:
    """Wraps an OpenAI streaming response, recording an ordered span per chunk."""

    def __init__(
        self,
        inner: Iterator[Any],
        recorder: SpanRecorder,
        parent: Span,
        start_t: float,
    ) -> None:
        self._inner = iter(inner)
        self._recorder = recorder
        self._parent = parent
        self._sequence = 0
        self._start_t = start_t
        self._last_model = parent.attributes.get("model", "")
        self._last_fingerprint: str | None = None
        self._aggregated_finish: str | None = None

    def __iter__(self) -> _StreamWrapper:
        return self

    def __next__(self) -> Any:
        try:
            chunk = next(self._inner)
        except StopIteration:
            duration_ms = (time.monotonic() - self._start_t) * 1000.0
            self._parent.attributes["model"] = self._last_model
            self._parent.attributes["model_signature"] = _model_signature(
                self._last_model, self._last_fingerprint
            )
            self._parent.attributes["duration_ms"] = duration_ms
            self._parent.attributes["finish_reason"] = self._aggregated_finish
            raise

        # Capture chunk metadata for the model_call parent + emit chunk span.
        model = _get(chunk, "model")
        if isinstance(model, str) and model:
            self._last_model = model
        fingerprint = _get(chunk, "system_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            self._last_fingerprint = fingerprint
        # The finish_reason is on the first choice when stream terminates.
        choices = _get(chunk, "choices") or []
        if choices:
            fr = _get(choices[0], "finish_reason")
            if isinstance(fr, str) and fr:
                self._aggregated_finish = fr

        self._recorder.new_span(
            "stream_chunk",
            parent_span_id=self._parent.span_id,
            chunk_sequence=self._sequence,
            event_type="content_delta",
        )
        self._sequence += 1
        return chunk


__all__ = ["wrap_openai"]
