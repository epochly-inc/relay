"""W3.5 Anthropic adapter tests (VAL-W3-040 through VAL-W3-043).

Uses duck-typed fakes mirroring the Anthropic Messages API shape; the
``anthropic`` package is never imported.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import pytest
from relay.adapters import wrap_anthropic
from relay.adapters._spans import SpanRecorder

# ---------------------------------------------------------------------------
# Duck-typed Anthropic Messages API fakes.
# ---------------------------------------------------------------------------


@dataclass
class _AnthroUsage:
    input_tokens: int
    output_tokens: int
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class _TextBlock:
    type: str
    text: str


@dataclass
class _ToolUseBlock:
    type: str
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class _AnthroMessage:
    id: str
    model: str
    role: str
    content: list[Any]
    stop_reason: str
    usage: _AnthroUsage


@dataclass
class _AnthroEvent:
    type: str
    index: int = 0
    delta: dict[str, Any] | None = None
    content_block: Any | None = None
    message: Any | None = None
    usage: Any | None = None


class _FakeMessages:
    def __init__(self, response: Any) -> None:
        self._response = response

    def create(self, **kwargs: Any) -> Any:
        if kwargs.get("stream", False):
            return iter(self._response)
        return self._response


class _FakeAnthropicClient:
    def __init__(self, response: Any) -> None:
        self.messages = _FakeMessages(response)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tool_use_response() -> _AnthroMessage:
    return _AnthroMessage(
        id="msg_01",
        model="claude-opus-4-7",
        role="assistant",
        content=[
            _TextBlock(type="text", text="I'll look that up."),
            _ToolUseBlock(
                type="tool_use",
                id="toolu_01",
                name="lookup_account",
                input={"account_id": "acct_42", "ssn": "111-22-3333"},
            ),
        ],
        stop_reason="tool_use",
        usage=_AnthroUsage(
            input_tokens=200,
            output_tokens=60,
            cache_creation_input_tokens=10,
            cache_read_input_tokens=5,
        ),
    )


@pytest.fixture
def plain_response() -> _AnthroMessage:
    return _AnthroMessage(
        id="msg_02",
        model="claude-opus-4-7",
        role="assistant",
        content=[_TextBlock(type="text", text="hello")],
        stop_reason="end_turn",
        usage=_AnthroUsage(input_tokens=15, output_tokens=8),
    )


@pytest.fixture
def stream_events() -> list[_AnthroEvent]:
    return [
        _AnthroEvent(type="message_start", message={"id": "msg_s", "model": "claude-opus-4-7"}),
        _AnthroEvent(
            type="content_block_start",
            index=0,
            content_block=_TextBlock(type="text", text=""),
        ),
        _AnthroEvent(
            type="content_block_delta",
            index=0,
            delta={"type": "text_delta", "text": "he"},
        ),
        _AnthroEvent(
            type="content_block_delta",
            index=0,
            delta={"type": "text_delta", "text": "llo"},
        ),
        _AnthroEvent(type="content_block_stop", index=0),
        _AnthroEvent(
            type="message_delta",
            delta={"stop_reason": "end_turn"},
            usage=_AnthroUsage(input_tokens=10, output_tokens=4),
        ),
        _AnthroEvent(type="message_stop"),
    ]


# ---------------------------------------------------------------------------
# VAL-W3-040: tool_use captured
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-040")
def test_anthropic_adapter_captures_tool_calls(
    tool_use_response: _AnthroMessage,
) -> None:
    recorder = SpanRecorder()
    client = wrap_anthropic(
        _FakeAnthropicClient(tool_use_response), recorder=recorder
    )
    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "lookup acct_42"}],
        tools=[{"name": "lookup_account"}],
    )
    assert response is tool_use_response
    [model_span] = [s for s in recorder.spans if s.kind == "model_call"]
    [tool_span] = [s for s in recorder.spans if s.kind == "tool_call"]
    assert tool_span.attributes["tool_name"] == "lookup_account"
    assert tool_span.attributes["parent_span_id"] == model_span.span_id
    args_red = tool_span.attributes["args_redacted"]
    assert "111-22-3333" not in str(args_red)
    assert isinstance(tool_span.attributes["args_hash"], str)
    assert len(tool_span.attributes["args_hash"]) >= 32
    assert "result_hash" in tool_span.attributes
    assert tool_span.attributes["status"] in {"pending", "ok", "error"}
    assert isinstance(tool_span.attributes["duration_ms"], int | float)


# ---------------------------------------------------------------------------
# VAL-W3-041: usage + cost with cache_* fields
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-041")
def test_anthropic_adapter_captures_usage_and_cost(
    tool_use_response: _AnthroMessage,
) -> None:
    recorder = SpanRecorder()
    client = wrap_anthropic(
        _FakeAnthropicClient(tool_use_response), recorder=recorder
    )
    client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "x"}],
    )
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    assert span.attributes["input_tokens"] == 200
    assert span.attributes["output_tokens"] == 60
    assert span.attributes["cache_creation_input_tokens"] == 10
    assert span.attributes["cache_read_input_tokens"] == 5
    assert isinstance(span.attributes["total_cost_usd"], float)
    assert span.attributes["model"] == "claude-opus-4-7"
    assert span.attributes["provider"] == "anthropic"
    assert isinstance(span.attributes["sdk_version"], str)


# ---------------------------------------------------------------------------
# VAL-W3-042: streaming SSE events captured
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-042")
def test_anthropic_adapter_captures_streaming_chunks(
    stream_events: list[_AnthroEvent],
) -> None:
    recorder = SpanRecorder()
    client = wrap_anthropic(
        _FakeAnthropicClient(stream_events), recorder=recorder
    )
    it = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "stream"}],
        stream=True,
    )
    events = list(it)
    assert len(events) == 7
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    chunk_spans = [s for s in recorder.spans if s.kind == "stream_chunk"]
    # At least 3 chunks: content_block_delta, message_delta, message_stop.
    assert len(chunk_spans) >= 3
    types_seen = {s.attributes["event_type"] for s in chunk_spans}
    assert "content_block_delta" in types_seen
    assert "message_delta" in types_seen
    assert "message_stop" in types_seen
    seqs = [s.attributes["chunk_sequence"] for s in chunk_spans]
    assert seqs == sorted(seqs)
    assert seqs[0] == 0
    for cspan in chunk_spans:
        assert cspan.attributes["parent_span_id"] == parent.span_id


# ---------------------------------------------------------------------------
# VAL-W3-043: deterministic model_signature
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-043")
def test_anthropic_adapter_model_signature_deterministic(
    plain_response: _AnthroMessage,
) -> None:
    recorder = SpanRecorder()
    client = wrap_anthropic(_FakeAnthropicClient(plain_response), recorder=recorder)
    client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "hi"}],
    )
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    sig = span.attributes["model_signature"]
    # Round-5 re-hunt parity fix: model_signature is anthropic:<model>:<response.id>
    # (or :<sha256(model)[:16]> when the id is absent), byte-identical to the TS
    # Anthropic adapter and the OpenAI sibling. plain_response.id == "msg_02".
    assert sig == "anthropic:claude-opus-4-7:msg_02", sig
    assert span.attributes["response_id"] == "msg_02"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-043")
def test_anthropic_adapter_model_signature_is_stable_across_calls(
    plain_response: _AnthroMessage,
) -> None:
    """Two calls with the same model produce byte-identical signatures."""
    recorder = SpanRecorder()
    client = wrap_anthropic(_FakeAnthropicClient(plain_response), recorder=recorder)
    client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1,
        messages=[{"role": "user", "content": "1"}],
    )
    client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1,
        messages=[{"role": "user", "content": "2"}],
    )
    sigs = [
        s.attributes["model_signature"]
        for s in recorder.spans
        if s.kind == "model_call"
    ]
    assert len(sigs) == 2
    assert sigs[0] == sigs[1]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-043")
def test_anthropic_model_signature_falls_back_to_sha256_when_id_absent() -> None:
    """When response.id is absent the signature is anthropic:<model>:<sha256
    (model)[:16]>, byte-identical to the TS adapter + OpenAI sibling."""
    import hashlib

    resp = _AnthroMessage(
        id="",  # no provider id
        model="claude-opus-4-7",
        role="assistant",
        content=[_TextBlock(type="text", text="hi")],
        stop_reason="end_turn",
        usage=_AnthroUsage(input_tokens=1, output_tokens=1),
    )
    recorder = SpanRecorder()
    client = wrap_anthropic(_FakeAnthropicClient(resp), recorder=recorder)
    client.messages.create(model="claude-opus-4-7", max_tokens=1, messages=[])
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    fallback = hashlib.sha256(b"claude-opus-4-7").hexdigest()[:16]
    assert span.attributes["model_signature"] == f"anthropic:claude-opus-4-7:{fallback}"
    assert span.attributes["response_id"] is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-033")
def test_anthropic_streaming_model_signature_carries_message_id(
    stream_events: list[_AnthroEvent],
) -> None:
    """The streaming finalize captures message.id from message_start and
    re-computes model_signature as anthropic:<model>:<message.id> + sets
    response_id (Py<->TS parity). stream_events' message_start id == 'msg_s'."""
    recorder = SpanRecorder()
    client = wrap_anthropic(_FakeAnthropicClient(stream_events), recorder=recorder)
    stream = client.messages.create(
        model="claude-opus-4-7", max_tokens=64, stream=True, messages=[]
    )
    for _ in stream:
        pass
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    assert span.attributes["model_signature"] == "anthropic:claude-opus-4-7:msg_s"
    assert span.attributes["response_id"] == "msg_s"


# ---------------------------------------------------------------------------
# VAL-ISO-020: streaming usage aggregation must not double-count output
# tokens and must seed input tokens from message_start (Py<->TS parity).
#
# Mirrors packages/sdk-typescript/test/w4_5_anthropic_adapter.test.ts
# describe("VAL-ISO-020: ..."). Anthropic's message_delta usage.output_tokens
# is the AUTHORITATIVE CUMULATIVE final output count, not a per-event
# increment; message_start carries the input token count plus a small initial
# output seed. The adapter must ASSIGN (not add) the cumulative output and
# read input from event.message.usage on message_start.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-020")
def test_anthropic_streaming_does_not_double_count_output_tokens() -> None:
    """message_delta cumulative output_tokens is authoritative (assign, not
    add); input is seeded once from message_start.

    Real stream: message_start{input=40, output=2}, two message_delta
    cumulative snapshots (80 then 150). Correct: input=40, output=150. The
    pre-fix Python summed every event (output 2+80+150=232) and never read
    event.message.usage (input 0)."""
    recorder = SpanRecorder()
    events = [
        _AnthroEvent(
            type="message_start",
            message={
                "id": "msg_dbl_count",
                "model": "claude-3-5-sonnet",
                "usage": {"input_tokens": 40, "output_tokens": 2},
            },
        ),
        _AnthroEvent(
            type="content_block_start",
            index=0,
            content_block=_TextBlock(type="text", text=""),
        ),
        # First message_delta: cumulative output so far = 80.
        _AnthroEvent(
            type="message_delta",
            delta={"stop_reason": None},
            usage=_AnthroUsage(input_tokens=0, output_tokens=80),
        ),
        # Second message_delta: cumulative final output = 150 (NOT +150).
        _AnthroEvent(
            type="message_delta",
            delta={"stop_reason": "end_turn"},
            usage=_AnthroUsage(input_tokens=0, output_tokens=150),
        ),
        _AnthroEvent(type="message_stop"),
    ]
    client = wrap_anthropic(_FakeAnthropicClient(events), recorder=recorder)
    it = client.messages.create(
        model="claude-3-5-sonnet",
        max_tokens=1024,
        messages=[{"role": "user", "content": "stream"}],
        stream=True,
    )
    list(it)
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    # input seeded from message_start only.
    assert parent.attributes["input_tokens"] == 40
    # output is the LAST cumulative message_delta value, NOT 2+80+150=232.
    assert parent.attributes["output_tokens"] == 150


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-020")
def test_anthropic_streaming_seed_not_clobbered_without_delta_usage() -> None:
    """When no message_delta carries a usage block, the message_start output
    seed must NOT be clobbered to 0, and input stays seeded."""
    recorder = SpanRecorder()
    events = [
        _AnthroEvent(
            type="message_start",
            message={
                "id": "msg_no_delta_usage",
                "model": "claude-3-5-sonnet",
                "usage": {"input_tokens": 9, "output_tokens": 3},
            },
        ),
        # message_delta with no usage block: must not clobber the seed to 0.
        _AnthroEvent(
            type="message_delta",
            delta={"stop_reason": "end_turn"},
        ),
        _AnthroEvent(type="message_stop"),
    ]
    client = wrap_anthropic(_FakeAnthropicClient(events), recorder=recorder)
    it = client.messages.create(
        model="claude-3-5-sonnet",
        max_tokens=1024,
        messages=[{"role": "user", "content": "x"}],
        stream=True,
    )
    list(it)
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    assert parent.attributes["input_tokens"] == 9
    assert parent.attributes["output_tokens"] == 3


# ---------------------------------------------------------------------------
# VAL-W4-039: streamed tool_use reconstructed from input_json_delta fragments
# (Py<->TS parity with the TypeScript adapter's ingestEvent/finalizeStream).
# Pre-fix the Python streaming wrapper emitted only generic stream_chunk spans
# and never reconstructed the tool_use block, nor set chunk_count.
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W4-039")
def test_anthropic_streaming_reconstructs_tool_use() -> None:
    recorder = SpanRecorder()
    events = [
        _AnthroEvent(
            type="message_start",
            message={"id": "msg_t", "model": "claude-opus-4-7"},
        ),
        _AnthroEvent(
            type="content_block_start",
            index=0,
            content_block=_ToolUseBlock(
                type="tool_use", id="toolu_9", name="get_weather", input={}
            ),
        ),
        # The tool args arrive as input_json_delta fragments, never as a single
        # block -- the wrapper must accumulate partial_json across deltas.
        _AnthroEvent(
            type="content_block_delta",
            index=0,
            delta={"type": "input_json_delta", "partial_json": '{"city": "Par'},
        ),
        _AnthroEvent(
            type="content_block_delta",
            index=0,
            delta={"type": "input_json_delta", "partial_json": 'is"}'},
        ),
        _AnthroEvent(type="content_block_stop", index=0),
        _AnthroEvent(
            type="message_delta",
            delta={"stop_reason": "tool_use"},
            usage=_AnthroUsage(input_tokens=50, output_tokens=12),
        ),
        _AnthroEvent(type="message_stop"),
    ]
    client = wrap_anthropic(_FakeAnthropicClient(events), recorder=recorder)
    it = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "weather in Paris"}],
        stream=True,
    )
    list(it)
    tool_spans = [s for s in recorder.spans if s.kind == "tool_call"]
    assert len(tool_spans) == 1
    assert tool_spans[0].attributes["tool_name"] == "get_weather"
    # Args reconstructed from the streamed fragments ('{"city": "Paris"}').
    assert "Paris" in str(tool_spans[0].attributes["args_redacted"])
    assert tool_spans[0].attributes["parent_span_id"] == (
        [s for s in recorder.spans if s.kind == "model_call"][0].span_id
    )
    # chunk_count populated on the model_call parent (parity with the TS
    # finalizeStream, which sets state.chunkCount).
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    assert parent.attributes["chunk_count"] == len(events)
    # stop_reason surfaced on the parent (parity with non-stream + TS stream).
    assert parent.attributes["stop_reason"] == "tool_use"
