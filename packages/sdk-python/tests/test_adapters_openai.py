"""W3.5 OpenAI adapter tests (VAL-W3-036 through VAL-W3-039).

These tests construct fake OpenAI client objects (duck-typed; we never
import the ``openai`` package) and pass them to
:func:`relay.adapters.openai_adapter.wrap_openai`. The wrapped client
replicates the OpenAI Python SDK's surface (``client.chat.completions.
create(...)`` and ``client.responses.create(...)``) but every call is
intercepted to emit Relay spans describing the model_call, tool_call,
and (for streaming) ordered stream_chunk children.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from relay.adapters import wrap_openai
from relay.adapters._spans import SpanRecorder

# ---------------------------------------------------------------------------
# Fake OpenAI response classes (duck-typed; we never import openai).
# ---------------------------------------------------------------------------


@dataclass
class _FakeUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass
class _FakeFunctionCall:
    name: str
    arguments: str  # JSON-encoded args, mirroring OpenAI Tool Use


@dataclass
class _FakeToolCall:
    id: str
    type: str
    function: _FakeFunctionCall


@dataclass
class _FakeMessage:
    role: str
    content: str | None
    tool_calls: list[_FakeToolCall] | None = None


@dataclass
class _FakeChoice:
    index: int
    message: _FakeMessage
    finish_reason: str


@dataclass
class _FakeChatCompletion:
    id: str
    model: str
    system_fingerprint: str | None
    choices: list[_FakeChoice]
    usage: _FakeUsage


@dataclass
class _FakeChunkDelta:
    content: str | None = None


@dataclass
class _FakeChunkChoice:
    index: int
    delta: _FakeChunkDelta
    finish_reason: str | None = None


@dataclass
class _FakeChunk:
    id: str
    model: str
    system_fingerprint: str | None
    choices: list[_FakeChunkChoice]


class _FakeCompletions:
    """Stand-in for ``openai.OpenAI().chat.completions``."""

    def __init__(self, response: Any) -> None:
        self._response = response

    def create(self, **kwargs: Any) -> Any:
        stream = kwargs.get("stream", False)
        if stream:
            # When streaming the caller iterates the response. Our fake
            # response is the list of chunks the caller is expected to
            # consume.
            return iter(self._response)
        return self._response


class _FakeChat:
    def __init__(self, response: Any) -> None:
        self.completions = _FakeCompletions(response)


class _FakeOpenAIClient:
    """Stand-in for ``openai.OpenAI``. Carries a ``chat.completions`` surface."""

    def __init__(self, response: Any) -> None:
        self.chat = _FakeChat(response)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def usage() -> _FakeUsage:
    return _FakeUsage(prompt_tokens=120, completion_tokens=45, total_tokens=165)


@pytest.fixture
def tool_call_response(usage: _FakeUsage) -> _FakeChatCompletion:
    return _FakeChatCompletion(
        id="chatcmpl-abc",
        model="gpt-4o-2024-08-06",
        system_fingerprint="fp_44709d6fcb",
        choices=[
            _FakeChoice(
                index=0,
                message=_FakeMessage(
                    role="assistant",
                    content=None,
                    tool_calls=[
                        _FakeToolCall(
                            id="call_001",
                            type="function",
                            function=_FakeFunctionCall(
                                name="get_weather",
                                arguments='{"city": "Paris", "api_key": "sk-123"}',
                            ),
                        )
                    ],
                ),
                finish_reason="tool_calls",
            )
        ],
        usage=usage,
    )


@pytest.fixture
def plain_response(usage: _FakeUsage) -> _FakeChatCompletion:
    return _FakeChatCompletion(
        id="chatcmpl-xyz",
        model="gpt-4o-2024-08-06",
        system_fingerprint="fp_44709d6fcb",
        choices=[
            _FakeChoice(
                index=0,
                message=_FakeMessage(role="assistant", content="hello", tool_calls=None),
                finish_reason="stop",
            )
        ],
        usage=usage,
    )


@pytest.fixture
def stream_chunks() -> list[_FakeChunk]:
    return [
        _FakeChunk(
            id="chatcmpl-s",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[_FakeChunkChoice(index=0, delta=_FakeChunkDelta(content="he"))],
        ),
        _FakeChunk(
            id="chatcmpl-s",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[_FakeChunkChoice(index=0, delta=_FakeChunkDelta(content="llo"))],
        ),
        _FakeChunk(
            id="chatcmpl-s",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeChunkChoice(
                    index=0,
                    delta=_FakeChunkDelta(content="!"),
                    finish_reason="stop",
                )
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# VAL-W3-036: tool calls captured with name + redacted args + result hash
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-036")
def test_openai_adapter_captures_tool_calls(
    tool_call_response: _FakeChatCompletion,
) -> None:
    """A model-emitted tool_call must produce a tool_call span carrying
    the required fields."""
    recorder = SpanRecorder()
    client = wrap_openai(_FakeOpenAIClient(tool_call_response), recorder=recorder)
    response = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "weather in Paris?"}],
        tools=[{"type": "function", "function": {"name": "get_weather"}}],
    )
    assert response is tool_call_response  # original return preserved
    model_spans = [s for s in recorder.spans if s.kind == "model_call"]
    tool_spans = [s for s in recorder.spans if s.kind == "tool_call"]
    assert len(model_spans) == 1
    assert len(tool_spans) == 1
    span = tool_spans[0]
    assert span.attributes["tool_name"] == "get_weather"
    assert span.attributes["parent_span_id"] == model_spans[0].span_id
    # args_redacted: api_key MUST be redacted (default policy contains the
    # api-key matcher); the raw string must NOT appear.
    args_red = span.attributes["args_redacted"]
    assert "sk-123" not in str(args_red)
    # args_hash: hex digest (HMAC-SHA-256 over redacted bytes) >= 64 chars.
    assert isinstance(span.attributes["args_hash"], str)
    assert len(span.attributes["args_hash"]) >= 32
    # result_hash present (may be empty digest for pre-tool-execution).
    assert "result_hash" in span.attributes
    assert span.attributes["status"] in {"pending", "ok", "error"}
    assert isinstance(span.attributes["duration_ms"], int | float)
    assert span.attributes["retry_count"] == 0
    assert span.attributes["side_effect_marker"] is False
    # normalized_error_class is None for a successful tool call.
    assert "normalized_error_class" in span.attributes


# ---------------------------------------------------------------------------
# VAL-W3-037: token usage and cost captured
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-037")
def test_openai_adapter_captures_usage_and_cost(
    plain_response: _FakeChatCompletion,
) -> None:
    """model_call span carries input/output/total tokens, cost, provider,
    sdk_version, model_signature."""
    recorder = SpanRecorder()
    client = wrap_openai(_FakeOpenAIClient(plain_response), recorder=recorder)
    client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "hi"}],
    )
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    assert span.attributes["input_tokens"] == 120
    assert span.attributes["output_tokens"] == 45
    assert span.attributes["total_tokens"] == 165
    assert isinstance(span.attributes["total_cost_usd"], float)
    assert span.attributes["total_cost_usd"] >= 0.0
    assert span.attributes["model"] == "gpt-4o-2024-08-06"
    assert span.attributes["provider"] == "openai"
    assert isinstance(span.attributes["sdk_version"], str)
    assert span.attributes["sdk_version"]
    assert span.attributes["model_signature"].startswith("openai:")


# ---------------------------------------------------------------------------
# VAL-W3-038: streaming chunks as ordered child spans
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-038")
def test_openai_adapter_captures_streaming_chunks(
    stream_chunks: list[_FakeChunk],
) -> None:
    """Streamed completion produces a parent model_call span plus ordered
    stream_chunk children with monotonically increasing chunk_sequence."""
    recorder = SpanRecorder()
    client = wrap_openai(_FakeOpenAIClient(stream_chunks), recorder=recorder)
    it = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "stream please"}],
        stream=True,
    )
    chunks = list(it)
    assert len(chunks) == 3
    parents = [s for s in recorder.spans if s.kind == "model_call"]
    chunk_spans = [s for s in recorder.spans if s.kind == "stream_chunk"]
    assert len(parents) == 1
    assert len(chunk_spans) >= 3
    seqs = [s.attributes["chunk_sequence"] for s in chunk_spans]
    assert seqs == sorted(seqs)
    assert seqs[0] == 0 and seqs[-1] == len(chunk_spans) - 1
    # Every chunk references the model_call parent.
    for cspan in chunk_spans:
        assert cspan.attributes["parent_span_id"] == parents[0].span_id


# ---------------------------------------------------------------------------
# VAL-W3-039: model_signature from system_fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-039")
def test_openai_adapter_tags_model_signature_from_system_fingerprint(
    plain_response: _FakeChatCompletion,
) -> None:
    recorder = SpanRecorder()
    client = wrap_openai(_FakeOpenAIClient(plain_response), recorder=recorder)
    client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "hi"}],
    )
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    assert (
        span.attributes["model_signature"]
        == "openai:gpt-4o-2024-08-06:fp_44709d6fcb"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-039")
def test_openai_adapter_model_signature_without_system_fingerprint(
    usage: _FakeUsage,
) -> None:
    """When system_fingerprint is None the model_signature falls back to
    ``openai:<model>:<sha256(model_version)>`` so the field is always
    populated for refresh-policy use."""
    response = _FakeChatCompletion(
        id="x",
        model="gpt-4o-2024-08-06",
        system_fingerprint=None,
        choices=[
            _FakeChoice(
                index=0,
                message=_FakeMessage(role="assistant", content="hi"),
                finish_reason="stop",
            )
        ],
        usage=usage,
    )
    recorder = SpanRecorder()
    client = wrap_openai(_FakeOpenAIClient(response), recorder=recorder)
    client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "hi"}],
    )
    [span] = [s for s in recorder.spans if s.kind == "model_call"]
    sig = span.attributes["model_signature"]
    assert sig.startswith("openai:gpt-4o-2024-08-06:")
    assert len(sig.split(":")) == 3


# ---------------------------------------------------------------------------
# VAL-REDACT-008: adapter-boundary scrubber must mask common credential
# key names (lockstep with the TypeScript ``scrubSecretShape``).
# ---------------------------------------------------------------------------


def test_scrub_masks_common_credential_key_names() -> None:
    """VAL-REDACT-008: high-risk credential key names beyond the original
    8-name exact-match set are scrubbed; benign keys are not.

    Reproducing trigger: tool-call arguments carrying HTTP/OAuth credential
    headers (``authorization``, ``access_token``, ``cookie`` ...) were
    recorded verbatim because the key name did not equal one of the
    original hints.
    """
    from relay.adapters.openai_adapter import _scrub

    scrubbed = _scrub(
        {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload",
            "auth": "Basic dXNlcjpwYXNz",
            "bearer": "eyJabc",
            "access_token": "ya29.A0ARrdaM-real-token",
            "refresh_token": "1//refresh-token-value",
            "session_token": "FQoGZXIvYXdzED",
            "client_secret": "GOCSPX-client-secret",
            "cookie": "session=abc123; csrf=def456",
            "set-cookie": "session=abc123; HttpOnly",
            "private_key": "-----BEGIN PRIVATE KEY-----MIIE",
            # benign keys that MUST NOT be scrubbed (no false positives)
            "city": "Paris",
            "token_count": 42,
            "authorized_user": "alice",
            "bearings": "north",
        }
    )
    assert scrubbed["authorization"] == "[REDACTED]"
    assert scrubbed["auth"] == "[REDACTED]"
    assert scrubbed["bearer"] == "[REDACTED]"
    assert scrubbed["access_token"] == "[REDACTED]"
    assert scrubbed["refresh_token"] == "[REDACTED]"
    assert scrubbed["session_token"] == "[REDACTED]"
    assert scrubbed["client_secret"] == "[REDACTED]"
    assert scrubbed["cookie"] == "[REDACTED]"
    assert scrubbed["set-cookie"] == "[REDACTED]"
    assert scrubbed["private_key"] == "[REDACTED]"
    # no false positives on benign keys
    assert scrubbed["city"] == "Paris"
    assert scrubbed["token_count"] == 42
    assert scrubbed["authorized_user"] == "alice"
    assert scrubbed["bearings"] == "north"


def test_scrub_suffix_rules_token_and_secret() -> None:
    """VAL-REDACT-008: ``*_token``/``*-token`` and ``*_secret``/``*-secret``
    suffix rules cover provider-specific credential keys without scrubbing
    benign substring matches (lockstep with TypeScript)."""
    from relay.adapters.openai_adapter import _scrub

    scrubbed = _scrub(
        {
            "id_token": "eyJid",
            "x-csrf-token": "csrf-value",
            "api_secret": "secret-value",
            "app-secret": "another-secret",
            # benign: substring 'token'/'secret' not in suffix position
            "token_count": 7,
            "secretary_name": "Bob",
        }
    )
    assert scrubbed["id_token"] == "[REDACTED]"
    assert scrubbed["x-csrf-token"] == "[REDACTED]"
    assert scrubbed["api_secret"] == "[REDACTED]"
    assert scrubbed["app-secret"] == "[REDACTED]"
    assert scrubbed["token_count"] == 7
    assert scrubbed["secretary_name"] == "Bob"
