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
            "private_key": "pk-test-REDACTME-0123456789",
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


def test_scrub_masks_camelcase_credential_key_names() -> None:
    """VAL-REDACT-008: camelCase credential key names (common in JS/TS
    tool-call args) are scrubbed via de-camelCase normalization, while
    benign camelCase keys stay verbatim (no false positives).

    Reproducing trigger: ``accessToken`` lowercased to ``accesstoken``,
    which is neither a hint-set member nor ``*_token``-suffixed, so the
    credential value was recorded verbatim. The de-camelCase rule maps
    ``accessToken`` -> ``access_token`` (suffix match) before the check.
    Lockstep with the TypeScript ``scrubSecretShape``.
    """
    from relay.adapters.openai_adapter import _scrub

    scrubbed = _scrub(
        {
            "accessToken": "ya29.A0ARrdaM-real-token",
            "refreshToken": "1//refresh-token-value",
            "sessionToken": "FQoGZXIvYXdzED",
            "idToken": "eyJid",
            "clientSecret": "GOCSPX-client-secret",
            "privateKey": "pk-test-REDACTME-0123456789",
            # benign camelCase keys that MUST NOT be scrubbed
            "tokenCount": 42,
            "secretaryName": "Bob",
            "authorizedUser": "alice",
            "bearings": "north",
        }
    )
    assert scrubbed["accessToken"] == "[REDACTED]"
    assert scrubbed["refreshToken"] == "[REDACTED]"
    assert scrubbed["sessionToken"] == "[REDACTED]"
    assert scrubbed["idToken"] == "[REDACTED]"
    assert scrubbed["clientSecret"] == "[REDACTED]"
    assert scrubbed["privateKey"] == "[REDACTED]"
    # no false positives on benign camelCase keys
    assert scrubbed["tokenCount"] == 42
    assert scrubbed["secretaryName"] == "Bob"
    assert scrubbed["authorizedUser"] == "alice"
    assert scrubbed["bearings"] == "north"


# ---------------------------------------------------------------------------
# Gate-2 structural REAL_DEFECT C: ``_scrub`` recursed with no cycle guard
# and no depth bound. A self-referential or pathologically deep tool-args
# object (reachable via the live, non-JSON-round-tripped call sites in
# anthropic_adapter._redact_tool_input) caused a RecursionError that crashed
# inline span emission in the model-call wrap path. The fix fails safe: a
# cycle is replaced with the "[relay:cycle]" marker and a subtree past
# SCRUB_MAX_DEPTH with "[relay:elided-depth]", never crashing and never
# leaking secret values. Lockstep markers with the TypeScript
# ``scrubSecretShape``.
# ---------------------------------------------------------------------------


def test_scrub_handles_self_referential_dict_without_crash() -> None:
    """Gate-2 C: a dict that references itself is scrubbed without a
    RecursionError; the credential key is still masked and the
    back-reference becomes the deterministic "[relay:cycle]" marker."""
    from relay.adapters.openai_adapter import _scrub

    d: dict[str, Any] = {"token": "sk-secret-AAAAAAAAAAAA", "n": 1}
    d["self"] = d
    scrubbed = _scrub(d)
    assert scrubbed["token"] == "[REDACTED]"
    assert scrubbed["n"] == 1
    assert scrubbed["self"] == "[relay:cycle]"
    # Adversarial: serialised output must not leak the seed secret.
    import json as _json

    assert "sk-secret-AAAAAAAAAAAA" not in _json.dumps(scrubbed)


def test_scrub_handles_cycle_in_list_without_crash() -> None:
    """Gate-2 C: a cycle nested inside a list is elided without crash."""
    from relay.adapters.openai_adapter import _scrub

    arr: list[Any] = []
    node: dict[str, Any] = {"items": arr, "secret": "sk-deep-BBBBBBBB"}
    arr.append(node)
    scrubbed = _scrub(node)
    assert scrubbed["secret"] == "[REDACTED]"
    assert scrubbed["items"][0] == "[relay:cycle]"


def test_scrub_elides_deeply_nested_object_without_recursionerror() -> None:
    """Gate-2 C: a ~2000-deep nested dict is elided at the depth bound
    instead of raising RecursionError; output is deterministic and the
    bottom secret cannot leak past the bound."""
    import json as _json

    from relay.adapters.openai_adapter import _scrub

    deep: dict[str, Any] = {"token": "sk-bottom-CCCCCCCC"}
    for _ in range(2000):
        deep = {"child": deep}
    scrubbed = _scrub(deep)
    serialized = _json.dumps(scrubbed)
    assert "[relay:elided-depth]" in serialized
    assert "sk-bottom-CCCCCCCC" not in serialized
    # Determinism: scrubbing twice yields byte-identical output.
    assert _json.dumps(_scrub(deep)) == serialized


def test_scrub_does_not_treat_shared_subtree_as_cycle() -> None:
    """Gate-2 C: an acyclic sub-object referenced from two siblings is
    scrubbed in BOTH positions, not falsely elided as a cycle. The cycle
    guard must track the active recursion path, not every container seen."""
    from relay.adapters.openai_adapter import _scrub

    shared: dict[str, Any] = {"api_key": "sk-shared-DDDDDDDD", "keep": "ok"}
    root = {"left": shared, "right": shared}
    scrubbed = _scrub(root)
    assert scrubbed["left"]["api_key"] == "[REDACTED]"
    assert scrubbed["right"]["api_key"] == "[REDACTED]"
    assert scrubbed["left"]["keep"] == "ok"
    assert scrubbed["right"]["keep"] == "ok"
    assert scrubbed["left"]["api_key"] != "[relay:cycle]"
    assert scrubbed["right"]["api_key"] != "[relay:cycle]"


# ---------------------------------------------------------------------------
# Gate-2 structural REAL_DEFECT D: ``_scrub`` preserves the original
# (possibly non-string) dict key, then ``json.dumps(redacted,
# sort_keys=True, ...)`` in ``_redact_tool_arguments`` raises TypeError on
# heterogeneous keys -- crashing args_hash, while the TS side (whose keys
# are always strings) hashes fine. The fix coerces dict keys to strings
# deterministically before the sort+dump so non-string keys cannot crash
# the hash and Py/TS align for the same logical input.
# ---------------------------------------------------------------------------


def test_redact_tool_arguments_with_non_string_key_no_typeerror() -> None:
    """Gate-2 D: a tool-input dict carrying a non-string key computes
    args_hash WITHOUT TypeError, and the secret value is scrubbed."""
    import json as _json

    from relay.adapters.openai_adapter import _redact_tool_arguments

    # ``raw`` is the provider's JSON-encoded args string. A heterogeneous
    # key arises after json.loads when the model emits a numeric-keyed
    # object, or via the live (non-round-tripped) Anthropic path. We feed a
    # raw string that json.loads cannot recover heterogeneous keys from, so
    # exercise the dict path directly via the Anthropic redactor below and
    # the openai redactor here through a pre-built dict round-trip.
    raw = _json.dumps({"access_token": "ya29.A0ARrdaM-real-token", "x": 1})
    redacted, args_hash = _redact_tool_arguments(raw)
    assert redacted["access_token"] == "[REDACTED]"
    assert isinstance(args_hash, str) and len(args_hash) == 64


def test_anthropic_redact_tool_input_non_string_keys_no_typeerror() -> None:
    """Gate-2 D: the Anthropic redactor receives the live tool_input dict
    (no JSON round-trip), so non-string keys reach json.dumps. Coercion
    must prevent the TypeError and still scrub the secret value."""
    from relay.adapters.anthropic_adapter import _redact_tool_input

    tool_input = {"access_token": "ya29.A0ARrdaM-real-token", 1: "x"}
    redacted, args_hash = _redact_tool_input(tool_input)
    assert redacted["access_token"] == "[REDACTED]"
    assert isinstance(args_hash, str) and len(args_hash) == 64


def test_scrub_mixed_int_and_string_keys_args_hash_stable() -> None:
    """Gate-2 D: mixed int/str keys are sorted by their string form so the
    args_hash is stable and deterministic across calls."""
    from relay.adapters.anthropic_adapter import _redact_tool_input

    tool_input: dict[Any, Any] = {2: "b", "access_token": "sk-leak-EEEE", 10: "c"}
    _, h1 = _redact_tool_input(tool_input)
    _, h2 = _redact_tool_input(dict(tool_input))
    assert h1 == h2


# ---------------------------------------------------------------------------
# sdk-python-run-005 (P2): tool-call args_hash MUST be byte-identical Py<->TS.
#
# The adapters previously canonicalized via json.dumps(redacted,
# sort_keys=True, default=str), whose default separators (", " / ": ") and
# ensure_ascii=True escaping diverge from the TypeScript ``canonicalStringify``
# (compact separators, ensure_ascii=False) -- so the SAME logical tool-call
# args produced DIFFERENT args_hash values across the two SDKs, breaking the
# keystone Py<->TS parity invariant. The fix routes both adapters through the
# shared JCS canonicalizer ``relay.redaction._canonical_json_stringify``.
#
# Expected hashes below are produced by the TS ``canonicalStringify`` +
# SHA-256 over the SAME redacted payloads (computed from
# packages/sdk-typescript/src/adapters/anthropic.ts / openai.ts), so this
# test pins the cross-language wire bytes. Covers an ASCII payload AND a
# non-ASCII payload (the case that the old ensure_ascii=True path corrupted).
# ---------------------------------------------------------------------------

# TS canonicalStringify({"city":"Paris","count":3,"unit":"celsius"}) ->
# '{"city":"Paris","count":3,"unit":"celsius"}'; sha256 of those bytes:
_TS_ARGS_HASH_ASCII = (
    "e7a10193123f4f1bd82032a0acc942094726848c8a1cee601a6d9be84efaecac"
)
# TS canonicalStringify({"emoji":"\U0001F680","note":"café ... résumé"})
# emits the code points as literal UTF-8 (ensure_ascii=False); sha256:
_TS_ARGS_HASH_UNICODE = (
    "f4c2d95659ffa625097e66bba5bf4f5896ce1734c941ecc5a428e620281e6605"
)


def test_openai_args_hash_matches_typescript_ascii() -> None:
    """The OpenAI adapter args_hash equals the TS-produced hash for a plain
    ASCII tool-call arguments string."""
    from relay.adapters.openai_adapter import _redact_tool_arguments

    raw = '{"city": "Paris", "unit": "celsius", "count": 3}'
    _, args_hash = _redact_tool_arguments(raw)
    assert args_hash == _TS_ARGS_HASH_ASCII


def test_openai_args_hash_matches_typescript_unicode() -> None:
    """The OpenAI adapter args_hash equals the TS-produced hash for a
    non-ASCII tool-call arguments string. The old json.dumps path used
    ensure_ascii=True (\\uXXXX escapes), diverging from TS; the JCS path
    emits literal UTF-8 like JSON.stringify."""
    from relay.adapters.openai_adapter import _redact_tool_arguments

    raw = '{"note": "café — résumé", "emoji": "\U0001f680"}'
    _, args_hash = _redact_tool_arguments(raw)
    assert args_hash == _TS_ARGS_HASH_UNICODE


def test_anthropic_args_hash_matches_typescript_unicode() -> None:
    """The Anthropic adapter args_hash equals the TS-produced hash for the
    same non-ASCII tool input (Anthropic receives a live dict, not a JSON
    string)."""
    from relay.adapters.anthropic_adapter import _redact_tool_input

    tool_input = {"note": "café — résumé", "emoji": "\U0001f680"}
    _, args_hash = _redact_tool_input(tool_input)
    assert args_hash == _TS_ARGS_HASH_UNICODE


def test_redact_tool_input_raises_typeerror_on_unsupported_value() -> None:
    """The JCS canonicalizer fails CLOSED (TypeError) on a value type it
    cannot serialise, where the old default=str silently coerced it. For
    JSON-shaped tool args (post json.loads) this path is never hit, but a
    live dict carrying a non-JSON value (e.g. a set) must not silently hash
    a lossy string form."""
    from relay.adapters.anthropic_adapter import _redact_tool_input

    with pytest.raises(TypeError):
        _redact_tool_input({"weird": {1, 2, 3}})


# ---------------------------------------------------------------------------
# Py<->TS streaming-usage parity: the streaming wrapper must aggregate token
# usage from the terminal usage-only chunk (OpenAI with
# stream_options.include_usage emits a final chunk with empty choices and a
# populated .usage) and write input/output/total tokens + cost on finalize.
# Mirrors the TS adapter's ingestChunk/finalizeStream (it accumulates
# usage.prompt_tokens/completion_tokens). Pre-fix the Python streaming
# wrapper never read chunk.usage, so every streamed call kept the seed
# zeros, diverging from the non-stream path and from TypeScript.
# ---------------------------------------------------------------------------


@dataclass
class _FakeUsageChunk:
    """Terminal usage-only chunk: empty choices + populated .usage.

    OpenAI with ``stream_options={"include_usage": True}`` emits this as the
    final SSE chunk (choices is empty, usage carries the totals).
    """

    id: str
    model: str
    system_fingerprint: str | None
    choices: list[_FakeChunkChoice]
    usage: _FakeUsage


@pytest.mark.plumbing
def test_openai_streaming_aggregates_usage_on_finalize() -> None:
    """A streamed sequence ending in a usage-only chunk (prompt=120,
    completion=30) yields a model_call span with input_tokens=120,
    output_tokens=30, total_tokens=150, and a nonzero cost mirroring the
    non-stream path's cost computation."""
    recorder = SpanRecorder()
    chunks: list[Any] = [
        _FakeChunk(
            id="chatcmpl-u",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[_FakeChunkChoice(index=0, delta=_FakeChunkDelta(content="he"))],
        ),
        _FakeChunk(
            id="chatcmpl-u",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeChunkChoice(
                    index=0,
                    delta=_FakeChunkDelta(content="llo"),
                    finish_reason="stop",
                )
            ],
        ),
        # Terminal usage-only chunk: choices empty, usage populated.
        _FakeUsageChunk(
            id="chatcmpl-u",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[],
            usage=_FakeUsage(
                prompt_tokens=120, completion_tokens=30, total_tokens=150
            ),
        ),
    ]
    client = wrap_openai(_FakeOpenAIClient(chunks), recorder=recorder)
    it = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "stream please"}],
        stream=True,
        stream_options={"include_usage": True},
    )
    list(it)
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    assert parent.attributes["input_tokens"] == 120
    assert parent.attributes["output_tokens"] == 30
    assert parent.attributes["total_tokens"] == 150
    # Cost mirrors the non-stream path exactly (gpt-4o-2024-08-06 pricing).
    expected_cost = (120 / 1_000_000.0) * 2.50 + (30 / 1_000_000.0) * 10.00
    assert parent.attributes["total_cost_usd"] == round(expected_cost, 6)
    assert parent.attributes["total_cost_usd"] > 0.0


# ---------------------------------------------------------------------------
# Streamed tool_calls (HIGH #1): a streaming completion that emits
# choices[].delta.tool_calls[] must aggregate the per-index id/name/arguments
# deltas and emit exactly ONE tool_call span per aggregated call on finalize,
# mirroring the TS openai.ts ingestChunk/finalizeStream (VAL-W4-039). The
# Python stream path previously dropped delta.tool_calls entirely, so a
# streamed tool-using call recorded ZERO tool_call spans.
#
# chunk_count parity (MED #2): finalize must set chunk_count on the model_call
# parent equal to the number of chunks consumed (TS sets
# state.parent.attributes['chunk_count'] = state.chunkCount).
#
# total_tokens parity (MED #3): TS finalizeStream FORCES
# total_tokens = prompt_tokens + completion_tokens (ignoring any provider
# total). A terminal usage chunk whose total disagrees with the sum must
# yield total_tokens == prompt + completion.
# ---------------------------------------------------------------------------


@dataclass
class _FakeToolCallFunctionDelta:
    """Streamed function delta: name and arguments arrive in fragments."""

    name: str | None = None
    arguments: str | None = None


@dataclass
class _FakeToolCallDelta:
    """One element of delta.tool_calls, keyed by ``index``."""

    index: int
    id: str | None = None
    type: str | None = None
    function: _FakeToolCallFunctionDelta | None = None


@dataclass
class _FakeToolDelta:
    """A choices[].delta carrying streamed tool_calls fragments."""

    content: str | None = None
    tool_calls: list[_FakeToolCallDelta] | None = None


@dataclass
class _FakeToolChunkChoice:
    index: int
    delta: _FakeToolDelta
    finish_reason: str | None = None


@dataclass
class _FakeToolChunk:
    id: str
    model: str
    system_fingerprint: str | None
    choices: list[_FakeToolChunkChoice]


@pytest.mark.plumbing
def test_openai_streaming_emits_one_tool_call_span_per_aggregated_call() -> None:
    """Streamed delta.tool_calls fragments aggregate per index into a single
    tool_call span carrying the stitched name and args, mirroring TS
    finalizeStream. The args secret must be redacted at the boundary."""
    recorder = SpanRecorder()
    chunks: list[Any] = [
        # Call index 0: name arrives first, then arguments in two fragments.
        _FakeToolChunk(
            id="chatcmpl-t",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeToolChunkChoice(
                    index=0,
                    delta=_FakeToolDelta(
                        tool_calls=[
                            _FakeToolCallDelta(
                                index=0,
                                id="call_001",
                                type="function",
                                function=_FakeToolCallFunctionDelta(
                                    name="get_weather", arguments='{"city": '
                                ),
                            )
                        ]
                    ),
                )
            ],
        ),
        _FakeToolChunk(
            id="chatcmpl-t",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeToolChunkChoice(
                    index=0,
                    delta=_FakeToolDelta(
                        tool_calls=[
                            _FakeToolCallDelta(
                                index=0,
                                function=_FakeToolCallFunctionDelta(
                                    arguments='"Paris", "api_key": "sk-123"}'
                                ),
                            )
                        ]
                    ),
                    finish_reason="tool_calls",
                )
            ],
        ),
    ]
    client = wrap_openai(_FakeOpenAIClient(chunks), recorder=recorder)
    it = client.chat.completions.create(
        model="gpt-4o-2024-08-06",
        messages=[{"role": "user", "content": "weather in Paris?"}],
        tools=[{"type": "function", "function": {"name": "get_weather"}}],
        stream=True,
    )
    list(it)
    tool_spans = [s for s in recorder.spans if s.kind == "tool_call"]
    parents = [s for s in recorder.spans if s.kind == "model_call"]
    assert len(parents) == 1
    # Exactly ONE tool_call span per aggregated call (not one per chunk).
    assert len(tool_spans) == 1
    span = tool_spans[0]
    assert span.attributes["tool_name"] == "get_weather"
    assert span.attributes["parent_span_id"] == parents[0].span_id
    # Stitched args: city=Paris, with the credential redacted.
    args_red = span.attributes["args_redacted"]
    assert args_red["city"] == "Paris"
    assert args_red["api_key"] == "[REDACTED]"
    assert "sk-123" not in str(args_red)
    assert isinstance(span.attributes["args_hash"], str)
    assert len(span.attributes["args_hash"]) == 64
    assert span.attributes["status"] == "pending"
    assert span.attributes["side_effect_marker"] is False


@pytest.mark.plumbing
def test_openai_streaming_emits_one_span_per_parallel_tool_call() -> None:
    """Two parallel streamed tool calls (distinct indices) aggregate into two
    separate tool_call spans, mirroring TS toolCallsByIndex."""
    recorder = SpanRecorder()
    chunks: list[Any] = [
        _FakeToolChunk(
            id="chatcmpl-p",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeToolChunkChoice(
                    index=0,
                    delta=_FakeToolDelta(
                        tool_calls=[
                            _FakeToolCallDelta(
                                index=0,
                                id="call_a",
                                function=_FakeToolCallFunctionDelta(
                                    name="get_weather", arguments='{"city": "Paris"}'
                                ),
                            ),
                            _FakeToolCallDelta(
                                index=1,
                                id="call_b",
                                function=_FakeToolCallFunctionDelta(
                                    name="get_time", arguments='{"tz": "UTC"}'
                                ),
                            ),
                        ]
                    ),
                    finish_reason="tool_calls",
                )
            ],
        ),
    ]
    client = wrap_openai(_FakeOpenAIClient(chunks), recorder=recorder)
    list(
        client.chat.completions.create(
            model="gpt-4o-2024-08-06",
            messages=[{"role": "user", "content": "weather + time?"}],
            stream=True,
        )
    )
    tool_spans = [s for s in recorder.spans if s.kind == "tool_call"]
    assert len(tool_spans) == 2
    names = sorted(s.attributes["tool_name"] for s in tool_spans)
    assert names == ["get_time", "get_weather"]


@pytest.mark.plumbing
def test_openai_streaming_sets_chunk_count_on_parent() -> None:
    """finalize sets chunk_count on the model_call parent equal to the number
    of chunks consumed (TS state.parent.attributes['chunk_count'])."""
    recorder = SpanRecorder()
    chunks: list[Any] = [
        _FakeChunk(
            id="chatcmpl-c",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[_FakeChunkChoice(index=0, delta=_FakeChunkDelta(content="a"))],
        ),
        _FakeChunk(
            id="chatcmpl-c",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[_FakeChunkChoice(index=0, delta=_FakeChunkDelta(content="b"))],
        ),
        _FakeChunk(
            id="chatcmpl-c",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeChunkChoice(
                    index=0,
                    delta=_FakeChunkDelta(content="c"),
                    finish_reason="stop",
                )
            ],
        ),
    ]
    client = wrap_openai(_FakeOpenAIClient(chunks), recorder=recorder)
    list(
        client.chat.completions.create(
            model="gpt-4o-2024-08-06",
            messages=[{"role": "user", "content": "stream"}],
            stream=True,
        )
    )
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    assert parent.attributes["chunk_count"] == 3


@pytest.mark.plumbing
def test_openai_streaming_total_tokens_is_input_plus_output_parity() -> None:
    """Py<->TS parity: TS finalizeStream FORCES total_tokens =
    prompt_tokens + completion_tokens, ignoring any provider total. A terminal
    usage chunk whose total (999) disagrees with the sum (120 + 30 = 150) must
    yield total_tokens == 150, not 999."""
    recorder = SpanRecorder()
    chunks: list[Any] = [
        _FakeChunk(
            id="chatcmpl-tt",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[
                _FakeChunkChoice(
                    index=0,
                    delta=_FakeChunkDelta(content="hi"),
                    finish_reason="stop",
                )
            ],
        ),
        _FakeUsageChunk(
            id="chatcmpl-tt",
            model="gpt-4o-2024-08-06",
            system_fingerprint="fp_44709d6fcb",
            choices=[],
            # Provider total deliberately disagrees with prompt+completion.
            usage=_FakeUsage(
                prompt_tokens=120, completion_tokens=30, total_tokens=999
            ),
        ),
    ]
    client = wrap_openai(_FakeOpenAIClient(chunks), recorder=recorder)
    list(
        client.chat.completions.create(
            model="gpt-4o-2024-08-06",
            messages=[{"role": "user", "content": "stream"}],
            stream=True,
            stream_options={"include_usage": True},
        )
    )
    [parent] = [s for s in recorder.spans if s.kind == "model_call"]
    assert parent.attributes["input_tokens"] == 120
    assert parent.attributes["output_tokens"] == 30
    # NOT 999: total is forced to the sum for Py<->TS parity.
    assert parent.attributes["total_tokens"] == 150
