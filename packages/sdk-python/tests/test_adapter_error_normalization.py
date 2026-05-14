"""W3.5 VAL-W3-046: adapter errors normalize to stable Relay codes.

Per the contract gap note (1551) the provider-exception -> normalized code
mapping table is not in the spec. This test fixes the v0.1 table:

  provider_specific (any of: openai.RateLimitError, anthropic.RateLimitError,
      stripe-cli-like RateLimitError shapes)            -> MODEL_RATE_LIMIT
  provider_specific timeout (any of: openai.APITimeoutError,
      anthropic.APITimeoutError, httpx.TimeoutException) -> MODEL_TIMEOUT
  provider_specific context-overflow
      (openai.BadRequestError with code 'context_length_exceeded';
       anthropic.BadRequestError with type 'invalid_request_error' and
       'prompt is too long')                            -> MODEL_CONTEXT_OVERFLOW
  provider_specific tool-arg validation failure         -> TOOL_BAD_ARGUMENTS

Every NormalizedError MUST also carry the original ``raw_type`` (provider
exception class name) and a deterministic ``signature``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from relay.adapters.errors import normalize_error

# ---------------------------------------------------------------------------
# Fake provider exception classes named to match real openai/anthropic types.
# ---------------------------------------------------------------------------


class _OpenAIRateLimitError(Exception):
    def __init__(self, message: str = "rate limited") -> None:
        super().__init__(message)


_OpenAIRateLimitError.__module__ = "openai"
_OpenAIRateLimitError.__qualname__ = "RateLimitError"


class _OpenAIAPITimeoutError(Exception):
    pass


_OpenAIAPITimeoutError.__module__ = "openai"
_OpenAIAPITimeoutError.__qualname__ = "APITimeoutError"


class _OpenAIBadRequestError(Exception):
    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


_OpenAIBadRequestError.__module__ = "openai"
_OpenAIBadRequestError.__qualname__ = "BadRequestError"


class _AnthropicRateLimitError(Exception):
    pass


_AnthropicRateLimitError.__module__ = "anthropic"
_AnthropicRateLimitError.__qualname__ = "RateLimitError"


class _AnthropicAPITimeoutError(Exception):
    pass


_AnthropicAPITimeoutError.__module__ = "anthropic"
_AnthropicAPITimeoutError.__qualname__ = "APITimeoutError"


class _AnthropicBadRequestError(Exception):
    def __init__(
        self,
        message: str,
        error_type: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_type = error_type


_AnthropicBadRequestError.__module__ = "anthropic"
_AnthropicBadRequestError.__qualname__ = "BadRequestError"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-046")
@pytest.mark.parametrize(
    ("exc", "expected_code"),
    [
        (_OpenAIRateLimitError(), "MODEL_RATE_LIMIT"),
        (_AnthropicRateLimitError(), "MODEL_RATE_LIMIT"),
        (_OpenAIAPITimeoutError(), "MODEL_TIMEOUT"),
        (_AnthropicAPITimeoutError(), "MODEL_TIMEOUT"),
        (
            _OpenAIBadRequestError(
                "context too long", code="context_length_exceeded"
            ),
            "MODEL_CONTEXT_OVERFLOW",
        ),
        (
            _AnthropicBadRequestError(
                "prompt is too long: 1234 tokens > limit",
                error_type="invalid_request_error",
            ),
            "MODEL_CONTEXT_OVERFLOW",
        ),
    ],
)
def test_normalize_error_maps_provider_codes(
    exc: Exception, expected_code: str
) -> None:
    ne = normalize_error(exc)
    assert ne.code == expected_code
    # raw_type preserves the original provider class name.
    assert ne.raw_type.endswith(type(exc).__qualname__)
    # signature is a stable string.
    assert isinstance(ne.signature, str)
    assert ne.signature


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-046")
def test_normalize_error_tool_bad_arguments() -> None:
    """Tool-call argument validation failure normalizes to TOOL_BAD_ARGUMENTS."""

    class _ToolArgValidation(ValueError):
        pass

    exc = _ToolArgValidation("invalid tool arguments: missing 'city'")
    ne = normalize_error(exc, context={"tool_call": True})
    assert ne.code == "TOOL_BAD_ARGUMENTS"
    assert ne.raw_type.endswith("_ToolArgValidation")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-046")
def test_normalize_error_unknown_falls_back_to_model_unknown() -> None:
    """An exception class the SDK does not recognise normalizes to a
    deterministic ``MODEL_UNKNOWN`` code, preserving raw_type + signature."""
    exc = RuntimeError("kaboom")
    ne = normalize_error(exc)
    assert ne.code == "MODEL_UNKNOWN"
    assert ne.raw_type.endswith("RuntimeError")
    assert ne.signature


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-W3-046")
def test_normalize_error_signature_is_deterministic() -> None:
    """Two normalizations of the same exception class produce identical
    signatures so cassettes can match across runs."""
    e1 = _OpenAIRateLimitError("foo")
    e2 = _OpenAIRateLimitError("bar")
    assert normalize_error(e1).signature == normalize_error(e2).signature
