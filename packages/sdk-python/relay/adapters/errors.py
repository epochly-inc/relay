"""Adapter error normalization (W3.5, VAL-W3-046).

Maps provider-specific exception classes (openai.RateLimitError,
anthropic.RateLimitError, ...) to stable normalized Relay codes. The
mapping table is duck-typed: we never import ``openai`` or ``anthropic``;
we dispatch on the exception's ``__module__`` + ``__qualname__`` strings
plus on attribute-level hints (e.g. an OpenAI BadRequestError whose
``.code == 'context_length_exceeded'``).

Normalized codes (per VAL-W3-046 contract text):

  MODEL_RATE_LIMIT        provider raised RateLimitError
  MODEL_TIMEOUT           provider raised APITimeoutError / generic timeout
  MODEL_CONTEXT_OVERFLOW  provider rejected request as too long for model
  TOOL_BAD_ARGUMENTS      tool-call args failed validation
  MODEL_UNKNOWN           fallback for unknown classes (still carries
                          raw_type + signature so downstream binders
                          can attribute even unknown failure modes)

Every :class:`NormalizedError` carries:

  * ``code``      -- one of the canonical strings above.
  * ``raw_type``  -- ``f"{module}.{qualname}"`` of the original exception.
  * ``signature`` -- deterministic SHA-256-prefix hex of ``raw_type`` plus
                     the normalized code; stable across runs so the
                     refresh policy can detect signature drift.
  * ``message``   -- the original exception's ``str()``.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final

# Closed set of normalized codes.
MODEL_RATE_LIMIT: Final[str] = "MODEL_RATE_LIMIT"
MODEL_TIMEOUT: Final[str] = "MODEL_TIMEOUT"
MODEL_CONTEXT_OVERFLOW: Final[str] = "MODEL_CONTEXT_OVERFLOW"
TOOL_BAD_ARGUMENTS: Final[str] = "TOOL_BAD_ARGUMENTS"
MODEL_UNKNOWN: Final[str] = "MODEL_UNKNOWN"

_NORMALIZED_CODES: Final[frozenset[str]] = frozenset(
    {
        MODEL_RATE_LIMIT,
        MODEL_TIMEOUT,
        MODEL_CONTEXT_OVERFLOW,
        TOOL_BAD_ARGUMENTS,
        MODEL_UNKNOWN,
    }
)


@dataclass(frozen=True)
class NormalizedError:
    """The structured form an adapter attaches to a failed call span."""

    code: str
    raw_type: str
    signature: str
    message: str

    def __post_init__(self) -> None:
        if self.code not in _NORMALIZED_CODES:
            raise ValueError(f"unknown normalized code: {self.code!r}")


def _raw_type(exc: BaseException) -> str:
    """Return ``module.qualname`` for the exception class."""
    cls = type(exc)
    mod = getattr(cls, "__module__", "") or ""
    name = getattr(cls, "__qualname__", "") or cls.__name__
    if mod and mod != "__main__":
        return f"{mod}.{name}"
    return name


def _signature(raw_type: str, code: str) -> str:
    """Deterministic stable signature: SHA-256(raw_type + '|' + code) prefix."""
    payload = f"{raw_type}|{code}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def _classify(
    exc: BaseException, *, context: dict[str, Any] | None
) -> str:
    """Return the normalized code for ``exc``.

    Dispatch is in priority order:

      1. Rate-limit (``RateLimitError`` class name)
      2. Timeout (``Timeout`` class name OR builtins.TimeoutError)
      3. Context overflow (provider-specific BadRequestError shape)
      4. Tool-arg validation (caller-supplied context hint or ValueError
         with 'tool' / 'argument' in the message)
      5. Fallback: MODEL_UNKNOWN
    """
    cls = type(exc)
    qual = getattr(cls, "__qualname__", "") or cls.__name__
    module = getattr(cls, "__module__", "") or ""
    lower_q = qual.lower()
    lower_m = module.lower()
    message = str(exc)

    # 1) Rate limit
    if "ratelimit" in lower_q or "rate_limit" in lower_q:
        return MODEL_RATE_LIMIT

    # 2) Timeout
    if (
        "timeout" in lower_q
        or isinstance(exc, TimeoutError)
        or (
            "httpx" in lower_m
            and "timeout" in lower_q
        )
    ):
        return MODEL_TIMEOUT

    # 3) Context overflow (provider-specific shapes)
    #    OpenAI: BadRequestError with .code == 'context_length_exceeded'.
    #    Anthropic: BadRequestError with .error_type == 'invalid_request_error'
    #               AND message contains 'too long' / 'context'.
    code_attr = getattr(exc, "code", None)
    error_type_attr = getattr(exc, "error_type", None)
    if isinstance(code_attr, str) and code_attr == "context_length_exceeded":
        return MODEL_CONTEXT_OVERFLOW
    if (
        isinstance(error_type_attr, str)
        and error_type_attr == "invalid_request_error"
        and ("too long" in message.lower() or "context" in message.lower())
    ):
        return MODEL_CONTEXT_OVERFLOW

    # 4) Tool-arg validation
    if (
        context is not None
        and context.get("tool_call") is True
        and (
            isinstance(exc, ValueError | TypeError)
            or "argument" in message.lower()
        )
    ):
        return TOOL_BAD_ARGUMENTS
    if (
        isinstance(exc, ValueError)
        and "tool" in message.lower()
        and "argument" in message.lower()
    ):
        return TOOL_BAD_ARGUMENTS

    # 5) Fallback
    return MODEL_UNKNOWN


def normalize_error(
    exc: BaseException, *, context: dict[str, Any] | None = None
) -> NormalizedError:
    """Translate a provider exception into a :class:`NormalizedError`.

    Args:
        exc: The raised exception caught around the model/tool call.
        context: Optional adapter-supplied hints. Recognised keys:
          * ``tool_call`` (bool) -- failure occurred while invoking a
            tool function rather than the model itself.

    Returns:
        A :class:`NormalizedError` carrying ``code``, ``raw_type``,
        ``signature``, ``message``.
    """
    code = _classify(exc, context=context)
    raw_type = _raw_type(exc)
    sig = _signature(raw_type, code)
    return NormalizedError(
        code=code,
        raw_type=raw_type,
        signature=sig,
        message=str(exc),
    )


__all__ = [
    "MODEL_CONTEXT_OVERFLOW",
    "MODEL_RATE_LIMIT",
    "MODEL_TIMEOUT",
    "MODEL_UNKNOWN",
    "NormalizedError",
    "TOOL_BAD_ARGUMENTS",
    "normalize_error",
]
