"""Pure-only UDF registry for the Relay CEL profile.

CLAUDE.md banned pattern #16: every Relay UDF MUST be ``pure``: no wall
clock, no network, no filesystem reads outside the inputs, no
locale-dependent comparisons, no mutable process globals, no random
sources. This module provides the single registration entry point that
the rest of ``packages/contracts/`` consumes; passing ``pure=False``
raises :class:`RelayUdfPurityError` at registration time so the
non-determinism cannot reach evaluation.

VAL-W6-004 binds: a guard test attempts to register ``pure=False`` and
asserts the registration call raises before the UDF can be invoked.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import RelayUdfPurityError


@dataclass(frozen=True)
class PureUdf:
    """A registered, pure-only UDF.

    ``name`` is the identifier the CEL expression invokes (e.g.,
    ``relay.coverage``). ``fn`` is the Python callable bound at
    evaluation time. ``arity`` is the fixed positional-argument count
    (variadic UDFs are not supported in v0.1; spec D.4 / D.2 / D-coverage
    fix the arity per UDF).
    """

    name: str
    fn: Callable[..., Any]
    arity: int


def register_udf(
    name: str,
    fn: Callable[..., Any],
    *,
    pure: bool,
    arity: int,
) -> PureUdf:
    """Register a UDF for the Relay CEL evaluator.

    ``pure`` MUST be ``True``. Passing ``pure=False`` raises
    :class:`RelayUdfPurityError` immediately -- the UDF is never
    constructed and never reaches evaluation. This enforces CLAUDE.md
    banned pattern #16 structurally rather than via review.

    The kwarg form (``pure=`` / ``arity=``) is mandatory; positional
    purity flags are easy to flip by accident in a refactor and would
    silently regress the invariant.
    """

    if not isinstance(pure, bool):
        # Truthy non-bool ("yes", 1, [True]) is a category error, not a
        # purity claim. Reject explicitly to avoid silent coercion.
        raise RelayUdfPurityError(
            f"register_udf({name!r}): 'pure' MUST be a bool; got {type(pure).__name__}"
        )
    if pure is not True:
        raise RelayUdfPurityError(
            f"register_udf({name!r}): 'pure' MUST be True; got {pure!r}. "
            "CLAUDE.md banned pattern #16: non-deterministic UDFs are forbidden."
        )
    if not isinstance(name, str) or not name:
        raise RelayUdfPurityError(
            f"register_udf: 'name' MUST be a non-empty string; got {name!r}"
        )
    if not callable(fn):
        raise RelayUdfPurityError(
            f"register_udf({name!r}): 'fn' MUST be callable; got {type(fn).__name__}"
        )
    if not isinstance(arity, int) or arity < 0:
        raise RelayUdfPurityError(
            f"register_udf({name!r}): 'arity' MUST be a non-negative int; got {arity!r}"
        )
    return PureUdf(name=name, fn=fn, arity=arity)
