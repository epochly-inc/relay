"""VAL-ISO-017: side-effect idempotency key MUST be deterministic.

Bug (base commit): ``_canonical_args`` serialises (name, args, kwargs)
via ``json.dumps(..., default=str)``. For any argument value that is not
natively JSON-serialisable (a custom object without a JSON form), the
``default=str`` callback falls back to ``object.__repr__`` which yields an
ADDRESS-BEARING repr, e.g. ``<crm.Client object at 0x7f3c9a4b1d90>``. The
embedded ``id()`` is non-deterministic across runs/processes, so
``compute_idempotency_key`` produces a different key for two otherwise
identical invocations. That breaks replay idempotency (keystone #6): a
replayed side-effecting tool can no longer be matched to its original
marker.

PASS when: ``compute_idempotency_key`` / ``_canonical_args`` refuse to
fold an address-bearing repr into the key. The fix raises a typed error
requiring the caller to supply a stable key (or canonicalises via a
content-derived projection). It must NEVER silently emit an
``id()``-dependent key.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import re

import pytest
from relay.adapters._side_effects import (
    NonDeterministicIdempotencyKey,
    compute_idempotency_key,
)

# Matches the CPython default ``object.__repr__`` form, e.g.
# ``<module.Class object at 0x7f3c9a4b1d90>`` (address-bearing).
_ADDRESS_REPR = re.compile(r"<[^>]+ at 0x[0-9a-fA-F]+>")


class _OpaqueClient:
    """A client handle with no JSON representation and no stable repr.

    Uses the default ``object.__repr__`` so ``str()`` produces an
    address-bearing string. This is the realistic case of a tool that
    is invoked with a connection/handle as a positional argument.
    """


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_address_bearing_arg_does_not_yield_address_dependent_key() -> None:
    """A non-JSON arg whose ``str()`` is an address-bearing repr MUST NOT
    be folded into the idempotency key.

    At base commit this test is RED: ``compute_idempotency_key`` returns a
    hex digest computed over ``'<...object at 0x...>'`` bytes, which is
    ``id()``-dependent. We assert the deterministic contract: a typed
    refusal is raised (the caller must supply a stable key) rather than a
    silently non-deterministic digest.
    """
    client = _OpaqueClient()

    # Sanity: confirm the value really does fall back to an address-bearing
    # repr (so the test is exercising the real defect, not a strawman).
    assert _ADDRESS_REPR.search(str(client)) is not None, (
        "test precondition: _OpaqueClient must use the default "
        "address-bearing object repr"
    )

    with pytest.raises(NonDeterministicIdempotencyKey):
        compute_idempotency_key("crm.create_case", (client,), {"case_id": "c1"})


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_address_bearing_kwarg_is_also_refused() -> None:
    """The refusal applies to nested/keyword arguments too, not just the
    leading positional handle."""
    client = _OpaqueClient()
    with pytest.raises(NonDeterministicIdempotencyKey):
        compute_idempotency_key(
            "crm.create_case", (), {"handle": client, "case_id": "c1"}
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_json_serialisable_args_still_produce_stable_deterministic_key() -> None:
    """No regression: ordinary JSON-serialisable args produce a stable key
    that is byte-identical across repeated calls within and across
    processes (the digest depends only on content)."""
    k1 = compute_idempotency_key(
        "crm.create_case", ("c1",), {"priority": 3, "tags": ["a", "b"]}
    )
    k2 = compute_idempotency_key(
        "crm.create_case", ("c1",), {"priority": 3, "tags": ["a", "b"]}
    )
    assert k1 == k2
    # Different content -> different key.
    k3 = compute_idempotency_key(
        "crm.create_case", ("c2",), {"priority": 3, "tags": ["a", "b"]}
    )
    assert k1 != k3
    # The key never embeds an address-bearing repr.
    assert _ADDRESS_REPR.search(k1) is None
