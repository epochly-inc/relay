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
import subprocess
import sys

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


# ---------------------------------------------------------------------------
# sdk-python-run-002: set/frozenset args must be hash-seed-independent.
#
# Bug: ``_strict_default`` (and the non-strict default) fall back to
# ``str(value)`` for a set/frozenset. ``str({...})`` renders elements in
# CPython hash-iteration order, which is salted by ``PYTHONHASHSEED``. So
# ``compute_idempotency_key`` folds a process-hash-ordered string into the
# SHA-256 and the resulting key DIFFERS across processes with different
# seeds. In a replayed run (fresh process, different seed) the recomputed
# key no longer matches the persisted pre_action/post_success_proof marker
# and ``validate_pairing`` rejects the pairing -- the side-effect
# idempotency keystone (#6) breaks.
# ---------------------------------------------------------------------------

# Computes the key for a tool whose kwarg is a set built by inserting the
# same three elements; prints the hex digest. Run under differing
# PYTHONHASHSEED to prove the digest is (or is not) seed-invariant.
_SUBPROC_SNIPPET = (
    "from relay.adapters._side_effects import compute_idempotency_key;"
    "print(compute_idempotency_key("
    "'crm.create_case', ('c1',), {'tags': {'urgent', 'vip', 'escalated'}}))"
)


def _key_under_hashseed(seed: str) -> str:
    """Compute the set-arg idempotency key in a FRESH subprocess pinned to
    ``PYTHONHASHSEED=seed``.

    A subprocess is the only faithful reproduction of the replay scenario:
    set iteration order is fixed for the life of a process by the hash
    seed, so two seeds must run in two processes to expose the defect.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _SUBPROC_SNIPPET],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PYTHONHASHSEED": seed, "PATH": __import__("os").environ.get("PATH", "")},
        check=True,
    )
    return proc.stdout.strip()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_set_arg_key_is_hash_seed_invariant_across_processes() -> None:
    """A set/frozenset argument MUST yield the SAME idempotency key in two
    processes started with different ``PYTHONHASHSEED`` values.

    At base commit this is RED: ``str(set)`` renders elements in
    hash-seed-salted iteration order, so the SHA-256 differs per seed.
    """
    key_seed1 = _key_under_hashseed("1")
    key_seed2 = _key_under_hashseed("2")
    # Both must be real digests (subprocess imported relay successfully).
    assert len(key_seed1) == 64, f"unexpected digest: {key_seed1!r}"
    assert len(key_seed2) == 64, f"unexpected digest: {key_seed2!r}"
    assert key_seed1 == key_seed2, (
        "set-arg idempotency key is NOT hash-seed-invariant: "
        f"PYTHONHASHSEED=1 -> {key_seed1}, PYTHONHASHSEED=2 -> {key_seed2}; "
        "str(set) iteration order leaked into the digest"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_set_arg_key_is_insertion_order_invariant() -> None:
    """Two sets with identical elements inserted in different orders MUST
    produce identical idempotency keys (content-addressed, not order)."""
    a = set()
    for e in ("urgent", "vip", "escalated"):
        a.add(e)
    b = set()
    for e in ("escalated", "urgent", "vip"):
        b.add(e)
    ka = compute_idempotency_key("crm.create_case", ("c1",), {"tags": a})
    kb = compute_idempotency_key("crm.create_case", ("c1",), {"tags": b})
    assert ka == kb
    # Different set contents must still produce a different key.
    kc = compute_idempotency_key(
        "crm.create_case", ("c1",), {"tags": {"urgent", "vip"}}
    )
    assert ka != kc


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-017")
def test_frozenset_and_nested_set_of_dict_are_canonicalised() -> None:
    """frozenset args and sets nested inside dict/list values must also be
    canonicalised deterministically (recursive), not str()-rendered in
    hash order."""
    fa = compute_idempotency_key(
        "crm.tag", (), {"labels": frozenset({"a", "b", "c"})}
    )
    fb = compute_idempotency_key(
        "crm.tag", (), {"labels": frozenset({"c", "a", "b"})}
    )
    assert fa == fb
    # A set nested under a dict value -> still order-invariant.
    na = compute_idempotency_key(
        "crm.tag", (), {"meta": {"labels": {"x", "y", "z"}}}
    )
    nb = compute_idempotency_key(
        "crm.tag", (), {"meta": {"labels": {"z", "y", "x"}}}
    )
    assert na == nb
