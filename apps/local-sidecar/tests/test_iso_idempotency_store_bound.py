"""Regression: the in-memory ``idempotency_store`` must not grow unbounded
when keyed on the attacker-controlled HTTP ``Idempotency-Key``.

Bug: ``_store_idempotency`` writes
``runtime.idempotency_store[surface][key] = {...}`` for every distinct
(surface, Idempotency-Key) and NEVER prunes. The Idempotency-Key is
attacker-controlled with effectively unlimited cardinality (26-char
Crockford ULID grammar). An authenticated client streaming distinct keys
grows the in-memory map without bound, each entry carrying the full
response_body -> authenticated memory-exhaustion DoS. The DB-backed
``idempotency_records`` table HAS a 24h TTL but the in-memory map did not.

Fix mirrors the existing hardening for the same attack class: the nonce
store (``_prune_nonce_store`` + ``MAX_ISSUED_NONCES`` in health.py) and the
rate-limit bucket stale sweep (``_rate_limit_state`` in runtime.py). Each
in-memory idempotency record is stamped with an insertion time; a TTL sweep
(same 24h TTL the DB layer uses) plus a hard size cap (oldest-first
eviction) run on every ``_store_idempotency`` so the map stays bounded.

RED at base (the map accumulates one permanent entry per distinct key, with
no TTL sweep and no size cap); GREEN after (stale and over-cap entries are
swept while the in-memory replay semantics for live keys are preserved).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
import relay_sidecar.runtime as rt_mod
from relay_sidecar.runtime import (
    IDEMPOTENCY_RECORD_TTL_S,
    MAX_IDEMPOTENCY_RECORDS,
    _prune_idempotency_store,
)


def _total_entries(store: dict[str, dict[str, dict[str, object]]]) -> int:
    return sum(len(per_surface) for per_surface in store.values())


@pytest.mark.plumbing
def test_size_cap_evicts_oldest_first() -> None:
    """Entries past the hard size cap are evicted oldest-first.

    Seed more than ``MAX_IDEMPOTENCY_RECORDS`` records across surfaces, all
    inside the TTL window, then prune. The survivor count must be bounded by
    the cap, and the OLDEST (smallest insertion stamp) entries are the ones
    evicted -- the newest survive.
    """
    now = 1_000_000.0
    store: dict[str, dict[str, dict[str, object]]] = {}
    overflow = 500
    total = MAX_IDEMPOTENCY_RECORDS + overflow
    for i in range(total):
        surface = f"PUT /v1/gates/g{i % 4}"
        per_surface = store.setdefault(surface, {})
        # Older entries get smaller stamps; all well within the TTL window.
        per_surface[f"key-{i:08d}"] = {
            "request_digest": "sha256-" + ("0" * 64),
            "response_status": 201,
            "response_body": {"i": i},
            "_stored_at_epoch_s": now - (total - i),
        }
    assert _total_entries(store) == total

    _prune_idempotency_store(store, now=now, ttl_s=IDEMPOTENCY_RECORD_TTL_S)

    assert _total_entries(store) == MAX_IDEMPOTENCY_RECORDS, (
        "size cap not enforced: "
        f"{_total_entries(store)} entries remain (cap "
        f"{MAX_IDEMPOTENCY_RECORDS})"
    )
    # The oldest ``overflow`` entries (i in [0, overflow)) must be gone; the
    # newest must survive.
    survivors = {
        key for per_surface in store.values() for key in per_surface
    }
    assert "key-00000000" not in survivors  # oldest evicted
    assert f"key-{total - 1:08d}" in survivors  # newest survives


@pytest.mark.plumbing
def test_ttl_sweep_drops_expired_entries() -> None:
    """An entry past its TTL is swept regardless of the size cap."""
    now = 1_000_000.0
    store: dict[str, dict[str, dict[str, object]]] = {}
    surface = "POST /v1/manifests"
    per_surface = store.setdefault(surface, {})
    # One fresh entry (age 0) and one expired entry (age > TTL).
    per_surface["fresh"] = {
        "request_digest": "sha256-" + ("1" * 64),
        "response_status": 201,
        "response_body": {"ok": True},
        "_stored_at_epoch_s": now,
    }
    per_surface["expired"] = {
        "request_digest": "sha256-" + ("2" * 64),
        "response_status": 201,
        "response_body": {"ok": True},
        "_stored_at_epoch_s": now - IDEMPOTENCY_RECORD_TTL_S - 1.0,
    }
    assert _total_entries(store) == 2

    _prune_idempotency_store(store, now=now, ttl_s=IDEMPOTENCY_RECORD_TTL_S)

    assert "expired" not in per_surface, "expired entry was not swept"
    assert "fresh" in per_surface, "fresh entry was wrongly swept"
    assert _total_entries(store) == 1


@pytest.mark.plumbing
def test_db_ttl_matches_in_memory_ttl() -> None:
    """The in-memory TTL constant equals the DB-layer 24h TTL so the two
    stay consistent (same key returns the cached response within TTL)."""
    assert IDEMPOTENCY_RECORD_TTL_S == 24 * 60 * 60
    # Sanity: the prune helper and constants are exported from runtime.
    assert callable(rt_mod._prune_idempotency_store)
    assert MAX_IDEMPOTENCY_RECORDS > 0
