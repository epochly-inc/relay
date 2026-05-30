"""VAL-IDEMP-002: idempotency check-then-store TOCTOU -> duplicate execution.

Bug (base commit c911607): ``_check_idempotency`` (the read) and
``_store_idempotency`` (the write) are SEPARATE steps with multiple ``await``
points (body parse, reader.execute for the actors/manifest anchor tables,
validate_three_anchor_handoff) in between. On a cache miss neither call
RESERVES the canonical idempotency key. So two concurrent requests carrying the
SAME (surface, Idempotency-Key) BOTH observe "no record" before either reaches
``_store_idempotency`` -- both pass the miss branch, both execute the write
handler body, both create a distinct draft / round / bundle. That is duplicate
execution of a write handler (keystone invariant #6: side-effect idempotency).

PASS when: the cache-miss path RESERVES the key atomically (an in-flight
"pending" marker inserted synchronously, with no ``await`` between the miss
check and the reservation write, so it is atomic within the single-threaded
asyncio event loop). The race LOSER must WAIT for the winner and then REPLAY
the winner's stored response (Idempotent-Replay: true), or receive a 409 --
it must NOT execute the handler body a second time.

Scope of the fix is documented in the helper docstring: the in-process
reservation closes the asyncio TOCTOU (the surface this finding's trigger
exercises -- two concurrent coroutines in ONE sidecar process). The DB-backed
``idempotency_records`` UNIQUE primary key (written through
``transactional_db_write_raw``) remains the cross-process backstop on the final
store.

RED at base commit c911607 (two concurrent same-key gate-draft requests BOTH
return 202 with DISTINCT draft_ids -> the handler executed twice). GREEN after
the fix (exactly one 202 with a fresh draft_id; the loser replays that SAME
draft_id with Idempotent-Replay: true; only ONE gate round was opened).

A separate sequential case proves the legitimate replay path still works after
the reservation change (genuine retry of the same key replays the stored
result).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import httpx
import pytest
from _v2m02_w25_helpers import scope_header, seed_three_anchor_handoff

# One valid Crockford-base32 ULID Idempotency-Key shared by the racing pair so
# the ONLY thing under test is the check-then-store reservation, not key
# derivation.
_RACE_KEY = "01HZX9F8K7M3N4P5Q6R7S8T9V0"

# Anchors for the gate-draft POSTs. VAL-ISO-003 made the three-anchor
# handoff validator run unconditionally (fail closed on unseeded
# registries), so the draft-posting tests must seed a valid actor +
# active manifest matching these hashes.
_DRAFT_MANIFEST_HASH = "sha256-" + ("0" * 64)
_DRAFT_ACTOR_HASH = "sha256-" + ("1" * 64)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-002")
@pytest.mark.asyncio
async def test_concurrent_same_key_gate_draft_executes_exactly_once(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """Race two concurrent POST /v1/gates/G/drafts with the SAME
    (surface, Idempotency-Key, body). Exactly ONE must execute the handler
    body; the other must REPLAY it (or 409), never double-execute.

    The handler-body side effect we count is the creation of a gate ROUND:
    a second execution appends a second entry to ``runtime.gate_rounds[gate]``.
    Exactly-once <=> exactly one round opened for the gate.
    """
    c, db_path, app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    headers = {
        **scope_header("gates:execute"),
        "Idempotency-Key": _RACE_KEY,
    }
    body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "round": 1,
    }

    # Fire both concurrently so they interleave at the post-check awaits.
    r1, r2 = await asyncio.gather(
        c.post("/v1/gates/race-gate/drafts", json=body, headers=headers),
        c.post("/v1/gates/race-gate/drafts", json=body, headers=headers),
    )

    statuses = sorted((r1.status_code, r2.status_code))
    # Both calls succeed at the HTTP layer (the loser replays a 202 or is a
    # 409 conflict on the reused key). Neither is a 5xx.
    assert all(s < 500 for s in statuses), (r1.text, r2.text)

    # The winner returns a fresh 202; the loser must NOT be served a SECOND
    # freshly-executed 202 with a DISTINCT draft_id. Either it replays the
    # winner's draft_id (Idempotent-Replay: true) or it is a 409.
    draft_ids = []
    replay_flags = []
    for r in (r1, r2):
        if r.status_code == 202:
            draft_ids.append(r.json()["draft_id"])
            replay_flags.append(r.headers.get("idempotent-replay") == "true")

    # At least one 202 (the winner). Every 202 draft_id must be identical:
    # a distinct second draft_id is the duplicate-execution signature.
    assert draft_ids, (r1.text, r2.text)
    assert len(set(draft_ids)) == 1, (
        "concurrent same-key requests produced DISTINCT draft_ids "
        f"{draft_ids!r} -> the write handler executed twice (TOCTOU window "
        "between _check_idempotency and _store_idempotency was not closed)"
    )

    # If both came back 202, exactly one must be a fresh execution and the
    # other a replay (Idempotent-Replay: true).
    if len(replay_flags) == 2:
        assert sum(replay_flags) == 1, (
            "two 202 responses but not exactly one was an idempotent replay "
            f"(replay flags = {replay_flags!r}) -> handler ran twice"
        )

    # The decisive exactly-once invariant: only ONE gate round was opened
    # for the gate, regardless of how the loser was served.
    runtime = cast(Any, app).state.runtime
    rounds = runtime.gate_rounds.get("race-gate", [])
    assert len(rounds) == 1, (
        f"expected exactly ONE gate round opened, found {len(rounds)} -> the "
        "write handler body executed more than once under the same key"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-002")
@pytest.mark.asyncio
async def test_sequential_same_key_retry_still_replays(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """A genuine SEQUENTIAL retry (same key, same body, after the first
    completes) MUST still replay the stored result. The reservation change
    must not break the legitimate idempotent-replay path.
    """
    c, db_path, app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    headers = {
        **scope_header("gates:execute"),
        "Idempotency-Key": _RACE_KEY,
    }
    body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "round": 1,
    }

    r1 = await c.post("/v1/gates/seq-gate/drafts", json=body, headers=headers)
    assert r1.status_code == 202, r1.text
    first = r1.json()

    r2 = await c.post("/v1/gates/seq-gate/drafts", json=body, headers=headers)
    assert r2.status_code == 202, r2.text
    assert r2.headers.get("idempotent-replay") == "true", (
        "sequential same-key retry was NOT served as an idempotent replay -- "
        "the reservation change broke the legitimate replay path"
    )
    assert r2.json() == first

    # Exactly one round opened across both calls.
    runtime = cast(Any, app).state.runtime
    rounds = runtime.gate_rounds.get("seq-gate", [])
    assert len(rounds) == 1, (
        f"sequential retry opened {len(rounds)} rounds; replay must not "
        "re-execute the handler body"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-IDEMP-002")
@pytest.mark.asyncio
async def test_aborted_winner_does_not_wedge_the_key(
    v2m02_client: tuple[httpx.AsyncClient, object, object],
) -> None:
    """If the request that reserves a key ABORTS before storing (an early
    validation 422 that never calls _store_idempotency), the reservation must
    be released so a later genuine request with the SAME key can still
    execute. The reservation must be self-healing, not a permanent wedge.
    """
    c, db_path, app = v2m02_client
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_DRAFT_ACTOR_HASH,
        manifest_commit_hash=_DRAFT_MANIFEST_HASH,
    )
    headers = {
        **scope_header("gates:execute"),
        "Idempotency-Key": _RACE_KEY,
    }
    # First request is missing manifest_commit_hash -> 422 early-return that
    # never reaches _store_idempotency.
    bad_body = {"actor_identity_hash": _DRAFT_ACTOR_HASH, "round": 1}
    r_bad = await c.post(
        "/v1/gates/wedge-gate/drafts", json=bad_body, headers=headers
    )
    assert r_bad.status_code == 422, r_bad.text

    # A later well-formed request with the SAME key must NOT be wedged on the
    # stale reservation: it must execute and return a fresh 202.
    good_body = {
        "manifest_commit_hash": _DRAFT_MANIFEST_HASH,
        "actor_identity_hash": _DRAFT_ACTOR_HASH,
        "round": 1,
    }
    r_good = await c.post(
        "/v1/gates/wedge-gate/drafts", json=good_body, headers=headers
    )
    assert r_good.status_code == 202, (
        "a later good request was wedged on a stale reservation left by an "
        f"aborted request (got {r_good.status_code}: {r_good.text})"
    )
    runtime = cast(Any, app).state.runtime
    rounds = runtime.gate_rounds.get("wedge-gate", [])
    assert len(rounds) == 1, rounds
