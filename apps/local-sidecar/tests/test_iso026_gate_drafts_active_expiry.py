"""VAL-ISO-026 regression: ``gate_drafts_active`` is never cleared, so a
resolved/expired round permanently blocks every other worker with
409 RELAY-GATE-014 (perma-block + memory leak).

Bug (base commit c911607): ``v1_post_gate_draft`` writes
``runtime.gate_drafts_active[(gate_id, round_n)] = draft_record`` (line
~4520) and reads it to reject a second worker (line ~4471, 409
RELAY-GATE-014), but NOTHING in the file ever removes an entry. Once a
draft for (gate_id, round) is recorded, a different worker is rejected
FOREVER -- even after the draft's ``draft_ttl_seconds`` has elapsed (the
round is effectively closed) -- and the map grows without bound across
distinct (gate_id, round) pairs.

Fix: expire entries based on the gate's ``draft_ttl_seconds`` (store the
submitted epoch and treat an entry past its TTL as ABSENT, clearing it),
so a new worker is admitted after the round's TTL window closes; the
active-draft mutual exclusion still holds WITHIN the TTL window.

RED at base (second worker perma-409 even after TTL); GREEN after (second
worker admitted 202 once the first draft's TTL has elapsed, while a
within-TTL conflict still 409s).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header, seed_three_anchor_handoff

_ACTOR_HASH = "sha256-" + ("1" * 64)
_MANIFEST_HASH = "sha256-" + ("0" * 64)


async def _seed(db_path) -> None:
    await seed_three_anchor_handoff(
        db_path,
        actor_identity_hash=_ACTOR_HASH,
        manifest_commit_hash=_MANIFEST_HASH,
    )


def _draft_body(worker_id: str, round_n: int = 1) -> dict:
    return {
        "manifest_commit_hash": _MANIFEST_HASH,
        "actor_identity_hash": _ACTOR_HASH,
        "worker_id": worker_id,
        "round": round_n,
    }


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-026")
@pytest.mark.asyncio
async def test_within_ttl_conflict_still_blocks(
    v2m02_client: V2M02Client,
) -> None:
    """Within the TTL window, a different worker on the same (gate, round)
    is still rejected (mutual exclusion preserved)."""
    c, db_path, _app = v2m02_client
    await _seed(db_path)
    # A generous TTL so the second request is comfortably within window.
    await c.put(
        "/v1/gates/gate-iso026-live",
        json={"name": "g", "draft_ttl_seconds": 3600},
        headers=scope_header("gates:configure"),
    )
    r1 = await c.post(
        "/v1/gates/gate-iso026-live/drafts",
        json=_draft_body("worker-A"),
        headers=scope_header("gates:execute"),
    )
    assert r1.status_code == 202, r1.text
    r2 = await c.post(
        "/v1/gates/gate-iso026-live/drafts",
        json=_draft_body("worker-B"),
        headers=scope_header("gates:execute"),
    )
    assert r2.status_code == 409, r2.text
    assert json.loads(r2.text)["code"] == "RELAY-GATE-014"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-026")
@pytest.mark.asyncio
async def test_expired_ttl_admits_new_worker(
    v2m02_client: V2M02Client,
) -> None:
    """After the first draft's ``draft_ttl_seconds`` has elapsed, a new
    worker on the same (gate, round) must be ADMITTED (202), not
    perma-blocked with 409.

    We configure a tiny TTL and then backdate the recorded draft's
    submitted epoch so the entry is past its TTL without sleeping.
    """
    c, db_path, app = v2m02_client
    await _seed(db_path)
    runtime = app.state.runtime  # type: ignore[attr-defined]
    await c.put(
        "/v1/gates/gate-iso026-exp",
        json={"name": "g", "draft_ttl_seconds": 1},
        headers=scope_header("gates:configure"),
    )
    r1 = await c.post(
        "/v1/gates/gate-iso026-exp/drafts",
        json=_draft_body("worker-A"),
        headers=scope_header("gates:execute"),
    )
    assert r1.status_code == 202, r1.text

    # Backdate the active entry's submitted epoch so it is past its 1s TTL.
    active = runtime.gate_drafts_active[("gate-iso026-exp", 1)]
    assert "submitted_at_epoch" in active, (
        "draft record must record a numeric submitted epoch for TTL expiry"
    )
    active["submitted_at_epoch"] -= 100  # well past the 1s TTL

    r2 = await c.post(
        "/v1/gates/gate-iso026-exp/drafts",
        json=_draft_body("worker-B"),
        headers=scope_header("gates:execute"),
    )
    assert r2.status_code == 202, (
        f"new worker perma-blocked after TTL expiry (entry never cleared); "
        f"got {r2.status_code}: {r2.text}"
    )
    assert "draft_id" in json.loads(r2.text)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-026")
@pytest.mark.asyncio
async def test_same_worker_resubmit_not_blocked(
    v2m02_client: V2M02Client,
) -> None:
    """The SAME worker re-submitting for the same (gate, round) within the
    TTL is not treated as a conflict (only a DIFFERENT worker is)."""
    c, db_path, _app = v2m02_client
    await _seed(db_path)
    await c.put(
        "/v1/gates/gate-iso026-same",
        json={"name": "g", "draft_ttl_seconds": 3600},
        headers=scope_header("gates:configure"),
    )
    r1 = await c.post(
        "/v1/gates/gate-iso026-same/drafts",
        json=_draft_body("worker-A"),
        headers=scope_header("gates:execute"),
    )
    assert r1.status_code == 202, r1.text
    r2 = await c.post(
        "/v1/gates/gate-iso026-same/drafts",
        json=_draft_body("worker-A"),
        headers=scope_header("gates:execute"),
    )
    assert r2.status_code == 202, r2.text
