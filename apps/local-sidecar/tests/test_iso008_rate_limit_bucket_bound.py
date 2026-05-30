"""VAL-ISO-008 regression: ``rate_limit_buckets`` must not grow unbounded
when keyed on attacker-controlled, unauthenticated request headers.

Bug (base commit c911607): ``_rate_limit_state`` writes
``runtime.rate_limit_buckets[key] = (window_start, count)`` for every
distinct bucket key and NEVER prunes expired/stale windows. Bucket keys
are derived from attacker-controlled inputs (``ip:<X-Forwarded-For>``,
``jwt:<bearer>``, ``project:<X-Relay-Project>``). A loop of requests each
carrying a unique ``X-Forwarded-For`` value creates a permanent entry per
value -> unbounded memory growth (DoS).

Fix: the fixed-window is 1 second (``reset_epoch = window_start + 1``), so
any entry whose ``window_start < now`` is dead. Sweep stale entries on
each access so the dict stays bounded by the number of buckets ACTIVE in
the current 1-second window, while rate-limiting for active keys is
preserved.

RED at base (dict accumulates one entry per stale key forever); GREEN
after (stale entries swept; active-key counting still works).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import pytest
from _v2m02_w25_helpers import V2M02Client, scope_header


def _bucket_count(app: object) -> int:
    return len(app.state.runtime.rate_limit_buckets)  # type: ignore[attr-defined]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-008")
@pytest.mark.asyncio
async def test_stale_buckets_swept_on_access(
    monkeypatch: pytest.MonkeyPatch,
    v2m02_client: V2M02Client,
) -> None:
    """Distinct attacker keys from PRIOR seconds must not accumulate.

    We seed many ``ip:<value>:verify`` entries whose ``window_start`` is
    in a prior second (dead windows). A single subsequent request must
    cause those dead entries to be swept rather than retained forever.
    Before the fix the dict only ever grows; after the fix it is bounded
    to the buckets touched in the current window.
    """
    from datetime import UTC, datetime

    c, _db, app = v2m02_client
    runtime = app.state.runtime  # type: ignore[attr-defined]

    # Mirror runtime._now_epoch_s(): int(datetime.now(UTC).timestamp()).
    now = int(datetime.now(UTC).timestamp())
    # Seed 5000 distinct attacker-controlled bucket keys in a window that
    # is already dead (one full second in the past).
    dead_window = now - 10
    n_attacker = 5000
    for i in range(n_attacker):
        runtime.rate_limit_buckets[f"ip:attacker-{i}:verify"] = (dead_window, 1)
    assert _bucket_count(app) >= n_attacker

    # A single legitimate request in the CURRENT window. After it runs,
    # the thousands of dead-window entries must have been swept; the dict
    # must be bounded to the small number of buckets active this second
    # (the project/jwt/ip buckets the request itself touches), NOT
    # n_attacker+.
    r = await c.put(
        "/v1/gates/g-iso008",
        json={"name": "g"},
        headers=scope_header("gates:configure"),
    )
    assert r.status_code in (200, 201), r.text

    remaining = _bucket_count(app)
    assert remaining < n_attacker, (
        f"stale buckets not swept: {remaining} entries remain "
        f"(seeded {n_attacker} dead-window entries)"
    )
    # Tight bound: only the current-window buckets touched by this single
    # request should survive (a small constant), proving real pruning.
    assert remaining <= 8, (
        f"dict not bounded to current-window buckets: {remaining} remain"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-ISO-008")
@pytest.mark.asyncio
async def test_active_window_rate_limit_still_enforced(
    monkeypatch: pytest.MonkeyPatch,
    v2m02_client: V2M02Client,
) -> None:
    """Sweeping stale windows must NOT break rate-limiting for an active
    key in the current window.

    Pin the runtime clock, seed the per-project bucket at the configured
    limit for the CURRENT (frozen) window, then issue one request: the
    middleware increments count -> limit+1 in the SAME window -> 429. This
    proves the sweep removes only PRIOR-second entries, not the live one.
    """
    from datetime import UTC, datetime

    import relay_sidecar.runtime as rt_mod

    frozen = datetime(2025, 6, 1, tzinfo=UTC)

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):  # type: ignore[override]
            return frozen if tz is None else frozen.astimezone(tz)

    monkeypatch.setattr(rt_mod, "datetime", _FrozenDateTime)
    frozen_epoch = int(frozen.timestamp())

    monkeypatch.setenv("RELAY_SIDECAR_RATELIMIT_PROJECT_RPS", "2")
    c, _db, app = v2m02_client
    runtime = app.state.runtime  # type: ignore[attr-defined]

    # A stale (prior-second) entry for the SAME key must be ignored by the
    # sweep and NOT carried into the live window's count.
    runtime.rate_limit_buckets["project:proj-iso008"] = (
        frozen_epoch - 5, 999
    )
    # And seed the CURRENT window at the limit.
    runtime.rate_limit_buckets["project:proj-iso008"] = (frozen_epoch, 2)

    hdrs = {
        **scope_header("gates:configure"),
        "X-Relay-Project": "proj-iso008",
    }
    r = await c.put("/v1/gates/g2", json={"name": "g"}, headers=hdrs)
    assert r.status_code == 429, (
        f"active-window rate limit not enforced after sweep; got "
        f"{r.status_code}"
    )
    import json

    assert json.loads(r.text)["code"] == "RELAY-RATE-001"
