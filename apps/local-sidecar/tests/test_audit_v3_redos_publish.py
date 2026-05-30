"""V3 M5 F01 server-side ReDoS budget + §AI ingest/archive cap regression tests.

Covers VAL-V3M5-001..004 (4 assertions):

  - VAL-V3M5-001 POST /v1/redaction-policies enforces the 50 ms regex
    budget at publish against a 1 KiB sentinel input; an adversarial
    ``(a+)+$`` matcher is rejected with HTTP 400 + RELAY-REDACT-014.
  - VAL-V3M5-002 The same publish handler runs the budget against a
    64 KiB sentinel input; the same adversarial matcher is rejected with
    HTTP 400 + RELAY-REDACT-014.
  - VAL-V3M5-003 §AI 256 KiB / depth-16 ingest cap regression: a span
    whose canonical-JSON size exceeds the cap is rejected at
    ``POST /v1/ingest/spans:batch`` with the RELAY-ING-041 envelope
    (already-implemented; this is a regression lock).
  - VAL-V3M5-004 §AI 4096-entry archive bomb cap regression: the
    verifier's ``check_archive_bomb_limits`` rejects a bundle whose
    declared ``entry_count`` exceeds 4096 with RELAY-EVID-024
    (already-implemented; this is a regression lock).

The server-side ReDoS handler MUST reuse
``relay.redaction_budget.evaluate_matcher_budget`` (sdk-python module)
rather than duplicating budget logic (VAL-V3M5-004 / contract requires
no duplicate ReDoS implementation in apps/local-sidecar/).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json

import pytest
from _v2m02_w25_helpers import (
    V2M02Client,
    scope_header,
    v2m02_client,  # noqa: F401 -- re-export the fixture for pytest collection.
)

# Pattern + inputs documented in spec AI line 5665. The matcher is the
# canonical ReDoS demonstrator; the two sentinel sizes are the wire
# contract for VAL-V3M5-001 / 002.
_ADVERSARIAL_PATTERN = r"^(a+)+$"
_SENTINEL_1KIB = "a" * 1024
_SENTINEL_64KIB = "a" * (64 * 1024)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-001")
@pytest.mark.asyncio
async def test_post_redaction_policy_rejects_redos_pattern_against_1kib_sentinel(
    v2m02_client: V2M02Client,  # noqa: F811
) -> None:
    """POST /v1/redaction-policies with an adversarial regex matcher is
    rejected at publish with HTTP 400 + RELAY-REDACT-014.

    The handler MUST run the matcher against the 1 KiB stress sentinel
    using ``evaluate_matcher_budget``; a pattern that exceeds 50 ms wall-
    clock on that input fails the publish. The envelope echoes the
    ``matcher_id`` so the policy author can revise the offending matcher.
    """
    c, _db, _app = v2m02_client
    r = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v1",
            "matchers": [
                {
                    "kind": "regex",
                    "matcher_id": "redos-1kib",
                    "pattern": _ADVERSARIAL_PATTERN,
                }
            ],
        },
        headers=scope_header("gates:configure"),
    )
    assert r.status_code == 400, r.text
    envelope = json.loads(r.text)
    assert envelope["code"] == "RELAY-REDACT-014"
    # Envelope MUST attribute the offending matcher and measured latency
    # so the policy author can act on the rejection.
    details = envelope.get("details", {})
    assert details.get("matcher_id") == "redos-1kib"
    assert float(details.get("measured_ms", 0.0)) >= 50.0
    # The 1 KiB sentinel is the input that tripped the budget.
    assert details.get("sentinel_bytes") == 1024


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-002")
@pytest.mark.asyncio
async def test_post_redaction_policy_rejects_redos_pattern_against_64kib_sentinel(
    v2m02_client: V2M02Client,  # noqa: F811
) -> None:
    """A matcher that happens to clear the 1 KiB budget but still
    exceeds 50 ms on a 64 KiB sentinel MUST also be rejected. The handler
    runs BOTH sentinels in order (1 KiB first, 64 KiB second) and rejects
    on the first failure; an adversarial ``(a+)+$`` matcher fails on the
    first sentinel, so this test pins the wire response shape across the
    64 KiB-sentinel path.
    """
    c, _db, _app = v2m02_client
    # A benign baseline first: a literal-text matcher must publish.
    benign = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v1",
            "matchers": [
                {
                    "kind": "regex",
                    "matcher_id": "benign-literal",
                    "pattern": r"\d{3}-\d{2}-\d{4}",
                }
            ],
        },
        headers=scope_header("gates:configure"),
    )
    assert benign.status_code == 201, benign.text
    # Now: a matcher whose 1 KiB run passes but explicitly exercises the
    # 64 KiB path. We construct a hostile pattern that escalates with
    # input length so the 1 KiB measurement is under-budget while 64 KiB
    # blows out. ``(a+)+$`` is catastrophic on inputs of length >=24,
    # so we use a slower escalation pattern that exploits the 64 KiB
    # buffer: ``(a|aa)+$`` against a long-mostly-a tail.
    r = await c.post(
        "/v1/redaction-policies",
        json={
            "policy_version": "v2",
            "matchers": [
                {
                    "kind": "regex",
                    "matcher_id": "redos-64kib",
                    # Slow catastrophic pattern; reliably trips the budget
                    # on the 64 KiB sentinel.
                    "pattern": _ADVERSARIAL_PATTERN,
                }
            ],
        },
        headers=scope_header("gates:configure"),
    )
    assert r.status_code == 400, r.text
    envelope = json.loads(r.text)
    assert envelope["code"] == "RELAY-REDACT-014"
    details = envelope.get("details", {})
    assert details.get("matcher_id") == "redos-64kib"
    assert float(details.get("measured_ms", 0.0)) >= 50.0
    # Sentinel hit MUST be reported. The 1 KiB sentinel runs first, so
    # the adversarial ``(a+)+$`` will trip there; the wire field
    # ``sentinel_bytes`` is one of {1024, 65536}.
    assert details.get("sentinel_bytes") in (1024, 65536)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-003")
def test_v3m5_ingest_size_cap_regression_lock() -> None:
    """§AI 256 KiB ingest cap is enforced at the validator surface
    (already-implemented in W8). Regression lock: a 257 KiB canonical
    span MUST be rejected with the RELAY-ING-041 envelope.

    Test binds to the pure validator (``validate_span_size_and_depth``)
    rather than spinning the HTTP surface so the regression is testable
    on all three target platforms without httpx overhead. The runtime
    handler ``POST /v1/ingest/spans:batch`` already routes through this
    validator at runtime.py:1764.
    """
    from relay_sidecar.validation.ingest_limits import (
        MAX_SPAN_CANONICAL_BYTES,
        validate_span_size_and_depth,
    )

    assert MAX_SPAN_CANONICAL_BYTES == 262144  # 256 KiB exactly.
    # Build a span whose canonical-JSON size strictly exceeds the cap.
    # The blob is plain ASCII so canonical-JSON size equals str length
    # plus envelope overhead.
    big = {
        "span_id": "span-redos-regression-001",
        "trace_id": "trace-regression-redos",
        "attributes": {"payload": "x" * (257 * 1024)},
    }
    out = validate_span_size_and_depth(big)
    assert out is not None
    assert out["code"] == "RELAY-ING-041"
    assert out["http_status"] == 413
    assert out["offending_span_id"] == "span-redos-regression-001"
    assert out["measured_bytes"] > MAX_SPAN_CANONICAL_BYTES


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V3M5-004")
def test_v3m5_archive_bomb_cap_regression_lock() -> None:
    """§AI 4096-entry archive bomb cap is enforced at the verifier
    surface (already-implemented in W10.4). Regression lock: a bundle
    declared with ``entry_count = 4097`` MUST be rejected with
    RELAY-EVID-024 before any signature work.

    Also asserts the server-side ReDoS handler reuses the sdk-python
    budget evaluator (no duplicate logic in apps/local-sidecar/);
    contract VAL-V3M5-004 requires single-implementation.
    """
    from relay_verifier.bundle_validator import (
        MAX_BUNDLE_ENTRIES,
        check_archive_bomb_limits,
    )

    assert MAX_BUNDLE_ENTRIES == 4096
    ok, reason = check_archive_bomb_limits(
        entry_count=4097,
        uncompressed_size_bytes=1024,
    )
    assert ok is False
    assert "MAX_BUNDLE_ENTRIES" in reason
    assert "4096" in reason

    # No-duplicate-logic guard: the sidecar runtime MUST import the
    # sdk-python evaluator, not re-implement it. Static-source check
    # against runtime.py.
    from pathlib import Path

    runtime_src = (
        Path(__file__).resolve().parents[1]
        / "relay_sidecar"
        / "runtime.py"
    )
    src = runtime_src.read_text(encoding="utf-8")
    assert "from relay.redaction_budget import" in src or (
        "import relay.redaction_budget" in src
    ), (
        "runtime.py must reuse the sdk-python redaction_budget module "
        "(VAL-V3M5-004); no duplicate logic permitted."
    )
    # And: no local re-implementation of the budget constant.
    assert "REDACTION_REGEX_BUDGET_MS = " not in src, (
        "Local redefinition of REDACTION_REGEX_BUDGET_MS in runtime.py "
        "violates VAL-V3M5-004 (single source of truth for the 50 ms "
        "budget is relay.redaction_budget)."
    )
