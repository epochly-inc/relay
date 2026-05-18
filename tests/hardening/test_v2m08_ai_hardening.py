"""Tier-1 plumbing tests for M08-W8 w8-ai-hardening (VAL-V2M08-001..019).

Spec anchors: AI lines 5651-5732 (adversarial / i18n / abuse).
Contract: /Users/chandlervaughn/.ops-runtime/relay-v0.2-oss-completeness/contract.md
Sub-feature: w8-ai-hardening (19 assertions).

The tests bind directly to the public API of each hardening module:

  - ``relay_schemas.error_code_registry`` for the 5 new error codes
    (VAL-V2M08-001, 004, 006, 008, 009).
  - ``relay_sidecar.validation.ingest_limits`` for the 256 KiB span size +
    depth-16 nesting checks (VAL-V2M08-002, 003).
  - ``relay_sidecar.validation.ingest_utf8`` for the UTF-8 indexed-field
    check (VAL-V2M08-010).
  - ``relay.network_policy`` for the SSRF egress allowlist
    (VAL-V2M08-011..014).
  - ``relay_verifier.bundle_paths`` for the path-traversal hardening
    (VAL-V2M08-015..017).
  - ``relay_sidecar.validation.clock_skew`` for the +/-300 s window
    (VAL-V2M08-007).
  - The redaction publish path's 50 ms ReDoS budget
    (VAL-V2M08-005, exercised via ``relay.redaction.evaluate_matcher_budget``).
  - ``relay_sidecar.gate.aggregator`` for the matrix release-decision
    aggregator (VAL-V2M08-018, 019).

ASCII-only per CLAUDE.md "ASCII-Safe Source". Every test is decorated
with ``@pytest.mark.plumbing`` + ``@pytest.mark.fulfills("VAL-V2M08-NNN")``
so the contract gate can attribute each pass to its assertion.
"""

from __future__ import annotations

import json
import unicodedata

import pytest

# -----------------------------------------------------------------------------
# VAL-V2M08-001 / 004 / 006 / 008 / 009: 5 new error codes registered
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-001")
def test_relay_ing_041_registered_with_category_and_template() -> None:
    """RELAY-ING-041 must be present in the registry with category=ingest,
    http_status=413, and a message_template that references both the
    256 KiB and depth-16 limits."""
    from relay_schemas.error_code_registry import (
        get_code_details,
        load_codes,
    )

    assert "RELAY-ING-041" in load_codes()
    detail = get_code_details("RELAY-ING-041")
    assert detail is not None
    assert detail.category == "ingest"
    assert detail.http_status == 413
    assert detail.message_template is not None
    tmpl = detail.message_template
    # Template must mention BOTH the size cap and the depth cap.
    assert "256 KiB" in tmpl
    assert "depth-16" in tmpl


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-004")
def test_relay_redact_014_registered_with_50ms_budget() -> None:
    """RELAY-REDACT-014 must be present with category=redaction,
    http_status=422, and a message_template that names the 50 ms budget."""
    from relay_schemas.error_code_registry import (
        get_code_details,
        load_codes,
    )

    assert "RELAY-REDACT-014" in load_codes()
    detail = get_code_details("RELAY-REDACT-014")
    assert detail is not None
    assert detail.category == "redaction"
    assert detail.http_status == 422
    assert detail.message_template is not None
    assert "50 ms" in detail.message_template


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-006")
def test_relay_auth_017_registered_for_clock_skew() -> None:
    """RELAY-AUTH-017 must be present with category=auth, http_status=401,
    and a message_template that names a remediation hint (NTP / time sync)
    and the +/-300 s window."""
    from relay_schemas.error_code_registry import (
        get_code_details,
        load_codes,
    )

    assert "RELAY-AUTH-017" in load_codes()
    detail = get_code_details("RELAY-AUTH-017")
    assert detail is not None
    assert detail.category == "auth"
    assert detail.http_status == 401
    assert detail.message_template is not None
    tmpl = detail.message_template
    assert "300 s" in tmpl
    assert "NTP" in tmpl


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-008")
def test_relay_auth_022_registered_with_out_of_scope_marker() -> None:
    """RELAY-AUTH-022 must be present with category=auth, http_status=403,
    and a description that flags [OUT-OF-SCOPE-PRIVATE] for the enforcement
    path."""
    from relay_schemas.error_code_registry import (
        get_code_details,
        load_codes,
    )

    assert "RELAY-AUTH-022" in load_codes()
    detail = get_code_details("RELAY-AUTH-022")
    assert detail is not None
    assert detail.category == "auth"
    assert detail.http_status == 403
    assert "[OUT-OF-SCOPE-PRIVATE]" in detail.description


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-009")
def test_relay_ing_045_registered_for_invalid_utf8() -> None:
    """RELAY-ING-045 must be present with category=ingest, http_status=400,
    and a message_template that names the offending field path."""
    from relay_schemas.error_code_registry import (
        get_code_details,
        load_codes,
    )

    assert "RELAY-ING-045" in load_codes()
    detail = get_code_details("RELAY-ING-045")
    assert detail is not None
    assert detail.category == "ingest"
    assert detail.http_status == 400
    assert detail.message_template is not None
    assert "{field_path}" in detail.message_template


# -----------------------------------------------------------------------------
# VAL-V2M08-002 / 003: 256 KiB canonical-JSON + depth-16 nesting limit
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-002")
def test_ingest_rejects_span_above_256_kib() -> None:
    """A span whose canonical-JSON serialization strictly exceeds 262144
    bytes is rejected with RELAY-ING-041 + offending_span_id +
    measured_bytes; a 262143-byte span is accepted."""
    from relay_sidecar.validation.ingest_limits import (
        MAX_SPAN_CANONICAL_BYTES,
        validate_span_size_and_depth,
    )

    assert MAX_SPAN_CANONICAL_BYTES == 262144

    # Build a span whose attributes string fills to exactly the cap.
    span_id = "01JG2YINGEST00000000000000"
    base = {"span_id": span_id, "attributes": {"x": ""}}
    base_bytes = len(json.dumps(base, separators=(",", ":")).encode("utf-8"))
    # filler length so that total canonical-JSON == 262144 + 1 (just over).
    filler_len = MAX_SPAN_CANONICAL_BYTES + 1 - base_bytes
    assert filler_len > 0, "test span shape produced no headroom"
    over = {"span_id": span_id, "attributes": {"x": "A" * filler_len}}
    out = validate_span_size_and_depth(over)
    assert out is not None
    assert out["code"] == "RELAY-ING-041"
    assert out["offending_span_id"] == span_id
    assert out["measured_bytes"] > MAX_SPAN_CANONICAL_BYTES

    # 262143-byte span (just under the cap) is accepted.
    filler_len_under = MAX_SPAN_CANONICAL_BYTES - 1 - base_bytes
    assert filler_len_under > 0
    ok = {"span_id": span_id, "attributes": {"x": "A" * filler_len_under}}
    ok_canon = json.dumps(ok, separators=(",", ":")).encode("utf-8")
    assert len(ok_canon) == MAX_SPAN_CANONICAL_BYTES - 1
    assert validate_span_size_and_depth(ok) is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-003")
def test_ingest_rejects_depth_17_accepts_depth_16() -> None:
    """A span nested 17 levels deep is rejected with RELAY-ING-041 +
    reason=nesting_depth_exceeded; depth-16 is accepted."""
    from relay_sidecar.validation.ingest_limits import (
        MAX_SPAN_NESTING_DEPTH,
        validate_span_size_and_depth,
    )

    assert MAX_SPAN_NESTING_DEPTH == 16
    span_id = "01JG2YINGEST00000000000017"

    def nested(depth: int) -> dict:
        node: dict = {"leaf": 1}
        for _ in range(depth - 1):
            node = {"child": node}
        return node

    # depth 17 (17 nested attributes) -> rejected.
    over = {"span_id": span_id, "attributes": nested(17)}
    out = validate_span_size_and_depth(over)
    assert out is not None
    assert out["code"] == "RELAY-ING-041"
    assert out["offending_span_id"] == span_id
    assert out["reason"] == "nesting_depth_exceeded"

    # depth 16 -> accepted.
    ok = {"span_id": span_id, "attributes": nested(16)}
    assert validate_span_size_and_depth(ok) is None


# -----------------------------------------------------------------------------
# VAL-V2M08-005: ReDoS regex budget (50 ms per-input)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-005")
def test_redos_regex_budget_50ms_rejects_catastrophic_pattern() -> None:
    """A catastrophic-backtracking regex applied to a stress input is
    rejected with RELAY-REDACT-014 and a measured_ms over the 50 ms cap;
    a benign regex passes."""
    from relay.redaction_budget import (
        REDACTION_REGEX_BUDGET_MS,
        evaluate_matcher_budget,
    )

    assert REDACTION_REGEX_BUDGET_MS == 50

    # Classic catastrophic-backtracking pattern + adversarial input.
    bad_pattern = r"^(a+)+$"
    bad_input = "a" * 30 + "X"
    bad = evaluate_matcher_budget(
        matcher_id="bad_matcher",
        pattern=bad_pattern,
        stress_inputs=[bad_input],
    )
    assert bad is not None
    assert bad["code"] == "RELAY-REDACT-014"
    assert bad["matcher_id"] == "bad_matcher"
    assert bad["measured_ms"] >= REDACTION_REGEX_BUDGET_MS

    # Benign pattern under the budget.
    good = evaluate_matcher_budget(
        matcher_id="good_matcher",
        pattern=r"\d{3}-\d{2}-\d{4}",
        stress_inputs=["123-45-6789", "abc def"],
    )
    assert good is None


# -----------------------------------------------------------------------------
# VAL-V2M08-007: clock-skew rejection (uses RELAY-AUTH-017 envelope)
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-007")
def test_clock_skew_rejects_outside_300s_window() -> None:
    """A request whose claim is +301 s / -301 s outside server now() is
    rejected with RELAY-AUTH-017; +299 s is accepted. Envelope carries
    both server_now_utc and client_claim_utc."""
    from relay_sidecar.validation.clock_skew import (
        CLOCK_SKEW_WINDOW_S,
        check_clock_skew,
    )

    assert CLOCK_SKEW_WINDOW_S == 300

    server_now = 1_700_000_000
    # +301 s -> reject
    res = check_clock_skew(
        server_now_unix=server_now,
        client_claim_unix=server_now + 301,
    )
    assert res is not None
    assert res["code"] == "RELAY-AUTH-017"
    assert res["server_now_utc"].endswith("Z")
    assert res["client_claim_utc"].endswith("Z")

    # -301 s -> reject
    res2 = check_clock_skew(
        server_now_unix=server_now,
        client_claim_unix=server_now - 301,
    )
    assert res2 is not None
    assert res2["code"] == "RELAY-AUTH-017"

    # +299 s -> accept
    assert (
        check_clock_skew(
            server_now_unix=server_now,
            client_claim_unix=server_now + 299,
        )
        is None
    )


# -----------------------------------------------------------------------------
# VAL-V2M08-010: invalid UTF-8 in indexed fields
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-010")
def test_ingest_rejects_invalid_utf8_in_indexed_field() -> None:
    """Span carrying invalid UTF-8 in an indexed field is rejected with
    RELAY-ING-045 + field_path; valid NFC is accepted."""
    from relay_sidecar.validation.ingest_utf8 import (
        DEFAULT_INDEXED_STRING_FIELDS,
        validate_indexed_utf8,
    )

    # Default index list MUST include the canonical 4 fields.
    for field in ("prompt_template_id", "tool_name", "model", "retriever_name"):
        assert field in DEFAULT_INDEXED_STRING_FIELDS

    # bytes-not-valid-UTF-8 -> reject. Use the JSON-friendly "raw bytes
    # arrived" path: many WSGI/asgi frameworks decode body bytes via
    # 'utf-8'. We simulate the raw-bytes-as-attribute path by passing
    # a bytes value directly through the validator's bytes accessor.
    bad = validate_indexed_utf8(
        {
            "tool_name": b"\xff\xfe\xfd",  # lone surrogate / invalid UTF-8
        }
    )
    assert bad is not None
    assert bad["code"] == "RELAY-ING-045"
    assert bad["field_path"] == "tool_name"

    # Lone-surrogate code-point in a Python str (already a unicode
    # surrogate; UTF-8-encoding it would raise UnicodeEncodeError) -> reject.
    bad2 = validate_indexed_utf8(
        {
            "model": "\ud800",  # lone surrogate
        }
    )
    assert bad2 is not None
    assert bad2["code"] == "RELAY-ING-045"

    # Valid NFC -> accept.
    assert (
        validate_indexed_utf8(
            {
                "prompt_template_id": "tmpl-001",
                "tool_name": "search.web",
                "model": "gpt-4o",
                "retriever_name": "docs-faiss",
            }
        )
        is None
    )


# -----------------------------------------------------------------------------
# VAL-V2M08-011..014: SSRF egress allowlist denies
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-011")
def test_egress_allowlist_denies_10_8() -> None:
    """RFC 1918 10.0.0.0/8 entries are rejected; boundary samples
    10.0.0.1 + 10.255.255.254 both denied; 9.255.255.255 (outside) ok."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in ("http://10.0.0.5:8080", "10.0.0.1", "10.255.255.254"):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["code"] == "RELAY-REPLAY-SSRF"
        assert env["denied_entry"] == host

    # Outside 10/8 + outside every reserved range -> ok. Audit-r3
    # BUG-B1 tightened the guard so RFC 5737 documentation ranges
    # (192.0.2/24, 198.51.100/24, 203.0.113/24) are now rejected (the
    # stdlib flags them ``is_private=True``); use a genuinely public
    # routable address for the negative path.
    validate_egress_entries(["http://1.1.1.1/"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-012")
def test_egress_allowlist_denies_172_16_12() -> None:
    """RFC 1918 172.16/12 entries are rejected; 172.32.0.1 (outside) ok."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in ("http://172.20.5.5/", "172.16.0.1", "172.31.255.254"):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        assert exc.value.envelope["denied_entry"] == host

    # 172.32.0.1 is outside 172.16.0.0/12 (and outside RFC 1918) -> ok.
    validate_egress_entries(["172.32.0.1"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-013")
def test_egress_allowlist_denies_192_168_16() -> None:
    """RFC 1918 192.168/16 entries rejected; 192.169.0.1 (outside) ok."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    for host in ("192.168.0.1", "192.168.255.254"):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        assert exc.value.envelope["denied_entry"] == host

    validate_egress_entries(["192.169.0.1"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-014")
def test_egress_allowlist_denies_link_local_and_cloud_metadata() -> None:
    """169.254/16 (link-local) and the well-known cloud-metadata
    endpoints are rejected with denied_reason values; outside addresses
    are accepted."""
    from relay.network_policy import EgressDenied, validate_egress_entries

    # Cloud metadata well-known addresses.
    metadata_cases = [
        ("169.254.169.254", "cloud_metadata"),
        ("100.100.100.200", "cloud_metadata"),
        ("fd00:ec2::254", "cloud_metadata"),
    ]
    for host, reason in metadata_cases:
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([host])
        env = exc.value.envelope
        assert env["denied_entry"] == host
        assert env["denied_reason"] == reason

    # Non-metadata link-local (169.254.x.y where not the metadata IP) ->
    # rejected with denied_reason=link_local.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["169.254.1.2"])
    env = exc.value.envelope
    assert env["denied_reason"] == "link_local"

    # Globally-routable public address -> accepted. Note: audit-r3 BUG-B1
    # tightened the guard so RFC 5737 documentation ranges (192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24) are now classified as
    # ``rfc1918`` via Python's ``IPv4Address.is_private`` (the stdlib
    # tags those documentation ranges private). A genuinely public
    # routable address must be used here.
    validate_egress_entries(["8.8.8.8"])


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-014")
def test_egress_allowlist_handles_bracketed_ipv6_authority_form() -> None:
    """RFC 3986 bracketed IPv6 + port form is parsed correctly.

    Regression for the audit P2: previously the bare bracketed
    ``[ipv6]:port`` form was undocumented. The host extractor now
    strips brackets (and any trailing ``:port``) and the SSRF
    classifier sees the canonical IPv6 literal.
    """
    from relay.network_policy import EgressDenied, validate_egress_entries

    # Link-local IPv6 in bracketed-with-port form must be denied.
    for bracketed in ("[fe80::1]:8080", "[fe80::1]:443", "[fe80::1]"):
        with pytest.raises(EgressDenied) as exc:
            validate_egress_entries([bracketed])
        env = exc.value.envelope
        assert env["denied_reason"] == "link_local", (
            f"expected link_local for {bracketed!r}; got {env!r}"
        )
        assert env["denied_entry"] == bracketed

    # ULA (unique local address fc00::/7) in bracketed form -> rfc1918.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["[fc00::1]:9090"])
    assert exc.value.envelope["denied_reason"] == "rfc1918"

    # Loopback ``::1`` is tagged ``rfc1918`` because Python's
    # ``IPv6Address.is_private`` reports True for the IPv6 loopback
    # (and the SSRF guard rolls up rfc4193 ULA + loopback under
    # ``rfc1918`` for parity with IPv4 internal addresses).
    # Bracketed-form parsing is what we are testing here: the
    # extractor must yield ``"::1"`` (no brackets, no port) so that
    # ``_classify`` can run at all.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["[::1]:8080"])
    assert exc.value.envelope["denied_reason"] == "rfc1918"

    # URL form with bracketed IPv6 authority -> urlparse strips brackets.
    with pytest.raises(EgressDenied) as exc:
        validate_egress_entries(["http://[fe80::1]:8080/path"])
    assert exc.value.envelope["denied_reason"] == "link_local"


# -----------------------------------------------------------------------------
# VAL-V2M08-015..017: bundle verifier path-traversal hardening
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-015")
def test_bundle_verifier_rejects_relative_path_traversal() -> None:
    """Manifest artifact paths containing '..' segments are rejected
    with path_violation=relative_traversal."""
    from relay_verifier.bundle_paths import check_artifact_path

    for bad in (
        "../etc/passwd",
        "evidence/../../../etc/passwd",
        "./../secrets",
        "artifacts/../../etc/passwd",
    ):
        out = check_artifact_path(bad)
        assert out is not None
        assert out["code"] == "RELAY-EVID-024"
        assert out["path_violation"] == "relative_traversal"
        assert out["offending_path"] == bad


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-016")
def test_bundle_verifier_rejects_absolute_paths() -> None:
    """POSIX-absolute (/), Windows drive (C:\\), and UNC (\\\\host\\share)
    paths are rejected with path_violation=absolute_path; a relative path
    under artifacts/ is accepted."""
    from relay_verifier.bundle_paths import check_artifact_path

    for bad in ("/etc/passwd", "C:\\Windows\\System32", "\\\\host\\share\\file"):
        out = check_artifact_path(bad)
        assert out is not None
        assert out["code"] == "RELAY-EVID-024"
        assert out["path_violation"] == "absolute_path"
        assert out["offending_path"] == bad

    # Acceptable relative path.
    assert check_artifact_path("artifacts/run-001/output.json") is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-017")
def test_bundle_verifier_rejects_non_nfc_and_invalid_utf8_names() -> None:
    """Artifact paths that are NFD-encoded (not Unicode NFC) or that
    contain invalid UTF-8 byte sequences are rejected with the matching
    path_violation; a clean NFC ASCII path is accepted."""
    from relay_verifier.bundle_paths import check_artifact_path

    # NFD-encoded name: U+0065 U+0301 ("e" + combining acute) != "é".
    nfd_name = "artifacts/" + unicodedata.normalize("NFD", "café.txt")
    nfc_form = unicodedata.normalize("NFC", nfd_name)
    assert nfd_name != nfc_form
    out = check_artifact_path(nfd_name)
    assert out is not None
    assert out["code"] == "RELAY-EVID-024"
    assert out["path_violation"] == "non_nfc_name"

    # Invalid UTF-8 byte name.
    out2 = check_artifact_path(b"artifacts/\xff\xfe.txt")
    assert out2 is not None
    assert out2["code"] == "RELAY-EVID-024"
    assert out2["path_violation"] == "invalid_utf8_name"

    # Clean ASCII NFC -> accept.
    assert check_artifact_path("artifacts/run-001/output.json") is None


# -----------------------------------------------------------------------------
# VAL-V2M08-018 / 019: matrix CI aggregator gate
# -----------------------------------------------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-018")
def test_matrix_aggregator_writes_parent_release_decision() -> None:
    """Given N leg decisions all accept, the aggregator writes exactly
    one parent gate_decisions row keyed (gate_id_parent, release_sha)
    with written_by=control_plane and decision=accept. If any leg is
    reject, the parent is reject with reason.failed_legs[]."""
    from relay_sidecar.gate.aggregator import (
        MatrixAggregator,
        ParentDecision,
    )

    # All accept -> parent accept.
    agg = MatrixAggregator(
        release_sha="sha256:" + ("a" * 64),
        leg_ids=("leg-py3.12", "leg-py3.13", "leg-py3.14"),
        parent_gate_id="release-parent-001",
    )
    agg.record_leg("leg-py3.12", "accept")
    agg.record_leg("leg-py3.13", "accept")
    agg.record_leg("leg-py3.14", "accept")
    decision = agg.compute_parent_decision()
    assert isinstance(decision, ParentDecision)
    assert decision.decision == "accept"
    assert decision.written_by == "control_plane"
    assert decision.gate_id == "release-parent-001"
    assert decision.gate_kind == "release"

    # One leg reject -> parent reject + failed_legs.
    agg2 = MatrixAggregator(
        release_sha="sha256:" + ("b" * 64),
        leg_ids=("leg-1", "leg-2", "leg-3"),
        parent_gate_id="release-parent-002",
    )
    agg2.record_leg("leg-1", "accept")
    agg2.record_leg("leg-2", "reject")
    agg2.record_leg("leg-3", "accept")
    decision2 = agg2.compute_parent_decision()
    assert decision2 is not None
    assert decision2.decision == "reject"
    assert decision2.reason is not None
    assert decision2.reason.get("failed_legs") == ["leg-2"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M08-019")
def test_matrix_aggregator_holds_parent_until_all_legs_decided() -> None:
    """While any leg is still pending (no recorded decision), the
    aggregator returns None for the parent decision. Once the last leg
    writes its decision, the aggregator returns a single ParentDecision."""
    from relay_sidecar.gate.aggregator import MatrixAggregator

    agg = MatrixAggregator(
        release_sha="sha256:" + ("c" * 64),
        leg_ids=("leg-1", "leg-2", "leg-3"),
        parent_gate_id="release-parent-003",
    )
    agg.record_leg("leg-1", "accept")
    agg.record_leg("leg-2", "accept")
    # leg-3 still pending.
    assert agg.compute_parent_decision() is None

    agg.record_leg("leg-3", "accept")
    decision = agg.compute_parent_decision()
    assert decision is not None
    assert decision.decision == "accept"

    # Idempotency: a second call returns the same decision (no double-write).
    decision2 = agg.compute_parent_decision()
    assert decision2 is not None
    assert decision2.decision == "accept"
    assert decision2.gate_id == decision.gate_id
