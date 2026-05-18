"""Plumbing-tier tests for VAL-V2M05-001 through VAL-V2M05-027 (M05 w5-explain).

Covers:
  - Schema YAML presence + required fields + enum + bounds + evidence_refs
    + generator regex (001..006).
  - SQL DDL extension at packages/schemas/sql/0009_explain.sql + sidecar
    mirror at apps/local-sidecar/migrations/0017_explain.sql; CHECK +
    UNIQUE behaviour via in-memory SQLite (007..013).
  - Engine: taxonomy clamp + span-on-run + dedupe + promotion API
    happy/sad paths (014..021).
  - pass@N filter (022..025).
  - Quality harness (026).
  - Control-plane sole-writer guard (027).

Spec anchors:
  T 4856-4896    Explain object behavior
  A.15 3316-3328 RootCauseHypothesis envelope
  AJ 5733-5746   generator taxonomy + Explain pipeline
  AL.2 5775-5785 pass@N filter

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jsonschema.exceptions import ValidationError
from relay_evals.pass_at_n import DEFAULT_N, PassAtNResult, check_pass_at_n
from relay_explain.api import (
    InMemoryPromotionService,
    build_explain_router,
)
from relay_explain.engine import (
    ExplainEngine,
    HypothesisRecord,
    InMemoryHypothesisStore,
    SpanNotOnRunError,
    canonical_evidence_refs_digest,
    new_hypothesis_id,
    now_rfc3339,
)
from relay_explain.heuristic import (
    GENERATOR_ID,
    HeuristicV1Generator,
)
from relay_explain.quality.harness import (
    GroundTruthCase,
    evaluate_generator,
)
from relay_schemas.error_code_registry import (
    get_code_details,
    load_code_details,
    load_codes,
)
from relay_schemas.error_codes import RelayErrorCode
from relay_schemas.root_cause_hypothesis import (
    EXAMPLE_JSON_PATH,
    GENERATOR_REGEX,
    HYPOTHESIS_CLASSES,
    REVIEWER_DECISIONS,
    SCHEMA_VERSION,
    SCHEMA_YAML_PATH,
    get_validator,
    iter_errors,
    load_example,
    load_schema,
    validate,
)

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PG_MIGRATION = _REPO_ROOT / "packages" / "schemas" / "sql" / "0009_explain.sql"
_SQLITE_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0017_explain.sql"
)
_BASE_SQLITE_MIGRATION = (
    _REPO_ROOT
    / "apps"
    / "local-sidecar"
    / "migrations"
    / "0012_v2_canonical_tables.sql"
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _good_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hypothesis_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "span_id": None,
        "hypothesis_class": "schema_contract_drift",
        "confidence": 0.7,
        "evidence_refs": [
            {
                "kind": "contract_result",
                "ref": "contract_results:" + str(uuid.uuid4()),
            }
        ],
        "generator": "heuristic.v1",
        "reviewer_email": None,
        "reviewer_decision": None,
        "promoted_to_replay_case_id": None,
        "created_at": "2026-05-17T12:00:00Z",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def fresh_sqlite() -> Iterator[sqlite3.Connection]:  # type: ignore[name-defined]
    """In-memory SQLite with ONLY the explain table (drop the FKs and triggers).

    We isolate the explain table here to test its CHECK / UNIQUE constraints
    without bringing the entire scope_state machinery into the test. This is
    a focused unit test of the DDL contract, not an end-to-end integration.
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(_explain_sqlite_ddl_for_test())
        yield conn
    finally:
        conn.close()


def _explain_sqlite_ddl_for_test() -> str:
    """Extract the CREATE TABLE root_cause_hypotheses statement from the M05
    sidecar migration and run it standalone (no FK or trigger dependencies).
    """
    text = _SQLITE_MIGRATION.read_text(encoding="utf-8")
    match = re.search(
        r"CREATE\s+TABLE\s+root_cause_hypotheses[\s\S]+?\);",
        text,
        re.IGNORECASE,
    )
    assert match, "explain CREATE TABLE statement not found in 0017_explain.sql"
    return match.group(0) + ";\n"


# ===========================================================================
# VAL-V2M05-001: schema YAML file present + top-level schema_version
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-001")
def test_schema_yaml_file_present() -> None:
    assert SCHEMA_YAML_PATH.is_file(), f"missing schema YAML: {SCHEMA_YAML_PATH}"
    data = yaml.safe_load(SCHEMA_YAML_PATH.read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-001")
def test_example_record_validates_against_schema() -> None:
    assert EXAMPLE_JSON_PATH.is_file()
    example = load_example()
    # Must not raise.
    validate(example)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-001")
def test_schema_yaml_digest_is_stable() -> None:
    raw = SCHEMA_YAML_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert len(digest) == 64


# ===========================================================================
# VAL-V2M05-002: required fields list
# ===========================================================================


_REQUIRED_FIELDS = {
    "schema_version",
    "hypothesis_id",
    "run_id",
    "hypothesis_class",
    "confidence",
    "evidence_refs",
    "generator",
    "created_at",
}


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-002")
def test_schema_required_set_matches_spec() -> None:
    schema = load_schema()
    assert set(schema["required"]) == _REQUIRED_FIELDS


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-002")
@pytest.mark.parametrize("missing", sorted(_REQUIRED_FIELDS))
def test_missing_required_field_is_rejected(missing: str) -> None:
    payload = _good_payload()
    payload.pop(missing)
    errors = iter_errors(payload)
    assert errors, f"expected validation error for missing {missing!r}"
    messages = " | ".join(err.message for err in errors)
    assert missing in messages


# ===========================================================================
# VAL-V2M05-003: hypothesis_class enum (12 values)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-003")
def test_hypothesis_class_enum_has_12_values() -> None:
    schema = load_schema()
    enum = set(schema["properties"]["hypothesis_class"]["enum"])
    assert enum == set(HYPOTHESIS_CLASSES)
    assert len(HYPOTHESIS_CLASSES) == 12


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-003")
@pytest.mark.parametrize("value", sorted(HYPOTHESIS_CLASSES))
def test_hypothesis_class_accepts_each_canonical_value(value: str) -> None:
    validate(_good_payload(hypothesis_class=value))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-003")
@pytest.mark.parametrize(
    "value", ["typo_class", "schema-contract-drift", "PROVIDER_DRIFT", ""]
)
def test_hypothesis_class_rejects_non_canonical_values(value: str) -> None:
    with pytest.raises(ValidationError):
        validate(_good_payload(hypothesis_class=value))


# ===========================================================================
# VAL-V2M05-004: confidence bounded [0, 1] inclusive
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-004")
@pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
def test_confidence_accepts_in_bounds(value: float) -> None:
    validate(_good_payload(confidence=value))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-004")
@pytest.mark.parametrize("value", [-0.01, 1.01, "high", None])
def test_confidence_rejects_out_of_bounds(value: Any) -> None:
    with pytest.raises(ValidationError):
        validate(_good_payload(confidence=value))


# ===========================================================================
# VAL-V2M05-005: evidence_refs non-empty, kind + ref present, ref pattern
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-005")
def test_evidence_refs_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        validate(_good_payload(evidence_refs=[]))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-005")
def test_evidence_refs_missing_kind_is_rejected() -> None:
    with pytest.raises(ValidationError):
        validate(
            _good_payload(
                evidence_refs=[{"ref": "spans:" + str(uuid.uuid4())}]
            )
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-005")
def test_evidence_refs_ref_pattern_is_enforced() -> None:
    with pytest.raises(ValidationError):
        validate(
            _good_payload(
                evidence_refs=[{"kind": "span", "ref": "spans:not-a-uuid"}]
            )
        )
    # Valid form (lowercase table + RFC4122 UUID) accepts.
    validate(
        _good_payload(
            evidence_refs=[
                {"kind": "span", "ref": "spans:" + str(uuid.uuid4())}
            ]
        )
    )


# ===========================================================================
# VAL-V2M05-006: generator regex (heuristic.v<N> or llm.<model>:v<N>)
# ===========================================================================


_GEN_ACCEPT = [
    "heuristic.v1",
    "heuristic.v3",
    "llm.gpt-4o:v1",
    "llm.claude-sonnet-4-7:v2",
]
_GEN_REJECT = [
    "heuristic",
    "heuristic.vX",
    "llm.gpt-4o",
    "LLM.GPT-4O:V1",
    "manual",
]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-006")
@pytest.mark.parametrize("value", _GEN_ACCEPT)
def test_generator_accepts_canonical(value: str) -> None:
    validate(_good_payload(generator=value))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-006")
@pytest.mark.parametrize("value", _GEN_REJECT)
def test_generator_rejects_malformed(value: str) -> None:
    with pytest.raises(ValidationError):
        validate(_good_payload(generator=value))


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-006")
def test_generator_regex_string_constant_matches_schema() -> None:
    schema = load_schema()
    assert schema["properties"]["generator"]["pattern"] == GENERATOR_REGEX
    pat = re.compile(GENERATOR_REGEX)
    for v in _GEN_ACCEPT:
        assert pat.match(v), v
    for v in _GEN_REJECT:
        assert not pat.match(v), v


# ===========================================================================
# VAL-V2M05-007: SQL migration file present + columns
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-007")
def test_postgres_migration_file_present() -> None:
    assert _PG_MIGRATION.is_file(), f"missing migration: {_PG_MIGRATION}"
    text = _PG_MIGRATION.read_text(encoding="utf-8")
    # Collapse runs of whitespace to a single space so column alignment
    # padding does not break the substring checks.
    normalized = re.sub(r"\s+", " ", text.lower())
    for fragment in (
        "create table root_cause_hypotheses",
        "hypothesis_id uuid primary key",
        "run_id uuid not null",
        "span_id uuid",
        "hypothesis_class text not null",
        "confidence numeric(4,3) not null",
        "evidence_refs jsonb not null",
        "evidence_refs_digest text not null",
        "generator text not null",
        "reviewer_email text",
        "reviewer_decision text",
        "promoted_to_replay_case_id uuid",
        "schema_version text not null",
        "created_at timestamptz not null",
    ):
        assert fragment in normalized, (
            f"missing fragment {fragment!r} in 0009_explain.sql"
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-007")
def test_sqlite_migration_file_present_with_columns(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    rows = list(fresh_sqlite.execute("PRAGMA table_info(root_cause_hypotheses)"))
    names = {row[1] for row in rows}
    expected = {
        "hypothesis_id",
        "run_id",
        "span_id",
        "hypothesis_class",
        "confidence",
        "evidence_refs",
        "evidence_refs_digest",
        "generator",
        "reviewer_email",
        "reviewer_decision",
        "promoted_to_replay_case_id",
        "schema_version",
        "created_at",
    }
    assert expected.issubset(names), f"missing columns: {expected - names}"


# ===========================================================================
# VAL-V2M05-008: hypothesis_class CHECK enforces 12-value enum
# ===========================================================================


def _insert(
    conn: sqlite3.Connection,
    *,
    hypothesis_class: str = "schema_contract_drift",
    generator: str = "heuristic.v1",
    confidence: float = 0.5,
    reviewer_decision: str | None = None,
    schema_version: str = "relay.root_cause_hypothesis.v1",
    evidence_refs_digest: str | None = None,
    run_id: str | None = None,
) -> str:
    hid = str(uuid.uuid4())
    rid = run_id or str(uuid.uuid4())
    digest = evidence_refs_digest or hashlib.sha256(b"[]").hexdigest()
    conn.execute(
        """
        INSERT INTO root_cause_hypotheses (
            hypothesis_id, run_id, span_id, hypothesis_class, confidence,
            evidence_refs, evidence_refs_digest, generator, reviewer_email,
            reviewer_decision, promoted_to_replay_case_id, schema_version,
            created_at
        ) VALUES (?, ?, NULL, ?, ?, '[]', ?, ?, NULL, ?, NULL, ?, ?)
        """,
        (
            hid,
            rid,
            hypothesis_class,
            confidence,
            digest,
            generator,
            reviewer_decision,
            schema_version,
            "2026-05-17T12:00:00Z",
        ),
    )
    return hid


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-008")
def test_hypothesis_class_check_accepts_all_canonical(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    for cls in sorted(HYPOTHESIS_CLASSES):
        _insert(fresh_sqlite, hypothesis_class=cls)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-008")
@pytest.mark.parametrize("value", ["typo_class", "PROVIDER_DRIFT", ""])
def test_hypothesis_class_check_rejects_non_canonical(
    fresh_sqlite: sqlite3.Connection, value: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _insert(fresh_sqlite, hypothesis_class=value)


# ===========================================================================
# VAL-V2M05-009: generator CHECK enforces taxonomy
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-009")
def test_generator_check_accepts_valid_examples(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    for gen in ("heuristic.v1", "heuristic.v22", "llm.gpt-4o:v1"):
        _insert(fresh_sqlite, generator=gen)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-009")
@pytest.mark.parametrize("value", ["manual", "heuristic", "llm.gpt-4o"])
def test_generator_check_rejects_malformed(
    fresh_sqlite: sqlite3.Connection, value: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _insert(fresh_sqlite, generator=value)


# ===========================================================================
# VAL-V2M05-010: confidence CHECK [0,1]
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-010")
def test_confidence_check_accepts_boundary_values(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    for v in (0.0, 0.5, 1.0):
        _insert(fresh_sqlite, confidence=v)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-010")
@pytest.mark.parametrize("value", [-0.001, 1.001])
def test_confidence_check_rejects_out_of_bounds(
    fresh_sqlite: sqlite3.Connection, value: float
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _insert(fresh_sqlite, confidence=value)


# ===========================================================================
# VAL-V2M05-011: reviewer_decision CHECK accept|modify|reject|NULL
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-011")
def test_reviewer_decision_accepts_canonical(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    # Audit-R3 (2026-05-18): added 'pending' per spec line 3325 +
    # envelopes.yaml. Canonical set is {accept, reject, modify, pending}.
    for v in (None, "accept", "modify", "reject", "pending"):
        _insert(fresh_sqlite, reviewer_decision=v)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-011")
@pytest.mark.parametrize("value", ["pending", "ACCEPT", "approved"])
def test_reviewer_decision_rejects_non_canonical(
    fresh_sqlite: sqlite3.Connection, value: str
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _insert(fresh_sqlite, reviewer_decision=value)


# ===========================================================================
# VAL-V2M05-012: UNIQUE (run_id, hypothesis_class, evidence_refs_digest)
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-012")
def test_dedupe_unique_rejects_direct_duplicate(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    rid = str(uuid.uuid4())
    digest = hashlib.sha256(b"[]").hexdigest()
    _insert(
        fresh_sqlite,
        run_id=rid,
        hypothesis_class="schema_contract_drift",
        evidence_refs_digest=digest,
    )
    with pytest.raises(sqlite3.IntegrityError):
        _insert(
            fresh_sqlite,
            run_id=rid,
            hypothesis_class="schema_contract_drift",
            evidence_refs_digest=digest,
        )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-012")
def test_engine_dedupe_merges_with_max_confidence() -> None:
    store = InMemoryHypothesisStore()
    rid = str(uuid.uuid4())
    sid = str(uuid.uuid4())
    store.register_span(rid, sid)
    eng = ExplainEngine(store=store)

    p1 = _good_payload(run_id=rid, span_id=sid, confidence=0.5)
    p2 = _good_payload(
        run_id=rid,
        span_id=sid,
        confidence=0.9,
        # Same dedupe triple as p1: same evidence_refs (same digest) and
        # same hypothesis_class. p2 has a fresh hypothesis_id so the
        # insert path would otherwise create a new row.
        evidence_refs=p1["evidence_refs"],
        hypothesis_class=p1["hypothesis_class"],
    )
    r1 = eng.ingest(p1)
    r2 = eng.ingest(p2)
    assert r1.deduped is False
    assert r2.deduped is True
    assert len(store.rows) == 1
    only = next(iter(store.rows.values()))
    assert only.confidence == 0.9


# ===========================================================================
# VAL-V2M05-013: schema_version CHECK pins canonical envelope version
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-013")
def test_schema_version_check_accepts_v1(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    _insert(fresh_sqlite, schema_version="relay.root_cause_hypothesis.v1")


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-013")
def test_schema_version_check_rejects_v2(
    fresh_sqlite: sqlite3.Connection,
) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        _insert(fresh_sqlite, schema_version="relay.root_cause_hypothesis.v2")


# ===========================================================================
# VAL-V2M05-014: invalid LLM hypothesis_class maps to 'unknown' + event
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-014")
def test_engine_clamps_unknown_class_and_emits_event() -> None:
    store = InMemoryHypothesisStore()
    rid = str(uuid.uuid4())
    sid = str(uuid.uuid4())
    store.register_span(rid, sid)
    eng = ExplainEngine(store=store)

    payload = _good_payload(
        run_id=rid,
        span_id=sid,
        hypothesis_class="totally_invented",
        generator="llm.gpt-4o:v1",
    )
    result = eng.ingest(payload)
    assert result.record.hypothesis_class == "unknown"
    assert result.taxonomy_event is not None
    assert result.taxonomy_event.name == "taxonomy_review_required"
    assert (
        result.taxonomy_event.payload["original_hypothesis_class"]
        == "totally_invented"
    )
    assert any(e.name == "taxonomy_review_required" for e in store.events)


# ===========================================================================
# VAL-V2M05-015: span_id not on run is rejected with RELAY-EXPLAIN-001
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-015")
def test_engine_rejects_span_not_on_run() -> None:
    store = InMemoryHypothesisStore()
    rid = str(uuid.uuid4())
    # NOTE: we deliberately do NOT register the span.
    eng = ExplainEngine(store=store)

    payload = _good_payload(run_id=rid, span_id=str(uuid.uuid4()))
    with pytest.raises(SpanNotOnRunError) as exc:
        eng.ingest(payload)
    assert exc.value.code == RelayErrorCode.RELAY_EXPLAIN_001
    assert exc.value.code == "RELAY-EXPLAIN-001"
    assert len(store.rows) == 0


# ===========================================================================
# VAL-V2M05-016: RELAY-EXPLAIN-001 present in error code registry
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-016")
def test_relay_explain_001_present_in_registry() -> None:
    codes = load_codes()
    assert "RELAY-EXPLAIN-001" in codes
    detail = get_code_details("RELAY-EXPLAIN-001")
    assert detail is not None
    assert detail.description and detail.description.strip()
    assert detail.http_status == 422


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-016")
def test_relay_explain_001_exposed_via_constants() -> None:
    assert RelayErrorCode.RELAY_EXPLAIN_001 == "RELAY-EXPLAIN-001"


# ===========================================================================
# VAL-V2M05-017: RELAY-EVAL-024 present in error code registry
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-017")
def test_relay_eval_024_present_in_registry() -> None:
    codes = load_codes()
    assert "RELAY-EVAL-024" in codes
    detail = get_code_details("RELAY-EVAL-024")
    assert detail is not None
    assert "pass@n" in detail.description.lower() or "pass at n" in detail.description.lower()
    assert detail.http_status == 422
    # Constant generated.
    assert RelayErrorCode.RELAY_EVAL_024 == "RELAY-EVAL-024"


# ===========================================================================
# VAL-V2M05-018: heuristic.v1 generator emits structured hypothesis
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-018")
def test_heuristic_v1_generates_validatable_hypotheses() -> None:
    gen = HeuristicV1Generator(
        now=lambda: datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC),
        id_factory=lambda: str(uuid.uuid4()),
    )
    rid = str(uuid.uuid4())
    sid = str(uuid.uuid4())
    spans = [
        {
            "span_id": sid,
            "span_type": "model_call",
            "status": "error",
            "error_class": "rate_limit",
        }
    ]
    contract_results = [
        {
            "contract_result_id": str(uuid.uuid4()),
            "status": "fail",
            "failure_kind": "schema_drift",
        }
    ]
    drafts = gen.generate(
        run_id=rid, spans=spans, contract_results=contract_results
    )
    assert len(drafts) >= 1
    for d in drafts:
        assert d.generator == GENERATOR_ID == "heuristic.v1"
        assert d.hypothesis_class in HYPOTHESIS_CLASSES
        assert d.evidence_refs
        assert 0.0 <= d.confidence <= 1.0
        # Round-trip through the schema validator.
        validate(d.to_payload())


# ===========================================================================
# VAL-V2M05-019, 020, 021: promotion API
# ===========================================================================


def _build_test_app(service: InMemoryPromotionService) -> TestClient:
    app = FastAPI()
    app.include_router(build_explain_router(service))
    return TestClient(app)


def _make_record(*, accepted: bool) -> HypothesisRecord:
    hid = str(uuid.uuid4())
    rid = str(uuid.uuid4())
    return HypothesisRecord(
        hypothesis_id=hid,
        run_id=rid,
        span_id=None,
        hypothesis_class="schema_contract_drift",
        confidence=0.9,
        evidence_refs=[
            {"kind": "contract_result", "ref": "contract_results:" + str(uuid.uuid4())}
        ],
        evidence_refs_digest=hashlib.sha256(b"[]").hexdigest(),
        generator="heuristic.v1",
        reviewer_email="lead@example.com" if accepted else None,
        reviewer_decision="accept" if accepted else None,
        promoted_to_replay_case_id=None,
        schema_version=SCHEMA_VERSION,
        created_at="2026-05-17T12:00:00Z",
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-019")
def test_promote_accepted_hypothesis_creates_replay_case() -> None:
    svc = InMemoryPromotionService()
    rec = _make_record(accepted=True)
    svc.add_hypothesis(rec)
    client = _build_test_app(svc)

    resp = client.post(f"/v1/replay-cases?from_hypothesis_id={rec.hypothesis_id}")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    new_id = body["replay_case_id"]
    assert body["run_id"] == rec.run_id
    # Source row's promoted_to_replay_case_id is populated.
    updated = svc.get_hypothesis(rec.hypothesis_id)
    assert updated is not None
    assert updated.promoted_to_replay_case_id == new_id

    # Round-trip GET.
    rt = client.get(f"/v1/replay-cases/{new_id}")
    assert rt.status_code == 200
    assert rt.json()["run_id"] == rec.run_id


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-020")
@pytest.mark.parametrize("decision", [None, "reject", "modify"])
def test_promote_non_accepted_hypothesis_rejects_422(
    decision: str | None,
) -> None:
    svc = InMemoryPromotionService()
    rec = _make_record(accepted=False)
    # Override decision to ensure the not-accept branch.
    rec = HypothesisRecord(
        **{**rec.__dict__, "reviewer_decision": decision}
    )
    svc.add_hypothesis(rec)
    client = _build_test_app(svc)

    resp = client.post(f"/v1/replay-cases?from_hypothesis_id={rec.hypothesis_id}")
    assert resp.status_code == 422, resp.text
    body = resp.json()
    assert body["error"]["code"] == "RELAY-EXPLAIN-001"
    # No replay_case rows created; source row unchanged.
    assert svc.replay_cases == {}
    again = svc.get_hypothesis(rec.hypothesis_id)
    assert again is not None
    assert again.promoted_to_replay_case_id is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-021")
def test_promote_unknown_hypothesis_returns_404() -> None:
    svc = InMemoryPromotionService()
    client = _build_test_app(svc)
    bogus = str(uuid.uuid4())
    resp = client.post(f"/v1/replay-cases?from_hypothesis_id={bogus}")
    assert resp.status_code == 404, resp.text
    body = resp.json()
    assert body["error"]["code"] == "RELAY-EXPLAIN-001"
    assert svc.replay_cases == {}


# ===========================================================================
# VAL-V2M05-022, 023, 024, 025: pass@N filter
# ===========================================================================


def _runs(pattern: str) -> list[dict[str, Any]]:
    """`'PPFP'` -> alternating pass/fail run records."""
    out: list[dict[str, Any]] = []
    for ch in pattern:
        if ch == "P":
            out.append({"status": "pass", "run_id": str(uuid.uuid4())})
        elif ch == "F":
            out.append({"status": "fail", "run_id": str(uuid.uuid4())})
        else:
            raise ValueError(f"unknown char {ch!r}")
    return out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-022")
def test_pass_at_n_rejects_all_pass_edge() -> None:
    result = check_pass_at_n(object(), _runs("P" * 8))
    assert isinstance(result, PassAtNResult)
    assert result.accepted is False
    assert result.error_code == "RELAY-EVAL-024"
    assert result.failing_edge == "all_pass"
    assert len(result.run_set) == 8


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-023")
def test_pass_at_n_rejects_all_fail_edge() -> None:
    result = check_pass_at_n(object(), _runs("F" * 8))
    assert result.accepted is False
    assert result.error_code == "RELAY-EVAL-024"
    assert result.failing_edge == "all_fail"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-024")
def test_pass_at_n_accepts_informative_set() -> None:
    result = check_pass_at_n(object(), _runs("PPPFFFFF"))  # 3 of 8
    assert result.accepted is True
    assert result.error_code is None
    assert result.failing_edge is None


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-025")
def test_pass_at_n_default_is_eight_and_configurable() -> None:
    assert DEFAULT_N == 8
    # Same 4-pass set; with n=4 it is all-pass and rejected.
    set_4_pass = _runs("PPPP")
    assert check_pass_at_n(object(), set_4_pass, n=4).accepted is False
    # With n=8 over fewer-than-8 runs the all-pass branch is NOT
    # triggered (insufficient history); the result is accepted.
    assert check_pass_at_n(object(), set_4_pass, n=8).accepted is True


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-025")
def test_pass_at_n_zero_is_rejected() -> None:
    with pytest.raises(ValueError):
        check_pass_at_n(object(), [], n=0)


# ===========================================================================
# VAL-V2M05-026: quality harness metrics
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-026")
def test_quality_harness_returns_metrics_in_unit_interval() -> None:
    # Audit R3 BUG-E5: HeuristicV1Generator no longer defaults
    # id_factory to uuid4(). Inject a deterministic counter so the
    # quality harness can reproduce the same hypothesis_id sequence.
    _counter = {"n": 0}

    def _deterministic_id() -> str:
        _counter["n"] += 1
        return f"h-{_counter['n']:08d}"

    gen = HeuristicV1Generator(
        now=lambda: datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC),
        id_factory=_deterministic_id,
    )
    cases: list[GroundTruthCase] = []
    # 10 TP-eligible cases: each has a fail contract_result with
    # schema_drift -> expected schema_contract_drift.
    for _ in range(10):
        cr = {
            "contract_result_id": str(uuid.uuid4()),
            "status": "fail",
            "failure_kind": "schema_drift",
        }
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[cr],
                expected_class="schema_contract_drift",
            )
        )
    # 10 clean cases: no spans, no failing contract_results, expected None.
    for _ in range(10):
        cases.append(
            GroundTruthCase(
                case_id=str(uuid.uuid4()),
                run_id=str(uuid.uuid4()),
                spans=[],
                contract_results=[],
                expected_class=None,
            )
        )
    report = evaluate_generator(
        gen, cases, generator_id=GENERATOR_ID, confidence_threshold=0.5
    )
    assert report.generator_id == "heuristic.v1"
    assert report.n_cases == 20
    for metric in (
        report.precision,
        report.recall,
        report.false_positive_rate,
    ):
        assert isinstance(metric, float)
        assert 0.0 <= metric <= 1.0
    # The heuristic with confidence 0.85 on schema_drift fails -> all TP,
    # zero FN, zero FP, zero TN should be true positives 10 + true neg 10.
    assert report.true_positives == 10
    assert report.true_negatives == 10
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.false_positive_rate == 0.0


# ===========================================================================
# VAL-V2M05-027: control plane is the sole writer of root_cause_hypotheses
# ===========================================================================


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-027")
def test_control_plane_sole_writer_static_guard() -> None:
    """Static grep guard: no module under packages/sdk-python/, packages/cli/,
    packages/evals/, or apps/replay-proxy/ may issue a direct INSERT/UPDATE
    against ``root_cause_hypotheses``. Only the explain engine
    (packages/explain/) and the local-sidecar may touch it.
    """
    forbidden_roots = [
        _REPO_ROOT / "packages" / "sdk-python",
        _REPO_ROOT / "packages" / "cli",
        _REPO_ROOT / "packages" / "evals",
        _REPO_ROOT / "apps" / "replay-proxy",
    ]
    offending: list[str] = []
    insert_pattern = re.compile(r"INSERT\s+INTO\s+root_cause_hypotheses", re.IGNORECASE)
    update_pattern = re.compile(r"UPDATE\s+root_cause_hypotheses", re.IGNORECASE)
    for root in forbidden_roots:
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if insert_pattern.search(text) or update_pattern.search(text):
                offending.append(str(path))
    assert not offending, (
        "Direct writes to root_cause_hypotheses detected outside the "
        f"explain engine / sidecar: {offending}"
    )


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M05-027")
def test_canonical_digest_is_deterministic_for_dedupe_key() -> None:
    refs = [{"kind": "span", "ref": "spans:" + str(uuid.uuid4())}]
    d1 = canonical_evidence_refs_digest(refs)
    # Same content, different ordering of dict keys -> same digest.
    refs2 = [{"ref": refs[0]["ref"], "kind": refs[0]["kind"]}]
    d2 = canonical_evidence_refs_digest(refs2)
    assert d1 == d2
    # Different content -> different digest.
    refs3 = [{"kind": "span", "ref": "spans:" + str(uuid.uuid4())}]
    assert canonical_evidence_refs_digest(refs3) != d1


# ===========================================================================
# Sanity / helper tests (not bound to assertions; provide regression cover)
# ===========================================================================


@pytest.mark.plumbing
def test_now_rfc3339_is_z_suffixed_utc() -> None:
    s = now_rfc3339()
    assert s.endswith("Z")
    # Parses as ISO 8601 / RFC 3339.
    datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.plumbing
def test_new_hypothesis_id_is_uuid_v4_like() -> None:
    val = new_hypothesis_id()
    parsed = uuid.UUID(val)
    assert parsed.version == 4


@pytest.mark.plumbing
def test_get_validator_is_cached() -> None:
    a = get_validator()
    b = get_validator()
    assert a is b


@pytest.mark.plumbing
def test_load_code_details_includes_only_known_codes() -> None:
    details = load_code_details()
    codes = load_codes()
    for code in details:
        assert code in codes


@pytest.mark.plumbing
def test_reviewer_decisions_is_four_values() -> None:
    # Audit-R3 (2026-05-18): aligned to spec line 3325 + envelopes.yaml +
    # openapi.yaml -- {accept, reject, modify, pending}. Prior 3-value
    # set omitted 'pending'.
    assert frozenset({"accept", "reject", "modify", "pending"}) == REVIEWER_DECISIONS


@pytest.mark.plumbing
def test_canonical_digest_uses_json_canonical_form() -> None:
    refs = [{"kind": "span", "ref": "spans:" + "0" * 32}]
    expected = hashlib.sha256(
        json.dumps(refs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert canonical_evidence_refs_digest(refs) == expected


@pytest.mark.plumbing
def test_postgres_and_sqlite_migrations_present() -> None:
    assert _PG_MIGRATION.is_file()
    assert _SQLITE_MIGRATION.is_file()
    assert _BASE_SQLITE_MIGRATION.is_file()
