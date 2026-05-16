"""V2M01-w1.3 plumbing tests: GateMetricCatalog v1 (spec section AA).

Covers VAL-V2M01-014 through VAL-V2M01-025:

  - VAL-V2M01-014: catalog file present + schema_version pinned + altered
    schema_version rejected by JSON Schema.
  - VAL-V2M01-015: exactly the 8 spec-mandated metrics; each carries the
    7 required fields.
  - VAL-V2M01-016 .. VAL-V2M01-023: each of the 8 metrics has the
    field-by-field values pinned by the spec.
  - VAL-V2M01-024: metric compiler rejects unknown metric name in a
    GatePolicy with RELAY-GATE-031.
  - VAL-V2M01-025: metric compiler rejects source SQL whose FROM/JOIN
    tables are not present in the canonical SQL schema registry with
    RELAY-GATE-033.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from relay_gate_engine.metric_catalog import (
    CATALOG_PATH,
    SCHEMA_VERSION,
    SOURCE_SENTINEL_AGGREGATION_BLOCK,
    SPEC_METRIC_NAMES,
    GateMetricCatalog,
    MetricCompiler,
    MetricCompilerError,
    MetricDefinition,
    extract_cte_names,
    extract_tables_from_source,
    load_catalog,
    load_catalog_schema,
)
from relay_schemas.error_codes import RelayErrorCode

# -- Fixtures ---------------------------------------------------------------


@pytest.fixture(scope="module")
def catalog_raw() -> dict:
    """Parsed catalog JSON (no Pydantic conversion)."""
    with CATALOG_PATH.open("r", encoding="utf-8") as fp:
        return json.load(fp)


@pytest.fixture(scope="module")
def catalog() -> GateMetricCatalog:
    """The fully-validated catalog object."""
    return load_catalog()


@pytest.fixture(scope="module")
def catalog_schema() -> dict:
    return load_catalog_schema()


def _metric_by_name(raw: dict, name: str) -> dict:
    for entry in raw["metrics"]:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"metric {name!r} not present in catalog")


# -- VAL-V2M01-014: catalog file shape --------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-014")
def test_catalog_file_present_and_parses() -> None:
    """The catalog file exists at the canonical path and parses as JSON."""
    assert CATALOG_PATH.is_file(), f"catalog missing at {CATALOG_PATH}"
    with CATALOG_PATH.open("rb") as fp:
        data = fp.read()
    parsed = json.loads(data)
    assert isinstance(parsed, dict)
    # Evidence: sha256 digest of the catalog file (recorded for audit).
    digest = hashlib.sha256(data).hexdigest()
    assert len(digest) == 64


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-014")
def test_catalog_schema_version_literal(catalog_raw: dict) -> None:
    """Root pins schema_version to relay.gate_metric_catalog.v1."""
    assert catalog_raw["schema_version"] == "relay.gate_metric_catalog.v1"
    assert SCHEMA_VERSION == "relay.gate_metric_catalog.v1"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-014")
def test_catalog_root_has_metrics_and_baselines_arrays(catalog_raw: dict) -> None:
    assert isinstance(catalog_raw.get("metrics"), list)
    assert len(catalog_raw["metrics"]) >= 1
    assert isinstance(catalog_raw.get("baselines"), list)
    assert len(catalog_raw["baselines"]) >= 1


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-014")
def test_catalog_schema_validates_catalog_file(
    catalog_raw: dict,
    catalog_schema: dict,
) -> None:
    """Canonical schema validates the catalog file successfully."""
    Draft202012Validator(catalog_schema).validate(catalog_raw)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-014")
def test_catalog_schema_rejects_altered_schema_version(
    catalog_raw: dict,
    catalog_schema: dict,
) -> None:
    """A fixture with an altered schema_version fails JSON Schema validation."""
    tampered = copy.deepcopy(catalog_raw)
    tampered["schema_version"] = "relay.gate_metric_catalog.v2"
    with pytest.raises(ValidationError):
        Draft202012Validator(catalog_schema).validate(tampered)


# -- VAL-V2M01-015: exactly the 8 metrics with required fields --------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-015")
def test_catalog_has_exactly_eight_spec_mandated_metrics(catalog_raw: dict) -> None:
    """metrics[].name == the exact 8-name set; no additions; no omissions."""
    actual_names = {m["name"] for m in catalog_raw["metrics"]}
    expected = {
        "p0_assertion_failures",
        "schema_contract.outcome.pass_rate",
        "tool_call.side_effect_attempts_blocked",
        "replay.reproduction_rate",
        "rag.empty_retrieval_rate",
        "cost.usd_per_run.p95",
        "eval.net_new_failures",
        "eval.flaky_count",
    }
    assert actual_names == expected
    # Also assert the module-level constant matches.
    assert frozenset(expected) == SPEC_METRIC_NAMES


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-015")
def test_each_metric_carries_required_fields(catalog_raw: dict) -> None:
    """Per-metric required-field presence report."""
    required_fields = {
        "name",
        "unit",
        "source",
        "filter",
        "aggregation",
        "missing_data",
        "sampling_eligibility",
    }
    missing_by_metric: dict[str, set[str]] = {}
    for entry in catalog_raw["metrics"]:
        missing = required_fields - set(entry.keys())
        if missing:
            missing_by_metric[entry["name"]] = missing
    assert missing_by_metric == {}, (
        f"metrics missing required fields: {missing_by_metric}"
    )


# -- VAL-V2M01-016: p0_assertion_failures -----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-016")
def test_p0_assertion_failures_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "p0_assertion_failures")
    assert m["unit"] == "count"
    assert m["source"] == (
        "contract_results c JOIN assertion_definitions a "
        "ON c.assertion_id = a.assertion_id"
    )
    assert m["filter"] == "a.severity = 'p0' AND c.outcome IN ('fail','error')"
    assert m["aggregation"] == "count"
    assert m["missing_data"] == "treated_as_zero"
    assert m["sampling_eligibility"] == "completeness>=0.9"


# -- VAL-V2M01-017: schema_contract.outcome.pass_rate -----------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-017")
def test_schema_contract_outcome_pass_rate_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "schema_contract.outcome.pass_rate")
    assert m["unit"] == "ratio[0..1]"
    assert m["source"] == (
        "contract_results c JOIN assertion_definitions a "
        "ON c.assertion_id = a.assertion_id"
    )
    assert m["filter"] == (
        "a.kind = 'schema_contract' AND "
        "c.outcome IN ('pass','fail','repaired','error')"
    )
    assert m["aggregation"] == (
        "count_where(c.outcome IN ('pass','repaired')) / count_total"
    )
    assert m["missing_data"] == "undefined_when_total_zero"
    assert m["sampling_eligibility"] == "completeness>=0.9"


# -- VAL-V2M01-018: tool_call.side_effect_attempts_blocked ------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-018")
def test_tool_call_side_effect_attempts_blocked_definition(
    catalog_raw: dict,
) -> None:
    m = _metric_by_name(catalog_raw, "tool_call.side_effect_attempts_blocked")
    assert m["unit"] == "count"
    assert m["source"] == "side_effect_markers"
    assert m["filter"] == "state IN ('blocked_by_approval','failed')"
    assert m["aggregation"] == "count"
    assert m["missing_data"] == "treated_as_zero"
    assert m["sampling_eligibility"] == "completeness>=0.5"


# -- VAL-V2M01-019: replay.reproduction_rate --------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-019")
def test_replay_reproduction_rate_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "replay.reproduction_rate")
    assert m["unit"] == "ratio[0..1]"
    assert m["source"] == "replay_results"
    assert m["filter"] == "TRUE"
    assert m["aggregation"] == (
        "count_where(outcome = 'reproduced') / count_total"
    )
    assert m["missing_data"] == "undefined_when_total_zero"
    assert m["sampling_eligibility"] == "completeness>=0.5"


# -- VAL-V2M01-020: rag.empty_retrieval_rate --------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-020")
def test_rag_empty_retrieval_rate_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "rag.empty_retrieval_rate")
    assert m["unit"] == "ratio[0..1]"
    assert m["source"] == "retrieval_spans"
    assert m["filter"] == "TRUE"
    assert m["aggregation"] == (
        "count_where(empty_retrieval) / count_total"
    )
    assert m["missing_data"] == "undefined_when_total_zero"
    assert m["sampling_eligibility"] == "completeness>=0.7"


# -- VAL-V2M01-021: cost.usd_per_run.p95 ------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-021")
def test_cost_usd_per_run_p95_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "cost.usd_per_run.p95")
    assert m["unit"] == "usd"
    assert m["missing_data"] == "undefined_when_population_lt_100"
    assert m["sampling_eligibility"] == "completeness>=0.9"

    agg = m["aggregation"]
    assert "WITH model_cost AS" in agg
    assert "embedding_cost AS" in agg
    assert "per_run AS" in agg
    assert "percentile_disc(0.95) WITHIN GROUP (ORDER BY run_cost)" in agg

    # Negative assertions: the aggregation SQL must NOT sum from
    # tool_call_spans or retrieval_spans (those tables carry no cost_usd
    # column in v1). Scan only the aggregation field; the notes block is
    # permitted to reference them as a forward-looking design note.
    assert "tool_call_spans" not in agg
    assert "retrieval_spans" not in agg


# -- VAL-V2M01-022: eval.net_new_failures -----------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-022")
def test_eval_net_new_failures_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "eval.net_new_failures")
    assert m["unit"] == "count"
    assert m["source"] == "eval_run_deltas"
    assert m["filter"] == "delta_class = 'net_new_failure'"
    assert m["aggregation"] == "count"
    assert m["missing_data"] == "treated_as_zero"
    assert m["sampling_eligibility"] == "completeness>=0.9"


# -- VAL-V2M01-023: eval.flaky_count ----------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-023")
def test_eval_flaky_count_definition(catalog_raw: dict) -> None:
    m = _metric_by_name(catalog_raw, "eval.flaky_count")
    assert m["unit"] == "count"
    assert m["source"] == "eval_run_deltas"
    assert m["filter"] == "delta_class = 'flaky'"
    assert m["aggregation"] == "count"
    assert m["missing_data"] == "treated_as_zero"
    assert m["sampling_eligibility"] == "completeness>=0.5"


# -- VAL-V2M01-024: compiler rejects unknown metric name --------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-024")
def test_metric_compiler_rejects_unknown_metric(catalog: GateMetricCatalog) -> None:
    """A policy referencing an undefined metric raises RELAY-GATE-031."""
    compiler = MetricCompiler(catalog)
    bad_policy = {
        "id": "bad_policy",
        "conditions": [
            {
                "id": "bad_condition",
                "metric": "completely_made_up_metric",
                "comparator": "gte",
                "value": 0.99,
                "scope": "project:demo",
            }
        ],
    }
    with pytest.raises(MetricCompilerError) as exc_info:
        compiler.validate_policy(bad_policy)
    assert exc_info.value.error_code == RelayErrorCode.RELAY_GATE_031
    assert exc_info.value.offending_metric == "completely_made_up_metric"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-024")
def test_metric_compiler_accepts_catalog_defined_metric_names(
    catalog: GateMetricCatalog,
) -> None:
    """A policy referencing only catalog-defined metric names validates."""
    compiler = MetricCompiler(catalog)
    good_policy = {
        "id": "good_policy",
        "conditions": [
            {
                "id": "structured_output_pass_rate",
                "metric": "schema_contract.outcome.pass_rate",
                "comparator": "gte",
                "value": 0.995,
                "scope": "eval_dataset:smoke-prod",
            },
            {
                "id": "no_p0_fails",
                "metric": "p0_assertion_failures",
                "comparator": "eq",
                "value": 0,
                "scope": "run",
            },
        ],
    }
    # Must not raise.
    compiler.validate_policy(good_policy)


# -- VAL-V2M01-025: compiler rejects unknown source tables ------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_metric_compiler_rejects_unknown_source_table(
    catalog: GateMetricCatalog,
) -> None:
    """A metric whose source FROM/JOIN names an unknown table raises RELAY-GATE-033."""
    compiler = MetricCompiler(catalog)
    bad_metric = MetricDefinition(
        name="custom_bad_metric",
        unit="count",
        source="FROM nonexistent_table_xyz",
        filter="TRUE",
        aggregation="count",
        missing_data="treated_as_zero",
        sampling_eligibility="completeness>=0.5",
    )
    with pytest.raises(MetricCompilerError) as exc_info:
        compiler.validate_metric(bad_metric)
    assert exc_info.value.error_code == RelayErrorCode.RELAY_GATE_033
    assert exc_info.value.offending_table == "nonexistent_table_xyz"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_metric_compiler_rejects_unknown_join_target(
    catalog: GateMetricCatalog,
) -> None:
    """A JOIN target not in the canonical-tables registry is rejected."""
    compiler = MetricCompiler(catalog)
    bad_metric = MetricDefinition(
        name="custom_bad_join",
        unit="count",
        source=(
            "contract_results c JOIN dropped_legacy_table d "
            "ON c.assertion_id = d.assertion_id"
        ),
        filter="TRUE",
        aggregation="count",
        missing_data="treated_as_zero",
        sampling_eligibility="completeness>=0.5",
    )
    with pytest.raises(MetricCompilerError) as exc_info:
        compiler.validate_metric(bad_metric)
    assert exc_info.value.error_code == RelayErrorCode.RELAY_GATE_033
    assert exc_info.value.offending_table == "dropped_legacy_table"


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_metric_compiler_accepts_canonical_metric(
    catalog: GateMetricCatalog,
) -> None:
    """Every catalog-defined metric passes source-table validation."""
    compiler = MetricCompiler(catalog)
    # Must not raise -- this proves the full catalog is internally consistent.
    compiler.validate_catalog()


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_metric_compiler_accepts_custom_metric_against_known_table(
    catalog: GateMetricCatalog,
) -> None:
    """A custom metric whose source parses cleanly validates successfully."""
    compiler = MetricCompiler(catalog)
    good_metric = MetricDefinition(
        name="custom.runs_per_release",
        unit="count",
        source="FROM run_results rr JOIN runs r ON rr.run_id = r.run_id",
        filter="r.release_sha IS NOT NULL",
        aggregation="count",
        missing_data="treated_as_zero",
        sampling_eligibility="completeness>=0.9",
    )
    # Must not raise.
    compiler.validate_metric(good_metric)


# -- Internal helpers (defense in depth) ------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_extract_tables_handles_sentinel_source() -> None:
    """The sentinel source value short-circuits to no FROM/JOIN tokens."""
    assert extract_tables_from_source(SOURCE_SENTINEL_AGGREGATION_BLOCK) == []


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_extract_tables_handles_schema_qualified_identifier() -> None:
    """schema.table identifiers reduce to the bare table name."""
    out = extract_tables_from_source(
        "public.contract_results c JOIN public.assertion_definitions a "
        "ON c.assertion_id = a.assertion_id"
    )
    # FROM ... and JOIN ... regex matches both segments.
    # Note: the leading 'public.contract_results' is captured only if a
    # FROM keyword precedes it. The fixture intentionally omits FROM, so
    # only the JOIN target is captured.
    assert "assertion_definitions" in out


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-025")
def test_extract_cte_names_captures_with_and_continuation() -> None:
    """WITH and , AS ( continuations are both captured."""
    sql = (
        "WITH a AS (SELECT 1), b AS (SELECT 2), c AS (SELECT 3) "
        "SELECT * FROM a JOIN b USING(x) JOIN c USING(y)"
    )
    assert extract_cte_names(sql) == ["a", "b", "c"]


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-021")
def test_canonical_cost_metric_uses_cte_aliases(catalog: GateMetricCatalog) -> None:
    """The cost metric's aggregation defines the expected CTE aliases."""
    metric = catalog.get_metric("cost.usd_per_run.p95")
    assert metric is not None
    cte_names = set(extract_cte_names(metric.aggregation))
    assert {"model_cost", "embedding_cost", "per_run"}.issubset(cte_names)


# -- Catalog object structural checks ---------------------------------------


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-015")
def test_catalog_baselines_are_two_spec_names(catalog: GateMetricCatalog) -> None:
    """Baseline names match the spec AA lines 5377-5386 pair."""
    names = catalog.baseline_names()
    assert names == frozenset({"previous_release_sha", "rolling_p50_7d"})


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-015")
def test_metric_definition_sampling_threshold_parses() -> None:
    """sampling_eligibility threshold parses to a float in (0, 1]."""
    m = MetricDefinition(
        name="x",
        unit="count",
        source="FROM runs",
        filter="TRUE",
        aggregation="count",
        missing_data="treated_as_zero",
        sampling_eligibility="completeness>=0.9",
    )
    assert m.sampling_threshold() == pytest.approx(0.9)


@pytest.mark.plumbing
@pytest.mark.fulfills("VAL-V2M01-024")
def test_compiler_skips_conditions_without_metric_field(
    catalog: GateMetricCatalog,
) -> None:
    """Non-metric conditions (e.g., raw assertion-id rules) are passed over."""
    compiler = MetricCompiler(catalog)
    policy = {
        "id": "mixed_policy",
        "conditions": [
            {"id": "no_metric", "kind": "assertion_id_allowlist", "value": []}
        ],
    }
    # Must not raise.
    compiler.validate_policy(policy)
