"""GateMetricCatalog v1 loader + metric compiler (V2M01-w1.3).

Implements spec section AA: a deterministic registry of named metrics that
GatePolicy conditions reference. Two engineers cannot otherwise implement
diverging aggregations for the same metric name; the catalog is the single
source of truth.

Public surface:

  - :data:`CATALOG_PATH` and :data:`CATALOG_SCHEMA_PATH` -- canonical
    on-disk locations of the catalog data and its JSON Schema.
  - :data:`SCHEMA_VERSION` -- the pinned schema-version literal
    (``"relay.gate_metric_catalog.v1"``).
  - :data:`SPEC_METRIC_NAMES` -- frozenset of the 8 spec-mandated metric
    names (VAL-V2M01-015).
  - :data:`CANONICAL_TABLES` -- frozenset of every canonical SQL table the
    metric compiler recognises as a valid FROM/JOIN target. Sourced from
    the union of ``packages/schemas/sql/*.sql`` (the v2 canonical migrations)
    and the spec-defined tables that other milestones will land
    (``runs``, ``run_results``, ``gate_decisions``, ``gate_decision_drafts``,
    ``gate_rounds``, ``gates``, ``side_effect_markers``, ``eval_run_deltas``).
  - :func:`load_catalog` -- parse the catalog JSON, validate against its
    JSON Schema, and return a frozen :class:`GateMetricCatalog`.
  - :func:`load_catalog_schema` -- parse the JSON Schema as a dict.
  - :class:`GateMetricCatalog` -- frozen catalog record with metric and
    baseline lookups.
  - :class:`MetricDefinition`, :class:`BaselineDefinition` -- record types.
  - :class:`MetricCompiler` -- validates metrics + GatePolicy conditions
    at publish time. Raises :class:`MetricCompilerError` carrying one of
    the ``RELAY-GATE-{031,033,038}`` codes.

Spec anchors:
  - AA lines 5295-5408 (full section).
  - AA lines 5301 (schema_version literal).
  - AA lines 5302-5375 (metric definitions).
  - AA lines 5377-5386 (baselines).
  - AA line 5390 (RELAY-GATE-031 unknown metric, RELAY-GATE-033 source
    mismatch).
  - AA line 5408 (RELAY-GATE-038 insufficient coverage).
  - F (manifest is source of truth -- the canonical-tables registry is
    derived from the canonical SQL DDLs in packages/schemas/sql/, not
    invented).

CLAUDE.md anchors:
  - Keystone invariant 3 (manifest source of truth) -- the canonical-tables
    set is derived from canonical SQL DDL, not improvised.
  - Banned pattern 10 (no schema invention) -- every recognised table maps
    to a CREATE TABLE statement in the canonical migrations or a spec-
    defined sibling table.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from relay_schemas.error_codes import RelayErrorCode

# Public path constants ------------------------------------------------------
#
# Resolved relative to the relay/ working tree root. The traversal walks up
# from this file (packages/gate/src/relay_gate_engine/metric_catalog.py) to
# reach packages/schemas/.
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[4]  # relay/

CATALOG_PATH: Final[Path] = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "catalogs"
    / "gate_metric_catalog.v1.json"
)
CATALOG_SCHEMA_PATH: Final[Path] = (
    _REPO_ROOT
    / "packages"
    / "schemas"
    / "catalogs"
    / "relay.gate_metric_catalog.v1.schema.json"
)

# Spec AA line 5301: pinned schema-version literal.
SCHEMA_VERSION: Final[str] = "relay.gate_metric_catalog.v1"

# Spec AA lines 5302-5375: the 8 catalog metrics, verbatim.
SPEC_METRIC_NAMES: Final[frozenset[str]] = frozenset({
    "p0_assertion_failures",
    "schema_contract.outcome.pass_rate",
    "tool_call.side_effect_attempts_blocked",
    "replay.reproduction_rate",
    "rag.empty_retrieval_rate",
    "cost.usd_per_run.p95",
    "eval.net_new_failures",
    "eval.flaky_count",
})

# Spec AA lines 5305-5374 enumerated units.
SPEC_UNITS: Final[frozenset[str]] = frozenset({
    "count",
    "ratio[0..1]",
    "usd",
})

# Spec AA lines 5309-5374 enumerated missing_data behaviors.
SPEC_MISSING_DATA: Final[frozenset[str]] = frozenset({
    "treated_as_zero",
    "undefined_when_total_zero",
    "undefined_when_population_lt_100",
})

# Canonical SQL tables the metric compiler recognises as valid FROM/JOIN
# targets. Sourced from the union of:
#
#   1. packages/schemas/sql/0001_actors.sql       (actors)
#   2. packages/schemas/sql/0002_control_plane.sql (manifest_versions,
#      scope_state, idempotency_records, event_log_entries)
#   3. packages/schemas/sql/0003_evidence_replay.sql (evidence_bundles,
#      evidence_claims, replay_cases, replay_fixtures)
#   4. packages/schemas/sql/0004_v2_canonical_tables.sql (gate_policies,
#      contract_results, assertion_definitions, replay_results, manifests,
#      redaction_policies, incidents, root_cause_hypotheses, spans,
#      model_call_spans, tool_call_spans, retrieval_spans, embedding_spans)
#   5. Spec-defined sibling tables that the §AA catalog references but that
#      land in other v0.2 milestones (M02 endpoints, M04 §X markers, etc.):
#      runs, run_results, gate_decisions, gate_decision_drafts, gate_rounds,
#      gates, side_effect_markers, eval_run_deltas. Source citations:
#        - run_results, runs:                spec A.1 lines 2978-3000
#        - gate_decisions:                   spec A.2 lines 3005-3018
#        - gate_decision_drafts, gate_rounds, gates: A.3-A.5
#        - side_effect_markers:              spec X line 5136
#        - eval_run_deltas:                  spec AA line 5361 (referenced
#                                            by eval.net_new_failures and
#                                            eval.flaky_count metrics)
#
# Workers must not extend this set with invented tables. To add a table,
# land its CREATE TABLE statement in packages/schemas/sql/ first.
CANONICAL_TABLES: Final[frozenset[str]] = frozenset({
    # Tier-1 (already shipped in v0.1 + v0.2 w1-1):
    "actors",
    "manifest_versions",
    "scope_state",
    "idempotency_records",
    "event_log_entries",
    "evidence_bundles",
    "evidence_claims",
    "replay_cases",
    "replay_fixtures",
    "gate_policies",
    "contract_results",
    "assertion_definitions",
    "replay_results",
    "manifests",
    "redaction_policies",
    "incidents",
    "root_cause_hypotheses",
    "spans",
    "model_call_spans",
    "tool_call_spans",
    "retrieval_spans",
    "embedding_spans",
    # Tier-2 (spec-defined siblings landed by other milestones; the catalog
    # references them by name today):
    "runs",
    "run_results",
    "gate_decisions",
    "gate_decision_drafts",
    "gate_rounds",
    "gates",
    "side_effect_markers",
    "eval_run_deltas",
})

# Sentinel source value for metrics whose actual SQL lives entirely in the
# `aggregation` CTE chain (spec AA line 5351). The compiler does NOT attempt
# to introspect the sentinel string; instead it parses the `aggregation`
# field for FROM/JOIN tokens.
SOURCE_SENTINEL_AGGREGATION_BLOCK: Final[str] = "see aggregation block below"

# Spec AA: every metric source uses these SQL connector tokens. The regex
# below captures the identifier following each one. Whitespace and commas
# bound identifiers. Identifiers may be schema-qualified (`schema.table`);
# the compiler validates only the bare table name (the part after any dot).
_FROM_JOIN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_\.]*)",
    re.IGNORECASE,
)

# Spec AA line 5353: CTE-defined names (`WITH model_cost AS (...)`) are
# legal FROM/JOIN targets within the same statement. The regex captures
# the identifier after WITH or after a top-level `, name AS (` continuation.
_CTE_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:\bWITH\b|,)\s*([A-Za-z_][A-Za-z0-9_]*)\s+AS\s*\(",
    re.IGNORECASE,
)

# Reserved SQL keywords that may appear immediately after FROM/JOIN inside
# a CTE chain (e.g., `FROM (SELECT ...)`); these are not table names.
# Also subquery openings that begin with `(`.
_NON_TABLE_TOKENS: Final[frozenset[str]] = frozenset({
    "SELECT",
    "LATERAL",
})


@dataclass(frozen=True)
class MetricDefinition:
    """A single metric record from the catalog."""

    name: str
    unit: str
    source: str
    filter: str
    aggregation: str
    missing_data: str
    sampling_eligibility: str
    notes: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> MetricDefinition:
        return cls(
            name=raw["name"],
            unit=raw["unit"],
            source=raw["source"],
            filter=raw["filter"],
            aggregation=raw["aggregation"],
            missing_data=raw["missing_data"],
            sampling_eligibility=raw["sampling_eligibility"],
            notes=raw.get("notes"),
        )

    def sampling_threshold(self) -> float:
        """Return the numeric threshold from ``sampling_eligibility``.

        Spec AA line 5408: ``completeness>=0.9`` -> 0.9. Used by gate
        evaluation when emitting RELAY-GATE-038.
        """
        match = re.match(r"^completeness>=(0\.[0-9]+)$", self.sampling_eligibility)
        if not match:
            raise ValueError(
                f"sampling_eligibility {self.sampling_eligibility!r} "
                "does not match completeness>=<float> grammar"
            )
        return float(match.group(1))


@dataclass(frozen=True)
class BaselineDefinition:
    """A single baseline record from the catalog (spec AA lines 5377-5386)."""

    name: str
    lookup: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BaselineDefinition:
        return cls(name=raw["name"], lookup=raw["lookup"])


@dataclass(frozen=True)
class GateMetricCatalog:
    """Frozen catalog of named metrics + baselines."""

    schema_version: str
    metrics: tuple[MetricDefinition, ...]
    baselines: tuple[BaselineDefinition, ...]

    def metric_names(self) -> frozenset[str]:
        return frozenset(m.name for m in self.metrics)

    def get_metric(self, name: str) -> MetricDefinition | None:
        for m in self.metrics:
            if m.name == name:
                return m
        return None

    def baseline_names(self) -> frozenset[str]:
        return frozenset(b.name for b in self.baselines)


class MetricCompilerError(Exception):
    """Raised by :class:`MetricCompiler` with a Relay error code.

    The ``error_code`` attribute carries one of:

      - ``RELAY-GATE-031`` -- unknown metric (VAL-V2M01-024)
      - ``RELAY-GATE-033`` -- metric source mismatch (VAL-V2M01-025)
      - ``RELAY-GATE-038`` -- insufficient coverage (raised by gate
        evaluation, not the compiler; this class is the structured carrier)
    """

    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        offending_metric: str | None = None,
        offending_table: str | None = None,
    ) -> None:
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
        self.offending_metric = offending_metric
        self.offending_table = offending_table


def load_catalog_schema(
    path: Path | None = None,
) -> dict[str, Any]:
    """Load the GateMetricCatalog JSON Schema as a dict."""
    target = path if path is not None else CATALOG_SCHEMA_PATH
    with target.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def load_catalog(
    path: Path | None = None,
    *,
    schema_path: Path | None = None,
) -> GateMetricCatalog:
    """Load and JSON-Schema-validate the canonical catalog.

    :raises MetricCompilerError: if the catalog file fails schema validation.
        The error code is ``RELAY-GATE-031`` (unknown metric) when an
        unknown name is implied, ``RELAY-GATE-033`` for a structural source
        mismatch, or it bubbles a :class:`jsonschema.ValidationError` for
        catalog-level shape failures (caller may catch and re-raise).
    """
    target = path if path is not None else CATALOG_PATH
    with target.open("r", encoding="utf-8") as fp:
        raw = json.load(fp)
    schema = load_catalog_schema(schema_path)
    Draft202012Validator(schema).validate(raw)

    metrics = tuple(MetricDefinition.from_dict(m) for m in raw["metrics"])
    baselines = tuple(BaselineDefinition.from_dict(b) for b in raw["baselines"])
    return GateMetricCatalog(
        schema_version=raw["schema_version"],
        metrics=metrics,
        baselines=baselines,
    )


def extract_tables_from_source(source: str) -> list[str]:
    """Extract bare table names that follow ``FROM`` / ``JOIN`` tokens.

    Schema-qualified identifiers (``schema.table``) are reduced to their
    last segment. Subquery openings (``(SELECT ...``) and the ``LATERAL``
    keyword are skipped.

    For the sentinel value :data:`SOURCE_SENTINEL_AGGREGATION_BLOCK`, the
    function returns ``[]`` -- the caller is expected to parse the
    ``aggregation`` field instead.
    """
    if source.strip() == SOURCE_SENTINEL_AGGREGATION_BLOCK:
        return []
    out: list[str] = []
    for match in _FROM_JOIN_PATTERN.finditer(source):
        candidate = match.group(1)
        bare = candidate.rsplit(".", 1)[-1]
        if bare.upper() in _NON_TABLE_TOKENS:
            continue
        out.append(bare)
    return out


def extract_cte_names(sql: str) -> list[str]:
    """Extract CTE-defined names from a SQL fragment.

    Matches both ``WITH foo AS (...)`` and ``, foo AS (...)`` continuations.
    Used by :meth:`MetricCompiler.validate_metric` to treat CTE aliases as
    locally-known table names so the cost metric's pre-aggregated CTE chain
    (spec AA line 5353) validates cleanly.
    """
    return [m.group(1) for m in _CTE_PATTERN.finditer(sql)]


class MetricCompiler:
    """Validate metrics + GatePolicy conditions against the catalog.

    Constructed with a :class:`GateMetricCatalog` and an optional override
    for the recognised canonical-tables set. The default registry is
    :data:`CANONICAL_TABLES`.

    Methods:

      - :meth:`validate_metric` -- check a single metric's ``source`` SQL
        FROM/JOIN tables resolve in the canonical-tables registry. Raises
        :class:`MetricCompilerError` with ``RELAY-GATE-033`` on the first
        unknown table.
      - :meth:`validate_policy` -- check every condition references a metric
        name that exists in the catalog. Raises :class:`MetricCompilerError`
        with ``RELAY-GATE-031`` on the first unknown metric name.
      - :meth:`validate_catalog` -- run :meth:`validate_metric` over every
        catalog metric. Used by ``rly contract publish`` to refuse a catalog
        that has been hand-edited to reference a dropped table.
    """

    def __init__(
        self,
        catalog: GateMetricCatalog,
        *,
        known_tables: frozenset[str] | None = None,
    ) -> None:
        self.catalog = catalog
        self.known_tables = (
            known_tables if known_tables is not None else CANONICAL_TABLES
        )

    def validate_metric(self, metric: MetricDefinition) -> None:
        """Validate a metric's ``source`` clause names only known tables.

        :raises MetricCompilerError: ``RELAY-GATE-033`` on first unknown
            table name.
        """
        # Spec AA line 5351: metrics may set source to the sentinel
        # "see aggregation block below" when the FROM/JOIN chain lives in
        # the aggregation CTE. For those metrics, parse the aggregation
        # field for both CTE-defined names (locally known) and FROM/JOIN
        # tables. CTE names are treated as locally-known table aliases.
        tables = list(extract_tables_from_source(metric.source))
        local_known = set(self.known_tables)
        if metric.source.strip() == SOURCE_SENTINEL_AGGREGATION_BLOCK:
            local_known.update(extract_cte_names(metric.aggregation))
            tables.extend(extract_tables_from_source(metric.aggregation))
        else:
            # Even non-sentinel sources may use a leading WITH (rare in v1
            # but harmless to support); fold those into the local known set.
            local_known.update(extract_cte_names(metric.source))

        for table in tables:
            if table not in local_known:
                raise MetricCompilerError(
                    RelayErrorCode.RELAY_GATE_033,
                    (
                        f"metric {metric.name!r} source references unknown "
                        f"table {table!r}; not present in canonical SQL "
                        "schema registry"
                    ),
                    offending_metric=metric.name,
                    offending_table=table,
                )

    def validate_catalog(self) -> None:
        """Validate every metric in the catalog. Stops at the first failure."""
        for metric in self.catalog.metrics:
            self.validate_metric(metric)

    def validate_policy(self, policy: dict[str, Any]) -> None:
        """Validate every condition references a catalog-defined metric.

        ``policy`` follows the §D.3 GatePolicy shape: a dict with a
        ``conditions`` array of dicts, each carrying a ``metric`` field.

        :raises MetricCompilerError: ``RELAY-GATE-031`` on first unknown
            metric name.
        """
        known = self.catalog.metric_names()
        for condition in policy.get("conditions", []):
            name = condition.get("metric")
            if name is None:
                # Conditions without a `metric` field are out of scope for
                # this compiler (some condition kinds are non-metric, e.g.,
                # raw assertion-id allowlists). Skip silently.
                continue
            if name not in known:
                raise MetricCompilerError(
                    RelayErrorCode.RELAY_GATE_031,
                    (
                        f"GatePolicy references unknown metric {name!r}; "
                        f"not defined in {SCHEMA_VERSION}"
                    ),
                    offending_metric=name,
                )


__all__ = [
    "CANONICAL_TABLES",
    "CATALOG_PATH",
    "CATALOG_SCHEMA_PATH",
    "BaselineDefinition",
    "GateMetricCatalog",
    "MetricCompiler",
    "MetricCompilerError",
    "MetricDefinition",
    "SCHEMA_VERSION",
    "SOURCE_SENTINEL_AGGREGATION_BLOCK",
    "SPEC_METRIC_NAMES",
    "SPEC_MISSING_DATA",
    "SPEC_UNITS",
    "ValidationError",
    "extract_tables_from_source",
    "load_catalog",
    "load_catalog_schema",
]
