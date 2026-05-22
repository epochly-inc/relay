# Schemas reference

> Generated from packages/schemas/catalogs/*.schema.json. Do not edit by hand.

Every canonical Relay schema. Each entry shows the source file, the literal `schema_version` discriminator engines accept, a one-line description, and the required top-level fields. Cross-links point to the narrative documentation that explains how each schema is used.

Total schemas: **2**.

## `manifest.v1`

- **Source:** `packages/schemas/catalogs/manifest.v1.schema.json`
- **schema_version:** `relay.manifest.v1`
- **Description:** Canonical JSON Schema for the Relay Manifest v1 (spec F lines 4007-4103). The manifest is the source of truth for what a worker is allowed to run. Workers REFUSE to execute commands not declared in the active manifest. Every event-log entry written by a worker carries the manifest_commit_hash of the manifest under which it ran. CLAUDE.md keystone invariant 3.
- **Required top-level fields:** `schema_version`, `manifest_id`, `services`, `commands`, `validation_surfaces`
- **See also:** [narrative docs](../../contracts/manifest-binding.md)

## `relay.gate_metric_catalog.v1`

- **Source:** `packages/schemas/catalogs/relay.gate_metric_catalog.v1.schema.json`
- **schema_version:** `relay.gate_metric_catalog.v1`
- **Description:** Canonical schema for the GateMetricCatalog (spec section AA). Conditions in GatePolicy reference metrics by name; this catalog defines them deterministically so two engineers cannot implement diverging aggregations. The compiler validates each metric's `source` SQL FROM/JOIN clause against the active canonical-table registry at publish time. A condition referencing an undefined metric is rejected with RELAY-GATE-031; a metric whose source columns no longer resolve in the active schema is rejected with RELAY-GATE-033; a condition whose source-table completeness falls below the metric's `sampling_eligibility` threshold is rejected at evaluation time with RELAY-GATE-038.
- **Required top-level fields:** `schema_version`, `metrics`, `baselines`
- **See also:** [narrative docs](../../contracts/coverage-invariant.md)

---

Spec: §A
