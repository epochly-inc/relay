# Manifest Amendments (Audit Log)

This file records local-only amendments to `.ops/manifest.yaml`.

Why this file exists: `.ops/` is gitignored in this repository (see
`.gitignore:52`), so direct edits to `.ops/manifest.yaml` are NOT versioned
by git. That gitignore is a DELIBERATE convention locked post-W1.6 by
orchestrator decision 2026-05-13 (SCR-W1-H001 resolution): the manifest
holds local workstation state (paths, ports, side-effect classes that
differ between dev environments) and is therefore intentionally not
versioned. This file is the canonical propagation channel — every
functional change to the manifest MUST be mirrored here so git history
captures the intent, the before/after diff, and the reasoning. Workers
on other workstations replay these entries against their local
`.ops/manifest.yaml` to stay in sync.

Each entry MUST include:

1. Date (UTC, RFC 3339)
2. Operation + milestone identifier
3. Finding ID (or change driver) being addressed
4. Before / after `cmd` (or other field) verbatim
5. Reasoning + verification command + observed result

---

## 2026-05-13 -- relay-v0.1-oss-wedge / m01-w1-schemas / SCR-W1-002

Driver: scrutiny gate round 1 finding SCR-W1-002 (critical).

Manifest command affected: `test-tier-1`.

### Before

```yaml
- name: "test-tier-1"
  description: "Tier-1 plumbing tests: offline, every commit, budget <= 60s. pytest -m plumbing + vitest plumbing tier."
  cmd: "uv run pytest -m plumbing --timeout=60 --tb=short -q && npm test --workspaces --if-present -- --tier=plumbing"
  cwd: "."
  timeout_ms: 600000
  side_effect_class: "none"
  requires_env: {}
```

### After

```yaml
- name: "test-tier-1"
  # Fix SCR-W1-002: --tier=plumbing was a vitest unknown option (CACError);
  # all vitest tests are tier-1 plumbing in v0.1, so the flag is redundant.
  # Tier-2 smoke gets its own command when introduced in W7/W8.
  description: "Tier-1 plumbing tests: offline, every commit, budget <= 60s. pytest -m plumbing + full vitest suite (all vitest tests are tier-1 plumbing in v0.1; tier-2 smoke gets its own command when introduced in W7/W8)."
  cmd: "uv run pytest -m plumbing --timeout=60 --tb=short -q && npm test --workspaces --if-present"
  cwd: "."
  timeout_ms: 600000
  side_effect_class: "none"
  requires_env: {}
```

### Reasoning

The W1 author appended `-- --tier=plumbing` so npm would forward the flag
to each workspace's `test` script. Each workspace's `test` script runs
`vitest run --reporter=verbose`. Vitest uses the CAC argument parser,
which rejects unknown long flags. The actual failure mode observed by
the orchestrator was:

```
CACError: Unknown option `--tier`
```

The flag does not select a tier; it crashes the runner. The pytest half
of the `&&` chain is correct (`-m plumbing` is a real pytest marker) and
is preserved.

In v0.1 there are no smoke or eval vitest tests. The full vitest suite
is the tier-1 vitest cadence by construction. When tier-2 smoke is
introduced in W7/W8, it gets its own `test-tier-2` manifest command (a
parallel `test-tier-2` slot is already declared at line 134); the W7/W8
work will need to either split the vitest configs or add per-test tags
at that time. That is a deliberate future change, not work for this
fix.

The inline YAML comment in the manifest cites SCR-W1-002 so a future
reader does not re-add `--tier=plumbing`.

### Verification

Command executed at the relay/ working directory:

```bash
bash -c "uv run pytest -m plumbing --timeout=60 --tb=short -q \
         && npm test --workspaces --if-present"
```

Observed:

- Chain exit code: 0
- pytest: 393 passed, 1 warning in 3.84s
- vitest (packages/schemas/typescript): 367 passed (2 test files)
- vitest (packages/sdk-typescript): 17 passed (1 test file)
- Total vitest: 384 passed

Additionally:

- `uv run python scripts/check-codegen-drift.py` -> exit 0
  ("[check] codegen drift: 0 files differ")

Contributes to: VAL-W1-040, VAL-W1-044.

---

## 2026-05-17 -- relay-v0.2-oss-completeness / m03-w3-manifest-locks-guards / VAL-V2M03-010

Driver: w3-manifest sub-feature -- VAL-V2M03-010 requires that
`relay/.ops/manifest.yaml` validate cleanly against the canonical
`packages/schemas/catalogs/manifest.v1.schema.json` (spec F lines
4007-4103) with zero errors.

### Change

Additive augmentation of `.ops/manifest.yaml` with the canonical fields
required by `relay.manifest.v1`. No existing fields removed; the
ops-runner-native fields (`name`, `cmd`, `timeout_ms`, `side_effect_class`,
`requires_env`, etc.) coexist with the spec-canonical fields:

| Level   | Added field(s)                                                              |
|---------|------------------------------------------------------------------------------|
| root    | `schema_version: relay.manifest.v1`                                          |
| root    | `manifest_id: 0d63cba5-5e8e-4b69-9b3f-7c6e3c8a1d11`                          |
| root    | `validation_surfaces[]` (aggregated from existing `test_discovery.*_glob`)   |
| root    | `network_policy.egress_default: deny` + `egress_allowlist[]`                 |
| root    | `artifacts: []`, `side_effect_tools: []`, `mutation_boundaries: []`          |
| root    | `grace_window.seconds: 1800` (spec F line 4095 default)                      |
| command | `id` (= existing `name`), `argv` (shlex-split from `cmd`),                   |
| command | `timeout_seconds` (= `timeout_ms // 1000`, clamped to 1..7200)               |
| command | `network_policy.egress_default: deny` + `egress_allowlist[]` (anchored)      |
| command | `mutation_boundaries: []`, `side_effect_tools: []`, `artifacts: []`          |
| service | `id` (= existing `name`), `image: local:<name>`, `ports: [1]` (sentinels)   |

Reasoning: the existing manifest predates the canonical relay.manifest.v1
schema. Workers operate against the YAML data structure -- the comment
header was operational documentation, not load-bearing for any consumer
(grep across packages/ apps/ scripts/ for `.ops/manifest` returns only
docstrings and grep markers). The augmentation was performed via
yaml.safe_dump roundtrip after dict augmentation; structure is fully
preserved, only the comment header was removed.

For commands whose shell `cmd` includes `&&`, `||`, `|`, or redirect
operators, the canonical `argv` is wrapped as `["sh", "-c", <cmd_str>]`
so the positional-argv invariant is preserved (the ops runner still
interprets the original `cmd` as a shell string verbatim, so behavior
is unchanged).

### Verification

```bash
uv run pytest packages/schemas/python/tests/test_v2m03_manifest.py \
              -m plumbing --timeout=60 --tb=short -q
```

Observed: `25 passed in 0.31s` (covering VAL-V2M03-001 through -011).
The VAL-V2M03-010 specific test
`test_ops_manifest_validates_against_canonical_schema` passes with
zero errors from `Draft202012Validator(schema).iter_errors(body)`.

Contributes to: VAL-V2M03-001, VAL-V2M03-002, VAL-V2M03-003,
VAL-V2M03-004, VAL-V2M03-005, VAL-V2M03-006, VAL-V2M03-007,
VAL-V2M03-008, VAL-V2M03-009, VAL-V2M03-010, VAL-V2M03-011.

