# Manifest Amendments (Audit Log)

This file records local-only amendments to `.ops/manifest.yaml`.

Why this file exists: `.ops/` is gitignored in this repository (see
`.gitignore:52`), so direct edits to `.ops/manifest.yaml` are NOT versioned
by git. That gitignore rule is being tracked separately as SCR-W1-H001.
Until that is resolved, every functional change to the manifest must be
mirrored here so git history captures the intent, the before/after diff,
and the reasoning, even though the canonical manifest lives only on the
authoring workstation.

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
