# Relay Documentation

Relay is an **agent reliability OS** for teams that ship AI agents. It captures
every LLM call, tool call, and retrieval an agent makes; lets you
**deterministically replay** captured runs against modified code; evaluates
each run against **contracts that gate releases**; and emits signed,
content-addressed **evidence bundles** that prove how the agent behaved.

This site is the user-facing manual for the public Relay OSS distribution
(`epochly-inc/relay`, Apache 2.0). The hosted control plane on
`relay.epochly.com` is a separate commercial product; cross-references to
hosted features are marked explicitly.

## Where do I start?

Six personas drive Relay's day-to-day use. Pick the row that matches your
role and follow its entry-point link.

### Developer / agent author

You write the agent code. You want to wrap an OpenAI / Anthropic / Vercel AI
/ LangChain / MCP call with Relay, see a trace, write a CEL contract that
gates your CI, and pull a signed evidence bundle out the other side.

Start here: [Install Relay](getting-started/install.md).

### Eval engineer

You run quality regressions across model versions, prompts, and tools. You
want pass/fail evaluators, eval-deltas across providers, and assertion
templates that hit a known precision/recall.

Start here: [Evals package overview](../packages/evals/README.md).

### SRE / oncall

A production run went sideways and a customer is on the phone. You want to
load the cassette, replay it deterministically against the current code,
read the `RELAY-REPLAY-*` codes, and decide between cassette-mode and live
replay before you touch anything.

Start here: [Debug a replay failure](how-to/debug-replay-failures.md).

### Compliance officer / auditor

You owe an auditor evidence that a specific agent run met its
**readiness evidence** obligations. You want to pull a bundle, list its
**coverage** and **gaps**, and produce something **ready for auditor
review** without ever touching the agent code.

Start here: [Extract AI Act readiness evidence](how-to/extract-ai-act-readiness-evidence.md).

### ML safety reviewer

You sign off on agent releases. You want to read a CEL contract, audit a
specific `gate_decision` row, walk its three-anchor handoff, and see
exactly why the gate engine wrote `accepted` or `rejected`.

Start here: [Audit a gate decision](how-to/audit-gate-decision.md).

### Contract author

You write the CEL assertions that other teams' agents are gated against.
You want the CEL primer, the Relay UDF reference, and the rules for keeping
custom UDFs `pure` (deterministic, no clock, no network, no filesystem).

Start here: [CEL primer for Relay contracts](contracts/cel-primer.md).

## What this site covers

| Section | What's in it |
|---|---|
| `getting-started/` | Install, first agent, first contract, first evidence bundle, first replay, CI integration |
| `contracts/` | CEL primer, Relay UDF reference, writing assertions, coverage invariant, manifest binding |
| `evidence/` | Bundle anatomy, claim binding, trust anchor, offline verification, signing-key lifecycle |
| `how-to/` | Persona-routed task guides for SRE, compliance officer, ML safety reviewer, contract author, developer CI |
| `reference/` | Auto-generated CLI reference, Python + TypeScript SDK reference, HTTP API, JSON schemas, per-error-code pages, adapter reference |
| `architecture/` | System overview, keystone invariants, state machine, sandbox threat model, trust-anchor pointer |
| `cloud-upgrade/` | Feature parity vs. hosted, migration path from local SQLite to hosted, decision framework for when to upgrade |
| `local-deploy/` | Local sidecar lifecycle, Docker Compose, devcontainer, SQLite storage |
| `legal/` | Trust-anchor governance |
| `compliance/` | EU AI Act readiness scope (no banned product copy; see §J.5) |

Some links above point to pages that land in later waves of the docs
buildout; if a link 404s today, the page is on the roadmap and the audit
script will list it as a known cross-wave reference.

---

The authoritative product spec lives at `planning/epochly-replay-spec.md` in
the workspace parent repository (`epochly-inc/relay-workspace`, private).
This landing page derives from §S (P0/P1/P2 placement) and §AO.4 (default
trust anchor).

Spec: §S, §AO.4
