# Relay

**An agent reliability OS for engineers shipping AI features.**

Relay captures every LLM call, tool call, and retrieval an AI agent makes;
lets you deterministically replay them against modified code; evaluates them
against contracts you write; and produces signed, content-addressed evidence
bundles that prove how the agent behaved.

Apache 2.0. Python, TypeScript, and a `rly` CLI.

[![PyPI](https://img.shields.io/pypi/v/epochly-relay.svg?label=PyPI%20epochly-relay)](https://pypi.org/project/epochly-relay/)
[![npm](https://img.shields.io/npm/v/@epochly/relay.svg?label=npm%20%40epochly%2Frelay)](https://www.npmjs.com/package/@epochly/relay)
[![npm sidecar](https://img.shields.io/npm/v/@epochly/relay-sidecar-bundle.svg?label=npm%20sidecar-bundle)](https://www.npmjs.com/package/@epochly/relay-sidecar-bundle)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Why Relay

If you build with AI agents — LangChain, LangGraph, the OpenAI or Anthropic
SDK, the Vercel AI SDK, MCP servers, or your own framework — you have
already hit at least one of:

- A tool call that worked yesterday and silently does nothing today.
- A structured-output schema the model has started quietly ignoring.
- A retrieval step that returns the right doc in dev and the wrong one
  in production.
- A provider rolled out a new model version and your evals dropped eight
  points overnight, and you cannot tell whether your code or theirs changed.
- A customer can describe what their agent did wrong but you cannot
  reproduce it.

Relay is the layer underneath your agent that makes all of these debuggable.
Think of it as a **flight recorder + replay theatre + contract engine +
evidence factory**, with the same trace format and contract DSL across SDKs.

## Install

```bash
# Python SDK + CLI (installs the `rly` binary)
pip install epochly-relay
# or, with uv:
uv pip install epochly-relay

# TypeScript SDK + sidecar bundle (also installs the `rly` binary)
npm install @epochly/relay
```

Both packages publish from this repo via OIDC trusted publishing with
SLSA L3 provenance and Sigstore attestations on every release.

## 30-second quickstart

Wrap your agent's LLM and tool calls, define a contract, and let Relay
record what happened:

```python
from epochly_relay import trace, model_call, tool_call, validate_contract

@model_call
def ask(prompt: str) -> str:
    ...

@tool_call(side_effect="read")
def search(query: str) -> list[str]:
    ...

with trace(scope_id="refund-policy-lookup") as run:
    answer = ask("Find the policy for refund requests")
    docs = search(answer)
    result = validate_contract("refund_policy_present", run)
    assert result.ok
```

When you want to investigate, replay, or hand the trace to QA or compliance:

```bash
# Re-run a recorded trace against modified code, deterministically
rly replay run refund-policy-lookup --against ./my_agent.py

# Evaluate a saved gate (passes only if every contract holds)
rly gate evaluate refund-quality-gate

# Verify a signed evidence bundle offline (no Relay account required)
rly verify ./bundles/refund-policy-lookup.acef
```

Every command emits machine-readable JSON when given `--json`, and exits
with stable, documented codes. See [`docs/`](docs/).

## What you get

- **One trace format across SDKs.** Python and TypeScript SDKs produce
  byte-identical envelopes; you can record in TS and replay in Python.
- **Cassette-first replay.** Default replay mode plays a recorded
  cassette of provider responses for deterministic re-runs. Live replay
  is opt-in and clearly marked in the resulting evidence.
- **Contracts in CEL.** Describe what "correct" looks like for an agent
  in a declarative DSL with first-class UDFs for tool-arg checks,
  retrieval coverage, and structured-output schema matching.
- **Side-effect aware.** Tool calls declare an idempotency class
  (`read`, `idempotent_write`, `mutating`, `external_irreversible`).
  Replay refuses to re-execute irreversible side effects unless you
  explicitly authorize it.
- **Signed evidence bundles.** Every gate decision binds artifact
  hashes, command exit codes, trace span IDs, contract assertion IDs,
  and a manifest commit hash into one Sigstore-signed bundle you can
  verify offline.
- **Default-deny on raw capture.** The local sidecar never persists
  raw prompts, model outputs, tool arguments, or retrieval documents
  unless you turn raw capture on with a signed redaction policy.
- **Adapters that disappear.** Drop-in adapters for OpenAI, Anthropic,
  Vercel AI SDK, LangChain, LangGraph, and MCP. Your existing code
  keeps working; Relay records and replays around it.

## Package names

Deliberately short and registry-searchable:

| Surface | Name |
|---|---|
| PyPI package | `epochly-relay` |
| Python import | `epochly_relay` |
| **CLI binary** | **`rly`** |
| npm package | `@epochly/relay` |
| npm sidecar bundle | `@epochly/relay-sidecar-bundle` |

## Repository layout

```
relay/
├── packages/
│   ├── sdk-python/                       # Python SDK (epochly-relay)
│   ├── sdk-typescript/                   # TypeScript SDK (@epochly/relay)
│   ├── sdk-typescript-sidecar-bundle/    # signed sidecar bundle (@epochly/relay-sidecar-bundle)
│   ├── cli/                              # `rly` CLI (Typer-based)
│   ├── schemas/                          # JSON Schema 2020-12 + OpenAPI 3.1 + codegen
│   ├── contracts/                        # CEL parser + Relay UDFs + conformance corpus
│   ├── evals/                            # pass/fail evaluators, eval-delta tooling
│   ├── verifier/                         # offline JCS + JWS + Merkle bundle verifier
│   ├── acef/                             # Agent Conversation Evidence Format helpers
│   ├── adapters/                         # OpenAI, Anthropic, Vercel AI, LangChain, MCP
│   └── replay-proxy/                     # mitmproxy-based replay enforcement
├── apps/
│   └── local-sidecar/                    # asyncio + aiosqlite local Relay daemon
├── deploy/
│   ├── local-compose/                    # docker-compose for self-hosted local
│   └── devcontainer/                     # VS Code devcontainer
├── examples/                             # ready-to-run agents (OpenAI, LangChain, Vercel, MCP)
├── tests/
│   ├── contract/                         # tier-1 plumbing (under 60s)
│   ├── integration/                      # tier-2 smoke (under 8 min)
│   ├── golden/                           # canonical envelope + bundle fixtures
│   └── conformance/                      # RFC 8785 JCS, JWS RFC 7515, CEL parity corpus
└── docs/                                 # getting-started, architecture, contracts, evidence
```

## Verifying a release offline

Every published artifact ships with a Sigstore attestation and a SLSA L3
provenance statement. The `rly` CLI verifies them without contacting
Relay infrastructure:

```bash
rly verify ./bundles/your-trace.acef
```

The OSS verifier ships with the canonical JWKS trust anchor at
`relay.epochly.com/.well-known/jwks.json`. You can swap it for your own
trust anchor with `--trust-anchor <url>` for forks or self-hosted
installations. See
[docs/legal/trust-anchor-governance.md](docs/legal/trust-anchor-governance.md)
for the governance rules around key rotation and transparency log
custody.

## Contributing

External contributions are gated on signing the [Relay CLA](CLA.md)
(one-time, electronic, via the CLA Assistant Lite bot) **and** a
`Signed-off-by:` DCO trailer on every commit. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the
three-tier test cadence (plumbing / smoke / eval), and the code-review
expectations.

For security disclosures, please follow the procedure in
[SECURITY.md](SECURITY.md) (do not file a public issue for a
suspected vulnerability).

## License

Apache License 2.0. See [LICENSE](LICENSE).
