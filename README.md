# Relay

> **Status: pre-1.0.** Public scaffold only — implementation in progress. The
> first usable release will be `v0.1.0` once the v0.1 wedge (Python SDK, TS
> SDK, CLI, sidecar, contracts, gate, evals, verifier, ACEF, replay proxy)
> ships.

Relay is an **agent reliability OS**. It captures every LLM call, tool call,
and retrieval an AI agent makes; lets you deterministically replay them
against modified code; evaluates them against contracts you write; and
produces signed, content-addressed evidence bundles that prove how the
agent behaved.

## What Relay is for

If you build with AI agents — LangChain, LangGraph, the OpenAI SDK,
Anthropic SDK, Vercel AI SDK, MCP servers, or your own framework — you
have run into at least one of:

- A tool call that worked yesterday and silently does nothing today.
- A structured-output schema that the model has started ignoring.
- A retrieval step that returned the right doc in dev and the wrong one
  in prod.
- A provider rolled out a new model version and your evals dropped 8
  points overnight, and you cannot tell whether your code or theirs
  changed.
- A customer can describe what their agent did wrong but you can't
  reproduce it.

Relay gives you a **flight recorder + replay theatre + contract engine +
evidence factory**, with the same trace format and contract spec across
SDKs. Run locally during dev, ship signed evidence bundles when the gate
passes.

## Status

- **Public OSS repo:** scaffold only at this commit.
- **Sister private repo:** `epochly-inc/relay-platform` holds the hosted
  control plane and commercial packs. Not required for OSS local use.
- **License:** Apache 2.0.
- **Trust anchor:** the OSS verifier defaults to
  `relay.epochly.com/.well-known/jwks.json`. You can override at the CLI
  with `--trust-anchor <url>` or via config for forks and self-hosters.
  See [docs/legal/trust-anchor-governance.md](docs/legal/trust-anchor-governance.md).

## Naming

Three pieces, deliberately separate so the registry name is searchable and
the CLI is fast to type:

| Surface | Name |
|---|---|
| PyPI package | `epochly-relay` |
| Python import | `epochly_relay` |
| **CLI binary** | **`rly`** |
| npm package | `@epochly/relay` |
| npm `bin` entry | `rly` |

## Install (when v0.1.0 ships)

```bash
# Python SDK + CLI (binary lands as `rly`)
pip install epochly-relay              # or: uv pip install epochly-relay

# TypeScript SDK (also installs the `rly` bundled binary)
npm install @epochly/relay
```

Neither is on the registry yet — this repo is currently a scaffold.

## Quickstart (planned for v0.1)

```python
from epochly_relay import trace, model_call, tool_call, validate_contract

@model_call
def ask(prompt: str) -> str:
    ...

@tool_call(side_effect="read")
def search(query: str) -> list[str]:
    ...

with trace(scope_id="agent-run-2026-05-12") as run:
    answer = ask("Find the policy for refund requests")
    docs = search(answer)
    result = validate_contract("refund_policy_present", run)
    assert result.ok
```

Then later:

```bash
rly replay run agent-run-2026-05-12 --against ./my_agent.py
rly gate evaluate refund-quality-gate
rly verify ./bundles/agent-run-2026-05-12.acef
```

## Repository layout

```
relay/
├── packages/
│   ├── sdk-python/         # Python SDK
│   ├── sdk-typescript/     # TS SDK (cross-runtime parity)
│   ├── cli/                # `relay` CLI (Typer)
│   ├── schemas/            # OpenAPI 3.1 + JSON Schema 2020-12, codegen
│   ├── contracts/          # CEL parser + UDF macros + conformance corpus
│   ├── evals/              # pass/fail evaluators, eval-delta
│   ├── gate/               # gate decision engine (§AA metric catalog)
│   ├── verifier/           # offline JCS + JWS + Merkle verifier
│   ├── acef/               # ACEF wire format helpers
│   ├── adapters/           # OpenAI, Anthropic, Vercel AI, LangChain, MCP
│   └── replay-proxy/       # mitmproxy-based replay enforcement (HTTPS_PROXY)
├── apps/
│   ├── local-sidecar/      # asyncio + aiosqlite local Relay daemon
│   └── web-community/      # local dashboard (deferred)
├── deploy/local-compose/   # docker-compose for self-hosted local
├── examples/               # ready-to-run agents (OpenAI, LangChain, Vercel, MCP)
├── tests/
│   ├── contract/           # tier-1 plumbing (≤60s)
│   ├── integration/        # tier-2 smoke (≤8min)
│   ├── golden/             # canonical fixtures
│   └── conformance/        # RFC 8785 JCS, JWS RFC 7515, CEL, Relay-CEL
└── docs/                   # getting-started, architecture, contracts, evidence, ...
```

## Contributing

External contributions are gated on signing the
[Relay CLA](CLA.md) (one-time, electronic, via CLA Assistant Lite bot)
**and** a `Signed-off-by:` DCO trailer on every commit. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
