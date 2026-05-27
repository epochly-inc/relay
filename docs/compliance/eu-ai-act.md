# EU AI Act readiness evidence

This page describes what Relay produces for EU AI Act conformity assessment
work — Article 12 logging, Annex IV technical documentation, and post-market
monitoring under [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj).

Relay is an evidence pipeline. It records what your AI system did, binds
each captured artifact to a verifiable signature, and emits portable
bundles that you can hand to internal counsel, an auditor, or a notified
body. It does not render legal conclusions and it does not certify a
deployed system. Customer-facing surfaces in Relay use the language
discipline documented in this page: "readiness evidence", "evidence
coverage", and "gaps".

## What the OSS pipeline produces

Three concrete outputs map onto AI Act obligations:

### Article 12 (automatic logging of events)

Every traced agent run is captured by the local Relay sidecar as a signed
envelope. The envelope records the model call, every tool call, every
retrieval step, and the timestamps that anchor them. Envelopes are
written to a tamper-evident append-only log on the local host
(`${RELAY_HOME}/sidecar.db`, SQLite WAL mode). The sidecar refuses to
persist raw prompts, model outputs, tool arguments, or retrieval
documents unless a signed redaction policy explicitly enables raw
capture (see [docs/how-to/write-redaction-policy.md](../how-to/write-redaction-policy.md)).

The append-only log is the substrate for the rest of the pipeline. Each
envelope carries enough binding information (scope identifier, manifest
commit hash, redaction policy version) for a downstream consumer to
reconstruct the context the system ran in.

### Annex IV (technical documentation)

Annex IV requires technical documentation describing the system, its
risk controls, and the evidence that those controls actually fired. The
Relay gate engine produces this evidence per gate decision:

- Every contract that was evaluated, with its CEL source.
- Every assertion that was checked, with its identifier.
- The artifact hashes the assertion saw.
- The manifest commit hash the system was built against.
- The trace span identifiers the assertion referenced.
- The redaction policy version active at evaluation time.

These bindings travel inside the signed evidence bundle, so a third
party verifying the bundle can reproduce the gate decision without
contacting your CI or your Relay deployment.

### Post-market monitoring

Cassette-first replay reproduces a customer-reported failure
deterministically against the exact model version and tool surface the
system saw at the time of the incident. See
[docs/how-to/debug-replay-failures.md](../how-to/debug-replay-failures.md).
Because the cassette is content-addressed, a recorded failure replays
identically months later, even after the provider rolls out a new model
version.

## The Annex IV mapping template

Relay ships a machine-readable mapping of EU AI Act provisions to
evidence claim shapes:

```text
packages/acef/upstream/src/acef/templates/eu-ai-act-2024.json
```

The template enumerates every Annex IV provision Relay's evidence
pipeline can produce structured claims for, with each provision linked
to the normative text reference (`Regulation (EU) 2024/1689` article and
paragraph), the applicable system types (high-risk, GPAI,
GPAI-systemic, limited-risk), and the evidence claim shape the
provision expects.

The template covers (non-exhaustive):

- Article 9 — Risk management system
- Article 10 — Data governance
- Article 11 — Technical documentation
- Article 12 — Automatic logging
- Article 13 — Transparency and provision of information
- Article 14 — Human oversight
- Article 15 — Accuracy, robustness, and cybersecurity
- Annex IV — Technical documentation contents

The same template directory holds parallel files for NIST AI RMF 1.0,
the NIST GAI Profile (AI 600-1), ISO/IEC 23894:2023, ISO/IEC 42001:2023,
the EU GPAI Code of Practice 2025, and the China CAC labeling rules
2025. Pick the template that matches your jurisdiction.

## How OSS users consume the template

The OSS pipeline gives you three building blocks:

1. **Capture.** Run your agent under the Relay SDK; the local sidecar
   records every model call, tool call, and retrieval as a signed
   envelope.
2. **Evaluate.** Author CEL contracts that map to the Annex IV
   provisions you care about. The gate engine evaluates them against
   the captured trace. Each gate decision is emitted as a signed
   evidence bundle with the bindings described above.
3. **Verify.** Run `rly evidence verify <bundle>` to confirm the bundle
   is intact, signatures resolve against the published JWKS trust
   anchor, and every claim is bound to its underlying artifact. The
   verifier runs fully offline.

Operators preparing conformity assessment material treat the resulting
bundles as the input to their counsel review or notified-body
submission. The bundle is structured so a human reviewer can see, per
Annex IV section, whether evidence exists and what it consists of.

## Important: what Relay does not do

- Relay does not determine whether a system conforms to the AI Act.
  Conformity assessment is the operator's responsibility (Article 43)
  and, for high-risk systems, the notified body's.
- Relay does not represent its output as a legal opinion. The bundles
  are evidence — recordings of what the system did, signed and bound
  to their context. Legal conclusions are downstream of Relay.
- Relay does not exempt operators from any AI Act obligation. The
  pipeline produces the evidence record an auditor asks for; it does
  not substitute for the obligations themselves.

## See also

- [docs/how-to/extract-ai-act-readiness-evidence.md](../how-to/extract-ai-act-readiness-evidence.md)
  — step-by-step procedure for emitting an AI-Act-scoped evidence bundle.
- [docs/evidence/bundle-anatomy.md](../evidence/bundle-anatomy.md) —
  the structure of a signed evidence bundle.
- [docs/evidence/claim-binding.md](../evidence/claim-binding.md) — what
  makes a claim bound versus narrative.
- [docs/evidence/offline-verification.md](../evidence/offline-verification.md)
  — how `rly evidence verify` works without contacting Relay.
- [docs/legal/trust-anchor-governance.md](../legal/trust-anchor-governance.md)
  — key rotation and transparency log custody rules.
