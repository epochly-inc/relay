# EU AI Act readiness — public stub

> **Status:** public stub. Full counsel-reviewed Article 11 / Annex IV mapping
> is publication-gated (PW1-6) and lives behind the trust-anchor governance
> review track. This page exists so OSS users can locate the upstream ACEF
> template and understand the scope of what Relay produces today.

## What this page is

This is a pointer, not a counsel-grade interpretation of the EU AI Act. Relay
is an evidence pipeline: it captures runs, binds artifacts to assertions, and
emits signed bundles. It does not render legal conclusions. Customer-facing
surfaces in Relay obey the language discipline in §J.5 of the spec: we speak
in terms of "AI Act readiness evidence", "evidence coverage", and "gaps".
We do not use language that would imply a legal determination.

## Where the mapping template lives

The Article 11 / Annex IV scaffold ships in the public OSS tree as an ACEF
template:

```text
packages/acef/upstream/src/acef/templates/eu-ai-act-2024.json
```

That JSON file is the authoritative source for which Annex IV sections Relay
recognises and which evidence claim shapes map to each section. It is loaded
by the ACEF template registry (`packages/acef/upstream/src/acef/registry.py`)
and is what `relay evidence build` consults when assembling an AI-Act-scoped
bundle.

What the template gives you today:

- The set of Annex IV section identifiers Relay knows about
- The evidence claim shape each section expects (artifact digest, command +
  exit code, trace span IDs, manifest commit hash, redaction policy version)
- A machine-readable mapping suitable for diffing against a system's actual
  captured evidence to surface gaps

What the template deliberately does not give you:

- Counsel-reviewed interpretation of any Annex IV clause
- A determination that a system meets any specific Article 11 obligation
- Any claim about the legal status of a deployed model

That work is publication-gated and tracked under PW1-6 in the
relay-platform private repository. Until it ships, this page and the upstream
template are the public surface.

## How to read the output

When `relay evidence build --scope eu-ai-act-2024` runs against a project, it
produces an ACEF bundle whose `claims[]` are scoped to the Annex IV sections
in the template above. The bundle reports:

- **Evidence coverage:** which Annex IV sections have at least one bound,
  signed claim
- **Gaps:** which Annex IV sections the template recognises but for which the
  project has no bound claim
- **Per-claim binding:** for every claim, the artifact digest, command and
  exit code, trace span IDs, manifest commit hash, and redaction policy
  version that anchor it (per §K)

A bundle reporting non-zero evidence coverage is exactly that — evidence — and
nothing more. It is not a determination of legal status, and Relay output must
not be represented as one. If you are preparing material for an auditor or for
internal counsel review, the bundle is the input to that review, not its
conclusion.

## See also

- Spec §J (compliance assessment) — banned product copy rules in §J.5
- Spec §K (evidence binding) — what makes a claim bound rather than narrative
- Spec §AO (trust anchor) — why bundle signatures are verifiable offline
- `packages/acef/upstream/src/acef/templates/` — full set of upstream
  regulatory templates Relay recognises today
