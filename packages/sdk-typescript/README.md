# @epochly/relay (TypeScript SDK)

Placeholder package skeleton. The TypeScript SDK lands in W4.

For W1.5 (schemas codegen pipeline), this package carries the generated
canonical control-plane envelope types under `src/_generated/`. Source of
truth: `packages/schemas/raw/openapi.yaml`.

Regenerate via:

```bash
uv run python packages/schemas/scripts/codegen.py
```

The hand-authored rich-validation guards (`parseRunResult`,
`parseEventLogEntry`, JCS canonical serializers, etc.) live under
`packages/schemas/typescript/src/envelopes.ts`.

License: Apache 2.0.
