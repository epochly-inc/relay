# epochly-relay (Python SDK)

Placeholder package skeleton. The Python SDK lands in W3.

For W1.5 (schemas codegen pipeline), this package carries the generated
canonical control-plane envelope models under `relay/_generated/schemas/`.
Source of truth: `packages/schemas/raw/openapi.yaml`.

Generated models are Pydantic v2 `BaseModel` subclasses with
`model_config = ConfigDict(extra='forbid')`. Regenerate via
`uv run python packages/schemas/scripts/codegen.py`.

The hand-authored rich-validation envelopes (cross-field checks, canonical
serializers, RFC 3339 offset enforcement) live under
`packages/schemas/python/relay_schemas/envelopes.py`.

License: Apache 2.0.
