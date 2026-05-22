# `relay.redaction` -- SDK-side redaction

> Generated from packages/sdk-python/relay/__init__.py. Do not edit by hand.

Per CLAUDE.md keystone invariant #7 (default-deny raw capture) and spec
§G, the SDK redacts every trace-bound payload BEFORE the HTTP body
crosses localhost. Plaintext never leaves the calling process on the
default policy. Hosted Relay re-validates as defense in depth, but the
SDK is the first line of defense.

See also: how-to guide [Write a redaction policy](../../how-to/write-redaction-policy.md).

## `DEFAULT_APPLIES_TO_FIELDS`

```python
DEFAULT_APPLIES_TO_FIELDS: Final[tuple[str, ...]] = (
    "model_call.input",
    "model_call.output",
    "tool_call.args",
    "tool_call.result",
    "retrieval.documents",
)
```

The default list of top-level trace-payload fields the matcher set runs
against. Policies may override `applies_to_fields`.

## `RedactionPolicy`

```python
@dataclass(frozen=True)
class RedactionPolicy:
    policy_version: str
    raw_capture: bool
    dpa_ref: str | None
    approver_user_id: str | None
    matchers: tuple[_CompiledMatcher, ...]
    action_policy: _ActionPolicy
    applies_to_fields: tuple[str, ...] = DEFAULT_APPLIES_TO_FIELDS

    @classmethod
    def load(cls, body: dict[str, Any]) -> RedactionPolicy: ...
```

A parsed, validated v1 redaction policy (spec §G.2). Construct via
`RedactionPolicy.load`; direct construction bypasses validation and is
reserved for engine internals.

**raw_capture rule.** Per CLAUDE.md banned pattern #11, `raw_capture:
true` is rejected unless BOTH `dpa_ref` and `approver_user_id` are
non-empty. The SDK refuses to load such a policy, raising
`RelayPolicyError` with `details["reason"] = "raw-capture-missing-dpa-or-approver"`.

**Raises**

- `RelayPolicyError` -- the policy body is structurally invalid.
  `details["reason"]` names the specific failure (`schema_version`,
  `raw_capture_dpa`, `bad_regex`, `unknown_kind`, `unknown_action`,
  etc.). The SDK fails closed; no partially-applied policy is returned
  (VAL-W3-025).

## `RedactionEngine`

```python
class RedactionEngine:
    def __init__(
        self,
        *,
        policy: RedactionPolicy,
        salt_provider: SaltProvider,
    ) -> None: ...

    @property
    def policy(self) -> RedactionPolicy: ...

    def redact(self, payload: dict[str, Any]) -> dict[str, Any]: ...
```

A policy-bound redactor that walks a payload, applies matchers, and
emits a redacted copy. The engine is stateless across calls -- redacting
the same payload twice produces byte-identical output (VAL-W3-024).
Thread-safe.

Determinism (spec §G.3): two engines built from the same policy version
and salt provider produce byte-identical output for the same input.
Hash matchers use HMAC-SHA-256 keyed by the policy's `salt_ref`; plain
SHA-256 is never used (VAL-W3-028).

## `SaltProvider`

```python
SaltProvider = Callable[[str], bytes]
```

Caller-supplied salt resolver. Salts are tenant-scoped secrets the SDK
never bakes in. Production callers wire this to the sidecar salt
registry; tests pass a deterministic in-memory provider.

## `redact_capture_payload`

```python
def redact_capture_payload(
    engine: RedactionEngine, payload: dict[str, Any]
) -> bytes: ...
```

Canonical SDK entry point: redacts `payload` and serialises the result
to UTF-8 JSON bytes (sorted keys, compact separators). The returned
bytes are exactly what the SDK transport hands to the HTTP client;
tests inspect them to assert plaintext absence (VAL-W3-020..024).

**Example**

```python
from relay import RedactionEngine, RedactionPolicy, redact_capture_payload

policy = RedactionPolicy.load({
    "schema_version": "relay.redaction.v1",
    "policy_version": "example.v1",
    "matchers": [
        {
            "id": "secret-field",
            "kind": "regex",
            "pattern": "(?i)secret",
            "action": "redact",
        },
    ],
    "action_policy": {
        "hash": {"algorithm": "hmac-sha256", "salt_ref": "salt_a"},
        "redact": {"placeholder": "<redacted>"},
        "drop": {"placeholder": None},
    },
})
engine = RedactionEngine(policy=policy, salt_provider=lambda ref: b"deterministic-salt-bytes")
wire_bytes = redact_capture_payload(engine, {"model_call.input": "the secret is 42"})
```

Spec: §G
