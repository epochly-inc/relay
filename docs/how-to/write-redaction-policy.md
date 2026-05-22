# How to Write a Redaction Policy

A *redaction policy* is the SDK-side filter that scrubs prompts, model
outputs, tool arguments, tool results, and retrieval documents BEFORE the
HTTP body crosses localhost into the Relay control plane. Plaintext never
leaves your process on the default policy. Per CLAUDE.md keystone
invariant #7 (default-deny raw capture), an SDK-internal bug that emits
raw bytes is treated as a P0 product failure regardless of which side
catches it.

This how-to walks through:

1. Why a policy is the load-bearing privacy boundary in Relay
2. The v1 YAML schema as parsed by the Python and TypeScript SDKs
3. The three supported matcher kinds
4. The two non-drop actions (`redact`, `hash`)
5. The `raw_capture` rule -- when raw text MAY be persisted hosted-side,
   and what preconditions are mandatory
6. How `rly contract publish` validates the policy at load time
7. A complete minimal example policy

## Why it matters

Hosted Relay enforces the same rule the SDK does, but the SDK is the
first line of defense. A policy that does not match (a regex with the
wrong character class, a JSON Pointer that misses the actual prompt
path, a `raw_capture: true` policy that slipped past review) sends
plaintext to the hosted ingest. Defense in depth catches it; the
incident is still real.

The right time to author a policy is BEFORE any production traffic is
captured. The right time to review it is whenever any of:

- a new tool is added to the agent (its arguments may carry secrets)
- a new retrieval source is added (its documents may carry PII)
- the prompt envelope changes (the JSON shape the matchers run against
  may have shifted)
- the org's DPA, retention class, or approver list changes

## YAML schema (v1)

The canonical wire `schema_version` is `relay.redaction.v1`. The
codegen-friendly alias `relay.redaction_policy.v1` is also accepted; both
literals load identically across the Python and TypeScript SDKs (see
`packages/sdk-python/relay/redaction.py` `_POLICY_SCHEMA_VERSIONS`).

Top-level fields:

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `schema_version` | string | yes | -- | One of `relay.redaction.v1` or `relay.redaction_policy.v1` |
| `policy_version` | string | yes | -- | Opaque version string captured at publish time; determinism keys off this value |
| `raw_capture` | bool | no | `false` | Whether hosted Relay is permitted to persist raw text |
| `dpa_ref` | string or null | conditional | `null` | Reference to the signed DPA; REQUIRED when `raw_capture: true` |
| `approver_user_id` | string or null | conditional | `null` | User id of the org-admin who approved this policy version; REQUIRED when `raw_capture: true` |
| `matchers` | list of objects | yes | `[]` | Ordered matcher list; see Matcher kinds below |
| `action_policy` | object | yes | -- | Per-action behaviour: `hash`, `redact`, `drop` |
| `applies_to_fields` | list of strings | no | see below | Top-level trace-payload fields the matchers run against |

The `applies_to_fields` default (from
`packages/sdk-python/relay/redaction.py` `DEFAULT_APPLIES_TO_FIELDS`) is:

```
model_call.input
model_call.output
tool_call.args
tool_call.result
retrieval.documents
```

## Matcher kinds

The SDK supports exactly three matcher kinds. Any other `kind` value
fails closed at policy load with
`RelayPolicyError(reason="unknown_kind")`. The set is closed in source
at `_KNOWN_MATCHER_KINDS` in
`packages/sdk-python/relay/redaction.py`.

### `regex`

A Python `re`-compatible (and ECMAScript-compatible on the TS side)
regular expression applied to every reachable string leaf. Strings are
NFKC-normalised plus passed through a small Cyrillic / Greek
confusables map before matching, so a Cyrillic `A` (U+0410) cannot
smuggle a secret past an ASCII `[A-Z]` character class.

Use `regex` when the secret has a syntactic shape (email address, SSN,
API key prefix, phone number).

Required fields: `id`, `kind: regex`, `pattern`, `action`.

Example matcher entry:

```yaml
- id: email
  kind: regex
  pattern: "[\\w.+-]+@[\\w-]+\\.[\\w.-]+"
  action: hash
```

A pattern that fails to compile raises
`RelayPolicyError(reason="bad_regex")` at load time; the SDK never
ships a half-loaded policy.

### `json_pointer`

An RFC 6901 JSON Pointer naming a specific leaf in the payload tree.
The pointer is matched exactly against the pointer the SDK computes
while walking the payload (e.g. `/user/email`,
`/messages/0/content/text`).

Use `json_pointer` when the secret is identified by its position in the
payload rather than its content (e.g. the user-supplied email field is
always at `/user/email`, regardless of what string lives there).

Per-leaf evaluation: a `json_pointer` matcher whose `paths` includes
the current leaf's pointer wins over any `regex` matcher for that leaf,
because the pointer match is the more specific selector (see
`_find_json_pointer_match` in `redaction.py`).

Required fields: `id`, `kind: json_pointer`, `paths` (non-empty list of
strings), `action`.

Example matcher entry:

```yaml
- id: user-fields
  kind: json_pointer
  paths:
    - /user/email
    - /user/dob
  action: redact
```

### `json_path`

An RFC 9535 JSONPath subset selector compiled at policy load to its
equivalent RFC 6901 JSON Pointer. Supported subset (from
`_jsonpath_to_pointer` in `redaction.py`):

- `$` -- the root document
- `$.<key>` -- dotted child access; key chars `[A-Za-z_][A-Za-z0-9_-]*`
- `$.<key>[N]` -- non-negative integer array index
- Chained combinations: `$.a.b[0].c[1]`

Out of scope (raises `RelayPolicyError(reason="json_path_unsupported")`):
recursive descent `..`, wildcards `*`, filter expressions `[?(...)]`,
slices `[start:end:step]`, bracket-notation string keys `['key']`.

Use `json_path` when the JSON Pointer is awkward to write (long
hierarchical paths) or when the selector should live alongside other
JSONPath consumers in the same codebase.

Required fields: `id`, `kind: json_path`, `paths` (non-empty list of
JSONPath strings), `action`.

Example matcher entry:

```yaml
- id: answer-raw
  kind: json_path
  paths:
    - $.answer.raw
  action: redact
```

## Actions

The SDK supports three actions, set on each matcher's `action` field
and parameterised by the policy's `action_policy` block. The set is
closed in source at `_KNOWN_ACTIONS` in `redaction.py`.

### `redact`

Replaces the matched span (regex) or the entire leaf
(`json_pointer` / `json_path`) with `action_policy.redact.placeholder`.
The default placeholder is `<redacted>`.

### `hash`

Replaces the matched span or leaf with the HMAC-SHA-256 hex digest of
the matched substring, keyed by the salt resolved from
`action_policy.hash.salt_ref`. Plain SHA-256 is NEVER used; the SDK
rejects `action_policy.hash.algorithm` values other than `hmac-sha256`
at load time.

Salts are tenant-scoped secrets. The SDK never bakes them in. Production
callers wire a `salt_provider` callable to the sidecar salt registry;
tests pass a deterministic in-memory provider.

### `drop`

Removes the matched span entirely (or emits
`action_policy.drop.placeholder` when configured). Use sparingly --
dropping changes the shape of the payload the downstream consumer sees,
which can mask real errors.

## The `raw_capture` rule (CRITICAL)

Per spec section G.1:

> Hosted Relay does not persist raw prompts, raw outputs, raw tool
> args, or raw retrieval documents by default.

Storage of any raw field requires ALL of the following preconditions
(spec section G.1, enforced in source at `redaction.py` lines 419-434):

1. `raw_capture: true` in the policy body with explicit `retention_days`
   and a `dpa_ref` (UUID of the signed Data Processing Agreement in
   Relay's contract management system).
2. The DPA referenced by `dpa_ref` must be in `signed` state with a
   non-revoked signature from both the customer's org owner and Relay's
   org owner.
3. The `approver_user_id` of the policy version must be an org admin at
   the customer side; the audit log row for the policy create event must
   reference the human approver.

Absent both, the SDK refuses to load the policy with
`RelayPolicyError(reason="raw-capture-missing-dpa-or-approver",
missing=["dpa_ref", "approver_user_id"])`. Hosted ingest re-validates
as defense in depth.

CLAUDE.md banned pattern #11 is exactly this rule: `raw_capture: true`
without a signed DPA and an org-admin approver is a structural violation.
Default-deny is the load-bearing privacy posture; opting in is a paper
process, not a YAML edit.

The hosted default policy at
`packages/schemas/raw/redaction-policy.default.v1.yaml` ships with
`raw_capture: false`, `dpa_ref: null`, `approver_user_id: null` -- the
shape of every policy that has NOT been audited for raw capture.

## Validation

`rly contract publish` parses each candidate policy through the SDK's
`RedactionPolicy.load()`. Failures surface as `RELAY-REDACT-*` error
codes; the reason key on the `RelayPolicyError` (see the
`details["reason"]` field) names the specific failure:

| Reason | Trigger |
|---|---|
| `schema_version` | `schema_version` literal is not `relay.redaction.v1` or `relay.redaction_policy.v1` |
| `policy_version_missing` | `policy_version` absent, empty, or non-string |
| `raw_capture_not_bool` | `raw_capture` is not a strict bool |
| `raw-capture-missing-dpa-or-approver` | `raw_capture: true` without both `dpa_ref` and `approver_user_id` |
| `matchers_wrong_type` | `matchers` is not a list |
| `matcher_wrong_type` | a matcher entry is not a dict |
| `unknown_kind` | matcher `kind` is not `regex`, `json_pointer`, or `json_path` |
| `unknown_action` | matcher `action` is not `redact`, `hash`, or `drop` |
| `matcher_id_missing` | matcher `id` absent or empty |
| `regex_pattern_missing` | regex matcher has no `pattern` |
| `bad_regex` | regex `pattern` fails to compile |
| `json_paths_missing` | `json_pointer` / `json_path` matcher has empty `paths` |
| `json_path_unsupported` | `json_path` selector uses an unsupported feature |
| `hash_algorithm_unsupported` | `action_policy.hash.algorithm` is not `hmac-sha256` |
| `hash_salt_ref_missing` | `action_policy.hash.salt_ref` empty |
| `applies_to_fields_wrong_type` | `applies_to_fields` not a list of non-empty strings |

The SDK fails closed: no partially-applied policy is returned to the
caller. Fix the offending entry and re-publish.

## Example: a minimal policy with all three matcher kinds

```yaml
schema_version: relay.redaction.v1
policy_version: example.v1
raw_capture: false
dpa_ref: null
approver_user_id: null
matchers:
  - id: email
    kind: regex
    pattern: "[\\w.+-]+@[\\w-]+\\.[\\w.-]+"
    action: hash
  - id: api-key
    kind: regex
    pattern: "(sk-|key_)[A-Za-z0-9]{20,}"
    action: redact
  - id: user-email-pointer
    kind: json_pointer
    paths:
      - /user/email
    action: redact
  - id: answer-raw-path
    kind: json_path
    paths:
      - $.answer.raw
    action: redact
action_policy:
  hash:
    algorithm: hmac-sha256
    salt_ref: tenant_salt_v1
  redact:
    placeholder: <redacted>
  drop:
    placeholder: null
applies_to_fields:
  - model_call.input
  - model_call.output
  - tool_call.args
  - tool_call.result
  - retrieval.documents
```

This policy:

- declares the canonical wire `schema_version`
- leaves `raw_capture` at the default-deny value (no DPA, no approver)
- hashes email addresses (so duplicate detection across runs still works
  without storing the address itself)
- redacts API-key-shaped substrings
- redacts the `/user/email` leaf even when the value does not look like
  an email (defense against malformed input)
- redacts the deeply-nested `$.answer.raw` leaf via JSONPath selector
- applies HMAC-SHA-256 with a tenant-scoped salt reference

## See also

- [Extract AI Act readiness evidence](extract-ai-act-readiness-evidence.md)
  -- the compliance-officer walkthrough that consumes the policy version
  recorded on each run.

Spec: §G, §G.1
