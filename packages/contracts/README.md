# epochly-relay-contracts

Relay contract DSL evaluator -- Python side. Houses the `cel-python` wrapper
configured with the Relay CEL profile, the pure-only UDF registry, the
RFC 8785 JCS canonicalizer, and the structured error envelope shared with
the cel-js mirror that ships in W6.2.

Spec anchors: D, AM.6.
Eng plan anchors: CQ1 (single-source CEL evaluator per language;
dyn/timestamp/duration disabled; RE2-only regex; wall-clock
timeout-bounded), X4 (UDFs MUST be registered with pure=True).
CLAUDE.md anchors: keystone invariant 6, banned pattern #16.

Public surface (W6.1):

- `RelayCelEvaluator` -- the cel-python wrapper bound to the Relay profile.
- `register_udf(name, fn, *, pure: bool, ...)` -- raises
  `RelayUdfPurityError` at registration time if `pure=False`.
- `jcs_canonicalize(value)` -- RFC 8785 JCS bytes.
- `RelayCelError` and its subclasses -- the structured error envelope
  carrying canonical `RELAY-CEL-NNN` codes plus stable subtype tokens.

ASCII-only per CLAUDE.md "ASCII-Safe Source".
