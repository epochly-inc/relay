# @epochly/relay-contracts

TypeScript mirror of the Python `relay_contracts` package. Wraps `cel-js`
behind the Relay CEL profile (CQ1 line 146): native `dyn(...)`,
`timestamp(...)`, and `duration(...)` are rejected at parse time, regex
literals are pinned to the RE2 subset, every evaluation runs under a
wall-clock timeout (default 50 ms, capped at 250 ms), UDFs must be
registered with `pure: true`, and structured outputs are canonicalised
with RFC 8785 JCS so the byte form is identical to the cel-python
output (VAL-W6-014).

ASCII-only per CLAUDE.md "ASCII-Safe Source".
