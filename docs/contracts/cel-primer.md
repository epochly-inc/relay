# CEL Primer for Relay Contracts

Relay contract assertions express their checks as small expressions in CEL
(the Common Expression Language). This page introduces CEL for users who
have never written one before, shows where CEL shows up in Relay, and
explains the single constraint that distinguishes Relay's CEL profile from
upstream CEL: every Relay user-defined function (UDF) MUST be `pure=True`.

## What is CEL

CEL is a small, non-Turing-complete expression language originally designed
at Google for policy and configuration checks. A CEL expression always
returns a single value (typically a `bool`) given a fixed set of named input
variables. CEL has booleans, numbers, strings, lists, maps, comparison and
logical operators, indexed access, function calls, and short-circuit
evaluation. CEL does not have loops, mutable variables, statements,
assignment, or I/O. Relay uses CEL because those omissions are exactly the
ones that make replay deterministic: an expression that cannot read the
wall clock, cannot open a socket, cannot touch disk, and cannot mutate
state produces the same answer on every replay of the same trace.

## Basic syntax

CEL expressions look similar to a Python expression, but the grammar is
intentionally narrower. The snippets below are CEL, not Python; the
operator equivalents will already be familiar.

Literals:

```cel
1 + 2          // 3
"hello"        // string literal
[1, 2, 3]      // list literal
{"k": "v"}    // map literal
true && false  // false
```

Comparison and logical operators (mirroring Python's operator semantics):

```cel
x == "ok"
x != null
x > 10
a && b
a || b
!a
```

Indexed access and field navigation:

```cel
trace.steps
trace["steps"]
call.args["case_id"]
```

Function calls, including dotted-name calls (Relay UDFs are registered
with dotted identifiers such as `relay.coverage`):

```cel
relay.coverage(trace, "plan")
size(trace.steps)
```

The cel-python runtime that Relay uses parses these forms using the same
operator equivalents Python developers expect, with one structural
difference: there are no statements, only one expression per assertion.

## Where CEL appears in Relay

CEL expressions appear in two contract DSL kinds defined in spec section
D: `BehavioralAssertion` (D.1) and `EvalAssertion` (D.5). Both place the
CEL string under the `expression` field of an assertion document. When
the gate engine evaluates an assertion it binds the trace data into
named CEL variables. The bindings that ship in v0.1 are:

- `trace` -- a map containing the run trace, including `trace.steps`
  (a list of step records each with a `name` field).
- `run` -- a map containing run-level metadata; the same shape passed
  to the gate engine.
- `call` -- when an assertion is bound to a single tool invocation,
  `call` is the call record with `call.args` mapping argument names to
  their values.

Three short examples (each a complete CEL expression):

```cel
relay.coverage(trace, "plan") && relay.coverage(trace, "act")
```

```cel
relay.tool_arg(call, "case_id") != null
```

```cel
relay.schema_match(run.output, {"type": "object", "required": ["status"]})
```

Every expression must compile under Relay's CEL profile (no `dyn`, no
`timestamp`, no `duration`, RE2-only regex, wall-clock timeout bounded
per spec section AM.6) and must use only UDFs registered with
`pure=True`.

## Relay UDF surface

Relay ships three production UDFs in v0.1. They are exported from
`packages/contracts/src/relay_contracts/__init__.py` in the `RELAY_UDFS`
tuple and documented per-signature in
[the UDF reference](udf-reference.md).

- `relay.coverage(trace, step_name)` -- returns `true` when
  `trace.steps` contains a step whose `name` equals `step_name`;
  otherwise `false`.
- `relay.schema_match(payload, schema)` -- returns `true` when `payload`
  conforms to a JSON Schema subset declared by `schema`; otherwise
  `false`.
- `relay.tool_arg(call, key)` -- returns `call.args[key]` when present;
  otherwise `null`.

All three are registered in source via `register_udf(..., pure=True)`,
which is the only structural way to register a UDF in Relay.

## PURE-only constraint

This is the single hard rule that separates Relay's CEL profile from
upstream CEL. Every Relay UDF MUST be `pure=True`. This is CLAUDE.md
banned pattern #16, enforced at registration time by `register_udf`,
which raises `RelayUdfPurityError` if `pure=False` is passed.

Permitted inside a pure UDF:

- Reading the inputs the CEL caller passes in.
- Pure arithmetic, comparisons, string equality on Python `str` /
  `celtypes.StringType` (codepoint-based, not locale-aware).
- Lookups against mappings and sequences supplied as inputs.

Forbidden inside a pure UDF:

- No wall clock -- no `time.time()`, no `datetime.now()`, no
  `time.monotonic()`.
- No network -- no `socket`, `urllib`, `httpx`, `requests`.
- No filesystem -- no `open`, no `pathlib.read_*` outside the input
  values themselves.
- No locale-dependent string comparisons -- no `str.lower()` /
  `casefold()` / `locale.strcoll` / collation. Use codepoint equality
  (`==`) only.
- No mutable process globals -- no `os.environ` reads, no module-level
  mutable singletons.
- No random sources -- no `random`, no `secrets`, no `os.urandom`.

Why this is non-negotiable: replay is Relay's evidence guarantee. If a
UDF could read the wall clock or the network, the same trace would
produce different verdicts on different machines, and the cassette
replay determinism contract documented in spec section AC would
collapse. The Relay Conformance Corpus (`tests/conformance/cel/`)
enforces byte-identical JCS-canonical output between the cel-python
and cel-js runtimes for every UDF; any non-determinism would fail the
parity test before merge.

## Your first UDF call

The shortest useful CEL expression in Relay calls `relay.coverage`
against a trace to confirm a named step ran:

```cel
relay.coverage(trace, "plan")
```

Wrap that in a behavioral assertion and the gate engine will evaluate
it on every run that flows through the matching gate.

## Next

- [UDF reference](udf-reference.md) -- full signatures, return types,
  shape tolerance, and parity notes for every Relay UDF.
- [Writing assertions](writing-assertions.md) -- tutorial-style walk
  through composing real assertions and the coverage invariant rules
  that govern them.

Spec: §D, §AC
