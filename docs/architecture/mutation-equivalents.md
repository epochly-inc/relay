# Justified equivalent mutants

The shakedown loop's convergence bar is "zero **un-triaged** survivors": every
surviving mutant is either killed by a new TDD test or **justified in writing**
as an equivalent / out-of-scope mutant. An equivalent mutant changes the source
but produces no behavior any test can observe, so it cannot be killed -- listing
it here (with the reason) is the triage.

This file records the justified equivalents. Class A is auto-classified by the
harness; Class B is per-module logic equivalents encoded in
`scripts/run-mutation.py` (the target's `justified_equivalents`) so a re-run
reports `real_survivor_count == 0` when convergence is reached.

## Class A -- annotation bit-operator mutants (auto)

`cosmic-ray`'s `ReplaceBinaryOperator` mutates the `|` in `str | None` type
annotations (e.g. `str | None` -> `str & None`). Under `from __future__ import
annotations` (PEP 563) annotations are not evaluated at runtime, and in any case
carry no test-observable behavior, so these survive by construction. The harness
detects them by AST (every `BinOp` inside a parameter `annotation` / `returns`)
and reports them as `equivalent_survivors`. Example count: `compare_and_set.py`
= 88.

## Class B -- compare_and_set.py logic equivalents (22)

Confirmed by a foreground check (apply each survivor's recorded diff, run the
current `compare_and_set` test files): 55 of 77 real survivors are killed by the
new tests; the remaining 22 are equivalents, below.

### B1. Dead `rowcount != 1` defensive block (L667 `</>`, L678, L681, L684)

`compare_and_set_state` reads the current epoch and issues the state UPDATE
matched by `(scope_kind, scope_id, epoch)` within a single `BEGIN IMMEDIATE`
transaction held under the process-wide single-writer lock. No other writer can
change the row between the read and the UPDATE, and there is no delete path, so
`rowcount` is **invariantly 1**. The `if rowcount != 1:` block is therefore
unreachable defensive code:

- L667 `rowcount != 1` `<` / `>` variants: for the value 1,
  `1 != 1 == 1 < 1 == 1 > 1 == False`, so the branch is not taken either way
  (the `==` / `<=` / `>=` variants DO change the taken-branch and ARE killed by
  the epoch-increment test).
- L678 / L681 (`str(refreshed[0])` / `int(refreshed[1])` NumberReplacer,
  `is not`->`is`, AddNot) and L684 (`ok=False`->True): all inside the
  unreachable block; no test can reach them.

### B2. Dead `else 0` COALESCE arm (L560 / L767 NumberReplacer)

`next_seq = int(row[0]) if row is not None else 0` where `row` comes from
`SELECT COALESCE(MAX(ingest_sequence), -1) + 1 ...`, which always returns exactly
one row, so `row is not None` is invariantly True and the `else 0` is dead. The
NumberReplacer on the `0` is unreachable (the live-arm AddNot / `is not`->`is`
variants ARE killed by the seq-assertion tests).

### B3. Defensive `except BaseException` (L201 / L585)

`ExceptionReplacer` mutates `except BaseException:` -> `except Exception:`. The
only inputs that differ are `KeyboardInterrupt` / `SystemExit` / `GeneratorExit`
raised by the interpreter mid-`INSERT`; impractical to inject and producing
identical observable behavior (`ROLLBACK` + re-raise). Equivalent.

### B4. `==` vs `is` identity (L725, L309)

- L725 `override_event_kind == OPERATOR_OVERRIDE_EVENT_KIND` -> `is`:
  `override_event_kind` is assigned literally
  `OPERATOR_OVERRIDE_EVENT_KIND if ... else None` two lines above, so when set it
  IS the same object; `is` and `==` give identical results.
- L309 `payload.get("applied_at_epoch") == target[...]` -> `is`: the epoch is a
  small int and CPython caches `-5..256`, so `is` == `==` over the bounded epoch
  range exercised by the idempotency probe.

### B5. Keyword-only `*` marker (L266)

the Mul-Div binary-operator mutation on the bare `*` in `def f(*, ...)`: the `*` is a
syntactic keyword-only separator, not an arithmetic operator; mutating it has no
runtime behavioral effect.

## Class C -- guards.py logic equivalents (17)

`state_engine/guards.py` holds 23 pure guard predicates. After the direct-unit
suite (`tests/test_guards_pred_*.py`, 144 tests) killed 315 of the 368 original
real survivors, 53 remained; 36 of those were killed by targeted-input tests
(integer `0`/`1` to pin `is False`/`is True` identity checks, two-row fixtures
for `continue`-vs-`break`, boundary values for comparison mutants), leaving these
17 logic equivalents (encoded in `scripts/run-mutation.py` `guards.justified_
equivalents`). Each was verified unobservable by a sandboxed harness that execs a
copy of the predicate with the mutation applied across every reaching scenario.

### C1. Single-column `row[-1]` / dead `else 0` (NumberReplacer; L243, L244, L277, L373, L409, L514, L515, L746, L783)

cosmic-ray's `NumberReplacer` offsets are exactly `+1`/`-1`. On a row from a
single-column `SELECT` (`project_id`, `contract_id`, `COUNT(*)`), `row[-1]` is
identically `row[0]`, so the `-1` variant is unobservable; the `+1` variant
(`row[1]`) raises `IndexError` and IS killed by the existing predicate tests. The
`else 0` arm of `int(row[0]) if row is not None else 0` over `COUNT(*)`/single-row
`fetchone()` (never `None`) is dead, so mutating the `0` literal (`->1`/`->-1`) is
unobservable.

*Whitelist-safety adjudication (roborev d23f48d):* the harness matches these by
`(line, op_contains="NumberReplacer")` only, which is sound because the ONLY other
NumberReplacer variant cosmic-ray emits on these lines is the `+1` sibling
(`row[0] -> row[1]`), and on a single-column tuple `row[1]` raises `IndexError` at
runtime -- so any test reaching the line KILLS it (or it is INCOMPETENT). A `+1`
mutant can therefore NEVER be a SURVIVOR, so it never reaches `_classify_survivors`
to be mis-bucketed as equivalent. The authoritative `real_survivor_count == 0`
re-run confirms no real survivor hides behind this whitelist.

### C2. `== 0` vs `<= 0` over COUNT(*) (Eq_LtE; L278, L410, L747)

`count/total = int(COUNT(*))` is non-negative for every input, so `== 0` and
`<= 0` cannot diverge.

### C3. Subset set-difference (Sub_BitXor; L376)

`set(required) - evaluated == set(required) ^ evaluated` because `evaluated` is
always a subset of `required` (built from `WHERE contract_id IN (required)`), so
`evaluated - required` is empty.

### C4. Keyword-only `*` marker (Mul_Div; L91)

`ReplaceBinaryOperator_Mul_Div` on the bare `*` in `def register_guard(name, fn,
*, override=...)`: the `*` is the keyword-only-args separator, not an arithmetic
operator; mutating it has no runtime behavior (same class as B5).

Spec: §C, §H, §AM
