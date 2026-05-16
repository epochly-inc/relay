# W17.4 idiom-coverage analyzer (weak form)

Per VAL-W17-019 and contract.md gap #4 reconciliation, this analyzer
ships in v0.1 in its **weak form**: it asserts every Relay UDF
referenced from CEL expressions in `relay/packages/contracts/` has at
least one corresponding case under
`tests/conformance/cel/relay-udfs/<udf>/`.

The **full CEL-idiom taxonomy** (every operator, builtin function,
type coercion, list/map comprehension, regex pattern, etc.) is
deferred to v0.2. Rationale (from contract.md gap #4):

> Idiom-coverage static analyzer (VAL-W17-019) is non-trivial.
> Scanning CEL expression strings for "the set of idioms used"
> requires a CEL parser invocation per expression and a canonical
> idiom taxonomy. The taxonomy is not specified anywhere in spec or
> eng plan. Recommendation: implement the taxonomy as a YAML file at
> `relay/tests/conformance/cel/idiom-taxonomy.yaml` reviewed during
> W6, OR weaken VAL-W17-019 to "every UDF appears in the corpus"
> (covered by VAL-W17-015) and defer full-idiom coverage to v0.2.

The W17.4 worker chose the second option. The weak form is implemented
in `analyzer.py`; the test that consumes it is
`../test_w17_4_idiom_coverage.py`.

## What the analyzer does

1. Walks `relay/packages/contracts/` and
   `relay/packages/contracts-typescript/` (excluding `__pycache__`,
   `node_modules`, and `dist/`).
2. Reads every `.py` / `.ts` / `.tsx` / `.mts` / `.cts` file.
3. Extracts every textual reference to a Relay UDF call site via the
   regex `(?<![A-Za-z0-9_])relay\.NAME(`.
4. Returns the set of distinct UDF names found, with source-file
   and line-number metadata for diagnostics.

## What v0.2 will add

- CEL parser invocation per expression to extract the precise idiom
  set (not just UDF call sites).
- Canonical idiom taxonomy YAML reviewed against the cel-spec
  grammar.
- Per-idiom coverage cross-check (every idiom used in production
  contracts has >= 1 corpus case exercising it).

Until v0.2 lands, the weak form combined with the W6.5 idiom-matrix
assertion (`test_w6_5_corpus.py::test_corpus_idiom_matrix_coverage`,
which enforces >=2 cases for each of 16 named idioms) provides the
release-blocking baseline.
