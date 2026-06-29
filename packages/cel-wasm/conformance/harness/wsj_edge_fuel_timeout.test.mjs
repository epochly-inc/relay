// WS-J edge fuel-timeout node-harness test (VAL-CWC-P7EDGE-006).
//
// Proves the TypeScript/edge loader (packages/cel-wasm/typescript/relay-cel-wasm.mjs)
// threads a positive `fuelBudget` opt through to the wasm eval request so a
// Cloudflare-Workers-shaped path -- NO worker_threads, NO Worker.terminate, NO
// wall-clock thread-kill -- obtains a structured
//   {ok:false, code:"RELAY-CEL-003", subtype:"RELAY-CEL-TIMEOUT-001"}
// purely from the in-engine deterministic fuel counter. The same expression with
// a generous budget returns ok:true (proves the cap, not a hard rejection).
//
// It also pins the no-WASI reactor contract (VAL-CWC-P7EDGE-005): the loader must
// keep instantiating with an EMPTY import object (no host clock, no fuel hook) --
// the fuel counter is in-wasm. We assert the import object handed to
// WebAssembly.instantiate is `{}` by spying on the global, and we assert this
// loader module imports no worker_threads (the edge path is single-threaded).
//
// Run: node --test packages/cel-wasm/conformance/harness/wsj_edge_fuel_timeout.test.mjs
// (built-in node test runner; no extra deps -- the cel-wasm package carries no
// vitest config, and the WS-C contracts-typescript backend test is a SEPARATE
// feature/file. This harness exercises the loader directly, which is what
// VAL-006 requires of THIS loader.)
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { RelayCel } from "../../typescript/relay-cel-wasm.mjs";

// A deterministically fuel-exhausting expression: a nested .map (25 inner
// multiplications + the comprehension scaffolding) whose evaluated AST-node /
// iteration count far exceeds a tiny budget. Same expr the Python loader proves.
const EXHAUSTING_EXPR = "[1,2,3,4,5].map(x, [1,2,3,4,5].map(y, x*y)).size()";
const SMALL_BUDGET = 8;
const GENEROUS_BUDGET = 10000000;
// The u64 max (2**64 - 1). A positive integer the wasm CAN read as a u64 -- the
// largest valid budget. The crate reads fuel_budget with serde as_u64(); a value
// the JSON serializes OUTSIDE u64 becomes 0 (unwrap_or(0)) in the wasm, silently
// DISABLING the budget. The loader fail-closed guard rejects such values BEFORE
// serialization. Note JS Number.MAX_SAFE_INTEGER (2**53 - 1) is already < u64
// max, so Number.isSafeInteger covers the representable-as-exact-u64 requirement
// (a safe integer always serializes as a plain decimal the wasm can read).
const U64_MAX = 18446744073709551615n;

// Spy on WebAssembly.instantiate to capture the import object the loader passes,
// proving the no-import reactor is preserved (VAL-005) end-to-end through the
// fuel path. Restored after capture so we never perturb the real instantiation.
async function loadCapturingImports() {
  const realInstantiate = WebAssembly.instantiate;
  let capturedImports;
  let captured = false;
  WebAssembly.instantiate = function (bytesOrModule, importObject) {
    if (!captured) {
      capturedImports = importObject;
      captured = true;
    }
    return realInstantiate.call(this, bytesOrModule, importObject);
  };
  try {
    const cel = await RelayCel.load();
    return { cel, capturedImports };
  } finally {
    WebAssembly.instantiate = realInstantiate;
  }
}

test("loader instantiates the wasm with an EMPTY import object (no-WASI reactor)", async () => {
  const { capturedImports } = await loadCapturingImports();
  // Empty import object: WebAssembly.instantiate(bytes, {}). Either an empty
  // object literal or undefined leaves the import section unresolved-by-host;
  // the loader uses {}. Assert it has zero own keys (no host clock/fuel hook).
  assert.ok(
    capturedImports !== undefined,
    "loader must pass an import object to WebAssembly.instantiate",
  );
  assert.equal(
    typeof capturedImports,
    "object",
    "import object must be an object",
  );
  assert.equal(
    Object.keys(capturedImports).length,
    0,
    "import object MUST be empty -- the fuel counter is in-wasm, no host import",
  );
});

test("the loader module imports no worker_threads (Workers-shaped, single-threaded edge path)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const loaderPath = normalize(
    join(here, "..", "..", "typescript", "relay-cel-wasm.mjs"),
  );
  const src = readFileSync(loaderPath, "utf8");
  // The edge fuel path must not DEPEND on worker_threads / Worker.terminate to
  // bound runtime -- the in-wasm fuel budget IS the bound. We assert on actual
  // import/usage syntax (an `import ... from "[node:]worker_threads"`, a
  // `require("worker_threads")`, a `new Worker(...)`, or a `.terminate(` call),
  // NOT on prose: the doc comment legitimately describes the Workers-shaped path
  // ("no worker_threads, no Worker.terminate"), so a bare word-grep would
  // false-positive on its own documentation. Strip line/block comments first,
  // then scan the executable source.
  const code = src
    .replace(/\/\*[\s\S]*?\*\//g, "") // block comments
    .replace(/^\s*\/\/.*$/gm, ""); // full-line // comments
  const importsWorkerThreads =
    /\bfrom\s+['"](?:node:)?worker_threads['"]/.test(code) ||
    /\brequire\(\s*['"](?:node:)?worker_threads['"]\s*\)/.test(code);
  const spawnsWorker = /\bnew\s+Worker\s*\(/.test(code);
  const callsTerminate = /\.terminate\s*\(/.test(code);
  assert.equal(
    importsWorkerThreads,
    false,
    "edge loader must not import worker_threads; the in-wasm fuel budget is the bound",
  );
  assert.equal(
    spawnsWorker,
    false,
    "edge loader must not spawn a worker_threads Worker; fuel is the bound",
  );
  assert.equal(
    callsTerminate,
    false,
    "edge loader must not call Worker.terminate (no wall-clock thread-kill on the edge path)",
  );
});

test("fuel-exhausting expr with a small fuelBudget returns RELAY-CEL-003 / RELAY-CEL-TIMEOUT-001 (no thread-kill)", async () => {
  const cel = await RelayCel.load();
  const out = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuelBudget: SMALL_BUDGET,
  });
  assert.equal(out.ok, false, "fuel-exhausting eval must not return ok:true");
  assert.equal(
    out.code,
    "RELAY-CEL-003",
    "fuel exhaustion maps to the existing timeout code RELAY-CEL-003",
  );
  assert.equal(
    out.subtype,
    "RELAY-CEL-TIMEOUT-001",
    "fuel exhaustion maps to the existing timeout subtype RELAY-CEL-TIMEOUT-001",
  );
});

test("the SAME expr with a generous fuelBudget returns ok:true (cap, not a hard rejection)", async () => {
  const cel = await RelayCel.load();
  const out = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuelBudget: GENEROUS_BUDGET,
  });
  assert.equal(
    out.ok,
    true,
    "a generous budget must let the same expr evaluate to a value",
  );
  assert.ok(out.value, "the success envelope carries a value");
});

test("an ABSENT fuel budget on the exhausting expr returns ok:true (off by default)", async () => {
  const cel = await RelayCel.load();
  // No opts at all, and an opts object with no fuel field -- both must be the
  // unbounded form (byte-identical request to the no-fuel form).
  const noOpts = await cel.eval(EXHAUSTING_EXPR);
  const emptyOpts = await cel.eval(EXHAUSTING_EXPR, undefined, {});
  assert.equal(noOpts.ok, true, "no opts => unbounded => ok:true");
  assert.equal(emptyOpts.ok, true, "opts without fuel => unbounded => ok:true");
});

test("fuelBudget=0 is the disabled sentinel: unbounded, request JSON byte-identical to the no-fuel form", async () => {
  // The loader must add fuel_budget to the request ONLY when a positive int, so
  // 0 / negative leave the request byte-identical to the no-fuel form. We verify
  // behavior (unbounded) here; byte-identity is enforced by the positive-only
  // guard in the loader (mirrors the Python loader's fuel_budget > 0 check).
  const cel = await RelayCel.load();
  const zero = await cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: 0 });
  const negative = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuelBudget: -5,
  });
  assert.equal(zero.ok, true, "fuelBudget:0 (disabled sentinel) => unbounded");
  assert.equal(negative.ok, true, "negative fuelBudget => unbounded");
});

// --- FAIL-CLOSED on an out-of-u64 / non-safe-integer fuel budget (roborev MED) -
//
// The crate reads fuel_budget with serde as_u64().unwrap_or(0): a POSITIVE value
// the JSON serializes OUTSIDE u64 (e.g. 1e21, or a JS non-safe integer like
// 2**53) becomes 0 in the wasm -- which is the DISABLED sentinel. So a "large
// finite" budget would SILENTLY become "unbounded" and a fuel-exhausting
// expression would run UNBOUNDED, defeating the timeout. The loader must FAIL
// CLOSED: for a positive number that is NOT a safe integer it THROWS a RangeError
// (surfaces the misconfig) rather than silently sending it (masks it) or silently
// dropping it (also masks it). absent / 0 / negative remain the no-field form.

test("fuelBudget 1e21 (positive, integer, but NOT a safe integer) THROWS a RangeError (fail closed, not a silent unbounded run)", async () => {
  const cel = await RelayCel.load();
  // 1e21 is Number.isInteger===true but serializes as "1e+21", which the wasm's
  // as_u64() cannot read -> unwrap_or(0) -> budget SILENTLY disabled. Must throw.
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: 1e21 }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected a RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      assert.match(
        err.message,
        /fuel/i,
        "the RangeError message must name the offending fuel budget",
      );
      return true;
    },
    "a positive out-of-u64 / non-safe-integer fuelBudget must FAIL CLOSED (throw), never silently disable the budget",
  );
});

test("fuelBudget 2**53 (positive integer just above MAX_SAFE_INTEGER) THROWS a RangeError (fail closed)", async () => {
  const cel = await RelayCel.load();
  // 2**53 == 9007199254740992: Number.isInteger===true, Number.isSafeInteger===
  // false (the first integer that loses exactness). It MAY round on serialize, so
  // it is not a trustworthy budget -> fail closed.
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: 2 ** 53 }),
    RangeError,
    "a positive non-safe-integer fuelBudget must throw a RangeError (fail closed)",
  );
});

test("the snake_case alias fuel_budget is ALSO fail-closed on an out-of-u64 value", async () => {
  const cel = await RelayCel.load();
  // The fail-closed guard must apply to BOTH the camelCase opt key and the
  // snake_case wire-name alias -- both feed the same wasm fuel_budget field.
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuel_budget: 1e21 }),
    RangeError,
    "the snake_case alias must be fail-closed too (same wasm field)",
  );
});

test("an IN-RANGE positive fuelBudget (8) still works after the fail-closed guard (no false rejection)", async () => {
  const cel = await RelayCel.load();
  // A small in-range budget must STILL trip the in-engine timeout (the guard
  // rejects only out-of-u64 values, never an ordinary safe-integer budget).
  const out = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuelBudget: SMALL_BUDGET,
  });
  assert.equal(out.ok, false, "an in-range budget must still cap the eval");
  assert.equal(out.code, "RELAY-CEL-003");
  assert.equal(out.subtype, "RELAY-CEL-TIMEOUT-001");
});

test("a LARGE but still safe-integer fuelBudget (MAX_SAFE_INTEGER) is accepted (boundary: < u64 max, representable)", async () => {
  const cel = await RelayCel.load();
  // Number.MAX_SAFE_INTEGER (2**53 - 1 == 9007199254740991) is the largest exact
  // integer JS can represent; it is < u64 max (2**64 - 1), serializes as a plain
  // decimal the wasm reads, so it is a VALID (huge, effectively unbounded) budget
  // and must NOT be rejected. The exhausting expr finishes under it -> ok:true.
  assert.ok(
    BigInt(Number.MAX_SAFE_INTEGER) < U64_MAX,
    "MAX_SAFE_INTEGER must be < u64 max for this boundary case to be valid",
  );
  const out = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuelBudget: Number.MAX_SAFE_INTEGER,
  });
  assert.equal(
    out.ok,
    true,
    "a safe-integer budget (< u64 max) must be accepted, not rejected",
  );
});

test("snake_case opts.fuel_budget is accepted as an alias for fuelBudget", async () => {
  // The loader mirrors the Python loader's request field name `fuel_budget`; for
  // ergonomic parity it accepts either the camelCase opts key (fuelBudget) or the
  // snake_case wire-name key (fuel_budget) on the opts object.
  const cel = await RelayCel.load();
  const out = await cel.eval(EXHAUSTING_EXPR, undefined, {
    fuel_budget: SMALL_BUDGET,
  });
  assert.equal(out.ok, false);
  assert.equal(out.code, "RELAY-CEL-003");
  assert.equal(out.subtype, "RELAY-CEL-TIMEOUT-001");
});

// --- loaders-1 (audit P2): FAIL CLOSED on a defined NON-number fuel budget ----
//
// The Python loader raises ValueError on any non-int budget (`type(fuel_budget)
// is not int`: a bool, a float, a string, an object). The TS loader's old
// `typeof fuel === "number"` guard SILENTLY DROPPED a non-number truthy budget
// (e.g. the string "8", `true`, `{}`), leaving the eval UNBOUNDED -- a fail-OPEN
// divergence from the Python fail-CLOSED contract (a "budget set" misconfig
// becomes "unbounded", defeating the timeout). The loader now rejects any
// defined-but-non-integer budget with a RangeError, matching Python. The single
// OUTER guard `typeof fuel !== "number" || !Number.isInteger(fuel)` rejects THREE
// classes: (a) non-number truthy values (string/bool/object/BigInt); (b) a
// fractional / NaN / Infinity NUMBER (Number.isInteger is false for all three);
// (c) an integer-but-non-safe positive (1e21, 2**53) is caught by the INNER
// isSafeInteger guard. NaN/Infinity matter because `NaN > 0` is false, so without
// the outer Number.isInteger clause they would slip past as "no field" -> the
// UNBOUNDED fail-OPEN form; the outer guard fails them CLOSED.

test("loaders-1: a string fuelBudget ('8') FAILS CLOSED with a RangeError (was silently dropped -> unbounded)", async () => {
  const cel = await RelayCel.load();
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: "8" }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      assert.match(err.message, /fuel/i, "the error must name the fuel budget");
      return true;
    },
    "a non-number truthy fuelBudget must FAIL CLOSED (throw), not be silently dropped (which leaves the eval UNBOUNDED -- fail-open vs the Python ValueError contract)",
  );
});

test("loaders-1: a boolean fuelBudget (true) FAILS CLOSED (mirrors Python rejecting bool)", async () => {
  const cel = await RelayCel.load();
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: true }),
    RangeError,
    "a boolean fuelBudget must throw (Python: type(True) is bool, not int -> ValueError)",
  );
});

test("loaders-1: an object fuelBudget ({}) FAILS CLOSED", async () => {
  const cel = await RelayCel.load();
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: {} }),
    RangeError,
    "a non-number fuelBudget object must throw, not be silently dropped",
  );
});

test("loaders-1: the snake_case alias fuel_budget is ALSO fail-closed on a non-number budget", async () => {
  const cel = await RelayCel.load();
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuel_budget: "8" }),
    RangeError,
    "the snake_case alias must be fail-closed on a non-number too (same wasm field)",
  );
});

// The fail-closed RangeError message must be built with a NON-THROWING value
// formatter: JSON.stringify itself THROWS a TypeError for a BigInt or a circular
// object, which would replace the documented RangeError with a TypeError and lose
// the diagnostic (roborev 3390681). Both still fail closed (they throw), but the
// error TYPE the caller / tests assert on must stay RangeError.
test("loaders-1: a BigInt fuelBudget FAILS CLOSED with a RangeError (not a TypeError from the formatter)", async () => {
  const cel = await RelayCel.load();
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: 8n }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      assert.match(err.message, /fuel/i, "the error must name the fuel budget");
      return true;
    },
    "a BigInt fuelBudget must fail closed with a RangeError; the error formatter must not throw a TypeError on a non-JSON-serialisable value",
  );
});

test("loaders-1: a circular-object fuelBudget FAILS CLOSED with a RangeError (not a TypeError from the formatter)", async () => {
  const cel = await RelayCel.load();
  const circular = {};
  circular.self = circular;
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: circular }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      return true;
    },
    "a circular-object fuelBudget must fail closed with a RangeError, not a TypeError from JSON.stringify",
  );
});

test("loaders-1: a null-prototype-object fuelBudget FAILS CLOSED with a RangeError (String() coercion cannot throw)", async () => {
  const cel = await RelayCel.load();
  // Object.create(null) has no toString / Symbol.toPrimitive, so String(it)
  // throws 'Cannot convert object to primitive value' -- the formatter must not.
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: Object.create(null) }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      return true;
    },
    "a null-prototype-object fuelBudget must fail closed with a RangeError, never a coercion TypeError",
  );
});

test("loaders-1: a throwing-toString fuelBudget FAILS CLOSED with a RangeError (formatter must not invoke a hostile hook)", async () => {
  const cel = await RelayCel.load();
  const hostile = {
    toString() {
      throw new Error("hostile toString");
    },
  };
  await assert.rejects(
    () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: hostile }),
    (err) => {
      assert.ok(
        err instanceof RangeError,
        `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
      );
      return true;
    },
    "a fuelBudget whose toString throws must still fail closed with a RangeError",
  );
});

// Class (b): a NUMBER that is not an integer -- fractional, NaN, or Infinity.
// Number.isInteger is false for all three, so the OUTER guard fails them CLOSED.
// NaN/Infinity are the dangerous ones: `NaN > 0` and `Infinity` handling could
// let them slip past a weaker guard into the "no field" UNBOUNDED form, so this
// pins the fail-CLOSED behavior the outer Number.isInteger clause provides.
for (const [label, value] of [
  ["fractional 1.5", 1.5],
  ["NaN", NaN],
  ["Infinity", Infinity],
  ["-Infinity", -Infinity],
]) {
  test(`loaders-1: a ${label} fuelBudget FAILS CLOSED with a RangeError (non-integer number)`, async () => {
    const cel = await RelayCel.load();
    await assert.rejects(
      () => cel.eval(EXHAUSTING_EXPR, undefined, { fuelBudget: value }),
      (err) => {
        assert.ok(
          err instanceof RangeError,
          `expected RangeError, got ${err && err.constructor && err.constructor.name}`,
        );
        return true;
      },
      `a ${label} fuelBudget must fail closed with a RangeError (not slip past as UNBOUNDED)`,
    );
  });
}
