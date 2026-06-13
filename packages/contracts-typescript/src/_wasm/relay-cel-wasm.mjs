// TypeScript/Node/edge loader for the relay-cel-wasm single CEL engine.
//
// This is the OSS-portable JS entrypoint: load the SAME signed `.wasm` reactor
// that the Python backend loads and evaluate CEL expressions over it. It is the
// future replacement for the @bufbuild/cel evaluation core (NOT wired into
// packages/contracts-typescript yet -- that is a later work-stream).
//
// Usage (Node):
//   import { RelayCel } from "./relay-cel-wasm.mjs";
//   const cel = await RelayCel.load();      // loads the release wasm (or CEL_WASM)
//   cel.eval("1 + 2");                       // {ok:true, value:{t:"int",v:"3"}}
//   cel.eval("x > 0", { x: { t: "int", v: "5" } });
//
// On Cloudflare Workers, instantiate from imported wasm module bytes instead of
// readFileSync; the eval() marshaling is identical (a later edge work-stream
// adds the Workers glue + signature verification).
//
// Typed-canonical value form and error envelope match the Python loader and
// crate/src/lib.rs exactly -- that identity is the ADR keystone (byte-parity).
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

// WS-G package-data wasm: the reproducible relay_cel_wasm.wasm is vendored as
// data of @epochly/relay-contracts (packages/contracts-typescript/src/_wasm/),
// so an INSTALLED package resolves the engine WITHOUT the gitignored
// crate/target/ tree. From this loader's directory
// (packages/cel-wasm/typescript/) the vendored copy is two levels up then into
// contracts-typescript/src/_wasm/. Both copies are byte-identical (same pinned
// sha 431d966b...); a Python+TS sha-drift guard catches any divergence.
function packageDataWasmPath() {
  const here = dirname(fileURLToPath(import.meta.url));
  return normalize(
    join(
      here,
      "..",
      "..",
      "contracts-typescript",
      "src",
      "_wasm",
      "relay_cel_wasm.wasm",
    ),
  );
}

function crateTargetWasmPath() {
  const here = dirname(fileURLToPath(import.meta.url));
  return normalize(
    join(
      here,
      "..",
      "crate",
      "target",
      "wasm32-unknown-unknown",
      "release",
      "relay_cel_wasm.wasm",
    ),
  );
}

// Default wasm artifact path (used when no explicit path and no CEL_WASM env).
// Resolution order: the WS-G package-data copy first (works from an installed
// package), then the in-repo crate/target/ build (dev-tree fallback). The
// package-data copy is the same bytes as the build.sh artifact, so either path
// loads an identical engine.
function defaultWasmPath() {
  const packaged = packageDataWasmPath();
  if (existsSync(packaged)) {
    return packaged;
  }
  return crateTargetWasmPath();
}

export class RelayCel {
  #exports;
  #bytes;
  #enc = new TextEncoder();

  constructor(bytes, instance) {
    this.#bytes = bytes;
    this.#exports = instance.exports;
  }

  /** Load from an explicit path, the CEL_WASM env var, or the release build. */
  static async load(wasmPath) {
    const path =
      wasmPath || process.env.CEL_WASM || defaultWasmPath();
    const bytes = readFileSync(path);
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return new RelayCel(bytes, instance);
  }

  /** Load directly from wasm bytes (Cloudflare Workers / no-fs environments). */
  static async fromBytes(bytes) {
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return new RelayCel(bytes, instance);
  }

  async #reinit() {
    const { instance } = await WebAssembly.instantiate(this.#bytes, {});
    this.#exports = instance.exports;
  }

  /**
   * Evaluate `expr` with optional typed `bindings` and an optional
   * `{relayProfile, container, fuelBudget}` options object. Returns the typed
   * result object: success carries `value`, failure carries `error` + `code`
   * (+ `subtype` for profile rejections / fuel exhaustion). A wasm trap (should
   * not happen for in-profile inputs after the G1 fence) is caught, the instance
   * re-instantiated, and reported as ENGINE_PANIC.
   *
   * `relayProfile: true` turns on the Relay CEL profile's call-level
   * restrictions: dyn()/timestamp()/duration() global calls are rejected with
   * RELAY-CEL-002 and the matching subtype. The Relay host wrapper sets this;
   * the cel-spec conformance harness leaves it off (so the request JSON is
   * byte-identical to the no-options form -- the field is ADDED only when
   * truthy). `container` is the optional CEL resolution namespace (e.g.
   * "com.example").
   *
   * `fuelBudget` (alias `fuel_budget`) is the optional per-evaluation
   * deterministic step budget (WS-J): a positive integer caps the number of
   * evaluated AST nodes / comprehension iterations; when the cap is exceeded the
   * in-wasm fuel counter returns a structured
   * `{ok:false, code:"RELAY-CEL-003", subtype:"RELAY-CEL-TIMEOUT-001"}` envelope
   * instead of running unbounded. Because the counter is an engine-internal
   * in-wasm thread-local (no host clock, no host import -- the reactor still
   * instantiates with an EMPTY import object), a Cloudflare-Workers-shaped path
   * (no worker_threads, no Worker.terminate) gets a portable, deterministic
   * RELAY-CEL-003 from the budget rather than from a wall-clock thread-kill. The
   * field is added to the request ONLY when it is a positive SAFE integer, so
   * an absent / 0 / negative / non-int value leaves the request JSON
   * byte-identical to the no-fuel form (0 is the wasm-side disabled sentinel).
   *
   * FAIL CLOSED on an out-of-u64 budget: the wasm reads fuel_budget with serde
   * as_u64().unwrap_or(0), so a POSITIVE value the JSON serializes OUTSIDE u64
   * (e.g. 1e21 -- Number.isInteger but serialized as "1e+21" -- or a JS non-safe
   * integer such as 2**53 that may lose exactness on serialize) would become 0 in
   * the wasm: the DISABLED sentinel. A "large finite" budget silently becoming
   * "unbounded" is an availability foot-gun (a fuel-exhausting expression would
   * then run unbounded, defeating the timeout), so a positive value that is NOT a
   * safe integer THROWS a RangeError -- surfacing the misconfig rather than
   * silently sending it (which masks it) or silently dropping it (also masks it).
   * Number.isSafeInteger is the exact ceiling: MAX_SAFE_INTEGER (2**53 - 1) is
   * already < u64 max (2**64 - 1), and a safe integer always serializes as a plain
   * decimal the wasm can read, so a safe positive integer is a representable u64.
   *
   * The wasm-request field names (`relay_profile`, `container`, `fuel_budget`)
   * MUST match the Python loader (relay_cel_wasm.py) and the crate
   * (crate/src/lib.rs) exactly -- both hosts hit the same reactor.
   */
  async eval(expr, bindings, options) {
    const { memory, alloc, eval: evalFn, dealloc } = this.#exports;
    const req = bindings ? { expr, bindings } : { expr };
    if (options) {
      if (options.container) {
        req.container = options.container;
      }
      if (options.relayProfile) {
        req.relay_profile = true;
      }
      // Mirror the Python loader: add fuel_budget ONLY when a positive SAFE
      // integer, so absent / 0 / negative / non-int leaves the request JSON
      // byte-identical to the no-fuel form (the disabled sentinel is the wasm
      // default). Accept either the camelCase opts key (fuelBudget) or the
      // snake_case wire-name key (fuel_budget).
      const fuel = options.fuelBudget ?? options.fuel_budget;
      if (typeof fuel === "number" && fuel > 0) {
        // FAIL CLOSED on an out-of-u64 / non-safe-integer positive budget: such a
        // value (e.g. 1e21, or 2**53) serializes outside u64, so the wasm's
        // as_u64().unwrap_or(0) would read 0 -- silently DISABLING the budget and
        // letting a fuel-exhausting expression run unbounded. Throw a RangeError so
        // the misconfig surfaces instead of being masked. Number.isSafeInteger is
        // the exact ceiling (MAX_SAFE_INTEGER 2**53 - 1 < u64 max 2**64 - 1).
        if (!Number.isSafeInteger(fuel)) {
          throw new RangeError(
            `fuel budget ${fuel} is not a safe integer (must be a positive ` +
              `integer <= ${Number.MAX_SAFE_INTEGER}); a larger/non-integer value ` +
              "would serialize outside u64 and SILENTLY DISABLE the budget in the wasm",
          );
        }
        req.fuel_budget = fuel;
      }
    }
    const inp = this.#enc.encode(JSON.stringify(req));
    const n = inp.length;
    try {
      const ptr = alloc(n);
      new Uint8Array(memory.buffer, ptr, n).set(inp);
      const packed = BigInt.asUintN(64, evalFn(ptr, n));
      const outPtr = Number(packed >> 32n);
      const outLen = Number(packed & 0xffffffffn);
      const out = new Uint8Array(memory.buffer.slice(outPtr, outPtr + outLen));
      dealloc(outPtr, outLen);
      dealloc(ptr, n);
      return JSON.parse(new TextDecoder().decode(out));
    } catch (e) {
      await this.#reinit();
      return {
        ok: false,
        error: "ENGINE_PANIC",
        code: "RELAY-CEL-PANIC",
        trap: String(e).split("\n")[0],
      };
    }
  }
}

// Tiny CLI smoke when run directly: node relay-cel-wasm.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  const cel = await RelayCel.load();
  for (const e of ["1 + 2", "dyn(1)", "double(1e12)", "size('\u00ff')", "Foo{a: 1}"]) {
    console.log(e, "=>", JSON.stringify(await cel.eval(e)));
  }
}
