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
import { readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

function defaultWasmPath() {
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
   * Evaluate `expr` with optional typed `bindings`. Returns the typed result
   * object: success carries `value`, failure carries `error` + `code`. A wasm
   * trap (should not happen for in-profile inputs after the G1 fence) is caught,
   * the instance re-instantiated, and reported as ENGINE_PANIC.
   */
  async eval(expr, bindings) {
    const { memory, alloc, eval: evalFn, dealloc } = this.#exports;
    const req = bindings ? { expr, bindings } : { expr };
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
