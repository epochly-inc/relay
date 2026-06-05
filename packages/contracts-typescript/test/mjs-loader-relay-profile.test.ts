// VAL-CWC-P2TSGATE-004: the .mjs wasm loader threads the relay_profile fence.
//
// The Python loader (packages/cel-wasm/python/relay_cel_wasm.py:85-108) accepts
// `relay_profile` / `container` and, when truthy, adds them to the wasm-request
// JSON under the EXACT field names `relay_profile` (bool) and `container` (str)
// -- the same names the crate reads (crate/src/lib.rs:239-240, 259). The .mjs
// loader previously sent only {expr} / {expr,bindings} and ignored any profile
// fence, so a fenced call (dyn/timestamp/duration) was NOT rejected from the TS
// host even when the caller wanted the Relay profile on.
//
// This suite proves the TS loader now honors a `{relayProfile, container}`
// options object:
//   - eval('dyn(1)', undefined, {relayProfile:true})  -> RELAY-CEL-002 envelope
//     (subtype RELAY-CEL-PROFILE-DYN-DISABLED), the wasm profile rejection.
//   - eval('dyn(1)')                                  -> NOT RELAY-CEL-002
//     (flag-off behavior preserved: the cel-spec conformance harness omits the
//     flag and must stay byte-identical; the wasm evaluates dyn() as a shim).
//   - eval('1 + 2')                                   -> 3 (baseline unchanged).
//
// Both hosts load the SAME signed .wasm, so the request field names MUST match
// the Python loader exactly or the byte-parity contract is void.
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));

// The reproducible build.sh wasm artifact. CEL_WASM overrides for CI layouts
// that vendor the wasm elsewhere; both hosts MUST load the SAME bytes.
const DEFAULT_WASM_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "crate",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "relay_cel_wasm.wasm",
);

// Absolute path to the sibling .mjs loader under test. The test dir is
// packages/contracts-typescript/test/, so the loader is two levels up under
// packages/cel-wasm/typescript/.
const LOADER_PATH = resolve(
  HERE,
  "..",
  "..",
  "cel-wasm",
  "typescript",
  "relay-cel-wasm.mjs",
);

// Structural type for the loader under test (it is plain .mjs, no .d.ts).
interface WasmEnvelope {
  ok: boolean;
  value?: { t: string; v?: unknown };
  error?: string;
  code?: string;
  subtype?: string;
}

interface EvalOptions {
  relayProfile?: boolean;
  container?: string;
}

interface RelayCelLoader {
  eval(
    expr: string,
    bindings?: Record<string, { t: string; v?: unknown }>,
    options?: EvalOptions,
  ): Promise<WasmEnvelope>;
}

interface RelayCelModule {
  RelayCel: {
    load(wasmPath?: string): Promise<RelayCelLoader>;
  };
}

const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;
const wasmPresent = existsSync(wasmPath);

let cel: RelayCelLoader;

describe("VAL-CWC-P2TSGATE-004: .mjs loader honors the relay_profile param", () => {
  beforeAll(async () => {
    // Fail-loud if the wasm is missing: a silent skip would hide whether the
    // fence is threaded at all (keystone invariant #16). Build it via
    // `make -C packages/cel-wasm build` (or set CEL_WASM).
    if (!wasmPresent) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build it via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip: a missing wasm would mask whether the relay_profile " +
          "fence is threaded into the wasm request (keystone invariant #16).",
      );
    }
    const mod = (await import(
      pathToFileURL(LOADER_PATH).href
    )) as unknown as RelayCelModule;
    cel = await mod.RelayCel.load(wasmPath);
  });

  test("relayProfile:true fences dyn(1) -> RELAY-CEL-002 PROFILE-DYN", async () => {
    const env = await cel.eval("dyn(1)", undefined, { relayProfile: true });
    expect(env.ok).toBe(false);
    expect(env.code).toBe("RELAY-CEL-002");
    expect(env.subtype).toBe("RELAY-CEL-PROFILE-DYN-DISABLED");
  });

  test("flag-off dyn(1) is NOT RELAY-CEL-002 (conformance behavior preserved)", async () => {
    const env = await cel.eval("dyn(1)");
    // Without the fence the wasm evaluates dyn() as a working shim: a successful
    // envelope (ok:true). Critically it must NOT be the profile rejection -- the
    // cel-spec conformance harness omits the flag and relies on this.
    expect(env.code).not.toBe("RELAY-CEL-002");
    expect(env.ok).toBe(true);
  });

  test("baseline arithmetic still evaluates: 1 + 2 == 3", async () => {
    const env = await cel.eval("1 + 2");
    expect(env.ok).toBe(true);
    expect(env.value).toEqual({ t: "int", v: "3" });
  });
});
