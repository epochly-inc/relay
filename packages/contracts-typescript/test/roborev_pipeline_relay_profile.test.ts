// roborev finding 1: evaluateUdfOutputs() called cel.eval() WITHOUT
// {relayProfile:true}, so the wasm did NOT enforce the dyn/timestamp/duration
// fence on the TS mirror path -- the TS host could emit UDF evidence for
// expressions the Python host (which passes relay_profile=True) rejects.
//
// The fix threads {relayProfile:true} (and the optional container) into the
// cel.eval(...) call. A fenced expression (dyn/timestamp/duration) under the
// Relay profile yields a RELAY-CEL-002 envelope, so evaluateUdfOutputs must
// surface that as an error rather than silently produce udf_outputs_jcs.
//
// Tool: vitest. Evidence: vitest exit code + a fenced expression no longer
// produces a successful udf_outputs reconstruction (it raises), while a
// fence-free expression still reconstructs the trace.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, test } from "vitest";

import { evaluateUdfOutputs } from "../src/pipeline.js";

const HERE = dirname(fileURLToPath(import.meta.url));
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
const wasmPath = process.env.CEL_WASM ?? DEFAULT_WASM_PATH;

describe("roborev finding 1: evaluateUdfOutputs threads the relay_profile fence", () => {
  beforeAll(() => {
    if (!existsSync(wasmPath)) {
      throw new Error(
        `relay_cel_wasm.wasm not found at ${wasmPath}. Build via ` +
          "`make -C packages/cel-wasm build` (or set CEL_WASM). This suite " +
          "must not skip: a missing wasm would hide whether the fence is " +
          "threaded into the TS mirror path (keystone invariant #16).",
      );
    }
  });

  // dyn(...) under the Relay profile is fenced (RELAY-CEL-002). With the fence
  // threaded, the wasm returns a non-ok RELAY-CEL-002 envelope, so the udf trace
  // extraction must FAIL (the envelope has no udf_trace / is an error) rather
  // than silently produce a udf_outputs_jcs that the Python host would never
  // emit. We assert the call REJECTS (the TS mirror now matches the Python fence).
  test("a dyn() expression is fenced (the TS mirror no longer emits evidence for it)", async () => {
    let thrown: unknown = null;
    try {
      await evaluateUdfOutputs("relay.tool_arg(dyn(call), 'k')", {
        call: { args: { k: "v" } },
      }, { wasmPath });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).not.toBeNull();
  });

  // A duration() constructor under the Relay profile is fenced (RELAY-CEL-002).
  test("a duration() constructor expression is fenced under the Relay profile", async () => {
    let thrown: unknown = null;
    try {
      await evaluateUdfOutputs("duration('1s') < duration('2s')", {}, {
        wasmPath,
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).not.toBeNull();
  });

  // A timestamp() constructor under the Relay profile is fenced (RELAY-CEL-002).
  test("a timestamp() constructor expression is fenced under the Relay profile", async () => {
    let thrown: unknown = null;
    try {
      await evaluateUdfOutputs("timestamp('2020-01-01T00:00:00Z') > timestamp('2019-01-01T00:00:00Z')", {}, {
        wasmPath,
      });
    } catch (e) {
      thrown = e;
    }
    expect(thrown).not.toBeNull();
  });

  // A fence-FREE relay.* UDF expression still reconstructs udf_outputs_jcs (the
  // fence does not break the happy path).
  test("a fence-free relay.tool_arg expression still reconstructs the udf trace", async () => {
    const result = await evaluateUdfOutputs(
      "relay.tool_arg(call, 'k')",
      { call: { args: { k: "v" } } },
      { wasmPath },
    );
    expect(result.udfsInvoked).toContain("relay.tool_arg");
    expect(result.udfOutputsJcsBytes.length).toBeGreaterThan(0);
  });
});
