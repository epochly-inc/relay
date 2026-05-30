// Relay-profile cel-js evaluator wrapper (TypeScript).
//
// The single TypeScript CEL evaluator (VAL-W6-010). Constructed with
// the Relay CEL profile (VAL-W6-011): `dyn` disabled, native CEL
// `timestamp(...)` and `duration(...)` disabled, regex pinned to the
// RE2 subset cel-js accepts (cel-js does not implement string.matches()
// at parse-time but the profile pre-screens regex literals in the raw
// expression text before handing to cel-js so backreference fixtures
// produce the same RELAY-CEL-007 / RELAY-CEL-PROFILE-REGEX-BACKREF
// envelope the cel-python module emits, satisfying VAL-W6-014's
// "identical input expression -> identical error code" contract).
//
// Every evaluation runs under a wall-clock timeout (VAL-W6-012)
// enforced by `worker_threads.Worker.terminate()` and rejects NaN /
// +Inf / -Inf at the result boundary. UDFs are registered through the
// pure-only `registerUdf` (VAL-W6-013) and serialised via
// `Function.prototype.toString()` for transport to the worker -- safe
// because every UDF is pure (CLAUDE.md banned pattern #16).
//
// Mirrors packages/contracts/src/relay_contracts/evaluator.py.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { createRequire } from "node:module";
import {
  MessageChannel,
  receiveMessageOnPort,
  Worker,
  type MessagePort,
} from "node:worker_threads";
import { parse, type Success } from "cel-js";

import {
  RelayCelError,
  RelayCelNumericOutOfBoundsError,
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  RelayCelTimeoutError,
  SUBTYPE_PROFILE_DUR_DISABLED,
  SUBTYPE_PROFILE_DYN_DISABLED,
  SUBTYPE_PROFILE_TS_DISABLED,
} from "./errors.js";
import type { PureUdf } from "./udf.js";

// CQ1 line 153 ("timeout-bounded"): default per-evaluation wall-clock
// budget is 50 ms; the per-tenant override caps at 250 ms.
export const DEFAULT_TIMEOUT_MS = 50;
export const MAX_TIMEOUT_MS = 250;

// VAL-PARITY-001: integral evaluation results whose absolute value exceeds
// 2**53 are rejected at the result boundary, mirroring
// packages/contracts/src/relay_contracts/evaluator.py SAFE_INTEGER_BOUND.
// cel-python keeps such an integer exact (arbitrary precision) while a JS
// double silently rounds it, so the same logical result would canonicalise
// to DIFFERENT JCS bytes in each runtime -- a cross-runtime digest break
// (CLAUDE.md keystone invariant #11). Both runtimes apply the SAME numeric
// threshold (abs > 2**53) so they fail-closed identically. The boundary
// value 2**53 is itself a power of two -- exactly representable as a double
// and byte-identical across runtimes -- so it is accepted; only abs > 2**53
// is rejected. (Note: 2**53 === Number.MAX_SAFE_INTEGER + 1; the bound is
// expressed as the numeric threshold rather than Number.isSafeInteger,
// which would also reject the byte-safe boundary value 2**53.)
export const SAFE_INTEGER_BOUND = 2 ** 53; // 9007199254740992

// Disabled native CEL identifiers when used as function calls
// (`dyn(x)`, `timestamp("...")`, `duration("...")`). Detection runs
// at parse/check time so the violation is surfaced before any
// evaluation. cel-js parses these as `macrosExpression` CST nodes
// regardless of whether it implements the macro -- we walk the CST
// to find them.
const DISABLED_BUILTINS: Record<string, { msg: string; subtype: typeof SUBTYPE_PROFILE_DYN_DISABLED | typeof SUBTYPE_PROFILE_TS_DISABLED | typeof SUBTYPE_PROFILE_DUR_DISABLED }> = {
  dyn: {
    msg:
      "Relay CEL profile disables 'dyn(...)': dynamic typing breaks " +
      "cross-runtime determinism.",
    subtype: SUBTYPE_PROFILE_DYN_DISABLED,
  },
  timestamp: {
    msg:
      "Relay CEL profile disables native 'timestamp(...)': use " +
      "schema-typed timestamp inputs instead.",
    subtype: SUBTYPE_PROFILE_TS_DISABLED,
  },
  duration: {
    msg:
      "Relay CEL profile disables native 'duration(...)': use " +
      "schema-typed duration inputs instead.",
    subtype: SUBTYPE_PROFILE_DUR_DISABLED,
  },
};

// Regex feature detection: backreference (\1, \2, ...) -- RE2 forbids
// these so we pre-screen them in the raw expression text. We screen
// the entire expression text rather than walking the cel-js CST
// because cel-js does not implement `string.matches()` at parse time
// (it rejects `"x".matches("y")` as `Redundant input, expecting EOF`)
// and the cross-runtime contract requires the backref-bearing
// expression to produce RELAY-CEL-007 in BOTH runtimes.
//
// The pattern matches `\<digit>` inside a string literal in the raw
// expression text. Single-quoted and double-quoted CEL strings both
// parse the backslash literally; an inner `\1` in the source text
// becomes the regex backref `\1` after CEL string parsing.
const STRING_LITERAL_PATTERN = /(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g;
const REGEX_BACKREF_PATTERN = /\\\d/;

interface CompiledExpression {
  expression: string;
  cst: unknown;
  bindings: Record<string, unknown>;
}

interface WorkerOk {
  ok: true;
  result: unknown;
}

interface WorkerErr {
  ok: false;
  error: { name: string; message: string };
}

type WorkerMessage = WorkerOk | WorkerErr;

interface UdfSpec {
  name: string;
  source: string;
}

// Walk the cel-js CST looking for `macrosExpression` nodes whose
// Identifier is one of the disabled builtins.
function checkProfileCst(cst: unknown): void {
  function walk(node: unknown): void {
    if (node === null || typeof node !== "object") {
      return;
    }
    const obj = node as { name?: string; children?: Record<string, unknown[]> };
    if (obj.name === "macrosExpression") {
      const idArr = obj.children?.["Identifier"];
      if (Array.isArray(idArr) && idArr.length > 0) {
        const idTok = idArr[0] as { image?: string } | undefined;
        const image = idTok?.image;
        if (typeof image === "string") {
          const entry = DISABLED_BUILTINS[image];
          if (entry !== undefined) {
            throw new RelayCelProfileError(entry.msg, entry.subtype);
          }
        }
      }
    }
    if (obj.children !== undefined) {
      for (const key of Object.keys(obj.children)) {
        const arr = obj.children[key];
        if (!Array.isArray(arr)) {
          continue;
        }
        for (const child of arr) {
          walk(child);
        }
      }
    }
  }
  walk(cst);
}

// Pre-screen the raw expression text for string literals containing
// regex backreferences. Mirrors packages/contracts/src/relay_contracts/
// evaluator.py:151-167. Only the first string-literal hit matters --
// any backref triggers the same envelope.
function checkRegexBackref(expression: string): void {
  let match: RegExpExecArray | null;
  // Reset lastIndex by reconstructing via fresh regex execution loop.
  const re = new RegExp(STRING_LITERAL_PATTERN.source, STRING_LITERAL_PATTERN.flags);
  while ((match = re.exec(expression)) !== null) {
    // match[1] = double-quoted body, match[2] = single-quoted body.
    const body = match[1] ?? match[2];
    if (typeof body === "string" && REGEX_BACKREF_PATTERN.test(body)) {
      throw new RelayCelRegexBackreferenceError(
        "Relay CEL profile pins regex to the RE2 subset; " +
          "backreferences (e.g., \\1) are not supported.",
      );
    }
  }
}

// Recursive finite-number check on a result tree. Lists and plain
// objects recurse; numeric leaves throw on non-finite OR on an integral
// value outside the IEEE-754 safe range. Mirrors
// packages/contracts/src/relay_contracts/evaluator.py _check_finite.
function checkFinite(value: unknown): unknown {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new RelayCelNumericOutOfBoundsError(
        `Relay CEL evaluator rejects non-finite number: ${String(value)}`,
      );
    }
    // VAL-PARITY-001: an integral result whose magnitude exceeds 2**53 is
    // an out-of-band signal -- cel-python preserves it exactly while a JS
    // double rounds it, diverging the cross-runtime digest. Fail-closed
    // here so cel-js refuses the same result cel-python refuses. The
    // boundary value 2**53 is exactly representable and accepted; only
    // abs > 2**53 is rejected. Non-integral numbers (e.g. 1.5) are not
    // subject to this bound.
    if (Number.isInteger(value) && Math.abs(value) > SAFE_INTEGER_BOUND) {
      throw new RelayCelNumericOutOfBoundsError(
        "Relay CEL evaluator rejects integer outside the IEEE-754 safe " +
          "range [-2**53, 2**53]: a cel-js double would lose precision " +
          `and diverge the cross-runtime digest: ${String(value)}`,
      );
    }
    return value;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      checkFinite(item);
    }
    return value;
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      checkFinite(obj[k]);
    }
    return value;
  }
  return value;
}

// Resolve cel-js to an absolute path so the worker (eval-mode) can
// dynamic-import it without depending on the worker's CWD or its
// inheriting node_modules visibility. createRequire accepts the
// caller's import.meta.url so resolution starts from THIS source
// file's neighbours -- which include the @epochly/relay-contracts
// node_modules tree (npm-workspaces-hoisted to relay/ root).
const requireFromHere = createRequire(import.meta.url);
const CELJS_ABSOLUTE_PATH = requireFromHere.resolve("cel-js");

// JSON-escape an absolute path for safe interpolation into the worker
// source string. Path separators are not JSON-special; double quotes
// and backslashes are. Cross-platform safe (Windows backslashes
// would be escaped here).
function jsonStringForPath(p: string): string {
  return JSON.stringify(p);
}

// Build the persistent worker's source text. The worker imports
// cel-js once at startup, reconstructs UDFs from
// `Function.prototype.toString()` source via `new Function`, then
// listens for evaluate-request messages on its parentPort and posts
// back results. The worker is reused across many evaluate() calls on
// a single RelayCelEvaluator instance, amortising the ~100 ms cel-js
// cold-import cost.
//
// Errors are forwarded by name + message; class identity does not
// survive structured clone but the parent maps the message text back
// to the right Relay envelope.
//
// Termination: the parent calls `worker.terminate()` to abort an
// in-flight evaluation on timeout, then spawns a fresh worker on the
// next evaluate() call (lazy respawn).
function buildWorkerSource(): string {
  const celjsLiteral = jsonStringForPath(CELJS_ABSOLUTE_PATH);
  return [
    "const { workerData } = require('node:worker_threads');",
    "const celjsPath = " + celjsLiteral + ";",
    "// The parent passes a MessagePort via workerData (transferList).",
    "// We use this dedicated port instead of parentPort so the parent",
    "// can synchronously poll messages via receiveMessageOnPort.",
    "const port = workerData.port;",
    "let evaluator = null;",
    "let functions = {};",
    "// Reconstruct UDFs once at startup. Pure UDFs have no closure",
    "// state so Function.prototype.toString() round-trips losslessly.",
    "for (const u of (workerData.udfs || [])) {",
    "  functions[u.name] = (new Function('return (' + u.source + ');'))();",
    "}",
    "const ready = import(require('node:url').pathToFileURL(celjsPath).href).then(mod => {",
    "  evaluator = mod.evaluate;",
    "  port.postMessage({ kind: 'ready' });",
    "}).catch(e => {",
    "  port.postMessage({ kind: 'startup_error', error: {",
    "    name: (e && e.constructor && e.constructor.name) || 'Error',",
    "    message: (e && e.message) || String(e),",
    "  }});",
    "});",
    "port.on('message', (msg) => {",
    "  if (msg.kind !== 'evaluate') return;",
    "  const reqId = msg.reqId;",
    "  ready.then(() => {",
    "    if (typeof evaluator !== 'function') {",
    "      port.postMessage({ kind: 'result', reqId, ok: false, error: { name: 'Error', message: 'evaluator unavailable (cel-js import failed)' } });",
    "      return;",
    "    }",
    "    try {",
    "      const result = evaluator(msg.expression, msg.bindings || {}, functions);",
    "      port.postMessage({ kind: 'result', reqId, ok: true, result });",
    "    } catch (e) {",
    "      port.postMessage({",
    "        kind: 'result', reqId, ok: false,",
    "        error: { name: (e && e.constructor && e.constructor.name) || 'Error', message: (e && e.message) || String(e) },",
    "      });",
    "    }",
    "  });",
    "});",
  ].join("\n");
}

const WORKER_SOURCE = buildWorkerSource();

// Map cel-js error messages back to a RelayCelError. cel-js raises
// `Error("Macros X not recognized")` for unknown macros at evaluate
// time -- but our profile check at compile() rejects dyn / timestamp
// / duration BEFORE evaluation begins, so this path catches only
// genuinely-unknown macros (defensive).
const MACRO_NOT_RECOGNIZED_PATTERN =
  /^Error\s+Macros\s+(\w+)\s+not\s+recognized$/;

function reraiseFromWorker(err: { name: string; message: string }, expression: string): never {
  const macroMatch = MACRO_NOT_RECOGNIZED_PATTERN.exec(err.message);
  if (macroMatch !== null) {
    const macroName = macroMatch[1];
    if (macroName !== undefined) {
      const entry = DISABLED_BUILTINS[macroName];
      if (entry !== undefined) {
        throw new RelayCelProfileError(entry.msg, entry.subtype);
      }
    }
    throw new RelayCelProfileError(
      `Relay CEL profile rejects macro: ${err.message}`,
      SUBTYPE_PROFILE_DYN_DISABLED,
    );
  }
  // Generic surface: cel-js parse / type / eval errors land here.
  throw new RelayCelProfileError(
    `cel-js evaluation failed: ${err.message} (expression=${JSON.stringify(expression)})`,
    SUBTYPE_PROFILE_DYN_DISABLED,
  );
}

// Cap on how long we wait for the worker's startup `ready` message.
// cel-js + chevrotain cold-import on a busy CI runner has been
// observed at ~150 ms; 5 seconds is a generous ceiling that is still
// fast enough to surface a hung-worker bug.
const WORKER_STARTUP_TIMEOUT_MS = 5000;

// Polling slice for synchronous message receive. We block in
// Atomics.wait on a private SharedArrayBuffer for this many ms before
// re-polling the MessagePort. Smaller = lower added latency on the
// happy path; larger = lower CPU spin. 5 ms is a reasonable balance
// for the per-evaluate budget which is at minimum 1 ms.
const SYNC_POLL_SLICE_MS = 5;

export class RelayCelEvaluator {
  public readonly timeoutMs: number;
  private readonly udfSpecs: UdfSpec[];
  private readonly compileCache: Map<string, CompiledExpression>;
  // Lazy-spawned persistent worker. `null` after construction and
  // after every termination; (re)spawned on demand by ensureWorker().
  private worker: Worker | null;
  // Parent's MessagePort end of the channel paired with the worker.
  // Synchronously polled via receiveMessageOnPort.
  private port: MessagePort | null;
  private nextReqId: number;

  constructor(
    options: { timeoutMs?: number; udfs?: readonly PureUdf[] } = {},
  ) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new Error(
        `timeoutMs MUST be a positive integer; got ${String(timeoutMs)}`,
      );
    }
    if (timeoutMs > MAX_TIMEOUT_MS) {
      throw new Error(
        `timeoutMs exceeds Relay cap (${MAX_TIMEOUT_MS} ms); got ${timeoutMs}`,
      );
    }
    this.timeoutMs = timeoutMs;
    this.udfSpecs = [];
    for (const udf of options.udfs ?? []) {
      // Defensive: callers can construct the PureUdf shape directly,
      // bypassing registerUdf. Recompute purity assertion here would
      // require a static analyser; we trust the registry.
      this.udfSpecs.push({
        name: udf.name,
        source: udf.fn.toString(),
      });
    }
    this.compileCache = new Map();
    this.worker = null;
    this.port = null;
    this.nextReqId = 0;
  }

  /**
   * Parse + check `expression` against the Relay CEL profile.
   * Cached by expression text. Profile violations raise at this point
   * (not at evaluate-time) so the gate runner sees the structured
   * error before any value is bound.
   */
  compile(expression: string): CompiledExpression {
    const cached = this.compileCache.get(expression);
    if (cached !== undefined) {
      return cached;
    }
    // Pre-screen regex backreferences in the raw expression text
    // (cel-js does not parse `string.matches(...)` so the AST walker
    // never sees the regex literal -- check the source directly).
    checkRegexBackref(expression);
    const parsed = parse(expression);
    if (!parsed.isSuccess) {
      throw new RelayCelProfileError(
        `cel-js parse failed: ${parsed.errors.join("; ")}`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    const success = parsed as Success;
    checkProfileCst(success.cst);
    const compiled: CompiledExpression = {
      expression,
      cst: success.cst,
      bindings: {},
    };
    this.compileCache.set(expression, compiled);
    return compiled;
  }

  /**
   * Synchronously poll `port` for one message until `deadlineMs` (a
   * monotonic epoch ms timestamp). Returns the message body or
   * `null` if the deadline elapsed without one. Between polls the
   * thread sleeps for SYNC_POLL_SLICE_MS via Atomics.wait on a
   * private SharedArrayBuffer (no busy loop).
   */
  private syncReceive(port: MessagePort, deadlineMs: number): unknown {
    const sab = new SharedArrayBuffer(4);
    const view = new Int32Array(sab);
    while (true) {
      const m = receiveMessageOnPort(port);
      if (m !== undefined) {
        return m.message;
      }
      const now = Date.now();
      if (now >= deadlineMs) {
        return null;
      }
      const slice = Math.min(SYNC_POLL_SLICE_MS, deadlineMs - now);
      // Atomics.wait sleeps the thread WITHOUT spinning the CPU and
      // WITHOUT blocking libuv message delivery on other ports
      // (worker -> port message arrival is via libuv but we are
      // polling the port directly, not awaiting libuv events).
      Atomics.wait(view, 0, 0, slice);
    }
  }

  /**
   * Spawn (or return) the persistent worker. Synchronously polls for
   * the worker's `{kind: 'ready'}` startup message so the cold-import
   * cost is paid here instead of inside the timeout-bounded
   * evaluate() call. Uses a long startup ceiling
   * (WORKER_STARTUP_TIMEOUT_MS) distinct from the per-evaluate
   * budget.
   */
  private ensureWorker(): { worker: Worker; port: MessagePort } {
    if (this.worker !== null && this.port !== null) {
      return { worker: this.worker, port: this.port };
    }
    const channel = new MessageChannel();
    const parentPort = channel.port1;
    const childPort = channel.port2;
    const w = new Worker(WORKER_SOURCE, {
      eval: true,
      workerData: { udfs: this.udfSpecs, port: childPort },
      transferList: [childPort],
    });

    const startupDeadline = Date.now() + WORKER_STARTUP_TIMEOUT_MS;
    let asyncError: Error | null = null;
    const onErrorOnce = (err: Error): void => {
      asyncError = err;
    };
    w.once("error", onErrorOnce);

    const startupMsg = this.syncReceive(parentPort, startupDeadline) as
      | { kind?: string; error?: { name: string; message: string } }
      | null;

    w.removeListener("error", onErrorOnce);

    if (asyncError !== null) {
      void w.terminate();
      parentPort.close();
      const e = asyncError as Error;
      throw new RelayCelProfileError(
        `cel-js worker failed at startup: ${e.message}`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    if (startupMsg === null) {
      void w.terminate();
      parentPort.close();
      throw new RelayCelProfileError(
        `cel-js worker did not become ready within ${WORKER_STARTUP_TIMEOUT_MS} ms`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    if (startupMsg.kind === "startup_error") {
      void w.terminate();
      parentPort.close();
      const errMsg = startupMsg.error?.message ?? "unknown startup error";
      throw new RelayCelProfileError(
        `cel-js worker reported startup error: ${errMsg}`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    if (startupMsg.kind !== "ready") {
      void w.terminate();
      parentPort.close();
      throw new RelayCelProfileError(
        `cel-js worker sent unexpected startup message: ${JSON.stringify(startupMsg)}`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    // Ensure the worker does not keep the parent process alive after
    // tests complete.
    w.unref();
    parentPort.unref();
    this.worker = w;
    this.port = parentPort;
    return { worker: w, port: parentPort };
  }

  /**
   * Evaluate `expression` with `bindings` under the configured
   * wall-clock timeout. NaN / +Inf / -Inf in the result raise
   * `RelayCelNumericOutOfBoundsError`. Profile violations raise at
   * compile() time, before evaluation begins.
   */
  evaluate(expression: string, bindings?: Record<string, unknown>): unknown {
    this.compile(expression);
    const { worker, port } = this.ensureWorker();
    const timeoutMs = this.timeoutMs;
    const reqId = this.nextReqId;
    this.nextReqId += 1;

    // Capture worker errors that may fire asynchronously while we
    // synchronously poll the port. The `let` is read after the poll
    // returns; defensive cast at the read site.
    let asyncError: Error | null = null;
    const onErrorOnce = (err: Error): void => {
      asyncError = err;
    };
    worker.once("error", onErrorOnce);

    // Send the evaluate request first. The worker's port has its own
    // queue so messages posted before the worker is ready are buffered.
    port.postMessage({
      kind: "evaluate",
      reqId,
      expression,
      bindings: bindings ?? {},
    });

    // Synchronously poll the port for the matching reply, bounded by
    // the wall-clock budget. Any non-matching message (stale reqId
    // from a previous evaluate that beat its kill, or future protocol
    // additions) is dropped and we keep polling.
    const deadline = Date.now() + timeoutMs;
    let finalResult: WorkerMessage | null = null;
    while (Date.now() < deadline) {
      const remaining = deadline - Date.now();
      const msg = this.syncReceive(port, Date.now() + remaining) as
        | {
            kind?: string;
            reqId?: number;
            ok?: boolean;
            result?: unknown;
            error?: { name: string; message: string };
          }
        | null;
      if (asyncError !== null) {
        break;
      }
      if (msg === null) {
        // Polling deadline elapsed inside syncReceive (== outer
        // deadline). Treat as timeout.
        break;
      }
      if (msg.kind !== "result" || msg.reqId !== reqId) {
        // Stray / stale message; drop and keep polling.
        continue;
      }
      if (msg.ok === true) {
        finalResult = { ok: true, result: msg.result };
      } else {
        const err = msg.error ?? { name: "Error", message: "unknown worker error" };
        finalResult = { ok: false, error: err };
      }
      break;
    }

    worker.removeListener("error", onErrorOnce);

    if (asyncError !== null) {
      const e = asyncError as Error;
      // Worker crashed; drop the cached pair so the next evaluate()
      // respawns.
      this.disposeInternal();
      throw new RelayCelProfileError(
        `cel-js worker failed: ${e.message}`,
        SUBTYPE_PROFILE_DYN_DISABLED,
      );
    }
    if (finalResult === null) {
      // Wall-clock budget exceeded. Aborting an in-flight evaluation
      // requires terminating the worker (no in-band cancel protocol
      // exists). Drop our handle so the next evaluate() respawns.
      this.disposeInternal();
      throw new RelayCelTimeoutError(
        `Relay CEL evaluation exceeded ${timeoutMs} ms wall-clock budget for expression: ${JSON.stringify(expression)}`,
      );
    }
    if (!finalResult.ok) {
      reraiseFromWorker(finalResult.error, expression);
    }
    return checkFinite(finalResult.result);
  }

  /**
   * Internal worker teardown -- closes the port and terminates the
   * worker without throwing. Used after a timeout or worker crash to
   * ensure the next evaluate() spawns a fresh worker.
   */
  private disposeInternal(): void {
    if (this.port !== null) {
      try {
        this.port.close();
      } catch {
        // Port may already be closed; ignore.
      }
      this.port = null;
    }
    if (this.worker !== null) {
      void this.worker.terminate();
      this.worker = null;
    }
  }

  /**
   * Terminate the persistent worker. Idempotent. Tests should call
   * this in afterEach / afterAll to free resources; production code
   * may rely on `worker.unref()` to avoid blocking process exit.
   */
  dispose(): void {
    this.disposeInternal();
  }
}

// Re-export the error classes the public surface needs at the
// evaluator-level (callers may catch them by import from this module
// or from index.ts; both surfaces are equivalent).
export {
  RelayCelError,
  RelayCelNumericOutOfBoundsError,
  RelayCelProfileError,
  RelayCelRegexBackreferenceError,
  RelayCelTimeoutError,
};
