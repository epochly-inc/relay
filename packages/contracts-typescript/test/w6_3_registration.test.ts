// w6.3 -- Relay UDF registration is gated on pure: true (TypeScript).
//
// VAL-W6-020/021/022 (TypeScript-side): each production UDF appears
// exactly once in RELAY_UDFS, registered via registerUdf({pure: true}).
// A source-grep guard confirms no production registerUdf call uses
// pure: false.
//
// Tool: vitest.
// Evidence: vitest exit code, source-grep result count = 1 per UDF.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";
import { describe, expect, test } from "vitest";

import {
  RELAY_COVERAGE_ARITY,
  RELAY_COVERAGE_NAME,
  RELAY_SCHEMA_MATCH_ARITY,
  RELAY_SCHEMA_MATCH_NAME,
  RELAY_TOOL_ARG_ARITY,
  RELAY_TOOL_ARG_NAME,
  RELAY_UDFS,
} from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_SRC_UDFS = join(HERE, "..", "src", "udfs");

function* walk(root: string): Generator<string> {
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    const st = statSync(path);
    if (st.isDirectory()) {
      yield* walk(path);
    } else if (path.endsWith(".ts")) {
      yield path;
    }
  }
}

interface RegisterCall {
  file: string;
  nameArg: string;
  pureArg: string;
}

// Match registerUdf({\n  name: NAME_OR_LITERAL,\n  fn: relayXxx,\n
// pure: true|false,\n  arity: N,\n}).  The kwarg shape is enforced by
// the registerUdf signature; this regex matches the exact form used
// in the production registry module.
const REGISTER_PATTERN = new RegExp(
  String.raw`registerUdf\s*\(\s*\{\s*` +
    String.raw`name:\s*([A-Z_][A-Z0-9_]*|"[^"]+")\s*,\s*` +
    String.raw`fn:\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*(?:as\s+[^,]+)?,\s*` +
    String.raw`pure:\s*(true|false)`,
  "g",
);

function gatherRegisterCalls(): RegisterCall[] {
  const out: RegisterCall[] = [];
  for (const file of walk(PKG_SRC_UDFS)) {
    const text = readFileSync(file, "utf-8");
    REGISTER_PATTERN.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = REGISTER_PATTERN.exec(text)) !== null) {
      out.push({
        file: relative(join(HERE, ".."), file),
        nameArg: m[1] ?? "",
        pureArg: m[2] ?? "",
      });
    }
  }
  return out;
}

describe("VAL-W6-020 (TS): relay.coverage declared pure", () => {
  test("relay.coverage is registered exactly once in RELAY_UDFS", () => {
    const matches = RELAY_UDFS.filter((u) => u.name === RELAY_COVERAGE_NAME);
    expect(matches.length).toBe(1);
    expect(matches[0]?.arity).toBe(RELAY_COVERAGE_ARITY);
  });
  test("source registerUdf call for relay.coverage uses pure: true", () => {
    const calls = gatherRegisterCalls().filter(
      (c) => c.nameArg === "RELAY_COVERAGE_NAME",
    );
    expect(calls.length).toBe(1);
    expect(calls[0]?.pureArg).toBe("true");
  });
});

describe("VAL-W6-021 (TS): relay.tool_arg declared pure", () => {
  test("relay.tool_arg is registered exactly once in RELAY_UDFS", () => {
    const matches = RELAY_UDFS.filter((u) => u.name === RELAY_TOOL_ARG_NAME);
    expect(matches.length).toBe(1);
    expect(matches[0]?.arity).toBe(RELAY_TOOL_ARG_ARITY);
  });
  test("source registerUdf call for relay.tool_arg uses pure: true", () => {
    const calls = gatherRegisterCalls().filter(
      (c) => c.nameArg === "RELAY_TOOL_ARG_NAME",
    );
    expect(calls.length).toBe(1);
    expect(calls[0]?.pureArg).toBe("true");
  });
});

describe("VAL-W6-022 (TS): relay.schema_match declared pure", () => {
  test("relay.schema_match is registered exactly once in RELAY_UDFS", () => {
    const matches = RELAY_UDFS.filter(
      (u) => u.name === RELAY_SCHEMA_MATCH_NAME,
    );
    expect(matches.length).toBe(1);
    expect(matches[0]?.arity).toBe(RELAY_SCHEMA_MATCH_ARITY);
  });
  test("source registerUdf call for relay.schema_match uses pure: true", () => {
    const calls = gatherRegisterCalls().filter(
      (c) => c.nameArg === "RELAY_SCHEMA_MATCH_NAME",
    );
    expect(calls.length).toBe(1);
    expect(calls[0]?.pureArg).toBe("true");
  });
});

describe("VAL-W6-020/021/022 (TS): no production registerUdf with pure: false", () => {
  test("packages/contracts-typescript/src/udfs/ has zero pure: false calls", () => {
    const calls = gatherRegisterCalls();
    const bad = calls.filter((c) => c.pureArg === "false");
    expect(bad).toEqual([]);
  });

  test("RELAY_UDFS has exactly three production UDFs", () => {
    expect(RELAY_UDFS.length).toBe(3);
    const names = RELAY_UDFS.map((u) => u.name).sort();
    expect(names).toEqual(
      [
        RELAY_COVERAGE_NAME,
        RELAY_SCHEMA_MATCH_NAME,
        RELAY_TOOL_ARG_NAME,
      ].sort(),
    );
  });

  test("RELAY_UDFS array is frozen at runtime", () => {
    expect(Object.isFrozen(RELAY_UDFS)).toBe(true);
  });
});
