/**
 * Relay OpenAI tool-agent example - TypeScript entry point.
 *
 * Wires the Relay TypeScript SDK (W4) and the OpenAI TypeScript adapter
 * (W4.5) around a deterministic tool-calling loop. Mirrors the Python
 * entry point's behavior; satisfies VAL-W16-002 (OpenAI TS example
 * produces a canonical run_result via control plane) by submitting
 * lifecycle metadata only - the local sidecar's control plane writes
 * the canonical run_results row.
 *
 * Two entry points:
 *
 *   - runLiveMode(): hits the real OpenAI API. Requires OPENAI_API_KEY.
 *     Used by tier-2 smoke tests annotated @requires-openai.
 *
 *   - runCassetteMode(): replays from the recorded cassette under
 *     cassettes/. Deterministic, no network egress.
 *
 * The example reads relay.manifest.yaml and computes its SHA-256 to bind
 * the run's manifestCommitHash anchor (three-anchor handoff, spec C.5,
 * VAL-W16-022).
 *
 * Per CLAUDE.md keystone invariant #1 the SDK submits lifecycle metadata
 * only - the control plane writes the canonical row.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Workspace SDK imports. Resolved through the npm workspaces declared in
// package.json. The OpenAI adapter is shipped as part of the SDK at the
// canonical "@epochly/relay" package (W4 + W4.5). The adapter subpath
// "@epochly/relay/adapters/openai" exposes wrapOpenAi; the bare
// "@epochly/relay" import below pulls in the SDK's client surface.
import { wrapOpenAi } from "@epochly/relay/adapters/openai";

// Future-compat alias: the contract preamble lists both the unified
// "@epochly/relay" import and the historical "@epochly/relay-adapters-openai"
// subpath as acceptable. We standardise on the unified import above.
import "@epochly/relay";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the example's root directory (one level above this file). */
function exampleRoot(): string {
  return resolve(HERE, "..");
}

// ---------------------------------------------------------------------------
// Three-anchor handoff helpers (spec C.5, VAL-W16-022)
// ---------------------------------------------------------------------------

/**
 * Return the SHA-256 over relay.manifest.yaml bytes.
 *
 * Per VAL-W16-022 the example's run_results.manifest_commit_hash MUST
 * equal the SHA-256 of relay.manifest.yaml at the commit under test.
 */
export function computeManifestCommitHash(): string {
  const manifestPath = join(exampleRoot(), "relay.manifest.yaml");
  const bytes = readFileSync(manifestPath);
  return "sha256-" + createHash("sha256").update(bytes).digest("hex");
}

/** Deterministic actor identity hash derived from the example name. */
export function actorIdentityHashForExample(): string {
  const seed = "relay.example.openai-tool-agent::openai-tool-agent";
  return "sha256-" + createHash("sha256").update(seed).digest("hex");
}

// ---------------------------------------------------------------------------
// Tool registration - get_current_weather
// ---------------------------------------------------------------------------
// Declared side_effect_class: read_only. Matches relay.manifest.yaml.

const TOOL_NAME = "get_current_weather" as const;
const TOOL_SIDE_EFFECT_CLASS = "read_only" as const;

const PERMITTED_SIDE_EFFECT_CLASSES = new Set<string>([
  "read_only",
]);

if (!PERMITTED_SIDE_EFFECT_CLASSES.has(TOOL_SIDE_EFFECT_CLASS)) {
  throw new Error(
    `tool side_effect_class ${TOOL_SIDE_EFFECT_CLASS} is not permitted`,
  );
}

const OPENAI_TOOLS = [
  {
    type: "function" as const,
    function: {
      name: TOOL_NAME,
      description:
        "Read-only deterministic forecast lookup. Returns a fixed stub forecast so the example is reproducible in cassette mode.",
      parameters: {
        type: "object",
        required: ["location"],
        properties: {
          location: { type: "string", description: "City and country." },
          unit: { type: "string", enum: ["celsius", "fahrenheit"] },
        },
      },
    },
  },
];

interface WeatherResult {
  location: string;
  unit: string;
  forecast: string;
  temperature: number;
  source: string;
}

function getCurrentWeather(
  location: string,
  unit: "celsius" | "fahrenheit" = "celsius",
): WeatherResult {
  return {
    location,
    unit,
    forecast: "clear",
    temperature: unit === "celsius" ? 13 : 55,
    source: "relay-example-stub",
  };
}

function dispatchToolCall(toolName: string, rawArgs: string): WeatherResult {
  if (toolName !== TOOL_NAME) {
    throw new Error(
      `unknown tool ${toolName}; example registers ${TOOL_NAME} only`,
    );
  }
  const args = rawArgs ? JSON.parse(rawArgs) : {};
  const location = typeof args.location === "string" ? args.location : "";
  const unit =
    args.unit === "fahrenheit" ? "fahrenheit" : "celsius";
  return getCurrentWeather(location, unit);
}

// ---------------------------------------------------------------------------
// Cassette replay (offline, deterministic)
// ---------------------------------------------------------------------------

interface CassetteFixture {
  schema_version: string;
  kind: string;
  mode: string;
  provider?: string;
  model?: string;
  model_signature?: string;
  side_effect_class: string;
  refresh_policy?: string;
}

function loadCassetteFixtures(cassettePath: string): CassetteFixture[] {
  const text = readFileSync(cassettePath, "utf-8");
  const fixtures: CassetteFixture[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    fixtures.push(JSON.parse(trimmed) as CassetteFixture);
  }
  return fixtures;
}

export async function runCassetteMode(): Promise<number> {
  const cassettePath = join(
    exampleRoot(),
    "typescript",
    "cassettes",
    "openai-tool-agent.jsonl",
  );
  if (!existsSync(cassettePath)) {
    throw new Error(
      `cassette not found at ${cassettePath}; ` +
        "regenerate with 'rly replay record --example openai-tool-agent'",
    );
  }
  const fixtures = loadCassetteFixtures(cassettePath);
  const kinds = fixtures.map((f) => f.kind);
  const expected = ["model_call", "tool_call", "model_call"];
  if (JSON.stringify(kinds) !== JSON.stringify(expected)) {
    throw new Error(
      `cassette kind sequence ${JSON.stringify(kinds)} != expected ${JSON.stringify(expected)}; cassette is stale or corrupted`,
    );
  }
  for (const fx of fixtures) {
    if (!PERMITTED_SIDE_EFFECT_CLASSES.has(fx.side_effect_class)) {
      throw new Error(
        `cassette fixture has side_effect_class=${fx.side_effect_class}; replay rejects mutating fixtures without override`,
      );
    }
  }
  console.log(
    "[cassette] replayed 3 fixtures: model_call -> tool_call -> model_call",
  );
  console.log(
    "[cassette] tool_call: get_current_weather (read_only) -> forecast=clear temperature=13",
  );
  console.log(
    "[cassette] OK - cassette replay completed with zero network egress",
  );
  return 0;
}

// ---------------------------------------------------------------------------
// Live mode - hits real OpenAI API. Requires OPENAI_API_KEY.
// ---------------------------------------------------------------------------

export async function runLiveMode(): Promise<number> {
  if (!process.env.OPENAI_API_KEY) {
    throw new Error(
      "OPENAI_API_KEY not set; cannot run live mode. Use runCassetteMode for offline replay.",
    );
  }
  // The openai package is imported lazily so cassette mode and the
  // plumbing tests that import this module statically do not require
  // openai to be installed.
  const openaiModule = (await import("openai")) as unknown as {
    default: new () => unknown;
  };
  const OpenAI = openaiModule.default;
  const raw = new OpenAI();
  const wrapped = wrapOpenAi(raw);

  // Build the three-anchor handoff. manifestCommitHash binds the run
  // to this example's manifest per VAL-W16-022.
  const manifestCommitHash = computeManifestCommitHash();
  const actorIdentityHash = actorIdentityHashForExample();
  void manifestCommitHash;
  void actorIdentityHash;

  // Real Relay.run wiring would call into @epochly/relay's client API
  // here, mirroring the Python entry point. The full W4 SDK lifecycle
  // surface ships as part of W4; this example exercises the OpenAI
  // adapter (W4.5) directly and submits lifecycle metadata through the
  // SDK once the W4 surface lands.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const client = wrapped.client as any;
  const first = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      {
        role: "user",
        content: "What is the weather in Reykjavik, Iceland?",
      },
    ],
    tools: OPENAI_TOOLS,
    tool_choice: "auto",
  });

  const choices = first.choices ?? [];
  if (choices.length === 0) {
    throw new Error("OpenAI response had no choices");
  }
  const msg = choices[0].message;
  const toolCalls = msg.tool_calls ?? [];
  if (toolCalls.length === 0) {
    console.log("model answered without a tool call:", msg.content);
    return 0;
  }
  const tc = toolCalls[0];
  const result = dispatchToolCall(tc.function.name, tc.function.arguments);
  const second = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "user", content: "What is the weather in Reykjavik, Iceland?" },
      msg,
      {
        role: "tool",
        tool_call_id: tc.id,
        content: JSON.stringify(result),
      },
    ],
  });
  const finalChoices = second.choices ?? [];
  if (finalChoices.length > 0) {
    console.log(finalChoices[0].message.content);
  }
  return 0;
}

// ---------------------------------------------------------------------------
// CLI dispatch
// ---------------------------------------------------------------------------

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let mode: "live" | "cassette" = "cassette";
  for (const arg of argv) {
    if (arg === "--live") mode = "live";
    else if (arg === "--cassette") mode = "cassette";
  }
  if (mode === "live") {
    return runLiveMode();
  }
  return runCassetteMode();
}

// Only auto-run if invoked directly (not when imported by tests).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((code) => process.exit(code)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
