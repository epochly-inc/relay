#!/usr/bin/env node
/**
 * ``npx @epochly/relay sidecar`` CLI entry (W4.1).
 *
 * Thin shim over :func:`launchSidecar`. Parses argv, runs the orchestrator,
 * emits a single JSON line to stdout on success or to stderr on failure
 * with a non-zero exit code carrying the error's ``code`` field.
 *
 * Per VAL-W4-008 the ``--trust-root`` flag is honored only when
 * ``RELAY_ALLOW_CUSTOM_TRUST_ROOT=1`` is set.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import { RelayError } from "../errors.js";
import { launchSidecar, type LaunchSidecarOptions } from "./wrapper.js";

interface ParsedArgs {
  command: "sidecar" | "version" | "help" | "unknown";
  trustRoot?: string;
  raw: string[];
}

function parseArgs(argv: ReadonlyArray<string>): ParsedArgs {
  // argv[0] = node, argv[1] = script. Drop both.
  const args = argv.slice(2);
  if (args.length === 0) {
    return { command: "help", raw: [] };
  }
  const command = args[0];
  if (command === "--help" || command === "-h" || command === "help") {
    return { command: "help", raw: args };
  }
  if (command === "--version" || command === "version") {
    return { command: "version", raw: args };
  }
  if (command !== "sidecar") {
    return { command: "unknown", raw: args };
  }
  const parsed: ParsedArgs = { command: "sidecar", raw: args };
  for (let i = 1; i < args.length; i++) {
    const flag = args[i];
    if (flag === "--trust-root") {
      const value = args[i + 1];
      if (value === undefined) {
        throw new Error("--trust-root requires a value");
      }
      parsed.trustRoot = value;
      i++;
      continue;
    }
    // Forward-compat: ignore unknown flags rather than failing closed --
    // npx wrappers commonly carry extra args that the sidecar binary
    // (spawned later) consumes. The wrapper itself ignores them.
  }
  return parsed;
}

function emitJsonLine(stream: NodeJS.WriteStream, value: unknown): void {
  stream.write(JSON.stringify(value) + "\n");
}

function printHelp(): void {
  process.stdout.write(
    [
      "Usage: npx @epochly/relay sidecar [--trust-root <host>]",
      "",
      "Downloads and verifies the signed @epochly/relay-sidecar-bundle for",
      "your platform, then prepares it for launch. Output is a JSON line",
      "describing the launch decision.",
      "",
      "Flags:",
      "  --trust-root <host>   Override the default Sigstore trust root.",
      "                        Requires RELAY_ALLOW_CUSTOM_TRUST_ROOT=1.",
      "",
      "Exit codes:",
      "  0  bundle verified and ready",
      "  1  bundle verification failed (see code on stderr)",
      "  2  arch/OS unsupported or trust-root override denied",
      "  3  network unreachable and no cache",
      "",
    ].join("\n"),
  );
}

async function main(argv: ReadonlyArray<string>): Promise<number> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 64; // EX_USAGE
  }
  if (parsed.command === "help") {
    printHelp();
    return 0;
  }
  if (parsed.command === "version") {
    process.stdout.write("@epochly/relay v0.0.0\n");
    return 0;
  }
  if (parsed.command !== "sidecar") {
    process.stderr.write(`error: unknown command ${JSON.stringify(parsed.raw[0])}\n`);
    return 64;
  }
  const options: LaunchSidecarOptions = {};
  if (parsed.trustRoot !== undefined) options.trustRoot = parsed.trustRoot;
  try {
    const decision = await launchSidecar(options);
    emitJsonLine(process.stdout, decision);
    return 0;
  } catch (err) {
    if (err instanceof RelayError) {
      emitJsonLine(process.stderr, err.toEnvelope());
      // Map the wire error code to an exit code per CLAUDE.md +
      // VAL-W4-031 spirit. The W4.4 feature finalises the table; the W4.1
      // surface only needs to surface a non-zero exit for any failure.
      if (err.code === "RELAY-SIDECAR-022") return 3; // unavailable
      if (err.code === "RELAY-SDK-012") return 2; // trust-root denied
      if (err.code === "RELAY-SIDECAR-023") return 2; // arch unsupported
      return 1;
    }
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 70; // EX_SOFTWARE
  }
}

// Run if invoked directly (not when imported by tests).
//
// The check uses ``import.meta.url`` against the resolved script path to
// stay robust against symlinked npx wrappers.
const isDirect =
  typeof process !== "undefined" &&
  process.argv[1] !== undefined &&
  import.meta.url === `file://${process.argv[1]}`;

if (isDirect) {
  main(process.argv)
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(
        `unhandled: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
      );
      process.exit(99);
    });
}

export { main as cliMain, parseArgs as _parseArgs };
