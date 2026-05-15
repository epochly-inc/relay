/**
 * W4.5 cross-language parity tests (VAL-W4-037, VAL-W4-041).
 *
 * VAL-W4-037: Py and TS SDKs emit byte-equal /v1/ingest/runs bodies
 *             for the same logical run. Loads the Py-generated corpus
 *             at tests/conformance/ingest/parity_fixtures.json and
 *             asserts the TS buildIngestRunEnvelope produces the same
 *             JCS-canonical bytes per fixture.
 *
 * VAL-W4-041: Cassette format Py-TS parity. Loads the Py-generated
 *             cassette JSONL fixture and asserts the TS reader
 *             (parseCassette / readCassetteFile) ingests it
 *             byte-identically (matching SHA-256 file digest).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { buildIngestRunEnvelope, type BuildIngestRunEnvelopeArgs } from "../src/lifecycle.js";
import {
  parseCassette,
  readCassetteFile,
  CASSETTE_HEADER_SCHEMA_VERSION,
  CASSETTE_ENTRY_SCHEMA_VERSION,
} from "../src/replay/cassette_reader.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");

const INGEST_CORPUS_PATH = path.join(
  REPO_ROOT,
  "tests",
  "conformance",
  "ingest",
  "parity_fixtures.json",
);

const CASSETTE_CORPUS_PATH = path.join(
  REPO_ROOT,
  "tests",
  "conformance",
  "cassettes",
  "parity_fixtures.json",
);

const CASSETTE_RAW_PATH = path.join(
  REPO_ROOT,
  "tests",
  "conformance",
  "cassettes",
  "cassette_minimal.jsonl",
);

// JCS-compatible canonical JSON encoder. Mirrors the Python
// ``relay_schemas.envelopes.canonical_bytes`` byte-for-byte for the
// JSON value subset Relay envelopes use. Identical to the canonicalizer
// in w4_4_cross_language_parity.test.ts.
function canonicalJsonStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalJsonStringify: non-finite number not allowed");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJsonStringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + canonicalJsonStringify(v));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalJsonStringify: unsupported type ${typeof value}`);
}

function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJsonStringify(value));
}

interface IngestParityFixture {
  readonly name: string;
  readonly inputs: Record<string, unknown>;
  readonly envelope: Record<string, unknown>;
  readonly canonical_hex: string;
  readonly canonical_sha256: string;
}

interface IngestParityCorpus {
  readonly schema_version: string;
  readonly fixtures: ReadonlyArray<IngestParityFixture>;
}

function loadIngestCorpus(): IngestParityCorpus {
  return JSON.parse(fs.readFileSync(INGEST_CORPUS_PATH, "utf8")) as IngestParityCorpus;
}

/** Map snake_case Python field names in the fixture to camelCase TS args. */
function pythonInputsToTsArgs(inputs: Record<string, unknown>): BuildIngestRunEnvelopeArgs {
  const args: BuildIngestRunEnvelopeArgs = {
    runId: inputs["run_id"] as string,
    traceId: inputs["trace_id"] as string,
    projectId: inputs["project_id"] as string,
    agent: inputs["agent"] as Record<string, unknown>,
    clientLifecycleStatus: inputs["client_lifecycle_status"] as string,
    startedAt: inputs["started_at"] as string,
    sdkVersion: inputs["sdk_version"] as string,
    sdkClock: inputs["sdk_clock"] as string,
    manifestCommitHash: inputs["manifest_commit_hash"] as string,
    actorIdentityHash: inputs["actor_identity_hash"] as string,
    redactionPolicyVersion: inputs["redaction_policy_version"] as string,
    sequenceNumber: inputs["sequence_number"] as number,
  };
  if (inputs["metadata"] !== undefined) {
    args.metadata = inputs["metadata"] as Record<string, unknown>;
  }
  if (inputs["idempotency_key"] !== undefined) {
    args.idempotencyKey = inputs["idempotency_key"] as string;
  }
  if (inputs["extras"] !== undefined) {
    args.extras = inputs["extras"] as Record<string, unknown>;
  }
  return args;
}

describe("VAL-W4-037: cross-language /v1/ingest/runs envelope parity", () => {
  const corpus = loadIngestCorpus();

  it("corpus is non-empty (sanity)", () => {
    expect(corpus.fixtures.length).toBeGreaterThan(0);
    expect(corpus.schema_version).toBe("relay.ingest_run_parity.v1");
  });

  for (const fixture of corpus.fixtures) {
    it(`${fixture.name}: TS buildIngestRunEnvelope produces byte-equal canonical bytes`, () => {
      const tsArgs = pythonInputsToTsArgs(fixture.inputs);
      const tsEnvelope = buildIngestRunEnvelope(tsArgs);
      // Top-level field check: envelope objects must be structurally equal.
      expect(tsEnvelope).toEqual(fixture.envelope);
      // JCS canonical-bytes equality: TS bytes must match Py-emitted hex.
      const tsBytes = canonicalBytes(tsEnvelope);
      const tsHex = Buffer.from(tsBytes).toString("hex");
      expect(tsHex).toBe(fixture.canonical_hex);
      const tsSha256 = crypto.createHash("sha256").update(tsBytes).digest("hex");
      expect(tsSha256).toBe(fixture.canonical_sha256);
    });
  }
});

interface CassetteParityFixture {
  readonly name: string;
  readonly inputs: Record<string, unknown>;
  readonly cassette_text: string;
  readonly cassette_sha256: string;
  readonly entry_count: number;
}

interface CassetteParityCorpus {
  readonly schema_version: string;
  readonly fixtures: ReadonlyArray<CassetteParityFixture>;
}

describe("VAL-W4-041: cassette format Py-TS parity", () => {
  const corpus = JSON.parse(fs.readFileSync(CASSETTE_CORPUS_PATH, "utf8")) as CassetteParityCorpus;

  it("corpus is non-empty (sanity)", () => {
    expect(corpus.fixtures.length).toBeGreaterThan(0);
    expect(corpus.schema_version).toBe("relay.cassette_parity.v1");
  });

  for (const fixture of corpus.fixtures) {
    it(`${fixture.name}: TS parseCassette ingests the Py-emitted JSONL byte-identically`, () => {
      const cassette = parseCassette(fixture.cassette_text);
      // SHA-256 of the raw bytes MUST match Python.
      expect(cassette.fileDigestSha256).toBe(fixture.cassette_sha256);
      // Header schema_version is the canonical token.
      expect(cassette.header.schema_version).toBe(CASSETTE_HEADER_SCHEMA_VERSION);
      // Entry count and per-entry schema_version line up.
      expect(cassette.entries.length).toBe(fixture.entry_count);
      for (const entry of cassette.entries) {
        expect(entry.schema_version).toBe(CASSETTE_ENTRY_SCHEMA_VERSION);
      }
    });
  }

  it("readCassetteFile reads the side-by-side raw .jsonl artefact", () => {
    const cassette = readCassetteFile(CASSETTE_RAW_PATH);
    // Entry sequences are 0-indexed and contiguous.
    cassette.entries.forEach((entry, i) => {
      expect(entry.sequence).toBe(i);
    });
    // Header carries non-empty case_id.
    expect(cassette.header.case_id.length).toBeGreaterThan(0);
  });

  it("parseCassette rejects a header with wrong schema_version", () => {
    const bogus =
      JSON.stringify({
        schema_version: "relay.cassette.v999",
        case_id: "x",
        session_id: "y",
        recorded_at: "z",
        manifest_commit_hash: "sha256-x",
      }) + "\n";
    expect(() => parseCassette(bogus)).toThrow(/schema_version/);
  });

  it("parseCassette rejects an entry with wrong sequence", () => {
    const bogus =
      JSON.stringify({
        schema_version: "relay.cassette.v1",
        case_id: "x",
        session_id: "y",
        recorded_at: "z",
        manifest_commit_hash: "sha256-x",
      }) +
      "\n" +
      JSON.stringify({
        schema_version: "relay.cassette_entry.v1",
        sequence: 99, // wrong: should be 0
        provider: "openai",
        model: "gpt",
        request_digest: "sha256-x",
        response: {},
        response_digest: "sha256-x",
        timestamp: "t",
      }) +
      "\n";
    expect(() => parseCassette(bogus)).toThrow(/sequence/);
  });
});
