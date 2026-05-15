/**
 * Cassette reader (W4.5; VAL-W4-041).
 *
 * The replay cassette format is JSONL: one JSON object per line, each
 * object describing a single recorded provider call. The on-disk format
 * is identical across the Python and TypeScript SDKs so a cassette
 * recorded by ``rly replay record`` (Python) is readable byte-identically
 * by the TS replay client and vice versa.
 *
 * Cassette schema (relay.cassette.v1):
 *
 *   {
 *     "schema_version": "relay.cassette.v1",
 *     "case_id": <ULID>,                  // replay_case the cassette belongs to
 *     "session_id": <ULID>,               // recording session
 *     "recorded_at": <RFC3339>,           // session start
 *     "manifest_commit_hash": "sha256-..." // anchor at record time
 *   }
 *   { "schema_version": "relay.cassette_entry.v1", ... }   <- one per call
 *   { "schema_version": "relay.cassette_entry.v1", ... }
 *   ...
 *
 * Each entry carries:
 *
 *   * ``sequence``       -- 0-based index in the cassette.
 *   * ``provider``       -- "openai" / "anthropic" / "vercel-ai" / etc.
 *   * ``model``          -- the resolved model identifier.
 *   * ``request_digest`` -- "sha256-<hex>" of the JCS-canonicalized request body.
 *   * ``response``       -- the recorded response object (canonical form).
 *   * ``response_digest``-- "sha256-<hex>" of the JCS-canonicalized response body.
 *   * ``timestamp``      -- RFC3339 of the recorded call.
 *
 * The reader validates the header schema_version and every entry
 * schema_version on load. Unknown schema versions raise synchronously
 * (CLAUDE.md keystone invariant #10).
 *
 * Cross-language byte-equality (VAL-W4-041) is asserted by writing the
 * cassette via the canonical JCS stringify on both sides; the reader
 * does NOT re-canonicalize on load.
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";

export const CASSETTE_HEADER_SCHEMA_VERSION = "relay.cassette.v1";
export const CASSETTE_ENTRY_SCHEMA_VERSION = "relay.cassette_entry.v1";

export interface CassetteHeader {
  readonly schema_version: typeof CASSETTE_HEADER_SCHEMA_VERSION;
  readonly case_id: string;
  readonly session_id: string;
  readonly recorded_at: string;
  readonly manifest_commit_hash: string;
}

export interface CassetteEntry {
  readonly schema_version: typeof CASSETTE_ENTRY_SCHEMA_VERSION;
  readonly sequence: number;
  readonly provider: string;
  readonly model: string;
  readonly request_digest: string;
  readonly response: Record<string, unknown>;
  readonly response_digest: string;
  readonly timestamp: string;
}

export interface Cassette {
  readonly header: CassetteHeader;
  readonly entries: ReadonlyArray<CassetteEntry>;
  /** SHA-256 of the entire cassette bytes; useful for parity assertions. */
  readonly fileDigestSha256: string;
}

/** Raised when the cassette cannot be parsed or validated. */
export class CassetteFormatError extends Error {
  readonly line: number;
  readonly path: string | null;
  constructor(message: string, line: number, path: string | null = null) {
    super(message);
    this.name = "CassetteFormatError";
    this.line = line;
    this.path = path;
  }
}

function parseLine(raw: string, line: number, path: string | null): unknown {
  const trimmed = raw.trim();
  if (trimmed === "") {
    throw new CassetteFormatError(
      "cassette line is empty; cassettes must not contain blank lines",
      line,
      path,
    );
  }
  try {
    return JSON.parse(trimmed);
  } catch (err) {
    throw new CassetteFormatError(
      `cassette line ${line} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
      line,
      path,
    );
  }
}

function asString(value: unknown, field: string, line: number, path: string | null): string {
  if (typeof value !== "string" || value === "") {
    throw new CassetteFormatError(
      `cassette field ${JSON.stringify(field)} must be a non-empty string`,
      line,
      path,
    );
  }
  return value;
}

function asInt(value: unknown, field: string, line: number, path: string | null): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new CassetteFormatError(
      `cassette field ${JSON.stringify(field)} must be a non-negative integer`,
      line,
      path,
    );
  }
  return value;
}

function asObject(value: unknown, field: string, line: number, path: string | null): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CassetteFormatError(
      `cassette field ${JSON.stringify(field)} must be an object`,
      line,
      path,
    );
  }
  return value as Record<string, unknown>;
}

function validateHeader(raw: unknown, path: string | null): CassetteHeader {
  const obj = asObject(raw, "header", 1, path);
  const schemaVersion = asString(obj["schema_version"], "schema_version", 1, path);
  if (schemaVersion !== CASSETTE_HEADER_SCHEMA_VERSION) {
    throw new CassetteFormatError(
      `cassette header schema_version must be ${CASSETTE_HEADER_SCHEMA_VERSION}; got ${JSON.stringify(schemaVersion)}`,
      1,
      path,
    );
  }
  return {
    schema_version: CASSETTE_HEADER_SCHEMA_VERSION,
    case_id: asString(obj["case_id"], "case_id", 1, path),
    session_id: asString(obj["session_id"], "session_id", 1, path),
    recorded_at: asString(obj["recorded_at"], "recorded_at", 1, path),
    manifest_commit_hash: asString(
      obj["manifest_commit_hash"],
      "manifest_commit_hash",
      1,
      path,
    ),
  };
}

function validateEntry(raw: unknown, line: number, path: string | null): CassetteEntry {
  const obj = asObject(raw, `entry@line${line}`, line, path);
  const schemaVersion = asString(obj["schema_version"], "schema_version", line, path);
  if (schemaVersion !== CASSETTE_ENTRY_SCHEMA_VERSION) {
    throw new CassetteFormatError(
      `cassette entry schema_version must be ${CASSETTE_ENTRY_SCHEMA_VERSION}; got ${JSON.stringify(schemaVersion)}`,
      line,
      path,
    );
  }
  return {
    schema_version: CASSETTE_ENTRY_SCHEMA_VERSION,
    sequence: asInt(obj["sequence"], "sequence", line, path),
    provider: asString(obj["provider"], "provider", line, path),
    model: asString(obj["model"], "model", line, path),
    request_digest: asString(obj["request_digest"], "request_digest", line, path),
    response: asObject(obj["response"], "response", line, path),
    response_digest: asString(obj["response_digest"], "response_digest", line, path),
    timestamp: asString(obj["timestamp"], "timestamp", line, path),
  };
}

/**
 * Parse a cassette from raw JSONL bytes / text.
 *
 * Validates header and every entry. Returns the canonical
 * :class:`Cassette` object. Per VAL-W4-041 the cassette is read
 * byte-identically -- no normalization or re-canonicalization on load
 * (the recorded bytes are the wire form by construction).
 */
export function parseCassette(raw: string | Uint8Array, path: string | null = null): Cassette {
  const text = typeof raw === "string" ? raw : new TextDecoder("utf-8").decode(raw);
  const buf = typeof raw === "string" ? Buffer.from(raw, "utf8") : Buffer.from(raw);
  const fileDigestSha256 = crypto.createHash("sha256").update(buf).digest("hex");
  const lines = text.split("\n");
  // Trim trailing empty newline if present.
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  if (lines.length === 0) {
    throw new CassetteFormatError("cassette is empty", 0, path);
  }
  const headerLine = lines[0] as string;
  const headerObj = parseLine(headerLine, 1, path);
  const header = validateHeader(headerObj, path);
  const entries: CassetteEntry[] = [];
  for (let i = 1; i < lines.length; i += 1) {
    const lineNum = i + 1;
    const obj = parseLine(lines[i] as string, lineNum, path);
    const entry = validateEntry(obj, lineNum, path);
    if (entry.sequence !== i - 1) {
      throw new CassetteFormatError(
        `cassette entry sequence must be ${i - 1}; got ${entry.sequence}`,
        lineNum,
        path,
      );
    }
    entries.push(entry);
  }
  return { header, entries, fileDigestSha256 };
}

/**
 * Read and parse a cassette from disk.
 */
export function readCassetteFile(path: string): Cassette {
  const raw = fs.readFileSync(path);
  return parseCassette(raw, path);
}

/**
 * Look up a cassette entry by sequence index.
 *
 * Returns the entry or null if out of range. Callers MUST check the
 * return value rather than indexing directly.
 */
export function getEntryBySequence(cassette: Cassette, sequence: number): CassetteEntry | null {
  if (!Number.isInteger(sequence) || sequence < 0 || sequence >= cassette.entries.length) {
    return null;
  }
  return cassette.entries[sequence] as CassetteEntry;
}

/**
 * Find the first entry matching a request_digest. Returns the entry or
 * null. Useful for cassette playback driven by request hashing.
 */
export function findEntryByRequestDigest(
  cassette: Cassette,
  requestDigest: string,
): CassetteEntry | null {
  for (const entry of cassette.entries) {
    if (entry.request_digest === requestDigest) return entry;
  }
  return null;
}
