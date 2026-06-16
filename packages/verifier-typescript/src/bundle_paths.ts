// Bundle verifier path-traversal hardening (VAL-V2M08-015..017).
//
// TypeScript parity port of
// packages/verifier/src/relay_verifier/bundle_paths.py.
//
// The OSS bundle verifier rejects any bundle whose manifest declares an
// artifact path that:
//
//   * contains `..` segments (`relative_traversal`)
//   * is absolute -- POSIX (`/`), Windows drive (`C:\`), or UNC
//     (`\\host\share`) (`absolute_path`)
//   * is not Unicode NFC (`non_nfc_name`)
//   * contains invalid UTF-8 byte sequences, NUL bytes, or lone
//     surrogates (`invalid_utf8_name`)
//   * is empty / leading-or-trailing whitespace
//     (`invalid_utf8_name` fall-through bucket -- consumers branch on
//     `code` not on the exact discriminator)
//   * exceeds 1024 UTF-8 bytes
//
// Rejections surface under the existing RELAY-EVID-024 path-violation
// code with a structured `path_violation` discriminator so downstream
// tooling can branch on the specific violation class.
//
// The check is pure (no filesystem access) so it can be exercised
// against in-memory manifests at the tier-1 plumbing tier. Callers
// wire this function into `validateBundle` just before any
// artifact-resolver invocation.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

/**
 * Public wire-code for path-traversal rejections. Mirrors
 * `relay_verifier.bundle_paths.RELAY_EVID_024`.
 */
export const RELAY_EVID_024_PATH = "RELAY-EVID-024" as const;

/**
 * Maximum permitted UTF-8 length, in bytes, of an artifact path.
 * Defends against pathological inputs that bypass downstream length
 * checks (filesystem PATH_MAX or zip header limits).
 */
export const MAX_ARTIFACT_PATH_BYTES = 1024;

/**
 * Structured rejection envelope for a path that fails any
 * path-hardening check. Field names are stable wire-format names.
 */
export interface PathViolation {
  /** Wire code; always {@link RELAY_EVID_024_PATH}. */
  readonly code: typeof RELAY_EVID_024_PATH;
  /** Discriminator: which class of path violation fired. */
  readonly path_violation:
    | "relative_traversal"
    | "absolute_path"
    | "non_nfc_name"
    | "invalid_utf8_name";
  /**
   * Verbatim offending value. String inputs surfaced as-is; bytes
   * inputs that failed UTF-8 decoding surfaced as `<invalid-utf8>`.
   */
  readonly offending_path: string;
}

// Windows drive-letter prefix: a single letter followed by ":\" or ":/".
const WIN_DRIVE_RE = /^[A-Za-z]:[\\/]/;

function isUncPath(path: string): boolean {
  return path.startsWith("\\\\") || path.startsWith("//");
}

function hasRelativeTraversal(path: string): boolean {
  // Normalize Windows-style backslash separators into POSIX-style
  // forward slashes so an attacker cannot smuggle a traversal under a
  // cross-platform separator. The check is conservative: a literal
  // `..` inside a filename (e.g. `my..file.txt`) is OK; only a
  // standalone `..` segment triggers rejection.
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  for (const seg of segments) {
    if (seg === "..") return true;
  }
  return false;
}

function isAbsolute(path: string): boolean {
  if (path.length === 0) return false;
  // POSIX absolute.
  if (path.startsWith("/")) return true;
  // UNC absolute (Windows network path).
  if (isUncPath(path)) return true;
  // Windows drive-letter absolute.
  return WIN_DRIVE_RE.test(path);
}

function utf8ByteLength(s: string): number {
  // TextEncoder produces the canonical UTF-8 byte count. Lone
  // surrogates are emitted as U+FFFD replacement bytes; we already
  // reject lone-surrogate inputs above.
  return new TextEncoder().encode(s).length;
}

// CPython str.strip() / str.isspace() whitespace codepoints. The path-collision
// screen below MUST match Python's `path.strip()` EXACTLY so the Py<->TS verdict
// is identical: JS String.trim() strips a DIFFERENT set -- it OMITS the C0/C1
// separators 0x1c-0x1f and 0x85 (NEL) that Python strips (a control-char-
// prefixed artifact_id slipped the TS screen while Python rejected it), and it
// STRIPS 0xFEFF (ZWNBSP) which Python does NOT. Every Python-whitespace
// codepoint is in the BMP (<= 0x3000), so charCodeAt indexing is exact and
// never splits a surrogate pair.
const _PY_WHITESPACE: ReadonlySet<number> = new Set<number>([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0,
  0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
  0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

/** Strip leading/trailing Python-whitespace codepoints -- byte-identical to
 * CPython ``str.strip()`` over the path-screen input domain. */
function _pythonStrip(s: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && _PY_WHITESPACE.has(s.charCodeAt(start))) start++;
  while (end > start && _PY_WHITESPACE.has(s.charCodeAt(end - 1))) end--;
  return s.slice(start, end);
}

/**
 * Return `null` if `path` passes every path-hardening check; otherwise
 * return a structured rejection envelope.
 *
 * Mirrors `relay_verifier.bundle_paths.check_artifact_path` behaviorally.
 *
 * Accepts `string`, `Uint8Array`, or any other value. `Uint8Array`
 * inputs are decoded as strict UTF-8 first; bytes that do not decode
 * surface as `path_violation="invalid_utf8_name"` BEFORE any other
 * check. Non-string / non-bytes inputs return `null` (the caller is
 * responsible for type-narrowing before reaching the resolver; we
 * never accept them in practice).
 */
export function checkArtifactPath(path: unknown): PathViolation | null {
  // Bytes input: must decode as strict UTF-8 first.
  if (path instanceof Uint8Array) {
    let decoded: string;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(path);
    } catch {
      return {
        code: RELAY_EVID_024_PATH,
        path_violation: "invalid_utf8_name",
        offending_path: "<invalid-utf8>",
      };
    }
    path = decoded;
  }

  if (typeof path !== "string") {
    return null;
  }

  // Empty / leading-trailing-whitespace rejection (bug-spec C1 instruction).
  if (path.length === 0) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "invalid_utf8_name",
      offending_path: path,
    };
  }
  if (path !== _pythonStrip(path)) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "invalid_utf8_name",
      offending_path: path,
    };
  }

  // Embedded NUL bytes are a path-traversal escape under several
  // filesystems; reject regardless of segment shape.
  if (path.indexOf("\0") !== -1) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "invalid_utf8_name",
      offending_path: path,
    };
  }

  // Lone-surrogate detection. JS strings are UTF-16; an unpaired
  // surrogate code unit cannot encode as valid UTF-8.
  for (let i = 0; i < path.length; i++) {
    const cu = path.charCodeAt(i);
    if (cu >= 0xd800 && cu <= 0xdbff) {
      // High surrogate; the next code unit MUST be a low surrogate.
      const next = i + 1 < path.length ? path.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        return {
          code: RELAY_EVID_024_PATH,
          path_violation: "invalid_utf8_name",
          offending_path: path,
        };
      }
      i += 1; // skip the matched low surrogate
    } else if (cu >= 0xdc00 && cu <= 0xdfff) {
      // Low surrogate without a preceding high surrogate.
      return {
        code: RELAY_EVID_024_PATH,
        path_violation: "invalid_utf8_name",
        offending_path: path,
      };
    }
  }

  // UTF-8 byte length cap. Computed after lone-surrogate rejection so
  // we never feed an invalid string to TextEncoder.
  if (utf8ByteLength(path) > MAX_ARTIFACT_PATH_BYTES) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "invalid_utf8_name",
      offending_path: path,
    };
  }

  // Absolute paths.
  if (isAbsolute(path)) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "absolute_path",
      offending_path: path,
    };
  }

  // Relative traversal.
  if (hasRelativeTraversal(path)) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "relative_traversal",
      offending_path: path,
    };
  }

  // NFC normalization. Reject any path whose normalized form differs
  // from the input. ECMAScript-standard, byte-equivalent to Python's
  // `unicodedata.normalize("NFC", s)`.
  if (path.normalize("NFC") !== path) {
    return {
      code: RELAY_EVID_024_PATH,
      path_violation: "non_nfc_name",
      offending_path: path,
    };
  }

  return null;
}
