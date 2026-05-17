// Subject-resolution check for the bundle validator (TS parity with
// packages/verifier/src/relay_verifier/retention.py).
//
// Per spec section K lines 4435 (tombstoned) and 4438 (redacted-after-
// signing) an evidence bundle's referenced subject (run / replay /
// eval_run) MAY no longer exist or MAY have been redacted by a
// superseding bundle. The verifier reports the resolution state without
// rejecting the bundle: internal consistency (subject id + digest) is
// preserved either way, and the original signature binding remains valid.
//
// ASCII-only per CLAUDE.md "ASCII-Safe Source".

export const SUBJECT_RESOLUTION_LIVE = "live" as const;
export const SUBJECT_RESOLUTION_TOMBSTONED = "tombstoned" as const;
export const SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING =
  "redacted_after_signing" as const;
export const SUBJECT_RESOLUTION_UNKNOWN = "unknown" as const;

export interface SubjectRecord {
  /** "live" | "tombstoned" | "redacted_after_signing". */
  readonly state: string;
  /** Digest the subject carried at the time the bundle was signed. */
  readonly original_digest_hex: string;
}

export interface SubjectStore {
  lookup(subject_id: string): SubjectRecord | null;
}

export interface SubjectResolutionResult {
  resolution: string;
  reason: string;
  original_digest_preserved: boolean;
}

function _newResult(): SubjectResolutionResult {
  return {
    resolution: SUBJECT_RESOLUTION_UNKNOWN,
    reason: "",
    original_digest_preserved: true,
  };
}

/**
 * Resolve a bundle's subject reference through an optional store.
 * Mirrors `relay_verifier.retention.resolve_subject` line-for-line.
 *
 * Never throws; failure modes are encoded in the result fields.
 */
export function resolveSubject(args: {
  subjectId: string | null | undefined;
  subjectDigestHex: string | null | undefined;
  subjectStore: SubjectStore | null | undefined;
}): SubjectResolutionResult {
  const result = _newResult();
  const { subjectId, subjectDigestHex, subjectStore } = args;

  if (subjectStore === null || subjectStore === undefined) {
    result.resolution = SUBJECT_RESOLUTION_UNKNOWN;
    result.reason =
      "no subject_store supplied; verifier cannot determine subject " +
      "state (offline mode)";
    return result;
  }

  if (subjectId === null || subjectId === undefined || subjectId === "") {
    result.resolution = SUBJECT_RESOLUTION_LIVE;
    result.reason = "bundle declares no subject_id; trivially live";
    return result;
  }

  const record = subjectStore.lookup(subjectId);
  if (record === null || record === undefined) {
    result.resolution = SUBJECT_RESOLUTION_TOMBSTONED;
    result.reason =
      `subject ${JSON.stringify(subjectId)} not found in store (deleted under retention)`;
    return result;
  }

  const known = new Set<string>([
    SUBJECT_RESOLUTION_LIVE,
    SUBJECT_RESOLUTION_TOMBSTONED,
    SUBJECT_RESOLUTION_REDACTED_AFTER_SIGNING,
  ]);
  if (!known.has(record.state)) {
    result.resolution = SUBJECT_RESOLUTION_UNKNOWN;
    result.reason =
      `subject ${JSON.stringify(subjectId)} record carries unknown state ${JSON.stringify(record.state)}`;
    return result;
  }

  if (
    subjectDigestHex !== null &&
    subjectDigestHex !== undefined &&
    record.original_digest_hex !== "" &&
    subjectDigestHex !== record.original_digest_hex
  ) {
    result.original_digest_preserved = false;
    result.reason =
      `subject ${JSON.stringify(subjectId)} original_digest_hex ` +
      `${JSON.stringify(record.original_digest_hex)} does not match bundle's ` +
      `subject_digest_hex ${JSON.stringify(subjectDigestHex)}`;
  }

  result.resolution = record.state;
  return result;
}

/**
 * Trivial dict-backed subject store; for tests/fixtures. Mirrors
 * `relay_verifier.retention.InMemorySubjectStore`.
 */
export class InMemorySubjectStore implements SubjectStore {
  private readonly records: Map<string, SubjectRecord>;

  constructor(records?: Record<string, SubjectRecord>) {
    this.records = new Map<string, SubjectRecord>();
    if (records) {
      for (const [k, v] of Object.entries(records)) {
        this.records.set(k, v);
      }
    }
  }

  lookup(subjectId: string): SubjectRecord | null {
    return this.records.get(subjectId) ?? null;
  }

  set(subjectId: string, record: SubjectRecord): void {
    this.records.set(subjectId, record);
  }
}
