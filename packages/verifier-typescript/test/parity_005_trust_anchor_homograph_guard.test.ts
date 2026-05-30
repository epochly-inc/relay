// VAL-PARITY-005: TS verifier omits the UTS-39 confusables/homograph guard
// on BYO trust-anchor URLs (Python enforces it).
//
// Python `resolve_trust_anchor_url` calls
// `_enforce_trust_anchor_homograph_guard()` on every BYO flag URL and every
// BYO config URL (packages/verifier/src/relay_verifier/jwks_loader.py:657,
// :662), rejecting hosts that are UTS-39 confusables of the canonical default
// host `relay.epochly.com` with `RelayConfigInvalidError` / code
// `RELAY-VERIFY-003` and reason `confusable` / `mixed_script` / `non_ascii`.
//
// Before this fix, TS `resolveTrustAnchorUrl` (jwks_loader.ts:233-246) OMITS
// that guard entirely, so a homograph host (e.g. `relay.epochly.com` where the
// ASCII `y` is replaced by Cyrillic small letter U U+0443) is ACCEPTED by TS
// and would be fetched -- a trust-anchor homograph attack vector Python blocks.
//
// Cyrillic / other non-ASCII characters are written as `\uXXXX` escapes so the
// source file stays pure ASCII per CLAUDE.md "ASCII-Safe Source"
// (scripts/lint-ascii-source.py).
//
// Cross-language ground truth (verified against the Python reference):
//   resolve_trust_anchor_url(flag_url='https://relay.epochl<U+0443>.com/...')
//     -> RelayConfigInvalidError code=RELAY-VERIFY-003 reason=confusable
//   resolve_trust_anchor_url(flag_url='https://relay.epochly.com/...') -> OK
//   resolve_trust_anchor_url(flag_url='https://example.com/...')        -> OK

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, test } from "vitest";

import {
  RELAY_VERIFY_CONFIG_INVALID,
  RelayVerifierError,
  checkHostConfusable,
  resolveJwks,
  resolveTrustAnchorUrl,
} from "../src/index.js";

// Canonical default host -- the UTS-39 fold target. Banned pattern #13: the
// DEFAULT trust anchor URL itself is unchanged; we only ADD a guard.
const CANONICAL_HOST = "relay.epochly.com";

// `relay.epochly.com` with the ASCII `y` swapped for Cyrillic small letter U
// (U+0443), which folds to `y` in the curated UTS-39 confusables map. The
// resulting skeleton is exactly the canonical host -> reason `confusable`.
const CYRILLIC_HOMOGRAPH_HOST = "relay.epochl\u0443.com"; // U+0443 CYRILLIC SMALL LETTER U in place of ASCII 'y'
const CYRILLIC_HOMOGRAPH_URL = `https://${CYRILLIC_HOMOGRAPH_HOST}/.well-known/jwks.json`;

const CANONICAL_URL = "https://relay.epochly.com/.well-known/jwks.json";
const UNRELATED_LEGIT_URL = "https://example.com/.well-known/jwks.json";

// A fetcher that should NEVER be reached for the homograph host: if the guard
// fires before the network step, this throws to make a leak obvious.
const trapFetcher = (): Record<string, unknown> => {
  throw new Error("fetcher must not be reached for a rejected homograph host");
};

// A benign fetcher for the accept-path assertions.
const okFetcher = (): Record<string, unknown> => ({
  keys: [{ kty: "OKP", crv: "Ed25519", x: "abc", kid: "k1" }],
});

describe("VAL-PARITY-005 trust-anchor homograph guard (flag branch)", () => {
  test("Cyrillic-u homograph flag URL is REJECTED with RELAY-VERIFY-003 / confusable", async () => {
    await expect(
      resolveJwks({ flagUrl: CYRILLIC_HOMOGRAPH_URL, fetcher: trapFetcher }),
    ).rejects.toMatchObject({
      code: RELAY_VERIFY_CONFIG_INVALID,
    });

    // Inspect the structured rejection directly for the reason + offending URL.
    let caught: unknown;
    try {
      await resolveJwks({ flagUrl: CYRILLIC_HOMOGRAPH_URL, fetcher: trapFetcher });
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(RelayVerifierError);
    const err = caught as RelayVerifierError;
    expect(err.code).toBe(RELAY_VERIFY_CONFIG_INVALID);
    expect(err.details["reason"]).toBe("confusable");
    expect(err.details["trust_anchor"]).toBe(CYRILLIC_HOMOGRAPH_URL);
  });

  test("resolveTrustAnchorUrl rejects the homograph flag URL before returning", () => {
    expect(() => resolveTrustAnchorUrl({ flagUrl: CYRILLIC_HOMOGRAPH_URL })).toThrow(
      RelayVerifierError,
    );
  });

  test("canonical relay.epochly.com flag URL is ACCEPTED (pure-ASCII BYO)", async () => {
    const out = await resolveJwks({ flagUrl: CANONICAL_URL, fetcher: okFetcher });
    expect(out.trust_anchor_url).toBe(CANONICAL_URL);
    expect(out.source).toBe("byo_flag");
  });

  test("unrelated legit host example.com flag URL is ACCEPTED", async () => {
    const out = await resolveJwks({ flagUrl: UNRELATED_LEGIT_URL, fetcher: okFetcher });
    expect(out.trust_anchor_url).toBe(UNRELATED_LEGIT_URL);
    expect(out.source).toBe("byo_flag");
  });
});

describe("VAL-PARITY-005 trust-anchor homograph guard (config branch)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "relay-parity005-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test("homograph config trust_anchor_url is REJECTED with RELAY-VERIFY-003 / confusable", () => {
    const cfgPath = join(tmpDir, "verifier.toml");
    writeFileSync(cfgPath, `trust_anchor_url = "${CYRILLIC_HOMOGRAPH_URL}"\n`, "utf-8");
    let caught: unknown;
    try {
      resolveTrustAnchorUrl({ configPath: cfgPath });
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(RelayVerifierError);
    const err = caught as RelayVerifierError;
    expect(err.code).toBe(RELAY_VERIFY_CONFIG_INVALID);
    expect(err.details["reason"]).toBe("confusable");
  });

  test("canonical config trust_anchor_url is ACCEPTED", () => {
    const cfgPath = join(tmpDir, "verifier.toml");
    writeFileSync(cfgPath, `trust_anchor_url = "${CANONICAL_URL}"\n`, "utf-8");
    const [url, source] = resolveTrustAnchorUrl({ configPath: cfgPath });
    expect(url).toBe(CANONICAL_URL);
    expect(source).toBe("byo_config");
  });
});

describe("VAL-PARITY-005 checkHostConfusable Py<->TS parity", () => {
  test("Cyrillic-u host folds to canonical skeleton -> confusable rejection", () => {
    let caught: unknown;
    try {
      checkHostConfusable(CYRILLIC_HOMOGRAPH_HOST, CANONICAL_HOST);
    } catch (exc) {
      caught = exc;
    }
    expect(caught).toBeInstanceOf(RelayVerifierError);
    const err = caught as RelayVerifierError;
    expect(err.code).toBe(RELAY_VERIFY_CONFIG_INVALID);
    expect(err.details["reason"]).toBe("confusable");
  });

  test("pure-ASCII canonical host passes the guard", () => {
    expect(() => checkHostConfusable(CANONICAL_HOST, CANONICAL_HOST)).not.toThrow();
  });

  test("pure-ASCII unrelated host passes the guard (operator BYO)", () => {
    expect(() => checkHostConfusable("example.com", CANONICAL_HOST)).not.toThrow();
  });

  test("empty host is a no-op (delegated to downstream URL validation)", () => {
    expect(() => checkHostConfusable("", CANONICAL_HOST)).not.toThrow();
  });
});
