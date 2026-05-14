/**
 * Atomic file write primitive for the TypeScript SDK (W4.1).
 *
 * Mirrors Python's ``relay.persistence.primitives.local_atomic_file_write``
 * (CLAUDE.md keystone invariant #8). Production code paths that need to
 * write a persistent file MUST go through this primitive. The lint at
 * ``scripts/lint-no-bypass-primitives.py`` rejects direct calls to
 * ``fs.writeFile``, ``fs.writeFileSync``, ``fs.promises.writeFile``,
 * ``fs.rename``, etc., outside this module.
 *
 * Semantics:
 *   1. Write payload to a sibling temp file (``.<basename>.tmp<random>``).
 *   2. Set mode 0o600 (POSIX) or document weaker default (Windows).
 *   3. ``fsync`` the temp file to flush kernel buffers to disk.
 *   4. ``rename`` the temp file over the target path; on POSIX this is
 *      atomic, on Windows it is replace-style (also atomic for our use).
 *   5. ``fsync`` the containing directory (POSIX) so the rename survives
 *      a crash; on Windows we skip the dir-fsync (not exposed).
 *
 * ASCII-only per CLAUDE.md "ASCII-Safe Source".
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export interface LocalAtomicWriteOptions {
  /** POSIX file mode applied to the temp file before rename. */
  mode?: number;
  /** When true, omit the directory fsync (cheaper for hot loops). */
  skipDirFsync?: boolean;
}

/**
 * Write ``payload`` to ``targetPath`` atomically.
 *
 * The temp file lives in the same directory as the target so the rename
 * is on a single filesystem (cross-fs renames are not atomic).
 *
 * Throws if the temp write or rename fails; the partial temp file is best
 * effort-deleted on failure. On Windows the mode argument is honored as
 * best-effort via ``fs.chmod``; Win32 ACL semantics differ from POSIX
 * permissions, so callers needing strict 0o600 on Windows should layer
 * their own ACL handling.
 */
export function localAtomicFileWrite(
  targetPath: string,
  payload: Buffer | string,
  options: LocalAtomicWriteOptions = {},
): void {
  const mode = options.mode ?? 0o600;
  const skipDirFsync = options.skipDirFsync === true;
  const dir = path.dirname(targetPath);
  const base = path.basename(targetPath);
  // 16 hex chars from random bytes -> 8 bytes of entropy.
  const suffix = crypto.randomBytes(8).toString("hex");
  const tmpPath = path.join(dir, `.${base}.tmp${suffix}`);

  // Step 1: open the temp file with O_WRONLY | O_CREAT | O_EXCL so that a
  // collision with a stray sibling temp file fails closed.
  const fd = fs.openSync(tmpPath, "wx", mode);
  try {
    const buf =
      typeof payload === "string"
        ? Buffer.from(payload, "utf8")
        : Buffer.isBuffer(payload)
          ? payload
          : Buffer.from(payload);
    let written = 0;
    while (written < buf.length) {
      written += fs.writeSync(fd, buf, written, buf.length - written, null);
    }
    fs.fsyncSync(fd);
  } finally {
    try {
      fs.closeSync(fd);
    } catch {
      // Already closed: tolerate.
    }
  }

  // Step 2: enforce mode (openSync `wx` mode is masked by umask on POSIX;
  // chmod after-the-fact bypasses umask).
  try {
    fs.chmodSync(tmpPath, mode);
  } catch {
    // Windows may surface EPERM here; safe to ignore.
  }

  // Step 3: atomic rename over the target.
  try {
    fs.renameSync(tmpPath, targetPath);
  } catch (err) {
    // Best-effort cleanup of the orphaned temp file.
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // Ignore.
    }
    throw err;
  }

  // Step 4: optional directory fsync so the rename survives a crash.
  if (!skipDirFsync && process.platform !== "win32") {
    let dirFd: number | null = null;
    try {
      dirFd = fs.openSync(dir, "r");
      fs.fsyncSync(dirFd);
    } catch {
      // Some filesystems (e.g., tmpfs on macOS network shares) refuse the
      // directory fsync; tolerate -- the rename itself is durable.
    } finally {
      if (dirFd !== null) {
        try {
          fs.closeSync(dirFd);
        } catch {
          // Ignore.
        }
      }
    }
  }
}
