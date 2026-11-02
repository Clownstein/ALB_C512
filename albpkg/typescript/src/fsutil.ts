/**
 * Private temporary files, owner-only permissions, atomic publication.
 *
 * FORMAT.md section 7.  Nothing partially written ever appears at a
 * destination path: work happens in an owner-only temporary file in the
 * destination directory (so the final rename stays on one filesystem) and is
 * published by rename only after every check has passed.
 */

import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  renameSync,
  linkSync,
  statSync,
  unlinkSync,
  chmodSync,
  constants as fsConstants,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as path from "node:path";
import { IoError } from "./errors.ts";

const IS_WINDOWS = process.platform === "win32";

/**
 * Make `target` readable and writable by its owner only.
 *
 * On POSIX this is chmod 0600.  On Windows we replace the DACL with a single
 * ACE for the current user via `icacls`, disabling inheritance.  If the
 * platform call fails we surface it rather than pretending the file is
 * protected.
 */
export function restrictPermissions(target: string): void {
  if (!IS_WINDOWS) {
    chmodSync(target, 0o600);
    return;
  }
  const who = spawnSync("whoami", ["/user", "/fo", "csv", "/nh"], {encoding:"utf8"});
  const sid = who.stdout?.match(/S-1-[0-9-]+/)?.[0];
  if (who.status !== 0 || !sid) throw new IoError("cannot determine current user SID");
  const principal = "*" + sid;
  const result = spawnSync(
    "icacls",
    [target, "/inheritance:r", "/grant:r", `${principal}:F`],
    { encoding: "utf8" },
  );
  if (result.error || result.status !== 0) {
    throw new IoError("failed to restrict file permissions", {
      cause: result.error,
    });
  }
}

/** Best-effort check used by tests and by the key loader. */
export function permissionsAreOwnerOnly(target: string): boolean {
  if (!IS_WINDOWS) {
    return (statSync(target).mode & 0o077) === 0;
  }
  const result = spawnSync("icacls", [target], { encoding: "utf8" });
  if (result.error || result.status !== 0) return false;
  const aceLines = result.stdout
    .split(/\r?\n/)
    .filter((line) => line.includes(":("));
  const shared = ["Everyone", "BUILTIN\\Users", "Authenticated Users"];
  return !aceLines.some((line) => shared.some((name) => line.includes(name)));
}

/** Create `target` exclusively with owner-only permissions and return its fd. */
export function openPrivateNew(target: string): number {
  let fd: number;
  try {
    fd = openSync(
      target,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      0o600,
    );
  } catch (cause) {
    const err = cause as NodeJS.ErrnoException;
    if (err.code === "EEXIST") throw cause;
    throw new IoError(`cannot create ${path.basename(target)}`, { cause });
  }
  if (IS_WINDOWS) {
    try {
      restrictPermissions(target);
    } catch (cause) {
      try {
        closeSync(fd);
      } catch {
        /* already failing */
      }
      try {
        unlinkSync(target);
      } catch {
        /* already failing */
      }
      throw cause;
    }
  }
  return fd;
}

function tempSibling(destination: string): string {
  const dir = path.dirname(destination);
  const base = path.basename(destination);
  return path.join(dir, `.${base}.albpkg-${randomBytes(8).toString("hex")}.tmp`);
}

export interface AtomicHandle {
  readonly fd: number;
  readonly tempPath: string;
}

/**
 * Run `body` against a private temp file and publish it atomically on success.
 *
 * On any throw the temporary file is removed and `destination` is left exactly
 * as it was.  Without `overwrite`, an existing destination fails *before* any
 * work is done and is never touched.
 */
export function withAtomicOutput<T>(
  destination: string,
  options: { overwrite?: boolean },
  body: (handle: AtomicHandle) => T,
): T {
  const overwrite = options.overwrite ?? false;
  const parent = path.dirname(destination);
  if (!existsSync(parent)) {
    throw new IoError(`destination directory does not exist: ${parent}`);
  }
  if (existsSync(destination) && !overwrite) {
    throw new IoError(
      `destination exists and overwrite was not requested: ${path.basename(destination)}`,
    );
  }

  let tempPath = tempSibling(destination);
  let fd: number | undefined;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      fd = openPrivateNew(tempPath);
      break;
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "EEXIST") throw cause;
      tempPath = tempSibling(destination);
    }
  }
  if (fd === undefined) {
    throw new IoError("could not create a unique temporary file");
  }

  let published = false;
  let closed = false;
  try {
    const result = body({ fd, tempPath });
    fsyncSync(fd);
    closeSync(fd);
    closed = true;
    if (overwrite) renameSync(tempPath, destination);
    else { linkSync(tempPath, destination); unlinkSync(tempPath); }
    published = true;
    return result;
  } finally {
    if (!closed) {
      try {
        closeSync(fd);
      } catch {
        /* the original failure is what matters */
      }
    }
    if (!published) {
      try {
        unlinkSync(tempPath);
      } catch {
        /* the original failure is what matters */
      }
    }
  }
}

/** An owner-only scratch file that is always deleted. */
export function withPrivateSpool<T>(
  directory: string,
  body: (handle: AtomicHandle) => T,
): T {
  const tempPath = path.join(
    directory,
    `.albpkg-spool-${randomBytes(8).toString("hex")}.tmp`,
  );
  const fd = openPrivateNew(tempPath);
  let closed = false;
  try {
    return body({ fd, tempPath });
  } finally {
    if (!closed) {
      try {
        closeSync(fd);
        closed = true;
      } catch {
        /* the original failure is what matters */
      }
    }
    try {
      unlinkSync(tempPath);
    } catch {
      /* the original failure is what matters */
    }
  }
}

/**
 * Overwrite a mutable secret buffer in place.
 *
 * Best-effort.  On a managed runtime it cannot reach copies the engine made
 * (V8 may have relocated or copied the backing store, and it may be in swap).
 * The C, C++, and Rust ports use their platform's guaranteed-erasure call.
 */
export function wipe(buffer: Buffer | Uint8Array): void {
  buffer.fill(0);
}
