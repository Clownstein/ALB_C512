/**
 * Suite constants, limits, and the fail-closed provider check.
 *
 * FORMAT.md sections 1 and 4.  Nothing here is configurable at runtime: a
 * build either supports ALBPKG-1 in full or refuses to load.
 */

import { generateKeyPairSync, createCipheriv, hkdfSync } from "node:crypto";
import { ProviderError } from "./errors.ts";

// ---- Suite ---------------------------------------------------------------

export const SUITE_ID = 0x0001;
export const SUITE_NAME = "ALBPKG-1";
export const FORMAT_VERSION = 1;

export const KEM_PUB_LEN = 1184;
export const KEM_CT_LEN = 1088;
export const KEM_SS_LEN = 32;
export const KEM_SEED_LEN = 64;
export const SIG_PUB_LEN = 1952;
export const SIG_LEN = 3309;
export const SIG_SEED_LEN = 32;

export const AEAD_KEY_LEN = 32;
export const AEAD_TAG_LEN = 16;
export const AEAD_NONCE_LEN = 12;
export const AEAD_NONCE = Buffer.alloc(AEAD_NONCE_LEN, 0);

export const FPR_LEN = 32;
export const PACKAGE_ID_LEN = 16;

/** Node's algorithm names for the suite's primitives. */
export const KEM_ALGORITHM = "ml-kem-768";
export const SIG_ALGORITHM = "ml-dsa-65";
export const AEAD_ALGORITHM = "aes-256-gcm";

// ---- Magics --------------------------------------------------------------

export const PUBID_MAGIC = Buffer.from("ALBPKID1", "ascii");
export const SKFILE_MAGIC = Buffer.from("ALBPKSK2", "ascii");

// Private identity container (FORMAT.md 2.4)
export const KDF_PBKDF2_SHA256 = 0x0001;
export const KDF_SALT_LEN = 16;
/** Written by this implementation.  Readers accept anything in the range. */
export const KDF_ITERATIONS = 600_000;
export const KDF_MIN_ITERATIONS = 600_000;
export const KDF_MAX_ITERATIONS = 10_000_000;
export const PACKAGE_MAGIC = Buffer.from("ALBPKG1\0", "ascii");
export const SIG_TRAILER_MAGIC = Buffer.from("ALBPKGSG", "ascii");

export const PUBID_LEN =
  PUBID_MAGIC.length + 2 + 2 + KEM_PUB_LEN + 2 + SIG_PUB_LEN; // 3150

export const HEADER_LEN =
  PACKAGE_MAGIC.length + 2 + 2 + 4 + 4 + 4 + FPR_LEN * 2 + PACKAGE_ID_LEN + 2 + KEM_CT_LEN; // 1194

export const SIG_TRAILER_LEN = 4 + SIG_TRAILER_MAGIC.length;

// ---- Domain separation strings (ASCII, no trailing NUL) ------------------

export const INFO_MASTER = Buffer.from("ALBPKG1 master v1", "ascii");
export const INFO_CHUNK = Buffer.from("ALBPKG1 chunk v1", "ascii");
export const INFO_COMPLETE = Buffer.from("ALBPKG1 complete v1", "ascii");

export const AAD_CHUNK_PREFIX = Buffer.from("ALBPKG1-CHUNK", "ascii");
export const AAD_COMPLETE_PREFIX = Buffer.from("ALBPKG1-COMPLETE", "ascii");
export const SIG_CONTEXT = Buffer.from("ALBPKG1-SIGV1", "ascii");

// ---- Limits --------------------------------------------------------------

export const CHUNK_SIZE = 1 << 20; // 1 MiB
export const MAX_PLAINTEXT = 1099511627776; // 1 TiB
export const MAX_CHUNKS = MAX_PLAINTEXT / CHUNK_SIZE; // 1048576
export const CHUNK_FRAME_OVERHEAD = 1 + 4 + AEAD_TAG_LEN;
export const COMPLETION_LEN = 16 + AEAD_TAG_LEN;

export const MAX_PACKAGE_SIZE =
  HEADER_LEN +
  MAX_CHUNKS * (CHUNK_SIZE + CHUNK_FRAME_OVERHEAD) +
  COMPLETION_LEN +
  SIG_LEN +
  SIG_TRAILER_LEN;

export const UINT32_MAX = 0xffffffff;

/**
 * Fail closed unless every required primitive is available.
 *
 * A partial provider is treated as no provider: we never silently substitute
 * a different algorithm.  Called once at module load.
 */
export function checkProvider(): void {
  const missing: string[] = [];

  try {
    generateKeyPairSync(KEM_ALGORITHM as never);
  } catch {
    missing.push("ML-KEM-768");
  }

  try {
    generateKeyPairSync(SIG_ALGORITHM as never);
  } catch {
    missing.push("ML-DSA-65");
  }

  try {
    const cipher = createCipheriv(
      AEAD_ALGORITHM,
      Buffer.alloc(AEAD_KEY_LEN),
      AEAD_NONCE,
    );
    cipher.final();
  } catch {
    missing.push("AES-256-GCM");
  }

  try {
    hkdfSync("sha256", Buffer.alloc(32), Buffer.alloc(32), Buffer.from("x"), 32);
  } catch {
    missing.push("HKDF-SHA-256");
  }

  if (missing.length > 0) {
    throw new ProviderError(
      `required algorithms unavailable from the cryptographic provider: ${missing.join(", ")}`,
    );
  }
}

/** Guard the compile-time constants against edit mistakes. */
function assertSelfConsistent(): void {
  if (PUBID_LEN !== 3150) throw new Error(`PUBID_LEN ${PUBID_LEN}`);
  if (HEADER_LEN !== 1194) throw new Error(`HEADER_LEN ${HEADER_LEN}`);
  if (MAX_CHUNKS !== 1048576) throw new Error(`MAX_CHUNKS ${MAX_CHUNKS}`);
}

assertSelfConsistent();
