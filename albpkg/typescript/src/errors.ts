/**
 * Structured errors for ALBPKG/1.
 *
 * Messages must never carry key material, plaintext, or passphrases.  Each
 * class corresponds to one of the categories required by FORMAT.md section 9.
 */

export type ErrorCategory =
  | "FORMAT"
  | "UNSUPPORTED"
  | "LIMIT"
  | "TRUST"
  | "AUTH"
  | "IO"
  | "PASSPHRASE"
  | "PROVIDER";

export class AlbpkgError extends Error {
  readonly category: ErrorCategory = "FORMAT";

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }

  override toString(): string {
    return `[${this.category}] ${this.message}`;
  }
}

/** Framing or parse failure: bad magic, bad lengths, trailing bytes. */
export class FormatError extends AlbpkgError {
  override readonly category: ErrorCategory = "FORMAT";
}

/** Unknown format version, suite id, or flag bits. */
export class UnsupportedError extends AlbpkgError {
  override readonly category: ErrorCategory = "UNSUPPORTED";
}

/** A declared or implied length exceeds a bound, or an addition overflows. */
export class LimitError extends AlbpkgError {
  override readonly category: ErrorCategory = "LIMIT";
}

/** Unknown, unverified, or revoked contact; or wrong recipient. */
export class TrustError extends AlbpkgError {
  override readonly category: ErrorCategory = "TRUST";
}

/** Signature verification or AEAD tag verification failed. */
export class AuthError extends AlbpkgError {
  override readonly category: ErrorCategory = "AUTH";
}

/** Filesystem or stream failure. */
export class IoError extends AlbpkgError {
  override readonly category: ErrorCategory = "IO";
}

/** Passphrase missing, rejected, or unreadable. */
export class PassphraseError extends AlbpkgError {
  override readonly category: ErrorCategory = "PASSPHRASE";
}

/** A required primitive is unavailable from the cryptographic provider. */
export class ProviderError extends AlbpkgError {
  override readonly category: ErrorCategory = "PROVIDER";
}
