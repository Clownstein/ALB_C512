/**
 * Package sealing and opening.
 *
 * FORMAT.md sections 3, 5, and 6.  Streaming throughout: memory use is bounded
 * by one chunk (1 MiB) plus framing regardless of file size, and nothing
 * partially decrypted is ever visible at the destination path.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  decapsulate,
  encapsulate,
  hkdfSync,
  randomBytes,
  sign as signWith,
  verify as verifyWith,
  type KeyObject,
} from "node:crypto";
import { closeSync, openSync, statSync, writeSync, readSync } from "node:fs";
import * as path from "node:path";

import * as suite from "./suite.ts";
import { Contact, ContactStore } from "./contacts.ts";
import {
  AuthError,
  FormatError,
  IoError,
  LimitError,
  TrustError,
  UnsupportedError,
} from "./errors.ts";
import { withAtomicOutput, withPrivateSpool, wipe } from "./fsutil.ts";
import {
  Identity,
  PublicIdentity,
  fingerprintsEqual,
  formatFingerprint,
} from "./identity.ts";
import {
  ByteReader,
  checkedAdd,
  readAtMostAt,
  readExactAt,
  requireIndex,
  u16,
  u32,
  u64,
  u8,
} from "./wire.ts";

/** Called as (bytesDone, chunksDone).  May throw to cancel the operation. */
export type ProgressHook = (bytesDone: number, chunksDone: number) => void;

// ---- Header --------------------------------------------------------------

export interface HeaderFields {
  senderFpr: Buffer;
  recipientFpr: Buffer;
  packageId: Buffer;
  kemCt: Buffer;
  chunkSize?: number;
  flags?: number;
}

export class Header {
  readonly senderFpr: Buffer;
  readonly recipientFpr: Buffer;
  readonly packageId: Buffer;
  readonly kemCt: Buffer;
  readonly chunkSize: number;
  readonly flags: number;

  constructor(fields: HeaderFields) {
    this.senderFpr = fields.senderFpr;
    this.recipientFpr = fields.recipientFpr;
    this.packageId = fields.packageId;
    this.kemCt = fields.kemCt;
    this.chunkSize = fields.chunkSize ?? suite.CHUNK_SIZE;
    this.flags = fields.flags ?? 0;
  }

  serialize(): Buffer {
    if (this.senderFpr.length !== suite.FPR_LEN) {
      throw new FormatError("sender fingerprint must be 32 bytes");
    }
    if (this.recipientFpr.length !== suite.FPR_LEN) {
      throw new FormatError("recipient fingerprint must be 32 bytes");
    }
    if (this.packageId.length !== suite.PACKAGE_ID_LEN) {
      throw new FormatError("package identifier must be 16 bytes");
    }
    if (this.kemCt.length !== suite.KEM_CT_LEN) {
      throw new FormatError("ML-KEM-768 encapsulation has the wrong length");
    }
    if (this.chunkSize !== suite.CHUNK_SIZE) {
      throw new UnsupportedError("only a 1 MiB chunk size is defined for ALBPKG-1");
    }
    if (this.flags !== 0) {
      throw new UnsupportedError("no header flags are defined for ALBPKG-1");
    }

    const blob = Buffer.concat([
      suite.PACKAGE_MAGIC,
      u16(suite.FORMAT_VERSION),
      u16(suite.SUITE_ID),
      u32(suite.HEADER_LEN),
      u32(this.flags),
      u32(this.chunkSize),
      this.senderFpr,
      this.recipientFpr,
      this.packageId,
      u16(suite.KEM_CT_LEN),
      this.kemCt,
    ]);
    if (blob.length !== suite.HEADER_LEN) {
      throw new FormatError("internal: header serialization length mismatch");
    }
    return blob;
  }

  get digest(): Buffer {
    return createHash("sha256").update(this.serialize()).digest();
  }

  static parse(blob: Buffer): Header {
    if (blob.length !== suite.HEADER_LEN) {
      throw new FormatError(
        `header must be exactly ${suite.HEADER_LEN} bytes, got ${blob.length}`,
      );
    }
    const r = new ByteReader(blob, "package header");
    r.expect(suite.PACKAGE_MAGIC, "package magic");

    const version = r.u16("format version");
    if (version !== suite.FORMAT_VERSION) {
      throw new UnsupportedError(`unsupported format version ${version}`);
    }
    const suiteId = r.u16("suite id");
    if (suiteId !== suite.SUITE_ID) {
      throw new UnsupportedError(
        `unsupported suite id 0x${suiteId.toString(16).padStart(4, "0")}`,
      );
    }

    const headerLen = r.u32("header length");
    if (headerLen !== suite.HEADER_LEN) {
      throw new FormatError("noncanonical header length");
    }

    const flags = r.u32("flags");
    if (flags !== 0) {
      throw new UnsupportedError(
        `unknown header flag bits set: 0x${flags.toString(16).padStart(8, "0")}`,
      );
    }

    const chunkSize = r.u32("chunk size");
    if (chunkSize !== suite.CHUNK_SIZE) {
      throw new UnsupportedError(`unsupported chunk size ${chunkSize}`);
    }

    const senderFpr = Buffer.from(r.take(suite.FPR_LEN, "sender fingerprint"));
    const recipientFpr = Buffer.from(r.take(suite.FPR_LEN, "recipient fingerprint"));
    const packageId = Buffer.from(r.take(suite.PACKAGE_ID_LEN, "package identifier"));

    const kemCtLen = r.u16("encapsulation length");
    if (kemCtLen !== suite.KEM_CT_LEN) {
      throw new FormatError("noncanonical encapsulation length");
    }
    const kemCt = Buffer.from(r.take(kemCtLen, "encapsulation"));
    r.finish();

    return new Header({
      senderFpr,
      recipientFpr,
      packageId,
      kemCt,
      chunkSize,
      flags,
    });
  }
}

// ---- Key derivation ------------------------------------------------------

function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length = suite.AEAD_KEY_LEN): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

export function deriveMaster(sharedSecret: Buffer, headerDigest: Buffer): Buffer {
  if (sharedSecret.length !== suite.KEM_SS_LEN) {
    throw new FormatError("shared secret has the wrong length");
  }
  if (headerDigest.length !== 32) {
    throw new FormatError("header digest has the wrong length");
  }
  return hkdf(sharedSecret, headerDigest, suite.INFO_MASTER);
}

export function deriveChunkKey(
  master: Buffer,
  headerDigest: Buffer,
  index: number,
): Buffer {
  requireIndex(index, "chunk index");
  if (index >= suite.MAX_CHUNKS) {
    throw new LimitError(`chunk index ${index} out of range`);
  }
  return hkdf(
    master,
    headerDigest,
    Buffer.concat([suite.INFO_CHUNK, u64(index)]),
  );
}

export function deriveCompletionKey(master: Buffer, headerDigest: Buffer): Buffer {
  return hkdf(master, headerDigest, suite.INFO_COMPLETE);
}

export function chunkAad(
  headerDigest: Buffer,
  index: number,
  ptLen: number,
  final: boolean,
): Buffer {
  return Buffer.concat([
    suite.AAD_CHUNK_PREFIX,
    headerDigest,
    u64(index),
    u32(ptLen),
    u8(final ? 1 : 0),
  ]);
}

export function completionAad(
  headerDigest: Buffer,
  totalBytes: number,
  chunkCount: number,
): Buffer {
  return Buffer.concat([
    suite.AAD_COMPLETE_PREFIX,
    headerDigest,
    u64(totalBytes),
    u64(chunkCount),
  ]);
}

export function signatureMessage(bodySha512: Buffer): Buffer {
  if (bodySha512.length !== 64) {
    throw new FormatError("body digest must be SHA-512");
  }
  return Buffer.concat([suite.SIG_CONTEXT, bodySha512]);
}

// ---- AEAD helpers --------------------------------------------------------

function aeadSeal(key: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv(suite.AEAD_ALGORITHM, key, suite.AEAD_NONCE, {
    authTagLength: suite.AEAD_TAG_LEN,
  });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

function aeadOpen(
  key: Buffer,
  aad: Buffer,
  ciphertextWithTag: Buffer,
  what: string,
): Buffer {
  if (ciphertextWithTag.length < suite.AEAD_TAG_LEN) {
    throw new FormatError(`${what} is shorter than an authentication tag`);
  }
  const split = ciphertextWithTag.length - suite.AEAD_TAG_LEN;
  const body = ciphertextWithTag.subarray(0, split);
  const tag = ciphertextWithTag.subarray(split);

  const decipher = createDecipheriv(suite.AEAD_ALGORITHM, key, suite.AEAD_NONCE, {
    authTagLength: suite.AEAD_TAG_LEN,
  });
  decipher.setAAD(aad, { plaintextLength: body.length });
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(body), decipher.final()]);
  } catch (cause) {
    throw new AuthError(`authentication failed on ${what}`, { cause });
  }
}

// ---- Results -------------------------------------------------------------

export interface SealResult {
  packagePath: string;
  packageId: Buffer;
  totalBytes: number;
  chunkCount: number;
  recipientFingerprint: string;
}

export interface OpenResult {
  outputPath: string;
  packageId: Buffer;
  totalBytes: number;
  chunkCount: number;
  senderName: string;
  senderFingerprint: string;
}

/** Writes through to a file descriptor while hashing every byte. */
class HashingWriter {
  readonly #fd: number;
  readonly #hash = createHash("sha512");
  #written = 0;

  constructor(fd: number) {
    this.#fd = fd;
  }

  write(data: Buffer): void {
    let offset = 0;
    while (offset < data.length) {
      offset += writeSync(this.#fd, data, offset, data.length - offset);
    }
    this.#hash.update(data);
    this.#written = checkedAdd(
      this.#written,
      data.length,
      Number.MAX_SAFE_INTEGER,
      "serialized package length",
    );
  }

  digest(): Buffer {
    return this.#hash.digest();
  }

  get written(): number {
    return this.#written;
  }
}

// ---- Sealing -------------------------------------------------------------

export interface SealOptions {
  sender: Identity;
  recipient: Contact | PublicIdentity;
  inputPath: string;
  outputPath: string;
  overwrite?: boolean;
  progress?: ProgressHook;
}

/**
 * Encrypt and sign `inputPath` into an ALBPKG/1 package.
 *
 * The recipient must be a `verified` contact.  A bare `PublicIdentity` is
 * accepted only for tests; the CLI always passes a `Contact`.
 */
export function sealFile(options: SealOptions): SealResult {
  suite.checkProvider();

  let recipientPublic: PublicIdentity;
  if (options.recipient instanceof Contact) {
    options.recipient.requireUsable();
    recipientPublic = options.recipient.public;
  } else {
    throw new TrustError("a verified Contact is required; bare public keys are not trusted");
  }

  const inputPath = options.inputPath;
  const outputPath = options.outputPath;

  const info = statSync(inputPath, { throwIfNoEntry: false });
  if (info === undefined || !info.isFile()) {
    throw new IoError(`input is not a regular file: ${inputPath}`);
  }
  if (info.size > suite.MAX_PLAINTEXT) {
    throw new LimitError(
      `input is ${info.size} bytes; the maximum is ${suite.MAX_PLAINTEXT} bytes (1 TiB)`,
    );
  }

  const encapsulated = encapsulate(recipientPublic.kemKey());
  const sharedSecret = Buffer.from(encapsulated.sharedKey);
  const kemCt = Buffer.from(encapsulated.ciphertext);

  let master: Buffer | undefined;
  try {
    const header = new Header({
      senderFpr: options.sender.fingerprint,
      recipientFpr: recipientPublic.fingerprint,
      packageId: randomBytes(suite.PACKAGE_ID_LEN),
      kemCt,
    });
    const headerBytes = header.serialize();
    const headerDigest = createHash("sha256").update(headerBytes).digest();
    master = deriveMaster(sharedSecret, headerDigest);

    let totalBytes = 0;
    let chunkCount = 0;

    const srcFd = openSync(inputPath, "r");
    try {
      const result = withAtomicOutput(
        outputPath,
        { overwrite: options.overwrite ?? false },
        ({ fd }) => {
          const out = new HashingWriter(fd);
          out.write(headerBytes);

          // One-chunk look-ahead so the final marker is known before the chunk
          // it belongs to is emitted, without seeking the input.
          let readOffset = 0;
          let pending = readAtMostAt(srcFd, suite.CHUNK_SIZE, readOffset);
          readOffset += pending.length;

          for (;;) {
            const lookahead = readAtMostAt(srcFd, suite.CHUNK_SIZE, readOffset);
            readOffset += lookahead.length;
            const final = lookahead.length === 0;
            if (pending.length !== suite.CHUNK_SIZE && !final) {
              throw new IoError("short read from input before end of file");
            }

            emitChunk(out, master!, headerDigest, chunkCount, pending, final);
            totalBytes = checkedAdd(
              totalBytes,
              pending.length,
              suite.MAX_PLAINTEXT,
              "plaintext",
            );
            chunkCount = checkedAdd(chunkCount, 1, suite.MAX_CHUNKS, "chunk count");
            options.progress?.(totalBytes, chunkCount);
            if (final) break;
            pending = lookahead;
          }

          // Completion record.
          const doneKey = deriveCompletionKey(master!, headerDigest);
          let completionCt: Buffer;
          try {
            completionCt = aeadSeal(
              doneKey,
              completionAad(headerDigest, totalBytes, chunkCount),
              Buffer.concat([u64(totalBytes), u64(chunkCount)]),
            );
          } finally {
            wipe(doneKey);
          }
          out.write(completionCt);

          // Signature over every byte emitted so far.
          const signature = signWith(
            null,
            signatureMessage(out.digest()),
            options.sender.sigPrivate,
          );
          if (signature.length !== suite.SIG_LEN) {
            throw new FormatError("unexpected ML-DSA-65 signature length");
          }
          writeSync(fd, signature);
          writeSync(fd, u32(signature.length));
          writeSync(fd, suite.SIG_TRAILER_MAGIC);

          return {
            packagePath: outputPath,
            packageId: header.packageId,
            totalBytes,
            chunkCount,
            recipientFingerprint: formatFingerprint(recipientPublic.fingerprint),
          } satisfies SealResult;
        },
      );
      return result;
    } finally {
      closeSync(srcFd);
    }
  } finally {
    wipe(sharedSecret);
    if (master !== undefined) wipe(master);
  }
}

function emitChunk(
  out: HashingWriter,
  master: Buffer,
  headerDigest: Buffer,
  index: number,
  plaintext: Buffer,
  final: boolean,
): void {
  const key = deriveChunkKey(master, headerDigest, index);
  let ct: Buffer;
  try {
    ct = aeadSeal(key, chunkAad(headerDigest, index, plaintext.length, final), plaintext);
  } finally {
    wipe(key);
  }
  out.write(u8(final ? 1 : 0));
  out.write(u32(plaintext.length));
  out.write(ct);
}

// ---- Opening -------------------------------------------------------------

export const MIN_PACKAGE_SIZE =
  suite.HEADER_LEN +
  suite.CHUNK_FRAME_OVERHEAD +
  suite.COMPLETION_LEN +
  suite.SIG_LEN +
  suite.SIG_TRAILER_LEN;

export interface OpenOptions {
  recipient: Identity;
  contacts: ContactStore;
  packagePath: string;
  outputPath: string;
  overwrite?: boolean;
  progress?: ProgressHook;
}

/**
 * Verify and decrypt an ALBPKG/1 package.
 *
 * The signature is verified against the trusted sender before any plaintext is
 * produced, and the result is published only after the final completion record
 * has verified.
 */
export function openFile(options: OpenOptions): OpenResult {
  suite.checkProvider();

  const info = statSync(options.packagePath, { throwIfNoEntry: false });
  if (info === undefined || !info.isFile()) {
    throw new IoError(`package is not a regular file: ${options.packagePath}`);
  }

  const fd = openSync(options.packagePath, "r");
  try {
    return withPrivateSpool(path.dirname(options.outputPath), ({fd: spool, tempPath}) => {
      let size=0;
      const block=Buffer.alloc(suite.CHUNK_SIZE);
      for (;;) {
        const n=readSync(fd,block,0,block.length,null);
        if (!n) break;
        size+=n;
        if (size>suite.MAX_PACKAGE_SIZE) throw new LimitError("package exceeds size limit");
        let pos=0;
        while(pos<n) {
          const written=writeSync(spool,block,pos,n-pos);
          if (!written) throw new IoError("short spool write");
          pos+=written;
        }
      }
      const snapshot=openSync(tempPath,"r");
      try { return openFromDescriptor({fd:snapshot, size, recipient:options.recipient,
          contacts:options.contacts,outputPath:options.outputPath,
          overwrite:options.overwrite??false,progress:options.progress}); }
      finally { closeSync(snapshot); }
    });
  } finally {
    closeSync(fd);
  }
}

export interface OpenBufferOptions {
  recipient: Identity;
  contacts: ContactStore;
  data: Buffer;
  outputPath: string;
  overwrite?: boolean;
  progress?: ProgressHook;
}

/**
 * Open a package held in memory or arriving from a non-seekable source.
 *
 * The bytes are spooled, bounded by the maximum package size, into a private
 * temporary file first, because the signature at the tail must be verified
 * before any decryption begins.
 */
export function openBuffer(options: OpenBufferOptions): OpenResult {
  suite.checkProvider();
  if (options.data.length > suite.MAX_PACKAGE_SIZE) {
    throw new LimitError(
      `package is larger than the format permits (${options.data.length} bytes)`,
    );
  }

  return withPrivateSpool(path.dirname(options.outputPath), ({ fd, tempPath }) => {
    let offset = 0;
    while (offset < options.data.length) {
      offset += writeSync(
        fd,
        options.data,
        offset,
        options.data.length - offset,
      );
    }
    const readFd = openSync(tempPath, "r");
    try {
      return openFromDescriptor({
        fd: readFd,
        size: options.data.length,
        recipient: options.recipient,
        contacts: options.contacts,
        outputPath: options.outputPath,
        overwrite: options.overwrite ?? false,
        progress: options.progress,
      });
    } finally {
      closeSync(readFd);
    }
  });
}

interface DescriptorOptions {
  fd: number;
  size: number;
  recipient: Identity;
  contacts: ContactStore;
  outputPath: string;
  overwrite: boolean;
  progress?: ProgressHook;
}

function openFromDescriptor(options: DescriptorOptions): OpenResult {
  const { fd, size } = options;

  if (size < MIN_PACKAGE_SIZE) {
    throw new FormatError(`package is too small to be valid (${size} bytes)`);
  }
  if (size > suite.MAX_PACKAGE_SIZE) {
    throw new LimitError(`package is larger than the format permits (${size} bytes)`);
  }

  // -- 1. header --
  const headerBytes = readExactAt(fd, suite.HEADER_LEN, 0, "package header");
  const header = Header.parse(headerBytes);
  const headerDigest = createHash("sha256").update(headerBytes).digest();

  // -- 2. trust --
  if (!fingerprintsEqual(header.recipientFpr, options.recipient.fingerprint)) {
    throw new TrustError(
      "this package is addressed to a different recipient " +
        `(${formatFingerprint(header.recipientFpr)})`,
    );
  }
  const sender = options.contacts.require(header.senderFpr);
  sender.requireUsable();

  // -- 3. signature, before any decryption --
  const trailerOffset = size - suite.SIG_TRAILER_LEN;
  const trailer = readExactAt(
    fd,
    suite.SIG_TRAILER_LEN,
    trailerOffset,
    "signature trailer",
  );
  const sigLen = trailer.readUInt32BE(0);
  if (!trailer.subarray(4).equals(suite.SIG_TRAILER_MAGIC)) {
    throw new FormatError(
      "missing signature trailer; the package is truncated or padded",
    );
  }
  if (sigLen !== suite.SIG_LEN) {
    throw new FormatError(`noncanonical signature length ${sigLen}`);
  }

  const bodyLen = size - suite.SIG_TRAILER_LEN - sigLen;
  if (bodyLen < suite.HEADER_LEN) {
    throw new FormatError("signature block overlaps the package body");
  }

  const signature = readExactAt(fd, sigLen, bodyLen, "signature");

  const bodyHash = createHash("sha512");
  let remaining = bodyLen;
  let cursor = 0;
  while (remaining > 0) {
    const block = readAtMostAt(fd, Math.min(1 << 20, remaining), cursor);
    if (block.length === 0) {
      throw new FormatError("package body is shorter than its framing declares");
    }
    bodyHash.update(block);
    remaining -= block.length;
    cursor += block.length;
  }

  if (
    !verifyWith(
      null,
      signatureMessage(bodyHash.digest()),
      sender.public.sigKey(),
      signature,
    )
  ) {
    throw new AuthError(
      `signature does not verify against contact '${sender.name}'`,
    );
  }

  // -- 4. decrypt --
  let sharedSecret: Buffer;
  try {
    sharedSecret = Buffer.from(
      decapsulate(options.recipient.kemPrivate, header.kemCt),
    );
  } catch (cause) {
    throw new AuthError("ML-KEM decapsulation failed for this encapsulation", {
      cause,
    });
  }

  let master: Buffer | undefined;
  try {
    master = deriveMaster(sharedSecret, headerDigest);

    let offset = suite.HEADER_LEN;
    const bodyEnd = bodyLen - suite.COMPLETION_LEN;
    if (bodyEnd < offset) {
      throw new FormatError("package has no room for a completion record");
    }

    let totalBytes = 0;
    let chunkCount = 0;
    let sawFinal = false;

    return withAtomicOutput(
      options.outputPath,
      { overwrite: options.overwrite },
      ({ fd: destFd }) => {
        while (offset < bodyEnd) {
          if (chunkCount >= suite.MAX_CHUNKS) {
            throw new LimitError("package exceeds the maximum chunk count");
          }
          if (sawFinal) {
            throw new FormatError("chunk records continue past the final chunk");
          }

          const frame = readExactAt(fd, 5, offset, "chunk framing");
          const finalFlag = frame[0]!;
          if (finalFlag !== 0 && finalFlag !== 1) {
            throw new FormatError(`noncanonical final marker ${finalFlag}`);
          }
          const ptLen = frame.readUInt32BE(1);

          if (ptLen > header.chunkSize) {
            throw new LimitError(
              `chunk ${chunkCount} declares ${ptLen} bytes, over the ` +
                `${header.chunkSize}-byte chunk size`,
            );
          }
          const final = finalFlag === 1;
          if (!final && ptLen !== header.chunkSize) {
            throw new FormatError(
              `chunk ${chunkCount} is short but is not marked final`,
            );
          }
          if (ptLen === 0 && !(final && chunkCount === 0)) {
            throw new FormatError("only a lone final chunk may be empty");
          }

          const ctLen = checkedAdd(
            ptLen,
            suite.AEAD_TAG_LEN,
            Number.MAX_SAFE_INTEGER,
            "chunk record",
          );
          const next = checkedAdd(
            offset,
            5 + ctLen,
            Number.MAX_SAFE_INTEGER,
            "package offset",
          );
          if (next > bodyEnd) {
            throw new FormatError(
              `chunk ${chunkCount} runs past the completion record`,
            );
          }

          const ct = readExactAt(fd, ctLen, offset + 5, `chunk ${chunkCount}`);
          const key = deriveChunkKey(master!, headerDigest, chunkCount);
          let plaintext: Buffer;
          try {
            plaintext = aeadOpen(
              key,
              chunkAad(headerDigest, chunkCount, ptLen, final),
              ct,
              `chunk ${chunkCount}`,
            );
          } finally {
            wipe(key);
          }

          if (plaintext.length !== ptLen) {
            throw new FormatError(`chunk ${chunkCount} plaintext length mismatch`);
          }

          let written = 0;
          while (written < plaintext.length) {
            written += writeSync(
              destFd,
              plaintext,
              written,
              plaintext.length - written,
            );
          }

          totalBytes = checkedAdd(totalBytes, ptLen, suite.MAX_PLAINTEXT, "plaintext");
          chunkCount += 1;
          sawFinal = final;
          offset = next;
          options.progress?.(totalBytes, chunkCount);
        }

        if (!sawFinal) {
          throw new FormatError("package has no final chunk; it is truncated");
        }
        if (offset !== bodyEnd) {
          throw new FormatError(
            "chunk records do not end at the completion record",
          );
        }

        // -- 5. completion --
        const completionCt = readExactAt(
          fd,
          suite.COMPLETION_LEN,
          bodyEnd,
          "completion record",
        );
        const doneKey = deriveCompletionKey(master!, headerDigest);
        let completionPt: Buffer;
        try {
          completionPt = aeadOpen(
            doneKey,
            completionAad(headerDigest, totalBytes, chunkCount),
            completionCt,
            "the completion record",
          );
        } catch (cause) {
          throw new AuthError(
            "completion record does not match the decrypted contents; " +
              "the package is truncated or altered",
            { cause },
          );
        } finally {
          wipe(doneKey);
        }

        if (!completionPt.equals(Buffer.concat([u64(totalBytes), u64(chunkCount)]))) {
          throw new AuthError(
            "completion record contents disagree with the package",
          );
        }

        return {
          outputPath: options.outputPath,
          packageId: header.packageId,
          totalBytes,
          chunkCount,
          senderName: sender.name,
          senderFingerprint: formatFingerprint(sender.fingerprint),
        } satisfies OpenResult;
      },
    );
  } finally {
    wipe(sharedSecret);
    if (master !== undefined) wipe(master);
  }
}
