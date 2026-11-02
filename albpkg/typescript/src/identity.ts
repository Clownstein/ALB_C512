/**
 * Identities: key generation, canonical public encoding, fingerprints, storage.
 *
 * FORMAT.md section 2.  The encryption key (ML-KEM-768) and the signing key
 * (ML-DSA-65) are generated independently and neither is derived from the
 * other.  The fingerprint covers both.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { openSync, closeSync, readSync, writeSync, chmodSync } from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import { Writable } from "node:stream";

import * as suite from "./suite.ts";
import {
  AuthError,
  FormatError,
  IoError,
  LimitError,
  PassphraseError,
  UnsupportedError,
} from "./errors.ts";
import {
  permissionsAreOwnerOnly,
  restrictPermissions,
  withAtomicOutput,
  wipe,
} from "./fsutil.ts";
import { ByteReader, u16, u32 } from "./wire.ts";
import {
  DEFAULT_ITERATIONS,
  decryptPrivateKeyInfo,
  encryptPrivateKeyInfo,
} from "./pkcs8.ts";

export type PassphraseProvider = (prompt: string) => string | Promise<string>;

const PEM_BEGIN = "-----BEGIN ALBPKG PUBLIC IDENTITY-----";
const PEM_END = "-----END ALBPKG PUBLIC IDENTITY-----";

export const MIN_PASSPHRASE_LEN = 8;
/** Generous bound on the sealed seed blob; the real one is 108 bytes. */
const MAX_SEALED_LEN = 1 << 12;

// ---- Fingerprints --------------------------------------------------------

export function fingerprintOf(pubid: Buffer): Buffer {
  return createHash("sha256").update(pubid).digest();
}

/** 64 lowercase hex characters in eight dash-separated groups of eight. */
export function formatFingerprint(fpr: Buffer): string {
  if (fpr.length !== suite.FPR_LEN) {
    throw new FormatError("fingerprint must be 32 bytes");
  }
  const hex = fpr.toString("hex");
  const groups: string[] = [];
  for (let i = 0; i < 64; i += 8) groups.push(hex.slice(i, i + 8));
  return groups.join("-");
}

/** Accept grouped or ungrouped hex.  The full 256 bits are required. */
export function parseFingerprint(text: string): Buffer {
  const cleaned = text
    .trim()
    .toLowerCase()
    .replace(/[-\s:]/g, "");
  if (cleaned.length !== 64) {
    throw new FormatError(
      "a fingerprint is 64 hex characters; truncated fingerprints are not accepted",
    );
  }
  if (!/^[0-9a-f]{64}$/.test(cleaned)) {
    throw new FormatError("fingerprint is not valid hex");
  }
  return Buffer.from(cleaned, "hex");
}

/** Constant-time fingerprint comparison. */
export function fingerprintsEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// ---- Canonical public identity ------------------------------------------

export function encodePubid(kemPub: Buffer, sigPub: Buffer): Buffer {
  if (kemPub.length !== suite.KEM_PUB_LEN) {
    throw new FormatError("ML-KEM-768 public key has the wrong length");
  }
  if (sigPub.length !== suite.SIG_PUB_LEN) {
    throw new FormatError("ML-DSA-65 public key has the wrong length");
  }
  return Buffer.concat([
    suite.PUBID_MAGIC,
    u16(suite.SUITE_ID),
    u16(suite.KEM_PUB_LEN),
    kemPub,
    u16(suite.SIG_PUB_LEN),
    sigPub,
  ]);
}

export function decodePubid(data: Buffer): { kemPub: Buffer; sigPub: Buffer } {
  if (data.length !== suite.PUBID_LEN) {
    throw new FormatError(
      `public identity must be exactly ${suite.PUBID_LEN} bytes, got ${data.length}`,
    );
  }
  const reader = new ByteReader(data, "public identity");
  reader.expect(suite.PUBID_MAGIC, "public identity magic");
  const suiteId = reader.u16("suite id");
  if (suiteId !== suite.SUITE_ID) {
    throw new UnsupportedError(
      `unsupported suite id 0x${suiteId.toString(16).padStart(4, "0")}`,
    );
  }
  const kemLen = reader.u16("kem public key length");
  if (kemLen !== suite.KEM_PUB_LEN) {
    throw new FormatError("noncanonical ML-KEM public key length");
  }
  const kemPub = Buffer.from(reader.take(kemLen, "kem public key"));
  const sigLen = reader.u16("signature public key length");
  if (sigLen !== suite.SIG_PUB_LEN) {
    throw new FormatError("noncanonical ML-DSA public key length");
  }
  const sigPub = Buffer.from(reader.take(sigLen, "signature public key"));
  reader.finish();
  return { kemPub, sigPub };
}

// ---- Raw key <-> KeyObject bridging -------------------------------------
//
// Node exposes raw ML-KEM / ML-DSA public keys through the AKP JWK form.  The
// wire format carries raw keys, so every import re-derives the KeyObject from
// exactly the bytes on the wire -- never from anything cached alongside them.

function rawPublicToKeyObject(raw: Buffer, alg: string): KeyObject {
  return createPublicKey({
    key: { kty: "AKP", alg, pub: raw.toString("base64url") } as never,
    format: "jwk",
  });
}

function rawSeedToPrivateKey(seed: Buffer, pub: Buffer, alg: string): KeyObject {
  // Node requires the public half alongside the seed in the AKP JWK form.  We
  // pass the public key the file already carries, and the caller re-derives and
  // compares the fingerprint afterwards, so a mismatched pair cannot slip past.
  return createPrivateKey({
    key: {
      kty: "AKP",
      alg,
      priv: seed.toString("base64url"),
      pub: pub.toString("base64url"),
    } as never,
    format: "jwk",
  });
}

function keyObjectToRawSeed(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" }) as unknown as { priv?: string };
  if (!jwk.priv) {
    throw new FormatError("provider did not expose a raw private seed");
  }
  return Buffer.from(jwk.priv, "base64url");
}

function keyObjectToRawPublic(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" }) as unknown as { pub?: string };
  if (!jwk.pub) {
    throw new FormatError("provider did not expose a raw public key");
  }
  return Buffer.from(jwk.pub, "base64url");
}

// ---- Public identity -----------------------------------------------------

export class PublicIdentity {
  readonly kemPublicBytes: Buffer;
  readonly sigPublicBytes: Buffer;

  constructor(kemPublicBytes: Buffer, sigPublicBytes: Buffer) {
    this.kemPublicBytes = kemPublicBytes;
    this.sigPublicBytes = sigPublicBytes;
  }

  get pubid(): Buffer {
    return encodePubid(this.kemPublicBytes, this.sigPublicBytes);
  }

  get fingerprint(): Buffer {
    return fingerprintOf(this.pubid);
  }

  get fingerprintText(): string {
    return formatFingerprint(this.fingerprint);
  }

  kemKey(): KeyObject {
    return rawPublicToKeyObject(this.kemPublicBytes, "ML-KEM-768");
  }

  sigKey(): KeyObject {
    return rawPublicToKeyObject(this.sigPublicBytes, "ML-DSA-65");
  }

  static fromPubid(data: Buffer): PublicIdentity {
    const { kemPub, sigPub } = decodePubid(data);
    return new PublicIdentity(kemPub, sigPub);
  }

  toArmored(): string {
    const body = this.pubid.toString("base64");
    const lines: string[] = [];
    for (let i = 0; i < body.length; i += 64) lines.push(body.slice(i, i + 64));
    return (
      `${PEM_BEGIN}\n` +
      `suite: ${suite.SUITE_NAME}\n` +
      `fingerprint: ${this.fingerprint.toString("hex")}\n` +
      `${lines.join("\n")}\n` +
      `${PEM_END}\n`
    );
  }

  static fromArmored(text: string): PublicIdentity {
    const lines = text
      .replace(/\r\n/g, "\n")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (lines.length === 0 || lines[0] !== PEM_BEGIN || lines.at(-1) !== PEM_END) {
      throw new FormatError("not an ALBPKG public identity file");
    }

    let declared: string | undefined;
    const b64: string[] = [];
    for (const line of lines.slice(1, -1)) {
      const lowered = line.toLowerCase();
      if (lowered.startsWith("suite:")) {
        if (line.split(":", 2)[1]?.trim() !== suite.SUITE_NAME) {
          throw new UnsupportedError("unsupported suite in public identity file");
        }
      } else if (lowered.startsWith("fingerprint:")) {
        if (declared !== undefined) {
          throw new FormatError("duplicate fingerprint header");
        }
        declared = line.slice(line.indexOf(":") + 1).trim().toLowerCase();
      } else if (line.includes(":") && !looksLikeBase64(line)) {
        throw new FormatError("unknown header in public identity file");
      } else {
        b64.push(line);
      }
    }
    if (declared === undefined) {
      throw new FormatError("public identity file has no fingerprint header");
    }

    const joined = b64.join("");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(joined)) {
      throw new FormatError("public identity body is not valid base64");
    }
    const raw = Buffer.from(joined, "base64");
    // Buffer.from is lenient; require an exact round trip so a corrupted body
    // cannot be silently normalized away.
    if (raw.toString("base64").replace(/=+$/, "") !== joined.replace(/=+$/, "")) {
      throw new FormatError("public identity body is not valid base64");
    }

    const identity = PublicIdentity.fromPubid(raw);
    if (!fingerprintsEqual(identity.fingerprint, parseFingerprint(declared))) {
      throw new FormatError(
        "public identity fingerprint header does not match the encoded keys",
      );
    }
    return identity;
  }
}

function looksLikeBase64(line: string): boolean {
  return /^[A-Za-z0-9+/=]+$/.test(line);
}

// ---- Private identity ----------------------------------------------------

export class Identity {
  readonly kemPrivate: KeyObject;
  readonly sigPrivate: KeyObject;

  constructor(kemPrivate: KeyObject, sigPrivate: KeyObject) {
    this.kemPrivate = kemPrivate;
    this.sigPrivate = sigPrivate;
  }

  get public(): PublicIdentity {
    return new PublicIdentity(
      keyObjectToRawPublic(createPublicKey(this.kemPrivate)),
      keyObjectToRawPublic(createPublicKey(this.sigPrivate)),
    );
  }

  get fingerprint(): Buffer {
    return this.public.fingerprint;
  }
}

/** Generate a fresh, independent encryption key and signing key. */
export function generateIdentity(): Identity {
  suite.checkProvider();
  const kem = generateKeyPairSync(suite.KEM_ALGORITHM as never);
  const sig = generateKeyPairSync(suite.SIG_ALGORITHM as never);
  return new Identity(kem.privateKey, sig.privateKey);
}

/** No-echo terminal prompt.  Never a command-line argument, never logged. */
export async function promptPassphrase(
  prompt: string,
  options: { confirm?: boolean } = {},
): Promise<string> {
  const ask = (label: string): Promise<string> =>
    new Promise((resolve, reject) => {
      if (!process.stdin.isTTY) {
        reject(
          new PassphraseError("no interactive terminal available for a passphrase"),
        );
        return;
      }
      // Readline may echo input and redraw its line. Discard every such write;
      // erasing the terminal afterwards would still leak the original bytes.
      const silent = new Writable({ write(_chunk, _encoding, done) { done(); } });
      const rl = readline.createInterface({
        input: process.stdin,
        output: silent,
        terminal: true,
        historySize: 0,
      });
      let settled = false;
      const fail = (): void => {
        if (settled) return;
        settled = true;
        rl.close();
        silent.destroy();
        process.stderr.write("\n");
        reject(new PassphraseError("passphrase input cancelled or closed"));
      };
      rl.once("SIGINT", fail);
      rl.once("close", fail);
      rl.once("error", fail);
      process.stderr.write(label);
      rl.question("", (answer) => {
        settled = true;
        rl.close();
        silent.destroy();
        process.stderr.write("\n");
        resolve(answer);
      });
    });

  const value = await ask(`${prompt}: `);
  if (options.confirm) {
    const again = await ask(`${prompt} (confirm): `);
    if (again !== value) throw new PassphraseError("passphrases did not match");
  }
  return value;
}

async function resolvePassphrase(
  provider: PassphraseProvider | undefined,
  prompt: string,
  confirm: boolean,
): Promise<Buffer> {
  const text =
    provider === undefined
      ? await promptPassphrase(prompt, { confirm })
      : await provider(prompt);
  if (typeof text !== "string" || text.length === 0) {
    throw new PassphraseError("an empty passphrase is not accepted");
  }
  if (text.length < MIN_PASSPHRASE_LEN) {
    throw new PassphraseError(
      `passphrase must be at least ${MIN_PASSPHRASE_LEN} characters`,
    );
  }
  return Buffer.from(text, "utf8");
}

/** PBKDF2-HMAC-SHA-256 over the passphrase (FORMAT.md 2.4). */
function deriveKek(passphrase: Buffer, salt: Buffer, iterations: number): Buffer {
  return pbkdf2Sync(passphrase, salt, iterations, 32, "sha256");
}

function encodeSeeds(kemSeed: Buffer, sigSeed: Buffer): Buffer {
  return Buffer.concat([
    u16(kemSeed.length),
    kemSeed,
    u16(sigSeed.length),
    sigSeed,
  ]);
}

function decodeSeeds(blob: Buffer): { kemSeed: Buffer; sigSeed: Buffer } {
  const reader = new ByteReader(blob, "identity seeds");
  const kemLen = reader.u16("kem seed length");
  if (kemLen !== suite.KEM_SEED_LEN) {
    throw new FormatError("noncanonical ML-KEM seed length");
  }
  const kemSeed = Buffer.from(reader.take(kemLen, "kem seed"));
  const sigLen = reader.u16("signing seed length");
  if (sigLen !== suite.SIG_SEED_LEN) {
    throw new FormatError("noncanonical ML-DSA seed length");
  }
  const sigSeed = Buffer.from(reader.take(sigLen, "signing seed"));
  reader.finish();
  return { kemSeed, sigSeed };
}

/**
 * Write the passphrase-encrypted private identity with owner-only mode.
 *
 * A fresh salt is drawn on every write, which is what makes the fixed all-zero
 * GCM nonce safe: the key encryption key is never reused.
 */
async function saveLegacyIdentity(
  identity: Identity,
  target: string,
  options: {
    passphraseProvider?: PassphraseProvider;
    overwrite?: boolean;
    iterations?: number;
  } = {},
): Promise<void> {
  const iterations = options.iterations ?? suite.KDF_ITERATIONS;
  if (
    iterations < suite.KDF_MIN_ITERATIONS ||
    iterations > suite.KDF_MAX_ITERATIONS
  ) {
    throw new LimitError(
      `iteration count must be between ${suite.KDF_MIN_ITERATIONS} and ${suite.KDF_MAX_ITERATIONS}`,
    );
  }

  const secret = await resolvePassphrase(
    options.passphraseProvider,
    `Passphrase for ${path.basename(target)}`,
    true,
  );

  const pubid = identity.public.pubid;
  const salt = randomBytes(suite.KDF_SALT_LEN);
  const prefix = Buffer.concat([
    suite.SKFILE_MAGIC,
    u16(suite.SUITE_ID),
    u16(suite.KDF_PBKDF2_SHA256),
    u32(iterations),
    salt,
    u32(pubid.length),
    pubid,
  ]);

  const seeds = encodeSeeds(
    keyObjectToRawSeed(identity.kemPrivate),
    keyObjectToRawSeed(identity.sigPrivate),
  );
  const kek = deriveKek(secret, salt, iterations);
  let sealed: Buffer;
  try {
    const cipher = createCipheriv(suite.AEAD_ALGORITHM, kek, suite.AEAD_NONCE, {
      authTagLength: suite.AEAD_TAG_LEN,
    });
    cipher.setAAD(prefix, { plaintextLength: seeds.length });
    sealed = Buffer.concat([
      cipher.update(seeds),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
  } finally {
    wipe(kek);
    wipe(seeds);
  }

  const blob = Buffer.concat([prefix, u32(sealed.length), sealed]);
  withAtomicOutput(target, { overwrite: options.overwrite ?? false }, ({ fd }) => {
    writeSync(fd, blob);
  });
  restrictPermissions(target);
}

/** Load and decrypt a private identity file, validating it strictly. */
async function loadLegacyIdentity(
  source: string,
  options: { passphraseProvider?: PassphraseProvider } = {},
): Promise<Identity> {
  suite.checkProvider();

  let blob: Buffer;
  try {
    const fd = openSync(source, "r");
    try {
      const bounded = Buffer.alloc(65537);
      let used = 0;
      while (used < bounded.length) {
        const count = readSync(fd, bounded, used, bounded.length - used, null);
        if (!count) break;
        used += count;
      }
      blob = bounded.subarray(0, used);
    } finally { closeSync(fd); }
  } catch (cause) {
    throw new IoError(`cannot read identity file ${path.basename(source)}`, {
      cause,
    });
  }

  if (blob.length > 65536) throw new LimitError("identity file exceeds 64 KiB");
  if (!permissionsAreOwnerOnly(source)) {
    throw new IoError(
      `identity file ${path.basename(source)} is readable by others; ` +
        "fix its permissions before use",
    );
  }

  const reader = new ByteReader(blob, "identity file");
  reader.expect(suite.SKFILE_MAGIC, "identity file magic");

  const suiteId = reader.u16("suite id");
  if (suiteId !== suite.SUITE_ID) {
    throw new UnsupportedError(
      `unsupported suite id 0x${suiteId.toString(16).padStart(4, "0")}`,
    );
  }

  const kdfId = reader.u16("kdf id");
  if (kdfId !== suite.KDF_PBKDF2_SHA256) {
    throw new UnsupportedError(
      `unsupported key derivation function 0x${kdfId.toString(16).padStart(4, "0")}`,
    );
  }

  const iterations = reader.u32("iteration count");
  if (
    iterations < suite.KDF_MIN_ITERATIONS ||
    iterations > suite.KDF_MAX_ITERATIONS
  ) {
    throw new LimitError(
      `iteration count ${iterations} is outside the permitted range ` +
        `[${suite.KDF_MIN_ITERATIONS}, ${suite.KDF_MAX_ITERATIONS}]`,
    );
  }

  const salt = Buffer.from(reader.take(suite.KDF_SALT_LEN, "salt"));

  const pubidLen = reader.u32("public identity length");
  if (pubidLen !== suite.PUBID_LEN) {
    throw new FormatError("noncanonical public identity length in identity file");
  }
  const pubid = Buffer.from(reader.take(pubidLen, "public identity"));
  const storedPublic = PublicIdentity.fromPubid(pubid);

  const prefixLen = reader.offset;
  const sealedLen = reader.u32("sealed length");
  if (sealedLen === 0 || sealedLen > MAX_SEALED_LEN) {
    throw new LimitError(`implausible sealed seed length ${sealedLen}`);
  }
  const sealed = Buffer.from(reader.take(sealedLen, "sealed seeds"));
  reader.finish();

  const secret = await resolvePassphrase(
    options.passphraseProvider,
    `Passphrase for ${path.basename(source)}`,
    false,
  );

  const kek = deriveKek(secret, salt, iterations);
  let seeds: Buffer;
  try {
    const split = sealed.length - suite.AEAD_TAG_LEN;
    const decipher = createDecipheriv(
      suite.AEAD_ALGORITHM,
      kek,
      suite.AEAD_NONCE,
      { authTagLength: suite.AEAD_TAG_LEN },
    );
    decipher.setAAD(blob.subarray(0, prefixLen), { plaintextLength: split });
    decipher.setAuthTag(sealed.subarray(split));
    seeds = Buffer.concat([
      decipher.update(sealed.subarray(0, split)),
      decipher.final(),
    ]);
  } catch (cause) {
    // A wrong passphrase and a tampered file are indistinguishable here, which
    // is the correct behaviour: both mean "do not proceed".
    throw new PassphraseError(
      "could not decrypt the identity file; the passphrase is wrong or the " +
        "file has been altered",
      { cause },
    );
  } finally {
    wipe(kek);
  }

  let identity: Identity;
  try {
    const { kemSeed, sigSeed } = decodeSeeds(seeds);
    try {
      identity = new Identity(
        rawSeedToPrivateKey(kemSeed, storedPublic.kemPublicBytes, "ML-KEM-768"),
        rawSeedToPrivateKey(sigSeed, storedPublic.sigPublicBytes, "ML-DSA-65"),
      );
    } catch (cause) {
      throw new FormatError("identity file seeds are not valid keys", { cause });
    } finally {
      wipe(kemSeed);
      wipe(sigSeed);
    }
  } finally {
    wipe(seeds);
  }

  if (!fingerprintsEqual(identity.fingerprint, storedPublic.fingerprint)) {
    throw new AuthError(
      "identity file seeds do not reproduce its stored public identity",
    );
  }
  return identity;
}

const IDENTITY_PREAMBLE = Buffer.from("ALBPKG PRIVATE IDENTITY 1\n", "ascii");
const PKCS8_BEGIN = Buffer.from("-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "ascii");
const PKCS8_END = Buffer.from("-----END ENCRYPTED PRIVATE KEY-----\n", "ascii");

function pemPkcs8(der: Buffer): Buffer {
  const text = der.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < text.length; i += 64) lines.push(text.slice(i, i + 64));
  return Buffer.concat([PKCS8_BEGIN, Buffer.from(lines.join("\n") + "\n", "ascii"), PKCS8_END]);
}

function takePemPkcs8(blob: Buffer, initial: number): { der: Buffer; offset: number } {
  if (!blob.subarray(initial, initial + PKCS8_BEGIN.length).equals(PKCS8_BEGIN)) {
    throw new FormatError("identity file is missing an encrypted PKCS#8 object");
  }
  const bodyStart = initial + PKCS8_BEGIN.length;
  const end = blob.indexOf(PKCS8_END, bodyStart);
  if (end < 0) throw new FormatError("identity file has an unterminated encrypted PKCS#8 object");
  const encoded = blob.subarray(bodyStart, end);
  if (encoded.length === 0 || encoded[encoded.length - 1] !== 0x0a) {
    throw new FormatError("noncanonical encrypted PKCS#8 PEM");
  }
  const lines = encoded.subarray(0, -1).toString("ascii").split("\n");
  if (lines.some((line, i) => line.length === 0 || line.length > 64 || (i < lines.length - 1 && line.length !== 64))) {
    throw new FormatError("noncanonical encrypted PKCS#8 PEM wrapping");
  }
  if (lines.some((line) => !/^[A-Za-z0-9+/]*={0,2}$/.test(line))) {
    throw new FormatError("invalid encrypted PKCS#8 base64");
  }
  const der = Buffer.from(lines.join(""), "base64");
  const offset = end + PKCS8_END.length;
  if (!pemPkcs8(der).equals(blob.subarray(initial, offset))) {
    throw new FormatError("noncanonical encrypted PKCS#8 PEM encoding");
  }
  return { der, offset };
}

export function parseIdentityPem(blob: Buffer): { kem: Buffer; sig: Buffer } {
  if (!blob.subarray(0, IDENTITY_PREAMBLE.length).equals(IDENTITY_PREAMBLE)) {
    throw new FormatError("unsupported private identity format");
  }
  const kem = takePemPkcs8(blob, IDENTITY_PREAMBLE.length);
  const sig = takePemPkcs8(blob, kem.offset);
  if (sig.offset !== blob.length) throw new FormatError("trailing bytes in private identity file");
  return { kem: kem.der, sig: sig.der };
}

export async function saveIdentity(
  identity: Identity,
  target: string,
  options: {
    passphraseProvider?: PassphraseProvider;
    overwrite?: boolean;
    iterations?: number;
  } = {},
): Promise<void> {
  const secret = await resolvePassphrase(
    options.passphraseProvider,
    `Passphrase for ${path.basename(target)}`,
    true,
  );
  try {
    const kemPlain = Buffer.from(identity.kemPrivate.export({ format: "der", type: "pkcs8" }));
    const sigPlain = Buffer.from(identity.sigPrivate.export({ format: "der", type: "pkcs8" }));
    const iterations = options.iterations ?? DEFAULT_ITERATIONS;
    const blob = Buffer.concat([
      IDENTITY_PREAMBLE,
      pemPkcs8(encryptPrivateKeyInfo(kemPlain, secret, iterations)),
      pemPkcs8(encryptPrivateKeyInfo(sigPlain, secret, iterations)),
    ]);
    withAtomicOutput(target, { overwrite: options.overwrite ?? false }, ({ fd }) => {
      writeSync(fd, blob);
    });
    restrictPermissions(target);
  } finally { wipe(secret); }
}

export async function loadIdentity(
  source: string,
  options: { passphraseProvider?: PassphraseProvider } = {},
): Promise<Identity> {
  suite.checkProvider();
  let blob: Buffer;
  try {
    const fd = openSync(source, "r");
    try {
      const bounded = Buffer.alloc(65537);
      let used = 0;
      while (used < bounded.length) {
        const count = readSync(fd, bounded, used, bounded.length - used, null);
        if (!count) break;
        used += count;
      }
      blob = bounded.subarray(0, used);
    } finally { closeSync(fd); }
  } catch (cause) {
    throw new IoError(`cannot read identity file ${path.basename(source)}`, { cause });
  }
  if (blob.length > 65536) throw new LimitError("identity file exceeds 64 KiB");
  if (!permissionsAreOwnerOnly(source)) {
    throw new IoError(`identity file ${path.basename(source)} is readable by others; fix its permissions before use`);
  }
  const encrypted = parseIdentityPem(blob);
  const secret = await resolvePassphrase(
    options.passphraseProvider,
    `Passphrase for ${path.basename(source)}`,
    false,
  );
  let kemPlain: Buffer | undefined;
  let sigPlain: Buffer | undefined;
  try {
    kemPlain = decryptPrivateKeyInfo(encrypted.kem, secret);
    sigPlain = decryptPrivateKeyInfo(encrypted.sig, secret);
    let kem: KeyObject;
    let sig: KeyObject;
    try {
      kem = createPrivateKey({ key: kemPlain, format: "der", type: "pkcs8" });
      sig = createPrivateKey({ key: sigPlain, format: "der", type: "pkcs8" });
    } catch (cause) {
      throw new FormatError("decrypted PKCS#8 object is not a valid private key", { cause });
    }
    if (kem.asymmetricKeyType !== suite.KEM_ALGORITHM) {
      throw new FormatError("first PKCS#8 object is not an ML-KEM-768 private key");
    }
    if (sig.asymmetricKeyType !== suite.SIG_ALGORITHM) {
      throw new FormatError("second PKCS#8 object is not an ML-DSA-65 private key");
    }
    return new Identity(kem, sig);
  } finally {
    wipe(secret);
    if (kemPlain) wipe(kemPlain);
    if (sigPlain) wipe(sigPlain);
  }
}

export async function migrateLegacyIdentity(
  source: string,
  target: string,
  options: { passphraseProvider?: PassphraseProvider; overwrite?: boolean } = {},
): Promise<Identity> {
  if (path.resolve(source) === path.resolve(target)) {
    throw new IoError("legacy source and PKCS#8 destination must be different paths");
  }
  const identity = await loadLegacyIdentity(source, options);
  await saveIdentity(identity, target, options);
  return identity;
}

/** Write the armored public identity and return its fingerprint text. */
export function exportPublicIdentity(
  identity: Identity | PublicIdentity,
  target: string,
  options: { overwrite?: boolean } = {},
): string {
  const pub = identity instanceof Identity ? identity.public : identity;
  const armored = pub.toArmored();
  withAtomicOutput(target, { overwrite: options.overwrite ?? false }, ({ fd }) => {
    writeSync(fd, Buffer.from(armored, "utf8"));
  });
  if (process.platform !== "win32") {
    chmodSync(target, 0o644);
  }
  return pub.fingerprintText;
}
