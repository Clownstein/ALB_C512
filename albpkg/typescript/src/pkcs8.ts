/** Strict PBES2 encrypted-PKCS#8 profile shared by ALBPKG ports. */
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { FormatError, LimitError, PassphraseError } from "./errors.ts";
import { wipe } from "./fsutil.ts";

export const DEFAULT_ITERATIONS = 600_000;
export const MIN_ITERATIONS = 600_000;
export const MAX_ITERATIONS = 10_000_000;
const MAX_DER = 4096;
const OID_PBES2 = Buffer.from("2a864886f70d01050d", "hex");
const OID_PBKDF2 = Buffer.from("2a864886f70d01050c", "hex");
const OID_HMAC_SHA256 = Buffer.from("2a864886f70d0209", "hex");
const OID_AES256_CBC = Buffer.from("60864801650304012a", "hex");

function derLength(value: number): Buffer {
  if (value < 0x80) return Buffer.from([value]);
  const bytes: number[] = [];
  for (let n = value; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(value.length), value]);
}
function seq(...values: Buffer[]): Buffer { return tlv(0x30, Buffer.concat(values)); }
function oid(value: Buffer): Buffer { return tlv(0x06, value); }
function octets(value: Buffer): Buffer { return tlv(0x04, value); }
function integer(value: number): Buffer {
  const bytes: number[] = [];
  for (let n = value; n > 0; n = Math.floor(n / 256)) bytes.unshift(n & 0xff);
  if (bytes.length === 0) bytes.push(0);
  if ((bytes[0]! & 0x80) !== 0) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
}

class DerReader {
  offset = 0;
  readonly data: Buffer;
  readonly label: string;
  constructor(data: Buffer, label = "PKCS#8") {
    this.data = data;
    this.label = label;
  }
  take(tag: number, field: string): Buffer {
    if (this.offset >= this.data.length || this.data[this.offset++] !== tag) {
      throw new FormatError(`noncanonical ${this.label}: expected ${field}`);
    }
    if (this.offset >= this.data.length) throw new FormatError(`truncated ${this.label} length`);
    const first = this.data[this.offset++]!;
    let size: number;
    if (first < 0x80) size = first;
    else {
      const count = first & 0x7f;
      if (count === 0 || count > 4 || this.offset + count > this.data.length) {
        throw new FormatError(`invalid ${this.label} length`);
      }
      if (this.data[this.offset] === 0 || (count === 1 && this.data[this.offset]! < 0x80)) {
        throw new FormatError(`noncanonical ${this.label} length`);
      }
      size = 0;
      for (let i = 0; i < count; i++) size = size * 256 + this.data[this.offset++]!;
    }
    if (!Number.isSafeInteger(size) || this.offset + size > this.data.length) {
      throw new FormatError(`truncated ${field}`);
    }
    const value = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }
  sequence(field: string): DerReader { return new DerReader(this.take(0x30, field), field); }
  oid(expected: Buffer, field: string): void {
    if (!this.take(0x06, field).equals(expected)) throw new FormatError(`unsupported ${field}`);
  }
  integer(field: string): number {
    const raw = this.take(0x02, field);
    if (raw.length === 0 || (raw[0]! & 0x80) || (raw.length > 1 && raw[0] === 0 && raw[1]! < 0x80)) {
      throw new FormatError(`noncanonical ${field}`);
    }
    let value = 0;
    for (const byte of raw) value = value * 256 + byte;
    if (!Number.isSafeInteger(value)) throw new LimitError(`${field} exceeds the numeric limit`);
    return value;
  }
  finish(): void {
    if (this.offset !== this.data.length) throw new FormatError(`trailing bytes in ${this.label}`);
  }
}

export function encryptPrivateKeyInfo(
  plain: Buffer,
  passphrase: Buffer,
  iterations = DEFAULT_ITERATIONS,
): Buffer {
  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new LimitError(`iteration count must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}`);
  }
  if (plain.length === 0 || plain.length > MAX_DER) throw new LimitError("private key information has an invalid size");
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const key = pbkdf2Sync(passphrase, salt, iterations, 32, "sha256");
  let ciphertext: Buffer;
  try {
    const cipher = createCipheriv("aes-256-cbc", key, iv);
    ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  } finally { wipe(key); }
  const prf = seq(oid(OID_HMAC_SHA256), tlv(0x05, Buffer.alloc(0)));
  const kdf = seq(oid(OID_PBKDF2), seq(octets(salt), integer(iterations), prf));
  const encryption = seq(oid(OID_AES256_CBC), octets(iv));
  return seq(seq(oid(OID_PBES2), seq(kdf, encryption)), octets(ciphertext));
}

export function decryptPrivateKeyInfo(blob: Buffer, passphrase: Buffer): Buffer {
  if (blob.length === 0 || blob.length > MAX_DER) throw new LimitError("encrypted PKCS#8 object has an invalid size");
  const root = new DerReader(blob);
  const outer = root.sequence("EncryptedPrivateKeyInfo");
  const algorithm = outer.sequence("encryption algorithm");
  algorithm.oid(OID_PBES2, "encryption algorithm OID");
  const params = algorithm.sequence("PBES2 parameters");
  const kdf = params.sequence("key derivation function");
  kdf.oid(OID_PBKDF2, "key derivation OID");
  const kdfParams = kdf.sequence("PBKDF2 parameters");
  const salt = kdfParams.take(0x04, "PBKDF2 salt");
  if (salt.length !== 16) throw new FormatError("PBKDF2 salt must be 16 bytes");
  const iterations = kdfParams.integer("PBKDF2 iteration count");
  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new LimitError(`iteration count ${iterations} is outside the permitted range [${MIN_ITERATIONS}, ${MAX_ITERATIONS}]`);
  }
  const prf = kdfParams.sequence("PBKDF2 PRF");
  prf.oid(OID_HMAC_SHA256, "PBKDF2 PRF OID");
  if (prf.take(0x05, "PBKDF2 PRF NULL parameters").length !== 0) throw new FormatError("PBKDF2 PRF parameters must be NULL");
  prf.finish(); kdfParams.finish(); kdf.finish();
  const encryption = params.sequence("encryption scheme");
  encryption.oid(OID_AES256_CBC, "encryption scheme OID");
  const iv = encryption.take(0x04, "AES-CBC IV");
  if (iv.length !== 16) throw new FormatError("AES-CBC IV must be 16 bytes");
  encryption.finish(); params.finish(); algorithm.finish();
  const ciphertext = outer.take(0x04, "encrypted private key");
  outer.finish(); root.finish();
  if (ciphertext.length === 0 || ciphertext.length > MAX_DER || ciphertext.length % 16 !== 0) {
    throw new FormatError("encrypted private key has a noncanonical length");
  }
  const key = pbkdf2Sync(passphrase, salt, iterations, 32, "sha256");
  try {
    const decipher = createDecipheriv("aes-256-cbc", key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (cause) {
    throw new PassphraseError("could not decrypt the private key; the passphrase is wrong or the key has been altered", { cause });
  } finally { wipe(key); }
}
