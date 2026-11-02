/**
 * Canonical big-endian serialization with checked arithmetic.
 *
 * The reader is deliberately strict: every read is exact, every length is
 * bounds-checked before it is used to size anything, and finishing a structure
 * requires that no trailing bytes remain.
 *
 * JavaScript numbers are doubles, so "integer" is not a type guarantee here the
 * way it is in the other ports.  Every encoder below therefore rejects NaN,
 * Infinity, fractions, and negatives explicitly rather than letting them coerce
 * silently -- the class of defect recorded against the research TypeScript
 * implementation, where `outputLength` of `NaN`, `0.5`, and `1.5` all produced
 * zero or truncated output.  Values that can exceed 2^53 (byte counts on a
 * 1 TiB file are not among them, but chunk indices in a u64 field are) use
 * BigInt at the encoding boundary.
 */

import { FormatError, IoError, LimitError } from "./errors.ts";
import { UINT32_MAX } from "./suite.ts";

export const MAX_SAFE = Number.MAX_SAFE_INTEGER;

// ---- Numeric validation --------------------------------------------------

/** Reject anything that is not a non-negative safe integer. */
export function requireIndex(value: number, what: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new LimitError(
      `${what} must be a non-negative integer, got ${describeNumber(value)}`,
    );
  }
  return value;
}

function describeNumber(value: unknown): string {
  if (typeof value !== "number") return typeof value;
  if (Number.isNaN(value)) return "NaN";
  if (!Number.isFinite(value)) return String(value);
  if (!Number.isInteger(value)) return `a fraction (${value})`;
  return String(value);
}

// ---- Checked arithmetic --------------------------------------------------

export function checkedAdd(
  a: number,
  b: number,
  limit: number = MAX_SAFE,
  what = "length",
): number {
  requireIndex(a, what);
  requireIndex(b, what);
  const total = a + b;
  if (!Number.isSafeInteger(total) || total > limit) {
    throw new LimitError(`${what} overflow: ${a} + ${b} exceeds ${limit}`);
  }
  return total;
}

export function checkedMul(
  a: number,
  b: number,
  limit: number = MAX_SAFE,
  what = "length",
): number {
  requireIndex(a, what);
  requireIndex(b, what);
  const total = a * b;
  if (!Number.isSafeInteger(total) || total > limit) {
    throw new LimitError(`${what} overflow: ${a} * ${b} exceeds ${limit}`);
  }
  return total;
}

// ---- Encoding ------------------------------------------------------------

export function u8(value: number): Buffer {
  requireIndex(value, "u8");
  if (value > 0xff) throw new LimitError("u8 out of range");
  return Buffer.from([value]);
}

export function u16(value: number): Buffer {
  requireIndex(value, "u16");
  if (value > 0xffff) throw new LimitError("u16 out of range");
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value, 0);
  return out;
}

export function u32(value: number): Buffer {
  requireIndex(value, "u32");
  if (value > UINT32_MAX) throw new LimitError("u32 out of range");
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value, 0);
  return out;
}

/**
 * 64-bit big-endian.  Accepts a safe integer or a BigInt; anything above
 * 2^53 - 1 must be passed as a BigInt so no precision is lost on the way in.
 */
export function u64(value: number | bigint): Buffer {
  let big: bigint;
  if (typeof value === "bigint") {
    big = value;
  } else {
    requireIndex(value, "u64");
    big = BigInt(value);
  }
  if (big < 0n || big > 0xffffffffffffffffn) {
    throw new LimitError("u64 out of range");
  }
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(big, 0);
  return out;
}

// ---- Bounds-checked cursor ----------------------------------------------

/**
 * Cursor over an in-memory buffer.  Cursor-based rather than
 * slice-and-reassign: repeated re-slicing of a large buffer is quadratic,
 * which is the defect recorded against the research streaming API.
 */
export class ByteReader {
  #buf: Buffer;
  #pos = 0;
  #name: string;

  constructor(data: Buffer, name = "input") {
    this.#buf = data;
    this.#name = name;
  }

  get offset(): number {
    return this.#pos;
  }

  get remaining(): number {
    return this.#buf.length - this.#pos;
  }

  take(n: number, what: string): Buffer {
    requireIndex(n, `${what} length`);
    const end = checkedAdd(this.#pos, n, MAX_SAFE, `${what} offset`);
    if (end > this.#buf.length) {
      throw new FormatError(
        `truncated ${this.#name}: ${what} needs ${n} bytes, ${this.remaining} remain`,
      );
    }
    const out = this.#buf.subarray(this.#pos, end);
    this.#pos = end;
    return out;
  }

  u8(what: string): number {
    return this.take(1, what)[0]!;
  }

  u16(what: string): number {
    return this.take(2, what).readUInt16BE(0);
  }

  u32(what: string): number {
    return this.take(4, what).readUInt32BE(0);
  }

  u64(what: string): bigint {
    return this.take(8, what).readBigUInt64BE(0);
  }

  expect(literal: Buffer, what: string): void {
    const got = this.take(literal.length, what);
    if (!got.equals(literal)) {
      throw new FormatError(`bad ${what}`);
    }
  }

  finish(): void {
    if (this.remaining !== 0) {
      throw new FormatError(
        `trailing bytes in ${this.#name}: ${this.remaining} unconsumed`,
      );
    }
  }
}

// ---- Exact reads from a file descriptor ---------------------------------

import { readSync } from "node:fs";

/** Read exactly `n` bytes at `position`, or throw.  A short read is a format error. */
export function readExactAt(
  fd: number,
  n: number,
  position: number,
  what: string,
): Buffer {
  requireIndex(n, `${what} length`);
  requireIndex(position, `${what} offset`);
  if (n === 0) return Buffer.alloc(0);
  const buf = Buffer.alloc(n);
  let got = 0;
  while (got < n) {
    let read: number;
    try {
      read = readSync(fd, buf, got, n - got, position + got);
    } catch (cause) {
      throw new IoError(`read failed for ${what}`, { cause });
    }
    if (read === 0) {
      throw new FormatError(
        `truncated input: wanted ${n} bytes for ${what}, got ${got}`,
      );
    }
    got += read;
  }
  return buf;
}

/** Read up to `n` bytes at `position`, looping over short reads. */
export function readAtMostAt(
  fd: number,
  n: number,
  position: number,
): Buffer {
  const buf = Buffer.alloc(n);
  let got = 0;
  while (got < n) {
    const read = readSync(fd, buf, got, n - got, position + got);
    if (read === 0) break;
    got += read;
  }
  return got === n ? buf : buf.subarray(0, got);
}
