// Explicit research-only gate. Never imported by the package implementation.
let experimental = false;
export function enableExperimentalResearch(): void { experimental = true; }
function requireResearch(): void {
  if (!experimental) throw new Error("C512 is broken research cryptography; call enableExperimentalResearch() only for experiments");
}
/**
 * ALB_C512 (C512) v2.0 — TypeScript Implementation
 *
 * A sponge-based authenticated encryption algorithm with:
 *   - 512-bit key, 256-bit nonce, 256-bit tag
 *   - 1024-bit internal state (32 lanes x 32 bits)
 *   - Five-layer permutation: RoundConstant + Theta + Chi + NTT Butterfly + RoundKey
 *   - Dual-phase rounds: A=24 (init/finalize), B=12 (data blocks)
 *
 * v2.0 changes from v1.0:
 *   - Fixed AAD absorption rounds (was 24/Phase-A, now 12/Phase-B)
 *   - Updated domain constants: KS="C520", TAG="TAG2", separator=0x02
 *   - Updated IV version marker
 *   - Added SIV mode (misuse-resistant AEAD)
 *   - Added XOF mode (extendable output / KDF)
 *
 * Zero external dependencies. Works in Node.js and browser environments.
 */

// ── Constants ────────────────────────────────────────────────────────────────

const C512_KEY_SIZE = 64;       // bytes (512 bits)
const C512_NONCE_SIZE = 32;     // bytes (256 bits)
const C512_TAG_SIZE = 32;       // bytes (256 bits)
const C512_RATE_SIZE = 64;      // bytes (512 bits)
const C512_LANES = 32;
const C512_ROUNDS_A = 24;       // init / finalize
const C512_ROUNDS_B = 12;       // per data block
const C512_KDF_ROUNDS = 4;      // key schedule bootstrap

const MASK32 = 0xFFFFFFFF;

// v2.0 domain constants
const C512_DOMAIN_KS  = 0x43353230;   // "C520" — key schedule domain
const C512_DOMAIN_TAG = 0x54414732;   // "TAG2" — tag derivation domain
const C512_DOMAIN_SEP = 0x00000002;   // AAD-to-plaintext separator
const C512_DOMAIN_XOF = 0x584F4632;   // "XOF2" — XOF mode domain
const C512_DOMAIN_SQZ = 0x53515A32;   // "SQZ2" — XOF squeeze domain
const C512_DOMAIN_SIV = 0x53495632;   // "SIV2" — SIV nonce derivation domain

// v2.0 init vector: 0x80500C1800000002 as two LE uint32s
const C512_IV_LO = 0x00000002;  // low 32 bits of 0x80500C1800000002
const C512_IV_HI = 0x80500C18;  // high 32 bits

// Round constants (fractional bits of sqrt(2), sqrt(3), SHA-256 K[0..23])
// Each is a 64-bit value stored as [lo, hi] uint32 pair
const ROUND_CONSTANTS: ReadonlyArray<[number, number]> = [
  [0xF3BCC908, 0x6A09E667], [0x84CAA73B, 0xBB67AE85],
  [0xFE94F82B, 0x3C6EF372], [0x5F1D36F1, 0xA54FF53A],
  [0xADE682D1, 0x510E527F], [0x2B3E6C1F, 0x9B05688C],
  [0xFB41BD6B, 0x1F83D9AB], [0x137E2179, 0x5BE0CD19],
  [0xD728AE22, 0x428A2F98], [0x23EF65CD, 0x71374491],
  [0xEC4D3B2F, 0xB5C0FBCF], [0x8189DBBC, 0xE9B5DBA5],
  [0xF348B538, 0x3956C25B], [0xB605D019, 0x59F111F1],
  [0xAF194F9B, 0x923F82A4], [0xDA6D8118, 0xAB1C5ED5],
  [0xA3030242, 0xD807AA98], [0x45706FBE, 0x12835B01],
  [0x4EE4B28C, 0x243185BE], [0xD5FFB4E2, 0x550C7DC3],
  [0xF27B896F, 0x72BE5D74], [0x3B1696B1, 0x80DEB1FE],
  [0x25C71235, 0x9BDC06A7], [0xCF692694, 0xC19BF174],
];

// NTT butterfly twiddle factors
const OMEGA: ReadonlyArray<number> = [
  0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
  0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
  0x5BE0CD19, 0x428A2F98, 0x71374491, 0xB5C0FBCF,
  0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
];

// Per-lane rotation offsets
const ROTATION_OFFSETS: ReadonlyArray<number> = [
   0,  1,  3,  6, 10, 15, 21, 28,
   2,  5,  9, 14, 20, 27,  3, 12,
   4,  8, 13, 19, 26,  1,  7, 16,
  11, 18, 25, 31, 17, 24, 30, 22,
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function stateFromBytes(b: Uint8Array): Uint32Array {
  if (b.length !== 128) {
    throw new Error("C512: stateFromBytes requires exactly 128 bytes");
  }
  const state = new Uint32Array(32);
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  for (let i = 0; i < 32; i++) {
    state[i] = dv.getUint32(i * 4, true); // little-endian
  }
  return state;
}

function stateToBytes(state: Uint32Array): Uint8Array {
  const out = new Uint8Array(128);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i < 32; i++) {
    dv.setUint32(i * 4, state[i] >>> 0, true);
  }
  return out;
}

/** Get a random nonce (works in Node.js and browser). */
function getRandomBytes(n: number): Uint8Array {
  // Browser
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.getRandomValues) {
    const buf = new Uint8Array(n);
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  // Node.js fallback (dynamic require to avoid bundler issues)
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require("crypto") as { randomBytes(n: number): Uint8Array };
    return new Uint8Array(crypto.randomBytes(n));
  } catch {
    throw new Error("C512: no crypto source available for random nonce generation");
  }
}

// ── Permutation Layer 1: Round Constants ─────────────────────────────────────

function applyRoundConstant(state: Uint32Array, roundIdx: number): void {
  const rc = ROUND_CONSTANTS[roundIdx % 24];
  state[16] = (state[16] ^ rc[0]) >>> 0;
  state[17] = (state[17] ^ rc[1]) >>> 0;
}

// ── Permutation Layer 2: Theta (column-parity diffusion) ─────────────────────

function applyTheta(state: Uint32Array): void {
  const parity = new Uint32Array(32);
  for (let i = 0; i < 32; i++) {
    parity[i] = (
      state[((i - 5) + 32) % 32] ^
      rotl32(state[(i + 5) % 32], 7) ^
      state[((i - 13) + 32) % 32] ^
      rotl32(state[(i + 13) % 32], 19)
    ) >>> 0;
  }
  for (let i = 0; i < 32; i++) {
    state[i] = (state[i] ^ parity[i]) >>> 0;
  }
  for (let i = 0; i < 32; i++) {
    state[i] = rotl32(state[i], ROTATION_OFFSETS[i]);
  }
}

// ── Permutation Layer 3: Chi (Keccak S-box) ──────────────────────────────────

function applyChi(state: Uint32Array): void {
  const temp = new Uint32Array(state);
  for (let i = 0; i < 32; i++) {
    state[i] = (temp[i] ^ ((~temp[(i + 1) % 32]) & temp[(i + 2) % 32])) >>> 0;
  }
}

// ── Permutation Layer 4: NTT Butterfly Mixing ────────────────────────────────

function nttButterflyHalf(state: Uint32Array, offset: number): void {
  let step = 8;
  while (step >= 1) {
    let group = 0;
    while (group < 16) {
      for (let j = 0; j < step; j++) {
        const idx1 = offset + group + j;
        const idx2 = offset + group + j + step;
        const omegaIdx = (j * ((16 / (step * 2)) | 0)) % 16;
        const t = Math.imul(state[idx2], OMEGA[omegaIdx]) >>> 0;
        state[idx2] = (state[idx1] - t) >>> 0;
        state[idx1] = (state[idx1] + t) >>> 0;
      }
      group += step * 2;
    }
    step = (step / 2) | 0;
  }
}

function applyNttButterfly(state: Uint32Array): void {
  nttButterflyHalf(state, 0);
  nttButterflyHalf(state, 16);
  // Cross-half rotation mix
  for (let i = 0; i < 16; i++) {
    const a = state[i];
    const b = state[16 + i];
    state[i] = (a ^ rotl32(b, 11)) >>> 0;
    state[16 + i] = (b ^ rotl32(a, 23)) >>> 0;
  }
}

// ── Permutation Layer 5: Round Key Injection ─────────────────────────────────

function applyRoundKey(state: Uint32Array, roundKey: Uint32Array): void {
  for (let i = 0; i < 32; i++) {
    state[i] = (state[i] ^ roundKey[i]) >>> 0;
  }
}

// ── Permutation ──────────────────────────────────────────────────────────────

function permutation(state: Uint32Array, rounds: number, roundKeys: Uint32Array[]): void {
  const numKeys = roundKeys.length;
  for (let i = 0; i < rounds; i++) {
    applyRoundConstant(state, i);
    applyTheta(state);
    applyChi(state);
    applyNttButterfly(state);
    applyRoundKey(state, roundKeys[i % numKeys]);
  }
}

function bootstrapPermutation(state: Uint32Array, rounds: number): void {
  for (let i = 0; i < rounds; i++) {
    applyRoundConstant(state, i);
    applyTheta(state);
    applyChi(state);
    applyNttButterfly(state);
  }
}

// ── Key Schedule ─────────────────────────────────────────────────────────────

function keySchedule(masterKey: Uint8Array): Uint32Array[] {
  requireResearch();
  if (masterKey.length !== C512_KEY_SIZE) {
    throw new Error(`C512: keySchedule requires ${C512_KEY_SIZE}-byte key`);
  }
  // revKey = masterKey reversed
  const revKey = new Uint8Array(C512_KEY_SIZE);
  for (let i = 0; i < C512_KEY_SIZE; i++) {
    revKey[i] = masterKey[C512_KEY_SIZE - 1 - i];
  }
  // combined = masterKey || revKey (128 bytes)
  const combined = new Uint8Array(128);
  combined.set(masterKey, 0);
  combined.set(revKey, C512_KEY_SIZE);
  const c = stateFromBytes(combined);

  const roundKeys: Uint32Array[] = [];
  for (let r = 0; r < 24; r++) {
    bootstrapPermutation(c, C512_KDF_ROUNDS);
    roundKeys.push(new Uint32Array(c));
    c[0] = (c[0] ^ (r & MASK32)) >>> 0;
    c[1] = (c[1] ^ C512_DOMAIN_KS) >>> 0;
  }

  return roundKeys;
}

// ── State Initialization ─────────────────────────────────────────────────────

function initState(key: Uint8Array, nonce: Uint8Array): Uint32Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512: initState requires ${C512_KEY_SIZE}-byte key`);
  }
  if (nonce.length !== C512_NONCE_SIZE) {
    throw new Error(`C512: initState requires ${C512_NONCE_SIZE}-byte nonce`);
  }
  // Layout: IV(8 bytes) + key(64 bytes) + nonce(32 bytes) + zeros(24 bytes) = 128 bytes
  const initBytes = new Uint8Array(128);
  const dv = new DataView(initBytes.buffer);
  // Write IV as little-endian uint64 (two uint32s)
  dv.setUint32(0, C512_IV_LO, true);
  dv.setUint32(4, C512_IV_HI, true);
  initBytes.set(key, 8);
  initBytes.set(nonce, 72);
  // bytes 104..127 remain zero
  return stateFromBytes(initBytes);
}

// ── Padding ──────────────────────────────────────────────────────────────────

function padData(data: Uint8Array, blockSize: number): Uint8Array {
  let padLen = blockSize - (data.length % blockSize);
  if (padLen === 0) {
    padLen = blockSize;
  }
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0);
  out[data.length] = 0x80;
  // rest already zero
  return out;
}

// ── XOR / Keystream Helpers ──────────────────────────────────────────────────

function xorBlockIntoState(state: Uint32Array, block: Uint8Array, offset: number): void {
  const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let i = 0; i < 16; i++) {
    const v = dv.getUint32(offset + i * 4, true);
    state[i] = (state[i] ^ v) >>> 0;
  }
}

function extractKeystream(state: Uint32Array, length: number): Uint8Array {
  const rateBytes = new Uint8Array(64);
  const dv = new DataView(rateBytes.buffer);
  for (let i = 0; i < 16; i++) {
    dv.setUint32(i * 4, state[i] >>> 0, true);
  }
  return rateBytes.subarray(0, length);
}

// ── AEAD Encrypt ─────────────────────────────────────────────────────────────

export function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512: encrypt requires ${C512_KEY_SIZE}-byte key`);
  }
  if (nonce.length !== C512_NONCE_SIZE) {
    throw new Error(`C512: encrypt requires ${C512_NONCE_SIZE}-byte nonce`);
  }

  const roundKeys = keySchedule(key);
  const state = initState(key, nonce);
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Absorb AAD (v2.0: uses Phase-B rounds, not Phase-A)
  if (aad.length > 0) {
    const aadPadded = padData(aad, C512_RATE_SIZE);
    const blocks = aadPadded.length / C512_RATE_SIZE;
    for (let i = 0; i < blocks; i++) {
      xorBlockIntoState(state, aadPadded, i * C512_RATE_SIZE);
      permutation(state, C512_ROUNDS_B, roundKeys);
    }
  }

  // Domain separation: AAD -> plaintext
  state[31] = (state[31] ^ C512_DOMAIN_SEP) >>> 0;

  // Absorb plaintext / emit ciphertext
  const ptLen = plaintext.length;
  const ciphertext = new Uint8Array(ptLen + C512_TAG_SIZE);
  const fullBlocks = (ptLen / C512_RATE_SIZE) | 0;
  const remaining = ptLen % C512_RATE_SIZE;

  for (let i = 0; i < fullBlocks; i++) {
    const keystream = extractKeystream(state, C512_RATE_SIZE);
    const off = i * C512_RATE_SIZE;
    for (let j = 0; j < C512_RATE_SIZE; j++) {
      ciphertext[off + j] = keystream[j] ^ plaintext[off + j];
    }
    // Absorb plaintext block
    const absorb = new Uint8Array(C512_RATE_SIZE);
    absorb.set(plaintext.subarray(off, off + C512_RATE_SIZE));
    xorBlockIntoState(state, absorb, 0);
    permutation(state, C512_ROUNDS_B, roundKeys);
  }

  const lastBlock = new Uint8Array(C512_RATE_SIZE);
  if (remaining > 0) {
    const off = fullBlocks * C512_RATE_SIZE;
    const keystream = extractKeystream(state, remaining);
    for (let j = 0; j < remaining; j++) {
      ciphertext[off + j] = keystream[j] ^ plaintext[off + j];
      lastBlock[j] = plaintext[off + j];
    }
  }
  lastBlock[remaining] = 0x80;
  xorBlockIntoState(state, lastBlock, 0);
  permutation(state, C512_ROUNDS_B, roundKeys);

  // Finalize
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Tag derivation with domain separator
  state[31] = (state[31] ^ C512_DOMAIN_TAG) >>> 0;
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Extract tag (8 uint32 lanes = 32 bytes)
  const tagDv = new DataView(ciphertext.buffer, ciphertext.byteOffset + ptLen, C512_TAG_SIZE);
  for (let i = 0; i < 8; i++) {
    tagDv.setUint32(i * 4, state[i] >>> 0, true);
  }

  return ciphertext;
}

// ── AEAD Decrypt ─────────────────────────────────────────────────────────────

export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512: decrypt requires ${C512_KEY_SIZE}-byte key`);
  }
  if (nonce.length !== C512_NONCE_SIZE) {
    throw new Error(`C512: decrypt requires ${C512_NONCE_SIZE}-byte nonce`);
  }
  if (data.length < C512_TAG_SIZE) {
    throw new Error("C512: data too short");
  }

  const ciphertext = data.subarray(0, data.length - C512_TAG_SIZE);
  const tag = data.subarray(data.length - C512_TAG_SIZE);

  const roundKeys = keySchedule(key);
  const state = initState(key, nonce);
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Absorb AAD (v2.0: Phase-B rounds)
  if (aad.length > 0) {
    const aadPadded = padData(aad, C512_RATE_SIZE);
    const blocks = aadPadded.length / C512_RATE_SIZE;
    for (let i = 0; i < blocks; i++) {
      xorBlockIntoState(state, aadPadded, i * C512_RATE_SIZE);
      permutation(state, C512_ROUNDS_B, roundKeys);
    }
  }

  // Domain separation
  state[31] = (state[31] ^ C512_DOMAIN_SEP) >>> 0;

  // Decrypt ciphertext
  const ctLen = ciphertext.length;
  const plaintext = new Uint8Array(ctLen);
  const fullBlocks = (ctLen / C512_RATE_SIZE) | 0;
  const remaining = ctLen % C512_RATE_SIZE;

  for (let i = 0; i < fullBlocks; i++) {
    const keystream = extractKeystream(state, C512_RATE_SIZE);
    const off = i * C512_RATE_SIZE;
    const absorb = new Uint8Array(C512_RATE_SIZE);
    for (let j = 0; j < C512_RATE_SIZE; j++) {
      const pb = keystream[j] ^ ciphertext[off + j];
      plaintext[off + j] = pb;
      absorb[j] = pb;
    }
    xorBlockIntoState(state, absorb, 0);
    permutation(state, C512_ROUNDS_B, roundKeys);
  }

  const lastBlock = new Uint8Array(C512_RATE_SIZE);
  if (remaining > 0) {
    const off = fullBlocks * C512_RATE_SIZE;
    const keystream = extractKeystream(state, remaining);
    for (let j = 0; j < remaining; j++) {
      const pb = keystream[j] ^ ciphertext[off + j];
      plaintext[off + j] = pb;
      lastBlock[j] = pb;
    }
  }
  lastBlock[remaining] = 0x80;
  xorBlockIntoState(state, lastBlock, 0);
  permutation(state, C512_ROUNDS_B, roundKeys);

  // Finalize
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Tag verification
  state[31] = (state[31] ^ C512_DOMAIN_TAG) >>> 0;
  permutation(state, C512_ROUNDS_A, roundKeys);

  const expectedTag = new Uint8Array(C512_TAG_SIZE);
  const etDv = new DataView(expectedTag.buffer);
  for (let i = 0; i < 8; i++) {
    etDv.setUint32(i * 4, state[i] >>> 0, true);
  }

  // Constant-time tag comparison
  let diff = 0;
  for (let i = 0; i < C512_TAG_SIZE; i++) {
    diff |= expectedTag[i] ^ tag[i];
  }
  if (diff !== 0) {
    throw new Error("C512: authentication failed -- ciphertext tampered");
  }

  return plaintext;
}

// ── XOF Mode (Extendable Output Function) ────────────────────────────────────

export function xof(
  key: Uint8Array,
  context: Uint8Array,
  outputLength: number,
): Uint8Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512-XOF: requires ${C512_KEY_SIZE}-byte key`);
  }
  if (!Number.isSafeInteger(outputLength) || outputLength < 0 || outputLength > 16777216) {
    throw new Error("C512-XOF: outputLength must be non-negative");
  }

  const roundKeys = keySchedule(key);

  const state = new Uint32Array(C512_LANES);
  const keyDv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 16; i++) {
    state[i] = keyDv.getUint32(i * 4, true);
  }
  state[31] = (state[31] ^ C512_DOMAIN_XOF) >>> 0;

  permutation(state, C512_ROUNDS_A, roundKeys);

  // Absorb context
  if (context.length > 0) {
    const ctxPadded = padData(context, C512_RATE_SIZE);
    const blocks = ctxPadded.length / C512_RATE_SIZE;
    for (let i = 0; i < blocks; i++) {
      xorBlockIntoState(state, ctxPadded, i * C512_RATE_SIZE);
      permutation(state, C512_ROUNDS_B, roundKeys);
    }
  }

  // Squeeze domain separator
  state[31] = (state[31] ^ C512_DOMAIN_SQZ) >>> 0;
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Squeeze output
  const output = new Uint8Array(outputLength);
  let produced = 0;
  while (produced < outputLength) {
    const needed = Math.min(C512_RATE_SIZE, outputLength - produced);
    const ks = extractKeystream(state, needed);
    output.set(ks, produced);
    produced += needed;
    if (produced < outputLength) {
      permutation(state, C512_ROUNDS_B, roundKeys);
    }
  }

  return output;
}

// ── SIV Mode (Misuse-Resistant AEAD) ─────────────────────────────────────────

function sivDeriveNonce(
  key: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  // Build SIV input: LE64(aad.length) + aad + LE64(plaintext.length) + plaintext
  const sivInput = new Uint8Array(8 + aad.length + 8 + plaintext.length);
  const sivDv = new DataView(sivInput.buffer);
  // Write aad length as LE uint64 (fits in 32 bits for practical sizes)
  sivDv.setUint32(0, aad.length, true);
  sivDv.setUint32(4, Math.floor(aad.length / 0x100000000), true);
  sivInput.set(aad, 8);
  const ptOffset = 8 + aad.length;
  sivDv.setUint32(ptOffset, plaintext.length, true);
  sivDv.setUint32(ptOffset + 4, Math.floor(plaintext.length / 0x100000000), true);
  sivInput.set(plaintext, ptOffset + 8);

  const roundKeys = keySchedule(key);

  const state = new Uint32Array(C512_LANES);
  const keyDv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 16; i++) {
    state[i] = keyDv.getUint32(i * 4, true);
  }
  state[31] = (state[31] ^ C512_DOMAIN_SIV) >>> 0;

  permutation(state, C512_ROUNDS_A, roundKeys);

  if (sivInput.length > 0) {
    const sivPadded = padData(sivInput, C512_RATE_SIZE);
    const blocks = sivPadded.length / C512_RATE_SIZE;
    for (let i = 0; i < blocks; i++) {
      xorBlockIntoState(state, sivPadded, i * C512_RATE_SIZE);
      permutation(state, C512_ROUNDS_B, roundKeys);
    }
  }

  state[31] = (state[31] ^ C512_DOMAIN_SQZ) >>> 0;
  permutation(state, C512_ROUNDS_A, roundKeys);

  // Extract 32-byte nonce from first 8 lanes
  const nonceBytes = new Uint8Array(C512_NONCE_SIZE);
  const nonceDv = new DataView(nonceBytes.buffer);
  for (let i = 0; i < 8; i++) {
    nonceDv.setUint32(i * 4, state[i] >>> 0, true);
  }
  return nonceBytes;
}

export function sivEncrypt(
  key: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512-SIV: requires ${C512_KEY_SIZE}-byte key`);
  }
  const nonce = sivDeriveNonce(key, aad, plaintext);
  const ctTag = encrypt(key, nonce, aad, plaintext);
  // Return: nonce(32) || ciphertext || tag(32)
  const result = new Uint8Array(C512_NONCE_SIZE + ctTag.length);
  result.set(nonce, 0);
  result.set(ctTag, C512_NONCE_SIZE);
  return result;
}

export function sivDecrypt(
  key: Uint8Array,
  aad: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (key.length !== C512_KEY_SIZE) {
    throw new Error(`C512-SIV: requires ${C512_KEY_SIZE}-byte key`);
  }
  if (data.length < C512_NONCE_SIZE + C512_TAG_SIZE) {
    throw new Error("C512-SIV: data too short");
  }

  const nonce = data.subarray(0, C512_NONCE_SIZE);
  const ctTag = data.subarray(C512_NONCE_SIZE);

  const plaintext = decrypt(key, nonce, aad, ctTag);

  // Verify synthetic nonce
  const expectedNonce = sivDeriveNonce(key, aad, plaintext);
  let diff = 0;
  for (let i = 0; i < C512_NONCE_SIZE; i++) {
    diff |= nonce[i] ^ expectedNonce[i];
  }
  if (diff !== 0) {
    throw new Error("C512-SIV: synthetic nonce verification failed");
  }

  return plaintext;
}

// ── Convenience Wrappers ─────────────────────────────────────────────────────

export function encryptWithNonce(
  key: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = getRandomBytes(C512_NONCE_SIZE);
  const inner = encrypt(key, nonce, aad, plaintext);
  const result = new Uint8Array(C512_NONCE_SIZE + inner.length);
  result.set(nonce, 0);
  result.set(inner, C512_NONCE_SIZE);
  return result;
}

export function decryptWithNonce(
  key: Uint8Array,
  aad: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  if (data.length < C512_NONCE_SIZE + C512_TAG_SIZE) {
    throw new Error("C512: data too short (missing nonce+tag)");
  }
  const nonce = data.subarray(0, C512_NONCE_SIZE);
  const inner = data.subarray(C512_NONCE_SIZE);
  return decrypt(key, nonce, aad, inner);
}

// ── Self-Test ────────────────────────────────────────────────────────────────

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function makeBytes(len: number, fill: number): Uint8Array {
  const buf = new Uint8Array(len);
  buf.fill(fill);
  return buf;
}

function makeRange(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    buf[i] = i & 0xFF;
  }
  return buf;
}

export function selfTest(): boolean {
  const key = makeRange(64);
  const nonce = makeRange(32);
  const empty = new Uint8Array(0);

  // 1: empty plaintext, empty AAD round-trip
  {
    const ct = encrypt(key, nonce, empty, empty);
    if (ct.length !== C512_TAG_SIZE) {
      throw new Error("selfTest 1: wrong length");
    }
    const pt = decrypt(key, nonce, empty, ct);
    if (pt.length !== 0) {
      throw new Error("selfTest 1: plaintext mismatch");
    }
  }

  // 2: 64B PT + 64B AAD round-trip
  {
    const plaintext = makeBytes(64, 0x55);
    const aad = makeBytes(64, 0xAA);
    const ct = encrypt(key, nonce, aad, plaintext);
    if (ct.length !== 64 + C512_TAG_SIZE) {
      throw new Error("selfTest 2: wrong length");
    }
    const pt = decrypt(key, nonce, aad, ct);
    if (!arraysEqual(pt, plaintext)) {
      throw new Error("selfTest 2: plaintext mismatch");
    }
  }

  // 3: SIV determinism
  {
    const plaintext = makeBytes(64, 0x55);
    const aad = makeBytes(64, 0xAA);
    const sivCt1 = sivEncrypt(key, aad, plaintext);
    const sivCt2 = sivEncrypt(key, aad, plaintext);
    if (!arraysEqual(sivCt1, sivCt2)) {
      throw new Error("selfTest 3: SIV not deterministic");
    }
    // Round-trip
    const sivPt = sivDecrypt(key, aad, sivCt1);
    if (!arraysEqual(sivPt, plaintext)) {
      throw new Error("selfTest 3: SIV round-trip mismatch");
    }
  }

  // 4: XOF determinism
  {
    const ctx = new TextEncoder().encode("test context");
    const xofOut1 = xof(key, ctx, 64);
    const xofOut2 = xof(key, ctx, 64);
    if (!arraysEqual(xofOut1, xofOut2)) {
      throw new Error("selfTest 4: XOF not deterministic");
    }
    if (xofOut1.length !== 64) {
      throw new Error("selfTest 4: wrong XOF length");
    }
    // Different context produces different output
    const ctx2 = new TextEncoder().encode("other context");
    const xofOut3 = xof(key, ctx2, 64);
    if (arraysEqual(xofOut1, xofOut3)) {
      throw new Error("selfTest 4: XOF collision");
    }
    // Prefix consistency
    const xof128 = xof(key, new TextEncoder().encode("test"), 128);
    const xof64 = xof(key, new TextEncoder().encode("test"), 64);
    if (!arraysEqual(xof128.subarray(0, 64), xof64)) {
      throw new Error("selfTest 4: XOF prefix mismatch");
    }
  }

  // 5: Tamper detection
  {
    const plaintext = makeBytes(64, 0x55);
    const aad = makeBytes(64, 0xAA);
    const ct = encrypt(key, nonce, aad, plaintext);

    // Tampered ciphertext byte
    const tampered = new Uint8Array(ct);
    tampered[0] ^= 0xFF;
    let caught = false;
    try {
      decrypt(key, nonce, aad, tampered);
    } catch (e: unknown) {
      if (e instanceof Error && e.message.includes("authentication failed")) {
        caught = true;
      }
    }
    if (!caught) {
      throw new Error("selfTest 5: tampered ciphertext should have been detected");
    }

    // SIV tamper detection
    const sivCt = sivEncrypt(key, aad, plaintext);
    const sivTampered = new Uint8Array(sivCt);
    sivTampered[40] ^= 0x01;
    caught = false;
    try {
      sivDecrypt(key, aad, sivTampered);
    } catch {
      caught = true;
    }
    if (!caught) {
      throw new Error("selfTest 5: SIV tamper should have been detected");
    }
  }

  return true;
}
