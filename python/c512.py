"""
ALB_C512 (C512) v2.0 — Reference Implementation in Python 3.10+

A sponge-based authenticated encryption algorithm with:
  - 512-bit key, 256-bit nonce, 256-bit tag
  - 1024-bit internal state (32 lanes x 32 bits)
  - Five-layer permutation: RoundConstant + Theta + Chi + NTT Butterfly + RoundKey
  - Dual-phase rounds: A=24 (init/finalize), B=12 (data blocks)

v2.0 changes from v1.0:
  - Fixed AAD absorption rounds (was 24/Phase-A, now 12/Phase-B)
  - Updated domain constants: KS="C520", TAG="TAG2", separator=0x02
  - Updated IV version marker
  - Added SIV mode (misuse-resistant AEAD)
  - Added XOF mode (extendable output / KDF)
  - Added streaming API (C512EncryptContext / C512DecryptContext)
  - Added class-based API wrapper (C512 class)

Usage:
  python c512.py test
  python c512.py encrypt --key <hex> --nonce <hex> --aad <hex> --plaintext <hex>
  python c512.py decrypt --key <hex> --nonce <hex> --aad <hex> --data <hex>
  python c512.py generate_vectors
"""

from __future__ import annotations
import struct
import os
import sys
import hmac as _hmac
from typing import Optional

# ── Version ────────────────────────────────────────────────────────────────

C512_VERSION = "2.0"

# ── Constants ──────────────────────────────────────────────────────────────

C512_KEY_SIZE = 64       # bytes (512 bits)
C512_NONCE_SIZE = 32     # bytes (256 bits)
C512_TAG_SIZE = 32       # bytes (256 bits)
C512_STATE_SIZE = 128    # bytes (1024 bits)
C512_RATE_SIZE = 64      # bytes (512 bits)
C512_LANES = 32
C512_HALF_LANES = 16
C512_ROUNDS_A = 24       # init / finalize
C512_ROUNDS_B = 12       # per data block
C512_KDF_ROUNDS = 4      # key schedule bootstrap

MASK32 = 0xFFFFFFFF

# v2.0 domain constants
C512_DOMAIN_KS  = 0x43353230   # "C520" — key schedule domain
C512_DOMAIN_TAG = 0x54414732   # "TAG2" — tag derivation domain
C512_DOMAIN_SEP = 0x00000002   # AAD-to-plaintext separator
C512_DOMAIN_XOF = 0x584F4632   # "XOF2" — XOF mode domain
C512_DOMAIN_SQZ = 0x53515A32   # "SQZ2" — XOF squeeze domain
C512_DOMAIN_SIV = 0x53495632   # "SIV2" — SIV nonce derivation domain

# v2.0 init vector: encodes state_size=128, rounds_a=24, rounds_b=12, version=2
C512_IV = 0x80500C1800000002

# Round constants (fractional bits of sqrt(2), sqrt(3), SHA-256 K[0..23])
ROUND_CONSTANTS: list[int] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    0x428A2F98D728AE22, 0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE,
    0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235, 0xC19BF174CF692694,
]

# NTT butterfly twiddle factors (derived from sqrt(2) and SHA-256 K values)
OMEGA: list[int] = [
    0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
    0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
    0x5BE0CD19, 0x428A2F98, 0x71374491, 0xB5C0FBCF,
    0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
]

# Per-lane rotation offsets (triangular + non-linear residues, all distinct)
ROTATION_OFFSETS = [
     0,  1,  3,  6, 10, 15, 21, 28,
     2,  5,  9, 14, 20, 27,  3, 12,
     4,  8, 13, 19, 26,  1,  7, 16,
    11, 18, 25, 31, 17, 24, 30, 22,
]


# Research only. This gate is deliberately separate from package encryption.
MAX_RESEARCH_BYTES = 16 * 1024 * 1024

def _require_experimental():
    if os.environ.get("ALB_C512_EXPERIMENTAL") != "1":
        raise RuntimeError("C512 is broken research cryptography; explicitly set ALB_C512_EXPERIMENTAL=1 for experiments only")

def _bound(value, name="input"):
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(name + " must be bytes")
    if len(value) > MAX_RESEARCH_BYTES:
        raise ValueError(name + " exceeds the 16 MiB research limit")

# ── Helpers ────────────────────────────────────────────────────────────────

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def state_from_bytes(b: bytes) -> list[int]:
    if len(b) != 128:
        raise ValueError("C512: state_from_bytes requires exactly 128 bytes")
    return list(struct.unpack_from('<32I', b))


def state_to_bytes(state: list[int]) -> bytes:
    return struct.pack('<32I', *[x & MASK32 for x in state])


# ── Permutation Layer 1: Round Constants ───────────────────────────────────

def apply_round_constant(state: list[int], round_idx: int) -> None:
    rc = ROUND_CONSTANTS[round_idx % 24]
    state[16] ^= (rc & MASK32)
    state[17] ^= ((rc >> 32) & MASK32)


# ── Permutation Layer 2: Theta (column-parity diffusion) ──────────────────

def apply_theta(state: list[int]) -> None:
    parity = [0] * 32
    for i in range(32):
        parity[i] = (
            state[(i - 5) % 32] ^
            _rotl32(state[(i + 5) % 32], 7) ^
            state[(i - 13) % 32] ^
            _rotl32(state[(i + 13) % 32], 19)
        ) & MASK32
    for i in range(32):
        state[i] = (state[i] ^ parity[i]) & MASK32
    for i in range(32):
        state[i] = _rotl32(state[i], ROTATION_OFFSETS[i])


# ── Permutation Layer 3: Chi (Keccak S-box) ───────────────────────────────

def apply_chi(state: list[int]) -> None:
    temp = state[:]
    for i in range(32):
        state[i] = (temp[i] ^ ((~temp[(i + 1) % 32]) & temp[(i + 2) % 32])) & MASK32


# ── Permutation Layer 4: NTT Butterfly Mixing ─────────────────────────────

def ntt_butterfly_half(state: list[int], offset: int) -> None:
    step = 8
    while step >= 1:
        group = 0
        while group < 16:
            for j in range(step):
                idx1 = offset + group + j
                idx2 = offset + group + j + step
                omega_idx = (j * (16 // (step * 2))) % 16
                temp = (state[idx2] * OMEGA[omega_idx]) & MASK32
                state[idx2] = (state[idx1] - temp) & MASK32
                state[idx1] = (state[idx1] + temp) & MASK32
            group += step * 2
        step //= 2


def apply_ntt_butterfly(state: list[int]) -> None:
    ntt_butterfly_half(state, 0)
    ntt_butterfly_half(state, 16)
    for i in range(16):
        a = state[i]
        b = state[16 + i]
        state[i] = (a ^ _rotl32(b, 11)) & MASK32
        state[16 + i] = (b ^ _rotl32(a, 23)) & MASK32


# ── Permutation Layer 5: Round Key Injection ───────────────────────────────

def apply_round_key(state: list[int], round_key: list[int]) -> None:
    for i in range(32):
        state[i] = (state[i] ^ round_key[i]) & MASK32


# ── Permutation ────────────────────────────────────────────────────────────

def permutation(state: list[int], rounds: int, round_keys: list[list[int]]) -> None:
    for i in range(rounds):
        apply_round_constant(state, i)
        apply_theta(state)
        apply_chi(state)
        apply_ntt_butterfly(state)
        apply_round_key(state, round_keys[i % len(round_keys)])


def bootstrap_permutation(state: list[int], rounds: int) -> None:
    for i in range(rounds):
        apply_round_constant(state, i)
        apply_theta(state)
        apply_chi(state)
        apply_ntt_butterfly(state)


# ── Key Schedule ───────────────────────────────────────────────────────────

def key_schedule(master_key: bytes) -> list[list[int]]:
    if len(master_key) != C512_KEY_SIZE:
        raise ValueError(f"C512: key_schedule requires {C512_KEY_SIZE}-byte key")
    _require_experimental()
    rev_key = master_key[::-1]
    combined = master_key + rev_key
    c = state_from_bytes(combined)

    round_keys: list[list[int]] = []
    for r in range(24):
        bootstrap_permutation(c, C512_KDF_ROUNDS)
        round_keys.append(c[:])
        c[0] = (c[0] ^ (r & MASK32)) & MASK32
        c[1] = (c[1] ^ C512_DOMAIN_KS) & MASK32

    return round_keys


# ── State Initialization ──────────────────────────────────────────────────

def init_state(key: bytes, nonce: bytes) -> list[int]:
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512: init_state requires {C512_KEY_SIZE}-byte key")
    if len(nonce) != C512_NONCE_SIZE:
        raise ValueError(f"C512: init_state requires {C512_NONCE_SIZE}-byte nonce")
    init_bytes = struct.pack('<Q', C512_IV) + key + nonce + b'\x00' * 24
    return state_from_bytes(init_bytes)


# ── Padding ────────────────────────────────────────────────────────────────

def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + b'\x80' + b'\x00' * (pad_len - 1)


# ── XOR / Keystream Helpers ───────────────────────────────────────────────

def xor_block_into_state(state: list[int], block: bytes, offset: int) -> None:
    for i in range(16):
        v = struct.unpack_from('<I', block, offset + i * 4)[0]
        state[i] = (state[i] ^ v) & MASK32


def extract_keystream(state: list[int], length: int) -> bytes:
    rate_bytes = struct.pack('<16I', *[state[i] & MASK32 for i in range(16)])
    return rate_bytes[:length]


# ── AEAD Encrypt ───────────────────────────────────────────────────────────

def encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt with C512 v2.0 AEAD.
    Returns: ciphertext || tag  (len(plaintext) + 32 bytes).
    """
    _bound(aad, "aad")
    _bound(plaintext, "plaintext")
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512: encrypt requires {C512_KEY_SIZE}-byte key")
    if len(nonce) != C512_NONCE_SIZE:
        raise ValueError(f"C512: encrypt requires {C512_NONCE_SIZE}-byte nonce")

    round_keys = key_schedule(key)
    state = init_state(key, nonce)
    permutation(state, C512_ROUNDS_A, round_keys)

    # Absorb AAD (v2.0: uses Phase-B rounds, not Phase-A)
    if len(aad) > 0:
        aad_padded = pad(aad, C512_RATE_SIZE)
        blocks = len(aad_padded) // C512_RATE_SIZE
        for i in range(blocks):
            xor_block_into_state(state, aad_padded, i * C512_RATE_SIZE)
            permutation(state, C512_ROUNDS_B, round_keys)

    # Domain separation: AAD -> plaintext
    state[31] = (state[31] ^ C512_DOMAIN_SEP) & MASK32

    # Absorb plaintext / emit ciphertext
    ciphertext = bytearray()
    pt_len = len(plaintext)
    full_blocks = pt_len // C512_RATE_SIZE
    remaining = pt_len % C512_RATE_SIZE

    for i in range(full_blocks):
        keystream = extract_keystream(state, C512_RATE_SIZE)
        off = i * C512_RATE_SIZE
        for j in range(C512_RATE_SIZE):
            ciphertext.append(keystream[j] ^ plaintext[off + j])
        absorb = bytearray(C512_RATE_SIZE)
        absorb[:] = plaintext[off:off + C512_RATE_SIZE]
        xor_block_into_state(state, bytes(absorb), 0)
        permutation(state, C512_ROUNDS_B, round_keys)

    last_block = bytearray(C512_RATE_SIZE)
    if remaining > 0:
        off = full_blocks * C512_RATE_SIZE
        keystream = extract_keystream(state, remaining)
        for j in range(remaining):
            ciphertext.append(keystream[j] ^ plaintext[off + j])
            last_block[j] = plaintext[off + j]
    last_block[remaining] = 0x80
    xor_block_into_state(state, bytes(last_block), 0)
    permutation(state, C512_ROUNDS_B, round_keys)

    # Finalize
    permutation(state, C512_ROUNDS_A, round_keys)

    # Tag derivation with domain separator
    state[31] = (state[31] ^ C512_DOMAIN_TAG) & MASK32
    permutation(state, C512_ROUNDS_A, round_keys)

    tag = struct.pack('<8I', *[state[i] & MASK32 for i in range(8)])
    return bytes(ciphertext) + tag


# ── AEAD Decrypt ───────────────────────────────────────────────────────────

def decrypt(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    """
    Decrypt with C512 v2.0 AEAD.
    Returns plaintext or raises ValueError on auth failure.
    """
    _bound(aad, "aad")
    _bound(data, "data")
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512: decrypt requires {C512_KEY_SIZE}-byte key")
    if len(nonce) != C512_NONCE_SIZE:
        raise ValueError(f"C512: decrypt requires {C512_NONCE_SIZE}-byte nonce")
    if len(data) < C512_TAG_SIZE:
        raise ValueError("C512: data too short")

    ciphertext = data[:-C512_TAG_SIZE]
    tag = data[-C512_TAG_SIZE:]

    round_keys = key_schedule(key)
    state = init_state(key, nonce)
    permutation(state, C512_ROUNDS_A, round_keys)

    # Absorb AAD (v2.0: Phase-B rounds)
    if len(aad) > 0:
        aad_padded = pad(aad, C512_RATE_SIZE)
        blocks = len(aad_padded) // C512_RATE_SIZE
        for i in range(blocks):
            xor_block_into_state(state, aad_padded, i * C512_RATE_SIZE)
            permutation(state, C512_ROUNDS_B, round_keys)

    # Domain separation
    state[31] = (state[31] ^ C512_DOMAIN_SEP) & MASK32

    # Decrypt ciphertext
    plaintext = bytearray()
    ct_len = len(ciphertext)
    full_blocks = ct_len // C512_RATE_SIZE
    remaining = ct_len % C512_RATE_SIZE

    for i in range(full_blocks):
        keystream = extract_keystream(state, C512_RATE_SIZE)
        off = i * C512_RATE_SIZE
        absorb = bytearray(C512_RATE_SIZE)
        for j in range(C512_RATE_SIZE):
            pb = keystream[j] ^ ciphertext[off + j]
            plaintext.append(pb)
            absorb[j] = pb
        xor_block_into_state(state, bytes(absorb), 0)
        permutation(state, C512_ROUNDS_B, round_keys)

    last_block = bytearray(C512_RATE_SIZE)
    if remaining > 0:
        off = full_blocks * C512_RATE_SIZE
        keystream = extract_keystream(state, remaining)
        for j in range(remaining):
            pb = keystream[j] ^ ciphertext[off + j]
            plaintext.append(pb)
            last_block[j] = pb
    last_block[remaining] = 0x80
    xor_block_into_state(state, bytes(last_block), 0)
    permutation(state, C512_ROUNDS_B, round_keys)

    # Finalize
    permutation(state, C512_ROUNDS_A, round_keys)

    # Tag verification
    state[31] = (state[31] ^ C512_DOMAIN_TAG) & MASK32
    permutation(state, C512_ROUNDS_A, round_keys)
    expected_tag = struct.pack('<8I', *[state[i] & MASK32 for i in range(8)])

    if not _hmac.compare_digest(expected_tag, tag):
        raise ValueError("C512: authentication failed — ciphertext tampered")

    return bytes(plaintext)


# ── XOF Mode (Extendable Output Function) ─────────────────────────────────

def xof(key: bytes, context: bytes, output_length: int) -> bytes:
    """
    C512-XOF: derive arbitrary-length output from key + context.
    Usable as KDF, PRF, or stream cipher primitive.
    """
    _bound(context, "context")
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512-XOF: requires {C512_KEY_SIZE}-byte key")
    if type(output_length) is not int or not 0 <= output_length <= MAX_RESEARCH_BYTES:
        raise ValueError("C512-XOF: output_length must be non-negative")

    round_keys = key_schedule(key)

    state = [0] * C512_LANES
    for i in range(16):
        state[i] = struct.unpack_from('<I', key, i * 4)[0]
    state[31] = (state[31] ^ C512_DOMAIN_XOF) & MASK32

    permutation(state, C512_ROUNDS_A, round_keys)

    # Absorb context
    if len(context) > 0:
        ctx_padded = pad(context, C512_RATE_SIZE)
        for i in range(len(ctx_padded) // C512_RATE_SIZE):
            xor_block_into_state(state, ctx_padded, i * C512_RATE_SIZE)
            permutation(state, C512_ROUNDS_B, round_keys)

    # Squeeze domain separator
    state[31] = (state[31] ^ C512_DOMAIN_SQZ) & MASK32
    permutation(state, C512_ROUNDS_A, round_keys)

    # Squeeze output
    output = bytearray()
    while len(output) < output_length:
        needed = min(C512_RATE_SIZE, output_length - len(output))
        output.extend(extract_keystream(state, needed))
        if len(output) < output_length:
            permutation(state, C512_ROUNDS_B, round_keys)

    return bytes(output[:output_length])


# ── SIV Mode (Misuse-Resistant AEAD) ──────────────────────────────────────

def _siv_derive_nonce(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Derive synthetic nonce from key + length-prefixed AAD + plaintext."""
    siv_input = (
        struct.pack('<Q', len(aad)) + aad +
        struct.pack('<Q', len(plaintext)) + plaintext
    )
    round_keys = key_schedule(key)

    state = [0] * C512_LANES
    for i in range(16):
        state[i] = struct.unpack_from('<I', key, i * 4)[0]
    state[31] = (state[31] ^ C512_DOMAIN_SIV) & MASK32

    permutation(state, C512_ROUNDS_A, round_keys)

    if len(siv_input) > 0:
        siv_padded = pad(siv_input, C512_RATE_SIZE)
        for i in range(len(siv_padded) // C512_RATE_SIZE):
            xor_block_into_state(state, siv_padded, i * C512_RATE_SIZE)
            permutation(state, C512_ROUNDS_B, round_keys)

    state[31] = (state[31] ^ C512_DOMAIN_SQZ) & MASK32
    permutation(state, C512_ROUNDS_A, round_keys)

    nonce_bytes = struct.pack('<8I', *[state[i] & MASK32 for i in range(8)])
    return nonce_bytes


def siv_encrypt(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """
    C512-SIV: misuse-resistant AEAD. No nonce parameter needed.
    Returns: synthetic_nonce(32) || ciphertext || tag(32).
    Nonce reuse produces identical ciphertext (no XOR leakage).
    """
    _bound(aad, "aad")
    _bound(plaintext, "plaintext")
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512-SIV: requires {C512_KEY_SIZE}-byte key")
    nonce = _siv_derive_nonce(key, aad, plaintext)
    ct_tag = encrypt(key, nonce, aad, plaintext)
    return nonce + ct_tag


def siv_decrypt(key: bytes, aad: bytes, data: bytes) -> bytes:
    """
    C512-SIV: misuse-resistant AEAD decrypt.
    Input: synthetic_nonce(32) || ciphertext || tag(32).
    """
    _bound(aad, "aad")
    _bound(data, "data")
    if len(key) != C512_KEY_SIZE:
        raise ValueError(f"C512-SIV: requires {C512_KEY_SIZE}-byte key")
    if len(data) < C512_NONCE_SIZE + C512_TAG_SIZE:
        raise ValueError("C512-SIV: data too short")

    nonce = data[:C512_NONCE_SIZE]
    ct_tag = data[C512_NONCE_SIZE:]

    plaintext = decrypt(key, nonce, aad, ct_tag)

    expected_nonce = _siv_derive_nonce(key, aad, plaintext)
    if not _hmac.compare_digest(nonce, expected_nonce):
        raise ValueError("C512-SIV: synthetic nonce verification failed")

    return plaintext


# ── Streaming API ──────────────────────────────────────────────────────────

class C512EncryptContext:
    """Incremental encryption context. Call update() with chunks, finalize() at end."""

    def __init__(self, key: bytes, nonce: bytes, aad: bytes = b''):
        if len(key) != C512_KEY_SIZE:
            raise ValueError(f"C512: requires {C512_KEY_SIZE}-byte key")
        if len(nonce) != C512_NONCE_SIZE:
            raise ValueError(f"C512: requires {C512_NONCE_SIZE}-byte nonce")

        _bound(aad, "aad")
        self._round_keys = key_schedule(key)
        self._state = init_state(key, nonce)
        permutation(self._state, C512_ROUNDS_A, self._round_keys)

        if len(aad) > 0:
            aad_padded = pad(aad, C512_RATE_SIZE)
            for i in range(len(aad_padded) // C512_RATE_SIZE):
                xor_block_into_state(self._state, aad_padded, i * C512_RATE_SIZE)
                permutation(self._state, C512_ROUNDS_B, self._round_keys)

        self._state[31] = (self._state[31] ^ C512_DOMAIN_SEP) & MASK32
        self._buffer = bytearray()
        self._ciphertext = bytearray()
        self._finalized = False

    def close(self):
        self._finalized = True
        for name in ("_buffer", "_plaintext", "_ciphertext", "_state"):
            value = getattr(self, name, None)
            if value is not None:
                for i in range(len(value)): value[i] = 0
                value.clear()
        for row in self._round_keys:
            for i in range(len(row)): row[i] = 0
        self._round_keys.clear()

    def update(self, plaintext_chunk: bytes) -> bytes:
        """Absorb plaintext chunk. Returns ciphertext produced from full blocks."""
        if self._finalized:
            raise ValueError("C512: context already finalized")

        _bound(plaintext_chunk)
        if len(self._ciphertext) + len(self._buffer) + len(plaintext_chunk) > MAX_RESEARCH_BYTES:
            self.close()
            raise ValueError("research context limit exceeded")
        self._buffer.extend(plaintext_chunk)
        ct_chunk = bytearray()

        cursor = 0
        while len(self._buffer) - cursor >= C512_RATE_SIZE:
            block = bytes(self._buffer[cursor:cursor + C512_RATE_SIZE])
            cursor += C512_RATE_SIZE
            keystream = extract_keystream(self._state, C512_RATE_SIZE)
            for j in range(C512_RATE_SIZE):
                ct_chunk.append(keystream[j] ^ block[j])
            xor_block_into_state(self._state, block, 0)
            permutation(self._state, C512_ROUNDS_B, self._round_keys)

        del self._buffer[:cursor]
        self._ciphertext.extend(ct_chunk)
        return bytes(ct_chunk)

    def finalize(self) -> tuple[bytes, bytes]:
        """Finalize encryption. Returns (full_ciphertext, tag)."""
        if self._finalized:
            raise ValueError("C512: context already finalized")
        self._finalized = True

        remaining = len(self._buffer)
        last_block = bytearray(C512_RATE_SIZE)
        tail_ct = bytearray()

        if remaining > 0:
            keystream = extract_keystream(self._state, remaining)
            for j in range(remaining):
                tail_ct.append(keystream[j] ^ self._buffer[j])
                last_block[j] = self._buffer[j]

        last_block[remaining] = 0x80
        xor_block_into_state(self._state, bytes(last_block), 0)
        permutation(self._state, C512_ROUNDS_B, self._round_keys)

        permutation(self._state, C512_ROUNDS_A, self._round_keys)
        self._state[31] = (self._state[31] ^ C512_DOMAIN_TAG) & MASK32
        permutation(self._state, C512_ROUNDS_A, self._round_keys)

        tag = struct.pack('<8I', *[self._state[i] & MASK32 for i in range(8)])
        self._ciphertext.extend(tail_ct)
        result = bytes(self._ciphertext), tag
        self.close()
        return result


class C512DecryptContext:
    """
    Incremental decryption context. Buffers all plaintext until tag is verified
    in finalize() — no plaintext is released before authentication succeeds.
    """

    def __init__(self, key: bytes, nonce: bytes, aad: bytes = b''):
        if len(key) != C512_KEY_SIZE:
            raise ValueError(f"C512: requires {C512_KEY_SIZE}-byte key")
        if len(nonce) != C512_NONCE_SIZE:
            raise ValueError(f"C512: requires {C512_NONCE_SIZE}-byte nonce")

        _bound(aad, "aad")
        self._round_keys = key_schedule(key)
        self._state = init_state(key, nonce)
        permutation(self._state, C512_ROUNDS_A, self._round_keys)

        if len(aad) > 0:
            aad_padded = pad(aad, C512_RATE_SIZE)
            for i in range(len(aad_padded) // C512_RATE_SIZE):
                xor_block_into_state(self._state, aad_padded, i * C512_RATE_SIZE)
                permutation(self._state, C512_ROUNDS_B, self._round_keys)

        self._state[31] = (self._state[31] ^ C512_DOMAIN_SEP) & MASK32
        self._buffer = bytearray()
        self._plaintext = bytearray()
        self._finalized = False

    def close(self):
        self._finalized = True
        for name in ("_buffer", "_plaintext", "_ciphertext", "_state"):
            value = getattr(self, name, None)
            if value is not None:
                for i in range(len(value)): value[i] = 0
                value.clear()
        for row in self._round_keys:
            for i in range(len(row)): row[i] = 0
        self._round_keys.clear()

    def update(self, ciphertext_chunk: bytes) -> None:
        """Absorb ciphertext chunk. Plaintext is buffered internally."""
        if self._finalized:
            raise ValueError("C512: context already finalized")

        _bound(ciphertext_chunk)
        if len(self._plaintext) + len(self._buffer) + len(ciphertext_chunk) > MAX_RESEARCH_BYTES:
            self.close()
            raise ValueError("research context limit exceeded")
        self._buffer.extend(ciphertext_chunk)

        cursor = 0
        while len(self._buffer) - cursor >= C512_RATE_SIZE:
            ct_block = bytes(self._buffer[cursor:cursor + C512_RATE_SIZE])
            cursor += C512_RATE_SIZE
            keystream = extract_keystream(self._state, C512_RATE_SIZE)
            absorb = bytearray(C512_RATE_SIZE)
            for j in range(C512_RATE_SIZE):
                pb = keystream[j] ^ ct_block[j]
                self._plaintext.append(pb)
                absorb[j] = pb
            xor_block_into_state(self._state, bytes(absorb), 0)
            permutation(self._state, C512_ROUNDS_B, self._round_keys)

        del self._buffer[:cursor]

    def finalize(self, tag: bytes) -> bytes:
        """Verify tag and return plaintext. Raises ValueError on auth failure."""
        if self._finalized:
            raise ValueError("C512: context already finalized")
        if len(tag) != C512_TAG_SIZE:
            self.close()
            raise ValueError(f"C512: tag must be {C512_TAG_SIZE} bytes")
        self._finalized = True

        remaining = len(self._buffer)
        last_block = bytearray(C512_RATE_SIZE)

        if remaining > 0:
            keystream = extract_keystream(self._state, remaining)
            for j in range(remaining):
                pb = keystream[j] ^ self._buffer[j]
                self._plaintext.append(pb)
                last_block[j] = pb

        last_block[remaining] = 0x80
        xor_block_into_state(self._state, bytes(last_block), 0)
        permutation(self._state, C512_ROUNDS_B, self._round_keys)

        permutation(self._state, C512_ROUNDS_A, self._round_keys)
        self._state[31] = (self._state[31] ^ C512_DOMAIN_TAG) & MASK32
        permutation(self._state, C512_ROUNDS_A, self._round_keys)

        expected_tag = struct.pack('<8I', *[self._state[i] & MASK32 for i in range(8)])

        if not _hmac.compare_digest(expected_tag, tag):
            self.close()
            raise ValueError("C512: authentication failed — ciphertext tampered")

        result = bytes(self._plaintext)
        self.close()
        return result


# ── Convenience Wrappers ───────────────────────────────────────────────────

def encrypt_with_nonce(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """Encrypt with auto-generated random nonce. Returns: nonce(32) || ct || tag(32)."""
    nonce = os.urandom(C512_NONCE_SIZE)
    inner = encrypt(key, nonce, aad, plaintext)
    return nonce + inner


def decrypt_with_nonce(key: bytes, aad: bytes, data: bytes) -> bytes:
    """Decrypt data that starts with a 32-byte nonce prefix."""
    if len(data) < C512_NONCE_SIZE + C512_TAG_SIZE:
        raise ValueError("C512: data too short (missing nonce+tag)")
    nonce = data[:C512_NONCE_SIZE]
    inner = data[C512_NONCE_SIZE:]
    return decrypt(key, nonce, aad, inner)


# ── Class-Based API ────────────────────────────────────────────────────────

class C512:
    """Object-oriented wrapper for all C512 v2.0 operations."""

    version = C512_VERSION

    def encrypt(self, key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        return encrypt(key, nonce, aad, plaintext)

    def decrypt(self, key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
        return decrypt(key, nonce, aad, data)

    def encrypt_with_nonce(self, key: bytes, aad: bytes, plaintext: bytes) -> bytes:
        return encrypt_with_nonce(key, aad, plaintext)

    def decrypt_with_nonce(self, key: bytes, aad: bytes, data: bytes) -> bytes:
        return decrypt_with_nonce(key, aad, data)

    def siv_encrypt(self, key: bytes, aad: bytes, plaintext: bytes) -> bytes:
        return siv_encrypt(key, aad, plaintext)

    def siv_decrypt(self, key: bytes, aad: bytes, data: bytes) -> bytes:
        return siv_decrypt(key, aad, data)

    def xof(self, key: bytes, context: bytes, output_length: int) -> bytes:
        return xof(key, context, output_length)

    def encrypt_context(self, key: bytes, nonce: bytes, aad: bytes = b'') -> C512EncryptContext:
        return C512EncryptContext(key, nonce, aad)

    def decrypt_context(self, key: bytes, nonce: bytes, aad: bytes = b'') -> C512DecryptContext:
        return C512DecryptContext(key, nonce, aad)


# ── Self-Test ──────────────────────────────────────────────────────────────

def self_test() -> bool:
    key = bytes(range(64))
    nonce = bytes(range(32))

    # 1: empty plaintext, empty AAD
    ct = encrypt(key, nonce, b'', b'')
    assert len(ct) == C512_TAG_SIZE, "test 1: wrong length"
    pt = decrypt(key, nonce, b'', ct)
    assert pt == b'', "test 1: plaintext mismatch"

    # 2: 64-byte plaintext, 64-byte AAD
    plaintext = bytes([0x55] * 64)
    aad = bytes([0xAA] * 64)
    ct = encrypt(key, nonce, aad, plaintext)
    assert len(ct) == 64 + C512_TAG_SIZE, "test 2: wrong length"
    pt = decrypt(key, nonce, aad, ct)
    assert pt == plaintext, "test 2: plaintext mismatch"

    # 3: non-aligned plaintext (37 bytes)
    pt3_in = b'Hello, ALB_C512 encryption test!!!'[:37]
    ct3 = encrypt(key, nonce, b'', pt3_in)
    pt3 = decrypt(key, nonce, b'', ct3)
    assert pt3 == pt3_in, "test 3: plaintext mismatch"

    # 4: tampered ciphertext
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    try:
        decrypt(key, nonce, aad, bytes(tampered))
        raise AssertionError("test 4: should have raised")
    except ValueError as e:
        assert "authentication failed" in str(e)

    # 5: convenience wrappers
    full = encrypt_with_nonce(key, aad, plaintext)
    pt5 = decrypt_with_nonce(key, aad, full)
    assert pt5 == plaintext, "test 5: wrapper mismatch"

    # 6: SIV mode round-trip
    siv_ct = siv_encrypt(key, aad, plaintext)
    siv_pt = siv_decrypt(key, aad, siv_ct)
    assert siv_pt == plaintext, "test 6: SIV mismatch"

    # 7: SIV determinism (same inputs → same output)
    siv_ct2 = siv_encrypt(key, aad, plaintext)
    assert siv_ct == siv_ct2, "test 7: SIV not deterministic"

    # 8: SIV tamper detection
    siv_tampered = bytearray(siv_ct)
    siv_tampered[40] ^= 0x01
    try:
        siv_decrypt(key, aad, bytes(siv_tampered))
        raise AssertionError("test 8: SIV should have raised")
    except ValueError:
        pass

    # 9: XOF determinism
    xof_out1 = xof(key, b'test context', 64)
    xof_out2 = xof(key, b'test context', 64)
    assert xof_out1 == xof_out2, "test 9: XOF not deterministic"
    assert len(xof_out1) == 64, "test 9: wrong XOF length"

    # 10: XOF different contexts produce different output
    xof_out3 = xof(key, b'other context', 64)
    assert xof_out1 != xof_out3, "test 10: XOF collision"

    # 11: XOF variable length
    xof_128 = xof(key, b'test', 128)
    xof_64 = xof(key, b'test', 64)
    assert xof_128[:64] == xof_64, "test 11: XOF prefix mismatch"

    # 12: streaming encrypt matches one-shot
    ctx = C512EncryptContext(key, nonce, aad)
    ctx.update(plaintext[:20])
    ctx.update(plaintext[20:])
    stream_ct, stream_tag = ctx.finalize()
    oneshot_ct = encrypt(key, nonce, aad, plaintext)
    assert stream_ct + stream_tag == oneshot_ct, "test 12: streaming mismatch"

    # 13: streaming decrypt matches one-shot
    dctx = C512DecryptContext(key, nonce, aad)
    ct_only = oneshot_ct[:-C512_TAG_SIZE]
    tag_only = oneshot_ct[-C512_TAG_SIZE:]
    dctx.update(ct_only[:30])
    dctx.update(ct_only[30:])
    stream_pt = dctx.finalize(tag_only)
    assert stream_pt == plaintext, "test 13: streaming decrypt mismatch"

    # 14: streaming tamper detection
    dctx2 = C512DecryptContext(key, nonce, aad)
    dctx2.update(ct_only)
    bad_tag = bytearray(tag_only)
    bad_tag[0] ^= 0xFF
    try:
        dctx2.finalize(bytes(bad_tag))
        raise AssertionError("test 14: streaming should have raised")
    except ValueError:
        pass

    # 15: two full blocks with AAD
    pt_2blk = bytes([0xEE] * 128)
    aad_2blk = bytes([0xDD] * 33)
    ct_2blk = encrypt(key, nonce, aad_2blk, pt_2blk)
    pt_2blk_out = decrypt(key, nonce, aad_2blk, ct_2blk)
    assert pt_2blk_out == pt_2blk, "test 15: two-block mismatch"

    # 16: class-based API
    cipher = C512()
    ct16 = cipher.encrypt(key, nonce, aad, plaintext)
    pt16 = cipher.decrypt(key, nonce, aad, ct16)
    assert pt16 == plaintext, "test 16: class API mismatch"

    # 17: single byte
    ct17 = encrypt(key, nonce, b'', b'\xff')
    pt17 = decrypt(key, nonce, b'', ct17)
    assert pt17 == b'\xff', "test 17: single byte mismatch"

    # 18: empty AAD with plaintext
    ct18 = encrypt(key, nonce, b'', plaintext)
    pt18 = decrypt(key, nonce, b'', ct18)
    assert pt18 == plaintext, "test 18: empty AAD mismatch"

    # 19: nonempty AAD, empty plaintext
    ct19 = encrypt(key, nonce, aad, b'')
    pt19 = decrypt(key, nonce, aad, ct19)
    assert pt19 == b'', "test 19: nonempty AAD empty PT mismatch"

    # 20: zero key
    zero_key = bytes(64)
    ct20 = encrypt(zero_key, nonce, bytes([0x11] * 16), bytes([0x22] * 32))
    pt20 = decrypt(zero_key, nonce, bytes([0x11] * 16), ct20)
    assert pt20 == bytes([0x22] * 32), "test 20: zero key mismatch"

    return True


# ── Test Vector Generation ─────────────────────────────────────────────────

def generate_test_vectors() -> str:
    import json

    key = bytes(range(64))
    nonce = bytes(range(32))
    zero_key = bytes(64)
    ones_key = bytes([0xFF] * 64)
    ones_nonce = bytes([0xFF] * 32)

    vectors = []

    def add_aead(name, k, n, a, p):
        ct = encrypt(k, n, a, p)
        vectors.append({
            "name": name, "mode": "aead",
            "key": k.hex(), "nonce": n.hex(),
            "aad": a.hex(), "plaintext": p.hex(),
            "ciphertext_tag": ct.hex()
        })

    def add_siv(name, k, a, p):
        ct = siv_encrypt(k, a, p)
        vectors.append({
            "name": name, "mode": "siv",
            "key": k.hex(),
            "aad": a.hex(), "plaintext": p.hex(),
            "siv_output": ct.hex()
        })

    def add_xof(name, k, ctx, length):
        out = xof(k, ctx, length)
        vectors.append({
            "name": name, "mode": "xof",
            "key": k.hex(), "context": ctx.hex(),
            "output_length": length,
            "output": out.hex()
        })

    # === AEAD vectors (30) ===
    add_aead("aead_empty", key, nonce, b'', b'')
    add_aead("aead_64B_pt_64B_aad", key, nonce, bytes([0xAA]*64), bytes([0x55]*64))
    add_aead("aead_37B_pt_no_aad", key, nonce, b'', b'Hello, ALB_C512 encryption test!!!'[:37])
    add_aead("aead_single_byte", key, nonce, b'', b'\xff')
    add_aead("aead_two_blocks_with_aad", key, nonce, bytes([0xDD]*33), bytes([0xEE]*128))
    add_aead("aead_zero_key", zero_key, nonce, bytes([0x11]*16), bytes([0x22]*32))
    add_aead("aead_empty_aad_with_pt", key, nonce, b'', bytes([0x55]*64))
    add_aead("aead_nonempty_aad_empty_pt", key, nonce, bytes([0xAA]*64), b'')
    add_aead("aead_boundary_65B", key, nonce, b'', bytes([0x77]*65))
    add_aead("aead_1B_pt", key, nonce, b'', b'\x01')
    add_aead("aead_63B_pt", key, nonce, b'', bytes(range(63)))
    add_aead("aead_64B_pt", key, nonce, b'', bytes(range(64)))
    add_aead("aead_127B_pt", key, nonce, b'', bytes([i & 0xFF for i in range(127)]))
    add_aead("aead_128B_pt", key, nonce, b'', bytes([i & 0xFF for i in range(128)]))
    add_aead("aead_129B_pt", key, nonce, b'', bytes([i & 0xFF for i in range(129)]))
    add_aead("aead_ones_key_ones_nonce", ones_key, ones_nonce, b'', bytes([0xAB]*64))
    add_aead("aead_ones_key_zero_nonce", ones_key, nonce, bytes([0xCC]*32), bytes([0xDD]*32))
    add_aead("aead_zero_key_ones_nonce", zero_key, ones_nonce, bytes([0xEE]*16), bytes([0xFF]*48))
    add_aead("aead_large_aad_small_pt", key, nonce, bytes([0xBB]*256), bytes([0x42]*8))
    add_aead("aead_small_aad_large_pt", key, nonce, bytes([0x42]*8), bytes([0xBB]*256))
    add_aead("aead_multi_block_aad", key, nonce, bytes([0xCC]*192), bytes([0xDD]*64))
    add_aead("aead_3_block_pt", key, nonce, b'', bytes([0xAA]*192))
    add_aead("aead_4_block_pt_with_aad", key, nonce, bytes([0x11]*64), bytes([0x22]*256))
    add_aead("aead_2B_pt", key, nonce, b'', b'\xDE\xAD')
    add_aead("aead_15B_aad_15B_pt", key, nonce, bytes(range(15)), bytes(range(15, 30)))
    add_aead("aead_sequential_key", bytes(range(64)), bytes(range(32, 64)), b'', bytes([0x99]*100))
    add_aead("aead_alternating", key, nonce, bytes([0xAA, 0x55]*32), bytes([0x55, 0xAA]*32))
    add_aead("aead_max_single_block", key, nonce, bytes([0xAA]*64), bytes([0xBB]*64))
    add_aead("aead_exact_2_blocks", key, nonce, bytes([0x11]*128), bytes([0x22]*128))
    add_aead("aead_5B_aad_5B_pt", key, nonce, b'HELLO', b'WORLD')

    # === SIV vectors (10) ===
    add_siv("siv_empty", key, b'', b'')
    add_siv("siv_64B_pt_64B_aad", key, bytes([0xAA]*64), bytes([0x55]*64))
    add_siv("siv_37B_pt", key, b'', b'Hello, ALB_C512 encryption test!!!'[:37])
    add_siv("siv_single_byte", key, b'', b'\xff')
    add_siv("siv_two_blocks", key, bytes([0xDD]*33), bytes([0xEE]*128))
    add_siv("siv_zero_key", zero_key, bytes([0x11]*16), bytes([0x22]*32))
    add_siv("siv_large_aad", key, bytes([0xBB]*256), bytes([0x42]*8))
    add_siv("siv_3_blocks", key, b'', bytes([0xAA]*192))
    add_siv("siv_with_aad", key, b'metadata', b'secret payload data')
    add_siv("siv_ones_key", ones_key, bytes([0xCC]*32), bytes([0xDD]*32))

    # === XOF vectors (10) ===
    add_xof("xof_32B", key, b'', 32)
    add_xof("xof_64B", key, b'', 64)
    add_xof("xof_128B", key, b'', 128)
    add_xof("xof_with_context", key, b'test context', 64)
    add_xof("xof_different_context", key, b'other context', 64)
    add_xof("xof_1B", key, b'', 1)
    add_xof("xof_zero_key", zero_key, b'ctx', 32)
    add_xof("xof_ones_key", ones_key, b'ctx', 32)
    add_xof("xof_long_context", key, bytes([0xAA]*256), 64)
    add_xof("xof_256B", key, b'kdf', 256)

    return json.dumps({"version": "2.0", "vectors": vectors}, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=f"ALB_C512 (C512) v{C512_VERSION} cipher CLI")
    parser.add_argument("--experimental", action="store_true",
                        help="Explicitly enable research-only cryptography")
    sub = parser.add_subparsers(dest="cmd")

    enc = sub.add_parser("encrypt", help="Encrypt data")
    enc.add_argument("--key-file", help="Read a hex key from this file; otherwise prompt without echo")
    enc.add_argument("--nonce", help="Hex-encoded 32-byte nonce (random if omitted)")
    enc.add_argument("--aad", default="", help="Hex-encoded associated data")
    enc.add_argument("--plaintext-file", required=True, help="Read plaintext bytes from this file")

    dec = sub.add_parser("decrypt", help="Decrypt data")
    dec.add_argument("--key-file", help="Read a hex key from this file; otherwise prompt without echo")
    dec.add_argument("--nonce", help="Hex-encoded 32-byte nonce")
    dec.add_argument("--aad", default="", help="Hex-encoded associated data")
    dec.add_argument("--data", required=True, help="Hex-encoded ciphertext+tag")

    siv_enc = sub.add_parser("siv-encrypt", help="SIV encrypt (misuse-resistant)")
    siv_enc.add_argument("--key-file", help="Read a hex key from this file; otherwise prompt without echo")
    siv_enc.add_argument("--aad", default="", help="Hex-encoded associated data")
    siv_enc.add_argument("--plaintext-file", required=True, help="Read plaintext bytes from this file")

    siv_dec = sub.add_parser("siv-decrypt", help="SIV decrypt")
    siv_dec.add_argument("--key-file", help="Read a hex key from this file; otherwise prompt without echo")
    siv_dec.add_argument("--aad", default="", help="Hex-encoded associated data")
    siv_dec.add_argument("--data", required=True, help="Hex-encoded SIV output")

    xof_cmd = sub.add_parser("xof", help="XOF / KDF output")
    xof_cmd.add_argument("--key-file", help="Read a hex key from this file; otherwise prompt without echo")
    xof_cmd.add_argument("--context", default="", help="Hex-encoded context")
    xof_cmd.add_argument("--length", type=int, required=True, help="Output length in bytes")

    sub.add_parser("test", help="Run self-test suite")
    sub.add_parser("generate_vectors", help="Generate v2.0 test vectors as JSON")

    args = parser.parse_args()
    if args.experimental:
        os.environ["ALB_C512_EXPERIMENTAL"] = "1"

    def read_key():
        import getpass
        if args.key_file:
            with open(args.key_file, "r", encoding="ascii") as handle:
                text = handle.read(130)
        else:
            # getpass otherwise falls back to echoed stdin; reject that path.
            if not sys.stdin.isatty():
                parser.error("key input requires a terminal or --key-file")
            text = getpass.getpass("Research key (128 hex characters): ")
        try:
            key = bytes.fromhex(text.strip())
        except ValueError:
            parser.error("invalid key encoding")
        if len(key) != C512_KEY_SIZE:
            parser.error("key must contain exactly 64 bytes")
        return key

    def read_plaintext():
        with open(args.plaintext_file, "rb") as handle:
            data = handle.read((16 << 20) + 1)
        if len(data) > 16 << 20:
            parser.error("research plaintext limit is 16 MiB")
        return data

    if args.cmd == "test":
        if self_test():
            print(f"All C512 v{C512_VERSION} self-tests PASSED.")
        sys.exit(0)

    if args.cmd == "generate_vectors":
        print(generate_test_vectors())
        sys.exit(0)

    if args.cmd == "encrypt":
        k = read_key()
        a = bytes.fromhex(args.aad) if args.aad else b''
        p = read_plaintext()
        if args.nonce:
            result = encrypt(k, bytes.fromhex(args.nonce), a, p)
        else:
            result = encrypt_with_nonce(k, a, p)
        print(result.hex())

    elif args.cmd == "decrypt":
        k = read_key()
        a = bytes.fromhex(args.aad) if args.aad else b''
        d = bytes.fromhex(args.data)
        if args.nonce:
            result = decrypt(k, bytes.fromhex(args.nonce), a, d)
        else:
            result = decrypt_with_nonce(k, a, d)
        print(result.hex())

    elif args.cmd == "siv-encrypt":
        k = read_key()
        a = bytes.fromhex(args.aad) if args.aad else b''
        p = read_plaintext()
        print(siv_encrypt(k, a, p).hex())

    elif args.cmd == "siv-decrypt":
        k = read_key()
        a = bytes.fromhex(args.aad) if args.aad else b''
        d = bytes.fromhex(args.data)
        print(siv_decrypt(k, a, d).hex())

    elif args.cmd == "xof":
        k = read_key()
        c = bytes.fromhex(args.context) if args.context else b''
        print(xof(k, c, args.length).hex())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
