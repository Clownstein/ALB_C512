"""
ALB_C512-Lite — Reduced-State Variant for Resource-Constrained Devices

A lightweight version of C512 with:
  - 256-bit key, 128-bit nonce, 128-bit tag
  - 512-bit internal state (16 lanes x 32 bits)
  - Same permutation structure as full C512, scaled to 16 lanes
  - Dual-phase rounds: A=16 (init/finalize), B=8 (data blocks)

Targets: embedded systems, IoT, microcontrollers with <4 KB RAM.

Usage:
  python c512_lite.py test
"""

from __future__ import annotations
import struct
import os
import sys
import hmac as _hmac

# ── Constants ──────────────────────────────────────────────────────────────

LITE_VERSION = "2.0"

LITE_KEY_SIZE = 32       # 256 bits
LITE_NONCE_SIZE = 16     # 128 bits
LITE_TAG_SIZE = 16       # 128 bits
LITE_STATE_SIZE = 64     # 512 bits
LITE_RATE_SIZE = 32      # 256 bits = 8 lanes
LITE_LANES = 16
LITE_HALF_LANES = 8
LITE_ROUNDS_A = 16
LITE_ROUNDS_B = 8
LITE_KDF_ROUNDS = 4

MASK32 = 0xFFFFFFFF

LITE_DOMAIN_KS  = 0x4C353230   # "L520" — lite key schedule
LITE_DOMAIN_TAG = 0x4C544732   # "LTG2" — lite tag derivation
LITE_DOMAIN_SEP = 0x00000002   # AAD-to-plaintext separator
LITE_IV = 0x40280810_00000002  # state_size=64, rounds_a=16, rounds_b=8, version=2

# Reuse full C512 round constants
ROUND_CONSTANTS = [
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

OMEGA = [
    0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
    0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
]

ROTATION_OFFSETS = [
    0, 1, 3, 6, 10, 15, 21, 28,
    2, 5, 9, 14, 20, 27, 3, 12,
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
    if len(b) != LITE_STATE_SIZE:
        raise ValueError("C512-Lite: state requires exactly 64 bytes")
    return list(struct.unpack_from('<16I', b))


def state_to_bytes(state: list[int]) -> bytes:
    return struct.pack('<16I', *[x & MASK32 for x in state])


# ── Permutation Layers (16-lane variant) ──────────────────────────────────

def apply_round_constant(state: list[int], round_idx: int) -> None:
    rc = ROUND_CONSTANTS[round_idx % 24]
    state[8] ^= (rc & MASK32)
    state[9] ^= ((rc >> 32) & MASK32)


def apply_theta(state: list[int]) -> None:
    parity = [0] * 16
    for i in range(16):
        parity[i] = (
            state[(i - 3) % 16] ^
            _rotl32(state[(i + 3) % 16], 7) ^
            state[(i - 7) % 16] ^
            _rotl32(state[(i + 7) % 16], 19)
        ) & MASK32
    for i in range(16):
        state[i] = (state[i] ^ parity[i]) & MASK32
    for i in range(16):
        state[i] = _rotl32(state[i], ROTATION_OFFSETS[i])


def apply_chi(state: list[int]) -> None:
    temp = state[:]
    for i in range(16):
        state[i] = (temp[i] ^ ((~temp[(i + 1) % 16]) & temp[(i + 2) % 16])) & MASK32


def ntt_butterfly_half(state: list[int], offset: int) -> None:
    step = 4
    while step >= 1:
        group = 0
        while group < 8:
            for j in range(step):
                idx1 = offset + group + j
                idx2 = offset + group + j + step
                omega_idx = (j * (8 // (step * 2))) % 8
                temp = (state[idx2] * OMEGA[omega_idx]) & MASK32
                state[idx2] = (state[idx1] - temp) & MASK32
                state[idx1] = (state[idx1] + temp) & MASK32
            group += step * 2
        step //= 2


def apply_ntt_butterfly(state: list[int]) -> None:
    ntt_butterfly_half(state, 0)
    ntt_butterfly_half(state, 8)
    for i in range(8):
        a = state[i]
        b = state[8 + i]
        state[i] = (a ^ _rotl32(b, 11)) & MASK32
        state[8 + i] = (b ^ _rotl32(a, 23)) & MASK32


def apply_round_key(state: list[int], round_key: list[int]) -> None:
    for i in range(16):
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
    if len(master_key) != LITE_KEY_SIZE:
        raise ValueError(f"C512-Lite: key must be {LITE_KEY_SIZE} bytes")
    _require_experimental()
    rev_key = master_key[::-1]
    combined = master_key + rev_key
    c = state_from_bytes(combined)

    round_keys: list[list[int]] = []
    for r in range(16):
        bootstrap_permutation(c, LITE_KDF_ROUNDS)
        round_keys.append(c[:])
        c[0] = (c[0] ^ (r & MASK32)) & MASK32
        c[1] = (c[1] ^ LITE_DOMAIN_KS) & MASK32

    return round_keys


# ── State Initialization ──────────────────────────────────────────────────

def init_state(key: bytes, nonce: bytes) -> list[int]:
    if len(key) != LITE_KEY_SIZE:
        raise ValueError(f"C512-Lite: key must be {LITE_KEY_SIZE} bytes")
    if len(nonce) != LITE_NONCE_SIZE:
        raise ValueError(f"C512-Lite: nonce must be {LITE_NONCE_SIZE} bytes")
    init_bytes = struct.pack('<Q', LITE_IV) + key + nonce + b'\x00' * 8
    return state_from_bytes(init_bytes)


# ── Padding ────────────────────────────────────────────────────────────────

def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + b'\x80' + b'\x00' * (pad_len - 1)


# ── XOR / Keystream Helpers ───────────────────────────────────────────────

def xor_block_into_state(state: list[int], block: bytes, offset: int) -> None:
    for i in range(8):
        v = struct.unpack_from('<I', block, offset + i * 4)[0]
        state[i] = (state[i] ^ v) & MASK32


def extract_keystream(state: list[int], length: int) -> bytes:
    rate_bytes = struct.pack('<8I', *[state[i] & MASK32 for i in range(8)])
    return rate_bytes[:length]


# ── AEAD Encrypt ───────────────────────────────────────────────────────────

def encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    _bound(aad, "aad")
    _bound(plaintext, "plaintext")
    if len(key) != LITE_KEY_SIZE:
        raise ValueError(f"C512-Lite: key must be {LITE_KEY_SIZE} bytes")
    if len(nonce) != LITE_NONCE_SIZE:
        raise ValueError(f"C512-Lite: nonce must be {LITE_NONCE_SIZE} bytes")

    round_keys = key_schedule(key)
    state = init_state(key, nonce)
    permutation(state, LITE_ROUNDS_A, round_keys)

    if len(aad) > 0:
        aad_padded = pad(aad, LITE_RATE_SIZE)
        blocks = len(aad_padded) // LITE_RATE_SIZE
        for i in range(blocks):
            xor_block_into_state(state, aad_padded, i * LITE_RATE_SIZE)
            permutation(state, LITE_ROUNDS_B, round_keys)

    state[15] = (state[15] ^ LITE_DOMAIN_SEP) & MASK32

    ciphertext = bytearray()
    pt_len = len(plaintext)
    full_blocks = pt_len // LITE_RATE_SIZE
    remaining = pt_len % LITE_RATE_SIZE

    for i in range(full_blocks):
        keystream = extract_keystream(state, LITE_RATE_SIZE)
        off = i * LITE_RATE_SIZE
        for j in range(LITE_RATE_SIZE):
            ciphertext.append(keystream[j] ^ plaintext[off + j])
        absorb = bytearray(LITE_RATE_SIZE)
        absorb[:] = plaintext[off:off + LITE_RATE_SIZE]
        xor_block_into_state(state, bytes(absorb), 0)
        permutation(state, LITE_ROUNDS_B, round_keys)

    last_block = bytearray(LITE_RATE_SIZE)
    if remaining > 0:
        off = full_blocks * LITE_RATE_SIZE
        keystream = extract_keystream(state, remaining)
        for j in range(remaining):
            ciphertext.append(keystream[j] ^ plaintext[off + j])
            last_block[j] = plaintext[off + j]
    last_block[remaining] = 0x80
    xor_block_into_state(state, bytes(last_block), 0)
    permutation(state, LITE_ROUNDS_B, round_keys)

    permutation(state, LITE_ROUNDS_A, round_keys)

    state[15] = (state[15] ^ LITE_DOMAIN_TAG) & MASK32
    permutation(state, LITE_ROUNDS_A, round_keys)

    tag = struct.pack('<4I', *[state[i] & MASK32 for i in range(4)])
    return bytes(ciphertext) + tag


# ── AEAD Decrypt ───────────────────────────────────────────────────────────

def decrypt(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    _bound(aad, "aad")
    _bound(data, "data")
    if len(key) != LITE_KEY_SIZE:
        raise ValueError(f"C512-Lite: key must be {LITE_KEY_SIZE} bytes")
    if len(nonce) != LITE_NONCE_SIZE:
        raise ValueError(f"C512-Lite: nonce must be {LITE_NONCE_SIZE} bytes")
    if len(data) < LITE_TAG_SIZE:
        raise ValueError("C512-Lite: data too short")

    ciphertext = data[:-LITE_TAG_SIZE]
    tag = data[-LITE_TAG_SIZE:]

    round_keys = key_schedule(key)
    state = init_state(key, nonce)
    permutation(state, LITE_ROUNDS_A, round_keys)

    if len(aad) > 0:
        aad_padded = pad(aad, LITE_RATE_SIZE)
        blocks = len(aad_padded) // LITE_RATE_SIZE
        for i in range(blocks):
            xor_block_into_state(state, aad_padded, i * LITE_RATE_SIZE)
            permutation(state, LITE_ROUNDS_B, round_keys)

    state[15] = (state[15] ^ LITE_DOMAIN_SEP) & MASK32

    plaintext = bytearray()
    ct_len = len(ciphertext)
    full_blocks = ct_len // LITE_RATE_SIZE
    remaining = ct_len % LITE_RATE_SIZE

    for i in range(full_blocks):
        keystream = extract_keystream(state, LITE_RATE_SIZE)
        off = i * LITE_RATE_SIZE
        absorb = bytearray(LITE_RATE_SIZE)
        for j in range(LITE_RATE_SIZE):
            pb = keystream[j] ^ ciphertext[off + j]
            plaintext.append(pb)
            absorb[j] = pb
        xor_block_into_state(state, bytes(absorb), 0)
        permutation(state, LITE_ROUNDS_B, round_keys)

    last_block = bytearray(LITE_RATE_SIZE)
    if remaining > 0:
        off = full_blocks * LITE_RATE_SIZE
        keystream = extract_keystream(state, remaining)
        for j in range(remaining):
            pb = keystream[j] ^ ciphertext[off + j]
            plaintext.append(pb)
            last_block[j] = pb
    last_block[remaining] = 0x80
    xor_block_into_state(state, bytes(last_block), 0)
    permutation(state, LITE_ROUNDS_B, round_keys)

    permutation(state, LITE_ROUNDS_A, round_keys)

    state[15] = (state[15] ^ LITE_DOMAIN_TAG) & MASK32
    permutation(state, LITE_ROUNDS_A, round_keys)
    expected_tag = struct.pack('<4I', *[state[i] & MASK32 for i in range(4)])

    if not _hmac.compare_digest(expected_tag, tag):
        raise ValueError("C512-Lite: authentication failed")

    return bytes(plaintext)


# ── Convenience Wrappers ───────────────────────────────────────────────────

def encrypt_with_nonce(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(LITE_NONCE_SIZE)
    inner = encrypt(key, nonce, aad, plaintext)
    return nonce + inner


def decrypt_with_nonce(key: bytes, aad: bytes, data: bytes) -> bytes:
    if len(data) < LITE_NONCE_SIZE + LITE_TAG_SIZE:
        raise ValueError("C512-Lite: data too short")
    nonce = data[:LITE_NONCE_SIZE]
    inner = data[LITE_NONCE_SIZE:]
    return decrypt(key, nonce, aad, inner)


# ── Self-Test ──────────────────────────────────────────────────────────────

def self_test() -> bool:
    key = bytes(range(32))
    nonce = bytes(range(16))

    # 1: empty
    ct = encrypt(key, nonce, b'', b'')
    assert len(ct) == LITE_TAG_SIZE
    pt = decrypt(key, nonce, b'', ct)
    assert pt == b''

    # 2: 32-byte PT + 32-byte AAD
    plaintext = bytes([0x55] * 32)
    aad = bytes([0xAA] * 32)
    ct = encrypt(key, nonce, aad, plaintext)
    assert len(ct) == 32 + LITE_TAG_SIZE
    pt = decrypt(key, nonce, aad, ct)
    assert pt == plaintext

    # 3: non-aligned (15 bytes)
    pt3_in = b'Hello C512Lite!!'[:15]
    ct3 = encrypt(key, nonce, b'', pt3_in)
    pt3 = decrypt(key, nonce, b'', ct3)
    assert pt3 == pt3_in

    # 4: single byte
    ct4 = encrypt(key, nonce, b'', b'\xff')
    pt4 = decrypt(key, nonce, b'', ct4)
    assert pt4 == b'\xff'

    # 5: tamper detection
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    try:
        decrypt(key, nonce, aad, bytes(tampered))
        raise AssertionError("should have raised")
    except ValueError:
        pass

    # 6: convenience wrappers
    full = encrypt_with_nonce(key, aad, plaintext)
    pt6 = decrypt_with_nonce(key, aad, full)
    assert pt6 == plaintext

    # 7: two full blocks (64 bytes)
    pt7 = bytes([0xEE] * 64)
    ct7 = encrypt(key, nonce, bytes([0xDD] * 16), pt7)
    pt7_out = decrypt(key, nonce, bytes([0xDD] * 16), ct7)
    assert pt7_out == pt7

    # 8: boundary (33 bytes = 1 full block + 1 byte)
    pt8 = bytes([0x77] * 33)
    ct8 = encrypt(key, nonce, b'', pt8)
    pt8_out = decrypt(key, nonce, b'', ct8)
    assert pt8_out == pt8

    # 9: zero key
    zk = bytes(32)
    ct9 = encrypt(zk, nonce, bytes([0x11] * 8), bytes([0x22] * 16))
    pt9 = decrypt(zk, nonce, bytes([0x11] * 8), ct9)
    assert pt9 == bytes([0x22] * 16)

    # 10: large AAD
    ct10 = encrypt(key, nonce, bytes([0xBB] * 128), bytes([0x42] * 4))
    pt10 = decrypt(key, nonce, bytes([0xBB] * 128), ct10)
    assert pt10 == bytes([0x42] * 4)

    return True


# ── Test Vector Generation ─────────────────────────────────────────────────

def generate_test_vectors() -> str:
    import json

    key = bytes(range(32))
    nonce = bytes(range(16))
    zero_key = bytes(32)

    vectors = []

    def add(name, k, n, a, p):
        ct = encrypt(k, n, a, p)
        vectors.append({
            "name": name,
            "key": k.hex(), "nonce": n.hex(),
            "aad": a.hex(), "plaintext": p.hex(),
            "ciphertext_tag": ct.hex()
        })

    add("lite_empty", key, nonce, b'', b'')
    add("lite_32B_pt_32B_aad", key, nonce, bytes([0xAA]*32), bytes([0x55]*32))
    add("lite_15B_pt", key, nonce, b'', b'Hello C512Lite!!'[:15])
    add("lite_single_byte", key, nonce, b'', b'\xff')
    add("lite_two_blocks", key, nonce, bytes([0xDD]*16), bytes([0xEE]*64))
    add("lite_zero_key", zero_key, nonce, bytes([0x11]*8), bytes([0x22]*16))
    add("lite_boundary_33B", key, nonce, b'', bytes([0x77]*33))
    add("lite_large_aad", key, nonce, bytes([0xBB]*128), bytes([0x42]*4))
    add("lite_1B_pt", key, nonce, b'', b'\x01')
    add("lite_31B_pt", key, nonce, b'', bytes(range(31)))

    return json.dumps({"version": "2.0-lite", "vectors": vectors}, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        if self_test():
            print(f"All C512-Lite v{LITE_VERSION} self-tests PASSED.")
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "generate_vectors":
        print(generate_test_vectors())
        sys.exit(0)

    print(f"ALB_C512-Lite v{LITE_VERSION}")
    print("Usage: python c512_lite.py test | generate_vectors")


if __name__ == "__main__":
    main()
