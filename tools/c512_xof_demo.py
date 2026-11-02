#!/usr/bin/env python3
"""
ALB_C512-XOF Demo — Extendable Output Function / Key Derivation

Demonstrates using C512-XOF as a KDF (key derivation function)
and PRF (pseudorandom function).
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
import c512


def main():
    print("=== C512-XOF Key Derivation Demo ===\n")

    master_key = os.urandom(c512.C512_KEY_SIZE)
    print(f"Master key: {master_key[:16].hex()}... ({c512.C512_KEY_SIZE} bytes)")

    # Derive multiple subkeys from one master key
    enc_key = c512.xof(master_key, b"encryption-key", 64)
    mac_key = c512.xof(master_key, b"mac-key", 64)
    session_id = c512.xof(master_key, b"session-id", 16)

    print(f"\nDerived encryption key: {enc_key[:16].hex()}... ({len(enc_key)} bytes)")
    print(f"Derived MAC key:        {mac_key[:16].hex()}... ({len(mac_key)} bytes)")
    print(f"Derived session ID:     {session_id.hex()} ({len(session_id)} bytes)")

    # Verify determinism
    enc_key2 = c512.xof(master_key, b"encryption-key", 64)
    assert enc_key == enc_key2, "XOF not deterministic!"
    print("\n[OK] XOF is deterministic (same key + context = same output)")

    # Verify independence
    assert enc_key != mac_key, "Different contexts should produce different keys!"
    print("[OK] Different contexts produce independent keys")

    # Variable-length output
    print("\n=== Variable-Length Output ===\n")
    for length in [16, 32, 64, 128, 256]:
        out = c512.xof(master_key, b"stream", length)
        print(f"  {length:3d} bytes: {out[:16].hex()}{'...' if length > 16 else ''}")

    # Prefix consistency
    out_256 = c512.xof(master_key, b"stream", 256)
    out_64 = c512.xof(master_key, b"stream", 64)
    assert out_256[:64] == out_64, "Prefix mismatch!"
    print("\n[OK] Prefix consistency: XOF(key, ctx, 256)[:64] == XOF(key, ctx, 64)")

    # Use as HKDF-like
    print("\n=== HKDF-like Key Expansion ===\n")
    ikm = b"input keying material from password or DH exchange"
    salt = os.urandom(32)
    context_str = b"my-app-v2|" + salt
    padded_ikm = ikm + b'\x00' * (64 - len(ikm))
    derived = c512.xof(padded_ikm, context_str, 96)
    aes_key = derived[:32]
    hmac_key = derived[32:64]
    iv = derived[64:80]
    print(f"  AES-256 key: {aes_key.hex()}")
    print(f"  HMAC key:    {hmac_key.hex()}")
    print(f"  IV:          {iv.hex()}")


if __name__ == "__main__":
    main()
