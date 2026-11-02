#!/usr/bin/env python3
"""
ALB_C512-SIV Demo — Misuse-Resistant AEAD

Demonstrates that SIV mode is safe even when nonces are reused
(same inputs always produce the same ciphertext, no XOR leakage).
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
import c512


def main():
    key = os.urandom(c512.C512_KEY_SIZE)
    aad = b"application-metadata-v2"
    messages = [
        b"First secret message",
        b"Second secret message",
        b"First secret message",  # duplicate to show determinism
    ]

    print("=== C512-SIV Misuse-Resistant AEAD Demo ===\n")

    outputs = []
    for i, msg in enumerate(messages):
        ct = c512.siv_encrypt(key, aad, msg)
        outputs.append(ct)
        print(f"Message {i+1}: {msg.decode()}")
        print(f"  SIV output ({len(ct)} bytes): {ct[:32].hex()}...")
        print()

    # Determinism: messages 1 and 3 are identical → identical ciphertext
    if outputs[0] == outputs[2]:
        print("[OK] Identical plaintexts produce identical SIV output (deterministic)")
    else:
        print("[FAIL] Determinism broken!")

    if outputs[0] != outputs[1]:
        print("[OK] Different plaintexts produce different SIV output")

    # Decrypt all
    print()
    for i, ct in enumerate(outputs):
        pt = c512.siv_decrypt(key, aad, ct)
        print(f"Decrypted {i+1}: {pt.decode()}")

    # Tamper detection
    print()
    tampered = bytearray(outputs[0])
    tampered[40] ^= 0x01
    try:
        c512.siv_decrypt(key, aad, bytes(tampered))
        print("[FAIL] Tampered SIV data was not rejected")
    except ValueError as e:
        print(f"[OK] Tampered SIV data rejected: {e}")

    # Compare with standard AEAD (nonce reuse is dangerous there)
    print("\n=== Comparison: Standard AEAD with nonce reuse ===\n")
    nonce = os.urandom(c512.C512_NONCE_SIZE)
    ct1 = c512.encrypt(key, nonce, aad, messages[0])
    ct2 = c512.encrypt(key, nonce, aad, messages[1])

    xor_leak = bytes(a ^ b for a, b in zip(ct1, ct2))
    print(f"Standard AEAD: reusing nonce leaks XOR of plaintexts!")
    print(f"  ct1 XOR ct2 = {xor_leak[:20].hex()}...")
    pt_xor = bytes(a ^ b for a, b in zip(messages[0], messages[1]))
    print(f"  pt1 XOR pt2 = {pt_xor[:20].hex()}...")
    if xor_leak[:min(len(messages[0]), len(messages[1]))] == pt_xor:
        print("  [DANGER] XOR of ciphertexts reveals XOR of plaintexts!")
    print("\n  SIV mode prevents this by deriving the nonce deterministically.")


if __name__ == "__main__":
    main()
