"""
Cross-language test vector verifier for ALB_C512 (C512).

Reads test_vectors.json and verifies each vector against the Python
reference implementation. Other language implementations should produce
bit-identical ciphertext_tag values for the same inputs.

Usage: python test_vectors_verify.py
"""

from importlib import import_module
import json
import os
import sys

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "python"))
C512 = import_module("c512")
encrypt = C512.encrypt
decrypt = C512.decrypt


def expect_reject(name, key, nonce, aad, data):
    try:
        decrypt(key, nonce, aad, data)
    except ValueError:
        print(f"  [PASS] negative: {name}")
        return True

    print(f"  [FAIL] negative: {name}: decrypt unexpectedly succeeded")
    return False

def main():
    vec_path = os.path.join(TOOLS_DIR, 'test_vectors.json')
    with open(vec_path, 'r', encoding='utf-8') as f:
        vectors = json.load(f)

    passed = 0
    failed = 0
    negative_passed = 0
    negative_failed = 0
    representative = None

    for v in vectors:
        name = v['name']
        key = bytes.fromhex(v['key'])
        nonce = bytes.fromhex(v['nonce'])
        aad = bytes.fromhex(v['aad']) if v['aad'] else b''
        pt = bytes.fromhex(v['plaintext']) if v['plaintext'] else b''
        expected = v['ciphertext_tag']

        ct = encrypt(key, nonce, aad, pt)
        actual = ct.hex()
        if representative is None and len(pt) > 0 and len(aad) > 0:
            representative = (name, key, nonce, aad, ct)

        if actual == expected:
            recovered = decrypt(key, nonce, aad, ct)
            if recovered == pt:
                print(f"  [PASS] {name}")
                passed += 1
            else:
                print(f"  [FAIL] {name}: decrypt mismatch")
                failed += 1
        else:
            print(f"  [FAIL] {name}:")
            print(f"    expected: {expected}")
            print(f"    actual:   {actual}")
            failed += 1

    if representative is not None:
        name, key, nonce, aad, ct = representative

        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x01
        if expect_reject(
            f"{name} ciphertext tamper",
            key,
            nonce,
            aad,
            bytes(tampered_ct),
        ):
            negative_passed += 1
        else:
            negative_failed += 1

        tampered_tag = bytearray(ct)
        tampered_tag[-1] ^= 0x01
        if expect_reject(
            f"{name} tag tamper",
            key,
            nonce,
            aad,
            bytes(tampered_tag),
        ):
            negative_passed += 1
        else:
            negative_failed += 1

        wrong_aad = aad + b"\x00"
        if expect_reject(f"{name} wrong AAD", key, nonce, wrong_aad, ct):
            negative_passed += 1
        else:
            negative_failed += 1

        wrong_nonce = bytes([nonce[0] ^ 0x01]) + nonce[1:]
        if expect_reject(f"{name} wrong nonce", key, wrong_nonce, aad, ct):
            negative_passed += 1
        else:
            negative_failed += 1

        wrong_key = bytes([key[0] ^ 0x01]) + key[1:]
        if expect_reject(f"{name} wrong key", wrong_key, nonce, aad, ct):
            negative_passed += 1
        else:
            negative_failed += 1

    print(f"\n{passed}/{passed + failed} vectors passed.")
    total_negative = negative_passed + negative_failed
    print(f"{negative_passed}/{total_negative} negative checks passed.")
    return failed == 0 and negative_failed == 0


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
