#!/usr/bin/env python3
"""
ALB_C512 v2.0 — Python Test Vector Verification Harness

Replays canonical v2.0 test vectors against the Python reference implementation
to confirm deterministic output and tag validation across all modes (AEAD, SIV, XOF).

Usage:
  python tools/test_vectors_v2_verify.py
  python tools/test_vectors_v2_verify.py --lite   # Also verify C512-Lite vectors
  python tools/test_vectors_v2_verify.py --verbose
"""

import json
import os
import sys
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
import c512


def verify_aead_vector(vec: dict, verbose: bool = False) -> bool:
    name = vec["name"]
    key = bytes.fromhex(vec["key"])
    nonce = bytes.fromhex(vec["nonce"])
    aad = bytes.fromhex(vec["aad"])
    plaintext = bytes.fromhex(vec["plaintext"])
    expected_ct_tag = bytes.fromhex(vec["ciphertext_tag"])

    ct_tag = c512.encrypt(key, nonce, aad, plaintext)
    if ct_tag != expected_ct_tag:
        print(f"  [FAIL] {name}: ciphertext mismatch")
        if verbose:
            print(f"    expected: {expected_ct_tag.hex()}")
            print(f"    got:      {ct_tag.hex()}")
        return False

    pt = c512.decrypt(key, nonce, aad, ct_tag)
    if pt != plaintext:
        print(f"  [FAIL] {name}: decrypt mismatch")
        return False

    # Tamper test
    tampered = bytearray(ct_tag)
    tampered[0] ^= 0xFF
    try:
        c512.decrypt(key, nonce, aad, bytes(tampered))
        print(f"  [FAIL] {name}: tampered ciphertext not rejected")
        return False
    except ValueError:
        pass

    if verbose:
        print(f"  [PASS] {name}")
    return True


def verify_siv_vector(vec: dict, verbose: bool = False) -> bool:
    name = vec["name"]
    key = bytes.fromhex(vec["key"])
    aad = bytes.fromhex(vec["aad"])
    plaintext = bytes.fromhex(vec["plaintext"])
    expected_output = bytes.fromhex(vec["siv_output"])

    output = c512.siv_encrypt(key, aad, plaintext)
    if output != expected_output:
        print(f"  [FAIL] {name}: SIV output mismatch")
        if verbose:
            print(f"    expected: {expected_output.hex()}")
            print(f"    got:      {output.hex()}")
        return False

    pt = c512.siv_decrypt(key, aad, output)
    if pt != plaintext:
        print(f"  [FAIL] {name}: SIV decrypt mismatch")
        return False

    # Determinism check
    output2 = c512.siv_encrypt(key, aad, plaintext)
    if output != output2:
        print(f"  [FAIL] {name}: SIV not deterministic")
        return False

    if verbose:
        print(f"  [PASS] {name}")
    return True


def verify_xof_vector(vec: dict, verbose: bool = False) -> bool:
    name = vec["name"]
    key = bytes.fromhex(vec["key"])
    context = bytes.fromhex(vec["context"])
    output_length = vec["output_length"]
    expected_output = bytes.fromhex(vec["output"])

    output = c512.xof(key, context, output_length)
    if output != expected_output:
        print(f"  [FAIL] {name}: XOF output mismatch")
        if verbose:
            print(f"    expected: {expected_output.hex()}")
            print(f"    got:      {output.hex()}")
        return False

    # Determinism check
    output2 = c512.xof(key, context, output_length)
    if output != output2:
        print(f"  [FAIL] {name}: XOF not deterministic")
        return False

    if verbose:
        print(f"  [PASS] {name}")
    return True


def verify_lite_vector(vec: dict, verbose: bool = False) -> bool:
    import c512_lite

    name = vec["name"]
    key = bytes.fromhex(vec["key"])
    nonce = bytes.fromhex(vec["nonce"])
    aad = bytes.fromhex(vec["aad"])
    plaintext = bytes.fromhex(vec["plaintext"])
    expected_ct_tag = bytes.fromhex(vec["ciphertext_tag"])

    ct_tag = c512_lite.encrypt(key, nonce, aad, plaintext)
    if ct_tag != expected_ct_tag:
        print(f"  [FAIL] {name}: Lite ciphertext mismatch")
        if verbose:
            print(f"    expected: {expected_ct_tag.hex()}")
            print(f"    got:      {ct_tag.hex()}")
        return False

    pt = c512_lite.decrypt(key, nonce, aad, ct_tag)
    if pt != plaintext:
        print(f"  [FAIL] {name}: Lite decrypt mismatch")
        return False

    if verbose:
        print(f"  [PASS] {name}")
    return True


def main():
    parser = argparse.ArgumentParser(description="C512 v2.0 test vector verification")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--lite", action="store_true", help="Also verify C512-Lite vectors")
    args = parser.parse_args()

    tools_dir = os.path.dirname(os.path.abspath(__file__))

    # Load v2.0 vectors
    vectors_path = os.path.join(tools_dir, "test_vectors_v2.json")
    with open(vectors_path) as f:
        data = json.load(f)

    print(f"ALB_C512 v2.0 Test Vector Verification")
    print(f"Vector file: {vectors_path}")
    print(f"Version: {data['version']}")
    print(f"Total vectors: {len(data['vectors'])}")
    print()

    passed = 0
    failed = 0

    # AEAD vectors
    aead_vectors = [v for v in data["vectors"] if v["mode"] == "aead"]
    print(f"=== AEAD Vectors ({len(aead_vectors)}) ===")
    for vec in aead_vectors:
        if verify_aead_vector(vec, args.verbose):
            passed += 1
        else:
            failed += 1
    if not args.verbose:
        print(f"  {len(aead_vectors)} vectors verified")

    # SIV vectors
    siv_vectors = [v for v in data["vectors"] if v["mode"] == "siv"]
    print(f"\n=== SIV Vectors ({len(siv_vectors)}) ===")
    for vec in siv_vectors:
        if verify_siv_vector(vec, args.verbose):
            passed += 1
        else:
            failed += 1
    if not args.verbose:
        print(f"  {len(siv_vectors)} vectors verified")

    # XOF vectors
    xof_vectors = [v for v in data["vectors"] if v["mode"] == "xof"]
    print(f"\n=== XOF Vectors ({len(xof_vectors)}) ===")
    for vec in xof_vectors:
        if verify_xof_vector(vec, args.verbose):
            passed += 1
        else:
            failed += 1
    if not args.verbose:
        print(f"  {len(xof_vectors)} vectors verified")

    # Negative tests
    print(f"\n=== Negative Tests ===")
    key = bytes(range(64))
    nonce = bytes(range(32))
    aad = bytes([0xAA] * 64)
    pt = bytes([0x55] * 64)
    ct = c512.encrypt(key, nonce, aad, pt)
    neg_passed = 0

    # Tag tamper
    for i in range(c512.C512_TAG_SIZE):
        t = bytearray(ct)
        t[-(i + 1)] ^= 0x01
        try:
            c512.decrypt(key, nonce, aad, bytes(t))
            print(f"  [FAIL] Tag tamper byte {i} not detected")
            failed += 1
        except ValueError:
            neg_passed += 1

    # CT tamper
    for i in range(min(8, len(ct) - c512.C512_TAG_SIZE)):
        t = bytearray(ct)
        t[i] ^= 0x01
        try:
            c512.decrypt(key, nonce, aad, bytes(t))
            print(f"  [FAIL] CT tamper byte {i} not detected")
            failed += 1
        except ValueError:
            neg_passed += 1

    # AAD tamper
    bad_aad = bytearray(aad)
    bad_aad[0] ^= 0x01
    try:
        c512.decrypt(key, nonce, bytes(bad_aad), ct)
        print(f"  [FAIL] AAD tamper not detected")
        failed += 1
    except ValueError:
        neg_passed += 1

    # Nonce tamper
    bad_nonce = bytearray(nonce)
    bad_nonce[0] ^= 0x01
    try:
        c512.decrypt(key, bytes(bad_nonce), aad, ct)
        print(f"  [FAIL] Nonce tamper not detected")
        failed += 1
    except ValueError:
        neg_passed += 1

    # Key tamper
    bad_key = bytearray(key)
    bad_key[0] ^= 0x01
    try:
        c512.decrypt(bytes(bad_key), nonce, aad, ct)
        print(f"  [FAIL] Key tamper not detected")
        failed += 1
    except ValueError:
        neg_passed += 1

    passed += neg_passed
    print(f"  {neg_passed} negative tests passed")

    # Lite vectors
    if args.lite:
        lite_path = os.path.join(tools_dir, "test_vectors_v2_lite.json")
        if os.path.exists(lite_path):
            with open(lite_path) as f:
                lite_data = json.load(f)
            print(f"\n=== C512-Lite Vectors ({len(lite_data['vectors'])}) ===")
            for vec in lite_data["vectors"]:
                if verify_lite_vector(vec, args.verbose):
                    passed += 1
                else:
                    failed += 1
            if not args.verbose:
                print(f"  {len(lite_data['vectors'])} vectors verified")
        else:
            print(f"\n  Lite vectors not found at {lite_path}")
            failed += 1

    # Summary
    print(f"\n{'='*50}")
    if failed == 0:
        print(f"ALL {passed} TESTS PASSED")
    else:
        print(f"FAILED: {failed} / {passed + failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
