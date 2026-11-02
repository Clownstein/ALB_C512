"""
C512 Cryptanalysis Smoke Tests — Attempts multiple attack strategies against
an ALB_C512 encrypted file to evaluate cipher security.

NOTE: These are smoke tests and demonstrations, not proofs of security.

Attacks performed:
  1. Statistical analysis (chi-squared, byte frequency, entropy)
  2. Avalanche effect test (bit sensitivity)
  3. Known-plaintext correlation
  4. Repeated-block detection (ECB-like weakness)
  5. Differential analysis (related-nonce)
  6. Brute-force key space estimation
  7. Bit-flip / malleability test
  8. Frequency of byte patterns
  9. Autocorrelation analysis
 10. Birthday attack feasibility

Usage:
  python c512_crack_attempt.py [--encrypted test_encrypted.c512]
"""

import os
import sys
import json
import math
import time
import struct
import hashlib
import collections
from typing import Optional

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "python"))
from c512 import (
    encrypt, decrypt, key_schedule, init_state, permutation,
    bootstrap_permutation, apply_chi, apply_ntt_butterfly,
    state_from_bytes, state_to_bytes, extract_keystream,
    C512_KEY_SIZE, C512_NONCE_SIZE, C512_TAG_SIZE,
    C512_RATE_SIZE, C512_ROUNDS_A, C512_ROUNDS_B
)

MAGIC = b'C512'


def read_encrypted_file(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError(f"Bad magic: {magic}")
        version = struct.unpack('<H', f.read(2))[0]
        pt_len = struct.unpack('<I', f.read(4))[0]
        nonce = f.read(32)
        aad_len = struct.unpack('<I', f.read(4))[0]
        aad = f.read(aad_len)
        ct_tag = f.read()
    return {
        'version': version,
        'pt_len': pt_len,
        'nonce': nonce,
        'aad': aad,
        'ciphertext': ct_tag[:-C512_TAG_SIZE],
        'tag': ct_tag[-C512_TAG_SIZE:],
        'ct_tag': ct_tag,
    }


class SecurityReport:
    def __init__(self):
        self.tests = []
        self.vulnerabilities = []

    def add(self, name, passed, detail, severity="info"):
        status = "PASS" if passed else "FAIL"
        self.tests.append((name, status, detail, severity))
        if not passed:
            self.vulnerabilities.append((name, detail, severity))

    def print_report(self):
        print("\n" + "=" * 70)
        print("  ALB_C512 CRYPTANALYSIS SMOKE TEST REPORT")
        print("=" * 70)

        for name, status, detail, sev in self.tests:
            icon = "\u2705" if status == "PASS" else "\u274c"
            print(f"\n  {icon} [{status}] {name}")
            for line in detail.split('\n'):
                print(f"         {line}")

        print("\n" + "-" * 70)
        if not self.vulnerabilities:
            print("  RESULT: Selected smoke checks passed; this is not a security assessment.")
            print("  C512 has known structural defects and must not protect real data.")
        else:
            print(f"  RESULT: {len(self.vulnerabilities)} potential "
                  f"issue(s) found:")
            for name, detail, sev in self.vulnerabilities:
                print(f"    [{sev.upper()}] {name}: {detail[:80]}")
        print("-" * 70 + "\n")


# ── Attack 1: Statistical byte frequency analysis ──────────────────────────

def test_byte_frequency(ct: bytes, report: SecurityReport):
    """Chi-squared test on ciphertext byte distribution."""
    n = len(ct)
    if n < 256:
        report.add("Byte Frequency (chi-sq)", True,
                    "Ciphertext too short for meaningful test")
        return

    counts = collections.Counter(ct)
    expected = n / 256.0
    chi_sq = sum((counts.get(b, 0) - expected) ** 2 / expected
                 for b in range(256))

    critical = 310.5
    passed = chi_sq < critical

    report.add(
        "Byte Frequency (chi-squared)",
        passed,
        f"chi-sq = {chi_sq:.2f} (critical @ 1% = {critical:.1f})\n"
        f"Expected uniform: {expected:.2f} per byte value\n"
        f"Min count: {min(counts.get(b, 0) for b in range(256))}, "
        f"Max count: {max(counts.get(b, 0) for b in range(256))}\n"
        f"{'UNIFORM — no bias detected' if passed else 'NON-UNIFORM — possible bias!'}"
    )


# ── Attack 2: Shannon entropy ──────────────────────────────────────────────

def test_entropy(ct: bytes, report: SecurityReport):
    """Measure Shannon entropy of ciphertext (ideal = 8.0 bits/byte)."""
    n = len(ct)
    if n == 0:
        report.add("Shannon Entropy", True, "No ciphertext to test")
        return

    counts = collections.Counter(ct)
    entropy = -sum(
        (c / n) * math.log2(c / n)
        for c in counts.values()
        if c > 0
    )

    passed = entropy > 7.5
    report.add(
        "Shannon Entropy",
        passed,
        f"Entropy = {entropy:.6f} bits/byte (ideal = 8.000000)\n"
        f"Deficit = {8.0 - entropy:.6f} bits\n"
        f"{'Excellent randomness' if entropy > 7.9 else 'Good' if entropy > 7.5 else 'LOW — possible structure leak!'}"
    )


# ── Attack 3: Avalanche effect ─────────────────────────────────────────────

def test_avalanche(report: SecurityReport):
    """Flip one bit in plaintext and measure ciphertext bit changes."""
    key = os.urandom(C512_KEY_SIZE)
    nonce = os.urandom(C512_NONCE_SIZE)
    pt = os.urandom(64)

    ct1 = encrypt(key, nonce, b'', pt)

    total_bits = 0
    total_flipped = 0
    trials = min(len(pt) * 8, 128)

    for bit_pos in range(trials):
        pt2 = bytearray(pt)
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        pt2[byte_idx] ^= (1 << bit_idx)

        ct2 = encrypt(key, nonce, b'', bytes(pt2))

        ct_len = min(len(ct1), len(ct2))
        for i in range(ct_len):
            diff = ct1[i] ^ ct2[i]
            total_flipped += bin(diff).count('1')
            total_bits += 8

    avg_pct = (total_flipped / total_bits) * 100 if total_bits > 0 else 0

    is_stream_like = avg_pct < 20.0
    report.add(
        "Plaintext Avalanche (stream cipher note)",
        True,
        f"Avg bit change: {avg_pct:.2f}%\n"
        f"Tested {trials} single-bit flips in plaintext\n"
        f"Total bits compared: {total_bits}\n"
        f"{'Stream-cipher behavior (C=KS\u2295P): expected ~low %' if is_stream_like else 'Higher than expected for XOR stream mode'}\n"
        f"NOTE: This is normal for sponge-AEAD. Key avalanche is the real metric."
    )


# ── Attack 4: Key avalanche ────────────────────────────────────────────────

def test_key_avalanche(report: SecurityReport):
    """Flip one bit in key and measure ciphertext bit changes."""
    key = os.urandom(C512_KEY_SIZE)
    nonce = os.urandom(C512_NONCE_SIZE)
    pt = os.urandom(64)

    ct1 = encrypt(key, nonce, b'', pt)

    total_bits = 0
    total_flipped = 0
    trials = min(C512_KEY_SIZE * 8, 128)

    for bit_pos in range(trials):
        key2 = bytearray(key)
        key2[bit_pos // 8] ^= (1 << (bit_pos % 8))

        ct2 = encrypt(bytes(key2), nonce, b'', pt)

        ct_len = min(len(ct1), len(ct2))
        for i in range(ct_len):
            diff = ct1[i] ^ ct2[i]
            total_flipped += bin(diff).count('1')
            total_bits += 8

    avg_pct = (total_flipped / total_bits) * 100 if total_bits > 0 else 0
    passed = 45.0 <= avg_pct <= 55.0
    report.add(
        "Key Avalanche Effect",
        passed,
        f"Avg bit change: {avg_pct:.2f}% (ideal = 50.00%)\n"
        f"Tested {trials} single-bit flips in key\n"
        f"{'Excellent key sensitivity' if passed else 'WEAK key sensitivity!'}"
    )


# ── Attack 5: Repeated block detection (ECB weakness) ──────────────────────

def test_repeated_blocks(ct: bytes, report: SecurityReport):
    """Check for repeated 64-byte blocks in ciphertext."""
    block_size = C512_RATE_SIZE
    if len(ct) < block_size * 2:
        report.add("Repeated Block Detection", True,
                    "Ciphertext too short for block analysis")
        return

    blocks = []
    for i in range(0, len(ct) - block_size + 1, block_size):
        blocks.append(ct[i:i + block_size])

    unique = len(set(blocks))
    total = len(blocks)
    duplicates = total - unique

    passed = duplicates == 0
    report.add(
        "Repeated Block Detection (ECB test)",
        passed,
        f"Total {block_size}-byte blocks: {total}\n"
        f"Unique blocks: {unique}\n"
        f"Duplicates: {duplicates}\n"
        f"{'No repeated blocks — not ECB-like' if passed else 'REPEATED BLOCKS FOUND — ECB-like weakness!'}"
    )


# ── Attack 6: Known-plaintext correlation ──────────────────────────────────

def test_known_plaintext_correlation(ct: bytes, pt: Optional[bytes],
                                     report: SecurityReport):
    """If plaintext is known, check correlation between PT and CT."""
    if pt is None or len(pt) == 0 or len(ct) == 0:
        report.add("Known-Plaintext Correlation", True,
                    "No plaintext available for correlation test")
        return

    compare_len = min(len(ct), len(pt))
    matching_bits = 0
    total_bits = compare_len * 8

    for i in range(compare_len):
        xor = ct[i] ^ pt[i]
        matching_bits += (8 - bin(xor).count('1'))

    correlation = matching_bits / total_bits if total_bits > 0 else 0.5
    deviation = abs(correlation - 0.5)

    passed = deviation < 0.05
    report.add(
        "Known-Plaintext Correlation",
        passed,
        f"Bit agreement: {correlation*100:.2f}% (ideal = 50.00%)\n"
        f"Deviation from ideal: {deviation*100:.2f}%\n"
        f"Compared {compare_len} bytes ({total_bits} bits)\n"
        f"{'No correlation detected' if passed else 'CORRELATION FOUND — possible plaintext leakage!'}"
    )


# ── Attack 7: Bit-flip / tag malleability ──────────────────────────────────

def test_tag_integrity(report: SecurityReport):
    """Verify that any bit flip in ciphertext causes auth failure."""
    key = os.urandom(C512_KEY_SIZE)
    nonce = os.urandom(C512_NONCE_SIZE)
    pt = os.urandom(128)
    aad = b"test-aad"

    ct = encrypt(key, nonce, aad, pt)
    rejections = 0
    trials = min(len(ct) * 8, 256)

    for bit_pos in range(trials):
        tampered = bytearray(ct)
        tampered[bit_pos // 8] ^= (1 << (bit_pos % 8))
        try:
            decrypt(key, nonce, aad, bytes(tampered))
        except ValueError:
            rejections += 1

    passed = rejections == trials
    report.add(
        "Tag Integrity (bit-flip rejection)",
        passed,
        f"Rejected {rejections}/{trials} tampered ciphertexts\n"
        f"{'All bit-flips detected — authentication is solid' if passed else f'ACCEPTED {trials - rejections} tampered messages!'}"
    )


# ── Attack 8: Autocorrelation ──────────────────────────────────────────────

def test_autocorrelation(ct: bytes, report: SecurityReport):
    """Check autocorrelation at various lags in the ciphertext."""
    n = len(ct)
    if n < 512:
        report.add("Autocorrelation", True,
                    "Ciphertext too short for autocorrelation")
        return

    mean = sum(ct) / n
    variance = sum((b - mean) ** 2 for b in ct) / n

    if variance == 0:
        report.add("Autocorrelation", False,
                    "Zero variance — constant ciphertext!")
        return

    max_corr = 0.0
    worst_lag = 0
    lags = [1, 2, 4, 8, 16, 32, 64, 128]

    for lag in lags:
        if lag >= n:
            continue
        cov = sum(
            (ct[i] - mean) * (ct[i + lag] - mean)
            for i in range(n - lag)
        ) / (n - lag)
        corr = abs(cov / variance)
        if corr > max_corr:
            max_corr = corr
            worst_lag = lag

    passed = max_corr < 0.1
    report.add(
        "Autocorrelation Analysis",
        passed,
        f"Max |autocorrelation| = {max_corr:.6f} at lag {worst_lag}\n"
        f"Tested lags: {lags}\n"
        f"{'No significant autocorrelation' if passed else 'AUTOCORRELATION DETECTED — possible stream weakness!'}"
    )


# ── Attack 9: Differential (related nonce) ─────────────────────────────────

def test_related_nonce(report: SecurityReport):
    """Encrypt same plaintext with slightly different nonces."""
    key = os.urandom(C512_KEY_SIZE)
    pt = b'\x00' * 128

    nonce1 = os.urandom(C512_NONCE_SIZE)
    nonce2 = bytearray(nonce1)
    nonce2[0] ^= 0x01

    ct1 = encrypt(key, nonce1, b'', pt)
    ct2 = encrypt(key, bytes(nonce2), b'', pt)

    compare_len = min(len(ct1), len(ct2))
    diff_bits = 0
    total_bits = compare_len * 8

    for i in range(compare_len):
        diff_bits += bin(ct1[i] ^ ct2[i]).count('1')

    pct = (diff_bits / total_bits) * 100 if total_bits > 0 else 0
    passed = 40.0 <= pct <= 60.0
    report.add(
        "Related-Nonce Differential",
        passed,
        f"Bit difference: {pct:.2f}% (ideal ~50%)\n"
        f"Single-bit nonce change produces {diff_bits}/{total_bits} "
        f"differing bits\n"
        f"{'Good nonce sensitivity' if passed else 'WEAK nonce sensitivity!'}"
    )


# ── Attack 10: Brute-force feasibility ─────────────────────────────────────

def test_brute_force_estimate(report: SecurityReport):
    """Estimate time to brute-force the key space."""
    key = os.urandom(C512_KEY_SIZE)
    nonce = os.urandom(C512_NONCE_SIZE)
    pt = b'test'

    trials = 100
    t0 = time.perf_counter()
    for _ in range(trials):
        try:
            test_key = os.urandom(C512_KEY_SIZE)
            ct = encrypt(test_key, nonce, b'', pt)
            decrypt(test_key, nonce, b'', ct)
        except Exception:
            pass
    elapsed = time.perf_counter() - t0
    rate = trials / elapsed

    key_bits = C512_KEY_SIZE * 8
    total_keys = 2 ** key_bits
    seconds_needed = total_keys / rate
    years_needed = seconds_needed / (365.25 * 24 * 3600)

    grover_keys = 2 ** (key_bits // 2)
    grover_seconds = grover_keys / (rate * 1e9)
    grover_years = grover_seconds / (365.25 * 24 * 3600)

    report.add(
        "Brute-Force Feasibility",
        True,
        f"Key space: 2^{key_bits} ({key_bits}-bit key)\n"
        f"Benchmark: {rate:.1f} encrypt+decrypt/sec (single core)\n"
        f"Classical brute-force: ~10^{math.log10(years_needed):.0f} years\n"
        f"Quantum (Grover, 10^9 parallel): ~10^{math.log10(grover_years):.0f} years\n"
        f"Universe age: ~1.38 × 10^10 years\n"
        f"Verdict: {'INFEASIBLE' if key_bits >= 256 else 'POTENTIALLY FEASIBLE'}"
    )


# ── Attack 11: Permutation output distribution ─────────────────────────────

def test_permutation_distribution(report: SecurityReport):
    """Test that the permutation output looks random."""
    outputs = bytearray()
    rk = key_schedule(os.urandom(C512_KEY_SIZE))

    for i in range(64):
        state = list(range(32))
        state[0] = i
        permutation(state, C512_ROUNDS_A, rk)
        out = state_to_bytes(state)
        outputs.extend(out)

    n = len(outputs)
    counts = collections.Counter(outputs)
    expected = n / 256.0
    chi_sq = sum((counts.get(b, 0) - expected) ** 2 / expected
                 for b in range(256))

    passed = chi_sq < 310.5
    report.add(
        "Permutation Output Distribution",
        passed,
        f"Collected {n} bytes from 64 permutation runs\n"
        f"Chi-squared: {chi_sq:.2f} (critical = 310.5)\n"
        f"{'Uniform distribution' if passed else 'NON-UNIFORM — permutation bias detected!'}"
    )


# ── Attack 12: Nibble/byte pattern analysis ────────────────────────────────

def test_pattern_analysis(ct: bytes, report: SecurityReport):
    """Look for common byte pair patterns (digram frequency)."""
    if len(ct) < 1024:
        report.add("Digram Frequency", True,
                    "Ciphertext too short for digram analysis")
        return

    digrams = collections.Counter()
    for i in range(len(ct) - 1):
        digrams[(ct[i], ct[i + 1])] += 1

    expected = (len(ct) - 1) / 65536.0
    observed = list(digrams.values())

    if len(observed) == 0:
        report.add("Digram Frequency", False, "No digrams found")
        return

    max_count = max(observed)
    unique_digrams = len(digrams)

    max_expected = expected + 5 * math.sqrt(expected) if expected > 0 else 10
    passed = max_count < max_expected * 3

    report.add(
        "Digram (byte-pair) Frequency",
        passed,
        f"Unique digrams: {unique_digrams}/65536 possible\n"
        f"Max frequency: {max_count} (expected ~{expected:.2f})\n"
        f"{'No suspicious patterns' if passed else 'PATTERN DETECTED — byte pairs are biased!'}"
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="C512 Cryptanalysis Smoke Test Suite"
    )
    parser.add_argument(
        "--encrypted", default="test_encrypted.c512",
        help="Path to encrypted .c512 file"
    )
    parser.add_argument(
        "--plaintext", default=None,
        help="Path to original plaintext (for correlation test)"
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Run quick tests only (skip slow avalanche tests)"
    )
    args = parser.parse_args()

    report = SecurityReport()

    print("=" * 70)
    print("  ALB_C512 (C512) CRYPTANALYSIS SMOKE TEST SUITE")
    print("=" * 70)

    enc_path = args.encrypted
    ct_data = None
    pt_data = None

    if os.path.exists(enc_path):
        print(f"\n[*] Loading encrypted file: {enc_path}")
        enc = read_encrypted_file(enc_path)
        ct_data = enc['ciphertext']
        print(f"    Ciphertext: {len(ct_data)} bytes")
        print(f"    Tag: {enc['tag'].hex()[:32]}...")
        print(f"    Nonce: {enc['nonce'].hex()[:32]}...")
    else:
        print(f"\n[!] No encrypted file found at {enc_path}")
        print("    Generating in-memory test data...")
        key = os.urandom(C512_KEY_SIZE)
        nonce = os.urandom(C512_NONCE_SIZE)
        pt_data = os.urandom(4096)
        ct_full = encrypt(key, nonce, b'', pt_data)
        ct_data = ct_full[:-C512_TAG_SIZE]

    if args.plaintext and os.path.exists(args.plaintext):
        with open(args.plaintext, 'rb') as f:
            pt_data = f.read()
        print(f"[*] Plaintext loaded: {len(pt_data)} bytes")
    elif os.path.exists("test_plain.bin"):
        with open("test_plain.bin", 'rb') as f:
            pt_data = f.read()
        print(f"[*] Plaintext loaded: test_plain.bin ({len(pt_data)} bytes)")

    print("\n[*] Running cryptanalysis tests...\n")

    print("  [1/12] Byte frequency analysis...")
    test_byte_frequency(ct_data, report)

    print("  [2/12] Shannon entropy measurement...")
    test_entropy(ct_data, report)

    print("  [3/12] Repeated block detection...")
    test_repeated_blocks(ct_data, report)

    print("  [4/12] Known-plaintext correlation...")
    test_known_plaintext_correlation(ct_data, pt_data, report)

    print("  [5/12] Autocorrelation analysis...")
    test_autocorrelation(ct_data, report)

    print("  [6/12] Digram pattern analysis...")
    test_pattern_analysis(ct_data, report)

    if not args.quick:
        print("  [7/12] Avalanche effect (plaintext)...")
        test_avalanche(report)

        print("  [8/12] Key avalanche effect...")
        test_key_avalanche(report)

        print("  [9/12] Tag integrity (bit-flip)...")
        test_tag_integrity(report)

        print("  [10/12] Related-nonce differential...")
        test_related_nonce(report)

        print("  [11/12] Permutation distribution...")
        test_permutation_distribution(report)

        print("  [12/12] Brute-force feasibility estimate...")
        test_brute_force_estimate(report)
    else:
        print("  [7-12] Skipped (--quick mode)")

    report.print_report()

    return len(report.vulnerabilities) == 0


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
