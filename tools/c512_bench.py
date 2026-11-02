#!/usr/bin/env python3
"""
ALB_C512 v2.0 Benchmark — Throughput measurement across modes.

Usage:
  python tools/c512_bench.py
  python tools/c512_bench.py --sizes 64,1024,65536
  python tools/c512_bench.py --iterations 100
"""

import os
import sys
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
import c512
import c512_lite


def bench(func, label, iterations=50):
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        t1 = time.perf_counter()
        times.append(t1 - t0)
    avg = sum(times) / len(times)
    median = sorted(times)[len(times) // 2]
    return avg, median


def format_throughput(size_bytes, seconds):
    if seconds == 0:
        return "N/A"
    mbps = (size_bytes / seconds) / (1024 * 1024)
    return f"{mbps:.1f} MB/s"


def main():
    parser = argparse.ArgumentParser(description="C512 v2.0 benchmark")
    parser.add_argument("--sizes", default="64,256,1024,4096,16384,65536",
                        help="Comma-separated message sizes in bytes")
    parser.add_argument("--iterations", type=int, default=20,
                        help="Iterations per benchmark")
    args = parser.parse_args()

    sizes = [int(s) for s in args.sizes.split(",")]
    iters = args.iterations

    key = os.urandom(c512.C512_KEY_SIZE)
    nonce = os.urandom(c512.C512_NONCE_SIZE)
    aad = os.urandom(32)
    lite_key = os.urandom(c512_lite.LITE_KEY_SIZE)
    lite_nonce = os.urandom(c512_lite.LITE_NONCE_SIZE)

    print(f"ALB_C512 v2.0 Benchmark (Python reference, {iters} iterations)")
    print(f"{'='*70}")

    # AEAD encrypt
    print(f"\n{'Size':>8} | {'AEAD Encrypt':>14} | {'AEAD Decrypt':>14} | {'SIV Encrypt':>14} | {'Lite Encrypt':>14}")
    print(f"{'-'*8}-+-{'-'*14}-+-{'-'*14}-+-{'-'*14}-+-{'-'*14}")

    for size in sizes:
        pt = os.urandom(size)
        lite_pt = os.urandom(size)

        avg_enc, _ = bench(lambda: c512.encrypt(key, nonce, aad, pt), "enc", iters)
        ct = c512.encrypt(key, nonce, aad, pt)
        avg_dec, _ = bench(lambda: c512.decrypt(key, nonce, aad, ct), "dec", iters)
        avg_siv, _ = bench(lambda: c512.siv_encrypt(key, aad, pt), "siv", iters)
        avg_lite, _ = bench(
            lambda: c512_lite.encrypt(lite_key, lite_nonce, aad[:16], lite_pt),
            "lite", iters
        )

        print(f"{size:>8} | {format_throughput(size, avg_enc):>14} | "
              f"{format_throughput(size, avg_dec):>14} | "
              f"{format_throughput(size, avg_siv):>14} | "
              f"{format_throughput(size, avg_lite):>14}")

    # XOF benchmark
    print(f"\n{'='*70}")
    print(f"XOF Output Generation:")
    print(f"{'Length':>8} | {'Throughput':>14}")
    print(f"{'-'*8}-+-{'-'*14}")

    for length in [32, 64, 256, 1024, 4096]:
        avg, _ = bench(lambda: c512.xof(key, b"bench", length), "xof", iters)
        print(f"{length:>8} | {format_throughput(length, avg):>14}")

    # Key schedule cost
    print(f"\n{'='*70}")
    avg_ks, _ = bench(lambda: c512.key_schedule(key), "ks", iters)
    print(f"Key schedule: {avg_ks*1000:.2f} ms (amortized over message)")

    avg_init, _ = bench(
        lambda: c512.encrypt(key, nonce, b'', b''),
        "init", iters
    )
    print(f"Empty message (init+finalize): {avg_init*1000:.2f} ms")


if __name__ == "__main__":
    main()
