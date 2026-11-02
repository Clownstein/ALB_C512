"""
Advanced mathematical analysis for ALB_C512 permutation.

Performs:
  1. Differential uniformity Monte Carlo (single-bit input differences)
  2. Linear correlation search (Walsh-like test)
  3. Fixed-point / short-cycle hunt
  4. Low Hamming weight diffusion (branch number proxy)
  5. Integral (balanced) test on 2^8 structured inputs

Usage:
  python c512_math_tests.py [--rounds 36] [--samples 2000]
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
from collections import Counter

import sys
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "python"))

from c512 import (
    state_from_bytes,
    state_to_bytes,
    bootstrap_permutation,
    key_schedule,
    permutation,
    C512_KEY_SIZE,
)

STATE_BYTES = 128
TOTAL_LANES = 32
BITS_PER_LANE = 32


def random_state() -> list[int]:
    return state_from_bytes(os.urandom(STATE_BYTES))


def clone_state(state: list[int]) -> list[int]:
    return [x for x in state]


def xor_states(a: list[int], b: list[int]) -> list[int]:
    return [(x ^ y) & 0xFFFFFFFF for x, y in zip(a, b)]


def hamming_weight_state(state: list[int]) -> int:
    data = state_to_bytes(state)
    return sum(bin(x).count("1") for x in data)


def toggle_single_bit(state: list[int], bit_index: int) -> list[int]:
    lane = bit_index // BITS_PER_LANE
    bit = bit_index % BITS_PER_LANE
    new_state = clone_state(state)
    new_state[lane] ^= (1 << bit)
    new_state[lane] &= 0xFFFFFFFF
    return new_state


def bootstrap_rounds(state: list[int], rounds: int) -> None:
    bootstrap_permutation(state, rounds)


def full_permutation(state: list[int], rounds: int) -> None:
    zero_key = bytes(C512_KEY_SIZE)
    round_keys = key_schedule(zero_key)
    permutation(state, rounds, round_keys)


def differential_uniformity(rounds: int, samples: int, use_keyed: bool = False) -> dict:
    """Estimate differential uniformity for single-bit input differences."""
    results = []
    target_rounds = rounds
    runner = full_permutation if use_keyed else bootstrap_rounds

    for bit in random.sample(range(TOTAL_LANES * BITS_PER_LANE), k=16):
        zero_count = 0
        collisions = Counter()
        for _ in range(samples):
            s1 = random_state()
            s2 = toggle_single_bit(s1, bit)
            st1 = clone_state(s1)
            st2 = clone_state(s2)
            runner(st1, target_rounds)
            runner(st2, target_rounds)
            diff = tuple(xor_states(st1, st2))
            if all(v == 0 for v in diff):
                zero_count += 1
            collisions[diff] += 1
        max_prob = max(collisions.values()) / samples
        results.append({
            "bit": bit,
            "zero_hits": zero_count,
            "max_prob": max_prob,
        })
    return {
        "rounds": target_rounds,
        "use_keyed": use_keyed,
        "results": results,
        "max_of_max": max(r["max_prob"] for r in results),
        "zero_hits": sum(r["zero_hits"] for r in results),
    }


def linear_correlation(rounds: int, samples: int, use_keyed: bool = False) -> dict:
    runner = full_permutation if use_keyed else bootstrap_rounds
    random_masks = [os.urandom(STATE_BYTES) for _ in range(16)]
    stats = []
    for mask in random_masks:
        ones = 0
        for _ in range(samples):
            state = random_state()
            st = clone_state(state)
            runner(st, rounds)
            parity_input = parity_bytes(state_to_bytes(state), mask)
            parity_output = parity_bytes(state_to_bytes(st), mask)
            if parity_input == parity_output:
                ones += 1
        bias = abs((ones / samples) - 0.5)
        stats.append(bias)
    return {
        "rounds": rounds,
        "use_keyed": use_keyed,
        "bias_mean": statistics.mean(stats),
        "bias_max": max(stats),
    }


def parity_bytes(data: bytes, mask: bytes) -> int:
    return sum(bin(d & m).count("1") for d, m in zip(data, mask)) & 1


def fixed_point_search(rounds: int, samples: int, use_keyed: bool = False) -> dict:
    runner = full_permutation if use_keyed else bootstrap_rounds
    hits = 0
    for _ in range(samples):
        state = random_state()
        original = clone_state(state)
        runner(state, rounds)
        if state == original:
            hits += 1
    return {
        "rounds": rounds,
        "use_keyed": use_keyed,
        "samples": samples,
        "fixed_points": hits,
    }


def low_weight_diffusion(rounds: int, use_keyed: bool = False) -> dict:
    runner = full_permutation if use_keyed else bootstrap_rounds
    weights = []
    for bit in random.sample(range(TOTAL_LANES * BITS_PER_LANE), k=64):
        state = [0] * TOTAL_LANES
        lane = bit // BITS_PER_LANE
        offset = bit % BITS_PER_LANE
        state[lane] = (1 << offset) & 0xFFFFFFFF
        runner(state, rounds)
        weights.append(hamming_weight_state(state))
    return {
        "rounds": rounds,
        "use_keyed": use_keyed,
        "min_weight": min(weights),
        "max_weight": max(weights),
        "avg_weight": statistics.mean(weights),
    }


def integral_test(rounds: int, dimension: int = 8, use_keyed: bool = False) -> dict:
    runner = full_permutation if use_keyed else bootstrap_rounds
    base_state = random_state()
    xor_accum = [0] * TOTAL_LANES
    total = 1 << dimension
    for value in range(total):
        st = clone_state(base_state)
        for bit in range(dimension):
            if (value >> bit) & 1:
                st = toggle_single_bit(st, bit)
        runner(st, rounds)
        for i in range(TOTAL_LANES):
            xor_accum[i] ^= st[i]
    balanced = all(x == 0 for x in xor_accum)
    return {
        "rounds": rounds,
        "use_keyed": use_keyed,
        "balanced": balanced,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="C512 mathematical analysis")
    parser.add_argument("--rounds", type=int, default=36,
                        help="Number of permutation rounds to test (default 36)")
    parser.add_argument("--samples", type=int, default=1000,
                        help="Monte Carlo samples per test")
    parser.add_argument("--keyed", action="store_true",
                        help="Use keyed permutation (slower)")
    args = parser.parse_args()

    print("=" * 70)
    print("  C512 PERMUTATION MATHEMATICAL ANALYSIS")
    print("=" * 70)
    print(f"Rounds: {args.rounds}  |  Samples: {args.samples}  |  Keyed: {args.keyed}")

    diff = differential_uniformity(args.rounds, args.samples, args.keyed)
    print("\n[Differential Uniformity]")
    print(f"  Max empirical prob: {diff['max_of_max']:.6f}")
    print(f"  Zero-output hits: {diff['zero_hits']} / {len(diff['results']) * args.samples}")

    lin = linear_correlation(args.rounds, args.samples, args.keyed)
    print("\n[Linear Correlation]")
    print(f"  Mean bias: {lin['bias_mean']:.6f}")
    print(f"  Max bias:  {lin['bias_max']:.6f}")

    fixed = fixed_point_search(args.rounds, args.samples, args.keyed)
    print("\n[Fixed Points]")
    print(f"  Samples: {fixed['samples']}  |  Fixed points found: {fixed['fixed_points']}")

    low = low_weight_diffusion(args.rounds, args.keyed)
    print("\n[Low-Weight Diffusion]")
    print(f"  Min weight: {low['min_weight']}  Max weight: {low['max_weight']}  Avg: {low['avg_weight']:.2f}")

    integ = integral_test(args.rounds, use_keyed=args.keyed)
    print("\n[Integral Test]")
    if integ['balanced']:
        print("  Balanced XOR over 2^8 inputs: YES")
    else:
        print("  Balanced XOR over 2^8 inputs: NO (integral distinguisher not observed — this is expected unless a special structure exists)")

    print("\nDone.")


if __name__ == "__main__":
    main()
