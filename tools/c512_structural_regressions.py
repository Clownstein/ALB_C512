#!/usr/bin/env python3
"""
ALB_C512 structural-defect regressions (P0).

These tests **assert that C512's known defects are still present**. That is
deliberate. The defects are the finding; freezing them as executable evidence
means nobody can quietly change a constant and make the problem disappear from
the record without the change being noticed and explained.

If one of these tests fails, the algorithm was modified. That is not a fix:
it is a new, differently-unreviewed algorithm, and it invalidates every
published vector. Bump the version, regenerate the vectors deliberately, and
say so in CHANGELOG.md.

The defects
-----------

1. **Chi is not invertible.** C512's Chi layer is
   ``out[i] = in[i] ^ (~in[i+1] & in[i+2])`` over a ring of **32** lanes.
   Keccak's chi is invertible only over an odd-length ring; over an even ring
   it is not. An alternating all-zero / all-ones lane pattern and its bitwise
   complement map to the *same* output.

2. **The NTT-style butterfly is not injective.** The zero half-state and the
   half-state with lanes 0 and 8 set to ``0x80000000`` produce identical
   output, because the butterfly's add/subtract pairs are taken mod 2^32 and
   ``0x80000000 + 0x80000000 == 0`` there.

3. **The cross-mix has a nonzero kernel.** ``a' = a ^ rotl(b, 11)`` and
   ``b' = b ^ rotl(a, 23)`` is a linear map over GF(2) with nontrivial kernel,
   so distinct ``(a, b)`` pairs collide.

Each of these means the "permutation" is a many-to-one function. That
invalidates the permutation-based design rationale the documentation rests on.
It does **not**, by itself, constitute a plaintext-recovery or forgery attack;
no such attack has been demonstrated here. The conclusion does not depend on
one: an unreviewed cipher whose stated rationale is provably false must not
protect real data.

Usage:
  python tools/c512_structural_regressions.py
"""

from __future__ import annotations

import os
import sys

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "python"))

os.environ.setdefault("ALB_C512_EXPERIMENTAL", "1")

import c512  # noqa: E402

try:
    import c512_lite  # noqa: E402
except Exception:  # pragma: no cover - Lite is optional
    c512_lite = None

MASK32 = 0xFFFFFFFF

_failures: list[str] = []
_checks = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _checks
    _checks += 1
    if condition:
        print(f"  [ok]   {label}")
    else:
        print(f"  [FAIL] {label}{(': ' + detail) if detail else ''}")
        _failures.append(label)


def rotl32(x: int, n: int) -> int:
    n &= 31
    if n == 0:
        return x & MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


# ---- 1. Chi over an even ring is not invertible --------------------------


def chi_collision(apply_chi, lanes: int = 32):
    a = [0 if i % 2 else MASK32 for i in range(lanes)]
    b = [x ^ MASK32 for x in a]
    sa, sb = list(a), list(b)
    apply_chi(sa)
    apply_chi(sb)
    return a, b, sa, sb


def test_chi_not_a_permutation() -> None:
    print("\n[1] Chi layer over an even lane ring")
    a, b, sa, sb = chi_collision(c512.apply_chi, 32)
    check("inputs are distinct", a != b)
    check(
        "distinct inputs collide under Chi",
        sa == sb,
        "Chi appears invertible now; the algorithm changed",
    )
    print(f"       input A[0:4] = {[hex(x) for x in a[:4]]}")
    print(f"       input B[0:4] = {[hex(x) for x in b[:4]]}")
    print(f"       both map to  = {[hex(x) for x in sa[:4]]}")


# ---- 2. The butterfly is not injective -----------------------------------


def test_butterfly_not_injective() -> None:
    print("\n[2] NTT-style butterfly over Z/2^32")
    zero = [0] * 32
    other = [0] * 32
    other[0] = 0x80000000
    other[8] = 0x80000000

    sz, so = list(zero), list(other)
    c512.ntt_butterfly_half(sz, 0)
    c512.ntt_butterfly_half(so, 0)

    check("inputs are distinct", zero != other)
    check(
        "distinct half-states collide under the butterfly",
        sz[:16] == so[:16],
        "the butterfly appears injective now; the algorithm changed",
    )
    print(f"       0x80000000 + 0x80000000 mod 2^32 = "
          f"{hex((0x80000000 + 0x80000000) & MASK32)}")


# ---- 3. The cross-mix has a nonzero kernel -------------------------------


def test_cross_mix_kernel() -> None:
    print("\n[3] Cross-mix a ^ rotl(b,11), b ^ rotl(a,23)")

    def mix(a: int, b: int) -> tuple[int, int]:
        return (a ^ rotl32(b, 11), b ^ rotl32(a, 23))

    # Search the low-weight part of the space for a nonzero kernel element.
    found = None
    for bit_a in range(32):
        for bit_b in range(32):
            a, b = 1 << bit_a, 1 << bit_b
            if mix(a, b) == (0, 0):
                found = (a, b)
                break
        if found:
            break

    if found is None:
        # The kernel of a linear GF(2) map on 64 bits is nonzero iff the map is
        # singular; search a wider structured set before concluding.
        for a in range(1, 1 << 12):
            b = 0
            if mix(a, b) == (0, 0):
                found = (a, b)
                break

    check(
        "the cross-mix is not a bijection on (a, b) pairs",
        _cross_mix_is_singular(mix),
        "the cross-mix appears bijective now; the algorithm changed",
    )
    if found:
        print(f"       kernel element: a={hex(found[0])} b={hex(found[1])}")


def _cross_mix_is_singular(mix) -> bool:
    """Rank the 64x64 GF(2) matrix of the cross-mix; singular means collisions."""
    rows = []
    for bit in range(64):
        if bit < 32:
            a, b = 1 << bit, 0
        else:
            a, b = 0, 1 << (bit - 32)
        oa, ob = mix(a, b)
        rows.append(oa | (ob << 32))

    rank = 0
    pivot_rows = []
    for col in range(64):
        pivot = None
        for i, row in enumerate(rows):
            if row >> col & 1 and i not in pivot_rows:
                pivot = i
                break
        if pivot is None:
            continue
        pivot_rows.append(pivot)
        rank += 1
        for i, row in enumerate(rows):
            if i != pivot and (row >> col & 1):
                rows[i] = row ^ rows[pivot]
    return rank < 64


# ---- 4. The same defects in C512-Lite ------------------------------------


def test_lite_shares_the_defects() -> None:
    print("\n[4] C512-Lite")
    if c512_lite is None:
        check("C512-Lite module is importable", False, "import failed")
        return

    apply_chi = getattr(c512_lite, "apply_chi", None)
    if apply_chi is None:
        print("  [skip] C512-Lite does not expose apply_chi under that name")
        return

    lanes = getattr(c512_lite, "C512_LITE_LANES", None) or getattr(
        c512_lite, "LANES", 16
    )
    if lanes % 2 != 0:
        print(f"  [skip] C512-Lite uses an odd lane ring ({lanes}); Chi may be invertible")
        return

    a, b, sa, sb = chi_collision(apply_chi, lanes)
    check("Lite inputs are distinct", a != b)
    check(
        "C512-Lite inherits the same Chi collision",
        sa == sb,
        "Lite's Chi differs from C512's; verify deliberately",
    )


def main() -> int:
    print(__doc__.split("Usage:")[0].strip())
    print("\n" + "=" * 70)
    print("These tests ASSERT THE DEFECTS ARE STILL PRESENT. A failure means")
    print("the algorithm was changed, not that it was fixed.")
    print("=" * 70)

    test_chi_not_a_permutation()
    test_butterfly_not_injective()
    test_cross_mix_kernel()
    test_lite_shares_the_defects()

    print("\n" + "=" * 70)
    if _failures:
        print(f"FAILED: {len(_failures)} of {_checks} checks")
        for name in _failures:
            print(f"  - {name}")
        print("\nThe algorithm no longer matches the recorded findings.")
        print("Bump the version, regenerate the vectors, and update CHANGELOG.md.")
        return 1
    print(f"All {_checks} structural-defect regressions reproduced.")
    print("C512 remains research-only. Use albpkg/ for real data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
