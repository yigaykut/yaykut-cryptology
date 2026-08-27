"""THE PYTHON TWIN of crypto25519.c, a verification tool for the C arithmetic.

WHY SUCH A FILE EXISTS

The C core was written but this machine had no compiler, and cryptography
code that has never been compiled does not count as written. The twin closes
that gap: a LINE BY LINE equivalent of the limb arithmetic in crypto25519.c,
with the same base, the same constants and the same carry passes. Anything
that passes here passes in C too; the only risk left is C syntax and
yakalar.

This file tests TWO things at once:

  1. CORRECTNESS: the twin must give the same result as the pure Python
     implementation in crypto/curve.py, which is tested against RFC vectors.
  2. OVERFLOW MARGIN: in C an int64 overflows silently, in Python it does
     not. The twin asserts every intermediate against the 2^63 bound, so
     "does this overflow in C?" gets answered in Python, without noise.

NOT USED IN PRODUCTION. The pure Python path is `crypto/curve.py` and the
fast path is the compiled C; the twin is a verification tool the tests call.
"""

from __future__ import annotations

LIMBS = 12
BASE = 22
MASK = (1 << BASE) - 1
FOLD = 9728          # 2^264 mod (2^255 - 19) = 19 * 512
LIMIT = 1 << 63       # the int64 overflow threshold

P = (1 << 255) - 19

P22 = [4194285, 4194303, 4194303, 4194303, 4194303, 4194303,
       4194303, 4194303, 4194303, 4194303, 4194303, 8191]

Q1024 = [4294947840, 4294966272, 4294966272, 4294966272, 4294966272,
         4294966272, 4294966272, 4294966272, 4294966272, 4294966272,
         4294966272, 8387584]


class OverflowGuard(AssertionError):
    """This would be an int64 overflow in C, and the twin does not let it pass."""


def _check_bounds(limbs, where: str) -> None:
    for i, v in enumerate(limbs):
        if not -LIMIT < v < LIMIT:
            raise OverflowGuard(
                f"{where}: limb[{i}] = {v} exceeds the int64 bound "
                f"(|v| >= 2^63). The C implementation would silently give "
                f"a wrong result here."
            )


# ───────────────────────── basic operations ─────────────────────────

def fe_carry(h: list[int]) -> None:
    """`fe_carry` from the C: three passes of carry propagation."""
    _check_bounds(h, "fe_carry input")
    for _ in range(3):
        for i in range(LIMBS - 1):
            c = h[i] >> BASE            # in Python this is an arithmetic shift too
            h[i] -= c << BASE
            h[i + 1] += c
        c = h[LIMBS - 1] >> BASE
        h[LIMBS - 1] -= c << BASE
        h[0] += c * FOLD
        _check_bounds(h, "fe_carry intermediate round")
    # The claim that three passes are enough is NOT CHECKED in C; it is here.
    for i, v in enumerate(h):
        if not 0 <= v <= MASK:
            raise OverflowGuard(
                f"fe_carry did not converge in three passes: limb[{i}] = {v}, "
                f"expected range [0, {MASK}]"
            )


def fe_add(f: list[int], g: list[int]) -> list[int]:
    h = [f[i] + g[i] for i in range(LIMBS)]
    fe_carry(h)
    return h


def fe_sub(f: list[int], g: list[int]) -> list[int]:
    h = [f[i] + Q1024[i] - g[i] for i in range(LIMBS)]
    # The claim that no borrow is ever needed is a silent assumption on the
    # C side and is tested here.
    for i, v in enumerate(h):
        if v < 0:
            raise OverflowGuard(
                f"fe_sub went negative: limb[{i}] = {v}. That means the Q1024 "
                f"multiple was not large enough."
            )
    fe_carry(h)
    return h


def fe_mul(f: list[int], g: list[int]) -> list[int]:
    acc = [0] * LIMBS
    for i in range(LIMBS):
        for j in range(LIMBS - i):
            acc[i + j] += f[i] * g[j]
        for j in range(LIMBS - i, LIMBS):
            acc[i + j - LIMBS] += FOLD * (f[i] * g[j])
    _check_bounds(acc, "fe_mul birikeci")
    h = list(acc)
    fe_carry(h)
    return h


def fe_sq(f: list[int]) -> list[int]:
    return fe_mul(f, f)


def fe_mul121665(f: list[int]) -> list[int]:
    h = [v * 121665 for v in f]
    fe_carry(h)
    return h


def fe_cswap(f: list[int], g: list[int], b: int) -> None:
    mask = -b
    for i in range(LIMBS):
        x = mask & (f[i] ^ g[i])
        f[i] ^= x
        g[i] ^= x


def fe_zero() -> list[int]:
    return [0] * LIMBS


def fe_one() -> list[int]:
    h = fe_zero()
    h[0] = 1
    return h


# ───────────────────── seri hâle getirme ─────────────────────

def fe_frombytes(s: bytes) -> list[int]:
    t = bytearray(s[:32]) + bytes(4)
    t[31] &= 0x7F
    h = []
    for i in range(LIMBS):
        bit = BASE * i
        byte, kay = bit >> 3, bit & 7
        v = (t[byte] | (t[byte + 1] << 8)
             | (t[byte + 2] << 16) | (t[byte + 3] << 24))
        h.append((v >> kay) & MASK)
    return h


def fe_reduce(h: list[int]) -> None:
    fe_carry(h)
    for _ in range(2):
        q = h[LIMBS - 1] >> 13
        h[LIMBS - 1] -= q << 13
        h[0] += 19 * q
        fe_carry(h)


def fe_tobytes(f: list[int]) -> bytes:
    h = list(f)
    fe_reduce(h)

    borrow = 0
    t = [0] * LIMBS
    for i in range(LIMBS):
        d = h[i] - P22[i] - borrow
        borrow = (d >> BASE) & 1
        t[i] = d + (borrow << BASE)
    mask = -borrow
    for i in range(LIMBS):
        h[i] = (h[i] & mask) | (t[i] & ~mask)

    output = bytearray(36)
    for i in range(LIMBS):
        bit = BASE * i
        byte, kay = bit >> 3, bit & 7
        v = h[i] << kay
        output[byte] |= v & 0xFF
        output[byte + 1] |= (v >> 8) & 0xFF
        output[byte + 2] |= (v >> 16) & 0xFF
        output[byte + 3] |= (v >> 24) & 0xFF
    return bytes(output[:32])


# ───────────────────────── ters alma ─────────────────────────

def fe_invert(z: list[int]) -> list[int]:
    t0 = fe_sq(z)
    t1 = fe_sq(fe_sq(t0))
    t1 = fe_mul(z, t1)
    t0 = fe_mul(t0, t1)
    t2 = fe_sq(t0)
    t1 = fe_mul(t1, t2)

    t2 = fe_sq(t1)
    for _ in range(1, 5):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)

    t2 = fe_sq(t1)
    for _ in range(1, 10):
        t2 = fe_sq(t2)
    t2 = fe_mul(t2, t1)

    t3 = fe_sq(t2)
    for _ in range(1, 20):
        t3 = fe_sq(t3)
    t2 = fe_mul(t3, t2)

    t2 = fe_sq(t2)
    for _ in range(1, 10):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)

    t2 = fe_sq(t1)
    for _ in range(1, 50):
        t2 = fe_sq(t2)
    t2 = fe_mul(t2, t1)

    t3 = fe_sq(t2)
    for _ in range(1, 100):
        t3 = fe_sq(t3)
    t2 = fe_mul(t3, t2)

    t2 = fe_sq(t2)
    for _ in range(1, 50):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)

    t1 = fe_sq(t1)
    for _ in range(1, 5):
        t1 = fe_sq(t1)
    return fe_mul(t1, t0)


# ─────────────────────── ladder and interface ───────────────────────

def ladder(k: bytes, u: list[int]) -> list[int]:
    x1 = list(u)
    x2, z2 = fe_one(), fe_zero()
    x3, z3 = list(u), fe_one()
    swap = 0

    for t in range(254, -1, -1):
        kt = (k[t >> 3] >> (t & 7)) & 1
        swap ^= kt
        fe_cswap(x2, x3, swap)
        fe_cswap(z2, z3, swap)
        swap = kt

        a = fe_add(x2, z2)
        aa = fe_sq(a)
        b = fe_sub(x2, z2)
        bb = fe_sq(b)
        e = fe_sub(aa, bb)
        c = fe_add(x3, z3)
        d = fe_sub(x3, z3)
        da = fe_mul(d, a)
        cb = fe_mul(c, b)

        x3 = fe_sq(fe_add(da, cb))
        z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)))
        x2 = fe_mul(aa, bb)
        z2 = fe_mul(e, fe_add(aa, fe_mul121665(e)))

    fe_cswap(x2, x3, swap)
    fe_cswap(z2, z3, swap)
    return fe_mul(x2, fe_invert(z2))


def x25519(secret: bytes, u: bytes) -> bytes:
    """The exact Python equivalent of the C function crypto25519()."""
    k = bytearray(secret[:32])
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return fe_tobytes(ladder(bytes(k), fe_frombytes(u)))


# ───────────────────── small helpers, for the tests ─────────────────────

def limbs_to_int(h: list[int]) -> int:
    """Turns the limb representation into an integer, for intermediate checks."""
    return sum(v << (BASE * i) for i, v in enumerate(h)) % P


def int_to_limbs(x: int) -> list[int]:
    x %= P
    return [(x >> (BASE * i)) & MASK for i in range(LIMBS)]
