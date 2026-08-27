"""X25519, key exchange on Curve25519 (RFC 7748).

Layer 1 uses no external dependencies, so ECDH had to be written by hand. The
advice not to write your own curve arithmetic is sound, but it does not apply
equally to every curve. X25519 was designed to be implementable safely:

  - every 32 byte string is a valid public key, so there is no point validation
  - the Montgomery ladder is branchless, with no special cases and no separate
    code path for the point at infinity
  - it is twist secure, so no separate small subgroup check is needed
  - scalar clamping closes the cofactor problem at the source

None of that is free on P-256: point validation, Jacobian coordinates,
separate special cases for addition and doubling. Given two implementations
written with equal care, the P-256 one is far more likely to be wrong.

RFC 7748 section 5 gives the ladder as pseudocode. The code here is a direct
translation of it and is tested against the RFC's own vectors.

An honest warning about constant time behaviour: the ladder runs a fixed
number of steps and the conditional swap is arithmetic, so there is no
branching at the algorithm level. But Python's arbitrary width integers take
different amounts of time depending on operand size, so this implementation is
algorithmically constant time, not physically so.

In a threat model where timing attacks are reachable, meaning shared hardware,
precise remote measurement, or side channel access, that is not enough and a C
or Rust implementation is needed. The rest of the engine is in the same
position.

`ccore/crypto25519.c` closes that gap by implementing the same algorithm on
fixed width 64 bit integers. If it is built, `x25519()` uses it; otherwise it
falls back to the pure Python path below. The result is identical either way,
only the timing profile differs. `x25519_pure()` always calls the pure path so
tests can compare the two.
"""

from __future__ import annotations

from . import fastpath
from .errors import KeyManagementError

# The prime field of Curve25519.
P = (1 << 255) - 19

# (A - 2) / 4 where A = 486662. The ladder's only curve constant.
A24 = 121665

# Scalar bits scanned. After clamping, bit 255 is always 1.
BITS = 255

# The u coordinate of the base point, RFC 7748 section 4.1.
BASE_U = 9

KEY_BYTES = 32

# The zero result that comes from small order points. RFC 7748 section 6.1
# recommends checking for it: a zero shared secret is independent of the other
# side's private key.
ZERO_RESULT = bytes(KEY_BYTES)


def _cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    """Conditional swap without an `if`.

    swap is 0 or 1. In Python -1 is a mask of all ones and -0 is zero, so the
    mask comes out of arithmetic rather than out of a branch.
    """
    mask = -swap & (a ^ b)
    return a ^ mask, b ^ mask


def _clamp(secret: bytes) -> int:
    """RFC 7748 section 5, decodeScalar25519.

    Three bits are forced:
      - the low 3 bits are cleared, so the scalar is a multiple of 8 and the
        cofactor of 8 has no effect
      - bit 255 is cleared, so the scalar stays on the curve
      - bit 254 is set, so the ladder always runs the same number of
        significant steps and the time does not depend on the scalar
    """
    k = bytearray(secret)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def _decode_u(data: bytes) -> int:
    """RFC 7748 section 5, decodeUCoordinate. Little endian, top bit ignored."""
    u = bytearray(data)
    u[31] &= 0x7F
    return int.from_bytes(u, "little") % P


def _encode_u(u: int) -> bytes:
    return (u % P).to_bytes(KEY_BYTES, "little")


def _ladder(k: int, u: int) -> int:
    """The Montgomery ladder, a direct translation of RFC 7748 section 5.

    It works on the u coordinate only; v is never computed. Point addition and
    doubling use the same sequence of formulas, so there are no special cases.
    """
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for t in range(BITS - 1, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) % P
        x3 = x3 * x3 % P
        z3 = (da - cb) % P
        z3 = x1 * (z3 * z3 % P) % P
        x2 = aa * bb % P
        z2 = e * ((aa + A24 * e) % P) % P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)

    # z2^(p-2) = z2^-1 by Fermat's little theorem. No separate inversion
    # algorithm is needed, and since the exponent is fixed the time is too.
    return x2 * pow(z2, P - 2, P) % P


def _validate(data: bytes, name: str) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise KeyManagementError(
            f"{name}: expected bytes, got {type(data).__name__}")
    if len(data) != KEY_BYTES:
        raise KeyManagementError(
            f"{name} must be {KEY_BYTES} bytes, got {len(data)}")
    return bytes(data)


# ───────────────────────── public interface ─────────────────────────

def x25519_pure(secret: bytes, u: bytes) -> bytes:
    """The pure Python path, which runs even when the C core exists.

    Tests compare the C core against this; if they diverge, a test fails.
    """
    return _encode_u(_ladder(_clamp(_validate(secret, "private key")),
                             _decode_u(_validate(u, "u coordinate"))))


def x25519(secret: bytes, u: bytes) -> bytes:
    """RFC 7748's X25519 function: scalar times u coordinate.

    This is the single primitive used both for public key generation, where
    u is the base point, and for shared secret derivation, where u is the
    other side's public key.

    It goes through the compiled C core if there is one, and through pure
    Python otherwise. Validation happens first on both paths, so an invalid
    key length behaves the same whether or not the core exists.
    """
    s = _validate(secret, "private key")
    uu = _validate(u, "u coordinate")

    from_c = fastpath.x25519(s, uu)
    if from_c is not None:
        return from_c
    return _encode_u(_ladder(_clamp(s), _decode_u(uu)))


def x25519_buffer(secret, u: bytes) -> bytes:
    """Read the private key from a secure buffer, so it never becomes `bytes`.

    `secret` is a `memory.SecureBuffer`. With the C core the secret passes
    straight from the buffer's address into C and never enters Python object
    space.

    Without the core the operation still happens, but the secret has to pass
    through a temporary `bytes` and that copy cannot be erased. Continuing
    silently is deliberate, matching the project's rule everywhere, but the
    gain is lost. `buffer.guarantee` tells you which case you are in.
    """
    from .memory import SecureBuffer

    if not isinstance(secret, SecureBuffer):
        raise KeyManagementError(
            f"expected a SecureBuffer, got {type(secret).__name__}")
    if len(secret) != KEY_BYTES:
        raise KeyManagementError(
            f"private key must be {KEY_BYTES} bytes, got {len(secret)}")
    uu = _validate(u, "u coordinate")

    addr = secret.address
    if addr is not None:
        import ctypes
        out = ctypes.create_string_buffer(KEY_BYTES)
        u_buf = ctypes.create_string_buffer(uu, KEY_BYTES)
        if fastpath.x25519_address(addr,
                                   ctypes.addressof(u_buf),
                                   ctypes.addressof(out)):
            return out.raw[:KEY_BYTES]

    # Fallback path: the secret briefly becomes `bytes` here.
    return x25519_pure(secret.to_bytes(), uu)


def public_key_buffer(secret) -> bytes:
    """The public key for a private key held in a secure buffer.

    Returning `bytes` is fine, since a public key is not secret.
    """
    return x25519_buffer(secret, _encode_u(BASE_U))


def shared_secret_buffer(secret, peer_public: bytes):
    """The shared secret, returned as a SecureBuffer the caller must close.

    A shared secret is secret, and returning `bytes` would make it
    unerasable, so the return type is a buffer too.
    """
    from .memory import SecureBuffer

    raw = x25519_buffer(secret, peer_public)
    if raw == ZERO_RESULT:
        raise KeyManagementError(
            "the shared secret came out zero: the other side sent a small "
            "order point (RFC 7748 section 6.1).")
    return SecureBuffer(KEY_BYTES, data=raw)


def private_key(random: bytes | None = None) -> bytes:
    """A new X25519 private key.

    Clamping is not done here; `x25519` clamps on every call. That way the key
    is always the raw 32 bytes on disk or on the wire, and clamped and
    unclamped forms never get mixed up.
    """
    if random is None:
        from .keys import master_key
        return master_key(KEY_BYTES)
    return _validate(random, "random material")


def public_key(secret: bytes) -> bytes:
    """The public key for a private key: X25519(secret, 9)."""
    return x25519(secret, _encode_u(BASE_U))


def shared_secret(secret: bytes, peer_public: bytes) -> bytes:
    """The shared secret both sides arrive at.

        shared_secret(a, public_key(b)) == shared_secret(b, public_key(a))

    because both are the u coordinate of the point (a*b)*G. An attacker sees
    both public keys but would have to solve a discrete logarithm to find the
    shared secret.

    A zero result is rejected. If a small order point is sent, the result
    comes out zero regardless of the other side's private key, which would let
    an attacker choose the shared secret. RFC 7748 section 6.1 recommends this
    check.
    """
    secret_out = x25519(secret, peer_public)
    if secret_out == ZERO_RESULT:
        raise KeyManagementError(
            "the shared secret came out zero: the other side sent a small "
            "order point. That secret is independent of the private key and "
            "cannot be used (RFC 7748 section 6.1).")
    return secret_out
