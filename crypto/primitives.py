"""Cryptographic primitives, built only on the standard library.

Everything here is deterministic: the same key and nonce always produce the
same output. Unpredictability comes from the nonce, not from the algorithm.

The keystream is HMAC-SHA256 run in counter mode, which is exactly
HKDF-Expand. It is secure as long as HMAC is a PRF. ChaCha20 would be
faster, but it would mean an external dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import os

HASH = hashlib.sha256
HASH_LEN = 32

NONCE_BYTES = 16
SELECTOR_BYTES = 2
TAG_BYTES = 32

# Domain separation. Subkeys derived from the same master key must not be
# interchangeable, so each use has its own label.
INFO_SELECTOR = b"kripto/v1/selector"
INFO_PAYLOAD = b"kripto/v1/payload"
INFO_MAC = b"kripto/v1/mac"


def new_nonce() -> bytes:
    """A fresh nonce from the operating system's CSPRNG.

    This is the only source of randomness in the system.
    """
    return os.urandom(NONCE_BYTES)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2. Compresses key material into a uniform PRK."""
    return hmac.new(salt or bytes(HASH_LEN), ikm, HASH).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3. Produces key material of the requested length."""
    if length < 0:
        raise ValueError("length cannot be negative")
    if length > 255 * HASH_LEN:
        raise ValueError(
            f"HKDF produces at most {255 * HASH_LEN} bytes, asked for {length}")
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), HASH).digest()
        out += block
        counter += 1
    return bytes(out[:length])


def subkeys(master_key: bytes, nonce: bytes,
            payload_len: int) -> tuple[bytes, bytes, bytes]:
    """Derive the three subkeys from the master key and nonce.

    The nonce is used as the salt, so every subkey changes on every message.
    Encrypting the same formula twice with the same key gives completely
    different output.

    Returns (selector mask, payload keystream, MAC key).
    """
    prk = hkdf_extract(salt=nonce, ikm=master_key)
    return (
        hkdf_expand(prk, INFO_SELECTOR, SELECTOR_BYTES),
        hkdf_expand(prk, INFO_PAYLOAD, payload_len),
        hkdf_expand(prk, INFO_MAC, HASH_LEN),
    )


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"XOR needs equal lengths: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def tag(mac_key: bytes, data: bytes) -> bytes:
    """Authentication tag over the encrypted data (encrypt-then-MAC)."""
    return hmac.new(mac_key, data, HASH).digest()


def verify_tag(mac_key: bytes, data: bytes, expected: bytes) -> bool:
    """Constant-time comparison.

    A plain == stops at the first differing byte, and the timing difference
    lets an attacker guess the tag one byte at a time.
    """
    return hmac.compare_digest(tag(mac_key, data), expected)
