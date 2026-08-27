"""X25519 — RFC 7748 uyumu.

The most important part of this file is the RFC's own test vectors. The only
valid way to claim our own curve arithmetic is correct is for it to produce
the known answers the standard gives.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import KeyManagementError, public_key, shared_secret, private_key, x25519  # noqa: E402
from crypto import curve# noqa: E402

h = bytes.fromhex


# ───────────────────── RFC 7748 §5.2, the X25519 vectors ─────────────────────

@pytest.mark.parametrize("scalar, u, expected", [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
])
def test_rfc7748_5_2(scalar, u, expected):
    assert x25519(h(scalar), h(u)).hex() == expected


def test_rfc7748_5_2_iterated_one_round():
    """The RFC's iterated vector, feeding the ladder its own output."""
    k = u = h("0900000000000000000000000000000000000000000000000000000000000000")
    k, u = x25519(k, u), k
    assert k.hex() == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"


@pytest.mark.skipif(
    not os.environ.get("CRYPTO_SLOW_TESTS"),
    reason="1000 rounds takes about 6 seconds; enable with CRYPTO_SLOW_TESTS=1",
)
def test_rfc7748_5_2_iterated_thousand_round():
    k = u = h("0900000000000000000000000000000000000000000000000000000000000000")
    for _ in range(1000):
        k, u = x25519(k, u), k
    assert k.hex() == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"


# ───────────────────── RFC 7748 §6.1, key exchange ─────────────────────

ALICE_SECRET = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PUBLIC = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_SECRET = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PUBLIC = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def test_rfc7748_6_1_open_keys():
    assert public_key(ALICE_SECRET) == ALICE_PUBLIC
    assert public_key(BOB_SECRET) == BOB_PUBLIC


def test_rfc7748_6_1_shared_secret():
    assert shared_secret(ALICE_SECRET, BOB_PUBLIC) == SHARED
    assert shared_secret(BOB_SECRET, ALICE_PUBLIC) == SHARED


# ───────────────────── cross check against an independent implementation ─────────────────

def test_cryptography_with_same_result():
    """A comparison against an independent, battle tested implementation.

    `cryptography` is NOT a RUNTIME dependency. Layer 1 uses only the standard
    library and it is not in requirements.txt. It is used here purely as a
    source of truth, when it is available.
    """
    crypto_lib = pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)

    for _ in range(25):
        ref = X25519PrivateKey.generate()
        secret = ref.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        # public key generation
        assert public_key(secret) == ref.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        # shared secret
        against = X25519PrivateKey.generate()
        peer_public = against.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert shared_secret(secret, peer_public) == ref.exchange(
            X25519PublicKey.from_public_bytes(peer_public))


# ───────────────────────── properties ─────────────────────────

def test_commutativity_property():
    """What all of DH rests on: a*(b*G) = b*(a*G)."""
    for _ in range(10):
        a, b = private_key(), private_key()
        assert shared_secret(a, public_key(b)) == shared_secret(b, public_key(a))


def test_different_key_different_secret():
    a, b, c = private_key(), private_key(), private_key()
    assert shared_secret(a, public_key(b)) != shared_secret(a, public_key(c))


def test_private_key_fresh_and_correct_size():
    a, b = private_key(), private_key()
    assert len(a) == curve.KEY_BYTES == 32
    assert a != b


def test_clamping_is_done():
    """An unclamped and a clamped scalar have to give the same result; the engine clamps."""
    raw = bytes(range(32))
    clamped = bytearray(raw)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    assert public_key(raw) == public_key(bytes(clamped))


def test_u_coordinate_upper_bit_none_counts():
    """RFC 7748 §5: the most significant bit has to be masked."""
    u = bytearray(public_key(private_key()))
    secret = private_key()
    once = shared_secret(secret, bytes(u))
    u[31] |= 0x80
    assert shared_secret(secret, bytes(u)) == once


# ───────────────────────── small order points ─────────────────────────

@pytest.mark.parametrize("point", [
    "00" * 32,                       # sonsuzdaki point
    "01" + "00" * 31,                # mertebe 1
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",  # mertebe 8
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",  # mertebe 8
])
def test_zero_shared_secret_is_refused(point):
    """A zero secret is independent of the private key, so the attacker would choose it."""
    with pytest.raises(KeyManagementError, match="came out zero"):
        shared_secret(private_key(), h(point))


def test_x25519_raw_as_is_zero_can_rotate():
    """The refusal is in `shared_secret`; the raw primitive behaves as the RFC defines."""
    assert x25519(private_key(), bytes(32)) == bytes(32)


# ───────────────────────── entry denetimi ─────────────────────────

@pytest.mark.parametrize("bad", [b"", b"kisa", bytes(31), bytes(33), "metin"])
def test_invalid_length_is_refused(bad):
    with pytest.raises(KeyManagementError):
        public_key(bad)
    with pytest.raises(KeyManagementError):
        shared_secret(bytes(32), bad)
