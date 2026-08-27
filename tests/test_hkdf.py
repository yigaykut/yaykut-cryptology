"""HKDF: RFC 5869's own test vectors.

WHY THIS FILE CAME LATER

While `docs/audit.md` was being prepared, this line surfaced:

    "HKDF was not tested against the RFC 5869 vectors. The construction is a
     translation of the RFC, but the vectors are not run."

That was the first place the audit document earned its keep: writing the
claims out one by one made it visible which of them had nothing behind it.
Closing the gap was cheaper than documenting it and moving on.

WHY IT MATTERS
HKDF is the system's **only** key derivation path. The selector mask, the
payload keystream, the MAC key, device and epoch keys, handshake session
keys, all of them come from here. A deviation here would affect everything,
and the rest of the tests COULD NOT CATCH IT: a wrong derivation that is
self consistent passes an encrypt and decrypt cycle without a problem.

Producing the known answers the standard gives is a different thing from
being self consistent. It is correctness.

The vectors: RFC 5869 Appendix A, only the SHA-256 ones (A.1, A.2, A.3).
A.4 to A.7 are for SHA-1, which this project does not use.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto.primitives import HASH_LEN, hkdf_expand, hkdf_extract  # noqa: E402

h = bytes.fromhex


# ───────────────────── RFC 5869 Appendix A, the SHA-256 vectors ─────────────────────

# A.1: the base case
A1_IKM = h("0b" * 22)
A1_SALT = h("000102030405060708090a0b0c")
A1_INFO = h("f0f1f2f3f4f5f6f7f8f9")
A1_L = 42
A1_PRK = h("077709362c2e32df0ddc3f0dc47bba63"
           "90b6c73bb50f9c3122ec844ad7c2b3e5")
A1_OKM = h("3cb25f25faacd57a90434f64d0362f2a"
           "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
           "34007208d5b887185865")

# A.2: long input and long output
A2_IKM = h("".join(f"{i:02x}" for i in range(80)))
A2_SALT = h("".join(f"{i:02x}" for i in range(0x60, 0x60 + 80)))
A2_INFO = h("".join(f"{i:02x}" for i in range(0xb0, 0xb0 + 80)))
A2_L = 82
A2_PRK = h("06a6b88c5853361a06104c9ceb35b45c"
           "ef760014904671014a193f40c15fc244")
A2_OKM = h("b11e398dc80327a1c8e7f78c596a4934"
           "4f012eda2d4efad8a050cc4c19afa97c"
           "59045a99cac7827271cb41c65e590e09"
           "da3275600c2f09b8367793a9aca3db71"
           "cc30c58179ec3e87c14c01d5c1f3434f"
           "1d87")

# A.3: empty salt and info
A3_IKM = h("0b" * 22)
A3_SALT = b""
A3_INFO = b""
A3_L = 42
A3_PRK = h("19ef24a32c717b167f33a91d6f648bdf"
           "96596776afdb6377ac434c1c293ccb04")
A3_OKM = h("8da4e775a563c18f715f802a063c5a31"
           "b8a11f5c5ee1879ec3454e5f3c738d2d"
           "9d201395faa4b61a96c8")


VECTORS = [
    pytest.param(A1_IKM, A1_SALT, A1_INFO, A1_L, A1_PRK, A1_OKM, id="A.1"),
    pytest.param(A2_IKM, A2_SALT, A2_INFO, A2_L, A2_PRK, A2_OKM, id="A.2"),
    pytest.param(A3_IKM, A3_SALT, A3_INFO, A3_L, A3_PRK, A3_OKM, id="A.3"),
]


@pytest.mark.parametrize("ikm, salt, info, length, prk, okm", VECTORS)
def test_rfc5869_extract(ikm, salt, info, length, prk, okm):
    """The extract step has to produce the PRK the standard gives."""
    assert hkdf_extract(salt, ikm) == prk


@pytest.mark.parametrize("ikm, salt, info, length, prk, okm", VECTORS)
def test_rfc5869_expand(ikm, salt, info, length, prk, okm):
    """The expand step has to produce the OKM the standard gives."""
    assert hkdf_expand(prk, info, length) == okm


@pytest.mark.parametrize("ikm, salt, info, length, prk, okm", VECTORS)
def test_rfc5869_end_end(ikm, salt, info, length, prk, okm):
    """Chained together they are correct too, which is how they are actually used."""
    assert hkdf_expand(hkdf_extract(salt, ikm), info, length) == okm


def test_empty_salt_zero_sequence_means():
    """RFC 5869 §2.2: with no salt, a HashLen string of zeros is used.

    The A.3 vector already tests this; the equivalence is shown explicitly
    here so nobody later "simplifies" the `salt or ...` line away.
    """
    assert hkdf_extract(b"", A3_IKM) == hkdf_extract(bytes(HASH_LEN), A3_IKM)


# ───────────────────── bounds ─────────────────────

def test_maximum_length():
    """RFC 5869: L <= 255*HashLen, because the counter is a single byte."""
    at_most = 255 * HASH_LEN
    prk = hkdf_extract(b"tuz", b"malzeme")
    assert len(hkdf_expand(prk, b"", at_most)) == at_most
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"", at_most + 1)


def test_negative_length():
    with pytest.raises(ValueError):
        hkdf_expand(hkdf_extract(b"", b"x"), b"", -1)


def test_zero_length():
    assert hkdf_expand(hkdf_extract(b"", b"x"), b"", 0) == b""


def test_block_bound_around():
    """Is truncation at the block boundary right: 31, 32 and 33 bytes.

    The most likely bug in a hand written HKDF is cutting the last block
    wrong. It goes unnoticed on short output and is a disaster on long output.
    """
    prk = hkdf_extract(b"tuz", b"malzeme")
    exact = hkdf_expand(prk, b"bilgi", 96)
    for n in (1, 31, 32, 33, 63, 64, 65, 96):
        assert hkdf_expand(prk, b"bilgi", n) == exact[:n]


# ───────────────────── domain separation ─────────────────────

def test_different_info_different_key():
    """The whole basis of domain separation: a different label, a different output.

    In the system the selector mask, the payload stream and the MAC key all
    derive from the same parent, and their non interchangeability rests on this.
    """
    prk = hkdf_extract(b"tuz", b"malzeme")
    outputs = {hkdf_expand(prk, label, 32)
               for label in (b"kripto/v1/selector",
                             b"kripto/v1/payload",
                             b"kripto/v1/mac",
                             b"")}
    assert len(outputs) == 4


def test_different_salt_different_prk():
    assert hkdf_extract(b"tuz-a", b"ayni") != hkdf_extract(b"tuz-b", b"ayni")
