"""Multi block long messages (`crypto/longmessage.py`).

WHY THIS FILE EXISTS

Naive splitting is open to four attacks without the key ever being known:
reordering, truncation, duplication, and splicing in a block from another
message. Because each block carries a valid MAC on its own, none of them
looks like "corrupt ciphertext"; what comes out is silently WRONG YET VALID.

Most of the tests here exercise those four separately. Their passing is the
proof that the block header really is inside MAC coverage.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crypto import DecodeError, EncodingError, load_corpus  # noqa: E402
from crypto.network import Network, NetworkMode  # noqa: E402
from crypto.longmessage import (  # noqa: E402
                                MAX_BLOCKS,
                                block_capacity,
                                decrypt_long,
                                long_capacity,
                                encrypt_long,
)

KEY = bytes(range(32))


@pytest.fixture(scope="module")
def corpus():
    return load_corpus()


@pytest.fixture(scope="module")
def long(corpus):
    return "A long message repeated to fill several blocks. " * 300


# ═══════════════════════ TEMEL ═══════════════════════

def test_round_return(corpus, long):
    b = encrypt_long(corpus, long, KEY)
    assert len(b) > 1
    assert decrypt_long(corpus, b, KEY) == long


def test_single_block_fitting_text_also_works(corpus):
    b = encrypt_long(corpus, "short", KEY)
    assert len(b) == 1
    assert decrypt_long(corpus, b, KEY) == "short"


def test_full_capacity_bound(corpus):
    """A length landing EXACTLY on a block boundary, so no off by one."""
    body = block_capacity(corpus)
    for n in (body - 1, body, body + 1, 2 * body):
        text = "a" * n
        assert decrypt_long(corpus, encrypt_long(corpus, text, KEY),
                            KEY) == text


def test_blocks_same_size(corpus, long):
    """The block size must not vary with the content (ADR-007 at block level)."""
    b = encrypt_long(corpus, long, KEY)
    assert len({len(x) for x in b}) == 1


def test_text_characters_is_not_broken(corpus):
    text = "repeated content for the size check " * 200
    assert decrypt_long(corpus, encrypt_long(corpus, text, KEY),
                        KEY) == text


def test_with_the_prekey_works(corpus, long):
    with Network.create(NetworkMode.OPEN) as net:
        k, p = net.member_key("alice"), net.prekey()
        b = encrypt_long(corpus, long, k, prekey=p)
        assert decrypt_long(corpus, b, k, prekey=p) == long


# ═══════════════════ THE FOUR ATTACKS ═══════════════════

def test_AGAIN_REORDER_harm_does_not_give(corpus, long):
    """The order is read from the header inside MAC coverage; transport order is irrelevant."""
    b = encrypt_long(corpus, long, KEY)
    mixed = list(b)
    random.Random(0).shuffle(mixed)
    assert mixed != b
    assert decrypt_long(corpus, mixed, KEY) == long


def test_TRUNCATION_is_caught(corpus, long):
    """Dropping the last blocks meant cutting off the end of the message."""
    b = encrypt_long(corpus, long, KEY)
    with pytest.raises(DecodeError, match="INCOMPLETE"):
        decrypt_long(corpus, b[:-1], KEY)
    with pytest.raises(DecodeError, match="INCOMPLETE"):
        decrypt_long(corpus, b[:1], KEY)


def test_DUPLICATION_is_caught(corpus, long):
    b = encrypt_long(corpus, long, KEY)
    with pytest.raises(DecodeError, match="twice"):
        decrypt_long(corpus, b + [b[0]], KEY)


def test_ANOTHER_FROM_THE_MESSAGE_block_is_caught(corpus, long):
    """Without `message_id` the blocks of two messages could be spliced."""
    a = encrypt_long(corpus, long, KEY)
    b = encrypt_long(corpus, long + " ikinci", KEY)
    with pytest.raises(DecodeError, match="different messages"):
        decrypt_long(corpus, a[:-1] + [b[len(a) - 1]], KEY)


def test_same_text_two_times_DIFFERENT_message_id_takes(corpus, long):
    """If `message_id` were fixed, the blocks of two messages could mix."""
    a = encrypt_long(corpus, long, KEY)
    b = encrypt_long(corpus, long, KEY)
    with pytest.raises(DecodeError, match="different messages"):
        decrypt_long(corpus, a[:-1] + [b[-1]], KEY)


def test_broken_block_MAC_in_fails(corpus, long):
    from crypto import VerificationError

    b = encrypt_long(corpus, long, KEY)
    broken = bytearray(b[1])
    broken[100] ^= 0xFF
    with pytest.raises(VerificationError):
        decrypt_long(corpus, [b[0], bytes(broken)] + b[2:], KEY)


def test_wrong_key_cannot_decode(corpus, long):
    from crypto import VerificationError

    b = encrypt_long(corpus, long, KEY)
    with pytest.raises(VerificationError):
        decrypt_long(corpus, b, bytes(32))


# ═══════════════════════ DOLGU ═══════════════════════

def test_block_target_length_hides(corpus):
    """Two messages of different lengths have to show the same block count."""
    a = encrypt_long(corpus, "a", KEY, target_blocks=6)
    b = encrypt_long(corpus, "b" * 3000, KEY, target_blocks=6)
    assert len(a) == len(b) == 6
    assert {len(x) for x in a} == {len(x) for x in b}
    assert decrypt_long(corpus, a, KEY) == "a"
    assert decrypt_long(corpus, b, KEY) == "b" * 3000


def test_block_target_clamping_DOES_NOT(corpus):
    """If the target is smaller than needed it must raise rather than silently lose data."""
    text = "x" * (block_capacity(corpus) * 3)
    with pytest.raises(EncodingError, match="blocks, target"):
        encrypt_long(corpus, text, KEY, target_blocks=1)


@pytest.mark.parametrize("target", [0, -1, "3", 1.5])
def test_broken_block_target_is_refused(corpus, target):
    with pytest.raises(EncodingError):
        encrypt_long(corpus, "x", KEY, target_blocks=target)


# ═══════════════════════ LIMITS ═══════════════════════

def test_empty_text_is_refused_2(corpus):
    with pytest.raises(EncodingError):
        encrypt_long(corpus, "", KEY)


def test_text_not_is_refused(corpus):
    with pytest.raises(EncodingError):
        encrypt_long(corpus, b"bytes", KEY)


def test_empty_block_list_is_refused(corpus):
    with pytest.raises(DecodeError):
        decrypt_long(corpus, [], KEY)


def test_block_ceiling(corpus):
    with pytest.raises(EncodingError, match="limit"):
        encrypt_long(corpus, "x", KEY, target_blocks=MAX_BLOCKS + 1)


def test_capacity_computation_consistent(corpus):
    assert long_capacity(corpus, 10) == block_capacity(corpus) * 10
    assert block_capacity(corpus) > 0
