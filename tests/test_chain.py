"""Chain mode: several formulas in one ciphertext."""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    MAX_RECORDS,
                    FRAME_BYTES,
                    BODY_FIXED_BYTES,
                    PAYLOAD_FIXED_BYTES,
                    CIPHERTEXT_BYTES,
                    CHAIN_ID,
                    DecodeError,
                    VerificationError,
                    EncodingError,
                    CorpusError,
                    Corpus,
                    Entry,
                    Engine,
                    decode,
                    decode_chain,
                    encode,
                    encode_chain,
                    load_corpus,
                    sample,
                    chain_capacity,
                    is_chain,
)

CORPUS = load_corpus()
KEY = bytes(range(32))
ENGINE = Engine(CORPUS, KEY)

# Small entries that fit comfortably into a chain.
SMALL = ["afin-sifre", "aes-sbox", "vigenere", "aes-mixcolumns", "chacha-ceyrek-tur"]


def record(slug: str, seed: int = 0):
    e = CORPUS.by_slug(slug)
    return slug, sample(e, random.Random(seed))


# ────────────────────────── round trip ──────────────────────────

@pytest.mark.parametrize("count", [1, 2, 3, 5])
def test_chain_round_return(count):
    records = [record(s, i) for i, s in enumerate(SMALL[:count])]
    blob = ENGINE.encrypt_chain(records)
    back = ENGINE.decode_chain(blob)

    assert len(back) == count
    for (e, values), (slug, original) in zip(back, records):
        assert e.slug == slug
        for p in e.public_params:
            assert values[p["name"]] == original[p["name"]]


def test_record_order_is_protected():
    records = [record("aes-sbox", 1), record("afin-sifre", 2), record("vigenere", 3)]
    back = ENGINE.decode_chain(ENGINE.encrypt_chain(records))
    assert [e.slug for e, _ in back] == ["aes-sbox", "afin-sifre", "vigenere"]


def test_same_formula_at_once_multi_times_can_be_set():
    records = [record("aes-sbox", i) for i in range(4)]
    back = ENGINE.decode_chain(ENGINE.encrypt_chain(records))
    assert len(back) == 4
    assert all(e.slug == "aes-sbox" for e, _ in back)


def test_identity_instead_slug_also_accept_is():
    e = CORPUS.by_slug("aes-sbox")
    records = [(e.id, sample(e, random.Random(0)))]
    back = ENGINE.decode_chain(ENGINE.encrypt_chain(records))
    assert back[0][0].id == e.id


# ────────────────────── the length says nothing ──────────────────────

@pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
def test_chain_length_fixed(count):
    """How many formulas it carries must not be readable from the output size."""
    records = [record(s, i) for i, s in enumerate(SMALL[:count])]
    assert len(ENGINE.encrypt_chain(records)) == CIPHERTEXT_BYTES


def test_chain_and_single_formula_same_length():
    """Whether it is a chain or a single formula must not be readable from the length either."""
    single = ENGINE.encrypt("aes-sbox", sample(CORPUS.by_slug("aes-sbox"), random.Random(0)))
    many = ENGINE.encrypt_chain([record(s, i) for i, s in enumerate(SMALL[:4])])
    assert len(single) == len(many) == CIPHERTEXT_BYTES


def test_same_chain_every_time_different_cipher():
    records = [record("aes-sbox", 0), record("afin-sifre", 0)]
    outputs = {ENGINE.encrypt_chain(records) for _ in range(30)}
    assert len(outputs) == 30


# ────────────────────────── mode confusion ──────────────────────────

def test_chain_single_formula_like_decoding_is_refused():
    blob = ENGINE.encrypt_chain([record("aes-sbox", 0)])
    with pytest.raises(DecodeError, match="chain"):
        ENGINE.decode(blob)


def test_single_formula_chain_like_decoding_is_refused():
    e = CORPUS.by_slug("aes-sbox")
    blob = ENGINE.encrypt(e.id, sample(e, random.Random(0)))
    with pytest.raises(DecodeError, match="not a chain"):
        ENGINE.decode_chain(blob)


def test_chain_correct_distinguish_does():
    e = CORPUS.by_slug("aes-sbox")
    single = ENGINE.encrypt(e.id, sample(e, random.Random(0)))
    many = ENGINE.encrypt_chain([record("aes-sbox", 0)])

    assert is_chain(CORPUS, many, KEY) is True
    assert is_chain(CORPUS, single, KEY) is False


def test_chain_wrong_in_the_key_error_gives():
    """Mode detection must not skip the tag."""
    blob = ENGINE.encrypt_chain([record("aes-sbox", 0)])
    with pytest.raises(VerificationError):
        is_chain(CORPUS, blob, os.urandom(32))


# ────────────────────────── capacity ──────────────────────────

def test_capacity_computation():
    e = CORPUS.by_slug("aes-sbox")
    needed, available = chain_capacity([e, e])
    # an 8 bit counter, a 16 bit id per record, and the payload
    assert needed == 8 + 2 * (16 + e.payload_bits)
    # What is open to the chain is the BODY, not the payload: the first 9 bytes are the frame header.
    assert available == BODY_FIXED_BYTES * 8
    assert available == (PAYLOAD_FIXED_BYTES - FRAME_BYTES) * 8


def test_not_fitting_chain_open_error_gives():
    """The largest entry does not fit into a chain: 24 bits of overhead overflows the payload."""
    large = max(CORPUS.active, key=lambda e: e.payload_bits)
    needed, available = chain_capacity([large])
    assert needed > available, "this test assumes the largest entry does not fit"

    with pytest.raises(EncodingError, match="does not fit"):
        ENGINE.encrypt_chain([(large.slug, sample(large, random.Random(0)))])


def test_multi_long_chain_is_refused():
    records = [record("afin-sifre", 0)] * (MAX_RECORDS + 1)
    with pytest.raises(EncodingError, match="at most"):
        ENGINE.encrypt_chain(records)


def test_empty_chain_is_refused():
    with pytest.raises(EncodingError, match="at least one"):
        ENGINE.encrypt_chain([])


def test_retired_entry_to_the_chain_cannot_be_set():
    retired = [e for e in CORPUS if e.status == "retired"]
    if not retired:
        pytest.skip("no retired entry in the corpus")
    e = retired[0]
    with pytest.raises(EncodingError, match="retired"):
        ENGINE.encrypt_chain([(e.id, {p["name"]: 0 for p in e.public_params})])


# ────────────────────────── integrity ──────────────────────────

def test_wrong_key_is_refused():
    blob = ENGINE.encrypt_chain([record("aes-sbox", 0), record("afin-sifre", 0)])
    with pytest.raises(VerificationError):
        Engine(CORPUS, os.urandom(32)).decode_chain(blob)


@pytest.mark.parametrize("position", [0, 20, 700, CIPHERTEXT_BYTES - 1])
def test_tampering_is_caught(position):
    blob = bytearray(ENGINE.encrypt_chain([record("aes-sbox", 0)]))
    blob[position] ^= 0x01
    with pytest.raises(VerificationError):
        ENGINE.decode_chain(bytes(blob))


def test_wrong_length_is_refused():
    with pytest.raises(DecodeError, match="wrong ciphertext length"):
        decode_chain(CORPUS, b"\x00" * 100, KEY)


# ────────────────────────── the reserved id ──────────────────────────

def test_corpus_reserved_identity_cannot_take():
    """0xFFFF is reserved for chain mode; if a corpus entry took that id it
    would be mistaken for a chain during decoding and silently shadowed."""
    fake = Entry(
        id=CHAIN_ID, slug="ayrilmis-deneme", version=1, status="active",
        doc={"name": "test"}, params=[],
    )
    with pytest.raises(CorpusError, match="reserved"):
        Corpus([fake])


def test_constraints_every_in_records_is_applied():
    """One invalid record in a chain has to stop the whole encryption."""
    from crypto import ConstraintViolation
    intact = record("aes-sbox", 0)
    broken = ("afin-sifre", {"m": 99, "a": 7, "b": 3})     # m < 26 ihlali
    with pytest.raises(ConstraintViolation, match="alphabet"):
        ENGINE.encrypt_chain([intact, broken])
