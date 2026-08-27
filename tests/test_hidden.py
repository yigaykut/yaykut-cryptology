"""The random decoy chain: hiding the message among different formulas every time."""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    TEXT_SLUG,
                    CIPHERTEXT_BYTES,
                    DecodeError,
                    VerificationError,
                    EncodingError,
                    Engine,
                    decode_chain,
                    decrypt_hidden,
                    encrypt_hidden,
                    load_corpus,
                    text_capacity,
)
from crypto.primitives import NONCE_BYTES  # noqa: E402

CORPUS = load_corpus()
KEY = bytes(range(32))
ENGINE = Engine(CORPUS, KEY)
CAPACITY = text_capacity(CORPUS)


def records(blob):
    return decode_chain(CORPUS, blob, KEY, check=False)


# ────────────────────────── round trip ──────────────────────────

@pytest.mark.parametrize("message", [
    "a",
    "Merhaba",
    "Modern cryptography: y^2 = x^3 + ax + b",
    "punctuation ,.;:!? and symbols",
    "A" * 1024,
], ids=["single-char", "simple", "with-formula", "non-ascii", "full-capacity"])
def test_covert_round_return(message):
    blob = ENGINE.encrypt_hidden(message)
    assert ENGINE.decrypt_hidden(blob) == message


def test_module_level_functions():
    blob = encrypt_hidden(CORPUS, "module", KEY)
    assert decrypt_hidden(CORPUS, blob, KEY) == "module"


# ────────────────────── is the randomness really there ──────────────────────

def test_every_in_encryption_formula_combination_changes():
    """The same message and key, but different decoy formulas every time."""
    combinations = set()
    for _ in range(20):
        blob = ENGINE.encrypt_hidden("the same message")
        names = tuple(e.slug for e, _ in records(blob))
        combinations.add(names)
    assert len(combinations) >= 15, f"not enough variety: {len(combinations)}/20"


def test_of_the_text_position_changes():
    """The real record must not always be in the same place."""
    positions = set()
    for _ in range(30):
        blob = ENGINE.encrypt_hidden("konum testi")
        record_list = records(blob)
        i = next(i for i, (e, _) in enumerate(record_list) if e.slug == TEXT_SLUG)
        positions.add(i)
    assert len(positions) >= 3, f"the text is always in the same position: {positions}"


def test_decoys_from_the_corpus_comes():
    blob = ENGINE.encrypt_hidden("decoy test")
    for e, _ in records(blob):
        assert e.id in CORPUS
        assert e.status == "active"


def test_text_record_full_one_count():
    for _ in range(10):
        blob = ENGINE.encrypt_hidden("tek metin")
        count = sum(1 for e, _ in records(blob) if e.slug == TEXT_SLUG)
        assert count == 1


def test_decoy_count_configurable():
    few = records(ENGINE.encrypt_hidden("x", target_decoys=1))
    many = records(ENGINE.encrypt_hidden("x", target_decoys=6))
    assert len(few) == 2          # 1 decoy + text
    assert len(many) > len(few)


def test_without_decoys_also_runs():
    blob = ENGINE.encrypt_hidden("alone", target_decoys=0)
    assert len(records(blob)) == 1
    assert ENGINE.decrypt_hidden(blob) == "alone"


# ────────────────────── nothing is visible from outside ──────────────────────

@pytest.mark.parametrize("message", ["a", "medium sized message", "Z" * 1024])
def test_output_length_fixed(message):
    assert len(ENGINE.encrypt_hidden(message)) == CIPHERTEXT_BYTES


def test_same_message_different_cipher():
    outputs = {ENGINE.encrypt_hidden("same") for _ in range(30)}
    assert len(outputs) == 30


def test_fixed_seed_and_nonce_with_deterministic():
    """Reproducibility: with a fixed seed and nonce the output is fixed too."""
    nonce = b"\x07" * NONCE_BYTES
    a = ENGINE.encrypt_hidden("repeat", rng=random.Random(42), nonce=nonce)
    b = ENGINE.encrypt_hidden("repeat", rng=random.Random(42), nonce=nonce)
    assert a == b


# ────────────────────────── mode confusion ──────────────────────────

def test_plain_text_covert_as_cannot_be_decoded():
    blob = ENGINE.encrypt_text("plain")
    with pytest.raises(DecodeError, match="not a chain"):
        ENGINE.decrypt_hidden(blob)


def test_covert_text_plain_as_cannot_be_decoded():
    blob = ENGINE.encrypt_hidden("secret")
    with pytest.raises(DecodeError, match="chain"):
        ENGINE.decrypt_text(blob)


def test_text_not_containing_chain_open_error_gives():
    from crypto import sample
    e = CORPUS.by_slug("aes-sbox")
    blob = ENGINE.encrypt_chain([(e.id, sample(e, random.Random(0)))])
    with pytest.raises(DecodeError, match="no text record"):
        ENGINE.decrypt_hidden(blob)


# ────────────────────────── error cases ──────────────────────────

def test_empty_text_is_refused():
    with pytest.raises(EncodingError, match="empty text"):
        ENGINE.encrypt_hidden("")


def test_multi_long_text_is_refused():
    with pytest.raises(EncodingError, match="too long"):
        ENGINE.encrypt_hidden("A" * (CAPACITY + 1))


def test_wrong_key_is_refused():
    blob = ENGINE.encrypt_hidden("secret")
    with pytest.raises(VerificationError):
        Engine(CORPUS, os.urandom(32)).decrypt_hidden(blob)


def test_tampering_is_caught():
    blob = bytearray(ENGINE.encrypt_hidden("integrity"))
    blob[500] ^= 0x01
    with pytest.raises(VerificationError):
        ENGINE.decrypt_hidden(bytes(blob))


# ────────────────────────── the padding region ──────────────────────────

from crypto import primitives# noqa: E402
from crypto.primitives import SELECTOR_BYTES, TAG_BYTES  # noqa: E402


def raw_payload(blob: bytes) -> bytes:
    """The payload BEFORE encryption, by backing out the keystream."""
    nonce = blob[:NONCE_BYTES]
    ct = blob[NONCE_BYTES + SELECTOR_BYTES:-TAG_BYTES]
    _, ks, _ = primitives.subkeys(KEY, nonce, len(ct))
    return primitives.xor(ct, ks)


def test_plain_in_mode_payload_end_zero():
    """The comparison baseline: in plain mode the unused area is zeros."""
    assert raw_payload(ENGINE.encrypt_text("short"))[-200:] == bytes(200)


@pytest.mark.parametrize("seed", range(12))
def test_covert_in_mode_zero_region_does_not_stay(seed):
    """Wherever the real record lands, no zero region may be left.

    In the first implementation the unused part of the text field was zero
    padded. When the record landed at the end, those zeros stayed at the end
    of the payload and reopened the very gap the decoys were closing. The leftover area is now random.
    """
    secret = raw_payload(ENGINE.encrypt_hidden("short", rng=random.Random(seed)))

    assert secret[-200:] != bytes(200), "there is a zero region at the end of the payload"
    assert b"\x00" * 64 not in secret, "there is a 64 byte run of zeros inside the payload"


def test_text_field_residue_random():
    """The unused area behind a short message must not be zeros."""
    record_list = records(ENGINE.encrypt_hidden("ab"))
    e, values = next((e, v) for e, v in record_list if e.slug == TEXT_SLUG)
    residue = values["metin"][values["uzunluk"]:]
    assert len(residue) > 900
    assert residue != bytes(len(residue))
