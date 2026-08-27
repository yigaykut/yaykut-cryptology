"""Free text encryption tests."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    CIPHERTEXT_BYTES,
                    DecodeError,
                    VerificationError,
                    EncodingError,
                    Engine,
                    load_corpus,
                    decrypt_text,
                    text_capacity,
                    encrypt_text,
)

CORPUS = load_corpus()
KEY = bytes(range(32))
ENGINE = Engine(CORPUS, KEY)
CAPACITY = text_capacity(CORPUS)


# ────────────────────────── round trip ──────────────────────────

@pytest.mark.parametrize("text", [
    "a",
    "café, naïve, üñî",
    "An encrypted message about modern cryptography",
    "punctuation ,.;:!? and symbols",
    "Line1\nLine2\ttab",
    "emoji and symbols: ∀x∈ℝ, √2 ≈ 1.414",
    "A" * 1024,
], ids=["single-char", "non-ascii", "sentence", "punctuation", "whitespace",
        "unicode-symbols", "full-capacity"])
def test_text_round_return(text):
    blob = ENGINE.encrypt_text(text)
    assert ENGINE.decrypt_text(blob) == text


def test_text_characters_two_byte_counts():
    """Non ASCII letters take 2 bytes in UTF-8; the capacity is in BYTES."""
    text = "é" * (CAPACITY // 2)
    assert len(text.encode("utf-8")) == CAPACITY
    assert ENGINE.decrypt_text(ENGINE.encrypt_text(text)) == text


def test_module_level_functions():
    blob = encrypt_text(CORPUS, "a module test", KEY)
    assert decrypt_text(CORPUS, blob, KEY) == "a module test"


# ────────────────────────── length privacy ──────────────────────────

def test_all_messages_same_length():
    """ADR-007: the message length must not be readable from the ciphertext."""
    lengths = {
        len(ENGINE.encrypt_text(m))
        for m in ["a", "short", "a message of medium length", "X" * 500, "Y" * 1024]
    }
    assert lengths == {CIPHERTEXT_BYTES}


def test_length_field_cipher_in_the_text_open_not():
    """The length is inside the payload and encrypted; it must not show in the raw bytes.

    The ciphertexts of a 1 byte and a 1024 byte message must not be
    systematically the same at any position.
    """
    a = ENGINE.encrypt_text("A")
    b = ENGINE.encrypt_text("B" * 1024)
    assert len(a) == len(b)
    # Apart from the nonce everything is encrypted with a different keystream,
    # so the matching byte ratio has to stay at chance level (about 1/256).
    same = sum(1 for x, y in zip(a, b) if x == y)
    assert same < len(a) * 0.05, f"more shared bytes than expected: {same}/{len(a)}"


def test_same_message_every_time_different_cipher():
    outputs = {ENGINE.encrypt_text("the same message") for _ in range(50)}
    assert len(outputs) == 50


# ────────────────────────── error cases ──────────────────────────

def test_empty_text_is_refused():
    with pytest.raises(EncodingError, match="empty text"):
        ENGINE.encrypt_text("")


def test_multi_long_text_is_refused():
    with pytest.raises(EncodingError, match="too long"):
        ENGINE.encrypt_text("A" * (CAPACITY + 1))


def test_multi_long_text_text_is_refused():
    """The character count can be under the limit while the byte count is over."""
    text = "é" * (CAPACITY // 2 + 1)
    assert len(text) < CAPACITY          # under the limit in characters
    assert len(text.encode("utf-8")) > CAPACITY   # over it in bytes
    with pytest.raises(EncodingError, match="too long"):
        ENGINE.encrypt_text(text)


def test_text_not_entry_is_refused():
    with pytest.raises(EncodingError, match="expected text"):
        ENGINE.encrypt_text(b"byte string")


def test_wrong_key_is_refused():
    blob = ENGINE.encrypt_text("secret")
    with pytest.raises(VerificationError):
        Engine(CORPUS, os.urandom(32)).decrypt_text(blob)


def test_tampering_is_caught():
    blob = bytearray(ENGINE.encrypt_text("an integrity test"))
    blob[100] ^= 0x01
    with pytest.raises(VerificationError):
        ENGINE.decrypt_text(bytes(blob))


def test_formula_entry_text_as_cannot_be_decoded():
    """A ciphertext carrying a formula must not silently return broken text."""
    blob = ENGINE.encrypt("afin-sifre", {"m": 7, "a": 7, "b": 3})
    with pytest.raises(DecodeError, match="not raw text"):
        ENGINE.decrypt_text(blob)


def test_text_blob_formula_as_decodable():
    """The other direction has to work: a raw text entry also reads with a normal decode."""
    blob = ENGINE.encrypt_text("both ways")
    entry, values = ENGINE.decode(blob)
    assert entry.slug == "ham-metin"
    assert values["metin"][: values["uzunluk"]].decode("utf-8") == "both ways"


# ────────────────────────── capacity ──────────────────────────

def test_capacity_from_the_corpus_is_derived():
    """It must not be hard coded; it has to be computed from the entry's bits."""
    entry = CORPUS.by_slug("ham-metin")
    assert CAPACITY == entry.param("metin")["bits"] // 8


def test_capacity_payload_to_the_bound_fits():
    entry = CORPUS.by_slug("ham-metin")
    from crypto import PAYLOAD_FIXED_BYTES
    assert entry.payload_bytes <= PAYLOAD_FIXED_BYTES
