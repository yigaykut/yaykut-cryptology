"""Free text encryption.

The engine really carries "which formula plus its parameters". To send raw
text there is a dedicated corpus entry, `0x0701 ham-metin`, whose parameters
are the text itself and its real length. The engine needed no changes: the
mechanism was already general, only a new corpus entry was added.

Message length does not leak. The length field lives inside the payload and
the payload is encrypted with the keystream. On top of that every ciphertext
is a fixed 1339 bytes, so a three letter message and a thousand letter one
look identical from outside; neither length nor content can be told apart.

One ciphertext carries at most 1024 bytes of UTF-8. Splitting longer messages
across blocks is possible, but the number of pieces gives away the length,
which brings back part of the leak the fixed size envelope closed. That is why
this is limited to a single block and overflow is rejected with a clear error.
See `longmessage.py` for the multi block path and what it costs.
"""

from __future__ import annotations

import random
from typing import Any

from .corpus import Corpus, Entry, param_bits
from .errors import DecodeError, EncodingError
from .frame import UNSEQUENCED
from .sampler import sample_or_free
from .wire import (
    BODY_FIXED_BYTES,
    CHAIN_COUNTER_BITS,
    SELECTOR_BYTES,
    decode,
    decode_chain,
    encode,
    encode_chain,
)

TEXT_SLUG = "ham-metin"

# Target number of decoy records in a random chain.
DEFAULT_DECOYS = 6


def text_capacity(corpus: Corpus) -> int:
    """Most UTF-8 bytes a single ciphertext can carry.

    Derived from the corpus entry rather than hard coded, so if the entry's
    `bits` value changes this limit follows automatically.
    """
    entry = corpus.by_slug(TEXT_SLUG)
    bits = param_bits(entry.param("metin"))
    if bits is None:
        raise EncodingError(
            f"{entry}: could not read the width of the 'metin' parameter")
    return bits // 8


def encrypt_text(
    corpus: Corpus,
    text: str,
    key: bytes,
    *,
    nonce: bytes | None = None,
    seq: int = UNSEQUENCED,
) -> bytes:
    """Encrypt free text.

    The output is always 1339 bytes, regardless of the text length.
    """
    if not isinstance(text, str):
        raise EncodingError(f"expected text, got {type(text).__name__}")

    raw = text.encode("utf-8")
    capacity = text_capacity(corpus)

    if not raw:
        raise EncodingError("cannot encrypt empty text")
    if len(raw) > capacity:
        raise EncodingError(
            f"text too long: {len(raw)} bytes of UTF-8, limit {capacity}. "
            f"Non-ASCII characters take more than one byte, so the character "
            f"count can be lower than the byte count.")

    entry = corpus.by_slug(TEXT_SLUG)
    return encode(
        entry,
        {"uzunluk": len(raw), "metin": raw.ljust(capacity, b"\x00")},
        key,
        nonce=nonce,
        seq=seq,
    )


def _pick_decoys(
    corpus: Corpus, bits_left: int, rng: random.Random, target: int
) -> list[Entry]:
    """Randomly chosen decoy formulas that fit in the remaining space.

    Candidates are shuffled and taken while they fit. Because the order is
    random, which formulas get picked changes on every encryption.
    """
    candidates = [e for e in corpus.active if e.slug != TEXT_SLUG]
    rng.shuffle(candidates)

    chosen: list[Entry] = []
    for e in candidates:
        if len(chosen) >= target:
            break
        cost = SELECTOR_BYTES * 8 + e.payload_bits
        if cost <= bits_left:
            chosen.append(e)
            bits_left -= cost
    return chosen


def encrypt_hidden(
    corpus: Corpus,
    text: str,
    key: bytes,
    *,
    rng: random.Random | None = None,
    target_decoys: int = DEFAULT_DECOYS,
    nonce: bytes | None = None,
    seq: int = UNSEQUENCED,
) -> bytes:
    """Encrypt text hidden among randomly chosen formulas.

    Every encryption pulls a different combination of formulas from the
    corpus, generates valid random values for each, and drops the real message
    at a random position among those records.

    The technique is chaff: hiding real data among fake records indistinguish-
    able from it. Rivest's 1998 "Chaffing and Winnowing" sets out the idea.

    The gain is layer independence. The strength of the encryption stops being
    the only defence. If the keystream ever fails, through nonce reuse, an
    implementation bug, or a weakness found later, the attacker is still left
    asking which record is real. It also fills the padding region with valid
    records instead of zeros; in plain mode that region would be free
    information in a scenario where the keystream is compromised.

    The output has the same shape as a normal chain and is opened with
    `decrypt_hidden`.
    """
    rng = rng or random.Random()
    raw = text.encode("utf-8")
    capacity = text_capacity(corpus)

    if not isinstance(text, str):
        raise EncodingError(f"expected text, got {type(text).__name__}")
    if not raw:
        raise EncodingError("cannot encrypt empty text")
    if len(raw) > capacity:
        raise EncodingError(
            f"text too long: {len(raw)} bytes of UTF-8, limit {capacity}.")

    # The unused part of the text field is filled with random bytes rather
    # than zeros. Zero padding would leave a large recognisable zero region in
    # the payload regardless of where the record landed, which is exactly the
    # hole the decoys are meant to close. The decoder knows the real end from
    # the length field, so this tail is never read.
    tail = bytes(rng.getrandbits(8) for _ in range(capacity - len(raw)))

    text_entry = corpus.by_slug(TEXT_SLUG)
    real = (text_entry.id, {"uzunluk": len(raw), "metin": raw + tail})

    used = CHAIN_COUNTER_BITS + SELECTOR_BYTES * 8 + text_entry.payload_bits
    left = BODY_FIXED_BYTES * 8 - used

    records: list[tuple[int, dict]] = []
    for e in _pick_decoys(corpus, left, rng, target_decoys):
        values, _ = sample_or_free(e, rng, max_rejections=200)
        records.append((e.id, values))

    # The real record goes in at a random position.
    records.insert(rng.randint(0, len(records)), real)

    # Decoy values need not satisfy their constraints, since being noise is
    # enough. The real record's validity is guaranteed by the length check
    # above.
    return encode_chain(corpus, records, key, nonce=nonce, check=False,
                        padding_rng=rng, seq=seq)


def decrypt_hidden(corpus: Corpus, blob: bytes, key: bytes) -> str:
    """Find and decode the real text inside a random chain.

    There is no early return, and that is deliberate. The first implementation
    left the loop as soon as it found the real record, which tied run time to
    the record's POSITION, while hiding that position is the whole point of a
    decoy chain. Having the decoder give it away through timing would defeat
    the mechanism on the receiving side.

    The loop now always walks every record, so the iteration count depends on
    the number of records, not on position.

    Measured: in Python the difference stayed below the parse cost of
    `decode_chain` (Welch |t| <= 3.4 against a threshold of 4.5, so it was not
    measurable). It was fixed anyway, because the fix is free and the ratio
    flips once parsing gets cheaper in a C port.
    """
    records = decode_chain(corpus, blob, key, check=False)

    found: dict[str, Any] | None = None
    for e, values in records:
        # `and found is None`: if there are several text records the first one
        # wins, matching the old behaviour. The difference is that the loop
        # does not stop early.
        if e.slug == TEXT_SLUG and found is None:
            found = values

    if found is None:
        raise DecodeError(
            f"no text record in the chain ({len(records)} records scanned). "
            f"This ciphertext is not hidden text.")

    raw = found["metin"][: found["uzunluk"]]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        raise DecodeError(f"decoded data is not valid UTF-8: {err}") from err


def decrypt_text(corpus: Corpus, blob: bytes, key: bytes) -> str:
    """Decode a ciphertext back to text.

    If the ciphertext carries a formula entry rather than raw text it is
    rejected explicitly, instead of silently returning garbage.
    """
    entry, values = decode(corpus, blob, key)

    if entry.slug != TEXT_SLUG:
        raise DecodeError(
            f"this ciphertext is not raw text, it carries a formula entry: "
            f"{entry}. Use decode() or Engine.decode() for formula entries.")

    length = values["uzunluk"]
    raw = values["metin"][:length]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise DecodeError(f"decoded data is not valid UTF-8: {e}") from e
