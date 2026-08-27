"""Multi block messages, for text that does not fit in one frame.

`message.encrypt_text` produces a single fixed size frame. The capacity comes
from the `ham-metin` corpus entry and is 1289 bytes. Anything longer used to
raise EncodingError.

Naive splitting is not safe. Encrypting each piece separately is not enough,
because every block carries a valid MAC on its own, so an attacker who does
not know the key can still:

  - reorder blocks
  - drop the last ones and truncate the message
  - duplicate blocks
  - splice in a block from a different message

None of that needs the key, since each block is individually correct. The
integrity of the whole message was never checked anywhere.

The fix is to bind every block to its place. Before encryption, an identity
header goes into each block's plaintext:

    message_id(16) ‖ index(2) ‖ total(2) ‖ total_length(4)  = 24 bytes

The header is inside the payload, so it is covered by the MAC and cannot be
altered. Decoding then checks:

  - every block shares the same message_id, so foreign blocks are rejected
  - every block reports the same total
  - indexes are exactly 0..total-1, so nothing is missing or duplicated
  - the block count equals total, which catches truncation

`message_id` comes from the CSPRNG on every message, so blocks from two
different messages cannot be mixed.

What this does not hide, and it is a step back from the fixed size envelope:
the block count is visible. A single frame leaked no length at all; across
blocks the length leaks at one block resolution, 1265 bytes. That is
unavoidable, since there is no way to carry unbounded length in a fixed size.

`target_blocks` closes it partially. The message is padded with zeros up to
the requested block count, so every length below that count looks the same.
The cost is bandwidth, and the choice is left to the caller.
"""

from __future__ import annotations

import os

from .corpus import Corpus
from .errors import DecodeError, EncodingError
from .message import TEXT_SLUG, text_capacity
from .wire import decode, encode

MESSAGE_ID_BYTES = 16
HEADER_BYTES = MESSAGE_ID_BYTES + 2 + 2 + 4   # id ‖ index ‖ total ‖ length
MAX_BLOCKS = 4096                             # about 5 MB, a DoS ceiling


def block_capacity(corpus: Corpus) -> int:
    """Useful bytes in one block, with the header subtracted."""
    capacity = text_capacity(corpus)
    if capacity <= HEADER_BYTES:
        raise EncodingError(
            f"corpus text capacity ({capacity}) is smaller than the block "
            f"header ({HEADER_BYTES}); multi block transport cannot be set up")
    return capacity - HEADER_BYTES


def long_capacity(corpus: Corpus, blocks: int = MAX_BLOCKS) -> int:
    """Most UTF-8 bytes carryable in the given number of blocks."""
    return block_capacity(corpus) * blocks


def encrypt_long(corpus: Corpus, text: str, key: bytes, *,
                 target_blocks: int | None = None, **kw) -> list[bytes]:
    """Encrypt a long text into a list of blocks.

    With `target_blocks` the output is at least that many blocks, the extra
    ones being zero padding. Every message using the same target looks the
    same length.

    The order of the returned list does not have to be preserved. The index
    lives inside each block and is covered by the MAC, so `decrypt_long`
    handles a shuffled list too.
    """
    if not isinstance(text, str):
        raise EncodingError(f"expected text, got {type(text).__name__}")

    raw = text.encode("utf-8")
    if not raw:
        raise EncodingError("cannot encrypt empty text")

    capacity = text_capacity(corpus)
    body = block_capacity(corpus)
    needed = (len(raw) + body - 1) // body

    total = needed
    if target_blocks is not None:
        if not isinstance(target_blocks, int) or isinstance(target_blocks, bool) \
                or target_blocks < 1:
            raise EncodingError("block target must be a positive integer")
        if target_blocks < needed:
            raise EncodingError(
                f"text needs {needed} blocks, target is {target_blocks}. "
                f"The target is for padding; it does not truncate.")
        total = target_blocks

    if total > MAX_BLOCKS:
        raise EncodingError(
            f"{total} blocks, limit {MAX_BLOCKS}. Content this long needs a "
            f"file transport design, not a message.")

    message_id = os.urandom(MESSAGE_ID_BYTES)
    entry = corpus.by_slug(TEXT_SLUG)
    # Padding blocks are encrypted like real ones. If they were
    # distinguishable the padding would be pointless.
    padded = raw.ljust(total * body, b"\x00")

    blocks = []
    for i in range(total):
        inner = (message_id
                 + i.to_bytes(2, "big")
                 + total.to_bytes(2, "big")
                 + len(raw).to_bytes(4, "big")
                 + padded[i * body:(i + 1) * body])
        blocks.append(encode(
            entry,
            {"uzunluk": len(inner), "metin": inner.ljust(capacity, b"\x00")},
            key, **kw))
    return blocks


def _split_header(inner: bytes) -> tuple[bytes, int, int, int, bytes]:
    if len(inner) < HEADER_BYTES:
        raise DecodeError(
            f"block header truncated: {len(inner)} bytes, "
            f"at least {HEADER_BYTES} needed")
    return (inner[:MESSAGE_ID_BYTES],
            int.from_bytes(inner[16:18], "big"),
            int.from_bytes(inner[18:20], "big"),
            int.from_bytes(inner[20:24], "big"),
            inner[HEADER_BYTES:])


def decrypt_long(corpus: Corpus, blocks: list[bytes], key: bytes, **kw) -> str:
    """Decode blocks and reassemble, checking order, integrity and completeness.

    Block order does not matter, since the index is read from the header the
    MAC covers. Each block's own MAC is already verified inside `decode`;
    what gets checked here is the integrity of the block set.
    """
    if not isinstance(blocks, (list, tuple)) or not blocks:
        raise DecodeError("at least one block is required")
    if len(blocks) > MAX_BLOCKS:
        raise DecodeError(f"{len(blocks)} blocks, limit {MAX_BLOCKS}")

    pieces: dict[int, bytes] = {}
    message_id = total = length = None

    for blob in blocks:
        entry, values = decode(corpus, blob, key, **kw)
        if entry.slug != TEXT_SLUG:
            raise DecodeError(f"block is not a text block: {entry.slug}")
        inner = values["metin"][:values["uzunluk"]]
        bid, index, tot, ln, body = _split_header(inner)

        if message_id is None:
            message_id, total, length = bid, tot, ln
        elif bid != message_id:
            raise DecodeError(
                "blocks belong to different messages, which means a splicing "
                "attack or mixed up records")
        elif tot != total or ln != length:
            raise DecodeError(
                "block headers disagree on total or length")

        if index in pieces:
            raise DecodeError(f"block {index} arrived twice")
        if not 0 <= index < total:
            raise DecodeError(
                f"block index out of range: {index} (total {total})")
        pieces[index] = body

    if len(pieces) != total:
        missing = sorted(set(range(total)) - pieces.keys())
        raise DecodeError(
            f"message is INCOMPLETE: {len(pieces)}/{total} blocks arrived. "
            f"Missing: {missing[:8]}{'...' if len(missing) > 8 else ''}")

    raw = b"".join(pieces[i] for i in range(total))
    if length > len(raw):
        raise DecodeError(
            f"header length ({length}) exceeds the data carried ({len(raw)})")
    try:
        return raw[:length].decode("utf-8")
    except UnicodeDecodeError as e:
        raise DecodeError(f"reassembled text is not UTF-8: {e}") from e
