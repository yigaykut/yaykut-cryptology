"""Frame header: the first 9 bytes of the payload.

The outer envelope is unchanged. It is still `nonce ‖ selector ‖ payload ‖
tag` at a fixed 1330 bytes. Only the inside of the payload changed:

    payload plaintext:
    ┌─────────┬──────────┬────────────────────────┬─────────┐
    │ version │ sequence │ body                   │ padding │
    │ 1 byte  │ 8 bytes  │ (formula or chain)     │         │
    └─────────┴──────────┴────────────────────────┴─────────┘

The sequence number exists to stop replays. Putting it in the nonce or
outside the envelope would leave it in the clear, and then an observer could
count messages, time them, and tell whether two streams came from the same
sender. That is exactly the metadata the fixed-size envelope was meant to
hide. Inside the payload it gets encrypted with the keystream and covered by
the MAC, so it can be neither read nor altered from outside.

The version byte is in the payload for the same reason: which format version
you use does not leak either. A version mismatch is rejected with a clear
error rather than silently decoded into garbage.

The cost is 9 bytes. The body gets 1271 instead of 1280, which affects
neither the text capacity (1024 bytes) nor the largest formula in the corpus.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import DecodeError, EncodingError, VersionError

# Format version. Version 1 had no frame, so v1 ciphertexts cannot be decoded
# by this version, and that is deliberate.
VERSION = 2

VERSION_BYTES = 1
SEQ_BYTES = 8
FRAME_BYTES = VERSION_BYTES + SEQ_BYTES

# 8 bytes is 1.8e19 messages. Sent continuously at 1 GHz that takes 584 years,
# so it will not run out in practice. Overflow still raises instead of
# wrapping: a wrapped sequence number repeats, and a repeat breaks the replay
# window.
MAX_SEQ = (1 << (SEQ_BYTES * 8)) - 1

# Stateless encryption outside a session. Without replay protection the
# sequence number stays 0, and the window rejects that value, so "unprotected"
# cannot be disguised as protected.
UNSEQUENCED = 0


@dataclass(frozen=True)
class Frame:
    """A decoded payload header."""

    version: int
    seq: int

    @property
    def in_session(self) -> bool:
        """Whether this message was sent through a session."""
        return self.seq != UNSEQUENCED

    def __str__(self) -> str:
        s = f"#{self.seq}" if self.in_session else "unsequenced"
        return f"frame(v{self.version}, {s})"


def wrap(seq: int, body: bytes) -> bytes:
    """Prepend the frame header to the body.

    Padding is not applied here. The padding strategy belongs to the caller:
    zeros in plain mode, random bytes in decoy mode.
    """
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise EncodingError(
            f"sequence number must be an integer, got {type(seq).__name__}")
    if not 0 <= seq <= MAX_SEQ:
        raise EncodingError(
            f"sequence number out of range: {seq} (0..{MAX_SEQ}). "
            f"Wrapping means a repeated sequence number, which breaks "
            f"replay protection.")
    return (VERSION.to_bytes(VERSION_BYTES, "big")
            + seq.to_bytes(SEQ_BYTES, "big") + body)


def unwrap(payload_pt: bytes) -> tuple[Frame, bytes]:
    """Split a decrypted payload into (frame, body).

    Only call this after the tag has been verified. Parsing unverified data
    opens an attack surface.
    """
    if len(payload_pt) < FRAME_BYTES:
        raise DecodeError(
            f"payload shorter than the frame header: "
            f"{len(payload_pt)} < {FRAME_BYTES} bytes")
    return read_header(payload_pt[:FRAME_BYTES]), payload_pt[FRAME_BYTES:]


def read_header(head: bytes) -> Frame:
    """Decode just the 9 byte header.

    The replay window does not need the whole payload, so this lets the window
    check run on a single keystream block.
    """
    if len(head) != FRAME_BYTES:
        raise DecodeError(
            f"frame header must be {FRAME_BYTES} bytes, got {len(head)}")
    version = head[0]
    if version != VERSION:
        raise VersionError(
            f"format version mismatch: ciphertext is v{version}, engine is "
            f"v{VERSION}. Cross-version decoding is not attempted; rejecting "
            f"is better than silently returning garbage.")
    return Frame(version=version,
                 seq=int.from_bytes(head[VERSION_BYTES:], "big"))
