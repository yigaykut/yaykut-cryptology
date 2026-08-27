"""Replay protection: a sliding window and a session.

The engine never remembered having seen a nonce before. An attacker who
captured a valid 1339 byte packet off the air and resent it hours later would
pass MAC verification, because the packet really did come from someone holding
the key. On a command link that means recording a command and replaying it at
will, without ever knowing the key.

Encryption alone cannot fix this. Integrity says "this message was not
modified", not "I am seeing this message for the first time". The second one
needs state.

Every message carries an increasing sequence number inside its payload, see
frame.py. The receiver keeps the numbers it has seen in a sliding window:

    top = 12, width = 8

    seq:   5  6  7  8  9 10 11 12 | 13 ->
           -  -  -  -  -  -  -  -
    mask:  1  0  1  1  1  0  1  1
           ^ outside the window: reject   ^ top: new arrivals land here

    - 13 arrives -> new, accepted, window slides
    - 10 arrives -> 0 in the mask, late but not a replay, accepted
    - 11 arrives -> 1 in the mask, REPLAY, rejected
    -  4 arrives -> outside the window, cannot decide, rejected

Why a window rather than "must be greater than the last one seen": network
packets arrive out of order, and a strict rule would drop slightly late but
legitimate packets. The window gives that tolerance in a bounded, auditable
way. Inside it, replays are caught; outside it, doubt goes to rejection.

This is the approach of RFC 4303 section 3.4.3, IPsec ESP.

The window lives in memory. If the process restarts it resets and old messages
become acceptable again. Where persistence matters, `state()` and
`from_state()` let the window be written to disk and restored.
"""

from __future__ import annotations

from typing import Any

from .errors import EncodingError, ReplayError
from .frame import MAX_SEQ, UNSEQUENCED, Frame

DEFAULT_WIDTH = 64
MAX_WIDTH = 4096


class ReplayWindow:
    """A sliding window holding seen sequence numbers in a bitmask.

    Memory cost is constant regardless of width: a single integer. Python
    integers are arbitrary width, so even a 4096 bit mask is one object.
    """

    def __init__(self, width: int = DEFAULT_WIDTH) -> None:
        if not isinstance(width, int) or isinstance(width, bool):
            raise EncodingError("window width must be an integer")
        if not 1 <= width <= MAX_WIDTH:
            raise EncodingError(
                f"window width must be in 1..{MAX_WIDTH}, got {width}")
        self.width = width
        self._top = 0      # largest sequence number seen
        self._mask = 0     # bit i means message (_top - i) was seen

    # ───────────────────────── queries ─────────────────────────

    @property
    def top(self) -> int:
        """The largest sequence number seen."""
        return self._top

    def seen(self, seq: int) -> bool:
        """Whether this number was already accepted. Does not modify state."""
        if seq > self._top:
            return False
        gap = self._top - seq
        if gap >= self.width:
            return True     # outside the window: treat as seen, doubt rejects
        return bool(self._mask >> gap & 1)

    # ───────────────────────── acceptance ─────────────────────────

    def accept(self, seq: int) -> None:
        """Check the number and mark it as seen.

        Returns silently if accepted, raises `ReplayError` otherwise. A
        rejected number is not recorded, otherwise an attacker could push the
        window forward with made up numbers and get legitimate messages
        dropped.
        """
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise EncodingError("sequence number must be an integer")

        if seq == UNSEQUENCED:
            raise ReplayError(
                "the message has no sequence number (0). A stateless message "
                "encrypted outside a session cannot go through replay "
                "protection; Session.encrypt() should have been used.")
        if not 0 < seq <= MAX_SEQ:
            raise ReplayError(f"sequence number out of range: {seq}")

        if seq > self._top:
            shift = seq - self._top
            if shift >= self.width:
                self._mask = 1              # the whole window fell behind
            else:
                self._mask = ((self._mask << shift | 1)
                              & ((1 << self.width) - 1))
            self._top = seq
            return

        gap = self._top - seq
        if gap >= self.width:
            raise ReplayError(
                f"sequence number {seq} fell outside the window "
                f"(window {self._top - self.width + 1}..{self._top}). "
                f"Whether it is a replay can no longer be known, so it is "
                f"rejected on suspicion.")
        if self._mask >> gap & 1:
            raise ReplayError(
                f"sequence number {seq} was already seen, this is a REPLAY. "
                f"The tag is valid, so the message really did come from "
                f"someone holding the key, but this copy is being replayed.")
        self._mask |= 1 << gap

    # ───────────────────────── persistence ─────────────────────────

    def state(self) -> dict[str, int]:
        """Turn the window into a dict that can be written to disk."""
        return {"width": self.width, "top": self._top, "mask": self._mask}

    @classmethod
    def from_state(cls, d: dict[str, int]) -> ReplayWindow:
        """Restore a window from `state()` output."""
        w = cls(d["width"])
        w._top = int(d["top"])
        w._mask = int(d["mask"]) & ((1 << w.width) - 1)
        return w

    def __repr__(self) -> str:
        used = bin(self._mask).count("1")
        return (f"ReplayWindow(top={self._top}, width={self.width}, "
                f"used={used})")


class Session:
    """Wraps the engine with a sequence counter and a replay window.

    The engine is stateless and stays that way; session state lives here. The
    whole encrypt and decrypt surface of `Engine` is mirrored under the same
    names. The only difference is that every call issues a sequence number and
    every decode goes through the window.

        engine  = Engine(corpus, key)
        session = Session(engine)

        blob = session.encrypt_text("order")
        session.decrypt_text(blob)      # works
        session.decrypt_text(blob)      # ReplayError

    Send counter and receive window are separate. Two endpoints talking with
    the same key do not see their own traffic in their own window, and each
    direction advances in its own number space. In a setup where the same key
    is used in both directions the numbers would collide, so each direction
    should use its own key. See keys.device_key.
    """

    def __init__(
        self,
        engine: Any,
        *,
        window: int = DEFAULT_WIDTH,
        start: int = 0,
    ) -> None:
        if not 0 <= start <= MAX_SEQ:
            raise EncodingError(f"start sequence number out of range: {start}")
        self.engine = engine
        self.window = ReplayWindow(window)
        self._outgoing = start

    @property
    def outgoing(self) -> int:
        """The last sequence number sent."""
        return self._outgoing

    def _next(self) -> int:
        if self._outgoing >= MAX_SEQ:
            raise EncodingError(
                "sequence numbers exhausted. Wrapping would repeat a number "
                "and break replay protection, so the key must be rotated "
                "(keys.epoch_key).")
        self._outgoing += 1
        return self._outgoing

    # ───────────────────────── sending ─────────────────────────

    def encrypt(self, formula: int | str, values: dict[str, Any],
                **kw) -> bytes:
        return self.engine.encrypt(formula, values, seq=self._next(), **kw)

    def encrypt_chain(self, records, **kw) -> bytes:
        return self.engine.encrypt_chain(records, seq=self._next(), **kw)

    def encrypt_text(self, text: str, **kw) -> bytes:
        return self.engine.encrypt_text(text, seq=self._next(), **kw)

    def encrypt_hidden(self, text: str, **kw) -> bytes:
        return self.engine.encrypt_hidden(text, seq=self._next(), **kw)

    # ───────────────────────── receiving ─────────────────────────

    def verify(self, blob: bytes) -> Frame:
        """Verify the tag, read the frame, run it through the window.

        The full payload is not decrypted, only the 9 byte header, so a
        replayed message is rejected cheaply and an attacker cannot burn CPU
        with a flood of replays.

        If this call succeeds the number has been recorded in the window.
        Passing the same blob a second time raises `ReplayError`.
        """
        frame = self.engine.read_frame(blob)
        self.window.accept(frame.seq)
        return frame

    def decode(self, blob: bytes, **kw):
        self.verify(blob)
        return self.engine.decode(blob, **kw)

    def decode_chain(self, blob: bytes, **kw):
        self.verify(blob)
        return self.engine.decode_chain(blob, **kw)

    def decrypt_text(self, blob: bytes) -> str:
        self.verify(blob)
        return self.engine.decrypt_text(blob)

    def decrypt_hidden(self, blob: bytes) -> str:
        self.verify(blob)
        return self.engine.decrypt_hidden(blob)

    # ───────────────────────── persistence ─────────────────────────

    def state(self) -> dict[str, Any]:
        """Session state in a form that can be written to disk.

        Contains no key. For replay protection to survive a restart this state
        must be stored; if it is lost, old messages become acceptable again.
        """
        return {"outgoing": self._outgoing, "window": self.window.state()}

    def load_state(self, d: dict[str, Any]) -> None:
        self._outgoing = int(d["outgoing"])
        self.window = ReplayWindow.from_state(d["window"])

    def __repr__(self) -> str:
        return f"Session(outgoing={self._outgoing}, {self.window!r})"
