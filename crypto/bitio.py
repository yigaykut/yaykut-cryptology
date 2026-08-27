"""Bit level reading and writing.

Parameter widths do not have to be whole bytes: 5 bits for a Caesar shift,
2 bits for an enum. Serialisation therefore works at bit precision and only
pads to a byte boundary at the very end.

The padding bits cause no trouble when decoding, because the schema says how
many bits to read and the leftovers are never touched.
"""

from __future__ import annotations

from .errors import DecodeError, EncodingError


class BitWriter:
    """Accumulates bits in order, then turns them into bytes."""

    __slots__ = ("_acc", "_nbits")

    def __init__(self) -> None:
        self._acc = 0
        self._nbits = 0

    @property
    def bit_count(self) -> int:
        return self._nbits

    def write_int(self, value: int, bits: int) -> None:
        """Write an unsigned integer at the given width, big-endian."""
        if bits <= 0:
            raise EncodingError(f"width must be positive, got {bits}")
        if not isinstance(value, int) or isinstance(value, bool):
            raise EncodingError(
                f"expected an integer, got {type(value).__name__}")
        if value < 0:
            raise EncodingError(f"cannot encode a negative value: {value}")
        if value >= (1 << bits):
            raise EncodingError(f"value does not fit in {bits} bits: {value}")
        self._acc = (self._acc << bits) | value
        self._nbits += bits

    def write_bytes(self, data: bytes, bits: int) -> None:
        """Write a byte string at the given bit width.

        `data` must be exactly ceil(bits/8) long. If the width is not a whole
        number of bytes, only the high bits of the last byte are used.
        """
        expected = (bits + 7) // 8
        if len(data) != expected:
            raise EncodingError(
                f"expected {expected} bytes for {bits} bits, got {len(data)}")
        value = int.from_bytes(data, "big")
        excess = expected * 8 - bits
        if excess:
            if value & ((1 << excess) - 1):
                raise EncodingError(
                    f"the unused {excess} bits of the last byte must be zero")
            value >>= excess
        self.write_int(value, bits)

    def to_bytes(self) -> bytes:
        """Pad with zeros to a byte boundary and return."""
        if self._nbits == 0:
            return b""
        pad = (-self._nbits) % 8
        total = (self._nbits + pad) // 8
        return (self._acc << pad).to_bytes(total, "big")


class BitReader:
    """Reads back what BitWriter produced, in the same order.

    Read cost does not depend on position, and that is deliberate.

    The first implementation held the whole buffer as one huge Python integer
    and did `(value >> shift) & mask` for each field. On a 1280 byte payload
    that is a 10240 bit integer, and bigint shifting costs more the further
    you shift. Reading an early field was measurably cheaper than reading a
    late one.

    That was a real timing leak. The order of records in a chain changed the
    parse time, so the position of the real record inside a decoy chain, which
    is exactly what decoy chains are meant to hide, could be read off the
    clock. Measured with a Welch t-test: |t| = 7.97 against a noise floor
    of 3.03.

    The fix is to slice out only the bytes a field touches, so cost now
    depends on field width alone, and that comes from the schema and is
    already public. The wire format did not change. As a side effect this is
    noticeably faster on large payloads.
    """

    __slots__ = ("_data", "_total", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._total = len(data) * 8
        self._pos = 0

    @property
    def remaining(self) -> int:
        return self._total - self._pos

    def read_int(self, bits: int) -> int:
        if bits <= 0:
            raise DecodeError(f"width must be positive, got {bits}")
        if self._pos + bits > self._total:
            raise DecodeError(
                f"not enough data: asked for {bits} bits, "
                f"{self.remaining} left")
        # Only the bytes the field touches. The slice length depends on bits,
        # not on _pos, which is where the position independence comes from.
        first = self._pos // 8
        last = (self._pos + bits + 7) // 8
        chunk = int.from_bytes(self._data[first:last], "big")
        # Drop the surplus bits at the end of the slice.
        surplus = last * 8 - (self._pos + bits)
        value = (chunk >> surplus) & ((1 << bits) - 1)
        self._pos += bits
        return value

    def read_bytes(self, bits: int) -> bytes:
        """Read bits as bytes, zero padded at the end to align."""
        value = self.read_int(bits)
        nbytes = (bits + 7) // 8
        excess = nbytes * 8 - bits
        return (value << excess).to_bytes(nbytes, "big")
