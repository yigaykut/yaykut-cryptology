"""Secure buffer: memory where key material can actually be erased.

The last item on the "cannot be fixed in Python" list used to be:

    "Keys cannot be wiped from memory. `bytes` is immutable and the garbage
     collector keeps copies in unexpected places."

That was a Python limit, and it stopped being one once the C core arrived.
`SecureBuffer` holds a block allocated in C, locked so it is never written to
swap, and genuinely zeroed when closed.

Three stages, all three needed:

    creation ->  crypto_random()      the secret never becomes `bytes`
    use      ->  crypto25519(addr...)   the secret never leaves the buffer
    death    ->  crypto_wipe()           a wipe the compiler cannot elide

Miss one and the chain breaks: once a secret has been a `bytes` it stays
there, because `bytes` is immutable and cannot be overwritten.

Honest limits, none of which are closed:

  - `to_bytes()` makes a copy and that copy cannot be erased. The method is
    deliberately not named "secure" and carries a warning.
  - The lock does not hold everywhere: Windows working set limits, Linux
    RLIMIT_MEMLOCK. When it fails `locked` is False rather than silent.
  - Without the C core the class still works, on a `bytearray`: erasable,
    not lockable. `guarantee` says so plainly.
  - A kernel crash dump can still contain locked pages.
  - Hibernation writes all of RAM to disk and the lock does not stop it.

So this module does not claim a key can never leak. It claims the countable
leak paths were closed and the ones that could not be closed are written down.
"""

from __future__ import annotations

import ctypes

from . import fastpath
from .errors import KeyManagementError


class BufferError_(KeyManagementError):
    """Access to a closed buffer, or an invalid size."""


# Guarantee levels returned by the `guarantee` property.
GUARANTEE_LOCKED = "C: locked memory, erasable, generated in C"
GUARANTEE_UNLOCKED = "C: erasable but COULD NOT LOCK (environment refused)"
GUARANTEE_PURE = "pure Python: bytearray, erasable, not lockable"


class SecureBuffer:
    """A fixed size block of erasable memory.

        with SecureBuffer.random(32) as secret:
            public = curve.public_key_buffer(secret)
            ...
        # past this point the buffer contents are zero

    Leaving the `with` block wipes the contents and releases the block.
    Making it impossible to forget is deliberate: key lifetime should match
    scope lifetime.
    """

    __slots__ = ("_size", "_addr", "_array", "_bytearray", "_locked",
                 "_closed")

    def __init__(self, size: int, *, data: bytes | None = None) -> None:
        if not isinstance(size, int) or size <= 0:
            raise BufferError_(f"size must be a positive integer, got {size!r}")

        self._size = size
        self._closed = False
        self._addr: int | None = None
        self._bytearray: bytearray | None = None
        self._locked = False

        lib = fastpath.lib()
        if lib is not None:
            lock = ctypes.c_int(0)
            addr = lib.crypto_buffer_open(size, ctypes.byref(lock))
            if addr:
                self._addr = int(addr)
                self._locked = bool(lock.value)
                self._array = (ctypes.c_ubyte * size).from_address(self._addr)
        if self._addr is None:
            # Pure Python path. Erasable, since a bytearray is mutable, but
            # not lockable, and the interpreter may still hold copies.
            self._bytearray = bytearray(size)
            self._array = self._bytearray

        if data is not None:
            self.write(data)

    # ───────────────────────── creation ─────────────────────────

    @classmethod
    def random(cls, size: int) -> "SecureBuffer":
        """A buffer filled with cryptographic randomness.

        With the C core the randomness is written straight into the buffer and
        no intermediate `bytes` ever exists. Without it `os.urandom` is used
        and that temporary `bytes` cannot be erased, which `guarantee` says.
        """
        buf = cls(size)
        lib = fastpath.lib()
        if lib is not None and buf._addr is not None:
            code = lib.crypto_random(buf._addr, size)
            if code == 0:
                return buf
            buf.close()
            raise BufferError_(f"C randomness failed (code {code})")

        import os
        buf.write(os.urandom(size))
        return buf

    # ───────────────────────── state ─────────────────────────

    @property
    def size(self) -> int:
        return self._size

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def locked(self) -> bool:
        """Whether the memory is locked against being swapped out."""
        return self._locked

    @property
    def address(self) -> int | None:
        """The raw address on the C side. None on the pure Python path.

        `fastpath.x25519_address` uses this, so the secret is processed
        without ever leaving the buffer.
        """
        self._check()
        return self._addr

    @property
    def guarantee(self) -> str:
        """What this buffer actually promises, in one honest line."""
        if self._addr is None:
            return GUARANTEE_PURE
        return GUARANTEE_LOCKED if self._locked else GUARANTEE_UNLOCKED

    # ───────────────────────── access ─────────────────────────

    def _check(self) -> None:
        if self._closed:
            raise BufferError_(
                "this buffer was closed and its contents erased. Touching a "
                "closed buffer means using a key that no longer exists.")

    def view(self) -> memoryview:
        """A writable view. Makes no copy, and is the intended way to use it."""
        self._check()
        return memoryview(self._array).cast("B")

    def write(self, data: bytes) -> None:
        self._check()
        if len(data) != self._size:
            raise BufferError_(
                f"data must be {self._size} bytes, got {len(data)}")
        self.view()[:] = data

    def to_bytes(self) -> bytes:
        """A COPY of the contents.

        This method exists for compatibility, not for security. The returned
        `bytes` is immutable and cannot be erased, and closing the buffer does
        not affect it. For secret material use `address` or `view()`. This is
        only appropriate for data that is not secret anyway, such as a public
        key.
        """
        self._check()
        return bytes(self.view())

    # ───────────────────────── death ─────────────────────────

    def wipe(self) -> None:
        """Zero the contents, leaving the buffer open for reuse."""
        self._check()
        lib = fastpath.lib()
        if lib is not None and self._addr is not None:
            lib.crypto_wipe(self._addr, self._size)
        else:
            self.view()[:] = bytes(self._size)

    def close(self) -> None:
        """Wipe and release the memory. Calling it twice is harmless."""
        if self._closed:
            return
        lib = fastpath.lib()
        if lib is not None and self._addr is not None:
            # Drop the view first. Freeing while the ctypes array is alive
            # would be a use after free.
            self._array = None
            lib.crypto_buffer_close(self._addr, self._size)
            self._addr = None
        else:
            if self._array is not None:
                self._array[:] = bytes(self._size)
            self._array = None
            self._bytearray = None
        self._closed = True

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __len__(self) -> int:
        return self._size

    def __repr__(self) -> str:
        state = "closed" if self._closed else self.guarantee
        # Never print the contents. A key that lands in a log is easier to
        # steal than one left in memory.
        return f"<SecureBuffer {self._size} bytes · {state}>"


def status() -> str:
    """What secure memory really provides on this machine."""
    with SecureBuffer(32) as buf:
        return buf.guarantee
