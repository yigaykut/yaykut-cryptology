"""Key hierarchy, rotation and forward secrecy.

Running the engine on a single static key was the biggest hole: if one device
was compromised, all past and future traffic encrypted with that key opened up.
This module closes it.

Everything is built on the HKDF in `primitives.py`; no new primitive was
introduced. The hierarchy:

    master key                (stays in the vault, never reaches a device)
      └─ device key           HKDF(master, "device" ‖ id)
           └─ epoch key       HKDF(device, "epoch" ‖ number)
                └─ chain      advances one step per message

Three levels solve three different problems.

Isolation, from the device key. If one device falls, only that device's
traffic opens; the rest of the fleet is unaffected. You cannot go back from a
device key to the master key, because HKDF is one way.

Rotation, from the epoch key. Scheduled renewal tied to a calendar. If one
epoch's key leaks, the damage stays inside that epoch.

Forward secrecy, from the chain. The key advances after every message and the
previous state is erased. Even if a device is taken today, traffic recorded
yesterday cannot be opened, because yesterday's key no longer exists anywhere.

The chain gives forward secrecy only, not backward: whoever takes today's key
also reads tomorrow's messages. Backward secrecy needs a mutual key exchange
such as ECDH. The corpus has elliptic curves but the engine does not use them
for this, which is a deliberate gap and is written in the README.
"""

from __future__ import annotations

import os

from .errors import KeyManagementError
from .primitives import HASH_LEN, hkdf_expand, hkdf_extract

# Domain separation, kept apart from the v1 labels in `primitives.py` so one
# level's output cannot be used at another level.
INFO_DEVICE = b"kripto/v2/anahtar/cihaz"
INFO_EPOCH = b"kripto/v2/anahtar/donem"
INFO_CHAIN = b"kripto/v2/anahtar/zincir"
INFO_MESSAGE = b"kripto/v2/anahtar/mesaj"
INFO_FINGERPRINT = b"kripto/v2/anahtar/parmak-izi"

KEY_BYTES = 32
MIN_KEY_BYTES = 16


def master_key(length: int = KEY_BYTES) -> bytes:
    """Generate a new master key.

    Randomness comes from the OS CSPRNG. On embedded targets a hardware RNG
    should be used instead of `os.urandom`: many microcontrollers start with
    weak entropy at boot, which would make every generated key predictable.
    """
    if length < MIN_KEY_BYTES:
        raise KeyManagementError(
            f"key must be at least {MIN_KEY_BYTES} bytes, asked for {length}")
    return os.urandom(length)


def _validate(key, name: str = "key") -> bytes:
    # A SecureBuffer is accepted too; the `to_bytes()` copy is short lived here.
    from .memory import SecureBuffer
    if isinstance(key, SecureBuffer):
        key = key.to_bytes()
    if not isinstance(key, (bytes, bytearray)):
        raise KeyManagementError(
            f"{name}: expected bytes, got {type(key).__name__}")
    if len(key) < MIN_KEY_BYTES:
        raise KeyManagementError(
            f"{name} must be at least {MIN_KEY_BYTES} bytes, got {len(key)}")
    return bytes(key)


def _derive(key: bytes, info: bytes, label: bytes) -> bytes:
    """A subkey via HKDF. One way: you cannot get back from output to input."""
    prk = hkdf_extract(salt=label, ikm=key)
    return hkdf_expand(prk, info, HASH_LEN)


def device_key(master: bytes, device_id: bytes | str) -> bytes:
    """Derive a key specific to one device.

    The master key stays in the vault and only its derivative is loaded onto
    the device. Even if the device is taken, the master key and its sibling
    devices' keys are safe.
    """
    master = _validate(master, "master key")
    if isinstance(device_id, str):
        device_id = device_id.encode("utf-8")
    if not device_id:
        raise KeyManagementError("device id cannot be empty")
    return _derive(master, INFO_DEVICE, bytes(device_id))


def epoch_key(key: bytes, epoch: int) -> bytes:
    """An epoch key for scheduled rotation.

    `epoch` comes from a calendar: day count, week, release number, whatever
    the system decides. The same epoch always gives the same key, so two
    endpoints need no extra handshake to agree; both just read the calendar.
    """
    key = _validate(key)
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise KeyManagementError(
            f"epoch must be a non-negative integer, got {epoch!r}")
    return _derive(key, INFO_EPOCH, epoch.to_bytes(8, "big"))


# ─────────── buffer returning counterparts ───────────
# The functions above return `bytes` and stay that way so no existing caller
# breaks. These do the same derivations but put the result in erasable memory.
#
# Honest limit, the HKDF intermediate: `hkdf_expand` uses Python's `hmac` and
# `hashlib`, which return `bytes`. The derived key therefore exists briefly as
# an unerasable `bytes` before being copied into the buffer. Closing that would
# have meant moving SHA-256 into C as well, and the project's own rule is not
# to rewrite primitives. The gain is still real: the long lived copy is in
# erasable memory, and the `bytes` intermediate becomes unreachable on the
# first garbage collection pass.
#
# `master_key_buffer` is exempt: the randomness is generated directly in C and
# never becomes `bytes`.

def master_key_buffer(length: int = KEY_BYTES):
    """A new master key, straight into a secure buffer.

    Unlike `master_key()` the secret never becomes `bytes`. With the C core
    the randomness is written into the buffer itself.
    """
    from .memory import SecureBuffer

    if length < MIN_KEY_BYTES:
        raise KeyManagementError(
            f"key must be at least {MIN_KEY_BYTES} bytes, asked for {length}")
    return SecureBuffer.random(length)


def _into_buffer(raw: bytes):
    from .memory import SecureBuffer
    return SecureBuffer(len(raw), data=raw)


def _read_key(key) -> bytes:
    """Accepts `bytes` or a `SecureBuffer`, returns `bytes`."""
    from .memory import SecureBuffer
    if isinstance(key, SecureBuffer):
        return key.to_bytes()
    return key


def device_key_buffer(master, device_id: bytes | str):
    """Same derivation as `device_key`, result in a secure buffer."""
    return _into_buffer(device_key(_read_key(master), device_id))


def epoch_key_buffer(key, epoch: int):
    """Same derivation as `epoch_key`, result in a secure buffer."""
    return _into_buffer(epoch_key(_read_key(key), epoch))


def fingerprint(key: bytes, length: int = 8) -> str:
    """A short, human readable identity for a key.

    Lets two ends confirm they hold the same key without showing it. It is a
    one way derivation, so the key cannot be recovered from the fingerprint.

    Eight bytes is 64 bits. The birthday bound is 2^32, so an accidental
    collision needs four billion keys. That is not enough against an attacker
    deliberately constructing a collision: this is a check digit for human
    review, not an authentication mechanism.
    """
    key = _validate(key)
    if not 4 <= length <= HASH_LEN:
        raise KeyManagementError(
            f"fingerprint length must be 4..{HASH_LEN} bytes")
    raw = hkdf_expand(hkdf_extract(b"", key), INFO_FINGERPRINT, length)
    return "-".join(raw.hex()[i:i + 4].upper()
                    for i in range(0, length * 2, 4))


def wipe(buffer) -> None:
    """Erase a key from memory.

    Given a `SecureBuffer` the wipe is real: a zeroing the compiler cannot
    elide runs on the C side, and if the page was locked no copy reached swap.

    Given a `bytearray` it is zeroed, but the guarantee is weak: the page is
    not locked and the interpreter may have left copies.

    `bytes` still cannot be erased, and that has not changed; there is no way
    to overwrite an immutable object. For long lived secrets use a
    `SecureBuffer`. `master_key_buffer`, `device_key_buffer` and
    `Identity.generate()` already return one.
    """
    from .memory import SecureBuffer

    if isinstance(buffer, SecureBuffer):
        buffer.wipe()
        return
    if not isinstance(buffer, bytearray):
        raise KeyManagementError(
            f"only a bytearray or SecureBuffer can be wiped, got "
            f"{type(buffer).__name__}. bytes is immutable and cannot be "
            f"overwritten.")
    for i in range(len(buffer)):
        buffer[i] = 0


class KeyChain:
    """A one way key ratchet providing forward secrecy.

    Each step takes two derivations:

        message key = HKDF(chain, "message")   used for encryption
        new chain   = HKDF(chain, "chain")     the chain's next state

    The old chain state is overwritten. HKDF is one way, so you cannot get
    back from the new state to the old one, which means whoever takes today's
    state cannot produce yesterday's message keys.

    The two endpoints must keep their step counters in sync. If a message is
    lost the receiver falls behind, and `fast_forward` closes the gap, but
    only within a limit, since unbounded fast forwarding is a denial of
    service vector.
    """

    MAX_FAST_FORWARD = 512

    def __init__(self, seed, *, step: int = 0) -> None:
        # The chain key lives in a secure buffer. Forward secrecy rests on the
        # old chain key ceasing to exist; a `bytearray` was zeroed but its page
        # was not locked, so a copy may have reached swap. A locked page closes
        # that.
        from .memory import SecureBuffer

        raw = _validate(seed, "seed")
        self._chain = SecureBuffer(len(raw), data=raw)
        self._step = step

    @property
    def step(self) -> int:
        return self._step

    def message_key(self) -> bytes:
        """The message key for the current step. Does not advance the chain."""
        return _derive(self._chain.to_bytes(), INFO_MESSAGE,
                       self._step.to_bytes(8, "big"))

    def advance(self) -> bytes:
        """Return this step's message key and move the chain forward one step.

        Once returned, the key is the caller's responsibility. The chain
        itself has moved irreversibly.
        """
        key = self.message_key()
        new = _derive(self._chain.to_bytes(), INFO_CHAIN,
                      self._step.to_bytes(8, "big"))
        # The old chain key dies here, which is the only thing irreversibility
        # rests on.
        if len(new) == len(self._chain):
            self._chain.write(new)
        else:
            # The seed may be shorter than HASH_LEN, since 16 bytes is
            # accepted, while a derivation is always HASH_LEN. The size
            # changes once, on the first advance.
            from .memory import SecureBuffer
            old = self._chain
            self._chain = SecureBuffer(len(new), data=new)
            old.close()
        self._step += 1
        return key

    def fast_forward(self, target_step: int) -> bytes:
        """Advance to a target step after falling behind on lost messages.

        There is a limit: an attacker must not be able to force millions of
        steps with a forged message. In practice this call should only happen
        after the tag has been verified.
        """
        if target_step < self._step:
            raise KeyManagementError(
                f"the chain cannot go back: currently {self._step}, asked for "
                f"{target_step}. That is the price of forward secrecy, the old "
                f"key is gone.")
        skipped = target_step - self._step
        if skipped > self.MAX_FAST_FORWARD:
            raise KeyManagementError(
                f"fast forward too long: {skipped} steps (limit "
                f"{self.MAX_FAST_FORWARD}). Unbounded fast forwarding is a "
                f"denial of service vector.")
        key = b""
        for _ in range(skipped + 1):
            key = self.advance()
        return key

    def close(self) -> None:
        """Erase the chain state and release the memory. Unusable afterwards.

        `wipe()` only zeroes; `close()` also releases the locked page.
        """
        self._chain.close()

    def __repr__(self) -> str:
        return f"KeyChain(step={self._step})"
