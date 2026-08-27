"""Pre-key: a per-network secret for the selector mask.

Until this existed, all three subkeys came from the same master key:

    PRK          = HKDF-Extract(salt = nonce, ikm = K)
    selector msk = HKDF-Expand(PRK, "selector")   <-- tied to K
    payload  ks  = HKDF-Expand(PRK, "payload")
    mac      key = HKDF-Expand(PRK, "mac")

So if K leaked, which formula was carried leaked with it. The content of a
message and its metadata hung on the same secret.

The pre-key cuts that link. Given a separate, independent secret P, the
selector mask is derived from it instead:

    selector msk = HKDF-Expand(HKDF-Extract(nonce, P), "v3/prekey/selector")

An attacker who takes K but not P can now read the message content but
cannot tell which formula it carried.

What it buys:

  - Key separation. Different purposes hang on different secrets.
  - Resistance to partial compromise. K falling alone is a real scenario:
    cryptanalysis, one subkey leaking, a memory dump that catches K but not P.
  - Group identity, which is the main gain. P can be shared across a whole
    network while K stays pairwise: a separate K per member, one shared P.
    The network becomes a coherent group whose members cannot read each
    other's messages. That is exactly the topology a canary trap needs.
  - Compartmenting between networks. Network A's selector distribution is
    independent of B's, so losing one does not give away the other's mapping.

What it does not buy, which should be written down too:

  - It does not change the 16 bit ceiling. The selector is 2 bytes, so the
    uncertainty about "which formula" is still at most 2^16.
  - It does nothing against an insider. A network member already holds P,
    otherwise they could not interpret the formula. What catches a spy is not
    cryptography, it is the canary trap.
  - It does not protect content. P only produces the selector mask. The
    plaintext still hangs on K, and if K falls the content is readable.

P has to be independent. Deriving P from K gains nothing, since whoever knows
K can compute it. `generate()` therefore draws straight from the CSPRNG, and
`Engine` rejects P == K, which is a cheap but real tripwire.

A fixed permutation was considered and deliberately rejected. "Let each
network use different formula codes" could be done with a permutation
pi_P: formula -> code, but a fixed permutation is deterministic. The same
formula gets the same code in every message, and an attacker can say "these
two are the same formula" without decrypting anything. A nonce-derived mask
does not leak that repetition, because the code changes every message.
"""

from __future__ import annotations

import hmac
import os

from . import primitives
from .errors import KeyManagementError
from .memory import SecureBuffer

# The v3 label: v1 is message subkeys, v2 the key hierarchy, v3 the pre-key.
# Domain separation stops the same bytes being used as a key for two
# different purposes.
INFO_PREKEY = b"kripto/v3/onanahtar/selector"

PREKEY_BYTES = 32
MIN_BYTES = 16


class PrekeyError(KeyManagementError):
    """The pre-key is invalid or has been closed."""


class Prekey:
    """A per-network secret for the selector mask.

    The secret lives in a `SecureBuffer`, because it is long lived and should
    be erasable and, where possible, in locked memory.

        with Prekey.generate() as p:
            blob = engine.encrypt("hkdf", values, prekey=p)
    """

    __slots__ = ("_buf",)

    def __init__(self, data: bytes | SecureBuffer) -> None:
        if isinstance(data, SecureBuffer):
            if data.closed:
                raise PrekeyError("a closed buffer cannot be a pre-key")
            if data.size < MIN_BYTES:
                raise PrekeyError(
                    f"pre-key must be at least {MIN_BYTES} bytes, "
                    f"got {data.size}")
            self._buf = data
            return

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise PrekeyError(
                f"expected bytes or SecureBuffer, got {type(data).__name__}")
        data = bytes(data)
        if len(data) < MIN_BYTES:
            raise PrekeyError(
                f"pre-key must be at least {MIN_BYTES} bytes, got {len(data)}")
        self._buf = SecureBuffer(len(data), data=data)

    @classmethod
    def generate(cls, size: int = PREKEY_BYTES) -> "Prekey":
        """A new pre-key, straight from the CSPRNG.

        It is not derived from K. If it were, anyone who knows K could compute
        it and the whole point of key separation would be lost.
        """
        if size < MIN_BYTES:
            raise PrekeyError(f"pre-key must be at least {MIN_BYTES} bytes")
        return cls(SecureBuffer.random(size))

    # ─────────── use ───────────

    def mask(self, nonce: bytes, length: int) -> bytes:
        """The selector mask for a given nonce.

        Same shape as `subkeys`, HKDF extract then expand, but with a
        different secret and a different domain label. The nonce is the salt,
        so the mask changes on every message and repetition does not leak.
        """
        self._check()
        if not isinstance(nonce, (bytes, bytearray)):
            raise PrekeyError("nonce must be bytes")
        if length <= 0:
            raise PrekeyError("mask length must be positive")
        secret = self._buf.to_bytes()
        try:
            prk = primitives.hkdf_extract(salt=bytes(nonce), ikm=secret)
            return primitives.hkdf_expand(prk, INFO_PREKEY, length)
        finally:
            # `to_bytes()` returns a copy that cannot be erased. Dropping the
            # local reference is hygiene, not a guarantee.
            del secret

    def fingerprint(self, length: int = 8) -> str:
        """Confirm two ends hold the same pre-key without showing it.

        Same reasoning and same limits as `keys.fingerprint`: it is for human
        checking, not authentication.
        """
        from .keys import fingerprint
        return fingerprint(self._buf.to_bytes(), length)

    def equals(self, other: bytes) -> bool:
        """Constant-time comparison, for the tripwire checks."""
        self._check()
        return hmac.compare_digest(self._buf.to_bytes(), bytes(other))

    # ─────────── lifecycle ───────────

    @property
    def buffer(self) -> SecureBuffer:
        return self._buf

    @property
    def closed(self) -> bool:
        return self._buf.closed

    def close(self) -> None:
        """Zero the contents and release the buffer. Not reversible."""
        self._buf.close()

    def _check(self) -> None:
        if self._buf.closed:
            raise PrekeyError("pre-key has been closed")

    def __enter__(self) -> "Prekey":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        """Never prints the contents."""
        if self._buf.closed:
            return "<Prekey CLOSED>"
        return f"<Prekey {self._buf.size} bytes, {self.fingerprint()}>"


def selector_mask(prekey: "Prekey | None", key: bytes,
                  nonce: bytes, length: int, default: bytes) -> bytes:
    """Choose the selector mask: from the pre-key if there is one, else from K.

    `default` is the mask `subkeys` derived from K. Without a pre-key it is
    used unchanged, so behaviour without a pre-key is byte for byte what it
    always was and old ciphertexts still decode.
    """
    if prekey is None:
        return default
    return prekey.mask(nonce, length)


def is_independent(prekey: "Prekey", key: bytes) -> bool:
    """Check that P and K are not the same value.

    This does not prove independence. If P were derived from K with HKDF this
    check would not notice. It only catches the obvious mistake of using the
    same bytes for two purposes.
    """
    return not prekey.equals(key)
