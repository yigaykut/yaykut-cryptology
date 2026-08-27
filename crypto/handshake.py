"""A four DH handshake, giving backward secrecy.

`KeyChain` gave forward secrecy: traffic recorded yesterday could not be
opened with today's key. The reverse was still open. Whoever took today's key
also read tomorrow's messages, because every key derived one way from a single
root, so once the root leaked, the rest of the chain leaked with it.

Closing that needs fresh randomness in each session's key that is not in the
root. The only way is a mutual key exchange: both sides generate an ephemeral
key, and together they produce a secret neither could have chosen alone.

One DH is not enough. Ephemerals alone, anonymous DH, give no authentication
and a man in the middle is free. Statics alone produce the same secret every
session and forward secrecy is gone. All four are used together:

    ee = DH(e_initiator, E_responder)   forward secrecy, ephemerals are erased
    es = DH(e_initiator, S_responder)   binds the initiator's ephemeral to an identity
    se = DH(s_initiator, E_responder)   binds the responder's ephemeral to an identity
    ss = DH(s_initiator, S_responder)   authentication, these two only

    session = HKDF(transcript; ee ‖ es ‖ se ‖ ss)

All four feed the HKDF, so ALL of them have to break. If ss leaks, ee still
protects; if the ephemerals are taken, ss still authenticates.

This is the same idea as the KK pattern in the Noise framework and Signal's
X3DH: each DH corresponds to a separate guarantee.

Transcript binding: the HKDF salt is all four public keys, so the session key
is bound to the full text of the handshake. An attacker cannot shuffle
messages and land two parties on the same key under different identities,
which is the unknown key share attack.

Direction separation: the two directions use separate keys. Using one key both
ways would collide the sequence numbers, and a packet one side sent would look
like a replay in the other's window.

Transport: handshake messages travel as ordinary ciphertexts through the
`0x0805` corpus entry, under a pre-shared symmetric key. So a handshake packet
is also 1339 bytes and indistinguishable from any other, and an observer
cannot even see when a session was established.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import curve
from .errors import DecodeError, KeyManagementError
from .memory import SecureBuffer
from .primitives import HASH_LEN, hkdf_expand, hkdf_extract

HANDSHAKE_SLUG = "x25519-el-sikisma"

INITIATOR = "initiator"
RESPONDER = "responder"

# Domain separation. Keys out of the same handshake are not interchangeable.
INFO_IDENTITY = b"kripto/v2/elsikisma/kimlik"
INFO_SESSION = b"kripto/v2/elsikisma/oturum"
INFO_FORWARD = b"kripto/v2/elsikisma/yon/baslatan-yanitlayan"
INFO_BACKWARD = b"kripto/v2/elsikisma/yon/yanitlayan-baslatan"
INFO_CONFIRM = b"kripto/v2/elsikisma/dogrulama"

IDENTITY_TRACE_BYTES = 8


class Identity:
    """A device's long lived X25519 identity.

    The static key pair is for authentication, not confidentiality. The
    ephemerals provide confidentiality; this key only answers "is the other
    side really who they claim".

    The private key lives in a secure buffer. It is the longest lived secret
    in the system, and if it leaks an attacker impersonates the device
    permanently. So it sits in a `SecureBuffer` rather than `bytes`: locked
    page, erasable contents, and generation through `generate()` that never
    creates a `bytes` at all.

    The constructor signature is unchanged, so `Identity(secret_bytes)` still
    works and code loading from disk does not break. `.secret` still works but
    now produces a COPY, with a warning on it.
    """

    __slots__ = ("_buf",)

    def __init__(self, secret) -> None:
        from .memory import SecureBuffer

        if isinstance(secret, SecureBuffer):
            if len(secret) != curve.KEY_BYTES:
                raise KeyManagementError(
                    f"an identity key must be {curve.KEY_BYTES} bytes, "
                    f"got {len(secret)}")
            # Ownership transfers: closing it becomes Identity's job.
            self._buf = secret
            return

        if not isinstance(secret, (bytes, bytearray)):
            raise KeyManagementError(
                f"an identity key must be bytes or a SecureBuffer, got "
                f"{type(secret).__name__}")
        if len(secret) != curve.KEY_BYTES:
            raise KeyManagementError(
                f"an identity key must be {curve.KEY_BYTES} bytes, "
                f"got {len(secret)}")
        self._buf = SecureBuffer(curve.KEY_BYTES, data=bytes(secret))

    @classmethod
    def generate(cls) -> Identity:
        """A fresh independent identity; the key never becomes `bytes`."""
        from .memory import SecureBuffer

        return cls(SecureBuffer.random(curve.KEY_BYTES))

    @property
    def buffer(self):
        """The private key itself, without copying. The intended path."""
        return self._buf

    @property
    def secret(self) -> bytes:
        """A COPY of the private key, for compatibility.

        The returned `bytes` is immutable and cannot be erased.
        `identity.close()` does not affect it. Use `buffer` for cryptographic
        operations; `x25519_buffer` and `public_key_buffer` take it directly.
        """
        return self._buf.to_bytes()

    def close(self) -> None:
        """Erase the private key. The identity is unusable afterwards."""
        self._buf.close()

    def __enter__(self) -> Identity:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @classmethod
    def from_key(cls, symmetric: bytes) -> Identity:
        """Derive an identity from the symmetric key hierarchy.

        The convenience: provisioning a device needs no separate X25519 key to
        distribute, store and record. A fleet manager can recompute every
        device's identity from the master key.

        The cost: whoever holds the master key can impersonate EVERY device.
        In fleet provisioning that is already true, since they distribute the
        keys anyway, but if identities are meant to be genuinely independent,
        use `generate()` and record the public keys separately.
        """
        if len(symmetric) < 16:
            raise KeyManagementError(
                "the symmetric key must be at least 16 bytes")
        prk = hkdf_extract(salt=b"", ikm=bytes(symmetric))
        # The HKDF output is `bytes`, an unavoidable intermediate. The
        # constructor copies it into a secure buffer immediately.
        return cls(hkdf_expand(prk, INFO_IDENTITY, curve.KEY_BYTES))

    @property
    def public(self) -> bytes:
        """The public key to hand the other side.

        Computed without the secret leaving the buffer; the return value is
        not secret anyway.
        """
        return curve.public_key_buffer(self._buf)

    @property
    def trace(self) -> bytes:
        """A short trace of the public key, to say which device this is."""
        return identity_trace(self.public)

    def __repr__(self) -> str:
        return f"Identity({self.trace.hex().upper()})"


def identity_trace(public: bytes) -> bytes:
    """A shortened identity for a public key.

    The public key is not secret; the trace exists only so a handshake packet
    carries 8 bytes instead of 32.
    """
    prk = hkdf_extract(salt=b"", ikm=bytes(public))
    return hkdf_expand(prk, INFO_IDENTITY, IDENTITY_TRACE_BYTES)


@dataclass(frozen=True)
class SessionKeys:
    """The result of a handshake."""

    sending: bytes
    receiving: bytes
    session: bytes
    confirmation_code: str

    def __repr__(self) -> str:
        return f"SessionKeys(confirmation={self.confirmation_code})"


class Handshake:
    """The state of one handshake.

        a = Handshake(identity_a, identity_b.public, initiator=True)
        b = Handshake(identity_b, identity_a.public, initiator=False)

        keys_a = a.complete(b.ephemeral_public)
        keys_b = b.complete(a.ephemeral_public)

        keys_a.sending == keys_b.receiving      # True

    The object is single use. After `complete` the ephemeral private key is
    erased, which is the whole basis of forward secrecy. A second call is
    rejected.
    """

    def __init__(
        self,
        identity: Identity,
        peer_public: bytes,
        *,
        initiator: bool,
        ephemeral_secret: bytes | None = None,
    ) -> None:
        if len(peer_public) != curve.KEY_BYTES:
            raise KeyManagementError(
                f"the peer public key must be {curve.KEY_BYTES} bytes, "
                f"got {len(peer_public)}")
        self.identity = identity
        self.peer_public = bytes(peer_public)
        self.initiator = initiator
        # The ephemeral private key lives in a secure buffer. Forward secrecy
        # rests entirely on this key dying; a `bytearray` could be zeroed but
        # could also reach swap, and with the C core it is possible to keep the
        # secret out of Python object space altogether. `ephemeral_secret` is
        # only passed in for tests and reproducibility, and in that case the
        # secret already arrived as `bytes`.
        if ephemeral_secret is None:
            self._ephemeral = SecureBuffer.random(curve.KEY_BYTES)
        else:
            self._ephemeral = SecureBuffer(curve.KEY_BYTES,
                                           data=bytes(ephemeral_secret))
        self.ephemeral_public = curve.public_key_buffer(self._ephemeral)
        self._done = False

    @property
    def role(self) -> str:
        return INITIATOR if self.initiator else RESPONDER

    def complete(self, peer_ephemeral: bytes) -> SessionKeys:
        """Take the peer's ephemeral key and derive the session keys."""
        if self._done:
            raise KeyManagementError(
                "this handshake is already complete. The ephemeral private "
                "key was erased, which is what forward secrecy rests on. Use "
                "a new Handshake for a new session.")
        if len(peer_ephemeral) != curve.KEY_BYTES:
            raise KeyManagementError(
                f"the peer ephemeral must be {curve.KEY_BYTES} bytes, "
                f"got {len(peer_ephemeral)}")
        peer_ephemeral = bytes(peer_ephemeral)
        # The ephemeral secret never leaves its buffer; the static identity key
        # is handled the same way.
        e, s = self._ephemeral, self.identity.buffer

        # Four DHs, ordered by ROLE, so both sides compute the same order.
        if self.initiator:
            ee = curve.x25519_buffer(e, peer_ephemeral)
            peer = curve.x25519_buffer(e, self.peer_public)
            se = curve.x25519_buffer(s, peer_ephemeral)
            E_i, E_r = self.ephemeral_public, peer_ephemeral
            S_i, S_r = self.identity.public, self.peer_public
        else:
            ee = curve.x25519_buffer(e, peer_ephemeral)
            peer = curve.x25519_buffer(s, peer_ephemeral)
            se = curve.x25519_buffer(e, self.peer_public)
            E_i, E_r = peer_ephemeral, self.ephemeral_public
            S_i, S_r = self.peer_public, self.identity.public
        ss = curve.x25519_buffer(s, self.peer_public)

        # Zero result check, RFC 7748 section 6.1. `shared_secret` does this
        # itself; on the buffer path it happens here, so an attacker sending a
        # small order point cannot choose the shared secret.
        for name, value in (("ee", ee), ("es", peer), ("se", se), ("ss", ss)):
            if value == curve.ZERO_RESULT:
                raise KeyManagementError(
                    f"{name} came out zero: the other side sent a small order "
                    f"point (RFC 7748 section 6.1).")

        # The ephemeral private key dies here, and this time for real: the
        # contents are zeroed and the locked page is released.
        self._ephemeral.close()
        self._done = True

        return _derive(ee + peer + se + ss, E_i + E_r + S_i + S_r,
                       self.initiator)


def _derive(material: bytes, transcript: bytes,
            initiator: bool) -> SessionKeys:
    """Direction separated session keys from the four DH outputs.

    The transcript, all four public keys, is the HKDF SALT, which binds the
    session key to the full text of the handshake.
    """
    prk = hkdf_extract(salt=transcript, ikm=material)
    forward = hkdf_expand(prk, INFO_FORWARD, HASH_LEN)
    backward = hkdf_expand(prk, INFO_BACKWARD, HASH_LEN)
    raw = hkdf_expand(prk, INFO_CONFIRM, 4)
    return SessionKeys(
        sending=forward if initiator else backward,
        receiving=backward if initiator else forward,
        session=hkdf_expand(prk, INFO_SESSION, HASH_LEN),
        # A short code the two ends can compare out loud. If the static keys
        # were not shared in advance, this is the only thing that catches a man
        # in the middle: the attacker has to run two separate sessions and the
        # codes will not match.
        confirmation_code=f"{int.from_bytes(raw, 'big') % 1000000:06d}",
    )


# ───────────────────────── transport ─────────────────────────

def pack(engine: Any, hs: Handshake, **kw) -> bytes:
    """Turn a handshake message into an ordinary ciphertext.

    `engine` carries the pre-shared SYMMETRIC key, so the handshake packet is
    authenticated and indistinguishable from any other packet. An observer
    cannot see when a session was established.
    """
    return engine.encrypt(
        HANDSHAKE_SLUG,
        {
            "rol": hs.role,
            "efemer": hs.ephemeral_public,
            "kimlik_izi": hs.identity.trace,
        },
        **kw,
    )


def unpack(engine: Any, blob: bytes) -> tuple[str, bytes, bytes]:
    """Decode a handshake packet into (role, ephemeral_public, identity_trace)."""
    entry, values = engine.decode(blob)
    if entry.slug != HANDSHAKE_SLUG:
        raise DecodeError(f"this ciphertext is not a handshake: {entry}")
    return values["rol"], values["efemer"], values["kimlik_izi"]


class SecureChannel:
    """A two way channel after a handshake.

    Each direction uses its own key, its own sequence counter and its own
    replay window, which removes the "using one key both ways collides the
    numbers" warning from `Session`.

        channel_a = SecureChannel(corpus, keys_a)
        channel_b = SecureChannel(corpus, keys_b)

        channel_b.decrypt_text(channel_a.encrypt_text("order"))   # "order"
    """

    def __init__(self, corpus: Any, keys: SessionKeys, *,
                 window: int = 64) -> None:
        from .session import Session
        from .wire import Engine

        self.keys = keys
        self._out = Session(Engine(corpus, keys.sending), window=window)
        self._in = Session(Engine(corpus, keys.receiving), window=window)

    @property
    def confirmation_code(self) -> str:
        """The six digit code the two ends compare out loud."""
        return self.keys.confirmation_code

    # sending, outgoing key
    def encrypt(self, formula, values, **kw):
        return self._out.encrypt(formula, values, **kw)

    def encrypt_chain(self, records, **kw):
        return self._out.encrypt_chain(records, **kw)

    def encrypt_text(self, text, **kw):
        return self._out.encrypt_text(text, **kw)

    def encrypt_hidden(self, text, **kw):
        return self._out.encrypt_hidden(text, **kw)

    # receiving, incoming key
    def decode(self, blob, **kw):
        return self._in.decode(blob, **kw)

    def decode_chain(self, blob, **kw):
        return self._in.decode_chain(blob, **kw)

    def decrypt_text(self, blob):
        return self._in.decrypt_text(blob)

    def decrypt_hidden(self, blob):
        return self._in.decrypt_hidden(blob)

    def state(self) -> dict[str, Any]:
        """Contains no keys, only counters and windows."""
        return {"out": self._out.state(), "in": self._in.state()}

    def load_state(self, d: dict[str, Any]) -> None:
        self._out.load_state(d["out"])
        self._in.load_state(d["in"])

    def __repr__(self) -> str:
        return f"SecureChannel(confirmation={self.confirmation_code})"
