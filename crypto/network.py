"""Network topology: open, restricted and covert networks.

The pre-key defined what a network IS: one shared P, pairwise K per member.
This module defines how networks relate to each other: whether a network can
contain another, and if so whether the parent can read it.

A network is a single root secret. Everything else derives from it:

    S  (32 bytes)
    ├─ P            = HKDF(S, "prekey")        selector mask secret
    ├─ K_member(id) = HKDF(S, "member" ‖ id)   member's pairwise key
    ├─ T            = HKDF(S, "corpus-seed")   seed for the network's corpus
    ├─ S_c(label)   = HKDF(S, "child" ‖ label) sub network root
    └─ S_d(no)      = HKDF(S, "epoch" ‖ no)    epoch network, itself complete

All five are siblings; none derives from another. That preserves the
separation the pre-key needs: even if K_member leaks, HKDF is one way so S
cannot be recovered and P does not fall with it. The rule "P must not derive
from K" is not broken. P and K are two branches of the same root, exactly like
`primitives.subkeys` producing three independent subkeys from one PRK.

Three modes.

OPEN can contain sub networks. A child's root secret comes straight from
`os.urandom` and the parent cannot compute it. How many sub networks exist is
written nowhere, because nothing keeps a ledger. A network is a secret, not an
account.

RESTRICTED cannot contain sub networks. `child_network` raises.

COVERT looks OPEN to its members. The difference is in one place: a child's
root secret is not random but DERIVED from the parent's. The parent can
therefore reproduce the child's P, its member keys and its corpus, which means
it can read the child's traffic. Creating one requires a password; that gate
is policy, not cryptography, and its limits are in the authorisation section
below.

Why it is indistinguishable, and what that rests on: what reaches a member is
a single root secret. In an open network it comes from `os.urandom`, in a
covert one from `HKDF(S_parent, ...)`. HMAC-SHA256 is a pseudorandom function,
so to anyone without S_parent the two are indistinguishable. That is not a
trick, it is HKDF's defined security property. On top of that `export()`
produces a fixed 38 byte descriptor with no field belonging to the parent, so
length, layout and distribution all match.

Places where honesty is required, all measured or stated:

The mechanism is not secret. This file is public. What is hidden is not
"does such a mode exist" but "is THIS network in it". That is what Kerckhoffs
requires; the opposite would not be security, it would be a concealed lie.

It is a reading capability, not a collection capability. The parent can derive
the child's keys; it cannot obtain the ciphertext. Without traffic capture the
capability is worthless.

The label must be known. A parent can only derive a sub network whose LABEL it
knows, and the label is chosen by whoever created it. In practice labels are
known because the parent ships the client that follows the counter convention,
but a member who modifies their client drops out of observation. That is not a
hole cryptography can close; it is a naming convention problem.

Second degree is invisible, and that is a consequence rather than a policy.
`child_network` always returns an OPEN network, even in covert mode. The
reason: a covert network OBJECT tells whoever holds it what mode it is in, so
covertness only means anything as long as it is not hidden from the holder. If
the child were covert its own owner would see that and covertness would break
anyway. Because children are open, their children are born from random secrets
and the root cannot see grandchildren. The requested "first degree only"
behaviour falls out of this by itself.

Epoch rotation does not protect the root. `epoch(d)` compartments in time: if
a device falls only that epoch's traffic opens, because S_d cannot lead back
to S. But if S itself is taken, every epoch falls. The only thing protecting
the root is keeping it off every device, and that is an operating decision, not
a mechanism.

The authorisation gate is not cryptographic. Tying covert mode to a password
restricts THIS PROGRAM's behaviour; it does not restrict the capability. Anyone
with the source deletes the check, and covert mode amounts to "I derive the
child's secret from my own", which anyone with their own secret can do in
their own code. The gate's real gain is separate: the password is not stored in
plaintext, so publishing the repository does not burn it.

This is a backdoor. A covert network means sub network keys can be reproduced
by the parent, and the name for that in the literature is key escrow. Adding no
field to the message makes it undetectable, which does not make it less of a
backdoor, only better hidden. Whoever builds it and whoever uses it should know
what it is.
"""

from __future__ import annotations

import hmac
import os
from datetime import date as _date
from enum import Enum

from . import primitives
from .errors import KeyManagementError
from .memory import SecureBuffer
from .prekey import Prekey

# v4 labels. v1 is message subkeys, v2 the key hierarchy, v3 the pre-key, v4
# network topology. Without domain separation one level's output could be used
# as a key at another level.
INFO_PREKEY = b"kripto/v4/ag/onanahtar"
INFO_MEMBER = b"kripto/v4/ag/uye"
INFO_CORPUS = b"kripto/v4/ag/korpus-tohumu"
INFO_CHILD = b"kripto/v4/ag/cocuk"
INFO_EPOCH = b"kripto/v4/ag/donem"

# Calendar origin. An epoch number is the number of slices since this date,
# which is how both ends find the same epoch without a handshake. The date is
# FIXED and cannot change: changing it would resolve old epoch numbers to
# different keys and make archived traffic unreadable.
CALENDAR_START = _date(2026, 1, 1)

ROOT_BYTES = 32
MIN_ROOT_BYTES = 16

# The descriptor must be a FIXED length: a length difference separates networks
# without reading a single byte of content. The network name therefore does not
# go into the descriptor. A name is a local bookkeeping label, not part of the
# secret.
DESCRIPTOR_MAGIC = b"KAG1"
DESCRIPTOR_BYTES = 4 + 1 + 1 + ROOT_BYTES  # magic + version + mode + root = 38


class NetworkError(KeyManagementError):
    """Invalid network setup or use."""


class AuthorisationError(NetworkError):
    """No authorisation for a covert network."""


# ═══════════════════════ COVERT MODE AUTHORISATION ═══════════════════════
#
# The work factor is 100,000 rounds of HMAC-SHA256, about half a second. Even
# if an offline attacker takes the digest, a 10 character alphanumeric password
# is about 59.5 bits, and brute force at this work factor is impractical.
# Lowering the round count makes that sentence false.
INFO_AUTH = b"kripto/v6/ag/yetki"
AUTH_ROUNDS = 100_000
AUTH_SALT = bytes.fromhex("dbe3c9b51cf135ceb926d73727e02ae4")
AUTH_DIGEST = bytes.fromhex(
    "c399e552ce99382936c438c1bfed619f045745827a84fdf746a12c23151b0f96")

# Environment variable used by tests and measurement tools to read the
# password. It is never written into the repository; it is set in the
# developer's session. Without it, tests exercising covert mode are SKIPPED
# rather than counted as passing.
AUTH_ENV = "CRYPTO_NETWORK_PASSWORD"

_authorised = False

# Marker for internal derivations such as `epoch`. A network derived from an
# already authorised one does not ask for the password again; if it did,
# `epoch()` would be unusable.
_INTERNAL_AUTH = object()


def _password_digest(password: str) -> bytes:
    """Iterated HMAC. No new primitive; HKDF's extract in a loop.

    The slowness is deliberate. A single round digest would give the password
    back from a leaked digest in seconds.
    """
    if not isinstance(password, str) or not password:
        raise AuthorisationError("the password must be a non-empty string")
    x = primitives.hkdf_extract(salt=AUTH_SALT, ikm=password.encode("utf-8"))
    for _ in range(AUTH_ROUNDS):
        x = primitives.hkdf_extract(salt=AUTH_SALT, ikm=x)
    return primitives.hkdf_expand(x, INFO_AUTH, 32)


def password_correct(password: str) -> bool:
    """Compare the password in constant time. Leaks no secret."""
    try:
        return hmac.compare_digest(_password_digest(password), AUTH_DIGEST)
    except AuthorisationError:
        return False


def authorise(password: str | None = None) -> bool:
    """Open covert mode authorisation for this process.

    Without `password` it is read from the environment variable. On success it
    returns True and authorisation stays open for the life of the process.

    Authorisation is process level and never written to disk; it ends with the
    process.
    """
    global _authorised
    if password is None:
        password = os.environ.get(AUTH_ENV)
    if not password:
        return False
    if password_correct(password):
        _authorised = True
        return True
    return False


def deauthorise() -> None:
    """Close authorisation. Existing network OBJECTS are unaffected."""
    global _authorised
    _authorised = False


def is_authorised() -> bool:
    return _authorised


class NetworkMode(Enum):
    """A network's sub network behaviour.

    The values are written into the descriptor, so they are permanent and
    cannot be changed.
    """

    OPEN = 1
    RESTRICTED = 2
    COVERT = 3

    @property
    def can_have_children(self) -> bool:
        return self is not NetworkMode.RESTRICTED

    @property
    def children_observable(self) -> bool:
        """Whether this mode can reproduce its sub networks' secrets."""
        return self is NetworkMode.COVERT


class Network:
    """A network: one root secret, one of three modes.

    The root secret lives in a `SecureBuffer`, because it is long lived and
    should be erasable and, where possible, in locked memory.

        with Network.create(NetworkMode.OPEN, name="hq") as net:
            p = net.prekey()
            k = net.member_key("alice")
            engine = Engine(corpus, k, prekey=p)
    """

    __slots__ = ("_root", "_mode", "name")

    def __init__(self, root: bytes | SecureBuffer, *,
                 mode: NetworkMode = NetworkMode.OPEN, name: str = "",
                 password: str | object | None = None) -> None:
        if not isinstance(mode, NetworkMode):
            raise NetworkError(
                f"mode must be a NetworkMode, got {type(mode).__name__}")

        # The authorisation gate is HERE, not in `create`. The reason: the
        # only way a `Network` object can CARRY covert mode is through this
        # constructor. `create`, `from_descriptor` and direct construction all
        # end up here. Putting the gate in `create` would let
        # `Network(root, mode=COVERT)` bypass it and the gate would be
        # decoration.
        if mode is NetworkMode.COVERT and password is not _INTERNAL_AUTH:
            if password is not None:
                if not isinstance(password, str) \
                        or not password_correct(password):
                    raise AuthorisationError("wrong covert network password")
            elif not _authorised:
                raise AuthorisationError(
                    "creating a covert network requires authorisation. Call "
                    f"`network.authorise(password)` or set the {AUTH_ENV} "
                    f"environment variable. This is a POLICY gate, not a "
                    f"cryptographic lock.")

        if isinstance(root, SecureBuffer):
            if root.closed:
                raise NetworkError("a closed buffer cannot be a network root")
            if root.size < MIN_ROOT_BYTES:
                raise NetworkError(
                    f"the network root must be at least {MIN_ROOT_BYTES} "
                    f"bytes, got {root.size}")
            self._root = root
        else:
            if not isinstance(root, (bytes, bytearray, memoryview)):
                raise NetworkError(
                    f"expected bytes or SecureBuffer, got "
                    f"{type(root).__name__}")
            raw = bytes(root)
            if len(raw) < MIN_ROOT_BYTES:
                raise NetworkError(
                    f"the network root must be at least {MIN_ROOT_BYTES} "
                    f"bytes, got {len(raw)}")
            self._root = SecureBuffer(len(raw), data=raw)

        self._mode = mode
        # The name is a local bookkeeping label. It does not enter the
        # descriptor, does not enter any derivation, and is not part of the
        # secret. It exists for humans to read.
        self.name = name

    @classmethod
    def create(cls, mode: NetworkMode = NetworkMode.OPEN, *, name: str = "",
               size: int = ROOT_BYTES, password: str | None = None) -> "Network":
        """A new network, root secret straight from the CSPRNG.

        COVERT needs authorisation: either `password`, or a previous call to
        `authorise()`. The reasoning and its LIMITS are in the authorisation
        section of this module. It is not a cryptographic lock.
        """
        if size < MIN_ROOT_BYTES:
            raise NetworkError(
                f"the network root must be at least {MIN_ROOT_BYTES} bytes")
        return cls(SecureBuffer.random(size), mode=mode, name=name,
                   password=password)

    # ─────────────────────── derivations ───────────────────────

    def _derive(self, info: bytes, label: bytes, length: int) -> bytes:
        self._check()
        secret = self._root.to_bytes()
        try:
            prk = primitives.hkdf_extract(salt=label, ikm=secret)
            return primitives.hkdf_expand(prk, info, length)
        finally:
            del secret

    def prekey(self) -> Prekey:
        """The network's pre-key, shared across the WHOLE network."""
        return Prekey(self._derive(INFO_PREKEY, b"", 32))

    def member_key(self, identity: bytes | str) -> bytes:
        """A member's PAIRWISE master key.

        A separate K with every member, one shared P. That is the topology a
        canary trap needs: different information can go to each person, but
        they all belong to the same network and cannot read each other.
        """
        if isinstance(identity, str):
            identity = identity.encode("utf-8")
        if not identity:
            raise NetworkError("member identity cannot be empty")
        return self._derive(INFO_MEMBER, bytes(identity), 32)

    def corpus_seed(self) -> bytes:
        """The seed for this network's own derived corpus.

        Deterministic: two ends of the same network produce the same corpus
        without exchanging a single byte.

        It goes through HKDF rather than using S directly because corpus
        generation runs on a `random.Random` style generator. Since the seed is
        an HKDF output, even in the worst case where the seed is fully
        compromised S cannot be recovered, and the loss stays limited to the
        corpus, which is not treated as an absolute secret anyway.
        """
        return self._derive(INFO_CORPUS, b"", 32)

    # ─────────────────────── epochs ───────────────────────

    def epoch(self, no: int, *, name: str = "") -> "Network":
        """A particular EPOCH of the network, itself a complete network.

            S_d = HKDF(S, "v4/epoch" ‖ d)

        The returned object is a `Network` with its own P, its own member keys,
        its own corpus and its own sub networks. The mode is preserved
        exactly: a covert network's epoch is covert, a restricted one's is
        restricted.

        What it gives, the network level counterpart of the key hierarchy: the
        root secret stays in the vault and only that epoch's network is loaded
        onto a device. If the device is compromised the attacker can read only
        that epoch's traffic, because HKDF is one way and S_d cannot lead back
        to S, so no other epoch can be derived.

        What it does not give, and the distinction is critical: it provides NO
        forward secrecy against the root being compromised. Whoever takes S
        computes every epoch. Epochs compartment in time; they do not protect
        the root secret itself. The only thing protecting the root is keeping
        it off every device, and that is an operating decision, not a
        mechanism.

        There is a cost and it should be known in advance. Changing epoch also
        changes the network's corpus, since the corpus seed derives from S, so
        decoding old ciphertexts needs that epoch's network. If the root is
        deleted for forward secrecy, your own archive becomes unreadable too.
        That is what forward secrecy means, and it is written here so it is
        not a surprise.
        """
        self._check()
        if not isinstance(no, int) or isinstance(no, bool) or no < 0:
            raise NetworkError(
                f"epoch must be a non-negative integer, got {no!r}")
        return Network(
            self._derive(INFO_EPOCH, no.to_bytes(8, "big"), ROOT_BYTES),
            mode=self._mode, password=_INTERNAL_AUTH,
            name=name or (f"{self.name}#e{no}" if self.name else ""))

    # ─────────────────────── sub networks ───────────────────────

    def child_network(self, label: bytes | str, *, name: str = "") -> "Network":
        """Create a sub network inside this one.

        The returned network is ALWAYS OPEN, even in covert mode. The reason is
        in the module docstring: a covert network object tells its holder what
        mode it is in, so giving the child covert mode would let the child's
        own owner see it and covertness would break anyway. The "only first
        degree is visible" behaviour is a CONSEQUENCE of this choice, not a
        separate rule.
        """
        self._check()
        if not self._mode.can_have_children:
            raise NetworkError(
                f"a {self._mode.name} network cannot contain sub networks; "
                f"that is what the mode means")

        label = self._label_bytes(label)

        # Both branches do the same work, and that is not decoration, it closes
        # a MEASURED leak.
        #
        # The first version ran `HKDF(S, label)` in the covert branch and
        # `os.urandom(32)` in the open one. The bytes were indistinguishable
        # but the TIME was not: |t| = 121.5 against a noise floor of 1.9, with
        # the covert branch 7.6 microseconds slower. A member requesting a sub
        # network from the parent and timing the reply would learn the mode, so
        # the claim "looks no different from an open network" was false on the
        # clock.
        #
        # Now both branches do one `os.urandom`, one root read and one HKDF;
        # only which secret goes into the HKDF is selected. What remains is a
        # Python reference assignment, and it sits below the noise floor in the
        # `sidechannel.py` measurement.
        random_root = os.urandom(ROOT_BYTES)
        root_copy = self._root.to_bytes()
        source = root_copy if self._mode.children_observable else random_root
        try:
            prk = primitives.hkdf_extract(salt=label, ikm=source)
            child_root = primitives.hkdf_expand(prk, INFO_CHILD, ROOT_BYTES)
        finally:
            del root_copy, random_root, source

        return Network(child_root, mode=NetworkMode.OPEN, name=name)

    def observe(self, label: bytes | str) -> "Network":
        """Re-derive a sub network from its LABEL. Covert mode only.

        The returned network is identical to the one `child_network(label)`
        handed the member: same P, same member keys, same corpus. That means
        the sub network's traffic can be read.

        This is only a READING capability. Obtaining the ciphertext is a
        separate job and out of scope for this module.
        """
        self._check()
        if not self._mode.children_observable:
            raise NetworkError(
                f"a {self._mode.name} network cannot observe its sub "
                f"networks; their root secrets are independent and stored "
                f"nowhere")
        label = self._label_bytes(label)
        return Network(
            self._derive(INFO_CHILD, label, ROOT_BYTES),
            mode=NetworkMode.OPEN,
            name=f"observed:{label.decode('utf-8', 'replace')}")

    def scan(self, count: int, *, pattern: str = "#{}") -> list["Network"]:
        """Derive sub networks following the counter convention, in order.

        This works as long as the client the parent distributes generates
        labels with `pattern`. A member who modifies their client and picks a
        different label drops out of the scan, which is exactly the "the label
        must be known" limit in the module docstring.
        """
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise NetworkError(
                f"count must be a non-negative integer: {count!r}")
        return [self.observe(pattern.format(i)) for i in range(count)]

    @staticmethod
    def _label_bytes(label: bytes | str) -> bytes:
        if isinstance(label, str):
            label = label.encode("utf-8")
        if not isinstance(label, (bytes, bytearray)):
            raise NetworkError(
                f"label must be bytes or str, got {type(label).__name__}")
        if not label:
            raise NetworkError("label cannot be empty")
        return bytes(label)

    # ─────────────────────── transport ───────────────────────

    def export(self, *, owner: bool = False) -> bytes:
        """The FIXED LENGTH descriptor handed to a member.

        Layout: magic(4) ‖ version(1) ‖ mode(1) ‖ root(32) = 38 bytes.

        No field belongs to the parent, and the length does not vary by mode.
        An open network's child and a covert network's child cannot be told
        apart at this level; both carry OPEN mode, see `child_network`.

        With owner=False a COVERT network cannot be exported. The reason cuts
        both ways: that descriptor gives away the mode AND the root secret, so
        whoever receives it sees everything the parent sees. What should be
        shared is not the network itself but the sub network `child_network`
        returns.
        """
        self._check()
        if self._mode is NetworkMode.COVERT and not owner:
            raise NetworkError(
                "a covert network's root descriptor cannot be shared; it "
                "gives away both the mode and the root secret. Give the "
                "member the result of `child_network(...)`. Use owner=True "
                "for backups.")
        return (DESCRIPTOR_MAGIC + bytes([1, self._mode.value])
                + self._root.to_bytes().ljust(ROOT_BYTES, b"\x00")[:ROOT_BYTES])

    @classmethod
    def from_descriptor(cls, descriptor: bytes, *, name: str = "",
                        password: str | None = None) -> "Network":
        """Read back what `export` produced."""
        if not isinstance(descriptor, (bytes, bytearray)):
            raise NetworkError("the descriptor must be bytes")
        descriptor = bytes(descriptor)
        if len(descriptor) != DESCRIPTOR_BYTES:
            raise NetworkError(
                f"the descriptor must be {DESCRIPTOR_BYTES} bytes, "
                f"got {len(descriptor)}")
        if not hmac.compare_digest(descriptor[:4], DESCRIPTOR_MAGIC):
            raise NetworkError("the descriptor is not in this format")
        if descriptor[4] != 1:
            raise NetworkError(f"unknown descriptor version: {descriptor[4]}")
        try:
            mode = NetworkMode(descriptor[5])
        except ValueError:
            raise NetworkError(
                f"unknown network mode: {descriptor[5]}") from None
        # Reading back a covert descriptor also needs authorisation: it carries
        # the root secret, and whoever reads it sees everything the parent sees.
        return cls(descriptor[6:], mode=mode, name=name, password=password)

    # ─────────────────────── identity and lifecycle ───────────────────────

    @property
    def mode(self) -> NetworkMode:
        return self._mode

    @property
    def closed(self) -> bool:
        return self._root.closed

    def fingerprint(self, length: int = 8) -> str:
        """The network's short identity. Leaks no root secret.

        Lets two ends confirm they are in the same network without showing the
        secret. It does not leak the mode either, since it derives from the
        root secret alone.
        """
        from .keys import fingerprint
        return fingerprint(self._root.to_bytes(), length)

    def same_as(self, other: "Network") -> bool:
        """Whether two network objects carry the same root. Constant time."""
        self._check()
        other._check()
        return hmac.compare_digest(self._root.to_bytes(),
                                   other._root.to_bytes())

    def close(self) -> None:
        """Erase the root secret. Not reversible; sub networks are gone too."""
        self._root.close()

    def _check(self) -> None:
        if self._root.closed:
            raise NetworkError("the network has been closed")

    def __enter__(self) -> "Network":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        """Never prints the root secret."""
        if self._root.closed:
            return "<Network CLOSED>"
        label = f" {self.name!r}" if self.name else ""
        return f"<Network {self._mode.name}{label} {self.fingerprint()}>"


# ═══════════════════════ CALENDAR ═══════════════════════

def epoch_number(day: "_date | None" = None, *, days_per_epoch: int = 1) -> int:
    """The epoch number from the calendar, slices since `CALENDAR_START`.

    This is how both ends find the same epoch without a handshake: both read
    the calendar. `days_per_epoch` is the epoch length, so 1 day means frequent
    rotation and 30 days means infrequent.

    Clock skew is a limit. If the two ends sit on different sides of a day
    boundary they compute different epochs and cannot talk. That is a
    distributed systems problem rather than a cryptographic one; in practice it
    is closed by also trying the previous epoch, and that decision belongs to
    the caller, not to this module.
    """
    day = day or _date.today()
    if not isinstance(days_per_epoch, int) or days_per_epoch < 1:
        raise NetworkError(
            f"epoch length must be at least 1 day: {days_per_epoch!r}")
    elapsed = (day - CALENDAR_START).days
    if elapsed < 0:
        raise NetworkError(
            f"{day} is before the calendar start ({CALENDAR_START}); an epoch "
            f"number cannot be negative")
    return elapsed // days_per_epoch
