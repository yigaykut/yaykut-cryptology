"""The secure buffer: wipeable and locked key memory (ADR-020).

WHAT MATTERS MOST IN THIS FILE

The most valuable test is `test_bytes_cannot_be_wiped_buffer_can_be_wiped`,
because that difference is exactly why ADR-020 exists, and writing a security
claim without testing it is worse than not writing it, since it gives false confidence.

The tests are meaningful without the C core too: the class then works on a
`bytearray`, wiping still happens and locking does not. `guarantee` says
which case you are in, and the tests verify that as well.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crypto import memory, curve, fastpath# noqa: E402
from crypto.memory import SecureBuffer, BufferError_  # noqa: E402

BASE_POINT = bytes([9] + [0] * 31)

not_compiled = pytest.mark.skipif(
    not fastpath.ready(),
    reason="the C core is not compiled (python ccore/build.py)")


# ═══════════════ the real claim: wipeability ═══════════════

def test_bytes_cannot_be_wiped_buffer_can_be_wiped():
    """ADR-020's one sentence reason, as a test.

    `bytes` is immutable: there is NO WAY to zero a secret you hold in one.
    A buffer sits on mutable memory and really does get zeroed.
    """
    secret = os.urandom(32)

    # bytes: there is no way even to try wiping it, it is immutable.
    with pytest.raises((TypeError, AttributeError)):
        secret[0] = 0                                    # type: ignore[index]
    assert secret != bytes(32)                           # hâlâ orada

    with SecureBuffer(32, data=secret) as t:
        assert bytes(t.view()) == secret
        t.wipe()
        assert bytes(t.view()) == bytes(32)        # really gone


def test_closed_buffer_cannot_be_used():
    """Trying to use a wiped key must not pass quietly."""
    t = SecureBuffer(32)
    t.close()
    assert t.closed
    for call in (t.view, t.to_bytes, t.wipe):
        with pytest.raises(BufferError_):
            call()
    with pytest.raises(BufferError_):
        _ = t.address


def test_closing_two_times_harmless():
    """Closing by hand inside a `with` has to be possible too."""
    t = SecureBuffer(16)
    t.close()
    t.close()          # must not blow up
    assert t.closed


def test_with_block_on_exit_wipes():
    t = SecureBuffer(32, data=b"\xA5" * 32)
    with t:
        assert bytes(t.view()) == b"\xA5" * 32
    assert t.closed


def test_byte_copy_from_the_buffer_independent():
    """The `to_bytes()` warning is real: the copy does not die when the buffer is wiped.

    That behaviour is DELIBERATE and written in its docs. The test pins it so
    nobody later assumes wrongly that "the copy gets wiped too".
    """
    with SecureBuffer(32, data=b"\x5A" * 32) as t:
        copy = t.to_bytes()
        t.wipe()
        assert bytes(t.view()) == bytes(32)
        assert copy == b"\x5A" * 32          # the copy SURVIVES, unavoidably


def test_new_buffer_zero():
    """No malloc residue may leak; the C side zeroes on allocation."""
    for _ in range(5):
        with SecureBuffer(64) as t:
            assert bytes(t.view()) == bytes(64)


# ═══════════════ generation ═══════════════

def test_random_pads():
    with SecureBuffer.random(32) as t:
        assert bytes(t.view()) != bytes(32)


def test_random_replay_does_not():
    """Producing the same value twice is 2^-256; if the generator is broken it blows up here."""
    samples = set()
    for _ in range(20):
        with SecureBuffer.random(32) as t:
            samples.add(t.to_bytes())
    assert len(samples) == 20


def test_random_byte_distribution_reasonable():
    """A rough sanity check that catches a generator returning a constant byte."""
    with SecureBuffer.random(4096) as t:
        raw = t.to_bytes()
    assert len(set(raw)) > 200        # at least 200 distinct values in 4096 bytes


# ═══════════════ status reporting ═══════════════

def test_guarantee_correct_the_one_says():
    """`guarantee` has to reflect the real state, undecorated."""
    with SecureBuffer(32) as t:
        if t.address is None:
            assert t.guarantee == memory.GUARANTEE_PURE
            assert t.locked is False
        elif t.locked:
            assert t.guarantee == memory.GUARANTEE_LOCKED
        else:
            assert t.guarantee == memory.GUARANTEE_UNLOCKED


def test_state_text_exists():
    assert isinstance(memory.status(), str) and memory.status()


def test_repr_content_does_not_leak():
    """A key that reaches a log is easier to get than one in memory."""
    secret = b"\xDE\xAD\xBE\xEF" * 8
    with SecureBuffer(32, data=secret) as t:
        text = repr(t)
        assert "dead" not in text.lower()
        assert "32 bytes" in text


def test_invalid_size():
    for bad in (0, -1, 3.5, "32", None):
        with pytest.raises(BufferError_):
            SecureBuffer(bad)                       # type: ignore[arg-type]


def test_wrong_length_data():
    with SecureBuffer(32) as t:
        with pytest.raises(BufferError_):
            t.write(b"kisa")


# ═══════════════ together with X25519 ═══════════════

def test_buffer_path_pure_way_same_result():
    """The buffer path must not diverge from the known correct one."""
    for _ in range(5):
        raw = os.urandom(32)
        with SecureBuffer(32, data=raw) as t:
            assert curve.public_key_buffer(t) == \
                   curve.x25519_pure(raw, BASE_POINT)


def test_buffer_diffie_hellman():
    a = SecureBuffer.random(32)
    b = SecureBuffer.random(32)
    try:
        A = curve.public_key_buffer(a)
        B = curve.public_key_buffer(b)
        s1 = curve.shared_secret_buffer(a, B)
        s2 = curve.shared_secret_buffer(b, A)
        try:
            assert bytes(s1.view()) == bytes(s2.view())
            assert bytes(s1.view()) != bytes(32)
        finally:
            s1.close()
            s2.close()
    finally:
        a.close()
        b.close()


def test_shared_secret_buffer_rotates_bytes_not():
    """A shared secret is secret; returning `bytes` would make it unwipeable."""
    a = SecureBuffer.random(32)
    b = SecureBuffer.random(32)
    try:
        s = curve.shared_secret_buffer(a, curve.public_key_buffer(b))
        assert isinstance(s, SecureBuffer)
        s.close()
    finally:
        a.close()
        b.close()


def test_x25519_buffer_wrong_round_refuses():
    from crypto import KeyManagementError
    with pytest.raises(KeyManagementError):
        curve.x25519_buffer(b"\x01" * 32, BASE_POINT)      # bytes, not a buffer
    with SecureBuffer(16) as short:
        with pytest.raises(KeyManagementError):
            curve.x25519_buffer(short, BASE_POINT)


# ═══════════════ integration with the handshake ═══════════════

def test_hand_shake_ephemeral_in_the_buffer_and_happens():
    """The ephemeral key has to live in a buffer and die after `complete`.

    Forward secrecy rests entirely on this: the ephemeral secret really has
    to disappear, not stay as a `bytes` we assume disappeared.
    """
    from crypto.handshake import Handshake, Identity

    a_id, b_id = Identity.generate(), Identity.generate()
    a = Handshake(a_id, b_id.public, initiator=True)
    b = Handshake(b_id, a_id.public, initiator=False)

    assert isinstance(a._ephemeral, SecureBuffer)
    assert not a._ephemeral.closed

    ka = a.complete(b.ephemeral_public)
    kb = b.complete(a.ephemeral_public)

    assert a._ephemeral.closed          # the ephemeral secret died
    assert b._ephemeral.closed
    assert ka.sending == kb.receiving
    assert ka.receiving == kb.sending


def test_hand_shake_given_with_the_ephemeral_reproducible():
    """The path for supplying an ephemeral from outside, for tests, must keep working."""
    from crypto.handshake import Handshake, Identity

    a_id, b_id = Identity.generate(), Identity.generate()
    ea, eb = os.urandom(32), os.urandom(32)

    def run():
        a = Handshake(a_id, b_id.public, initiator=True, ephemeral_secret=ea)
        b = Handshake(b_id, a_id.public, initiator=False, ephemeral_secret=eb)
        return a.complete(b.ephemeral_public).sending

    assert run() == run()


# ═══════════════ with the C core only ═══════════════

@not_compiled
def test_c_on_the_path_address_exists():
    with SecureBuffer(32) as t:
        assert isinstance(t.address, int) and t.address != 0


@not_compiled
def test_c_on_the_path_guarantee_lock_reports():
    """If the lock does not hold it must not stay SILENT; the text has to say so."""
    with SecureBuffer(32) as t:
        if t.locked:
            assert "locked" in t.guarantee
        else:
            assert "COULD NOT LOCK" in t.guarantee


@not_compiled
def test_c_memory_selftest_passed():
    """The loader already calls it; here once more explicitly."""
    assert fastpath.lib().crypto_memory_selftest() == 0


# ═══════════════ the pure Python fallback ═══════════════

def test_pure_path_separate_in_process_works():
    """Everything has to work with the C core TURNED OFF.

    This test runs in a subprocess because `CRYPTO_PURE` is read at import
    time. On a compiled machine the fallback would otherwise never be
    exercised, and an untested fallback is one that does not work when it is needed.
    """
    import subprocess
    script = (
        "import sys; sys.path.insert(0, r'%s')\n"
        "from crypto import memory, curve\n"
        "from crypto.handshake import Handshake, Identity\n"
        "assert not memory.fastpath.ready()\n"
        "t = memory.SecureBuffer.random(32)\n"
        "assert t.address is None and t.locked is False\n"
        "assert t.guarantee == memory.GUARANTEE_PURE\n"
        "ham = t.to_bytes()\n"
        "assert curve.public_key_buffer(t) == curve.x25519_pure(ham, bytes([9]+[0]*31))\n"
        "t.wipe(); assert bytes(t.view()) == bytes(32); t.close()\n"
        "a, b = Identity.generate(), Identity.generate()\n"
        "x = Handshake(a, b.public, initiator=True)\n"
        "y = Handshake(b, a.public, initiator=False)\n"
        "assert x.complete(y.ephemeral_public).sending == y.complete(x.ephemeral_public).receiving\n"
        "print('SAF YOL TAMAM')\n" % str(ROOT)
    )
    env = dict(os.environ, CRYPTO_PURE="1", PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-c", script],
                       capture_output=True, text=True, env=env, timeout=300)
    assert p.returncode == 0, f"the pure path failed:\n{p.stdout}\n{p.stderr}"
    assert "SAF YOL TAMAM" in p.stdout


# ═══════════════ ADR-021: long lived keys ═══════════════

def test_identity_covert_key_in_the_buffer():
    """The system's longest lived secret must not sit as `bytes`."""
    from crypto.handshake import Identity

    k = Identity.generate()
    assert isinstance(k.buffer, SecureBuffer)
    assert not k.buffer.closed
    plain = k.public
    k.close()
    assert k.buffer.closed
    # the public key is not secret anyway; it was taken before closing
    assert len(plain) == 32


def test_identity_constructor_signature_not_broken():
    """`Identity(bytes)` still has to work, so code loading a key from disk does not break."""
    from crypto.handshake import Identity

    raw = os.urandom(32)
    k = Identity(raw)
    assert k.secret == raw
    assert k.public == curve.x25519_pure(raw, BASE_POINT)
    k.close()


def test_identity_covert_copy_when_closed_does_not_happen():
    """The `.secret` warning applies here too: the copy cannot be wiped."""
    from crypto.handshake import Identity

    with Identity.generate() as k:
        copy = k.secret
    assert copy != bytes(32)          # closing did not affect the copy


def test_identity_invalid_entry():
    from crypto import KeyManagementError
    from crypto.handshake import Identity

    for bad in (b"kisa", "metin", 42, None):
        with pytest.raises(KeyManagementError):
            Identity(bad)               # type: ignore[arg-type]


def test_key_chain_in_the_buffer_and_back_no_way_back():
    """What forward secrecy rests on: the old chain key has to disappear."""
    from crypto.keys import KeyChain

    z = KeyChain(os.urandom(32))
    assert isinstance(z._chain, SecureBuffer)
    first = z.message_key()
    z.advance()
    assert z.message_key() != first
    z.close()
    assert z._chain.closed


def test_key_chain_short_with_a_seed_advances():
    """The seed can be shorter than HASH_LEN; the size changes on the first advance."""
    from crypto.keys import KeyChain

    z = KeyChain(os.urandom(16))          # 16 bytes is the minimum accepted
    assert len(z._chain) == 16
    z.advance()
    assert len(z._chain) == 32                 # a derivation is always HASH_LEN
    assert z.message_key() != bytes(32)
    z.advance()
    z.close()


def test_parent_key_buffer_never_bytes_does_not_happen():
    from crypto.keys import master_key_buffer, device_key_buffer
    from crypto.keys import device_key, epoch_key_buffer

    with master_key_buffer() as master:
        assert isinstance(master, SecureBuffer)
        assert bytes(master.view()) != bytes(32)
        # the buffer path and the bytes path must do the same derivation
        c1 = device_key_buffer(master, "uav-01")
        try:
            assert c1.to_bytes() == device_key(master.to_bytes(), "uav-01")
        finally:
            c1.close()
        d = epoch_key_buffer(master, 7)
        d.close()


def test_wipe_safe_buffer_also_wipes():
    from crypto.keys import wipe

    with SecureBuffer(32, data=b"\xFF" * 32) as t:
        wipe(t)
        assert bytes(t.view()) == bytes(32)


def test_wipe_bytes_still_refuses():
    """`bytes` cannot be wiped and that has not changed; it must not silently succeed."""
    from crypto import KeyManagementError
    from crypto.keys import wipe

    with pytest.raises(KeyManagementError):
        wipe(b"\xFF" * 32)              # type: ignore[arg-type]
