"""The key hierarchy, rotation and forward secrecy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    KeyManagementError,
                    KeyChain,
                    Engine,
                    master_key,
                    device_key,
                    epoch_key,
                    load_corpus,
                    fingerprint,
                    wipe,
)

CORPUS = load_corpus()
MASTER = bytes(range(32))


# ───────────────────────── generation ─────────────────────────

def test_parent_key_length_and_freshness():
    a, b = master_key(), master_key()
    assert len(a) == 32
    assert a != b


def test_short_key_is_refused_2():
    with pytest.raises(KeyManagementError):
        master_key(8)
    with pytest.raises(KeyManagementError):
        device_key(b"kisa", "c1")


# ───────────────────────── isolation ─────────────────────────

def test_device_keys_different():
    assert device_key(MASTER, "uav-01") != device_key(MASTER, "uav-02")


def test_device_key_deterministic():
    assert device_key(MASTER, "uav-01") == device_key(MASTER, "uav-01")
    assert device_key(MASTER, "uav-01") == device_key(MASTER, b"uav-01")


def test_device_key_from_the_parent_different():
    """A derivation must not leak the master key."""
    assert device_key(MASTER, "x") != MASTER


def test_compromise_appearing_device_siblings_does_not_open():
    """A concrete test of isolation: one device's key does not open another's traffic."""
    from crypto import VerificationError

    a = Engine(CORPUS, device_key(MASTER, "uav-01"))
    b = Engine(CORPUS, device_key(MASTER, "uav-02"))
    blob = a.encrypt_text("konum bildirimi")
    with pytest.raises(VerificationError):
        b.decrypt_text(blob)


def test_empty_device_identity_is_refused():
    with pytest.raises(KeyManagementError):
        device_key(MASTER, "")


# ───────────────────────── rotation ─────────────────────────

def test_epoch_keys_different():
    k = device_key(MASTER, "uav-01")
    assert epoch_key(k, 1) != epoch_key(k, 2)
    assert epoch_key(k, 7) == epoch_key(k, 7)


def test_invalid_epoch_is_refused():
    with pytest.raises(KeyManagementError):
        epoch_key(MASTER, -1)


def test_old_epoch_new_traffic_does_not_open():
    from crypto import VerificationError

    k = device_key(MASTER, "uav-01")
    new = Engine(CORPUS, epoch_key(k, 2))
    old = Engine(CORPUS, epoch_key(k, 1))
    with pytest.raises(VerificationError):
        old.decrypt_text(new.encrypt_text("a new epoch"))


# ───────────────────────── parmak izi ─────────────────────────

def test_finger_trace_deterministic_and_distinguishing():
    assert fingerprint(MASTER) == fingerprint(MASTER)
    assert fingerprint(MASTER) != fingerprint(master_key())


def test_finger_trace_key_does_not_leak():
    trace = fingerprint(MASTER)
    assert MASTER.hex().upper() not in trace.replace("-", "")
    assert len(trace.replace("-", "")) == 16     # 8 byte


def test_engine_finger_trace_same():
    assert Engine(CORPUS, MASTER).fingerprint() == fingerprint(MASTER)


# ───────────────────────── forward secrecy ─────────────────────────

def test_chain_every_step_different_key():
    z = KeyChain(MASTER)
    keys = [z.advance() for _ in range(10)]
    assert len(set(keys)) == 10


def test_chain_deterministic():
    a = [KeyChain(MASTER).advance() for _ in range(1)]
    b = [KeyChain(MASTER).advance() for _ in range(1)]
    assert a == b


def test_chain_back_cannot_be_taken():
    """The essence of forward secrecy: once advanced, the old key cannot be produced."""
    z = KeyChain(MASTER)
    first = z.advance()
    for _ in range(5):
        z.advance()
    with pytest.raises(KeyManagementError, match="cannot go back"):
        z.fast_forward(0)
    # the chain's current state gives back the first key in no way at all
    assert z.message_key() != first


def test_yesterday_traffic_does_not_open_with_todays_state():
    """Even if the device is seized today, yesterday's message must not open."""
    from crypto import VerificationError

    chain = KeyChain(MASTER)
    yesterday = Engine(CORPUS, chain.advance()).encrypt_text("yesterday's report")
    for _ in range(3):
        chain.advance()

    # The attacker SEIZED the device. What they hold is the chain's REAL
    # current state, not an imitation. There is no way to produce yesterday's key:
    captured = chain
    with pytest.raises(VerificationError):
        Engine(CORPUS, captured.message_key()).decrypt_text(yesterday)
    with pytest.raises(KeyManagementError, match="cannot go back"):
        captured.fast_forward(0)


def test_forward_wrapping_gap_closes():
    sender = KeyChain(MASTER)
    for _ in range(4):
        sender.advance()          # 4 message kayboldu
    expected = sender.advance()   # the key for the 5th message

    receiver = KeyChain(MASTER)
    assert receiver.fast_forward(4) == expected


def test_unbounded_forward_wrapping_is_prevented():
    with pytest.raises(KeyManagementError, match="denial of service"):
        KeyChain(MASTER).fast_forward(10**6)


def test_message_key_chain_does_not_advance():
    z = KeyChain(MASTER)
    assert z.message_key() == z.message_key()
    assert z.step == 0


# ───────────────────────── wiping ─────────────────────────

def test_wipe_zeroes():
    t = bytearray(MASTER)
    wipe(t)
    assert t == bytearray(32)


def test_bytes_cannot_be_wiped():
    """In Python bytes is immutable, so it raises rather than fail silently."""
    with pytest.raises(KeyManagementError, match="bytes is immutable"):
        wipe(MASTER)


def test_chain_when_closed_cannot_be_used():
    """THE BEHAVIOUR CHANGED (ADR-021), and the old one was a trap.

    `close()` used to zero the chain key but leave the object usable:
    `message_key()` still returned a key, derived from a zeroed chain, so it
    was THE SAME ON EVERY CLOSED CHAIN. Silently encrypting with the wrong
    key is far worse than raising.

    The chain now lives in a secure buffer; `close()` releases the memory too
    and accessing a closed chain is refused explicitly.
    """
    from crypto.memory import BufferError_

    z = KeyChain(MASTER)
    once = z.message_key()
    assert once
    z.close()
    with pytest.raises(BufferError_):
        z.message_key()
    with pytest.raises(BufferError_):
        z.advance()
