"""The frame header and replay protection."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    FRAME_BYTES,
                    MAX_SEQ,
                    CIPHERTEXT_BYTES,
                    UNSEQUENCED,
                    VERSION,
                    VerificationError,
                    EncodingError,
                    Engine,
                    Session,
                    VersionError,
                    ReplayError,
                    ReplayWindow,
                    read_frame,
                    load_corpus,
                    sample,
)
from crypto import frame as frame_module# noqa: E402

CORPUS = load_corpus()
KEY = bytes(range(32))
ENGINE = Engine(CORPUS, KEY)


def new_session(**kw) -> Session:
    return Session(Engine(CORPUS, KEY), **kw)


# ───────────────────────── kayan pencere ─────────────────────────

def test_first_message_accept():
    p = ReplayWindow()
    p.accept(1)
    assert p.top == 1


def test_same_number_second_times_rejection():
    p = ReplayWindow()
    p.accept(1)
    with pytest.raises(ReplayError, match="already seen"):
        p.accept(1)


def test_unordered_but_window_inside_accept():
    """Network packets arrive out of order; a delay inside the window is legitimate."""
    p = ReplayWindow(width=8)
    for s in (1, 2, 3, 5, 6):
        p.accept(s)
    p.accept(4)          # late but not a replay
    assert p.top == 6
    with pytest.raises(ReplayError):
        p.accept(4)      # a second time is now a replay


def test_window_outside_remaining_rejection():
    p = ReplayWindow(width=4)
    for s in range(1, 21):
        p.accept(s)
    with pytest.raises(ReplayError, match="outside the window"):
        p.accept(3)


def test_large_jump_window_fully_shifts():
    p = ReplayWindow(width=8)
    p.accept(1)
    p.accept(1000)
    assert p.top == 1000
    with pytest.raises(ReplayError):
        p.accept(1000)
    p.accept(999)        # inside the new window, seen for the first time


def test_refused_number_window_is_not_processed():
    """Otherwise an attacker could push the window forward with a made up number."""
    p = ReplayWindow(width=8)
    p.accept(5)
    with pytest.raises(ReplayError):
        p.accept(5)
    assert p.top == 5      # the replay attempt did not move the upper bound
    p.accept(6)


def test_zero_number_rejection():
    p = ReplayWindow()
    with pytest.raises(ReplayError, match="no sequence number"):
        p.accept(UNSEQUENCED)


def test_saw_window_does_not_change():
    p = ReplayWindow()
    p.accept(3)
    assert p.seen(3)
    assert not p.seen(4)
    p.accept(4)          # still accepted, because seen did not mark it


def test_window_state_permanent():
    p = ReplayWindow(width=16)
    for s in (1, 2, 5, 9):
        p.accept(s)
    back = ReplayWindow.from_state(p.state())
    assert back.top == p.top
    for s in (1, 2, 5, 9):
        with pytest.raises(ReplayError):
            back.accept(s)
    back.accept(3)


@pytest.mark.parametrize("width", [0, -1, 100000])
def test_invalid_width_is_refused(width):
    with pytest.raises(EncodingError):
        ReplayWindow(width)


# ───────────────────────── the frame ─────────────────────────

def test_frame_order_number_carries():
    blob = ENGINE.encrypt_text("trial", seq=42)
    c = read_frame(blob, KEY)
    assert c.seq == 42
    assert c.version == VERSION
    assert c.in_session


def test_unordered_encryption_zero_carries():
    blob = ENGINE.encrypt_text("trial")
    c = ENGINE.read_frame(blob)
    assert c.seq == UNSEQUENCED
    assert not c.in_session


def test_frame_read_tag_verifies():
    blob = bytearray(ENGINE.encrypt_text("trial", seq=1))
    blob[100] ^= 0x01
    with pytest.raises(VerificationError):
        read_frame(bytes(blob), KEY)


def test_frame_read_wrong_with_the_key_failure():
    blob = ENGINE.encrypt_text("trial", seq=1)
    with pytest.raises(VerificationError):
        read_frame(blob, os.urandom(32))


def test_frame_full_decode_same_result_gives():
    """The cheap header read and a full decode have to see the same frame."""
    blob = ENGINE.encrypt_text("has to be the same", seq=7)
    from crypto.wire import _open
    _fid, exact, _body = _open(blob, KEY)
    assert exact == read_frame(blob, KEY)


def test_order_number_from_outside_is_invisible():
    """The same text under different sequence numbers has to look completely different."""
    a = ENGINE.encrypt_text("the same text", seq=1)
    b = ENGINE.encrypt_text("the same text", seq=2)
    assert len(a) == len(b) == CIPHERTEXT_BYTES
    shared = sum(x == y for x, y in zip(a, b))
    assert shared < len(a) // 4     # rastgele iki dizide expected ~1/256


def test_invalid_version_is_refused():
    with pytest.raises(VersionError, match="version mismatch"):
        frame_module.read_header(bytes([99]) + bytes(8))


def test_excessive_order_number_is_refused():
    with pytest.raises(EncodingError, match="out of range"):
        frame_module.wrap(MAX_SEQ + 1, b"x")


def test_frame_round_return():
    payload = b"body"
    wrapped = frame_module.wrap(1234, payload)
    assert len(wrapped) == FRAME_BYTES + len(payload)
    c, body = frame_module.unwrap(wrapped)
    assert (c.seq, body) == (1234, b"body")


# ───────────────────────── session ─────────────────────────

def test_session_round_return():
    o = new_session()
    blob = o.encrypt_text("order")
    assert o.decrypt_text(blob) == "order"


def test_replay_second_times_is_refused():
    """The system's most critical new guarantee."""
    o = new_session()
    blob = o.encrypt_text("fire at will")
    assert o.decrypt_text(blob) == "fire at will"
    with pytest.raises(ReplayError):
        o.decrypt_text(blob)


def test_recorded_packet_hours_after_cannot_be_stolen():
    o = new_session(window=8)
    record = o.encrypt_text("command")
    o.decrypt_text(record)
    for i in range(20):
        o.decrypt_text(o.encrypt_text(f"traffic {i}"))
    with pytest.raises(ReplayError):
        o.decrypt_text(record)


def test_order_numbers_rises():
    o = new_session()
    numbers = [o.engine.read_frame(o.encrypt_text(f"m{i}")).seq for i in range(5)]
    assert numbers == [1, 2, 3, 4, 5]


def test_unsequenced_message_in_session_is_refused():
    """A statelessly encrypted message cannot go through replay protection."""
    o = new_session()
    blob = ENGINE.encrypt_text("unprotected")
    with pytest.raises(ReplayError, match="no sequence number"):
        o.decrypt_text(blob)


def test_session_all_modes_covers():
    o = new_session()
    entry = CORPUS.by_slug("aes-sbox")

    formula = o.encrypt(entry.id, sample(entry))
    secret = o.encrypt_hidden("secret message")
    chain = o.encrypt_chain([(entry.id, sample(entry))])

    assert o.decode(formula)[0].id == entry.id
    assert o.decrypt_hidden(secret) == "secret message"
    assert len(o.decode_chain(chain)) == 1

    for blob in (formula, secret, chain):
        with pytest.raises(ReplayError):
            o.verify(blob)


def test_tampered_packet_window_does_not_pollute():
    """If the tag fails, the number must not be written into the window."""
    o = new_session()
    blob = bytearray(o.encrypt_text("message"))
    blob[50] ^= 0xFF
    with pytest.raises(VerificationError):
        o.decrypt_text(bytes(blob))
    assert o.window.top == 0
    # the untampered original still has to be accepted
    o2 = new_session()
    assert o2.decrypt_text(o2.encrypt_text("message")) == "message"


def test_session_state_permanent():
    o = new_session()
    blob = o.encrypt_text("persistent")
    o.decrypt_text(blob)

    new = new_session()
    new.load_state(o.state())
    with pytest.raises(ReplayError):
        new.decrypt_text(blob)


def test_state_key_does_not_contain():
    o = new_session()
    o.encrypt_text("x")
    assert KEY not in repr(o.state()).encode("latin-1", "ignore")
    assert set(o.state()) == {"outgoing", "window"}


def test_order_when_exhausted_open_error():
    o = new_session(start=MAX_SEQ)
    with pytest.raises(EncodingError, match="exhausted"):
        o.encrypt_text("overflow")


def test_two_session_independent():
    """What one session sends does not affect the other's window."""
    a, b = new_session(), new_session()
    blob = a.encrypt_text("crossed")
    assert b.decrypt_text(blob) == "crossed"
    assert a.window.top == 0
