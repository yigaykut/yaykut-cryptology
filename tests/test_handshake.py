"""The four way DH handshake: backward secrecy and authentication."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    CIPHERTEXT_BYTES,
                    KeyManagementError,
                    DecodeError,
                    VerificationError,
                    Handshake,
                    SecureChannel,
                    Identity,
                    Engine,
                    ReplayError,
                    master_key,
                    device_key,
                    curve,
                    handshake_unpack,
                    handshake_pack,
                    load_corpus,
)
from crypto.handshake import _derive  # noqa: E402

CORPUS = load_corpus()
MASTER = bytes(range(32))
PRESHARED = bytes(range(32, 64))     # the pre-shared symmetric key


def pair() -> tuple[Identity, Identity]:
    return Identity.generate(), Identity.generate()


def squeeze(ka: Identity, kb: Identity):
    """A full handshake; returns (keys_a, keys_b)."""
    a = Handshake(ka, kb.public, initiator=True)
    b = Handshake(kb, ka.public, initiator=False)
    return a.complete(b.ephemeral_public), b.complete(a.ephemeral_public)


# ───────────────────────── identity ─────────────────────────

def test_identity_generate_fresh():
    a, b = pair()
    assert a.secret != b.secret and a.public != b.public


def test_identity_from_the_key_deterministic():
    k = device_key(MASTER, "uav-01")
    assert Identity.from_key(k).secret == Identity.from_key(k).secret


def test_different_device_different_identity():
    a = Identity.from_key(device_key(MASTER, "uav-01"))
    b = Identity.from_key(device_key(MASTER, "uav-02"))
    assert a.public != b.public and a.trace != b.trace


def test_identity_covert_key_does_not_leak():
    k = Identity.generate()
    assert k.secret not in (k.public, k.trace)
    assert k.secret.hex() not in repr(k)


def test_short_identity_is_refused():
    with pytest.raises(KeyManagementError):
        Identity(b"kisa")
    with pytest.raises(KeyManagementError):
        Identity.from_key(b"kisa")


# ───────────────────────── the handshake ─────────────────────────

def test_two_side_same_to_the_session_reaches():
    aa, ab = squeeze(*pair())
    assert aa.session == ab.session


def test_direction_separation():
    """A separate key per direction, otherwise the sequence numbers would collide."""
    aa, ab = squeeze(*pair())
    assert aa.sending == ab.receiving
    assert aa.receiving == ab.sending
    assert aa.sending != aa.receiving


def test_verification_code_equal_and_six_digit():
    aa, ab = squeeze(*pair())
    assert aa.confirmation_code == ab.confirmation_code
    assert len(aa.confirmation_code) == 6 and aa.confirmation_code.isdigit()


def test_every_hand_in_handshake_different_session():
    """Forward secrecy: a new key for every session, even under the same identities."""
    ka, kb = pair()
    sessions = {squeeze(ka, kb)[0].session for _ in range(5)}
    assert len(sessions) == 5


def test_hand_shake_single_use():
    ka, kb = pair()
    a = Handshake(ka, kb.public, initiator=True)
    b = Handshake(kb, ka.public, initiator=False)
    a.complete(b.ephemeral_public)
    with pytest.raises(KeyManagementError, match="already complete"):
        a.complete(b.ephemeral_public)


def test_wrong_with_the_id_session_does_not_hold():
    """A man in the middle cannot get in with their own identity."""
    ka, kb = pair()
    attacker = Identity.generate()
    a = Handshake(ka, kb.public, initiator=True)
    fake = Handshake(attacker, ka.public, initiator=False)
    assert a.complete(fake.ephemeral_public).session != fake.complete(a.ephemeral_public).session


def test_record_binding_ephemeral_when_it_changes_key_changes():
    """The session key is bound to the FULL TRANSCRIPT of the handshake."""
    ka, kb = pair()
    a = Handshake(ka, kb.public, initiator=True, ephemeral_secret=bytes(range(32)))
    b = Handshake(kb, ka.public, initiator=False, ephemeral_secret=bytes(range(32, 64)))
    correct = a.complete(b.ephemeral_public)

    other = Handshake(kb, ka.public, initiator=False, ephemeral_secret=bytes(range(64, 96)))
    a2 = Handshake(ka, kb.public, initiator=True, ephemeral_secret=bytes(range(32)))
    assert a2.complete(other.ephemeral_public).session != correct.session


def test_same_with_ephemerals_deterministic():
    ka, kb = pair()

    def setup():
        a = Handshake(ka, kb.public, initiator=True, ephemeral_secret=bytes(range(32)))
        b = Handshake(kb, ka.public, initiator=False, ephemeral_secret=bytes(range(32, 64)))
        return a.complete(b.ephemeral_public).session

    assert setup() == setup()


def test_invalid_against_key_is_refused():
    ka, _ = pair()
    with pytest.raises(KeyManagementError):
        Handshake(ka, b"kisa", initiator=True)
    with pytest.raises(KeyManagementError):
        Handshake(ka, bytes(32), initiator=True).complete(b"kisa")


def test_small_order_ephemeral_is_refused():
    ka, kb = pair()
    a = Handshake(ka, kb.public, initiator=True)
    with pytest.raises(KeyManagementError, match="came out zero"):
        a.complete(bytes(32))


# ──────────────────── backward secrecy ────────────────────

def test_static_key_leak_does_not_open_past_sessions():
    """The gap left open in ADR-015, tested concretely as closed.

    The attacker has compromised BOTH sides' static private keys and had
    recorded all the handshake traffic. They do not hold the ephemeral
    PRIVATE keys: `complete` wiped them.
    """
    ka, kb = pair()
    a = Handshake(ka, kb.public, initiator=True)
    b = Handshake(kb, ka.public, initiator=False)
    Ea, Eb = a.ephemeral_public, b.ephemeral_public
    real = a.complete(Eb)
    b.complete(Ea)

    # The THREE DHs the attacker can compute:
    ss = curve.shared_secret(ka.secret, kb.public)
    peer = curve.shared_secret(kb.secret, Ea)     # = DH(e_initiator, S_responder)
    se = curve.shared_secret(ka.secret, Eb)     # = DH(s_initiator, E_responder)
    record = Ea + Eb + ka.public + kb.public

    # ee = DH(e_initiator, E_responder) cannot be computed. No guess works:
    for prediction in (bytes(32), Ea, Eb, ss, peer, se):
        assert _derive(prediction + peer + se + ss, record, True).session != real.session


def test_positive_control_fourth_dh_with_key_holds():
    """For the test above to hold: THE ONLY MISSING THING has to be ee.

    Without this check, "no guess worked" could also come from the
    derivation being broken.
    """
    ka, kb = pair()
    ea, eb = curve.private_key(), curve.private_key()
    a = Handshake(ka, kb.public, initiator=True, ephemeral_secret=ea)
    b = Handshake(kb, ka.public, initiator=False, ephemeral_secret=eb)
    Ea, Eb = a.ephemeral_public, b.ephemeral_public
    real = a.complete(Eb)

    ee = curve.shared_secret(ea, Eb)           # ← ephemeral secret key ELDE
    peer = curve.shared_secret(kb.secret, Ea)
    se = curve.shared_secret(ka.secret, Eb)
    ss = curve.shared_secret(ka.secret, kb.public)
    record = Ea + Eb + ka.public + kb.public

    assert _derive(ee + peer + se + ss, record, True).session == real.session


def test_one_of_the_session_key_the_other_does_not_open():
    ka, kb = pair()
    aa1, _ = squeeze(ka, kb)
    _, ab2 = squeeze(ka, kb)
    k1 = SecureChannel(CORPUS, aa1)
    k2 = SecureChannel(CORPUS, ab2)
    with pytest.raises(VerificationError):
        k2.decrypt_text(k1.encrypt_text("old session"))


# ───────────────────────── transport ─────────────────────────

def test_hand_shake_packet_from_the_others_distinguish_cannot():
    ka, kb = pair()
    engine = Engine(CORPUS, PRESHARED)
    packet = handshake_pack(engine, Handshake(ka, kb.public, initiator=True))
    assert len(packet) == CIPHERTEXT_BYTES == len(engine.encrypt_text("ordinary"))


def test_packet_round_return():
    ka, kb = pair()
    engine = Engine(CORPUS, PRESHARED)
    a = Handshake(ka, kb.public, initiator=True)
    role, ephemeral, trace = handshake_unpack(engine, handshake_pack(engine, a))
    assert (role, ephemeral, trace) == ("initiator", a.ephemeral_public, ka.trace)


def test_responder_role_is_carried():
    ka, kb = pair()
    engine = Engine(CORPUS, PRESHARED)
    b = Handshake(kb, ka.public, initiator=False)
    assert handshake_unpack(engine, handshake_pack(engine, b))[0] == "responder"


def test_hand_shake_not_packet_is_refused():
    engine = Engine(CORPUS, PRESHARED)
    with pytest.raises(DecodeError, match="not a handshake"):
        handshake_unpack(engine, engine.encrypt_text("an ordinary message"))


def test_packet_wrong_in_advance_shared_with_the_key_does_not_open():
    ka, kb = pair()
    a = Handshake(ka, kb.public, initiator=True)
    packet = handshake_pack(Engine(CORPUS, PRESHARED), a)
    with pytest.raises(VerificationError):
        handshake_unpack(Engine(CORPUS, master_key()), packet)


# ───────────────────────── the secure channel ─────────────────────────

def test_channel_two_way():
    aa, ab = squeeze(*pair())
    ca, cb = SecureChannel(CORPUS, aa), SecureChannel(CORPUS, ab)
    assert cb.decrypt_text(ca.encrypt_text("forward")) == "forward"
    assert ca.decrypt_text(cb.encrypt_text("back")) == "back"


def test_channel_replay_protects():
    aa, ab = squeeze(*pair())
    ca, cb = SecureChannel(CORPUS, aa), SecureChannel(CORPUS, ab)
    blob = ca.encrypt_text("order")
    cb.decrypt_text(blob)
    with pytest.raises(ReplayError):
        cb.decrypt_text(blob)


def test_channel_own_what_was_sent_cannot_decode():
    """The concrete consequence of direction separation."""
    aa, _ = squeeze(*pair())
    ca = SecureChannel(CORPUS, aa)
    with pytest.raises(VerificationError):
        ca.decrypt_text(ca.encrypt_text("my own message"))


def test_channel_covert_and_chain_modes_supports():
    from crypto import sample
    aa, ab = squeeze(*pair())
    ca, cb = SecureChannel(CORPUS, aa), SecureChannel(CORPUS, ab)
    entry = CORPUS.by_slug("aes-sbox")

    assert cb.decrypt_hidden(ca.encrypt_hidden("with decoys")) == "with decoys"
    assert len(cb.decode_chain(ca.encrypt_chain([(entry.id, sample(entry))]))) == 1
    assert cb.decode(ca.encrypt(entry.id, sample(entry)))[0].id == entry.id


def test_channel_state_key_does_not_contain():
    aa, _ = squeeze(*pair())
    ca = SecureChannel(CORPUS, aa)
    ca.encrypt_text("x")
    assert aa.sending not in repr(ca.state()).encode("latin-1", "ignore")


def test_channel_state_permanent():
    aa, ab = squeeze(*pair())
    ca, cb = SecureChannel(CORPUS, aa), SecureChannel(CORPUS, ab)
    blob = ca.encrypt_text("persistent")
    cb.decrypt_text(blob)

    new = SecureChannel(CORPUS, ab)
    new.load_state(cb.state())
    with pytest.raises(ReplayError):
        new.decrypt_text(blob)
