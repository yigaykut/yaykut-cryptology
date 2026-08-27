"""Network topology (`crypto/network.py`) and the network corpus (`layer2/network_corpus.py`).

WHY THIS FILE EXISTS

Two of the three modes are obviously correct: if RESTRICTED does not allow a
child, it does not; if OPEN creates one, it does. The third is not like that.

COVERT claims to be "indistinguishable from an open network", and that claim
only means something if it is TESTED. If `child_network` one day carries the
mode down to the sub network by accident, or a field is added to the
descriptor, a covert network silently becomes visible and nobody notices,
because the encryption keeps working. Most of the tests here exist to catch
exactly that silent breakage.

The three most critical:

  * test_covert_of_the_network_child_open_of_the_network_from_the_child_distinguish_cannot
  * test_grandchildren_is_invisible          (is the first degree limit structural)
  * test_distinguish_ability_chance_does_not_exceed  (the measurement lock plus the CONTROL arm)
  * test_epoch_from_the_network_to_the_root_no_way_back     (rotation's only meaning)
  * test_root_compromise_if_it_passes_ALL_epochs_fails (it also locks WHAT IS NOT CLAIMED)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conftest import SECRET_GRANT, secret_grant_needed  # noqa: E402
from layer2 import network_attack  # noqa: E402
from layer2.network_corpus import net_corpus, watermark  # noqa: E402
from crypto import VerificationError, Engine, load_corpus  # noqa: E402
from crypto.network import (  # noqa: E402
                            MIN_ROOT_BYTES,
                            ROOT_BYTES,
                            DESCRIPTOR_BYTES,
                            CALENDAR_START,
                            AUTH_ENV,
                            Network,
                            NetworkError,
                            NetworkMode,
                            AuthorisationError,
                            epoch_number,
                            password_correct,
                            authorise,
                            is_authorised,
)


@pytest.fixture(scope="module")
def corpus():
    return load_corpus()


# ═══════════════════════ WHAT THE MODES ARE ═══════════════════════

def test_restricted_network_child_does_not_allow_creating():
    with Network.create(NetworkMode.RESTRICTED) as net:
        with pytest.raises(NetworkError, match="cannot contain sub networks"):
            net.child_network("#0")


@secret_grant_needed
@pytest.mark.parametrize("mode", [NetworkMode.OPEN, NetworkMode.COVERT])
def test_open_modes_child_allows_creating(mode):
    with Network.create(mode) as net:
        child = net.child_network("#0")
        assert child.mode is NetworkMode.OPEN


def test_open_network_child_cannot_observe():
    """An open network's sub network is INDEPENDENT. The parent cannot compute it."""
    with Network.create(NetworkMode.OPEN) as net:
        net.child_network("#0")
        with pytest.raises(NetworkError, match="cannot observe"):
            net.observe("#0")


def test_open_network_same_with_the_tag_DIFFERENT_child_produces():
    """A direct consequence of independence: the label decides nothing, randomness does."""
    with Network.create(NetworkMode.OPEN) as net:
        a, b = net.child_network("#0"), net.child_network("#0")
        assert not a.same_as(b)


@secret_grant_needed
def test_covert_network_same_with_the_tag_THE_SAME_child_produces():
    """In covert mode the label is decisive; observation is built on that."""
    with Network.create(NetworkMode.COVERT) as net:
        a, b = net.child_network("#0"), net.child_network("#0")
        assert a.same_as(b)


@secret_grant_needed
def test_covert_network_different_in_the_tag_different_child_produces():
    with Network.create(NetworkMode.COVERT) as net:
        assert not net.child_network("#0").same_as(net.child_network("#1"))


@secret_grant_needed
def test_observation_of_the_child_THE_SAME_gives():
    with Network.create(NetworkMode.COVERT) as net:
        child = net.child_network("#7")
        observed = net.observe("#7")
        assert observed.same_as(child)
        assert observed.prekey().fingerprint() == child.prekey().fingerprint()
        assert observed.member_key("alice") == child.member_key("alice")
        assert observed.corpus_seed() == child.corpus_seed()


@secret_grant_needed
def test_observation_scan_counter_layout_traces():
    with Network.create(NetworkMode.COVERT) as net:
        children = [net.child_network(f"#{i}") for i in range(5)]
        for observed, real in zip(net.scan(5), children):
            assert observed.same_as(real)


@secret_grant_needed
def test_observation_scan_negative_number_refuses():
    with Network.create(NetworkMode.COVERT) as net:
        with pytest.raises(NetworkError):
            net.scan(-1)


# ═══════════════ INDISTINGUISHABILITY, THE REAL CLAIM ═══════════════

@secret_grant_needed
def test_covert_of_the_network_child_open_of_the_network_from_the_child_distinguish_cannot():
    """THE MOST CRITICAL TEST.

    The descriptor a member receives must not give away its mode. If
    `child_network` one day carries the mode down, a covert network silently
    becomes visible, and because the encryption keeps working no other test catches it.
    """
    with Network.create(NetworkMode.COVERT) as secret, Network.create(NetworkMode.OPEN) as free:
        g = secret.child_network("#0").export()
        s = free.child_network("#0").export()

        assert len(g) == len(s) == DESCRIPTOR_BYTES   # the length does not leak
        assert g[:6] == s[:6]                       # magic, version and MODE identical
        assert g[5] == NetworkMode.OPEN.value         # both say OPEN
        assert g[6:] != s[6:]                       # only the root secret differs


@secret_grant_needed
def test_child_object_to_the_parent_about_no_thing_DOES_NOT_CARRY():
    """A sub network object must hold no field of the parent's, neither mode nor root."""
    with Network.create(NetworkMode.COVERT, name="root") as parent:
        child = parent.child_network("#0")
        assert child.mode is NetworkMode.OPEN
        assert not child.same_as(parent)
        # `__slots__` structurally prevents new fields being added.
        assert set(Network.__slots__) == {"_root", "_mode", "name"}


@secret_grant_needed
def test_finger_trace_mode_does_not_leak():
    """The same root secret in different modes gives the same fingerprint.

    If the fingerprint derived from the mode, everyone sharing the network's
    identity would learn the mode too.
    """
    raw = bytes(range(32))
    assert (Network(raw, mode=NetworkMode.OPEN).fingerprint()
            == Network(raw, mode=NetworkMode.COVERT).fingerprint())


@secret_grant_needed
def test_grandchildren_is_invisible():
    """The first degree limit is NOT A POLICY, it is a STRUCTURAL CONSEQUENCE.

    Because `child_network` always returns OPEN, grandchildren are born from a
    random secret. There is no way for the root network to derive one.
    """
    with Network.create(NetworkMode.COVERT) as root:
        child = root.child_network("#0")
        grandchild = child.child_network("#0")

        assert root.observe("#0").same_as(child)        # the first degree is visible
        with pytest.raises(NetworkError, match="cannot observe"):
            child.observe("#0")                         # the child is open
        # The root's only observation path is its own label space, and a
        # grandchild does not come from there.
        assert not any(root.observe(f"#{i}").same_as(grandchild) for i in range(8))


# ═══════════════════════ DERIVATION SEPARATION ═══════════════════════

@secret_grant_needed
def test_four_derived_also_from_each_other_different():
    """P, K_member, the seed and the child secret are SIBLINGS, none equal to another."""
    with Network.create(NetworkMode.COVERT) as net:
        p = net.prekey()
        values = {
            p.buffer.to_bytes(),
            net.member_key("alice"),
            net.corpus_seed(),
            net.child_network("#0").export()[6:],
        }
        assert len(values) == 4


def test_member_keys_identity_by_splits():
    """The pairwise key topology: a separate K per member, but a shared P."""
    with Network.create(NetworkMode.OPEN) as net:
        assert net.member_key("alice") != net.member_key("bob")
        assert net.member_key("alice") == net.member_key("alice")


def test_member_key_empty_identity_refuses():
    with Network.create(NetworkMode.OPEN) as net:
        with pytest.raises(NetworkError):
            net.member_key("")


def test_prekey_member_from_key_different_being_for_engine_accept_does(corpus):
    """`Engine` rejects P == K (ADR-026). Network derivations must not fall into that trap."""
    with Network.create(NetworkMode.OPEN) as net:
        Engine(corpus, net.member_key("alice"), prekey=net.prekey())


# ═══════════════ END TO END: THE PARENT READS ═══════════════

@secret_grant_needed
def test_covert_parent_sub_of_the_network_message_CAN_DECRYPT(corpus):
    """The whole point of a covert open network is in this test.

    A sub network member writes a message; the parent reads it knowing only the LABEL.
    """
    with Network.create(NetworkMode.COVERT) as root:
        alt = root.child_network("#3")
        member = Engine(corpus, alt.member_key("alice"), prekey=alt.prekey())
        blob = member.encrypt_text("at nine on the bridge")

        observation = root.observe("#3")
        owner = Engine(corpus, observation.member_key("alice"),
                       prekey=observation.prekey())
        assert owner.decrypt_text(blob) == "at nine on the bridge"


def test_open_parent_sub_of_the_network_message_CANNOT_DECRYPT(corpus):
    """Open mode's opposite claim, and it has to be tested too."""
    with Network.create(NetworkMode.OPEN) as root:
        alt = root.child_network("#3")
        member = Engine(corpus, alt.member_key("alice"), prekey=alt.prekey())
        blob = member.encrypt_text("at nine on the bridge")

        # The best the parent can do is try its own derivations.
        with pytest.raises(NetworkError):
            root.observe("#3")
        fake = Engine(corpus, root.member_key("alice"), prekey=root.prekey())
        with pytest.raises(VerificationError):
            fake.decrypt_text(blob)


def test_another_of_the_network_message_MAC_in_fails(corpus):
    """Cross network mixing is ALREADY prevented at the MAC, not by the corpus.

    That distinction matters: a network specific corpus buys a watermark, not secrecy.
    """
    with Network.create(NetworkMode.OPEN) as a, Network.create(NetworkMode.OPEN) as b:
        ma = Engine(corpus, a.member_key("alice"), prekey=a.prekey())
        mb = Engine(corpus, b.member_key("alice"), prekey=b.prekey())
        blob = ma.encrypt_text("network A's message")
        with pytest.raises(VerificationError):
            mb.decrypt_text(blob)


# ═══════════════════════ TANITICI ═══════════════════════

def test_descriptor_round_return():
    with Network.create(NetworkMode.RESTRICTED, name="x") as net:
        back = Network.from_descriptor(net.export(owner=True))
        assert back.mode is NetworkMode.RESTRICTED
        assert back.same_as(net)


@secret_grant_needed
def test_covert_root_descriptor_has_without_outside_cannot_be_given():
    """A footgun: that descriptor gives away both the mode and the root secret."""
    with Network.create(NetworkMode.COVERT) as net:
        with pytest.raises(NetworkError, match="cannot be shared"):
            net.export()
        assert len(net.export(owner=True)) == DESCRIPTOR_BYTES


@pytest.mark.parametrize("broken", [
    b"", b"XXXX" + bytes(34), b"KAG1" + bytes(33), b"KAG1" + bytes(35),
])
def test_broken_descriptor_is_refused(broken):
    with pytest.raises(NetworkError):
        Network.from_descriptor(broken)


def test_unknown_mode_is_refused():
    with pytest.raises(NetworkError, match="unknown network mode"):
        Network.from_descriptor(b"KAG1" + bytes([1, 99]) + bytes(32))


def test_short_root_is_refused():
    with pytest.raises(NetworkError):
        Network(bytes(MIN_ROOT_BYTES - 1))


# ═══════════════════════ LIFECYCLE ═══════════════════════

@secret_grant_needed
def test_closed_network_cannot_be_used():
    net = Network.create(NetworkMode.COVERT)
    net.close()
    assert net.closed
    for call in (net.prekey, lambda: net.member_key("a"),
                 net.corpus_seed, lambda: net.child_network("#0")):
        with pytest.raises(NetworkError, match="closed"):
            call()


@secret_grant_needed
def test_repr_secret_does_not_print():
    with Network.create(NetworkMode.COVERT, name="hub") as net:
        secret = net.export(owner=True)[6:]
        text = repr(net)
        assert secret.hex() not in text
        assert "COVERT" in text and "hub" in text


# ═══════════════════════ THE NETWORK CORPUS ═══════════════════════

def test_network_corpus_deterministic(corpus):
    """Two ends must produce the same corpus without exchanging a byte."""
    with Network.create(NetworkMode.OPEN) as net:
        t = net.corpus_seed()
        assert watermark(net_corpus(t, corpus, 6)) == watermark(net_corpus(t, corpus, 6))


def test_different_networks_different_corpus_produces(corpus):
    with Network.create(NetworkMode.OPEN) as a, Network.create(NetworkMode.OPEN) as b:
        fa = watermark(net_corpus(a.corpus_seed(), corpus, 6))
        fb = watermark(net_corpus(b.corpus_seed(), corpus, 6))
        assert fa and fb and fa != fb


def test_network_corpus_base_entries_protects(corpus):
    with Network.create(NetworkMode.OPEN) as net:
        k = net_corpus(net.corpus_seed(), corpus, 6)
        assert len(k) > len(corpus)
        for e in corpus:
            assert k.get(e.id).slug == e.slug


def test_network_corpus_only_DERIVED_produces(corpus):
    """A structural entry carries unverified mathematics; it must not enter real traffic."""
    with Network.create(NetworkMode.OPEN) as net:
        k = net_corpus(net.corpus_seed(), corpus, 6)
        base_id = {e.id for e in corpus}
        for e in k:
            if e.id in base_id:
                continue
            labels = e.doc.get("tags") or []
            assert "derived" in labels
            assert "generated" not in labels


def test_network_corpus_message_can_carry(corpus):
    """A derived corpus is not decoration; it has to really encrypt and decrypt."""
    from crypto.sampler import sample

    with Network.create(NetworkMode.OPEN) as net:
        k = net_corpus(net.corpus_seed(), corpus, 6)
        new = [e for e in k if "derived" in (e.doc.get("tags") or [])]
        assert new, "no derived entry was produced"
        engine = Engine(k, net.member_key("alice"), prekey=net.prekey())
        for entry in new[:3]:
            values = sample(entry)
            back_entry, back = engine.decode(engine.encrypt(entry.id, values))
            assert back_entry.id == entry.id
            for p in entry.public_params:
                assert back[p["name"]] == values[p["name"]]


@secret_grant_needed
def test_observed_sub_network_same_corpus_produces(corpus):
    """The parent must be able to reproduce the sub network's corpus too, or it cannot read."""
    with Network.create(NetworkMode.COVERT) as root:
        alt = root.child_network("#2")
        assert (watermark(net_corpus(alt.corpus_seed(), corpus, 6))
                == watermark(net_corpus(root.observe("#2").corpus_seed(), corpus, 6)))


def test_corpus_seed_root_of_the_secret_ITSELF_not():
    """The seed has to go through HKDF: even if the Mersenne Twister state is
    compromised, there must be no way back to the root secret."""
    with Network.create(NetworkMode.OPEN) as net:
        assert net.corpus_seed() != net.export()[6:]
        assert len(net.corpus_seed()) == ROOT_BYTES


# ═══════════════════ MEASUREMENT LOCKS ═══════════════════
# The results of `layer2/network_attack.py` are locked in here.

# ─────────────── the measurement lock ───────────────
#
# WHY A WIDE BAND RATHER THAN "beats_chance"
#
# `metrics.beats_chance` uses a 95% confidence interval and it is the right
# tool: that is exactly what should stay in `network_attack.py`'s report. But
# as a HARD TEST GATE it is wrong. A test at alpha=0.05 fails on about 5% of
# runs even when the null hypothesis is TRUE. And it did: the epoch arm burned
# on one run in three with nothing having changed in the network.
#
# A flaky security test is the worst kind: the day it fails because of a REAL
# leak, someone says "that flaky test again" and moves on.
#
# So the test uses a band of plus or minus 3 standard deviations (for n=100
# the sd is about 0.05). The false alarm rate drops to about 0.3%, and a real
# distinguisher is still caught because it would come out near 1.0.

CHANCE_BAND = (0.35, 0.65)


def _at_chance(r: dict) -> None:
    alt, top = CHANCE_BAND
    assert alt <= r["accuracy"] <= top, (
        f"{r['name']}: accuracy is outside the chance band, {r['accuracy']:.3f} "
        f"(bant {alt}–{top}), AUC {r['auc']:.4f}")
    assert alt <= r["auc"] <= top, (
        f"{r['name']}: AUC is outside the chance band, {r['auc']:.4f}")


@secret_grant_needed
def test_distinguish_ability_chance_does_not_exceed():
    """The real claim: a covert child cannot be told from an open one."""
    _at_chance(network_attack.arm("real", 200, sabotage=False))


@secret_grant_needed
def test_sabotage_arm_is_caught():
    """THE CONTROL. If this fails the distinguisher is blind and the test above says nothing.

    A blind distinguisher also fails to beat chance, so "it did not beat
    chance" only means something once this test passes.
    """
    r = network_attack.arm("sabotage", 200, sabotage=True)
    # It looks at AUC, NOT at accuracy. The first version used
    # `accuracy >= 0.95` and it was fragile: on one run the AUC was 0.999
    # while accuracy dropped to 0.930. The cause was not a blind
    # distinguisher but an uncalibrated 0.5 decision threshold. A logistic
    # regression trained on few samples ranks correctly but does not
    # calibrate probabilities. A fragile CONTROL test is the worst kind: the
    # day it fails because of a genuinely blind distinguisher, someone says
    # "that flaky test again" and moves on.
    assert r["auc"] >= 0.95, (
        f"the distinguisher could not even catch a deliberately wrong derivation: "
        f"AUC {r['auc']:.4f}, accuracy {r['accuracy']:.3f}")


@secret_grant_needed
def test_positive_control_full():
    """THE CONTROL. Can the parent re-derive its sub network, which is the proof
    that covert mode works."""
    assert network_attack.positive_control(100) == 1.0


# ═══════════════════════ EPOCH ROTATION ═══════════════════════
# ADR-015 at network level: the root in the safe, an epoch on the device.

def test_epoch_deterministic_and_epochs_separate():
    """Two ends must find the same epoch without a handshake; different epochs must differ."""
    with Network.create(NetworkMode.OPEN) as net:
        assert net.epoch(5).same_as(net.epoch(5))
        assert not net.epoch(5).same_as(net.epoch(6))


def test_epoch_all_derivatives_separates():
    """When the epoch changes, P, the member keys and the corpus seed change together.

    If one stayed fixed the rotation would be half done, and silently so.
    """
    with Network.create(NetworkMode.OPEN) as net:
        d5, d6 = net.epoch(5), net.epoch(6)
        assert d5.prekey().fingerprint() != d6.prekey().fingerprint()
        assert d5.member_key("alice") != d6.member_key("alice")
        assert d5.corpus_seed() != d6.corpus_seed()


def test_epoch_root_from_the_network_also_different():
    """An epoch network must not be the root itself, or the rotation never happened."""
    with Network.create(NetworkMode.OPEN) as net:
        assert not net.epoch(0).same_as(net)


@pytest.mark.parametrize("mode", list(NetworkMode))
def test_epoch_mode_protects(mode):
    # Only the COVERT parameter needs authorisation; the other two must be
    # tested on every run. Marking the whole test would silently remove the
    # coverage of open and restricted mode too.
    if mode is NetworkMode.COVERT and not SECRET_GRANT:
        pytest.skip("no covert mode authorisation")
    with Network.create(mode) as net:
        assert net.epoch(3).mode is mode


@secret_grant_needed
def test_epoch_covert_in_mode_observation_works():
    """A covert network's epoch is covert too; the owner sees that epoch's sub networks."""
    with Network.create(NetworkMode.COVERT) as root:
        d = root.epoch(4)
        assert d.observe("#0").same_as(d.child_network("#0"))


@secret_grant_needed
def test_one_epoch_another_of_the_epoch_sub_network_cannot_see():
    """Compartmentalisation has to reach the sub networks as well."""
    with Network.create(NetworkMode.COVERT) as root:
        child4 = root.epoch(4).child_network("#0")
        assert not root.epoch(5).observe("#0").same_as(child4)


def test_epoch_from_the_network_to_the_root_no_way_back(corpus):
    """THIS IS ROTATION'S ONLY MEANING.

    If a device holds only the epoch network, whoever seizes it cannot derive
    another epoch. After the root is closed the epoch network still works, but
    no new epoch comes out of the root.
    """
    root = Network.create(NetworkMode.OPEN)
    device = root.epoch(9)
    root.close()

    # The device keeps working with its own epoch.
    engine = Engine(corpus, device.member_key("alice"), prekey=device.prekey())
    assert engine.decrypt_text(engine.encrypt_text("epoch 9")) == "epoch 9"

    # No other epoch can be derived from the root, because the root is gone.
    with pytest.raises(NetworkError, match="closed"):
        root.epoch(10)
    device.close()


def test_another_of_the_epoch_message_cannot_be_decoded(corpus):
    """The measurable consequence of compartmentalisation."""
    with Network.create(NetworkMode.OPEN) as net:
        d5, d6 = net.epoch(5), net.epoch(6)
        m5 = Engine(corpus, d5.member_key("alice"), prekey=d5.prekey())
        m6 = Engine(corpus, d6.member_key("alice"), prekey=d6.prekey())
        with pytest.raises(VerificationError):
            m6.decrypt_text(m5.encrypt_text("epoch 5 message"))


def test_root_compromise_if_it_passes_ALL_epochs_fails():
    """AN HONESTY TEST: it keeps what is NOT claimed written down too.

    Epoch rotation gives NO forward secrecy against root compromise. If this
    is one day described as forward secrecy by accident, this test shows the
    document and the code saying the same thing.
    """
    with Network.create(NetworkMode.OPEN) as net:
        history = net.epoch(1)
        # As long as S is in hand, a past epoch can be recomputed.
        assert net.epoch(1).same_as(history)


@pytest.mark.parametrize("broken", [-1, 1.5, True, "3"])
def test_invalid_epoch_is_refused(broken):
    with Network.create(NetworkMode.OPEN) as net:
        with pytest.raises(NetworkError):
            net.epoch(broken)


# ─────────────── takvim ───────────────

def test_calendar_epoch_number():
    from datetime import date

    assert epoch_number(CALENDAR_START) == 0
    assert epoch_number(date(2026, 1, 31)) == 30
    assert epoch_number(date(2026, 1, 31), days_per_epoch=30) == 1


def test_calendar_same_in_the_slice_days_same_epoch():
    """With a 30 day epoch, two days in the same month must give the same key."""
    from datetime import date

    assert (epoch_number(date(2026, 3, 2), days_per_epoch=30)
            == epoch_number(date(2026, 3, 20), days_per_epoch=30))


def test_calendar_at_the_start_before_is_refused():
    from datetime import date

    with pytest.raises(NetworkError, match="before the calendar start"):
        epoch_number(date(2025, 12, 31))


def test_calendar_invalid_length_is_refused():
    with pytest.raises(NetworkError):
        epoch_number(days_per_epoch=0)


@secret_grant_needed
def test_epoch_network_fresh_from_the_network_distinguish_cannot():
    """Rotation must not give itself away."""
    _at_chance(network_attack.arm("epoch", 200, epoch=True))


# ═══════════════════ TIMING: THE CLOCK, NOT THE BYTES ═══════════════════

@secret_grant_needed
def test_sub_network_creation_mode_THROUGH_TIMING_does_not_leak():
    """A REGRESSION TEST FOR A MEASURED LEAK.

    In the first version `child_network` ran HKDF in covert mode and
    `os.urandom` in open mode. The bytes were indistinguishable, which
    `network_attack.py` confirmed, but the TIMES were not: |t| = 121.5, noise
    floor 1.9, the covert arm 7.6 us slower.

    What that meant: a member who asked the parent for their sub network and
    measured the response delay would learn the mode. The claim that it "looks
    no different from an open network" was right in the bytes and WRONG on the clock.

    Timing tests are fragile, so instead of an absolute threshold it uses the
    floor measured in the SAME RUN and takes the best of a few runs. That is
    more than enough to catch 121.5 and does not trip on noise.
    """
    from crypto.timing import THRESHOLD, measure

    secret = Network.create(NetworkMode.COVERT)
    free = Network.create(NetworkMode.OPEN)
    free2 = Network.create(NetworkMode.OPEN)

    def _t(a, b, seed):
        return abs(measure("x", lambda net: net.child_network("#0"),
                           lambda: a, lambda: b, repeats=1500, seed=seed).t)

    signal = min(_t(secret, free, i) for i in range(3))
    base = max(_t(free, free2, i) for i in range(3))

    assert signal <= max(THRESHOLD, 3 * base), (
        f"the sub network creation mode leaks through timing: |t|={signal:.2f}, "
        f"taban={base:.2f}")


@secret_grant_needed
def test_two_arm_also_same_primitives_calls():
    """The STRUCTURAL twin of the timing test, and it does not depend on noise.

    The timing test depends on the machine; this one does not. It counts
    directly that both branches call one `os.urandom` and one HKDF. If one is
    removed, this fails even when the timing test does not.
    """
    import crypto.network as netmod

    counter = {"urandom": 0, "extract": 0, "expand": 0}
    actual_gen, actual_ex, actual_ep = (netmod.os.urandom, netmod.primitives.hkdf_extract,
                                        netmod.primitives.hkdf_expand)

    def say(name, actual):
        def spiral(*a, **k):
            counter[name] += 1
            return actual(*a, **k)
        return spiral

    netmod.os.urandom = say("urandom", actual_gen)
    netmod.primitives.hkdf_extract = say("extract", actual_ex)
    netmod.primitives.hkdf_expand = say("expand", actual_ep)
    try:
        measured = {}
        for mode in (NetworkMode.COVERT, NetworkMode.OPEN):
            net = Network.create(mode)
            for k in counter:
                counter[k] = 0
            net.child_network("#0")
            measured[mode] = dict(counter)
    finally:
        netmod.os.urandom, netmod.primitives.hkdf_extract, netmod.primitives.hkdf_expand = (
            actual_gen, actual_ex, actual_ep)

    assert measured[NetworkMode.COVERT] == measured[NetworkMode.OPEN], (
        f"the arms do different work: {measured}")
    assert measured[NetworkMode.OPEN]["urandom"] >= 1
    assert measured[NetworkMode.OPEN]["expand"] >= 1


# ═══════════════════════ COVERT MODE AUTHORISATION (ADR-029) ═══════════════════════
#
# What this section tests is a POLICY gate, not a cryptographic lock: anyone
# with the source deletes the check. What is tested is that the gate really is
# closed in this program and does not open by accident.

def test_covert_network_unauthorised_CANNOT_BE_CREATED():
    """The gate's real job. All three paths must be closed."""
    from crypto.network import deauthorise

    opened = is_authorised()
    deauthorise()
    try:
        with pytest.raises(AuthorisationError, match="requires authorisation"):
            Network.create(NetworkMode.COVERT)
        with pytest.raises(AuthorisationError, match="requires authorisation"):
            Network(bytes(32), mode=NetworkMode.COVERT)
        with pytest.raises(AuthorisationError):
            Network.from_descriptor(b"KAG1" + bytes([1, NetworkMode.COVERT.value])
                                    + bytes(32))
    finally:
        if opened:
            authorise()


def test_open_and_restricted_authorisation_DOES_NOT_NEED():
    """The gate applies only to covert mode. The other two stay open to everyone."""
    from crypto.network import deauthorise

    opened = is_authorised()
    deauthorise()
    try:
        assert Network.create(NetworkMode.OPEN).mode is NetworkMode.OPEN
        assert Network.create(NetworkMode.RESTRICTED).mode is NetworkMode.RESTRICTED
        assert Network(bytes(32)).mode is NetworkMode.OPEN
    finally:
        if opened:
            authorise()


@pytest.mark.parametrize("wrong", ["", "wrong", "0123456789", "a" * 10])
def test_wrong_password_is_refused(wrong):
    assert not password_correct(wrong)
    with pytest.raises(AuthorisationError, match="wrong covert network password"):
        Network.create(NetworkMode.COVERT, password=wrong)


@secret_grant_needed
@pytest.mark.parametrize("form", [
    lambda p: " " + p, lambda p: p + " ", lambda p: p.upper(),
    lambda p: p.lower(), lambda p: p[:-1], lambda p: p + "x",
])
def test_of_the_password_near_variants_is_refused(form):
    """Leading and trailing space, letter case, one character short or extra.

    These variants are derived AT RUNTIME rather than written into the source.
    Writing a constant like `" " + password` would have put the password into
    the source. `test_PASSWORD_SOURCE_IN_THE_TREE_PLAIN_TEXT_NOT` caught that
    on its first run and it was right.
    """
    assert not password_correct(form(os.environ[AUTH_ENV]))


@pytest.mark.parametrize("broken", [None, 123, b"bytes", []])
def test_password_not_round_is_refused(broken):
    if broken is None:
        return                       # None = "session yetkisini kullan"
    assert not password_correct(broken)


@secret_grant_needed
def test_correct_password_authorisation_gives():
    password = os.environ[AUTH_ENV]
    assert password_correct(password)
    assert Network.create(NetworkMode.COVERT, password=password).mode is NetworkMode.COVERT


@secret_grant_needed
def test_authorisation_open_close_loop():
    from crypto.network import deauthorise

    deauthorise()
    assert not is_authorised()
    with pytest.raises(AuthorisationError):
        Network.create(NetworkMode.COVERT)
    assert authorise(os.environ[AUTH_ENV])
    assert is_authorised()
    Network.create(NetworkMode.COVERT)


@secret_grant_needed
def test_authorisation_when_closed_PRESENT_network_to_run_continues_does():
    """The authorisation gate applies to CREATION, not to use.

    A network that stopped working would be both pointless and dangerous: the
    owner would lose the ability to read their own sub networks the moment they turned authorisation off.
    """
    from crypto.network import deauthorise

    g = Network.create(NetworkMode.COVERT)
    child = g.child_network("#0")
    deauthorise()
    try:
        assert g.observe("#0").same_as(child)
        assert g.epoch(2).mode is NetworkMode.COVERT   # with the internal flag
    finally:
        authorise(os.environ[AUTH_ENV])


def test_password_digest_deterministic_and_back_one_way():
    from crypto.network import AUTH_DIGEST, _password_digest

    a, b = _password_digest("sample"), _password_digest("sample")
    assert a == b and len(a) == 32
    assert _password_digest("sample") != _password_digest("sample2")
    assert a != AUTH_DIGEST


@secret_grant_needed
def test_PASSWORD_SOURCE_IN_THE_TREE_PLAIN_TEXT_NOT():
    """THE MOST IMPORTANT TEST, this gate's only real gain.

    If the password sat in the repo in plaintext it would burn the moment the
    project went on GitHub (ADR-025 chooses to keep the repo open). The gate
    has no cryptographic value, but it has THIS value, and leaving it untested would be absurd.
    """
    password = os.environ[AUTH_ENV]
    skip = {"__pycache__", ".git", ".pytest_cache", "generated_corpus",
            ".claude", "webui"}
    found = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".yaml",
                                                     ".yml", ".c", ".h",
                                                     ".txt", ".json"}:
            continue
        if any(k in path.parts for k in skip):
            continue
        try:
            if password in path.read_text(encoding="utf-8", errors="ignore"):
                found.append(str(path.relative_to(ROOT)))
        except OSError:
            pass
    assert not found, f"the password was found in plaintext: {found}"


def test_authorisation_error_the_password_DOES_NOT_PRINT():
    """An error message must not leak the secret."""
    try:
        Network.create(NetworkMode.COVERT, password="denemeParolasi123")
    except AuthorisationError as e:
        assert "denemeParolasi123" not in str(e)
    else:
        pytest.fail("a wrong password was accepted")
