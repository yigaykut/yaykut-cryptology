"""The canary trap (`crypto/canary.py`).

WHY THIS FILE EXISTS

A canary is an ACCUSATION tool. If it works wrong the result is a wrong
identification, and that is worse than silently failing to decrypt: nobody
sees an error, they just accuse the wrong person.

So three things are tested separately:

  1. Does it find THE RIGHT PERSON (not just "one suspect left").
  2. With NO observation, does it accuse nobody, the negative control.
  3. Is the LIMIT it declares really there: can two colluding traitors frame
     an innocent. This test passing does not mean "the gap is closed", it
     means "the gap is where it was measured to be".
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from layer2 import canary_experiment  # noqa: E402
from crypto.network import Network, NetworkMode  # noqa: E402
from crypto.canary import (  # noqa: E402
                           MAX_ROUNDS,
                           Canary,
                           CanaryError,
                           min_rounds,
                           suggested_rounds,
)

SEED = bytes(range(32))


def _members(n: int) -> list[str]:
    return [f"member{i:03d}" for i in range(n)]


# ═══════════════════════ KOD ATAMA ═══════════════════════

def test_codes_deterministic():
    """Two ends have to compute the codes without distributing them."""
    a = Canary(_members(8), SEED)
    b = Canary(_members(8), SEED)
    assert all(a.code(u) == b.code(u) for u in a.members)


def test_code_assignment_list_from_the_order_INDEPENDENT():
    """The same member set given in a different order must give the same codes.

    If it depended on order, two ends holding the list differently would
    silently compute different codes and the identification would be wrong.
    """
    members = _members(10)
    mixed = list(members)
    random.Random(0).shuffle(mixed)
    a, b = Canary(members, SEED), Canary(mixed, SEED)
    assert all(a.code(u) == b.code(u) for u in members)


def test_codes_unique():
    k = Canary(_members(64), SEED)
    codes = [k.code(u) for u in k.members]
    assert len(set(codes)) == len(codes)


def test_different_seed_different_code():
    a = Canary(_members(8), SEED)
    b = Canary(_members(8), bytes(32))
    assert any(a.code(u) != b.code(u) for u in a.members)


def test_code_length_round_count_as():
    k = Canary(_members(8), SEED, rounds=12)
    assert all(len(k.code(u)) == 12 for u in k.members)


def test_network_with_the_secret_is_created():
    """A canary has to be able to feed off the network secret, with no separate key distribution."""
    with Network.create(NetworkMode.OPEN) as net:
        k = Canary(_members(6), net.member_key("canary"))
        assert len({k.code(u) for u in k.members}) == 6


# ═══════════════════════ DARALTMA ═══════════════════════

def test_full_observation_CORRECT_person_gives():
    """"One suspect left" is not enough; it has to be the right person."""
    k = Canary(_members(32), SEED)
    for traitor in k.members:
        code = k.code(traitor)
        s = k.narrow({t: code[t] for t in range(k.round_count)})
        assert s.identified and s.suspects == [traitor]


def test_partial_observation_traitor_IN_THE_SET_holds():
    """A traitor may not leak every round. The set narrows but does not lose them."""
    k = Canary(_members(32), SEED)
    traitor = "member013"
    code = k.code(traitor)
    for round_count in (1, 2, 4, 8):
        s = k.narrow({t: code[t] for t in range(round_count)})
        assert traitor in s.suspects
        assert s.consistent


def test_observation_as_it_rises_uncertainty_shrinks():
    k = Canary(_members(64), SEED)
    code = k.code("member007")
    previous = float("inf")
    for n in (1, 3, 6, 12):
        bit = k.narrow({t: code[t] for t in range(n)}).bits_left
        assert bit <= previous
        previous = bit
    assert previous == 0.0


def test_observation_WITHOUT_nobody_is_not_accused():
    """THE NEGATIVE CONTROL. Narrowing without observation means a fabricated result."""
    k = Canary(_members(16), SEED)
    s = k.narrow({})
    assert len(s.suspects) == 16
    assert s.consistent and not s.identified
    assert s.bits_left == pytest.approx(s.bits_start)


def test_inconsistent_observation_INCONSISTENT_says():
    """A sequence matching no code says the single traitor assumption is wrong."""
    k = Canary(_members(8), SEED)
    code = list(k.code("member003"))
    for t in range(len(code)):
        code[t] ^= 1                       # flip every bit
    s = k.narrow({t: code[t] for t in range(k.round_count)})
    assert not s.consistent
    assert s.suspects == []
    assert "INCONSISTENT" in str(s)


# ═══════════════════════ DISTRIBUTION ═══════════════════════

def test_distribution_every_to_the_member_variant_gives():
    k = Canary(_members(10), SEED)
    d = k.distribution(0)
    assert set(d.variant) == set(k.members)
    assert set(d.variant.values()) <= {0, 1}
    assert sorted(d.group(0) + d.group(1)) == sorted(k.members)


def test_distribution_of_the_round_bit_traces():
    k = Canary(_members(10), SEED)
    for t in range(k.round_count):
        d = k.distribution(t)
        assert all(d.variant[u] == k.code(u)[t] for u in k.members)


def test_one_one_to_everyone_separate_variant():
    k = Canary(_members(7), SEED)
    d = k.one_to_one()
    assert len(set(d.variant.values())) == 7


def test_distributions_all_rounds_covers():
    k = Canary(_members(5), SEED)
    assert [d.round for d in k.distributions()] == list(range(k.round_count))


# ═══════════════════════ COLLUSION, THE DECLARED LIMIT ═══════════════════════

def test_collusion_weakness_traitors_outward():
    k = Canary(_members(20), SEED, rounds=10)
    victims = k.collusion_exposure("member000", "member001")
    assert "member000" not in victims and "member001" not in victims


def test_collusion_victims_SHARED_in_bits_matches():
    """The marking assumption: traitors can only change the rounds where they differ.

    They cannot produce a code disagreeing on their shared bits, and the
    victim list has to follow that rule.
    """
    k = Canary(_members(30), SEED, rounds=8)
    a, b = "member000", "member001"
    ka, kb = k.code(a), k.code(b)
    shared = {i: ka[i] for i in range(k.round_count) if ka[i] == kb[i]}
    for victim in k.collusion_exposure(a, b):
        code = k.code(victim)
        assert all(code[i] == v for i, v in shared.items())


def test_few_rounds_collusion_POSSIBLE_many_rounds_hard():
    """It shows the limit really is where it is said to be.

    This test does not say "the gap is closed"; it pins that the gap thins
    out with the round count and where the default margin comes from.
    """
    few = Canary(_members(40), SEED, rounds=min_rounds(40))
    many = Canary(_members(40), SEED)          # the default margin
    assert few.worst_collusion()[0] > many.worst_collusion()[0]


def test_default_margin_collusion_ONE_lowers():
    """The default `COLLISION_MARGIN` was chosen by measurement and does NOT reach zero.

    The first version of this test expected `== 0` and it failed, correctly.
    The experiment tool was sampling RANDOM pairs and reporting "0% framing",
    while `worst_collusion`, which scans every pair, was finding a gap. With
    50 members there are 1225 pairs and hitting the worst in 200 trials is unlikely.

    A real attacker CHOOSES their pair rather than drawing one. What the
    default margin gives is not "zero" but "the worst pair can frame at most
    one innocent". Anyone wanting zero uses `build_safe`.
    """
    most, _ = Canary(_members(50), SEED).worst_collusion()
    assert most <= 1, (
        f"at the default margin {most} innocents can be framed; "
        f"COLLISION_MARGIN needs remeasuring")


def test_safe_create_collusion_gap_CLOSES():
    """The constructor that is not satisfied with the average: it scans down to zero."""
    k = Canary.build_safe(_members(50), SEED)
    assert k.is_safe()
    assert k.worst_collusion() == (0, None)
    # The cost is rounds; it has to be dearer than the default, or the
    # default was already safe and this constructor would have no reason to exist.
    assert k.round_count > Canary(_members(50), SEED).round_count


def test_safe_open_with_False():
    few = Canary(_members(40), SEED, rounds=min_rounds(40))
    assert not few.is_safe()


def test_safe_create_impossible_error_gives():
    with pytest.raises(CanaryError, match="collusion hole did not close"):
        Canary.build_safe(_members(40), SEED, limit=12)


def test_of_the_accusation_fabricability_is_auditable():
    """The function that turns a silent gap into an AUDITABLE one.

    When an identification comes out, the question "could two people have
    fabricated this" has to be answerable, or a wrong accusation stands quietly.
    """
    k = Canary(_members(50), SEED)
    most, pair = k.worst_collusion()
    if most == 0:
        pytest.skip("nobody can be framed under this seed")
    victim = k.collusion_exposure(*pair)[0]
    pairs = k.possible_framers(victim)
    assert tuple(sorted(pair)) in [tuple(sorted(x)) for x in pairs]
    assert all(victim not in x for x in pairs)


def test_safe_on_creation_no_accusation_cannot_be_fabricated():
    k = Canary.build_safe(_members(30), SEED)
    assert all(not k.possible_framers(x) for x in k.members)


# ═══════════════════════ ROUND COUNT ═══════════════════════

@pytest.mark.parametrize("n, expected", [(2, 1), (3, 2), (4, 2), (5, 3),
                                        (16, 4), (17, 5), (500, 9)])
def test_minimum_rounds_log2(n, expected):
    assert min_rounds(n) == expected


def test_recommended_round_sub_of_the_bound_over():
    for n in (2, 10, 100, 1000):
        assert suggested_rounds(n) > min_rounds(n)


def test_recommended_round_to_the_ceiling_catches():
    assert suggested_rounds(2 ** 60) <= MAX_ROUNDS


def test_insufficient_round_is_refused():
    """3 rounds cannot separate 16 members; it has to raise rather than collide silently."""
    with pytest.raises(CanaryError, match="cannot tell"):
        Canary(_members(16), SEED, rounds=3)


# ═══════════════════════ INPUT VALIDATION ═══════════════════════

@pytest.mark.parametrize("members", [[], ["one"], ["a", "a"]])
def test_broken_member_list_is_refused(members):
    with pytest.raises(CanaryError):
        Canary(members, SEED)


@pytest.mark.parametrize("seed", [b"", bytes(15), "metin"])
def test_broken_seed_is_refused(seed):
    with pytest.raises(CanaryError):
        Canary(_members(4), seed)


@pytest.mark.parametrize("round", [-1, 99, "0", True])
def test_broken_round_is_refused(round):
    k = Canary(_members(4), SEED)
    with pytest.raises(CanaryError):
        k.distribution(round)


def test_broken_observation_is_refused():
    k = Canary(_members(4), SEED)
    for broken in ({0: 2}, {0: -1}, {999: 0}, {-1: 0}):
        with pytest.raises(CanaryError):
            k.narrow(broken)
    with pytest.raises(CanaryError):
        k.narrow([(0, 1)])


def test_member_of_the_non_code_cannot_be_asked():
    k = Canary(_members(4), SEED)
    with pytest.raises(CanaryError, match="not a member"):
        k.code("stranger")


# ═══════════════════════ MEASUREMENT LOCKS ═══════════════════════

def test_experiment_negative_control_passes():
    """No result is fabricated without observation, the precondition for the other arms."""
    r = canary_experiment.arm_negative(20, 30, random.Random(0))
    assert r["all_members_suspect"] == 1.0


def test_experiment_full_on_a_leak_identification_full():
    r = canary_experiment.arm_single_traitor(20, 30, random.Random(0), fraction=1.0)
    assert r["fully_identified"] == 1.0
    assert r["inconsistent"] == 0.0


def test_experiment_partial_on_a_leak_even_narrows():
    """A traitor leaking in half the rounds must still be narrowed down considerably."""
    r = canary_experiment.arm_single_traitor(50, 30, random.Random(0), fraction=0.5)
    assert r["avg_suspects"] < 2.0


def test_experiment_worst_collusion_reports():
    """The experiment tool must not settle for the average; the real measure is the worst pair."""
    r = canary_experiment.arm_worst_collusion(50, 20, random.Random(0))
    assert "worst" in r and "clean_setups" in r
    assert r["worst"] >= 0
