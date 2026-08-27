"""Canary traps: narrowing down a leaker with marked variants.

The scenario this implements:

  "There is a spy in the network. You set up a separate key with every member,
   then gave each of them different information, say a location. If the person
   at a particular location is eliminated, you know who the spy is."

This module is the mechanism for that. It is called a canary trap, or a barium
meal, and its digital counterpart is traitor tracing.

There are two regimes.

One to one: n members get n different variants. The leaked variant names the
person directly. Simple but expensive, since 500 members means inventing 500
separate plausible pieces of false information.

Group testing, which is the real gain: every member is assigned a binary
codeword. In each round members split in two by that round's bit, one group
gets variant 0 and the other variant 1. The leaked variant reveals that
round's bit. As rounds accumulate the codeword fills in and one person is
left. For 500 members each round needs only two variants, and the theoretical
lower bound on identification is ceil(log2 500) = 9 rounds.

What it gives:

  - finding one person out of n with two variants per round
  - working with partial observations. A traitor may not leak every round;
    the suspect set narrows with whatever rounds you have, and the remaining
    uncertainty is reported in bits
  - visible inconsistency. An observation sequence matching no member says
    the single traitor assumption is wrong

What it does not give, and this is the important part.

It is NOT collusion resistant. Two traitors comparing codewords can see which
bits are their own, construct a codeword neither of them holds, and frame an
innocent member. Concretely: if A holds 0011 and B holds 0110, together they
can also produce 0010 and 0111, and whoever holds that code gets accused.

Four tools make the risk visible rather than closing it:

    collusion_exposure(a, b)     who this pair could frame
    is_safe()                    can any pair frame anyone (scans all pairs)
    build_safe(...)              adds rounds until no pair can
    possible_framers(x)          if x is accused, who could have faked it

The last one is the most useful: when a diagnosis comes out, whether the
accusation could have been manufactured is testable. A silent hole becomes an
auditable one.

None of them see a three way collusion. The real fix is Boneh-Shaw or Tardos
codes, which resist k way collusion at the cost of much longer codewords, and
they are out of scope here.

It is not a cryptographic guarantee. It produces no proof, it narrows
suspicion, and it cannot tell whether a leak came from a traitor or by some
other route.

It does not generate content. It says which member gets which VARIANT; the
variants themselves, the fake location or fake date, are invented by a human.
Plausibility is not something this module can solve.

Codewords are keyed and random rather than sequential. Writing member 5 as
0101 would also work, but sequential codes differ from their neighbours in a
single bit, which means the innocent people two traitors could frame are
exactly their neighbours, making the collusion attack as easy as possible.
With keyed codes a traitor cannot derive anyone else's code from their own.

The codes derive from the network secret, so they never need distributing;
both ends compute them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from . import primitives
from .errors import CryptoError

INFO_CODE = b"kripto/v5/kanarya/kod"

# Collision and collusion margin. For r bits and n members the birthday
# collision probability is about n^2/2^(r+1), and r = 2*log2(n) + MARGIN puts
# that at roughly 2^-MARGIN. Collusion, not collision, is what really decides
# the value: across the ~r/2 rounds where two traitors differ, an innocent
# person's code matching has probability 2^(-r/2).
#
# The value was chosen by measurement, not feel
# (`layer2/canary_experiment.py --sweep`, 50 members):
#
#     margin  rounds  framing
#          0      12      58%
#          8      20      10%
#         16      28       0%
#         24      36       0%
#
# It reaches zero at 16, and the default sits one step further, because a 0%
# from a limited sample is not proof. The cost is explicit: 36 rounds means 36
# separate rounds of false information. A cheaper setup can give up the margin
# with `rounds=`, and the table above shows what that gives up.
COLLISION_MARGIN = 24
MAX_ROUNDS = 128


class CanaryError(CryptoError):
    """Invalid canary setup or observation."""


@dataclass(frozen=True)
class Distribution:
    """One round's distribution: which member gets which variant."""

    round: int
    variant: dict[str, int]

    def group(self, no: int) -> list[str]:
        """Members receiving variant `no`."""
        return [m for m, v in self.variant.items() if v == no]

    def __str__(self) -> str:
        a, b = len(self.group(0)), len(self.group(1))
        return f"round {self.round}: variant0={a} people, variant1={b} people"


@dataclass
class Result:
    """The suspect set derived from observations."""

    suspects: list[str]
    consistent: bool
    rounds_observed: int
    rounds_total: int
    member_count: int

    @property
    def bits_left(self) -> float:
        """Remaining uncertainty across the suspects, in bits."""
        return math.log2(len(self.suspects)) if self.suspects else 0.0

    @property
    def bits_start(self) -> float:
        return math.log2(self.member_count)

    @property
    def identified(self) -> bool:
        return self.consistent and len(self.suspects) == 1

    def __str__(self) -> str:
        if not self.consistent:
            return ("INCONSISTENT: no member's code matches these "
                    "observations. The single traitor assumption is wrong, "
                    "through collusion or noise.")
        if self.identified:
            return f"ONE SUSPECT: {self.suspects[0]}"
        return (f"{len(self.suspects)} suspects left "
                f"({self.bits_start:.2f} bits -> {self.bits_left:.2f} bits)")


def suggested_rounds(member_count: int, *,
                     margin: int = COLLISION_MARGIN) -> int:
    """A round count leaving room for collision and collusion margin.

    The lower bound `min_rounds` (ceil(log2 n)) is only enough to identify
    someone and leaves no margin for either. The default is twice that plus a
    fixed margin.
    """
    if member_count < 2:
        raise CanaryError("a canary needs at least two members")
    return min(MAX_ROUNDS, 2 * min_rounds(member_count) + margin)


def min_rounds(member_count: int) -> int:
    """The theoretical lower bound for identification: ceil(log2 n).

    That many rounds can tell n people apart but leaves no margin at all; a
    single missed observation doubles the suspect set.
    """
    if member_count < 2:
        raise CanaryError("a canary needs at least two members")
    return max(1, math.ceil(math.log2(member_count)))


class Canary:
    """A canary trap layout for a set of members.

        canary = Canary(["alice", "bob", "can"], network.member_key("canary"))
        for d in canary.distributions():
            print(d)                        # who gets which variant
        result = canary.narrow({0: 1, 2: 0})   # the variants that leaked
    """

    __slots__ = ("_members", "_round_count", "_codes", "_masks", "_full_mask")

    def __init__(self, members: list[str], seed: bytes, *,
                 rounds: int | None = None) -> None:
        if not isinstance(members, (list, tuple)) or len(members) < 2:
            raise CanaryError("at least two members are required")
        if len(set(members)) != len(members):
            raise CanaryError("member names must be unique")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) < 16:
            raise CanaryError("the seed must be at least 16 bytes")

        self._members = list(members)
        n = len(self._members)
        self._round_count = rounds if rounds is not None else suggested_rounds(n)
        if not isinstance(self._round_count, int) or self._round_count < 1:
            raise CanaryError("round count must be a positive integer")
        if self._round_count > MAX_ROUNDS:
            raise CanaryError(f"round count can be at most {MAX_ROUNDS}")
        if 2 ** self._round_count < n:
            raise CanaryError(
                f"{self._round_count} rounds cannot tell {n} members apart; "
                f"at least {min_rounds(n)} are needed (2^rounds >= members)")

        self._codes = self._assign_codes(bytes(seed))
        self._full_mask = (1 << self._round_count) - 1
        self._masks = {m: sum(b << i for i, b in enumerate(c))
                       for m, c in self._codes.items()}

    # ─────────────────────── code assignment ───────────────────────

    def _assign_codes(self, seed: bytes) -> dict[str, tuple[int, ...]]:
        """A keyed, unique codeword for every member.

        Assignment walks the names in SORTED order so the order the list was
        given in does not change the result: the same member set always gets
        the same codes. On a collision only the colliding member's counter
        advances, leaving everyone else's code intact.
        """
        codes: dict[str, tuple[int, ...]] = {}
        taken: set[tuple[int, ...]] = set()
        prk = primitives.hkdf_extract(salt=b"", ikm=seed)

        for member in sorted(self._members):
            raw = member.encode("utf-8")
            for counter in range(256):
                bits = self._make_bits(prk, raw, counter)
                if bits not in taken:
                    codes[member] = bits
                    taken.add(bits)
                    break
            else:  # pragma: no cover - 256 collisions is not reachable
                raise CanaryError(
                    f"{member}: no unique code found in 256 attempts; the "
                    f"round count is far too small for this member count")
        return codes

    def _make_bits(self, prk: bytes, member: bytes,
                   counter: int) -> tuple[int, ...]:
        n = (self._round_count + 7) // 8
        raw = primitives.hkdf_expand(
            prk, INFO_CODE + counter.to_bytes(2, "big") + member, n)
        value = int.from_bytes(raw, "big")
        return tuple((value >> i) & 1 for i in range(self._round_count))

    # ─────────────────────── use ───────────────────────

    @property
    def members(self) -> list[str]:
        return list(self._members)

    @property
    def round_count(self) -> int:
        return self._round_count

    def code(self, member: str) -> tuple[int, ...]:
        """A member's codeword. Derived from the network secret, never sent."""
        try:
            return self._codes[member]
        except KeyError:
            raise CanaryError(
                f"{member!r} is not a member of this canary") from None

    def one_to_one(self) -> Distribution:
        """n members, n different variants: identification in one round.

        Expensive, since it needs n separate plausible fakes. Group testing
        does the same job with two variants per round, at the cost of needing
        several rounds.
        """
        return Distribution(round=-1,
                            variant={m: i for i, m
                                     in enumerate(self._members)})

    def distribution(self, round_no: int) -> Distribution:
        """One round's distribution, splitting members by that round's bit."""
        if not isinstance(round_no, int) or isinstance(round_no, bool) \
                or not 0 <= round_no < self._round_count:
            raise CanaryError(
                f"round must be in 0..{self._round_count - 1}, "
                f"got {round_no!r}")
        return Distribution(
            round=round_no,
            variant={m: self._codes[m][round_no] for m in self._members})

    def distributions(self) -> list[Distribution]:
        return [self.distribution(t) for t in range(self._round_count)]

    def narrow(self, observations: dict[int, int]) -> Result:
        """Derive the suspect set from the observed variants.

        `observations` maps round to the variant seen leaking. It does not
        have to cover every round, since a traitor may not leak each time.
        Missing rounds increase the uncertainty but do not invalidate the
        result.
        """
        if not isinstance(observations, dict):
            raise CanaryError("observations must be a {round: variant} dict")
        for round_no, variant in observations.items():
            if not isinstance(round_no, int) \
                    or not 0 <= round_no < self._round_count:
                raise CanaryError(f"invalid round: {round_no!r}")
            if variant not in (0, 1):
                raise CanaryError(
                    f"round {round_no}: variant must be 0 or 1, "
                    f"got {variant!r}")

        suspects = [
            m for m in self._members
            if all(self._codes[m][t] == v for t, v in observations.items())
        ]
        return Result(suspects=suspects, consistent=bool(suspects),
                      rounds_observed=len(observations),
                      rounds_total=self._round_count,
                      member_count=len(self._members))

    # ─────────────────────── honesty tools ───────────────────────

    def collusion_exposure(self, a: str, b: str) -> list[str]:
        """Which innocent members `a` and `b` together could accuse.

        Two traitors can only mix the bits they hold: in rounds where they
        differ they can produce either value, and in rounds where they agree
        they must produce that value. The returned list is the third parties
        holding codewords they could construct.

        An empty list is not a guarantee. It only says this particular pair
        has nobody to frame.
        """
        # The codewords they could build number 2^(differing rounds), so
        # instead of constructing them all, scanning member codes and keeping
        # the ones that match on the FIXED rounds is cheaper and gives the
        # same answer.
        #
        # Codes are also kept as integer masks, which reduces "does it match
        # on all shared rounds" to one XOR and AND. With a plain Python loop
        # `is_safe` took minutes at 50 members.
        ia, ib = self._masks[a], self._masks[b]
        shared = ~(ia ^ ib) & self._full_mask
        return sorted(m for m, mask in self._masks.items()
                      if m not in (a, b) and not (mask ^ ia) & shared)

    def worst_collusion(self) -> tuple[int, tuple[str, str] | None]:
        """Find the pair that could frame the most innocent members.

        Reduces how exposed the setup is to a single number. It is O(n^2) and
        expensive for large member counts; it is a measurement tool, not a hot
        path.
        """
        most, pair = 0, None
        for i, a in enumerate(self._members):
            for b in self._members[i + 1:]:
                k = len(self.collusion_exposure(a, b))
                if k > most:
                    most, pair = k, (a, b)
        return most, pair

    def is_safe(self) -> bool:
        """Whether no pair at all can frame anyone, verified by scanning.

        Counting rather than guessing: it looks at every pair. `True` means
        the collusion hole is closed for this member set and this seed. It
        must be rechecked if the member list changes.
        """
        for i, a in enumerate(self._members):
            for b in self._members[i + 1:]:
                if self.collusion_exposure(a, b):
                    return False       # stop at the first hole, no count needed
        return True

    @classmethod
    def build_safe(cls, members: list[str], seed: bytes, *,
                   step: int = 8, limit: int = MAX_ROUNDS) -> "Canary":
        """Add rounds until the collusion hole closes.

        `Canary(...)` uses the default margin, which protects the average
        case, while the worst pair can still frame one or two innocents. This
        constructor does not settle for the average; it scans down to zero.

        The cost is explicit: for 50 members the default 36 rounds is enough,
        while this can reach around 60, meaning twice as many rounds of false
        information to invent. Cheap is not safe, so the choice is left to the
        caller, with both options measured.
        """
        c = cls(members, seed)
        while not c.is_safe():
            more = c.round_count + step
            if more > limit:
                raise CanaryError(
                    f"the collusion hole did not close even at {limit} rounds "
                    f"({len(members)} members). Either split the member set or "
                    f"move to Boneh-Shaw / Tardos codes.")
            c = cls(members, seed, rounds=more)
        return c

    def possible_framers(self, accused: str) -> list[tuple[str, str]]:
        """Could this accusation have been manufactured, and by whom.

        This turns the canary's lack of collusion resistance from a silent
        hole into an auditable one: when a diagnosis comes out, the traitor
        pairs that could have produced it are listed.

        An empty list means two people could not have faked the accusation. A
        three way collusion is still possible and this function does not see
        it.
        """
        self.code(accused)                      # membership check
        return [(a, b)
                for i, a in enumerate(self._members)
                for b in self._members[i + 1:]
                if a != accused and b != accused
                and accused in self.collusion_exposure(a, b)]

    def __repr__(self) -> str:
        return (f"<Canary {len(self._members)} members, {self._round_count} "
                f"rounds (lower bound {min_rounds(len(self._members))})>")
