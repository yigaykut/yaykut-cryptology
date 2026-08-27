"""Does the canary trap really find the leaker, and does it accuse the innocent.

`crypto/canary.py` claims two things: a lone traitor is found, and two
traitors colluding can frame an innocent. Both get measured.

FOUR ARMS

  1. ONE TRAITOR, FULL LEAK   A lone traitor leaking every round. Expected:
                              100% full identification. Failing means the
                              mechanism is broken.

  2. ONE TRAITOR, PARTIAL     A traitor leaking in only some of the rounds.
                              It measures how far the suspect set narrows,
                              which is what happens in real life.

  3. TWO TRAITORS (COLLUSION) Two traitors mix their codes and try to
                              produce an innocent's codeword. TWO measures
                              are given at once: a RANDOM pair (the average
                              case) and THE WORST OF ALL PAIRS. The real
                              measure is the second, because a real attacker
                              CHOOSES their pair rather than drawing one at
                              random. Zero is not expected; the job here is
                              turning the weakness into a number.

  4. NEGATIVE CONTROL         A "traitor" who never leaks. The suspect set
                              must stay ALL members. If it narrows, the
                              mechanism is inventing a result without any
                              observation, and none of the other arms hold.

    python -m layer2.canary_experiment --member 50 --trial 400
"""

from __future__ import annotations

import argparse
import os
import random

from crypto.canary import Canary, min_rounds, suggested_rounds


def _members(n: int) -> list[str]:
    return [f"member{i:04d}" for i in range(n)]


def _canary(n: int, pay: int | None, round: int | None) -> Canary:
    members = _members(n)
    t = round if round is not None else suggested_rounds(n, margin=pay) \
        if pay is not None else None
    return Canary(members, os.urandom(32), rounds=t)


# ══════════════════════ arms ══════════════════════

def arm_single_traitor(n: int, trial: int, rng: random.Random,
                       *, fraction: float = 1.0, pay: int | None = None) -> dict:
    """A lone traitor leaking in `fraction` of the rounds."""
    exact, total_suspicion, inconsistent = 0, 0, 0
    for _ in range(trial):
        k = _canary(n, pay, None)
        traitor = rng.choice(k.members)
        code = k.code(traitor)
        rounds = [t for t in range(k.round_count) if rng.random() < fraction]
        result = k.narrow({t: code[t] for t in rounds})

        if not result.consistent:
            inconsistent += 1
            continue
        total_suspicion += len(result.suspects)
        # Full identification only counts if it leaves the RIGHT person alone.
        exact += int(result.identified and result.suspects[0] == traitor)

    return {"fully_identified": exact / trial,
            "avg_suspects": total_suspicion / max(1, trial - inconsistent),
            "inconsistent": inconsistent / trial}


def arm_collusion(n: int, trial: int, rng: random.Random,
                  *, pay: int | None = None) -> dict:
    """Can two traitors frame an innocent.

    Traitors can only mix the bits THEY HOLD: in rounds where they differ
    they can produce either value, and in rounds where they agree they have
    to produce that value (the marking assumption).
    """
    could_frame, tried, target_count = 0, 0, 0
    for _ in range(trial):
        k = _canary(n, pay, None)
        a, b = rng.sample(k.members, 2)
        victims = k.collusion_exposure(a, b)
        target_count += len(victims)
        tried += 1
        if not victims:
            continue

        # The traitors pick a victim and produce that person's code.
        victim = rng.choice(victims)
        fake = k.code(victim)
        result = k.narrow({t: fake[t] for t in range(k.round_count)})
        # Framing counts as SUCCESSFUL only if the innocent is the ONLY suspect.
        could_frame += int(
            result.identified and result.suspects[0] == victim)

    return {"framing": could_frame / tried,
            "avg_victims": target_count / tried}


def arm_worst_collusion(n: int, trial: int, rng: random.Random,
                        *, pay: int | None = None) -> dict:
    """How many innocents the WORST pair can frame.

    WHY THIS IS A SEPARATE ARM, and why it is the real measure

    `kol_birlesme` picks a RANDOM pair and that is misleading: with 50
    members there are 1225 pairs, and hitting the worst in 200 trials is
    unlikely. The first run reported "0% framing", while `worst_collusion`,
    which scans every pair on the same setup, was finding a gap.

    A real attacker CHOOSES their pair. The average case is not what they
    face; the worst case is the right measure.
    """
    worst, zero = 0, 0
    for _ in range(trial):
        k = _canary(n, pay, None)
        v = k.worst_collusion()[0]
        worst = max(worst, v)
        zero += int(v == 0)
    return {"worst": worst, "clean_setups": zero / trial}


def arm_negative(n: int, trial: int, rng: random.Random,
                 *, pay: int | None = None) -> dict:
    """No leak at all. The suspect set must stay ALL members."""
    correct = 0
    for _ in range(trial):
        k = _canary(n, pay, None)
        result = k.narrow({})
        correct += int(len(result.suspects) == n and result.consistent)
    return {"all_members_suspect": correct / trial}


# ══════════════════════ margin sweep ══════════════════════

def share_sweep(n: int, trial: int, rng: random.Random,
                shares: tuple[int, ...]) -> list[tuple[int, int, float, float]]:
    """How much framing thins out as the round count rises.

    It exists so the default margin is chosen from data. Rather than saying
    "make it large", it measures what each additional round buys.
    """
    lines = []
    for pay in shares:
        t = suggested_rounds(n, margin=pay)
        b = arm_collusion(n, trial, rng, margin=pay)
        lines.append((pay, t, b["framing"], b["avg_victims"]))
    return lines


# ══════════════════════ report ══════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--member", type=int, default=50)
    ap.add_argument("--trial", type=int, default=200)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--sweep", action="store_true",
                    help="run the margin sweep (the reasoning for the default)")
    a = ap.parse_args()

    if a.member < 2:
        print("  --member must be at least 2")
        return 2

    rng = random.Random(a.seed)
    n = a.member
    k0 = Canary(_members(n), bytes(32))

    print(f"\n  CANARY TRAP: {n} members, {a.trial} trials per arm")
    print(f"  {k0.round_count} rounds (the lower bound for identification is "
          f"{min_rounds(n)}, the rest is margin for collision and collusion)\n")

    neg = arm_negative(n, a.trial, rng)
    exact = arm_single_traitor(n, a.trial, rng, fraction=1.0)
    half = arm_single_traitor(n, a.trial, rng, fraction=0.5)
    few = arm_single_traitor(n, a.trial, rng, fraction=0.25)
    one = arm_collusion(n, a.trial, rng)
    bad = arm_worst_collusion(n, max(20, a.trial // 5), rng)

    print(f"  {'arm':<34}{'result':>10}")
    print(f"  {'-' * 52}")
    print(f"  {'negative control (no leak at all)':<34}"
          f"{neg['all_members_suspect']:>9.0%}  every member a suspect")
    print(f"  {'one traitor, leaking every round':<34}"
          f"{exact['fully_identified']:>9.0%}  fully identified")
    print(f"  {'one traitor, in 50% of rounds':<34}"
          f"{half['fully_identified']:>9.0%}  fully identified "
          f"({half['avg_suspects']:.2f} suspects on average)")
    print(f"  {'one traitor, in 25% of rounds':<34}"
          f"{few['fully_identified']:>9.0%}  fully identified "
          f"({few['avg_suspects']:.2f} suspects on average)")
    print(f"  {'two traitors, RANDOM pair':<34}"
          f"{one['framing']:>9.0%}  could frame someone "
          f"(avg. {one['avg_victims']:.2f} victims)")
    print(f"  {'TWO TRAITORS, WORST PAIR':<34}"
          f"{bad['worst']:>9d}  innocents can be framed "
          f"({bad['clean_setups']:.0%} of setups clean)")

    if a.sweep:
        print(f"\n  MARGIN SWEEP: framing against round count")
        print(f"  {'margin':>7}{'rounds':>8}{'framing':>10}{'avg victims':>14}")
        print(f"  {'-' * 39}")
        for pay, t, c, victim in share_sweep(
                n, max(50, a.trial // 4), rng, (0, 8, 16, 24, 32, 48)):
            print(f"  {pay:>5}{t:>6}{c:>13.0%}{victim:>14.2f}")

    print()
    error = 0

    if neg["all_members_suspect"] < 1.0:
        print("  x THE NEGATIVE CONTROL FAILED. With no observation the suspect")
        print("    set narrows, so the mechanism invents results. The other arms are void.")
        error = 1
    else:
        print("  + negative control: with no observation nobody is a suspect")

    if exact["fully_identified"] < 1.0:
        print(f"  x IDENTIFICATION INCOMPLETE ON A FULL LEAK ({exact['fully_identified']:.0%}).")
        print("    A traitor leaking every round should always have been found.")
        error = 1
    else:
        print("  + a traitor leaking every round is found 100% of the time")

    if bad["worst"] > 0:
        print(f"  ! THE COLLUSION GAP WAS MEASURED: the worst pair can frame {bad['worst']}")
        print(f"    innocents (in {bad['clean_setups']:.0%} of setups no one "
              f"was framed).")
        print("    That is NOT A BUG, it is the limit the module declares. To close")
        print("    it, `Canary.build_safe(...)` scans down to zero, at the cost of")
        print("    more rounds. A THREE way collusion is still out of scope; the")
        print("    answer for that is Boneh-Shaw or Tardos codes.")
    else:
        print("  + no pair could frame an innocent (every pair was scanned)")

    print()
    return error


if __name__ == "__main__":
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
