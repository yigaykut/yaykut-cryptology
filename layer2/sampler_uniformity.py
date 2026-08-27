"""Does the sampler distribute uniformly, the "partial" item in `docs/audit.md` §5.

SORU

`crypto/sampler.py` produces values satisfying the constraints, and that it
WORKS has been tested (34 of 34 entries sample, ADR-006). What has not been
tested is the DISTRIBUTION: are the values uniform across the valid space, or
do they pile up in a corner?

WHY IT MATTERS

What is measured is not plaintext secrecy. The payload is already masked with
the keystream, and non uniform plaintext is not readable without the key. The
real risk is in the DECOY CHAIN (ADR-012), where decoy records come from the
sampler. If the sampler's distribution departs systematically from real usage,
a statistic separating decoys from the real record appears and the whole point
kaybolur.

THE EXPECTED ANSWER, and knowing it already does not make the measurement pointless

`sample` has three stages:

  1. BOUND INFERENCE     Narrows the range. Uniform sampling within a
                         narrowed range IS STILL UNIFORM.
  2. EQUALITY SOLVING    Seeing `a + b == c` it COMPUTES c. That CANNOT be
                         uniform: if a and b are uniform, a+b is triangular.
  3. REJECTION SAMPLING  Uniform over the valid set, since rejection
                         sampling by definition gives conditional uniformity.

TWO LEGITIMATE SOURCES OF NON UNIFORMITY

The first version said "every skew not solved by an equality is a defect" and
reported 17 parameters as defects. That was wrong, its premise was faulty:

  * REJECTION SAMPLING IS UNIFORM over the JOINT valid set. The MARGINAL of a
    parameter coupled to others through constraints is generally NOT uniform,
    and does not need to be. If `p` has to be prime, p's marginal cannot be
    uniform.

  * THE BUCKET COUNT HAS TO MATCH THE RANGE. `block_size` takes only the
    values 2 to 8, so with 16 buckets 9 are necessarily empty and chi-square
    calls it "skewed". The measurement's own bug was being reported as a finding.

That leaves ONE meaningful question: is a parameter that **appears in no
constraint** skewed? Skew there is the base sampler's own problem and a real
defect.

TWO CONTROLS

  UNIFORM SOURCE   Values generated uniformly in the range with `os.urandom`.
                   The measurement MUST find it uniform; if it does not, the
                   measure is too sensitive and every finding is suspect.

  SKEWED SOURCE    A deliberately skewed source (squaring). The measurement
                   has to catch it; if it cannot, the measure is blind and its
                   "uniform" results mean nothing.

    python -m layer2.sampler_uniformity --samples 400
"""

from __future__ import annotations

import argparse
import math
import os
import random
import time
from collections import Counter

from crypto.corpus import Corpus, Entry, is_public, load_corpus
from crypto.constraints import free_names
from crypto.sampler import equality_plan, sample, bounds

BUCKET = 16
# The per entry time budget. Entries generating 2048 bit primes spend hundreds
# of ms per sample, and without a budget the tool hung for hours.
BUDGET_S = 6.0
MIN_SAMPLES = BUCKET * 5
# Bonferroni: with hundreds of parameters tested, a 5% threshold each produces
# random "findings". The threshold is divided by the parameter count.
RAW_THRESHOLD = 0.01


def _chi_square_p(observed: list[int], expected: float) -> float:
    """Chi-square goodness of fit, giving an approximate p-value.

    There is no `scipy` but there is `math`. With large degrees of freedom the
    Wilson-Hilferty cube root transform is close enough to the normal
    approximation, and more than good enough at this scale.
    """
    if expected <= 0:
        return 1.0
    x2 = sum((g - expected) ** 2 / expected for g in observed)
    sd = len(observed) - 1
    if sd <= 0:
        return 1.0
    # Wilson–Hilferty
    z = ((x2 / sd) ** (1 / 3) - (1 - 2 / (9 * sd))) / math.sqrt(2 / (9 * sd))
    return 0.5 * math.erfc(z / math.sqrt(2))


def uniformity(values: list[int], lo: int, hi: int,
               bucket: int = BUCKET) -> tuple[float, float]:
    """(p-value, largest bucket deviation), is it uniform across the range.

    The deviation is how far the fullest bucket departs from expectation, as a
    percentage; the p-value answers "could that much deviation be chance". Both
    are given, because on a large sample even a VERY SMALL deviation comes out
    statistically significant and p alone would mislead.
    """
    if hi <= lo or len(values) < 5:
        return 1.0, 0.0
    # THE BUCKET COUNT HAS TO MATCH THE RANGE. The first version always used
    # 16 buckets, so on a 7 value parameter like `block_size` 9 buckets were
    # necessarily empty; chi-square reported that as "skewed" when the
    # distribution was perfectly uniform over its own support. A measurement
    # bug was being reported as a finding.
    bucket = min(bucket, hi - lo + 1)
    if bucket < 2 or len(values) < bucket * 5:
        return 1.0, 0.0
    # INTEGER arithmetic: the corpus has 2048 bit primes and
    # `(hi - lo + 1) / buckets` overflowed a float (OverflowError).
    span = hi - lo + 1
    counter = Counter(
        min(bucket - 1, ((d - lo) * bucket) // span) for d in values)
    observed = [counter.get(i, 0) for i in range(bucket)]
    expected = len(values) / bucket
    deviation = max(abs(g - expected) for g in observed) / expected
    return _chi_square_p(observed, expected), deviation


# ══════════════════════ corpus measurement ══════════════════════

def measure_entry(entry: Entry, count: int, rng: random.Random,
                  budget_s: float = BUDGET_S) -> list[dict]:
    """A uniformity measurement for every public parameter of an entry.

    THERE IS A TIME BUDGET and there has to be: the corpus contains entries
    generating 2048 bit primes, where even 300 samples takes minutes. When the
    budget runs out it settles for what it has, and if that is not enough the
    entry is reported as "could not measure". A tool HANGING SILENTLY is worse
    than one giving an incomplete measurement.
    """
    t0 = time.monotonic()
    samples = []
    try:
        for _ in range(count):
            samples.append(sample(entry, rng))
            if time.monotonic() - t0 > budget_s:
                break
    except Exception as e:                                   # noqa: BLE001
        return [{"entry": entry.slug, "param": "-", "error": str(e)[:60]}]

    if len(samples) < MIN_SAMPLES:
        return [{"entry": entry.slug, "param": "-",
                 "error": f"budget exhausted, only {len(samples)} samples"}]

    bound = bounds(entry)
    by_equality = {name for _, name in equality_plan(entry, random.Random(entry.id))}
    # Every name appearing in a constraint. Rejection sampling is uniform over
    # the JOINT valid set, so the MARGINAL of a constraint coupled variable is
    # naturally not uniform. Counting that as a defect would be wrong.
    restricted: set[str] = set()
    for c in entry.constraints:
        try:
            restricted |= free_names(c["expr"])
        except Exception:                                    # noqa: BLE001
            pass

    lines = []
    for p in entry.params:
        if not is_public(p) or p.get("type") == "bytes":
            continue
        name = p["name"]
        values = [o[name] for o in samples if isinstance(o.get(name), int)]
        if not values:
            continue
        lo, hi = bound.get(name, (min(values), max(values)))
        pdeg, deviation = uniformity(values, lo, hi)
        lines.append({
            "entry": entry.slug, "param": name,
            "p": pdeg, "deviation": deviation,
            "by_equality": name in by_equality,
            "restricted": name in restricted,
            "free": name not in restricted and name not in by_equality,
            "error": None,
        })
    return lines


def measure_corpus(corpus: Corpus, count: int, seed: int = 0,
                   budget_s: float = BUDGET_S) -> list[dict]:
    rng = random.Random(seed)
    lines = []
    for entry in corpus.active:
        lines.extend(measure_entry(entry, count, rng, budget_s))
    return lines


# ══════════════════════ kontroller ══════════════════════

def control_uniform(count: int) -> tuple[float, float]:
    """A UNIFORM source; the measurement must find it uniform."""
    lo, hi = 0, 999
    d = [lo + int.from_bytes(os.urandom(4), "big") % (hi - lo + 1)
         for _ in range(count)]
    return uniformity(d, lo, hi)


def control_skewed(count: int) -> tuple[float, float]:
    """A SKEWED source; the measurement has to catch it.

    Squaring piles the distribution at the low end, an obvious departure from uniform.
    """
    lo, hi = 0, 999
    d = []
    for _ in range(count):
        u = (int.from_bytes(os.urandom(4), "big") % (hi - lo + 1)) / (hi - lo)
        d.append(lo + int(u * u * (hi - lo)))
    return uniformity(d, lo, hi)


# ══════════════════════ report ══════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--samples", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--budget", type=float, default=BUDGET_S,
                    help="seconds of budget per entry")
    ap.add_argument("--all", action="store_true",
                    help="also list the parameters that came out uniform")
    a = ap.parse_args()

    print(f"\n  SAMPLER DISTRIBUTION MEASUREMENT ({a.samples} samples per entry)\n")

    # -- controls first: if the measure does not work, nothing else matters --
    dp, ds = control_uniform(a.samples)
    cp, cs = control_skewed(a.samples)
    print(f"  {'control':<26}{'p':>10}{'deviation':>10}")
    print(f"  {'-' * 46}")
    print(f"  {'uniform source':<26}{dp:>10.4f}{ds:>9.1%}")
    print(f"  {'skewed source (squared)':<26}{cp:>10.4f}{cs:>9.1%}")

    error = 0
    if dp < RAW_THRESHOLD:
        print("\n  x THE UNIFORM SOURCE WAS FOUND SKEWED. The measure is too")
        print("    sensitive; the corpus findings may be false alarms.")
        error = 1
    if cp >= RAW_THRESHOLD:
        print("\n  x THE SKEWED SOURCE WAS NOT CAUGHT. The measure is blind, so")
        print("    none of its 'uniform' results mean anything.")
        error = 1
    if error:
        print()
        return error
    print("  + the measure works: it found the uniform uniform and the skewed skewed\n")

    # ── corpus ──
    lines = measure_corpus(load_corpus(), a.samples, a.seed, a.budget)
    measured = [s for s in lines if not s["error"]]
    faulty = [s for s in lines if s["error"]]
    threshold = RAW_THRESHOLD / max(1, len(measured))       # Bonferroni

    diagonals = sorted((s for s in measured if s["p"] < threshold),
                       key=lambda s: -s["deviation"])
    equality_solved = [s for s in diagonals if s["by_equality"]]
    restricted = [s for s in diagonals if s["restricted"] and not s["by_equality"]]
    unexpected = [s for s in diagonals if s["free"]]
    free_total = sum(1 for s in measured if s["free"])

    print(f"  parameters measured : {len(measured)} "
          f"({free_total} of them appear in no constraint)")
    print(f"  Bonferroni threshold: p < {threshold:.2e}")
    print(f"  found skewed        : {len(diagonals)}")
    print(f"    solved by equality (EXPECTED)          : {len(equality_solved)}")
    print(f"    constraint coupled, marginal (EXPECTED): {len(restricted)}")
    print(f"    APPEARING IN NO CONSTRAINT (REVIEW)    : {len(unexpected)}")
    if faulty:
        print(f"  COULD NOT MEASURE : {len(faulty)} entries")
        for h in faulty[:6]:
            print(f"      {h['entry'][:30]:<32}{h['error']}")

    to_show = unexpected if not a.all else diagonals
    if to_show:
        print(f"\n  {'entry':<24}{'param':<15}{'deviation':>10}  class")
        print(f"  {'-' * 62}")
        for s in to_show[:25]:
            if s["by_equality"]:
                cls = "solved by equality"
            elif s["restricted"]:
                cls = "constraint coupled"
            else:
                cls = "OPEN — incele"
            print(f"  {s['entry'][:23]:<24}{s['param'][:14]:<15}"
                  f"{s['deviation']:>7.1%}  {cls}")

    print()
    if unexpected:
        print(f"  ! {len(unexpected)} parameters are skewed DESPITE APPEARING IN NO")
        print("    CONSTRAINT. That is the base sampler's own problem and it MUST")
        print("    BE REVIEWED; with no constraint the distribution should be uniform.")
    else:
        print("  + every parameter appearing in no constraint is uniform.")
        print("    All the skew is in variables that are solved by equality or")
        print("    coupled through constraints, and both are EXPECTED.")

    print("\n  LIMIT: this is a measurement, not a proof. Uniformity is tested on a")
    print("  FINITE sample, and 'no skew found' does not mean 'not skewed'.\n")
    return 0


if __name__ == "__main__":
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
