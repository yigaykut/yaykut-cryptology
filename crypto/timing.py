"""Timing leak measurement with Welch's t-test.

Claiming code is constant time by reading it is not reliable. Compilers,
interpreters, caches and branch predictors introduce differences the source
does not show. Measuring is the only honest way.

The method is dudect (Reparaz, Balasch, Verbauwhede 2016). Two input classes
are prepared and timings are collected in random order:

    class A: the secret sits at one end, say the real record first
    class B: the secret sits at the other end, say the real record last

If the code is constant time the two distributions should share a mean.
Welch's t-test checks that:

    t = (meanA - meanB) / sqrt(varA/nA + varB/nB)

The |t| > 4.5 threshold is the usual one in the literature: 4.5 sigma, so
about a 1e-5 chance of being noise. Below the threshold does not mean "no
leak", it means "no leak found at this sample size".

Interleaving the classes matters. Measuring them in separate blocks lets CPU
boost, garbage collection and OS scheduling load onto one class and produce a
fake leak, so the class is picked at random on every measurement.

OS interrupts can inflate single measurements by orders of magnitude and bury
the real signal, so the slowest percentile is discarded, as dudect does.

An honest warning about what this cannot see. It catches algorithmic timing
differences: early returns, loop counts that depend on a secret, data
dependent branches. It does not catch, and Python cannot fix:

  - bigint arithmetic whose cost depends on operand size
  - cache timing and memory access patterns
  - power analysis and electromagnetic leakage
  - the garbage collector leaving key copies in memory

Passing this measurement does not mean "side channel resistant". It means "no
data dependent branch is left at the algorithm level". Real resistance needs
C or Rust and hardware support.
"""

from __future__ import annotations

import gc
import random
import time
from dataclasses import dataclass
from typing import Any, Callable

# The dudect threshold: 4.5 sigma.
THRESHOLD = 4.5

# Fraction of the slowest measurements to discard (OS interrupts).
TRIM_RATIO = 0.10

DEFAULT_REPEATS = 2000


@dataclass(frozen=True)
class TimingReport:
    """Result of a single measurement."""

    name: str
    t: float
    n_a: int
    n_b: int
    mean_a_ns: float
    mean_b_ns: float

    @property
    def leaking(self) -> bool:
        return abs(self.t) > THRESHOLD

    @property
    def diff_ns(self) -> float:
        return self.mean_a_ns - self.mean_b_ns

    def __str__(self) -> str:
        state = "LEAK" if self.leaking else "clean"
        return (f"{self.name}: |t| = {abs(self.t):.2f}  "
                f"({state}, threshold {THRESHOLD})  "
                f"delta = {self.diff_ns:+.0f} ns")


def _welch_t(a: list[float], b: list[float]) -> float:
    """Welch's t statistic. Does not assume equal variances.

    Student's t-test requires equal variance, but two different code paths do
    not have to share one, so Welch is the right choice.
    """
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        raise ValueError("each class needs at least 2 measurements")

    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)

    denom = (va / na + vb / nb) ** 0.5
    if denom == 0.0:
        return 0.0
    return (ma - mb) / denom


def _trim(samples: list[float], ratio: float) -> list[float]:
    """Drop the slowest `ratio` of samples, which are OS interrupts."""
    if not samples or ratio <= 0:
        return samples
    ordered = sorted(samples)
    keep = max(2, int(len(ordered) * (1 - ratio)))
    return ordered[:keep]


def measure(
    name: str,
    func: Callable[[Any], Any],
    input_a: Callable[[], Any],
    input_b: Callable[[], Any],
    *,
    repeats: int = DEFAULT_REPEATS,
    warmup: int = 200,
    seed: int = 0,
) -> TimingReport:
    """Look for a timing difference between two input classes.

    func    is the function under test, taking one argument
    input_a builds a fresh input from class A
    input_b builds a fresh input from class B

    Inputs are built up front so their construction cost stays out of the
    measurement. Class order is random.
    """
    rng = random.Random(seed)

    # Warm up so interpreter caches and the branch predictor settle.
    for _ in range(warmup):
        func(input_a())
        func(input_b())

    # Build inputs in advance, so build time is not measured.
    plan = [(rng.random() < 0.5) for _ in range(repeats)]
    ready = [(input_a() if a else input_b()) for a in plan]

    times_a: list[float] = []
    times_b: list[float] = []

    gc_was_on = gc.isenabled()
    gc.disable()      # a collection pause would pollute the measurement
    try:
        for is_a, item in zip(plan, ready):
            t0 = time.perf_counter_ns()
            func(item)
            elapsed = time.perf_counter_ns() - t0
            (times_a if is_a else times_b).append(float(elapsed))
    finally:
        if gc_was_on:
            gc.enable()

    ta = _trim(times_a, TRIM_RATIO)
    tb = _trim(times_b, TRIM_RATIO)
    return TimingReport(
        name=name,
        t=_welch_t(ta, tb),
        n_a=len(ta), n_b=len(tb),
        mean_a_ns=sum(ta) / len(ta),
        mean_b_ns=sum(tb) / len(tb),
    )


def worst(reports: list[TimingReport]) -> TimingReport:
    """Pick the largest |t| across several runs.

    Timing measurement is noisy and a single run misleads. When looking for a
    leak the worst case is the right one to take: if even one run crosses the
    threshold, it deserves investigation.
    """
    if not reports:
        raise ValueError("at least one report is required")
    return max(reports, key=lambda r: abs(r.t))
