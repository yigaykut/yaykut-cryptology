"""Coverage guided fuzzing: the tool itself is being tested.

THE MOST IMPORTANT TEST: `test_guidance_blind_without_searching_good`

"Coverage guided" is an adjective, and adjectives have to be proved. This
test shows the guidance is measurably better than blind search: on a target
needing three consecutive correct bytes, blind search needs 2^24 attempts
while guided search takes seconds.

If it could not be shown, the tool would be nothing but a name, and so would
every "clean" report `coverage_fuzz.py` produces.

STOCHASTICITY
The search is random and a single attempt hits 4 times in 5. So the tests try
a few seeds and ask that any one of them find it. Loosening the threshold
further would make the test meaningless; tightening it would false alarm.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import coverage_fuzz  # noqa: E402


def _control_tracer(target):
    """A tracer that watches only the target's own code object."""
    return coverage_fuzz.Tracer(filter=lambda c, k=target.__code__: c is k)


# ═══════════════ hit buckets ═══════════════

def test_bucket_afl_steps():
    """AFL's logarithmic buckets; the boundaries are exactly here."""
    assert [coverage_fuzz.bucket(n) for n in (1, 2, 3)] == [0, 1, 2]
    assert coverage_fuzz.bucket(4) == coverage_fuzz.bucket(7) == 3
    assert coverage_fuzz.bucket(8) == coverage_fuzz.bucket(15) == 4
    assert coverage_fuzz.bucket(16) == coverage_fuzz.bucket(31) == 5
    assert coverage_fuzz.bucket(32) == coverage_fuzz.bucket(127) == 6
    assert coverage_fuzz.bucket(128) == coverage_fuzz.bucket(10**6) == 7


def test_bucket_monotonic():
    previous = -1
    for n in range(1, 2000):
        k = coverage_fuzz.bucket(n)
        assert k >= previous
        previous = k


# ═══════════════ tracer ═══════════════

def test_tracer_starting_stands():
    trace = coverage_fuzz.Tracer()
    assert trace.start() is True
    assert trace.active
    trace.stop()
    assert not trace.active


def test_tracer_two_times_stoppable():
    trace = coverage_fuzz.Tracer()
    trace.start()
    trace.stop()
    trace.stop()          # must not blow up


def test_tracer_filter_outside_does_not_count():
    """Code outside the filter must not enter the coverage."""
    def off_target(x):
        return 1 if x else 0

    def target(x):
        return 1 if x else 0

    trace = _control_tracer(target)
    trace.start()
    try:
        trace.run(off_target, b"x")
        assert len(trace.edges) == 0, "code outside the filter was counted"
        trace.run(target, b"x")
        assert len(trace.edges) > 0, "code inside the filter was not counted"
    finally:
        trace.stop()


def test_tracer_depth_as_it_rises_new_coverage():
    """Every correct byte has to open NEW coverage; the whole of guidance rests on it.

    If that does not hold the search cannot climb, and indeed the first
    implementation had no hit counter and could not climb the comparison inside the loop.
    """
    target, _, _ = coverage_fuzz.target_control(4)
    trace = _control_tracer(target)
    trace.start()
    try:
        new_ones = []
        for entry in (bytes(4),
                      bytes([0xDE, 0, 0, 0]),
                      bytes([0xDE, 0xAD, 0, 0]),
                      bytes([0xDE, 0xAD, 0xBE, 0])):
            _, new = trace.run(target, entry)
            new_ones.append(new)
        assert all(y > 0 for y in new_ones), (
            f"the stepwise match opened no new coverage: {new_ones}")
    finally:
        trace.stop()


def test_tracer_error_does_not_swallow():
    def burst(_):
        raise RuntimeError("deliberate")

    trace = coverage_fuzz.Tracer()
    trace.start()
    try:
        error, _ = trace.run(burst, b"")
        assert isinstance(error, RuntimeError)
    finally:
        trace.stop()


# ═══════════════ mutate ═══════════════

def test_mutation_empty_with_the_entry_works():
    rng = random.Random(0)
    for _ in range(200):
        assert isinstance(coverage_fuzz.mutate(b"", rng, []), bytes)


def test_mutation_length_bounded():
    """Unbounded growth eats memory and slows the search down."""
    rng = random.Random(0)
    data = b"\x00" * 4000
    for _ in range(300):
        data = coverage_fuzz.mutate(data, rng, [data])
        assert len(data) <= 4096


def test_mutation_random_byte_generator_exists():
    """It was MISSING in the first version and the positive control exposed it.

    Bit flips go from 0x00 to 0xDE in six steps, and because the intermediate
    steps open no new coverage they are not kept in the corpus, which dead
    ends the search. This test pins that every byte value is reachable in one step.
    """
    rng = random.Random(1)
    base = bytes(1)
    seen = set()
    for _ in range(20000):
        m = coverage_fuzz.mutate(base, rng, [base])
        if len(m) == 1:
            seen.add(m[0])
    assert len(seen) > 100, (
        f"only {len(seen)} distinct byte values were reached in one step; "
        f"the random byte operator may be missing")


# ═══════════════ THE REAL CLAIM ═══════════════

@pytest.mark.parametrize("depth", [3])
def test_guidance_blind_without_searching_good(depth):
    """Guided search finds it, blind search does not.

    That is the only real justification for the adjective "coverage guided".
    Claiming without measuring was not done anywhere in this project.
    """
    target, accept, seeds = coverage_fuzz.target_control(depth)

    found = False
    for seed in range(4):                       # stochastic, a few attempts
        h, kb, th = coverage_fuzz.target_control(depth)
        trace = _control_tracer(h)
        trace.start()
        try:
            findings, _ = coverage_fuzz.guided(h, sure=3.0, seed=seed,
                                               seeds=th, accept=kb, tracer=trace)
        finally:
            trace.stop()
        if findings:
            found = True
            break
    assert found, "guided search failed on all 4 seeds; the guidance is not working"

    # Blind search must use the same time and fail; if it finds it, the target is too easy.
    blind_finding, blind_stat = coverage_fuzz.blind(target, sure=3.0, seed=0, accept=accept)
    assert blind_stat["runs"] > 10000, "blind search did not run enough"
    assert not blind_finding, (
        "blind search found it too; the positive control is too easy and "
        "the comparison is meaningless")


# ═══════════════ the real targets ═══════════════

@pytest.mark.parametrize("builder", ["target_raw", "target_engine"])
def test_real_targets_short_in_a_run_clean(builder):
    """A small budget on every pytest run; the long search by hand."""
    target, accept, seeds = getattr(coverage_fuzz, builder)()
    assert seeds, "the seed corpus is empty and the search cannot go deep"
    findings, stat = coverage_fuzz.guided(target, sure=2.0, seed=0,
                                          seeds=seeds, accept=accept)
    assert stat["tracing"], "sys.monitoring could not be started"
    assert stat["edges"] > 20, f"the coverage is suspiciously shallow: {stat['edges']}"
    assert not findings, "\n".join(str(b) for b in findings)


def test_seed_corpus_really_deep_drops():
    """Pins the difference between a seeded and an unseeded search.

    Without a seed corpus `hedef_ham` never gets past the tag gate, and that
    has to show up in the coverage count.
    """
    target, accept, seeds = coverage_fuzz.target_raw()

    _, seeded = coverage_fuzz.guided(target, sure=1.5, seed=0,
                                     seeds=seeds, accept=accept)
    _, unseeded = coverage_fuzz.guided(target, sure=1.5, seed=0,
                                       seeds=[b"\x00"], accept=accept)
    assert seeded["edges"] > unseeded["edges"] * 3, (
        f"the seed corpus made no difference: seeded={seeded['edges']}, "
        f"tohumsuz={unseeded['edges']}")
