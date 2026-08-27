"""Is the timing measurement instrument itself correct.

Results cannot be read without the measurement tool being verified: a broken
t-test can invent "no leak" just as easily as "a leak".

These tests DO NOT MEASURE TIME (that would be noisy and machine dependent);
they exercise the statistics and the tool's decision logic.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto.timing import (  # noqa: E402
                           THRESHOLD,
                           TimingReport,
                           _trim,
                           _welch_t,
                           worst,
                           measure,
)


def report(t: float) -> TimingReport:
    return TimingReport(name="x", t=t, n_a=10, n_b=10, mean_a_ns=1.0, mean_b_ns=1.0)


# ───────────────────────── Welch t-testi ─────────────────────────

def test_same_distribution_to_zero_near_t():
    a = [100.0, 101.0, 99.0, 100.5, 99.5] * 20
    assert abs(_welch_t(a, list(a))) < 0.001


def test_distinct_difference_high_t():
    a = [100.0, 101.0, 99.0] * 40
    b = [200.0, 201.0, 199.0] * 40
    assert abs(_welch_t(a, b)) > THRESHOLD


def test_marker_direction_correct():
    """If A is slower, t has to be positive."""
    slow = [200.0, 201.0, 199.0] * 40
    fast = [100.0, 101.0, 99.0] * 40
    assert _welch_t(slow, fast) > 0
    assert _welch_t(fast, slow) < 0


def test_large_variance_difference_hides():
    """Welch does not assume equal variances: on noisy data t has to shrink."""
    a = [100.0 + (i % 97) * 40 for i in range(300)]
    b = [110.0 + (i % 97) * 40 for i in range(300)]
    assert abs(_welch_t(a, b)) < THRESHOLD


def test_zero_variance_does_not_crash():
    """If every measurement is the same the denominator is zero; it must not raise."""
    assert _welch_t([5.0] * 10, [5.0] * 10) == 0.0


@pytest.mark.parametrize("a, b", [([], [1.0, 2.0]), ([1.0], [1.0]), ([1.0, 2.0], [])])
def test_insufficient_sample_is_refused(a, b):
    with pytest.raises(ValueError):
        _welch_t(a, b)


# ───────────────────────── outlier trimming ─────────────────────────

def test_clamping_drops_the_slowest():
    samples = [1.0] * 90 + [1_000_000.0] * 10
    clamped = _trim(samples, 0.10)
    assert max(clamped) == 1.0
    assert len(clamped) == 90


def test_clamping_zero_rate_does_not_touch():
    samples = [3.0, 1.0, 2.0]
    assert sorted(_trim(samples, 0)) == [1.0, 2.0, 3.0]


def test_clamping_leaves_at_least_two_samples():
    assert len(_trim([1.0, 2.0, 3.0], 0.99)) >= 2


# ───────────────────────── decision logic ─────────────────────────

@pytest.mark.parametrize("t, expected", [
    (0.0, False), (4.49, False), (-4.49, False),
    (4.51, True), (-4.51, True), (100.0, True),
])
def test_threshold_decision(t, expected):
    assert report(t).leaking is expected


def test_worst_picks_by_absolute_value():
    """A negative t is a leak too; the sign is direction, not magnitude."""
    chosen = worst([report(1.0), report(-9.0), report(3.0)])
    assert chosen.t == -9.0


def test_worst_refuses_an_empty_list():
    with pytest.raises(ValueError):
        worst([])


def test_report_text_state_says():
    assert "LEAK" in str(report(50.0))
    assert "clean" in str(report(0.5))


# ───────────────────────── end to end ─────────────────────────

def test_measure_deliberate_the_leak_catches():
    """The positive control: a function whose duration depends on its input has to be caught."""
    r = measure("leaking", lambda n: sum(range(n)),
                lambda: 5, lambda: 20000, repeats=400, warmup=50)
    assert r.leaking, f"the deliberate leak was not caught: |t| = {abs(r.t):.2f}"
    assert r.t < 0, "the class doing less work should have been faster"


def test_measure_fixed_is_wrong_alarm_does_not_give():
    """The negative control: work independent of the input must not count as a leak."""
    r = measure("fixed", lambda n: sum(range(300)),
                lambda: 5, lambda: 20000, repeats=400, warmup=50)
    assert not r.leaking, f"a false alarm on constant work: |t| = {abs(r.t):.2f}"


def test_measure_every_class_sample_distributes():
    r = measure("distribution", lambda n: n, lambda: 1, lambda: 2, repeats=400, warmup=10)
    assert r.n_a > 50 and r.n_b > 50
