"""The sampler distribution measurement (`layer2/sampler_uniformity.py`).

WHY THIS FILE EXISTS

This is a MEASUREMENT tool, and the most dangerous bug in a measurement tool
is measuring wrong quietly. Its first version produced 17 false findings for two separate reasons:

  1. It applied 16 buckets to a parameter with a 7 value range, and the empty
     buckets blew up the chi-square.
  2. It expected the MARGINAL of a constraint coupled variable to be uniform,
     when rejection sampling is uniform over the JOINT set.

Both are locked here.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from layer2.sampler_uniformity import (  # noqa: E402
                                       uniformity,
                                       control_skewed,
                                       control_uniform,
)


def test_control_uniform_source_uniform_finds():
    """The measure must not be too sensitive, or every finding is a false alarm.

    IT DOES NOT SAY `p >= 0.01` ON A SINGLE DRAW, and the reason is a lesson
    learned three times in this project: a test at alpha=0.01 fails on 1% of
    draws even when the null hypothesis is TRUE. Its first version did exactly
    that and failed on GitHub Actions (p = 0.0044). The measure was not
    broken, the test was fragile.

    The question asked here is not "is this draw uniform" but "does the
    measure find UNIFORM SOURCES SYSTEMATICALLY skewed". At most one of five
    independent draws is expected to fall below the threshold: under the null
    hypothesis the false alarm rate drops to about 0.1%, while a genuinely
    oversensitive measure fails all five and gets caught.
    """
    failing = sum(1 for _ in range(5) if control_uniform(3000)[0] < 0.01)
    assert failing <= 1, (
        f"the uniform source was found skewed in {failing} of 5 draws; "
        f"the measure is systematically too sensitive")


def test_control_skewed_source_catches():
    """The measure must not be blind, or its "uniform" results mean nothing."""
    p, deviation = control_skewed(3000)
    assert p < 1e-6
    assert deviation > 0.5


def test_narrow_in_range_empty_bucket_IS_NOT_FABRICATED():
    """A REGRESSION TEST. 16 buckets on a 7 value range is a false finding.

    The values are perfectly uniform over their own support and the
    measurement has to find them uniform.
    """
    values = [2 + (i % 7) for i in range(700)]
    p, deviation = uniformity(values, 2, 8)
    assert p >= 0.01, f"false skew on a narrow range: p={p}, deviation={deviation}"


def test_narrow_in_range_REAL_skew_is_caught():
    """The bucket correction must not have made the measure blind."""
    values = [2] * 600 + [3, 4, 5, 6, 7, 8] * 10
    p, _ = uniformity(values, 2, 8)
    assert p < 1e-6


def test_large_on_integers_overflow_none():
    """A REGRESSION TEST. A 2048 bit range did not fit in a float."""
    hi = 2 ** 2048
    values = [(i * hi) // 500 for i in range(500)]
    p, _ = uniformity(values, 0, hi)     # OverflowError vermemeli
    assert 0.0 <= p <= 1.0


def test_insufficient_in_samples_claim_is_not():
    """With few samples it must stay silent rather than say "uniform" or "skewed"."""
    assert uniformity([1, 2, 3], 0, 100) == (1.0, 0.0)
    assert uniformity([], 0, 100) == (1.0, 0.0)
