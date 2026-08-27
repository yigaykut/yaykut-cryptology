"""Traffic analysis (`layer2/traffic.py`) and timing from inside C (`ccore/`).

WHY THIS FILE EXISTS

Both lock the RESULT of a measurement:

  * Across multiple blocks the block count leaks the length, and
    `target_blocks` padding closes it. If the padding silently breaks one
    day (say the padding blocks come out a different size), no functional
    test fails, because the message still decodes. This test fails.

  * A single frame does not leak length (ADR-007). That claim was already
    measured in Experiment 1; here it is tested again from a traffic observer's point of view.
"""

from __future__ import annotations

import random
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from layer2 import traffic  # noqa: E402
from crypto import load_corpus# noqa: E402
from crypto.longmessage import block_capacity  # noqa: E402


@pytest.fixture(scope="module")
def corpus():
    return load_corpus()


@pytest.fixture(scope="module")
def spans(corpus):
    g = block_capacity(corpus)
    return (10, g), (g * 4, g * 6)


def test_negative_control_chance_level(corpus, spans):
    """The rig does not invent a signal, the precondition for the other arms."""
    short, _ = spans
    r = traffic.arm("neg", corpus, 120, random.Random(0),
                    mode="long", a_range=short, b_range=short)
    assert 0.30 <= r["accuracy"] <= 0.70


def test_unpadded_multi_block_length_LEAKS(corpus, spans):
    """Proof that the declared limit really is where it is said to be.

    This test PASSING confirms the leak exists. If it fails one day, either
    the leak was closed (good news, update the docs) or the rig went blind
    (bad news).
    """
    short, long = spans
    r = traffic.arm("unpadded", corpus, 120, random.Random(0),
                    mode="long", a_range=short, b_range=long)
    assert r["accuracy"] > 0.90


def test_block_target_padding_the_leak_CLOSES(corpus, spans):
    """The real lock. If the padding breaks, no functional test fails and this does."""
    short, long = spans
    r = traffic.arm("padded", corpus, 120, random.Random(0), mode="long",
                    a_range=short, b_range=long, target=8)
    assert 0.30 <= r["accuracy"] <= 0.70, (
        f"target_blocks padding does not hide the length: {r['accuracy']:.3f}")


def test_single_frame_length_does_not_leak(corpus):
    """ADR-007, from a traffic observer's point of view."""
    from crypto.message import text_capacity

    container = text_capacity(corpus)
    r = traffic.arm("single", corpus, 120, random.Random(0), mode="single",
                    a_range=(10, container // 4), b_range=(container // 2, container - 1))
    assert 0.30 <= r["accuracy"] <= 0.70


def test_observation_cipher_text_DOES_NOT_SEE():
    """Structural proof that no content reaches the observer."""
    blocks = [b"\xAA" * 100, b"\xBB" * 100]
    assert traffic._observation(blocks) == [2.0, 200.0]


# ═══════════════════ TIMING FROM INSIDE C ═══════════════════

@pytest.mark.skipif(shutil.which("gcc") is None
                    and shutil.which("clang") is None
                    and shutil.which("cc") is None,
                    reason="no compiler; the measurement is SKIPPED, not passed")
def test_c_timing_compiles_and_passes():
    """The `rdtsc` measurement: the positive control is caught, X25519 is clean.

    The program audits its own gates and returns non zero if one fails; the
    job here is to run it.
    """
    import subprocess

    p = subprocess.run(
        [sys.executable, "-m", "ccore.c_timing", "--samples", "400",
         "--warmup", "50"],
        cwd=str(ROOT), capture_output=True, text=True, errors="replace",
        timeout=900)
    assert p.returncode == 0, f"the C timing measurement failed:\n{p.stdout[-2000:]}"
    # An ASCII marker: the C program's output is re-encoded by the console
    # code page in a subprocess and cannot be compared reliably.
    assert "POSITIVE" in p.stdout and "X25519" in p.stdout
