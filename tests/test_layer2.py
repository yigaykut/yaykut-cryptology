"""Layer 2 tests.

Experiment results cannot be read without the measures themselves being
verified: a wrong AUC implementation can invent "no leak" just as easily as "a leak".
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from layer2 import (  # noqa: E402
                    auc,
                    split_data,
                    accuracy,
                    frame_data,
                    collapsed,
                    content_data,
                    confusion,
                    sabotaged_ciphertext,
                    beats_chance,
                    ciphertext,
                    report_binary,
                    per_class_accuracy,
                    length_ceiling,
                    length_data,
                    wilson_interval,
)
from layer2.data import SABOTAGE_BYTES, to_bits  # noqa: E402
from crypto import load_corpus# noqa: E402
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES  # noqa: E402

CORPUS = load_corpus()
KEY = bytes(range(32))


# ────────────────────────────── AUC ──────────────────────────────

def test_auc_perfect_separation():
    y = np.array([1, 1, 1, 0, 0, 0])
    score = np.array([0.9, 0.8, 0.7, 0.3, 0.2, 0.1])
    assert auc(y, score) == pytest.approx(1.0)


def test_auc_full_inverse_separation():
    y = np.array([1, 1, 1, 0, 0, 0])
    score = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
    assert auc(y, score) == pytest.approx(0.0)


def test_auc_fully_equal_scores_half_gives():
    """If every score is equal the model carries no information: AUC = 0.5."""
    y = np.array([1, 1, 0, 0])
    score = np.array([0.5, 0.5, 0.5, 0.5])
    assert auc(y, score) == pytest.approx(0.5)


def test_auc_partial_binds_correct_is_processed():
    y = np.array([1, 0])
    score = np.array([0.5, 0.5])
    assert auc(y, score) == pytest.approx(0.5)


def test_auc_random_score_to_half_near():
    rng = np.random.default_rng(0)
    y = np.concatenate([np.ones(2000, int), np.zeros(2000, int)])
    score = rng.random(4000)
    assert abs(auc(y, score) - 0.5) < 0.03


# ────────────────────────── confidence interval ──────────────────────────

def test_wilson_interval_ratio_covers():
    alt, top = wilson_interval(50, 100)
    assert alt < 0.5 < top


def test_wilson_narrows_sample_as_it_rises():
    narrow = wilson_interval(5000, 10000)
    wide = wilson_interval(50, 100)
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])


def test_wilson_three_values_does_not_overflow():
    alt, top = wilson_interval(0, 10)
    assert alt >= 0.0 and top <= 1.0
    alt, top = wilson_interval(10, 10)
    assert alt >= 0.0 and top <= 1.0


def test_chance_level_distinguish_cannot_counts():
    """Exactly 50% accuracy must not count as "can distinguish"."""
    y = np.concatenate([np.ones(500, int), np.zeros(500, int)])
    prediction = np.concatenate([np.ones(250, int), np.zeros(250, int),
                                 np.ones(250, int), np.zeros(250, int)])
    overflows, _ = beats_chance(y, prediction)
    assert overflows is False


def test_perfect_guess_chance_exceeds():
    y = np.concatenate([np.ones(500, int), np.zeros(500, int)])
    overflows, (alt, _) = beats_chance(y, y.copy())
    assert overflows is True and alt > 0.9


# ────────────────────────── collapse detection ──────────────────────────

def test_collapse_is_caught():
    assert collapsed(np.ones(100, int))
    assert collapsed(np.zeros(100, int))
    assert not collapsed(np.array([0, 1] * 50))


def test_collapsed_of_the_model_correctness_class_is_the_ratio():
    """A measurement trap found on 2026-08-15; it must not slip through again.

    A model collapsing to one class makes no decision at all, but on a
    balanced test set its accuracy comes out near 50% and looks like "chance
    level performance". That number is the class's SHARE of the set, not the model's success.
    """
    y = np.concatenate([np.ones(994, int), np.zeros(1006, int)])
    p = np.ones(len(y), int)          # it says "1" to everything
    r = report_binary("collapsed", y, p, np.random.default_rng(0).random(len(y)))

    assert r["collapsed"] is True
    assert r["prediction_split"] == [0, 2000]
    # the accuracy is exactly class 1's share; the information from the model is zero
    assert r["accuracy"] == pytest.approx(994 / 2000)


def test_healthy_model_collapsed_is_not_marked():
    y = np.concatenate([np.ones(500, int), np.zeros(500, int)])
    p = y.copy()
    p[:20] = 1 - p[:20]
    r = report_binary("healthy", y, p, y.astype(float))
    assert r["collapsed"] is False
    assert sum(r["prediction_split"]) == len(y)


def test_auc_collapsed_in_the_model_also_information_carries():
    """Under collapse accuracy goes blind, but AUC looks at raw scores and does not.

    That is what the fix rests on: with the same collapsed predictions, AUC
    still shows the real signal.
    """
    y = np.concatenate([np.ones(500, int), np.zeros(500, int)])
    cokmus_tahmin = np.ones(1000, int)

    perfect_score = y.astype(float)
    uninformed_score = np.full(1000, 0.7)

    assert auc(y, perfect_score) == pytest.approx(1.0)
    assert auc(y, uninformed_score) == pytest.approx(0.5)
    # the accuracy is THE SAME in both; it does not distinguish
    assert accuracy(y, cokmus_tahmin) == pytest.approx(0.5)


# ────────────────────────── confusion matrix ──────────────────────────

def test_confusion_matrix_sum_sample_count_equal():
    y = np.array([0, 1, 2, 1, 0])
    p = np.array([0, 1, 1, 1, 2])
    m = confusion(y, p, 3)
    assert m.sum() == len(y)
    assert m[0, 0] == 1 and m[1, 1] == 2 and m[2, 1] == 1


def test_class_per_accuracy():
    y = np.array([0, 0, 1, 1])
    p = np.array([0, 1, 1, 1])
    acc = per_class_accuracy(y, p, 2)
    assert acc[0] == pytest.approx(0.5)
    assert acc[1] == pytest.approx(1.0)


# ────────────────────────── data generation ──────────────────────────

def test_length_ceiling_chance_to_level_dropped():
    """After ADR-007: every entry is in one length group, so the ceiling is 1/N.

    This test is the guarantee the length leak stays closed. If the padding
    is removed or an entry starts producing a different length, it blows up here.
    """
    ceiling, colliding = length_ceiling(CORPUS)
    n = len(CORPUS.active)

    assert ceiling == pytest.approx(1 / n), "the length leak is back"
    assert len(colliding) == 1, "more than one length group"
    assert len(next(iter(colliding.values()))) == n, "every entry has to be in the same group"


def test_length_ceiling_real_sent_size_uses():
    """The ceiling has to look at the length actually SENT, not at the logical
    payload size. Otherwise the effect of the padding could not be measured."""
    ceiling, _ = length_ceiling(CORPUS)
    logically_distinct = len({e.payload_bytes for e in CORPUS.active})
    assert logically_distinct > 1, "the corpus's logical sizes should already vary"
    assert ceiling < logically_distinct / len(CORPUS.active)


def test_length_data_form():
    X, y, entries = length_data(CORPUS, KEY, samples=3, seed=1)
    assert X.shape == (len(entries) * 3, 16)
    assert set(np.unique(X)) <= {0.0, 1.0}
    assert len(np.unique(y)) == len(entries)


def test_content_data_length_equalised():
    """Both classes have to be the SAME length, or the Experiment 1 leak bleeds in."""
    entry = CORPUS.by_slug("afin-sifre")
    X, y = content_data(entry, KEY, samples=40, seed=2)
    assert X.shape[0] == 40
    assert set(np.unique(y)) == {0, 1}
    # Having a single X matrix already guarantees a fixed length.
    assert X.shape[1] % 8 == 0


def test_content_data_classes_balanced():
    entry = CORPUS.by_slug("aes-sbox")
    _, y = content_data(entry, KEY, samples=100, seed=3)
    assert (y == 1).sum() == (y == 0).sum() == 50


def test_frame_data_length_equalised():
    """The sequenced and unsequenced arms are the SAME length; only the content differs."""
    entry = CORPUS.by_slug("afin-sifre")
    X, y = frame_data(entry, KEY, samples=40, seed=2)
    assert X.shape[0] == 40
    assert set(np.unique(y)) == {0, 1}
    assert (y == 1).sum() == (y == 0).sum() == 20


def test_frame_data_arms_really_different_order_carries():
    """So the experiment means something: the two arms really have to carry different frames.

    Without this check, a result of "50%, indistinguishable" could also come
    from the arms carrying THE SAME data.
    """
    from crypto import UNSEQUENCED, read_frame, encode, sample

    entry = CORPUS.by_slug("afin-sifre")
    values = sample(entry)
    in_session = encode(entry, values, KEY, check=False, seq=7)
    sessionless = encode(entry, values, KEY, check=False)

    assert read_frame(in_session, KEY).seq == 7
    assert read_frame(sessionless, KEY).seq == UNSEQUENCED
    assert len(in_session) == len(sessionless)


def test_frame_data_sabotage_arm_separate():
    entry = CORPUS.by_slug("aes-sbox")
    flat, _ = frame_data(entry, KEY, samples=20, seed=5)
    sbt, _ = frame_data(entry, KEY, samples=20, seed=5, sabotage=True)
    assert not np.array_equal(flat, sbt)


def test_sabotage_really_trace_leaves():
    """Confirm the positive control really carries a learnable signal."""
    entry = CORPUS.by_slug("ec-weierstrass-short")
    rng = random.Random(0)
    blob = sabotaged_ciphertext(entry, KEY, rng)
    begin = NONCE_BYTES + SELECTOR_BYTES
    assert blob[begin:begin + SABOTAGE_BYTES] == bytes(SABOTAGE_BYTES)

    clean = ciphertext(entry, KEY, rng)
    assert len(clean) == len(blob), "the sabotage must not change the length"


def test_to_bits_transform_invertible():
    blobs = [b"\x00\xff", b"\xa5\x5a"]
    bit = to_bits(blobs)
    assert bit.shape == (2, 16)
    assert bit[0].tolist() == [0] * 8 + [1] * 8
    assert bit[1][:8].tolist() == [1, 0, 1, 0, 0, 1, 0, 1]


def test_split_test_set_with_training_does_not_intersect():
    X = np.arange(100).reshape(100, 1).astype(np.float32)
    y = np.arange(100)
    X_e, y_e, X_t, y_t = split_data(X, y, fraction=0.2, seed=0)
    assert len(y_e) == 80 and len(y_t) == 20
    assert not (set(y_e.tolist()) & set(y_t.tolist()))


# ────────────────────────── end to end sanity ──────────────────────────

def test_real_cipher_text_bit_balance_half_around():
    """The 0 and 1 bits in a ciphertext should be roughly equal.

    A serious deviation would be the first sign of a broken keystream.
    """
    entry = CORPUS.by_slug("rsa-modexp")
    rng = random.Random(7)
    blobs = [ciphertext(entry, KEY, rng) for _ in range(200)]
    ratio = to_bits(blobs).mean()
    assert 0.48 < ratio < 0.52, f"bit dengesi bozuk: {ratio}"
