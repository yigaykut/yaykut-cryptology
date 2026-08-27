"""Evaluation measures.

The critical point: in this project "the model could not tell them apart" is
a SUCCESS, but only if it is statistically supported. Is 50.4% accuracy
meaningfully different from 50%, or is it noise? That question cannot be
answered without a confidence interval, which is why every accuracy is
reported together with one.

No sklearn dependency; everything is numpy.
"""

from __future__ import annotations

import math

import numpy as np


def accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    return float((y_true == y_pred).mean())


def wilson_interval(hits: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson confidence interval for a proportion, at 95%.

    Far more reliable at the extremes than the normal approximation, and it
    is the right tool for values around 50%.
    """
    if total == 0:
        return (0.0, 1.0)
    p = hits / total
    denom = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def beats_chance(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[bool, tuple[float, float]]:
    """Does binary accuracy meaningfully exceed 50%.

    Yes if the lower bound of the confidence interval sits above 0.5.
    Otherwise the observed difference is indistinguishable from noise.
    """
    hits = int((y_true == y_pred).sum())
    low, high = wilson_interval(hits, len(y_true))
    return low > 0.5, (low, high)


def auc(y_true: np.ndarray, score: np.ndarray) -> float:
    """Area under the ROC curve, via rank statistics (Mann-Whitney U).

    0.5 means no better than guessing. 1.0 means perfect separation.
    """
    pos = score[y_true == 1]
    neg = score[y_true == 0]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan")

    everything = np.concatenate([pos, neg])
    ranks = everything.argsort().argsort().astype(np.float64) + 1
    # Give equal scores the average rank, so ties are handled correctly.
    _, inverse, counts = np.unique(everything, return_inverse=True, return_counts=True)
    rank_sums = np.zeros(len(counts))
    np.add.at(rank_sums, inverse, ranks)
    ranks = (rank_sums / counts)[inverse]

    r_pos = ranks[: len(pos)].sum()
    u = r_pos - len(pos) * (len(pos) + 1) / 2
    return float(u / (len(pos) * len(neg)))


def confusion(y_true: np.ndarray, y_pred: np.ndarray, class_count: int) -> np.ndarray:
    m = np.zeros((class_count, class_count), dtype=np.int64)
    np.add.at(m, (y_true, y_pred), 1)
    return m


def per_class_accuracy(y_true: np.ndarray, y_pred: np.ndarray, class_count: int) -> np.ndarray:
    m = confusion(y_true, y_pred, class_count)
    totals = m.sum(axis=1)
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(totals > 0, np.diag(m) / np.maximum(totals, 1), np.nan)


def collapsed(y_pred: np.ndarray) -> bool:
    """Is the model giving every sample the same class.

    WHY THIS IS REPORTED SEPARATELY
    The accuracy of a model that collapses to one class is that class's SHARE
    of the test set, not the model's performance. On a balanced set it comes
    out near 50% and looks like "chance level performance", when in fact the
    model made no decision at all.

    The difference matters for measurement: collapse is a sign that no
    learnable signal was found, which is the right answer, but the accuracy
    number DOES NOT SAY THAT. So collapse is reported separately and the
    interpretation rests on AUC, which looks at the raw scores rather than
    thresholded predictions and therefore still carries information under
    collapse.
    """
    return len(np.unique(y_pred)) == 1


def report_binary(name: str, y_true: np.ndarray, y_pred: np.ndarray, score: np.ndarray) -> dict:
    """A one line summary plus interpretation for a binary experiment."""
    acc = accuracy(y_true, y_pred)
    beats, (low, high) = beats_chance(y_true, y_pred)
    a = auc(y_true, score)
    return {
        "name": name,
        "accuracy": acc,
        "low": low,
        "high": high,
        "auc": a,
        "distinguishes": beats,
        "collapsed": collapsed(y_pred),
        "prediction_split": np.bincount(y_pred, minlength=2).tolist(),
    }

# ═══════════════ THE GATE BAND ═══════════════
#
# `beats_chance` uses a 95% confidence interval and that is the right tool
# for a REPORT. As an EXIT CODE GATE it is wrong: a test at alpha=0.05 fails
# on about 5% of runs even when the null hypothesis is TRUE. A tool that goes
# red at random teaches people not to look at it.
#
# The gate therefore uses a band of plus or minus 3 standard deviations. For
# n=100 the sd is about 0.05, giving 0.35 to 0.65. False alarms drop to about
# 0.3%, and a real distinguisher is still caught because it would come out
# near 1.0.
#
# The 95% interval keeps being printed in the report as it was.
CHANCE_BAND = (0.35, 0.65)


def in_chance_band(report: dict) -> bool:
    """Is the result inside the chance band. For the EXIT CODE, not the report."""
    low, high = CHANCE_BAND
    return (low <= report["accuracy"] <= high) and (low <= report["auc"] <= high)
