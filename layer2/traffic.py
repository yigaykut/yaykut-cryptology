"""The packet count and send time channels, an open item on the roadmap.

SORU

The CONTENT of a ciphertext cannot be read (ADR-007, Experiments 1 to 3). So
what does an observer learn who never opens the content and sees only **how
many packets went and when**?

The question became urgent with `crypto/longmessage.py`. A single frame was
fixed size and leaked no length at all; across multiple blocks the length
leaks at **block resolution**, and that module's docs say so plainly. What is
measured here is the SIZE of that leak, and whether `target_blocks` padding
really closes it.

WHAT THE OBSERVER SEES

Two numbers only: how many blocks a message was split into, and the total
byte count. Not a single byte of ciphertext is given.

FOUR ARMS

  1. UNPADDED         Two message classes, no padding. Expected: the
                      observer separates the classes at HIGH accuracy. That
                      is not a defect, it is the known leak being measured.

  2. PADDED           The same two classes with a shared `target_blocks`.
                      Expected: CHANCE. Beating it means the padding does
                      not work.
  3. SINGLE FRAME     One frame through `message.encrypt_text`. Expected:
                      CHANCE, which is ADR-007's claim, tested here too.

  4. NEGATIVE CONTROL Two classes drawn from the same distribution. If they
                      separate, the rig is inventing a signal.

    python -m layer2.traffic --round 400
"""

from __future__ import annotations

import argparse
import random

import numpy as np

from crypto import load_corpus
from crypto.message import text_capacity, encrypt_text
from crypto.longmessage import block_capacity, encrypt_long

from .metrics import report_binary, in_chance_band

KEY = bytes(range(32))


def _text(length: int, rng: random.Random) -> str:
    """Text of the given byte length. The content does not matter, length does."""
    return "".join(chr(rng.randint(97, 122)) for _ in range(length))


def _observation(blocks: list[bytes]) -> list[float]:
    """EVERYTHING the observer can see: block count and total bytes.

    The ciphertext content is deliberately withheld; this experiment asks
    what can be learned without seeing the content.
    """
    return [float(len(blocks)), float(sum(len(b) for b in blocks))]


# ══════════════════════ sample generation ══════════════════════

def samples(corpus, round: int, rng: random.Random, *,
            mode: str, a_range: tuple[int, int],
            b_range: tuple[int, int],
            target: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for i in range(round):
        cls = i % 2
        lo, hi = b_range if cls else a_range
        length = rng.randint(lo, hi)
        text = _text(length, rng)

        if mode == "single":
            blocks = [encrypt_text(corpus, text, KEY)]
        else:
            blocks = encrypt_long(corpus, text, KEY, target_blocks=target)

        X.append(_observation(blocks))
        y.append(cls)
    return np.array(X, dtype=np.float64), np.array(y)


def _threshold_split(X: np.ndarray, y: np.ndarray) -> tuple[float, int]:
    """The best single threshold, the simplest attack the observer has.

    No complex model is needed, because the block count is already a one
    dimensional number. Too strong a distinguisher would overstate the leak;
    too weak a one would hide it. A single threshold is the right scale.
    """
    best, best_threshold = 0.0, 0.0
    for threshold in sorted(set(X[:, 0])):
        for dir in (1, -1):
            prediction = ((X[:, 0] > threshold) if dir == 1 else (X[:, 0] <= threshold))
            d = float((prediction.astype(int) == y).mean())
            if d > best:
                best, best_threshold = d, threshold
    return best_threshold, 1


def arm(name: str, corpus, round: int, rng: random.Random, *,
        mode: str, a_range, b_range, target=None) -> dict:
    X, y = samples(corpus, round, rng, mode=mode, a_range=a_range,
                   b_range=b_range, target=target)
    cut = len(X) // 2
    threshold, _ = _threshold_split(X[:cut], y[:cut])
    score = (X[cut:, 0] - threshold)
    prediction = (X[cut:, 0] > threshold).astype(int)
    # Flip if the training arm did not settle which direction is better.
    if (prediction == y[cut:]).mean() < 0.5:
        prediction = 1 - prediction
        score = -score
    return report_binary(name, y[cut:], prediction, score)


# ══════════════════════ report ══════════════════════

def _line(r: dict) -> str:
    return (f"  {r['name']:<38}{r['accuracy']:8.4f}   "
            f"[{r['low']:.4f}, {r['high']:.4f}]  {r['auc']:6.4f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--round", type=int, default=400)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    if a.round < 40 or a.round % 4:
        print("  --round must be at least 40 and a multiple of 4")
        return 2

    corpus = load_corpus()
    body = block_capacity(corpus)
    single_box = text_capacity(corpus)
    rng = random.Random(a.seed)

    # Class A is short messages, class B long. On the single frame arm both
    # have to fit in one frame, otherwise the arm cannot run.
    short = (10, body)
    long = (body * 4, body * 6)
    single_short, single_long = (10, single_box // 4), (single_box // 2, single_box - 1)

    print(f"\n  TRAFFIC ANALYSIS ({a.round} samples per arm)")
    print(f"  block body {body} bytes, single frame capacity {single_box} bytes")
    print("  the observer sees ONLY the block count and the total bytes\n")

    neg = arm("negative control (same distribution)", corpus, a.round, rng,
              mode="long", a_range=short, b_range=short)
    unpadded = arm("multi block, UNPADDED", corpus, a.round, rng,
                   mode="long", a_range=short, b_range=long)
    padded = arm("multi block, target_blocks=8 PADDED", corpus, a.round, rng,
                 mode="long", a_range=short, b_range=long, target=8)
    single = arm("single frame (ADR-007)", corpus, a.round, rng,
                 mode="single", a_range=single_short, b_range=single_long)

    print(f"  {'arm':<38}{'accuracy':>8}   {'95% interval':^18}  {'AUC':>6}")
    print(f"  {'-' * 74}")
    for r in (neg, unpadded, padded, single):
        print(_line(r))

    print()
    error = 0

    if not in_chance_band(neg):
        print("  x THE NEGATIVE CONTROL BEAT CHANCE. Two classes drawn from the")
        print("    same distribution separated, so the rig is inventing a signal.")
        error = 1
    else:
        print("  + negative control: the same distribution cannot be separated")

    if in_chance_band(unpadded):
        print("  x THE UNPADDED ARM SHOWED NO LEAK. The block count varies with")
        print("    length, so not seeing it means the rig is blind.")
        error = 1
    else:
        print(f"  ! THE EXPECTED LEAK WAS MEASURED: unpadded, across multiple")
        print(f"    blocks the observer separates the classes at {unpadded['accuracy']:.0%}.")
        print("    That is not a bug, it is the limit `longmessage.py` declares.")

    if not in_chance_band(padded):
        print(f"  x THE PADDING DID NOT WORK ({padded['accuracy']:.0%}). `target_blocks`")
        print("    should have hidden the length.")
        error = 1
    else:
        print("  + the padding works: `target_blocks` brings the leak down to chance")

    if not in_chance_band(single):
        print(f"  x THE SINGLE FRAME LEAKS LENGTH ({single['accuracy']:.0%}),")
        print("    ADR-007 ihlali.")
        error = 1
    else:
        print("  + the single frame does not leak length (ADR-007 confirmed)")

    print()
    print("  NOT MEASURED: the send TIME channel. Inter packet delay depends on")
    print("  the application and the network. This library does not send")
    print("  packets, so there is no timing here that could be measured. If a")
    print("  transport layer is written, it should be measured there.\n")
    return error


if __name__ == "__main__":
    import sys

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
