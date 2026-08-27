"""Training data for the distinguisher.

TWO SEPARATE EXPERIMENTS, TWO SEPARATE QUESTIONS

Experiment 1: does the LENGTH of a ciphertext say which formula it is?
    The model sees only the length and picks one of 34 classes.
    It TURNS THE KNOWN GAP IN ADR-002 INTO A NUMBER.
    Expected: high accuracy. That is bad news and it is already known.

Experiment 2: is the CONTENT of a ciphertext distinguishable from random noise?
    The model sees the raw bits and says "real or random".
    Length is EQUALISED so the leak from Experiment 1 cannot bleed in.
    Expected: about 50%, meaning it cannot tell. That is good news.

WHY A POSITIVE CONTROL IS ESSENTIAL
In Experiment 2 a result of 50% proves nothing on its own. The same number
could come from a model that is too weak, from too little data, or from a
broken pipeline. So there is a third arm: deliberately SABOTAGED ciphertexts.
If the model can catch those, the rig works, and only then does the 50% on
the real cipher mean anything.
"""

from __future__ import annotations

import os
import random

import numpy as np

from crypto import Corpus, Entry, encode, sample_or_free, ciphertext_length
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES

# The fixed signature written at the start of the payload on the sabotage arm.
# It is an artificial signal, there to prove the rig can catch one when it exists.
SABOTAGE_BYTES = 8


def ciphertext(entry: Entry, key: bytes, rng: random.Random) -> bytes:
    values, _ = sample_or_free(entry, rng)
    return encode(entry, values, key, check=False)


def sabotaged_ciphertext(entry: Entry, key: bytes, rng: random.Random) -> bytes:
    """A ciphertext whose first payload bytes have been zeroed.

    THE POSITIVE CONTROL. It is not something the real engine produces; it is
    deliberately corrupted data confirming the rig can learn.
    """
    blob = bytearray(ciphertext(entry, key, rng))
    start = NONCE_BYTES + SELECTOR_BYTES
    for i in range(start, min(start + SABOTAGE_BYTES, len(blob) - 32)):
        blob[i] = 0
    return bytes(blob)


def to_bits(blobs: list[bytes]) -> np.ndarray:
    """Turns byte strings into a [N, length*8] matrix of 0s and 1s."""
    array = np.frombuffer(b"".join(blobs), dtype=np.uint8).reshape(len(blobs), -1)
    return np.unpackbits(array, axis=1).astype(np.float32)


# ---------------- Experiment 1: the formula from the length ----------------

def length_data(
    corpus: Corpus,
    key: bytes,
    *,
    samples: int = 300,
    seed: int = 0,
) -> tuple[np.ndarray, np.ndarray, list[Entry]]:
    """Produces ciphertexts for every formula, using ONLY the length as a feature.

    The length is given as a 16 bit binary value. The input carries exactly
    the length and nothing more, so the model can see nothing else.

    Returns (X [N, 16], y [N], entries).
    """
    rng = random.Random(seed)
    entries = corpus.active

    lengths: list[int] = []
    labels: list[int] = []
    for cls, entry in enumerate(entries):
        for _ in range(samples):
            lengths.append(len(ciphertext(entry, key, rng)))
            labels.append(cls)

    u = np.array(lengths, dtype=np.uint16)
    X = np.unpackbits(u.view(np.uint8).reshape(-1, 2)[:, ::-1], axis=1).astype(np.float32)
    return X, np.array(labels, dtype=np.int64), entries


def length_ceiling(corpus: Corpus) -> tuple[float, dict[int, list[str]]]:
    """Computes analytically the HIGHEST accuracy obtainable from length.

    If k formulas share a length, the best strategy is guessing and each is
    identified with probability 1/k. The model cannot beat that ceiling; if it
    does, there is leakage in the data.

    Grouping uses the ACTUAL TRANSMITTED length rather than the logical
    payload size. After ADR-007's fixed padding every entry falls into a
    single group and the ceiling drops to 1/N, which is chance level.

    Returns (ceiling, {length: [colliding entries]}).
    """
    entries = corpus.active
    groups: dict[int, list[str]] = {}
    for e in entries:
        groups.setdefault(ciphertext_length(e), []).append(f"0x{e.id:04X} {e.name}")

    # If k formulas share a length, each is identified with probability 1/k, so
    # the group contributes k * (1/k) = 1. The ceiling is groups / entries.
    correct = len(groups)
    colliding = {u: g for u, g in groups.items() if len(g) > 1}
    return correct / len(entries), colliding


# --------------- Experiment 2: is the content really random ---------------

def content_data(
    entry: Entry,
    key: bytes,
    *,
    samples: int = 6000,
    sabotage: bool = False,
    seed: int = 0,
) -> tuple[np.ndarray, np.ndarray]:
    """A length equalised "real or random" data set.

    Half is ciphertext from the engine (label 1) and half is pure random bytes
    of the same length (label 0). Because the length is IDENTICAL across both
    classes, the leak from Experiment 1 cannot bleed in.

    With sabotage=True, deliberately corrupted texts replace the real arm,
    which is the positive control.
    """
    rng = random.Random(seed)
    producer = sabotaged_ciphertext if sabotage else ciphertext

    half = samples // 2
    real = [producer(entry, key, rng) for _ in range(half)]
    length = len(real[0])
    random_bytes = [os.urandom(length) for _ in range(half)]

    X = to_bits(real + random_bytes)
    y = np.concatenate([np.ones(half, np.int64), np.zeros(half, np.int64)])

    shuffled = np.random.default_rng(seed).permutation(len(y))
    return X[shuffled], y[shuffled]


# ----------- Experiment 3: does the frame header leak (v2) -----------

def frame_data(
    entry: Entry,
    key: bytes,
    *,
    samples: int = 6000,
    sabotage: bool = False,
    seed: int = 0,
) -> tuple[np.ndarray, np.ndarray]:
    """Are sequenced and unsequenced ciphertexts distinguishable.

    ADR-013 put a 9 byte frame at a fixed position at the start of the
    payload: 1 version byte (always 0x02) plus an 8 byte sequence number. That
    raised A NEW QUESTION, and it cannot be waved away with an assumption:

      - The version byte is constant, known plaintext against the keystream.
      - The sequence number is 8 zero bytes on unsequenced messages and an
        increasing counter on sequenced ones. There IS a structural difference
        between the two arms.

    If an observer can see that difference, they can read which connection has
    replay protection, and even how many messages it has sent, which undercuts
    ADR-013's reason for putting the sequence number inside the payload.

    Label 1 means sequenced (1..N), label 0 means unsequenced (sequence 0).
    The length is the same on both arms, so content is the only thing that
    could distinguish them.

    With sabotage=True, deliberately corrupted texts replace the sequenced arm
    (the positive control, see the module header).
    """
    rng = random.Random(seed)
    half = samples // 2

    if sabotage:
        sequenced = [sabotaged_ciphertext(entry, key, rng) for _ in range(half)]
    else:
        sequenced = []
        for i in range(1, half + 1):
            values, _ = sample_or_free(entry, rng)
            sequenced.append(encode(entry, values, key, check=False, seq=i))

    unsequenced = [ciphertext(entry, key, rng) for _ in range(half)]

    X = to_bits(sequenced + unsequenced)
    y = np.concatenate([np.ones(half, np.int64), np.zeros(half, np.int64)])

    shuffled = np.random.default_rng(seed).permutation(len(y))
    return X[shuffled], y[shuffled]


def split_data(X: np.ndarray, y: np.ndarray, fraction: float = 0.2, seed: int = 0):
    """Train and test split. The test set is NEVER seen during training."""
    idx = np.random.default_rng(seed).permutation(len(y))
    cut = int(len(y) * (1 - fraction))
    train, test = idx[:cut], idx[cut:]
    return X[train], y[train], X[test], y[test]
