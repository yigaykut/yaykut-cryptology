"""Is a covert open network really indistinguishable? Measured, not claimed.

SORU

A member holding their sub network's root secret: can they tell whether their
network is OPEN or the child of a quietly observed COVERT one?

The answer could have been written as "HKDF is pseudorandom, so no". That is
true on paper, but if something slips in the implementation (a fixed byte, a
short seed, a leaking field) the paper will not say so. Hence the measurement.

FOUR ARMS, two of them CONTROLS

  1. REAL         Half children of an open parent, half of a covert one.
                  In a correct implementation, expected: CHANCE (50%, AUC 0.5).

  2. SABOTAGE     Covert children are derived DELIBERATELY wrong (the first
                  two bytes of the root secret are zeroed). The distinguisher
                  MUST catch this at 100%.

                  Without this arm the 50% on the real arm proves nothing: a
                  BLIND distinguisher also gives 50%. The sabotage arm proves
                  the distinguisher can see, and only after that does 50% on
                  the real arm mean "indistinguishable".

  3. EPOCH        Half derived with `epoch(d)`, half freshly created. It
                  tests that rotation (ADR-027 §9) does not give itself away.
                  Expected: CHANCE again.

  4. POSITIVE     The auditor is given the PARENT's secret and
     CONTROL      HKDF(S_parent, label) == S_child is checked directly. It
                  has to be 100%, otherwise covert mode is not working at all.

WHAT THE DISTINGUISHER SEES

Everything the member holds: the 256 bits of the root secret, the descriptor's
mode byte, and the fingerprint of the derived prekey. All the bits are given
RAW so the logistic regression can find any byte level deviation, and the
sabotage arm being caught is the proof of that.

The network specific corpus is NOT a feature, because it derives
deterministically from the same root secret. It carries no new information and would only slow the measurement down.

    python -m layer2.network_attack --round 400
"""

from __future__ import annotations

import argparse

import numpy as np

from crypto.network import AUTH_ENV, Network, NetworkMode, authorise, is_authorised

from .metrics import report_binary, in_chance_band

TAG_FORMAT = "#{}"


# ══════════════════════ sample generation ══════════════════════

def grant_ready() -> bool:
    """Is there authorisation to create a covert network? The measurement needs it.

    This tool has to create a COVERT network, since what it measures is
    whether a covert child can be told from an open one. Without
    authorisation the measurement CANNOT RUN and is not reported as a pass (ADR-029).
    """
    return is_authorised() or authorise()


def _child_root(net: Network, label: str) -> bytes:
    """The root secret `child_network` would produce, without building the object."""
    return net.child_network(label).export()[6:]


SABOTAGE_BYTES = 2


def _sabotaged_root(master: Network, label: str) -> bytes:
    """A DELIBERATELY wrong derivation: the first two bytes are zeroed.

    It never enters real code; it only proves the distinguisher can see.

    WHY TWO WHOLE BYTES: the first version zeroed a single BIT. That signal
    has a theoretical ceiling of 75% (if the bit is 1 it is certainly open,
    if 0 it is covert 2 times in 3), so even a perfect distinguisher could
    not reach 100% and the control could not separate "blind distinguisher"
    from "weak signal". With two bytes zeroed, an open child matching the
    same pattern has probability 1/65536, the ceiling sits at 100% and the control becomes unambiguous.
    """
    raw = bytearray(_child_root(master, label))
    for i in range(SABOTAGE_BYTES):
        raw[i] = 0
    return bytes(raw)


def epoch_samples(round: int) -> tuple[np.ndarray, np.ndarray]:
    """Is an epoch network distinguishable from a freshly created one.

    ADR-027's epoch rotation rests on the same HKDF argument:
    S_d = HKDF(S, "donem" ‖ d) is pseudorandom, so a member whose device is
    loaded with an epoch network cannot see whether it was derived or fresh.
    Since the same rig is already built, that claim gets measured too.
    """
    lines, labels = [], []
    for i in range(round):
        derived = bool(i % 2)
        if derived:
            net = Network.create(NetworkMode.OPEN).epoch(i)
        else:
            net = Network.create(NetworkMode.OPEN)
        lines.append(_attribute(net, net.export()[6:]))
        labels.append(int(derived))
    return np.array(lines, dtype=np.float32), np.array(labels)


def samples(round: int, *, sabotage: bool = False,
            rng: np.random.Generator | None = None
             ) -> tuple[np.ndarray, np.ndarray, list[tuple[Network, str, bytes]]]:
    """(X, y, records) where y=1 is a covert parent's child and y=0 an open one.

    `records` is for the positive control: (parent, label, child_root).
    """
    if not grant_ready():
        raise RuntimeError(
            f"no covert network authorisation, {AUTH_ENV} is not set. "
            f"This measurement has to create a covert network (ADR-029).")
    rng = rng or np.random.default_rng(0)
    lines: list[np.ndarray] = []
    labels: list[int] = []
    records: list[tuple[Network, str, bytes]] = []

    for i in range(round):
        secret = bool(i % 2)
        label = TAG_FORMAT.format(i)
        if secret:
            parent = Network.create(NetworkMode.COVERT)
            root = (_sabotaged_root(parent, label) if sabotage
                    else _child_root(parent, label))
        else:
            parent = Network.create(NetworkMode.OPEN)
            root = _child_root(parent, label)

        child = Network(root, mode=NetworkMode.OPEN)
        lines.append(_attribute(child, root))
        labels.append(int(secret))
        records.append((parent, label, root))

    return np.array(lines, dtype=np.float32), np.array(labels), records


def _attribute(child: Network, root: bytes) -> np.ndarray:
    """Everything the member can see, turned into numbers.

    256 raw bits plus the descriptor's mode byte plus the first bytes of the
    prekey fingerprint. The raw bits are deliberate: if a byte slips, the
    logistic regression finds it, and the sabotage arm confirms that.
    """
    bits = np.unpackbits(np.frombuffer(root, dtype=np.uint8))
    descriptor = child.export()
    p = child.prekey().fingerprint(4).replace("-", "")
    extra = np.array([descriptor[5]] + [int(p[i:i + 2], 16) for i in range(0, 8, 2)],
                     dtype=np.float32) / 255.0
    return np.concatenate([bits.astype(np.float32), extra])


# ══════════════════════ the distinguisher ══════════════════════

def _logistic(X: np.ndarray, y: np.ndarray, step: int = 6000,
              speed: float = 4.0) -> np.ndarray:
    """A small logistic regression, written here to avoid a new dependency.

    Torch was available but is unnecessary at this scale. What matters is
    not the model's power but that the control arm gets caught.
    """
    X = np.hstack([X, np.ones((len(X), 1), dtype=np.float32)])
    w = np.zeros(X.shape[1], dtype=np.float64)
    for _ in range(step):
        p = 1.0 / (1.0 + np.exp(-np.clip(X @ w, -30, 30)))
        w -= speed * (X.T @ (p - y)) / len(X)
    return w


def _score(X: np.ndarray, w: np.ndarray) -> np.ndarray:
    X = np.hstack([X, np.ones((len(X), 1), dtype=np.float32)])
    return 1.0 / (1.0 + np.exp(-np.clip(X @ w, -30, 30)))


def arm(name: str, round: int, *, sabotage: bool = False,
        epoch: bool = False) -> dict:
    """Run one arm: half for training, half for the exam."""
    if epoch:
        X, y = epoch_samples(round)
    else:
        X, y, _ = samples(round, sabotage=sabotage)
    cut = len(X) // 2
    w = _logistic(X[:cut], y[:cut])
    score = _score(X[cut:], w)
    return report_binary(name, y[cut:], (score >= 0.5).astype(int), score)


def positive_control(round: int) -> float:
    """With the PARENT's secret in hand, can the auditor find the covert child.

    A direct derivation check. It has to be 100%; if it is not, covert mode
    is not working and none of the other measurements mean anything.
    """
    _, y, records = samples(round)
    correct = 0
    for (parent, label, root), real in zip(records, y):
        observable = parent.mode.children_observable
        if observable:
            expected = parent.observe(label).export()[6:]
            prediction = int(expected == root)
        else:
            # An open parent cannot derive its own child; no secret attempt
            # matches, so it says "not covert".
            prediction = 0
        correct += int(prediction == real)
    return correct / len(y)


# ══════════════════════ report ══════════════════════

def _line(r: dict) -> str:
    return (f"  {r['name']:<34}{r['accuracy']:8.4f}   "
            f"[{r['low']:.4f}, {r['high']:.4f}]  {r['auc']:6.4f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--round", type=int, default=400)
    a = ap.parse_args()

    if a.round < 40 or a.round % 4:
        print("  --round must be at least 40 and a multiple of 4 (each arm splits into train and exam)")
        return 2

    if not grant_ready():
        print(f"\n  No covert network authorisation: {AUTH_ENV} is not set.")
        print("  This measurement has to create a covert network, so it COULD NOT RUN.")
        print("  A measurement that did not run is not a pass (ADR-029).\n")
        return 2

    print(f"\n  COVERT OPEN NETWORK, DISTINGUISHABILITY ({a.round} samples per arm)\n")

    sabot = arm("control (sabotaged derivation)", a.round, sabotage=True)
    actual = arm("real (covert vs open child)", a.round, sabotage=False)
    epoch = arm("real (epoch network vs fresh network)", a.round, epoch=True)

    print(f"  {'arm':<34}{'accuracy':>8}   {'95% interval':^18}  {'AUC':>6}")
    print(f"  {'-' * 70}")
    print(_line(sabot))
    print(_line(actual))
    print(_line(epoch))

    pk = positive_control(a.round)
    print(f"\n  positive control (the parent has the secret) : {pk:.0%}")

    print()
    error = 0

    # THE CONTROL GATE IS BOUND TO **AUC**, not to accuracy.
    # The first version used `accuracy >= 0.95` and it was FRAGILE: on one
    # run the AUC was 0.9994 while accuracy dropped to 0.9450. The cause was
    # not a blind distinguisher but an uncalibrated 0.5 decision threshold.
    # A logistic regression trained on few samples ranks correctly but does
    # not calibrate probabilities. AUC is threshold independent, so it is
    # the right measure.
    if sabot["auc"] < 0.95:
        print("  x THE SABOTAGE ARM WAS NOT CAUGHT. The distinguisher is blind, so")
        print("    the result on the real arm proves nothing. Fix it first.")
        error = 1
    else:
        print(f"  + the distinguisher can see: it caught the sabotaged derivation "
              f"(AUC {sabot['auc']:.4f})")

    if pk < 1.0:
        print("  x THE POSITIVE CONTROL FAILED. Covert mode cannot re-derive the")
        print("    sub network, so the observation capability does not exist.")
        error = 1
    else:
        print("  + covert mode works: the parent re-derived its sub network")

    if not in_chance_band(epoch):
        print("  x THE EPOCH ARM BEAT CHANCE. An epoch network is distinguishable")
        print("    from a fresh one, so rotation quietly gives itself away.")
        error = 1
    else:
        print("  + an epoch network is indistinguishable from a fresh one")

    if not in_chance_band(actual):
        print("  x THE REAL ARM BEAT CHANCE. A covert network is distinguishable,")
        print("    so the claim that it looks no different from an open one is WRONG.")
        error = 1
    else:
        print("  + the real arm did not beat chance: a covert child cannot be told")
        print("    from an open one (the 95% interval contains 0.5)")

    print()
    return error


if __name__ == "__main__":
    import sys

    # On Windows a redirected stream picks cp1254 and cannot print the box
    # characters. Same reasoning as `exam.py`; it is NOT done at module level,
    # because that breaks pytest's output capture.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
