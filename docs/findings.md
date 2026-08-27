# Layer 2 Findings

Run with `python experiments.py` · Seed `20260812` · Device CPU · Last measured 2026-08-18

The neural network does not decrypt here, it **audits** the cipher (ADR-001).
Three independent questions were asked. Experiment 1 ran twice, once to measure
a leak and once to confirm that closing it worked. Experiment 3 measures the new
question raised by the v2 frame header (ADR-013).

Every experiment has a **positive control**, a deliberately corrupted arm. If
the rig cannot catch that, the result on the real arm cannot be interpreted.

---

## Experiment 1: does the length give away which formula was used?

The model was given **only the length of the ciphertext**, as a 16 bit binary
value, and asked which of the 34 formulas it was.

### Result, before and after fixed padding

> **Update 2026-08-15.** The v2 column below was measured on a 34 formula
> corpus. The corpus grew to 53 entries and the frame header was added
> (ADR-013), so the experiment was repeated. Analytic ceiling **1.9%** (1/53),
> model accuracy **1.3%**, formulas recognised by length **1/53**, distinct
> lengths observed **1** (1339 bytes). Same conclusion, the leak is closed.

| | v1, variable length | v2, fixed padding (ADR-007) |
|---|---|---|
| Analytic ceiling | 82.4% | **2.9%** (1/34, chance) |
| Model test accuracy | **82.6%** | **2.1%** |
| Fully recognised formulas | 28/34 | 1/34 |
| Distinct lengths observed | 28 | **1** |

**In v1** the model sat right on the theoretical ceiling, meaning everything
extractable from length had been extracted. An attacker never touched the key
and still identified 28 of 34 formulas from the size of the envelope alone.

**In v2** every ciphertext has the same length (1330 in that version, 1339
after the frame header, see ADR-013). The model cannot beat chance because
there is nothing left to learn in the length.

### Groups that were already indistinguishable in v1 (historical)

Even before fixed padding these groups could not be separated by length:

| Payload | Colliding formulas |
|---|---|
| 1 byte | `0x0501` Caesar, `0x0502` Affine |
| 4 bytes | `0x0203` RSA private exponent, `0x0503` Vigenere |
| 96 bytes | `0x0101` Weierstrass, `0x0103` Montgomery, `0x0104` Edwards, `0x0208` modular inverse |
| 256 bytes | `0x0202` Euler totient, `0x0204` RSA-CRT |

---

## Experiment 2: is the content distinguishable from random noise?

Target `0x0101`, short Weierstrass. The model saw the raw bits and was asked
whether they were a real ciphertext or pure random bytes.

**Length was equalised across both classes**, so the leak from Experiment 1
could not bleed into this one.

| Arm | Accuracy | 95% CI | AUC | Prediction split | Distinguishes |
|---|---|---|---|---|---|
| Positive control (sabotaged) | 100.00% | 99.81 - 100.00% | 1.0000 | balanced | **YES** |
| Real engine | 49.70% | 47.51 - 51.89% | **0.478 - 0.518** | **[0, 2000]** | **NO** |

Input size is 10,712 bits, after the v2 frame header.

### Why the positive control is there

Saying "it came out at 49.70%, so it is safe" is **not a valid inference** on
its own. The same number could come from a model that is too weak, from too
little data, or from a broken pipeline. So a second arm ran on deliberately
corrupted data, ciphertexts whose first 8 payload bytes were zeroed.

The model caught that at **100% accuracy**. Only once the rig has proven it can
see a signal does the result on the real engine mean anything.

### Amendment 2026-08-15: the accuracy number was misleading

This report presented 49.70% as "chance level performance" from 2026-08-12
onwards. **That reading was too generous, and rerunning the measurement showed
it.**

On the real arm the model **collapses to a single class**, giving all 2000 test
samples the same label.

```
prediction split : [0, 2000]     <- not one "random" prediction
test labels      : [1006, 994]
accuracy         : 994 / 2000 = 49.70%
```

So **49.70% is the class ratio of the test set, not the model's performance.**
The model is not flipping a coin, it is not deciding at all. On a balanced set
that always lands near 50% and looks like chance.

**The conclusion does not change, but its evidence does.** Collapse is a sign
that no learnable signal was found, which is the right answer. The measure that
says so is **AUC**, not accuracy. AUC looks at the raw scores rather than
thresholded predictions, so it still carries information from a collapsed model.

| Measure | Value | Valid under collapse |
|---|---|---|
| Accuracy | 49.70% | **No**, it reflects the class ratio |
| Confidence interval | 47.51 - 51.89% | No, it is built on accuracy |
| **AUC** | **0.478 - 0.518** (6 runs) | **Yes**, this is the real evidence |

The positive control stays valid. The same model with the same
hyperparameters reaches 100% on sabotaged data and predicts both classes. The
collapse is therefore not a training failure, it is the result of having
nothing to learn.

`layer2.coktu_mu()` now reports this automatically, and `experiments.py` prints
the prediction split together with an explicit warning. It will not slip
through quietly again.

---

## Experiment 3: does the frame header give away session state? (v2)

ADR-013 put 9 bytes at a fixed position at the start of the payload: 1 version
byte, always `0x02`, plus an 8 byte sequence number. That raised a **new
question**.

There is a real structural difference between the two arms:

| Arm | Contents of the sequence field |
|---|---|
| Unsequenced message (label 0) | 8 zero bytes |
| Sequenced message (label 1) | increasing counter, 1..N |

If that difference is visible from outside, an eavesdropper can tell **which
connection has replay protection**, and even how many messages it has sent.
That would undercut ADR-013's reason for putting the frame inside the payload
in the first place.

| Arm | Accuracy | 95% CI | AUC | Prediction split | Distinguishes |
|---|---|---|---|---|---|
| Positive control (sabotaged) | 100.00% | 99.81 - 100.00% | 1.0000 | balanced | **YES** |
| Sequenced vs unsequenced | 49.70% | 47.51 - 51.89% | **0.496 - 0.513** | **[0, 2000]** | **NO** |

**No leak found.** The sequence number stays under the keystream and sequenced
messages cannot be told apart from unsequenced ones. ADR-013 holds up under
measurement.

### Why the two experiments give exactly the same accuracy

Experiment 2 and Experiment 3 report the same accuracy, 49.70%, and the same
confidence interval. **These are not two independent confirmations.** The same
seed produces the same split, both models collapse to one class, so both report
the same class ratio.

AUC is the only independent measure here, and it moves from run to run. Six
runs of each:

| Experiment | AUC values | Range | Median |
|---|---|---|---|
| 2, content | 0.5184 · 0.5007 · 0.4950 · 0.4977 · 0.4921 · 0.4784 | 0.478 - 0.518 | **0.4963** |
| 3, frame | 0.5129 · 0.4963 · 0.4976 · 0.5089 · 0.5024 · 0.5070 | 0.496 - 0.513 | **0.5047** |

Both distributions sit around 0.5 and contain it. The raw scores carry no
information.

### Collapse does not happen every run, and that strengthens the result

Across the spread runs, **two out of four** runs in each experiment did not
collapse (`coktu=False`). Accuracy in those runs still came out at 49.55 -
49.80%.

That matters. Chance level accuracy is **not merely a side effect of
collapse**. Even when the model does decide, it cannot tell the classes apart.
Collapse is the most extreme symptom of there being no signal, not the only
one.

---

## Limits of this result

Absence of evidence is not proof. The result holds only at this scale:

- Model: 69,314 parameters, 1D convolution plus fully connected
- Data: 8,000 samples, 25% held out
- Training: 15 epochs, Adam, lr=1e-3

A larger model, more data or a different input representation could find a
leak. If one does, that is not a failure, it is the layer doing its job.

### Reproducibility is partial, deliberately

**Amendment 2026-08-18.** This section used to say that `python experiments.py`
reproduces the same numbers under the same seed. **That is not true for AUC.**

In Experiments 2 and 3 the random arm comes from `os.urandom` and is **not
seeded**. It could be, but then the comparison would be weaker. The question
asked is whether a ciphertext is distinguishable from **real** randomness, not
from a pseudorandom source. A fixed seed would give that comparison a structure
of its own.

So the things the seed fixes (the sampler, the train/test split, the weight
initialisation) are identical every run, while the random arm differs every
run. Which means:

- **accuracy** comes out the same every run, but only because the model
  collapses, and a collapsed model's accuracy is the class ratio regardless of
  the data;
- **AUC** varies run to run, because the raw scores really are looking at
  different data.

AUC should therefore be read from its **spread**, never from a single run.

---

## Overall

| Front | v1 | v2 (current, 2026-08-18) |
|---|---|---|
| Length, envelope size | **82.4% leak** | chance level (1.3%, ceiling 1.9%) |
| Content, payload, selector, tag | no leak | no leak (AUC 0.478 - 0.518) |
| Frame header, session state | not present in v1 | no leak (AUC 0.496 - 0.513) |

All three fronts are clean against tests at this scale. Worth repeating that
this is not a security proof. It says only that no measurable leak was found on
the known attack surfaces.

**Unmeasured fronts.** These experiments look at a single ciphertext. Not
measured: timing, meaning when packets are sent, packet counts, side channels
in the X25519 handshake, and patterns visible across the traffic as a whole. A
fixed size envelope closes the size channel, not the time channel.

**The price paid.** The 1 byte of data in a Caesar cipher travels as a full
envelope. That is the cost of closing the length leak completely (ADR-007).

---

## Environment note

The installed PyTorch is the **CPU build** (`2.10.0+cpu`), so the machine's RTX
4050 goes unused. At this scale that is fine, the experiments all finish in
minutes on CPU. Larger distinguisher runs would need the CUDA wheel
reinstalled.
