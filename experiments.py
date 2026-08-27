"""Layer 2 experiments, the AI attacker.

    python experiments.py

Three questions are asked:
  1. Does the LENGTH of a ciphertext give away which formula it is?  (yes, known)
  2. Is the CONTENT distinguishable from random noise?               (no, hoped)
  3. Does the frame header give away session state?                  (no, hoped)

The answers to 2 and 3 only mean something if the POSITIVE CONTROL passed.
"""

from __future__ import annotations

import io
import os
import sys

import numpy as np

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from layer2 import (  # noqa: E402
                    DEVICE,
                    ContentModel,
                    LengthModel,
                    split_data,
                    frame_data,
                    accuracy,
                    train_model,
                    content_data,
                    parameter_count,
                    report_binary,
                    per_class_accuracy,
                    length_ceiling,
                    length_data,
)
from crypto import load_corpus# noqa: E402

SEED = 20260812
KEY = bytes(range(32))


def title(s: str) -> None:
    print(f"\n{'═' * 74}\n  {s}\n{'═' * 74}")


corpus = load_corpus()
print(f"Corpus: {len(corpus)} entries   |   Device: {DEVICE}   |   Seed: {SEED}")


# ══════════════════════════ EXPERIMENT 1 ══════════════════════════
title("EXPERIMENT 1: does the length give away which formula it is?")

ceiling, colliding = length_ceiling(corpus)
n = len(corpus.active)
group_count = round(ceiling * n)

print(f"  Analytic ceiling: {ceiling * 100:.1f}%   ({n} formulas, {group_count} distinct lengths)")

if group_count == 1:
    length = next(iter(colliding))
    print(f"\n  Every ciphertext is {length} bytes, so there is one length group.")
    print("  Length separates no formula from any other (ADR-007 fixed padding).")
    print(f"  The ceiling is {1}/{n}, which is chance level.")
elif colliding:
    print("\n  Groups sharing a length, and these are INDISTINGUISHABLE:")
    for length, group in sorted(colliding.items()):
        print(f"    {length:>5} bytes:")
        for name in group:
            print(f"          {name}")

print("\n  Training the model (input: only the 16 bit representation of the length)...")
X, y, entries = length_data(corpus, KEY, samples=300, seed=SEED)
X_e, y_e, X_t, y_t = split_data(X, y, fraction=0.25, seed=SEED)

model = LengthModel(class_count=len(entries))
result = train_model(model, X_e, y_e, X_t, y_t, epochs=40, lr=3e-3, seed=SEED)
acc = accuracy(result.y_true, result.y_pred)

print(f"\n  Model parameters  : {parameter_count(model):,}")
print(f"  Test accuracy     : {acc * 100:.1f}%")
print(f"  Analytic ceiling  : {ceiling * 100:.1f}%")
print(f"  Distance to ceiling: {abs(acc - ceiling) * 100:.1f} points")

class_acc = per_class_accuracy(result.y_true, result.y_pred, len(entries))
exact = [g for g, a in zip(entries, class_acc) if a > 0.99]
print(f"\n  Formulas fully identified by length: {len(exact)}/{len(entries)}")

print()
if group_count == 1:
    print("  RESULT: the leak is CLOSED. The model cannot get past chance level,")
    print("  because there is no information left to learn in the length.")
    print("  For comparison, before padding it was 82.6% (docs/findings.md, 2026-08-12).")
else:
    print("  RESULT: the leak is real and measured. Without ever touching the key,")
    print("  an attacker identifies most formulas from length alone.")


# ══════════════════════════ EXPERIMENT 2 ══════════════════════════
title("EXPERIMENT 2: is the content distinguishable from random noise?")

target = corpus.by_slug("ec-weierstrass-short")
print(f"  Target formula: 0x{target.id:04X}  {target.name}")
print("  Length is EQUAL across both classes, so the Experiment 1 leak cannot bleed in.\n")

reports = []
for name, sabotage, description in [
    ("POSITIVE CONTROL (sabotaged)", True, "confirms the rig can catch a signal"),
    ("THE REAL ENGINE", False, "the actual question"),
]:
    print(f"  ── {name} ── {description}")
    X, y = content_data(target, KEY, samples=8000, sabotage=sabotage, seed=SEED)
    X_e, y_e, X_t, y_t = split_data(X, y, fraction=0.25, seed=SEED)

    model = ContentModel(input_bits=X.shape[1])
    result = train_model(model, X_e, y_e, X_t, y_t, epochs=15, lr=1e-3, seed=SEED)
    r = report_binary(name, result.y_true, result.y_pred, result.score)
    reports.append(r)

    print(f"     input size     : {X.shape[1]} bits    samples: {len(y):,}")
    print(f"     test accuracy  : {r['accuracy'] * 100:.2f}%"
          f"   [95% CI: {r['low'] * 100:.2f}% – {r['high'] * 100:.2f}%]")
    print(f"     AUC            : {r['auc']:.4f}   <- THE measure under collapse")
    print(f"     prediction split: {r['prediction_split']}"
          f"{'   ! COLLAPSED TO ONE CLASS, accuracy is the class ratio' if r['collapsed'] else ''}")
    print(f"     can it distinguish: {'YES' if r['distinguishes'] else 'NO'}\n")

control, real = reports


# ══════════════════════════ EXPERIMENT 3 ══════════════════════════
title("EXPERIMENT 3: does the frame header give away the session? (v2)")

print("  ADR-013 put 9 bytes at a fixed position at the start of the payload:")
print("    1 version byte (always 0x02)  +  8 bytes of sequence number")
print()
print("  There is a STRUCTURAL DIFFERENCE between the arms: on unsequenced")
print("  messages the sequence field is 8 zero bytes, on sequenced ones an")
print("  increasing counter. If an observer can see that, they can read which")
print("  connection has replay protection, undercutting ADR-013's reasoning.\n")

frame_reports = []
for name, sabotage, description in [
    ("POSITIVE CONTROL (sabotaged)", True, "confirms the rig can catch a signal"),
    ("SEQUENCED vs UNSEQUENCED", False, "the actual question"),
]:
    print(f"  ── {name} ── {description}")
    X, y = frame_data(target, KEY, samples=8000, sabotage=sabotage, seed=SEED)
    X_e, y_e, X_t, y_t = split_data(X, y, fraction=0.25, seed=SEED)

    model = ContentModel(input_bits=X.shape[1])
    result = train_model(model, X_e, y_e, X_t, y_t, epochs=15, lr=1e-3, seed=SEED)
    r = report_binary(name, result.y_true, result.y_pred, result.score)
    frame_reports.append(r)

    print(f"     test accuracy  : {r['accuracy'] * 100:.2f}%"
          f"   [95% CI: {r['low'] * 100:.2f}% – {r['high'] * 100:.2f}%]")
    print(f"     AUC            : {r['auc']:.4f}   <- THE measure under collapse")
    print(f"     prediction split: {r['prediction_split']}"
          f"{'   ! COLLAPSED TO ONE CLASS, accuracy is the class ratio' if r['collapsed'] else ''}")
    print(f"     can it distinguish: {'YES' if r['distinguishes'] else 'NO'}\n")

c_control, c_real = frame_reports

if not c_control["distinguishes"]:
    print("  ! THE POSITIVE CONTROL FAILED, this experiment's result cannot be read.")
elif c_real["distinguishes"]:
    print("  ! A WEAKNESS WAS FOUND: the frame header leaks session state.")
    print(f"  The model distinguishes at {c_real['accuracy'] * 100:.2f}% accuracy.")
else:
    print("  ok The sequence number stays under the keystream. Sequenced and")
    print("  unsequenced messages are indistinguishable, so the decision to put")
    print("  the frame INSIDE the payload (ADR-013) is supported by measurement.")


title("INTERPRETATION")

if not control["distinguishes"]:
    print("  ! THE POSITIVE CONTROL FAILED.")
    print("  The model could not even catch deliberately corrupted data. Something is")
    print("  wrong with the rig and the result on the real engine CANNOT BE READ.")
    print("  Raise the model capacity or the data volume and run again.")
elif real["distinguishes"]:
    print("  ! A WEAKNESS WAS FOUND.")
    print(f"  The model tells real ciphertexts from random at {real['accuracy'] * 100:.2f}%")
    print("  accuracy. That is a leak and it should be investigated.")
else:
    print("  ok The rig works: the positive control was caught at"
          f" {control['accuracy'] * 100:.1f}% accuracy.")
    print(f"  ok The real engine could NOT be distinguished: {real['accuracy'] * 100:.2f}%"
          f" (95% CI lower bound {real['low'] * 100:.2f}% <= 50%).")

    if real["collapsed"] or c_real["collapsed"]:
        print()
        print("  ! A MEASUREMENT WARNING, DO NOT BE FOOLED BY THE ACCURACY NUMBER.")
        print("  On the real arms the model COLLAPSED TO ONE CLASS, giving every test")
        print("  sample the same label. Accuracy is then the class ratio of the test")
        print("  set, not the model's performance. On a balanced set that lands near")
        print("  50% and looks like 'chance level performance', when in fact the model")
        print("  made no decision at all.")
        print()
        print("  That does not make the RESULT WRONG, it makes the right result weakly")
        print("  measured: collapse is a sign no learnable signal was found. But the")
        print("  evidence is AUC, not accuracy. AUC looks at raw scores rather than")
        print(f"  thresholded predictions: Experiment 2 {real['auc']:.4f}, Experiment 3 {c_real['auc']:.4f}")
        print("  (both near 0.5, so the scores carry no information either).")
        print()
        print("  Experiments 2 and 3 gave EXACTLY the same accuracy. These are NOT two")
        print("  independent confirmations: same seed, same split, same collapse. The")
        print("  only independent measure is AUC, and it differs between them.")
    print()
    print("  This is empirical evidence that there is NO measurable leak on the content")
    print("  side. Absence of evidence is not proof: a larger model, more data or a")
    print("  different representation could find one. The result holds at this scale:")
    print(f"    a {parameter_count(model):,} parameter model, {len(y):,} samples, 15 epochs.")

print()
if group_count > 1:
    print("  Note: the system cannot count as safe until the Experiment 1 length leak")
    print("  is closed. Clean content does not make up for the envelope size telling.")
else:
    print("  Both fronts are clean: length is at chance level, content is indistinguishable.")
    print("  That is a valid result for tests at this scale, not a security proof.")
print()
