"""The exam for generated corpus entries: five gates, each with its own control.

    python -m layer2.exam
    python -m layer2.exam --fast        # skip gate 5, no torch needed

WHY AN "EXAM" AND WHY SO STRICT

`generator.py` produces entries that LOOK structurally valid. The word "look"
is critical: being valid by the generator's own criteria proves nothing,
because if the code that generates and the code that validates share the same
assumptions, they are wrong together. So the exam uses the ENGINE's criteria,
not the generator's: the same schema, the same parser, the same sampler, the
same encryption path.

THE FIVE GATES

  1. SCHEMA        formula.schema.json
  2. SEMANTICS     rules the schema cannot express (reference order, type and
                   field agreement, the payload ceiling, id collisions)
  3. SAMPLABLE     are the constraints SATISFIABLE? Generated constraints can
                   contradict each other (`x > 5` and `x < 3`). Rather than
                   proving the contradiction, we try the sampler.
  4. ROUND TRIP    encrypt, decrypt, are the values the same?
  5. INDISTINGUISHABLE  can a model look at a ciphertext and say whether it
                   came from the REAL or the GENERATED corpus?

WHY THE FIFTH GATE EXISTS, tied directly to the project's design

Separating networks with different formula sets only means something if
traffic between networks is indistinguishable. If network A's ciphertext can
be told apart from B's, an attacker partitions the traffic without breaking
the key at all and learns who is in which network. That is the exact opposite
of what compartmentalisation promises.

The expected result is about 50%, meaning it CANNOT tell. The reason should be
known too: the payload is XORed with the HKDF keystream, so the structure of
the plaintext is not visible in the envelope. The gate does not ASSUME that,
it measures it.

THE POSITIVE CONTROL, because an untested exam's verdict cannot be trusted

Every gate is also fed deliberately broken entries that MUST NOT pass. If a
broken entry gets through, the gate is broken and none of that round's
"passed" results mean anything. On gate 5 the control is a sabotaged
ciphertext: if the model cannot catch that, the rig is not working and a 50%
result means "could not be measured" rather than "indistinguishable".
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from crypto.corpus import Corpus, Entry, analyze_params, load_corpus  # noqa: E402
from crypto.errors import CryptoError  # noqa: E402
from crypto.sampler import SamplingError, sample  # noqa: E402
from crypto.wire import PAYLOAD_FIXED_BYTES, decode, encode  # noqa: E402

from layer2.generator import BLOCKED  # noqa: E402

SCHEMA_PATH = ROOT / "corpus" / "formula.schema.json"
GENERATED = ROOT / "generated_corpus" / "formulas"
KEY = bytes(range(32))

GATES = ["schema", "semantics", "samplable", "round-trip"]


@dataclass
class Result:
    """One entry's exam report."""

    slug: str
    entry_id: int
    passed: bool = True
    failed_gate: str | None = None
    reason: str | None = None
    constraint_count: int = 0

    def fail(self, gate: str, reason: str) -> "Result":
        self.passed = False
        self.failed_gate = gate
        self.reason = reason
        return self


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)
    control_errors: list[str] = field(default_factory=list)

    @property
    def passing(self) -> list[Result]:
        return [r for r in self.results if r.passed]

    @property
    def failing(self) -> list[Result]:
        return [r for r in self.results if not r.passed]


# ══════════════════════ GATES 1-4 ══════════════════════

def _schema_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def gate1_schema(raw: dict, dv: Draft202012Validator) -> str | None:
    errors = sorted(dv.iter_errors(raw), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        where = "/".join(str(x) for x in e.path) or "(root)"
        return f"{where}: {e.message}"
    return None


def gate2_semantics(raw: dict, real: Corpus) -> str | None:
    """Rules the schema cannot express."""
    if raw["id"] in BLOCKED:
        return f"0x{raw['id']:04X} is a blocked id"
    if raw["id"] in real:
        return f"0x{raw['id']:04X} collides with the real corpus"

    try:
        bits, errors, warnings = analyze_params(raw)
    except Exception as e:                            # noqa: BLE001
        return f"parameter analysis failed: {type(e).__name__}: {e}"
    # analyze_params returns (bits, ERRORS, warnings). I read that order
    # backwards in the first version, discarding `errors` and looking at
    # `warnings`. That is how the forward reference sabotage entry got through
    # the gate, and the positive control caught it. Errors and warnings are
    # now reported separately.
    if errors:
        return f"semantic error: {errors[0]}"
    if warnings:
        return f"semantic warning: {warnings[0]}"
    if bits > PAYLOAD_FIXED_BYTES * 8:
        return f"payload is {bits} bits; the ceiling is {PAYLOAD_FIXED_BYTES * 8}"
    return None


def gate3_samplable(entry: Entry, rng: random.Random) -> tuple[str | None, dict]:
    """Are the constraints satisfiable?

    It uses `sample` rather than `sample_or_free`. Falling back to an
    unconstrained value is not a success here, it is exactly the failure we
    want to catch.
    """
    try:
        return None, sample(entry, rng, max_rejections=2000)
    except SamplingError as e:
        return f"constraints unsatisfiable: {e}", {}
    except CryptoError as e:
        return f"sampling error: {type(e).__name__}: {e}", {}


def gate4_round_trip(entry: Entry, corpus: Corpus, values: dict) -> str | None:
    try:
        blob = encode(entry, values, KEY, check=True)
    except CryptoError as e:
        return f"encryption refused: {type(e).__name__}: {e}"
    if len(blob) != PAYLOAD_FIXED_BYTES + 16 + 2 + 32:
        return f"unexpected ciphertext size: {len(blob)}"
    try:
        back, back_values = decode(corpus, blob, KEY)
    except CryptoError as e:
        return f"decoding refused: {type(e).__name__}: {e}"
    if back.id != entry.id:
        return f"id changed: 0x{entry.id:04X} -> 0x{back.id:04X}"

    for p in entry.params:
        if p.get("role", "public") != "public":
            continue
        name = p["name"]
        if back_values.get(name) != values.get(name):
            return (f"{name} changed on the round trip: "
                    f"{values.get(name)!r} -> {back_values.get(name)!r}")
    return None


def _make_entry(raw: dict) -> Entry:
    return Entry(
        id=raw["id"], slug=raw["slug"], version=raw["version"],
        status=raw["status"], doc=raw["doc"], params=raw["params"],
        constraints=raw.get("constraints") or [],
        sampler=raw.get("sampler") or {}, source=None,
    )


def exam_1_4(raws: list[dict], real: Corpus, seed: int = 0) -> Report:
    """Runs the first four gates."""
    dv = _schema_validator()
    rng = random.Random(seed)
    report = Report()

    # Decoding needs a corpus holding the real entries and the candidates.
    candidates = []
    for raw in raws:
        try:
            candidates.append(_make_entry(raw))
        except Exception:                             # noqa: BLE001
            pass
    try:
        combined = Corpus(list(real) + candidates)
    except Exception:                                 # noqa: BLE001
        combined = real

    for raw in raws:
        r = Result(slug=raw.get("slug", "?"), entry_id=raw.get("id", 0),
                   constraint_count=len(raw.get("constraints") or []))

        error = gate1_schema(raw, dv)
        if error:
            report.results.append(r.fail("schema", error))
            continue

        error = gate2_semantics(raw, real)
        if error:
            report.results.append(r.fail("semantics", error))
            continue

        entry = _make_entry(raw)
        error, values = gate3_samplable(entry, rng)
        if error:
            report.results.append(r.fail("samplable", error))
            continue

        error = gate4_round_trip(entry, combined, values)
        if error:
            report.results.append(r.fail("round-trip", error))
            continue

        report.results.append(r)
    return report


# ══════════════════════ POSITIVE CONTROL (gates 1-4) ══════════════════════

def sabotage_entries() -> list[tuple[str, str, dict]]:
    """Triples of (name, THE GATE IT SHOULD FAIL AT, entry).

    Each targets a single gate. If one of them PASSES the exam, that gate is
    not working and none of that round's "passed" results can be trusted.
    """
    base = {
        "id": 0x02F0, "slug": "sabotage", "version": 1, "status": "active",
        "doc": {"name": "Sabotage", "latex": "x", "domain": "modular-arithmetic",
                "summary": "A control entry."},
        "params": [{"name": "x", "type": "uint", "bits": 16, "role": "public"}],
        "constraints": [], "sampler": {"strategy": "uniform_valid"},
    }

    def copy(**changes) -> dict:
        d = json.loads(json.dumps(base))
        d.update(changes)
        return d

    return [
        ("invalid slug", "schema",
         copy(id=0x02F1, slug="Gecersiz_Slug")),

        ("unknown type", "schema",
         copy(id=0x02F2, params=[{"name": "x", "type": "quantum",
                                  "bits": 16, "role": "public"}])),

        ("blocked id", "semantics", copy(id=0x0501)),

        ("forward reference", "semantics",
         copy(id=0x02F3, params=[
             {"name": "a", "type": "field_element", "bits": 32,
              "mod": "p", "role": "public"},
             {"name": "p", "type": "prime", "bits": 32, "role": "public"},
         ])),

        ("payload ceiling exceeded", "semantics",
         copy(id=0x02F4, params=[
             {"name": f"x{i}", "type": "uint", "bits": 8192, "role": "public"}
             for i in range(16)])),

        ("contradictory constraints", "samplable",
         copy(id=0x02F5, constraints=[
             {"expr": "x > 5000", "reason": "control", "severity": "error"},
             {"expr": "x < 3", "reason": "control", "severity": "error"},
         ])),
    ]


def control_1_4(real: Corpus) -> list[str]:
    """Do the sabotaged entries fail at the expected gate?"""
    errors: list[str] = []
    for name, expected, raw in sabotage_entries():
        report = exam_1_4([raw], real)
        r = report.results[0]
        if r.passed:
            errors.append(f"{name!r} PASSED THE EXAM, gate {expected!r} is not working")
        elif r.failed_gate != expected:
            errors.append(
                f"{name!r} should have failed at gate {expected!r}, "
                f"failed at {r.failed_gate!r} instead ({r.reason})")
    return errors


# ══════════════════════ GATE 5, DISTINGUISHABILITY ══════════════════════

def gate5_distinguishability(real_entries: list[Entry],
                             generated_entries: list[Entry],
                             *, samples: int = 4000, epochs: int = 12,
                             seed: int = 0) -> dict:
    """Can a model look at a ciphertext and say which corpus it came from?

    Label 1 is a real corpus entry, 0 a generated one. Both arms use the SAME
    key, the SAME envelope and the SAME fixed length; the only difference is
    the plaintext inside the payload.

    In the returned dict, the control is the positive control: when the
    generated arm is deliberately corrupted, the model MUST catch it. If it
    cannot, the 50% on the real measurement means "could not be measured"
    rather than "indistinguishable".
    """
    import numpy as np

    from layer2.train import train_model
    from layer2.model import ContentModel
    from layer2.metrics import report_binary
    from layer2.data import to_bits, sabotaged_ciphertext, ciphertext

    rng = random.Random(seed)
    half = samples // 2

    def arm(entries: list[Entry], sabotage: bool = False) -> list[bytes]:
        producer = sabotaged_ciphertext if sabotage else ciphertext
        return [producer(rng.choice(entries), KEY, rng) for _ in range(half)]

    def run(sabotage: bool, run_seed: int) -> dict:
        a = arm(real_entries)
        b = arm(generated_entries, sabotage=sabotage)
        X = to_bits(a + b)
        y = np.concatenate([np.ones(half, np.int64), np.zeros(half, np.int64)])
        p = np.random.default_rng(run_seed).permutation(len(y))
        X, y = X[p], y[p]

        cut = int(len(y) * 0.8)
        result = train_model(ContentModel(input_bits=X.shape[1]),
                             X[:cut], y[:cut], X[cut:], y[cut:],
                             epochs=epochs, seed=run_seed)
        return report_binary("distinguish", result.y_true, result.y_pred, result.score)

    real_arm = run(sabotage=False, run_seed=seed)
    control_arm = run(sabotage=True, run_seed=seed + 1)
    return {"real": real_arm, "control": control_arm}


# ══════════════════════ REPORTING ══════════════════════

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--directory", type=Path, default=GENERATED)
    ap.add_argument("--fast", action="store_true",
                    help="skip gate 5, no torch needed")
    ap.add_argument("--samples", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    if not a.directory.is_dir():
        print(f"no such directory: {a.directory}\n"
              f"Run `python -m layer2.generator` first.")
        return 2

    raws = []
    for path in sorted(a.directory.glob("*.yaml")):
        raws.append(yaml.safe_load(path.read_text(encoding="utf-8")))
    if not raws:
        print(f"{a.directory} is empty.")
        return 2

    real = load_corpus()

    print(f"\n{'═' * 74}")
    print("  GENERATED CORPUS EXAM")
    print(f"{'═' * 74}")
    print(f"\n  real corpus  : {len(real)} entries")
    print(f"  sitting exam : {len(raws)} entries")

    # The positive control comes first. If the exam is broken there is no
    # point printing results at all.
    print("\n  -- positive control (gates 1-4) --")
    control_errors = control_1_4(real)
    if control_errors:
        print("  !! THE EXAM IS BROKEN, sabotaged entries did not fail as expected:")
        for e in control_errors:
            print(f"     {e}")
        print("\n  Results withheld: a broken exam's verdict is not information.")
        return 1
    print(f"  all {len(sabotage_entries())} sabotaged entries failed at the "
          f"expected gate.")

    # The real exam
    report = exam_1_4(raws, real, seed=a.seed)
    print("\n  -- gates 1-4 --")
    for gate in GATES:
        failed = [r for r in report.failing if r.failed_gate == gate]
        print(f"  {gate:<16} failed: {len(failed)}")
    print(f"  {'PASSED':<16} {len(report.passing)} / {len(raws)}")

    if report.failing:
        print("\n  examples of failures:")
        for r in report.failing[:6]:
            print(f"    {r.slug:<40} [{r.failed_gate}] {r.reason}")
        if len(report.failing) > 6:
            print(f"    ... and {len(report.failing) - 6} more")

    passing_slugs = {r.slug for r in report.passing}
    passing_entries = [_make_entry(h) for h in raws if h.get("slug") in passing_slugs]

    if not passing_entries:
        print("\n  No entry passed the first four gates; gate 5 cannot run.")
        return 1

    if a.fast:
        print("\n  -- gate 5 skipped (--fast) --")
        return 0

    print("\n  -- gate 5: distinguishability --")
    print("  question: can a model look at a ciphertext and tell which corpus it came from?")
    try:
        r = gate5_distinguishability(
            list(real.active), passing_entries,
            samples=a.samples, seed=a.seed)
    except ImportError as e:
        print(f"  torch or numpy missing, skipped: {e}")
        return 0

    real_arm, control_arm = r["real"], r["control"]
    print(f"\n  {'arm':<28}{'accuracy':>10}{'95% interval':>20}{'AUC':>8}")
    for name, d in (("real (genuine vs generated)", real_arm),
                    ("control (sabotaged arm)", control_arm)):
        interval = f"[{d['low']:.4f}, {d['high']:.4f}]"
        print(f"  {name:<28}{d['accuracy']:>9.4f}{interval:>20}{d['auc']:>8.4f}")

    control_worked = control_arm["distinguishes"]
    real_leaks = real_arm["distinguishes"]

    print()
    if not control_worked:
        print("  !! THE POSITIVE CONTROL FAILED. The model could not even catch")
        print("     the sabotaged arm. The rig is not working, so the result on")
        print("     the real arm means 'could not be measured', NOT")
        print("     'indistinguishable'.")
        return 1

    print("  positive control passed: the rig catches a signal when there is one.")
    if real_leaks:
        print("\n  !! THE GENERATED CORPUS IS DISTINGUISHABLE.")
        print("     Accuracy beats chance statistically. That destroys the point of")
        print("     separating networks by formula set: an attacker can partition")
        print("     the traffic without ever breaking the key.")
        return 1

    print("\n  The generated corpus could NOT be told apart from the real one.")
    print("  That was the expected result and the reason is known: the payload is")
    print("  XORed with the HKDF keystream, so the structure of the plaintext is")
    print("  not visible in the envelope.")
    print()
    print("  CAREFUL, what this does not say: the measurement does not show that")
    print("  generated entries are 'safe'. Safety comes from the envelope, not")
    print("  from the entry. The only thing measured is that the entry ADDS NO")
    print("  EXTRA LEAK to the envelope.")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
