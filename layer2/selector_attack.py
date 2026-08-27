"""How much does the prekey actually protect? A measurement, not a claim.

    python -m layer2.selector_attack

THE ATTACK MODEL

The attacker **has the master key K but not the prekey P**. That is exactly
the scenario ADR-026 promises: even if K falls, which formula was carried
stays secret.

But an attacker with K can decrypt the payload, because the payload keystream
comes from K, not from P. They hold the formula's PARAMETERS and only lack
which formula they belong to. The corpus is public too (ADR-025).

So they can try this:

    for each candidate formula:
        parse the payload against THAT formula's parameter layout
        check its constraints
        if the parse is consistent and the constraints hold -> a candidate

How many candidates are left? If only one, the prekey gives this attacker
NOTHING. This tool measures that number.

WHY I WROTE THIS TOOL

After writing the prekey I could have said "someone with K cannot learn the
formula" and it would have sounded right. The only thing that says whether it
is right is a measurement. Attacking a defence before claiming it works has
become the rule in this project (ADR-018, ADR-022, ADR-023).

THE POSITIVE CONTROL

The same attack also runs in the case where P IS KNOWN. There the attacker's
accuracy has to be 100%, since the selector opens directly. If it is not, the
rig is broken and the number on the arm without P is meaningless too.
"""

from __future__ import annotations

import argparse
import math
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto import frame as frame_module  # noqa: E402
from crypto import primitives, load_corpus# noqa: E402
from crypto.constraints import check_all  # noqa: E402
from crypto.corpus import Corpus, Entry  # noqa: E402
from crypto.errors import CryptoError  # noqa: E402
from crypto.prekey import Prekey  # noqa: E402
from crypto.sampler import sample_or_free  # noqa: E402
from crypto.wire import (  # noqa: E402
                         NONCE_BYTES,
                         SELECTOR_BYTES,
                         TAG_BYTES,
                         deserialize,
                         encode,
)

KEY = bytes(range(32))


def candidates(corpus: Corpus, body: bytes) -> list[Entry]:
    """Which formulas can consistently explain the payload body?

    That is the only information the attacker has: the raw body bytes. For
    each candidate formula it tries to parse the body against that formula's
    parameter layout; if the parse holds and the constraints do, it is a candidate.
    """
    output = []
    for e in corpus.active:
        try:
            values = deserialize(e, body)
        except Exception:                              # noqa: BLE001
            continue                                   # this layout does not fit
        try:
            if check_all(e.constraints, values, skip_unknown=True):
                pass                                   # a warning only
        except CryptoError:
            continue                                   # constraint violation
        except Exception:                              # noqa: BLE001
            continue
        output.append(e)
    return output


def attack(corpus: Corpus, round: int, seed: int,
           prekey_known: bool) -> dict:
    """Generates that many messages and runs the attack."""
    rng = random.Random(seed)
    p = Prekey.generate()
    active = corpus.active

    correct = 0
    unique = 0
    candidate_counts: Counter = Counter()

    try:
        for _ in range(round):
            e = rng.choice(active)
            values, valid = sample_or_free(e, rng, max_rejections=200)
            blob = encode(e, values, KEY, check=False, prekey=p)

            nonce = blob[:NONCE_BYTES]
            selector = blob[NONCE_BYTES:NONCE_BYTES + SELECTOR_BYTES]
            payload_ct = blob[NONCE_BYTES + SELECTOR_BYTES:-TAG_BYTES]

            # The attacker has K: derive the payload stream and open the body.
            _sm, ks, _mk = primitives.subkeys(KEY, nonce, len(payload_ct))
            _c, body = frame_module.unwrap(primitives.xor(payload_ct, ks))

            if prekey_known:
                # POSITIVE CONTROL: with P known the selector opens directly.
                mask = p.mask(nonce, SELECTOR_BYTES)
                identity = int.from_bytes(primitives.xor(selector, mask), "big")
                found = [x for x in active if x.id == identity]
            else:
                found = candidates(corpus, body)

            candidate_counts[len(found)] += 1
            if len(found) == 1:
                unique += 1
            if any(x.id == e.id for x in found):
                correct += 1
    finally:
        p.close()

    return {
        "tur": round,
        "correct_in_candidates": correct / round,
        "narrowed_to_one": unique / round,
        "avg_candidates": sum(k * v for k, v in candidate_counts.items()) / round,
        "distribution": dict(sorted(candidate_counts.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--round", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()

    corpus = load_corpus()
    n = len(corpus.active)

    print(f"\n{'═' * 74}")
    print("  PREKEY ATTACK: K held, P not held")
    print(f"{'═' * 74}")
    print(f"\n  corpus       : {n} active formulas (public, ADR-025)")
    print(f"  rounds       : {a.round}")
    print(f"  blind guess  : {100 / n:.2f}%")

    print("\n  -- positive control: P IS KNOWN --")
    k = attack(corpus, min(a.round, 100), a.seed, prekey_known=True)
    print(f"  correct formula found : {k['correct_in_candidates'] * 100:.2f}%")
    if k["correct_in_candidates"] < 0.999:
        print("  !! THE POSITIVE CONTROL FAILED. The rig is broken, the numbers mean nothing.")
        return 1
    print("  the rig works.")

    print("\n  -- the real attack: P IS NOT KNOWN --")
    r = attack(corpus, a.round, a.seed, prekey_known=False)
    print(f"  correct formula in the candidate list : {r['correct_in_candidates'] * 100:.2f}%")
    print(f"  narrowed to ONE candidate            : {r['narrowed_to_one'] * 100:.2f}%")
    print(f"  average candidate count              : {r['avg_candidates']:.2f} / {n}")
    print(f"  candidate count distribution         : {r['distribution']}")

    # The real measure is uncertainty in BITS; percentages can mislead.
    blind_bits = math.log2(n)
    remaining_bits = math.log2(r["avg_candidates"]) if r["avg_candidates"] > 0 else 0.0
    print()
    print("  -- uncertainty, from the attacker's point of view --")
    print(f"  no prekey, K held            : {0.0:5.2f} bits  (they know exactly)")
    print(f"  prekey present + this attack : {remaining_bits:5.2f} bits")
    print(f"  blind guess (upper bound)    : {blind_bits:5.2f} bits  (log2 {n})")
    print(f"  what the attack strips       : {blind_bits - remaining_bits:5.2f} bits")

    print("\n" + "─" * 74)
    if r["narrowed_to_one"] > 0.5:
        print("  RESULT: with the CORPUS PUBLIC, the prekey does NOT protect the")
        print("  formula identity against an attacker holding K. They decrypt the")
        print("  payload with K, then try each formula's parameter layout and see")
        print("  which parses consistently. They never have to open the selector.")
        print()
        print("  What value the prekey has left is limited to:")
        print("    - key separation hygiene")
        print("    - the group identity topology (shared P, pairwise K)")
        print("    - deployments where the corpus is kept SECRET")
    else:
        print(f"  RESULT: the prekey WORKS. The attacker is left among")
        print(f"  {r['avg_candidates']:.1f} candidates. Of the {blind_bits:.2f} bits of")
        print(f"  uncertainty available, {remaining_bits:.2f} are protected; the parse")
        print(f"  consistency attack strips only {blind_bits - remaining_bits:.2f} bits.")
        print()
        print("  BUT the ceiling did not move: the total uncertainty across 53")
        print(f"  formulas is already {blind_bits:.2f} bits, and since the selector is")
        print("  2 bytes the architectural ceiling is 16 bits (ADR-025). The prekey")
        print("  PROTECTS that small budget, it does not ENLARGE it.")
    print()
    print("  Note: this measurement assumes the corpus is PUBLIC. With a secret")
    print("  corpus the attacker cannot know the candidate layouts and the attack")
    print("  cannot be set up this way. But then security rests on obscurity,")
    print("  which ADR-025 rejected.")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
