"""The corpus generator and its exam (`layer2/generator.py`, `layer2/exam.py`).

WHY THIS FILE EXISTS

The generator produces entries that go into the engine. A broken generator
does silent harm: an invalid entry enters the corpus and the engine tries to
decode it. The exam exists to prevent that, but the exam itself has to be tested too.

The most important test here is `test_generated_marker_wire_a_does_not_leak`:
generated entries must be marked for humans and unmarked in the ciphertext.
If the marker leaks into params or constraints, the generated corpus becomes
distinguishable from the ciphertext and network compartmentalisation collapses.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crypto import load_corpus# noqa: E402
from crypto.wire import SELECTOR_BYTES  # noqa: E402
from layer2 import exam as S  # noqa: E402
from layer2 import generator as U  # noqa: E402

CORPUS = load_corpus()
PROFILE = U.learn(CORPUS)


# ═══════════════ template extraction ═══════════════

@pytest.mark.parametrize("expr, expected", [
    ("p > 3", "X > 3"),
    ("n > 0", "X > 0"),
    ("a % p != 0", "X % Y != 0"),
    ("e % 2 == 1", "X % 2 == 1"),
    ("p != q", "X != Y"),
    ("m > n", "X > Y"),
])
def test_template_names_slot_converts(expr, expected):
    assert U.constraint_template(expr) == expected


def test_template_function_name_slot_DOES_NOT_TURN():
    """`gcd` is an ast.Name but it is NOT a slot.

    Turned into a slot it produces `X(e, phi)`, which the engine's parser
    refuses as "function not allowed". That is exactly what happened in the
    first version; this test is the lock on that bug.
    """
    s = U.constraint_template("gcd(e, phi) == 1")
    assert s is not None
    assert s.startswith("gcd(")
    assert "X" in s and "Y" in s
    from crypto.constraints import parse
    parse(s)                       # the engine's parser has to accept it


def test_template_string_with_constants_expression_skips():
    """`padding != 'none'` is specific to one entry and must not be templated."""
    assert U.constraint_template("padding != 'none'") is None


def test_template_unparsed_expression_none_rotates():
    assert U.constraint_template("import os") is None
    assert U.constraint_template("p >>> 3") is None


def test_template_fixed_expression_none_rotates():
    """An expression with no variable cannot be bound."""
    assert U.constraint_template("1 < 2") is None


# ═══════════════ learning ═══════════════

def test_real_from_the_corpus_learns():
    assert len(PROFILE.domains) >= 7
    assert len(PROFILE.templates) >= 20
    assert PROFILE.param_count and PROFILE.constraint_count
    assert PROFILE.used_ids == {e.id for e in CORPUS}


def test_domain_block_mapping_id_with_the_convention_consistent():
    """`elliptic-curves` has to be in the 0x01xx block, the schema convention."""
    assert PROFILE.domain_block["elliptic-curves"] == 0x01
    assert PROFILE.domain_block["modular-arithmetic"] == 0x02
    assert PROFILE.domain_block["hash-mac"] == 0x03


# ═══════════════ generation ═══════════════

def test_requested_count_is_generated():
    g = U.generate(PROFILE, 25, random.Random(1))
    assert len(g) == 25


def test_same_seed_same_output():
    a = U.generate(PROFILE, 10, random.Random(7))
    b = U.generate(PROFILE, 10, random.Random(7))
    assert [x["id"] for x in a] == [x["id"] for x in b]
    assert a == b


def test_ids_unique_and_real_with_the_corpus_does_not_collide():
    g = U.generate(PROFILE, 40, random.Random(2))
    ids = [x["id"] for x in g]
    assert len(ids) == len(set(ids)), "the generated ids repeat"
    assert not (set(ids) & PROFILE.used_ids)


def test_blocked_identity_never_is_not_assigned():
    """0x0501 belonged to the retired Caesar and is NEVER reused under
    ADR-003 and ADR-009. 0xFFFF belongs to chain mode."""
    g = U.generate(PROFILE, 120, random.Random(3))
    assert not ({x["id"] for x in g} & U.BLOCKED)


def test_payload_ceiling_does_not_hang():
    g = U.generate(PROFILE, 60, random.Random(4))
    for x in g:
        assert U._payload_bits(x["params"]) <= U.PAYLOAD_BIT_CEILING


def test_generated_constraints_of_the_engine_through_the_parser_passes():
    from crypto.constraints import parse
    g = U.generate(PROFILE, 40, random.Random(5))
    for x in g:
        for k in x["constraints"]:
            parse(k["expr"])            # if it raises, the test fails


def test_forward_reference_is_not_generated():
    """`mod` must always point at a prime defined BEFORE it."""
    g = U.generate(PROFILE, 60, random.Random(6))
    for x in g:
        seen: set[str] = set()
        for p in x["params"]:
            if p.get("mod"):
                assert p["mod"] in seen, f"{x['slug']}: forward reference"
            seen.add(p["name"])


# ═══════════════ the marker must not leak, THE MOST IMPORTANT TEST ═══════════════

def test_generated_marker_wire_a_does_not_leak():
    """The `generated` marker must be ONLY in the `doc` block.

    `doc` is invisible to the engine and never enters the wire format
    (formula.schema.json). If the marker leaks into params or constraints,
    the ciphertext of generated entries becomes distinguishable from that of
    real ones, which destroys the point of separating networks by formula set.
    """
    g = U.generate(PROFILE, 40, random.Random(8))
    for x in g:
        assert "generated" in x["doc"]["tags"], "there has to be a marker for humans"
        for p in x["params"]:
            assert "generated" not in str(p).lower(), f"{x['slug']}: leaked into params"
        for k in x["constraints"]:
            assert "generated" not in k["expr"].lower(), \
                f"{x['slug']}: leaked into a constraint"


def test_doc_block_mathematical_claim_is_not_found():
    """The `notes` field must say plainly that the entry is not a formula."""
    g = U.generate(PROFILE, 5, random.Random(9))
    for x in g:
        assert "NOT A MATHEMATICAL FORMULA" in x["doc"]["notes"]


# ═══════════════ the exam gates ═══════════════

def test_exam_positive_control_passes():
    """Do the sabotaged entries fail at the expected gate?

    If this breaks, none of the exam's 'passed' verdicts can be trusted.
    """
    assert S.control_1_4(CORPUS) == []


def test_sabotage_of_entries_all_one_gate_targets():
    targets = {expected for _, expected, _ in S.sabotage_entries()}
    assert targets <= set(S.GATES)
    assert len(S.sabotage_entries()) >= 6


def test_of_the_generated_most_four_gate_passes():
    g = U.generate(PROFILE, 40, random.Random(0))
    report = S.exam_1_4(g, CORPUS)
    ratio = len(report.passing) / len(g)
    assert ratio > 0.5, f"only {ratio * 100:.0f}% passed"


def test_failures_samplability_at_the_gate_fails():
    """Generated constraints can contradict each other; that is an EXPECTED failure.

    Failing at the schema or round trip gate means the generator is broken,
    because those gates test structural correctness.
    """
    g = U.generate(PROFILE, 40, random.Random(0))
    report = S.exam_1_4(g, CORPUS)
    for s in report.failing:
        assert s.failed_gate == "samplable", \
            f"{s.slug} failed at an unexpected gate: {s.failed_gate}, {s.reason}"


def test_appearing_entries_round_return_does():
    """Every entry that passes the gates has to really encrypt and decrypt."""
    g = U.generate(PROFILE, 20, random.Random(11))
    report = S.exam_1_4(g, CORPUS)
    assert report.passing, "no entry passed"


# ═══════════════ derived generation ═══════════════
#
# The structural generator cannot produce mathematics. Derived generation is
# the honest answer to that limit: do not generate the mathematics, inherit it.

def test_derived_mathematics_inherits_takes():
    """`latex` and `summary` have to come from the parent UNCHANGED, not derived."""
    master = CORPUS.by_slug("rsa-sifreleme") if any(
        e.slug == "rsa-sifreleme" for e in CORPUS) else CORPUS.active[0]
    t = U.derive(master, 0x02E0, 2.0)
    assert t is not None
    assert t["doc"]["latex"] == master.doc["latex"]
    assert t["doc"]["summary"] == master.doc["summary"]


def test_derived_source_shows():
    """A reader has to know where to verify the mathematics."""
    master = CORPUS.active[0]
    t = U.derive(master, 0x02E1, 2.0)
    assert f"0x{master.id:04X}" in t["doc"]["notes"]
    assert master.id in t["doc"]["related"]
    assert "derived" in t["doc"]["tags"]


def test_derived_generated_tag_DOES_NOT_CARRY():
    """A derived entry contains no generated mathematics; calling it `generated` would mislead."""
    master = CORPUS.active[0]
    t = U.derive(master, 0x02E2, 2.0)
    assert "generated" not in t["doc"]["tags"]


def test_derived_only_widths_changes():
    master = CORPUS.by_slug("hkdf")
    t = U.derive(master, 0x03E0, 2.0)
    assert len(t["params"]) == len(master.params)
    for new, old in zip(t["params"], master.params):
        assert new["name"] == old["name"]
        assert new["type"] == old["type"]
        assert new.get("role") == old.get("role")
    assert [k["expr"] for k in t["constraints"]] == \
           [k["expr"] for k in master.constraints]


def test_derived_schema_bounds_does_not_exceed():
    """A scale that exceeds the 8192 bit ceiling must return None, not an invalid entry."""
    master = CORPUS.active[0]
    for factor in U.FACTORS:
        t = U.derive(master, 0x02E3, factor)
        if t is None:
            continue
        for p in t["params"]:
            if "bits" in p:
                assert 1 <= p["bits"] <= 8192


def test_derivatives_exam_passes():
    """Derived entries must pass at a HIGHER rate than structural ones.

    Inheriting the mathematics also inherits constraint satisfiability, and the measured rate confirms it.
    fark bu beklentinin kilidi.
    """
    t = U.derivatives(CORPUS, PROFILE, 20, random.Random(0))
    report = S.exam_1_4(t, CORPUS)
    assert len(report.passing) / len(t) >= 0.9, \
        [f"{s.slug}: {s.reason}" for s in report.failing]


def test_derived_ids_parent_in_blocks_stays():
    """A derivative has to stay in its parent's id block, so the convention holds.

    The parent is found from the slug (`derive-{parent}-{factor}x`). Inferring
    it from `related` would not be reliable, because that field also carries
    the parent's OWN relations.
    """
    import re
    for t in U.derivatives(CORPUS, PROFILE, 20, random.Random(3)):
        m = re.fullmatch(r"derive-(.+)-[\d]+x", t["slug"])
        assert m, t["slug"]
        master = CORPUS.by_slug(m.group(1))
        assert (t["id"] >> 8) == (master.id >> 8), \
            f"{t['slug']}: 0x{t['id']:04X} is not in the same block as its parent 0x{master.id:04X}"
        assert t["id"] not in PROFILE.used_ids


# ═══════════════ mimari ceiling ═══════════════

def test_selector_16_bit_corpus_secrecy_ceiling_puts():
    """Corpus secrecy can NEVER exceed 16 bits.

    The selector in the wire format is 2 bytes. However many formulas get
    generated, the uncertainty that "which formula" can carry is at most
    2^16. The symmetric key is 256 bits, so the gap is 240 bits.

    That is the architectural proof of why corpus secrecy cannot replace the
    key (ADR-025).
    """
    assert SELECTOR_BYTES == 2
    ceiling_bits = SELECTOR_BYTES * 8
    assert ceiling_bits == 16
    assert ceiling_bits < 256


def test_real_of_the_corpus_entropy_small():
    """53 active entries is 5.73 bits. The lock on the number in ADR-025."""
    import math
    assert 5.0 < math.log2(len(CORPUS.active)) < 6.5
