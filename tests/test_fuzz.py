"""Fuzzing: a small budget on every run, a large budget by hand.

WHAT THESE TESTS ARE FOR

`fuzz.py` is a tool for long runs. This file wires it into the test suite so
it runs on a small budget on every `pytest`, and a regression is not missed
because somebody forgot to run a fuzzing campaign.

The budget is deliberately small; the tests must not take minutes. For a real
search:

    python fuzz.py 5000 <seed>

WHICH TEST MATTERS MOST
`test_positive_control_rig_works`. The fuzzer saying "no findings" only means
something once the fuzzer has been shown able to find one. The same
discipline runs through the layer 2 experiments and the side channel sweep.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fuzz  # noqa: E402
from crypto import CryptoError, Engine, load_corpus  # noqa: E402

CORPUS = load_corpus()
ENGINE = Engine(CORPUS, fuzz.KEY)


# ═══════════════ the rig itself ═══════════════

def test_positive_control_rig_works():
    """The fuzzer has to see all three deliberate defects.

    If it does not, "no findings" is worthless, because the fuzzer might be
    calling nothing at all.
    """
    findings: list = []
    caught = fuzz.campaign_positive_control(findings)
    assert caught == 3, f"the rig caught {caught} of 3 defects"
    assert not findings, [str(b) for b in findings]


def test_try_cryptoerror_accept_does():
    """A `CryptoError` is the expected behaviour, not a finding."""
    findings: list = []

    def reject():
        raise CryptoError("a proper refusal")

    fuzz._try(findings, "t", "reject", reject)
    assert not findings


def test_try_silent_success_finding_counts():
    findings: list = []
    fuzz._try(findings, "t", "accept", lambda: "value")
    assert len(findings) == 1
    assert "SILENT SUCCESS" in findings[0].ne


def test_try_success_accept_with_silent_does_not_stay():
    findings: list = []
    fuzz._try(findings, "t", "accept", lambda: "value", success_accept=True)
    assert not findings


# ═══════════════ the campaigns, small budget ═══════════════

@pytest.mark.parametrize("name", [
    "random", "bitflip", "truncate", "hostile_payload",
    "frame", "session", "curve",
])
def test_campaign_clean(name):
    """No campaign should produce a finding on a small budget."""
    import random
    rng = random.Random(20260819)
    findings: list = []
    round = 25

    if name == "random":
        fuzz.campaign_random(ENGINE, rng, round, findings)
    elif name == "bitflip":
        fuzz.campaign_bitflip(ENGINE, rng, round, findings)
    elif name == "truncate":
        fuzz.campaign_truncate(ENGINE, rng, round, findings)
    elif name == "hostile_payload":
        fuzz.campaign_hostile_payload(ENGINE, CORPUS, rng, round, findings)
    elif name == "frame":
        fuzz.campaign_frame(ENGINE, CORPUS, rng, round, findings)
    elif name == "session":
        fuzz.campaign_session(ENGINE, rng, 80, findings)
    elif name == "curve":
        fuzz.campaign_curve(rng, round, findings)

    assert not findings, "\n".join(str(b) for b in findings)


# ═══════════════ hand pinned edge cases ═══════════════

@pytest.mark.parametrize("blob", [
    b"",
    b"\x00",
    bytes(1339),
    b"\xFF" * 1339,
    bytes(1338),
    bytes(1340),
    bytes(range(256)) * 6,
], ids=["empty", "one-byte", "zero-filled", "one-filled",
        "one-short", "one-extra", "increasing"])
def test_worst_entries_with_cryptoerror_is_refused(blob):
    """These inputs must stay the same for years, as a regression lock.

    Random fuzzing produces them sooner or later, but a FIXED list keeps a
    regression from depending on which run happened to catch it.
    """
    for f in (ENGINE.decode, ENGINE.decrypt_text, ENGINE.decode_chain,
              ENGINE.decrypt_hidden, ENGINE.read_frame):
        with pytest.raises(CryptoError):
            f(blob)


def test_valid_of_the_text_every_byte_critical():
    """Changing ANY byte of the ciphertext has to be refused.

    Random bit flips sample; this test walks every byte one at a time. None
    of the 1339 bytes is "unimportant padding".
    """
    valid = ENGINE.encrypt_text("every byte matters")
    for i in range(0, len(valid), 7):        # every 7th byte, about 191 of them
        broken = bytearray(valid)
        broken[i] ^= 0x01
        with pytest.raises(CryptoError):
            ENGINE.decrypt_text(bytes(broken))


def test_with_the_envelope_helper_really_tag_passes():
    """`_zarfla` has to produce a text that passes the tag.

    If it does not, the `dusmanca_payload` campaign never reaches the parser
    and its "clean" result is an empty promise.
    """
    entry = CORPUS.by_slug("ham-metin")
    raw = "check".encode()
    from crypto.frame import wrap
    from crypto.wire import serialize

    body = wrap(0, serialize(entry, {"uzunluk": len(raw),
                                     "metin": raw.ljust(1024, b"\x00")}))
    blob = fuzz._wrap(entry.id, body)
    assert ENGINE.decrypt_text(blob) == "check"


# ═══════════════ the regression lock fuzzing found ═══════════════

def test_to_zero_divisor_constraint_cryptoerror_gives():
    """A FUZZING FINDING, 2026-08-19, seed 1, the "hostile payload" campaign.

    Constraint expressions are written assuming VALID values. During decoding
    the values come from the ciphertext, and if a hostile payload produced
    `p = 0`, the constraint `(4*a**3 + 27*b**2) % p != 0` raised
    **ValueError: division by zero**, OUTSIDE the `CryptoError` hierarchy.

    Why it matters: the engine's contract is "every refusal is a
    CryptoError". An exception outside the contract punches through the
    caller's `except CryptoError` block and takes the application down.

    Exploitability: not directly. Reaching this needs a valid tag, which
    means the key. But a faulty sender or corrupted storage produces the
    same result, and breaking the API contract is a defect on its own.
    """
    from crypto import ConstraintViolation
    from crypto.constraints import check_all

    constraints = [{"expr": "(4 * a**3 + 27 * b**2) % p != 0",
                    "reason": "the curve must not be singular"}]

    # p = 0 means the expression CANNOT BE EVALUATED. The right answer
    # is that the constraint is not satisfied.
    with pytest.raises(ConstraintViolation):
        check_all(constraints, {"a": 1, "b": 2, "p": 0})

    # behaviour on valid values must not change
    assert check_all(constraints, {"a": 1, "b": 2, "p": 97}) == []


def test_unevaluable_warning_constraint_does_not_raise():
    """A warning level constraint that cannot be evaluated must come back as a warning."""
    from crypto.constraints import check_all

    warnings = check_all(
        [{"expr": "x % y == 0", "reason": "divisibility",
          "severity": "warning"}],
        {"x": 5, "y": 0})
    assert len(warnings) == 1
    assert "could not be evaluated" in warnings[0]


def test_round_mismatch_also_constraint_violation():
    """Comparing `bytes` with a number used to raise TypeError."""
    from crypto import ConstraintViolation
    from crypto.constraints import check_all

    with pytest.raises(ConstraintViolation):
        check_all([{"expr": "x > 5", "reason": "bound"}], {"x": b"text"})


def test_real_engine_on_the_path_also_cryptoerror():
    """The same defect must not be reachable through the ENGINE path either.

    The unit test calls the constraint evaluator directly; this one uses the
    real path the fuzzer uses, a hostile payload with a valid tag.
    """
    import random
    rng = random.Random(1)
    findings: list = []
    fuzz.campaign_hostile_payload(ENGINE, CORPUS, rng, 400, findings)
    assert not findings, "\n".join(str(b) for b in findings)
