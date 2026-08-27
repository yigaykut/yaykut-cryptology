"""Engine core tests.

To run:
    python -m pytest tests/ -v
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto import (  # noqa: E402
                    VerificationError,
                    Entry,
                    ConstraintViolation,
                    EncodingError,
                    Engine,
                    SamplingError,
                    OVERHEAD_BYTES,
                    PAYLOAD_FIXED_BYTES,
                    CIPHERTEXT_BYTES,
                    decode,
                    deserialize,
                    encode,
                    load_corpus,
                    sample,
                    random_values,
                    serialize,
                    hard_constraints,
)
from crypto.bitio import BitReader, BitWriter  # noqa: E402
from crypto.constraints import equality_gap, evaluate, parse  # noqa: E402
from crypto.sampler import _solve, equality_plan  # noqa: E402
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES  # noqa: E402

CORPUS = load_corpus()
# Retired entries cannot encrypt (ADR-009), so the encryption tests run only
# on active entries.
ENTRIES = CORPUS.active
RETIRED = [e for e in CORPUS if e.status == "retired"]
KEY = bytes(range(32))


def entry_id(e):
    return f"{e.id:04X}-{e.slug}"


# ────────────────────────── bit level ──────────────────────────

def test_bitwriter_byte_bound_outside_widths():
    """Widths that are not a whole number of bytes must pack and read back correctly."""
    w = BitWriter()
    w.write_int(0b10110, 5)
    w.write_int(0b111, 3)
    w.write_int(0xABCD, 16)
    assert w.bit_count == 24
    r = BitReader(w.to_bytes())
    assert r.read_int(5) == 0b10110
    assert r.read_int(3) == 0b111
    assert r.read_int(16) == 0xABCD


def test_bitwriter_overflowing_value_is_refused():
    w = BitWriter()
    with pytest.raises(EncodingError, match="does not fit"):
        w.write_int(32, 5)  # 5 bit en fazla 31


def test_bitwriter_negative_value_is_refused():
    w = BitWriter()
    with pytest.raises(EncodingError, match="negative"):
        w.write_int(-1, 8)


def test_bitreader_data_when_it_ends_error_gives():
    r = BitReader(b"\xff")
    r.read_int(8)
    with pytest.raises(Exception, match="not enough"):
        r.read_int(1)


# ────────────────────────── the constraint evaluator ──────────────────────────

def test_constraint_code_running_refuses():
    with pytest.raises(ValueError, match="not allowed"):
        parse("__import__('os').system('dir')")


def test_constraint_attribute_access_refuses():
    with pytest.raises(ValueError, match="not allowed"):
        parse("a.__class__")


def test_constraint_large_exponent_is_refused():
    """Expressions like a ** a can eat memory; the exponent is bounded."""
    with pytest.raises(ValueError, match="exponent"):
        evaluate("a ** b", {"a": 2, "b": 10_000})


def test_constraint_to_zero_split_is_caught():
    with pytest.raises(ValueError, match="division by zero"):
        evaluate("a % b == 0", {"a": 5, "b": 0})


def test_constraint_gcd_runs():
    assert evaluate("gcd(a, 26) == 1", {"a": 7}) is True
    assert evaluate("gcd(a, 26) == 1", {"a": 13}) is False


# ────────────────────────── serialisation ──────────────────────────

@pytest.mark.parametrize("entry", ENTRIES, ids=entry_id)
def test_serialisation_round_return(entry):
    """For every entry: values -> bit string -> the same values.

    Constraints are off; what is tested here is only that the encoding is reversible.
    """
    rng = random.Random(entry.id)
    values = random_values(entry, rng)
    blob = serialize(entry, values)

    assert len(blob) == entry.payload_bytes

    back = deserialize(entry, blob)
    for p in entry.public_params:
        assert back[p["name"]] == values[p["name"]], f"{p['name']} did not survive the round trip"


@pytest.mark.parametrize("entry", ENTRIES, ids=entry_id)
def test_covert_parameters_is_not_written(entry):
    """Anything with role secret or derived must never enter the ciphertext."""
    rng = random.Random(entry.id)
    values = random_values(entry, rng)
    back = deserialize(entry, serialize(entry, values))

    public_names = {p["name"] for p in entry.public_params}
    secret_names = {p["name"] for p in entry.params} - public_names

    assert set(back) == public_names
    assert not (set(back) & secret_names)


def test_partial_public_parameter_error_gives():
    entry = CORPUS.by_slug("afin-sifre")
    with pytest.raises(EncodingError, match="missing"):
        serialize(entry, {})


# ────────────────────────── end to end encryption ──────────────────────────

@pytest.mark.parametrize("entry", ENTRIES, ids=entry_id)
def test_encrypt_decode_round_return(entry):
    """Encrypt, decrypt, get back the same entry and the same public values."""
    rng = random.Random(entry.id)
    values = random_values(entry, rng)

    blob = encode(entry, values, KEY, check=False)
    back_entry, back_values = decode(CORPUS, blob, KEY, check=False)

    assert back_entry.id == entry.id
    for p in entry.public_params:
        assert back_values[p["name"]] == values[p["name"]]


@pytest.mark.parametrize("entry", ENTRIES, ids=entry_id)
def test_cipher_text_length_fixed(entry):
    """ADR-007: every formula has to produce a ciphertext of THE SAME length.

    This test is the guarantee that the length leak stays closed.
    """
    rng = random.Random(entry.id)
    values = random_values(entry, rng)
    blob = encode(entry, values, KEY, check=False)
    assert len(blob) == CIPHERTEXT_BYTES


def test_all_entries_same_length():
    """There has to be a single length across the whole corpus; the leak is closed."""
    lengths = {
        len(encode(e, random_values(e, random.Random(e.id)), KEY, check=False))
        for e in ENTRIES
    }
    assert lengths == {CIPHERTEXT_BYTES}, (
        f"the length leak is back: {sorted(lengths)}"
    )


def test_padding_bit_decoding_does_not_affect():
    """Even the entry with the smallest payload has to decode correctly inside 1280 bytes of padding."""
    entry = CORPUS.by_slug("afin-sifre")  # 1 byte of real payload
    blob = encode(entry, {"m": 19, "a": 7, "b": 4}, KEY)
    back, values = decode(CORPUS, blob, KEY)
    assert back.id == entry.id and values["m"] == 19


@pytest.mark.parametrize("entry", RETIRED, ids=entry_id)
def test_retired_with_the_entry_encryption_is_refused(entry):
    """ADR-009: retired entries cannot be used for new encryption."""
    values = random_values(entry, random.Random(entry.id))
    with pytest.raises(EncodingError, match="retired"):
        encode(entry, values, KEY, check=False)


def test_retired_entry_in_the_corpus_stays():
    """A retired entry is not deleted: its id stays blocked (ADR-003)."""
    assert 0x0501 in CORPUS
    assert CORPUS.get(0x0501).status == "retired"
    assert 0x0501 not in {e.id for e in CORPUS.active}


def test_wire_constant_exceeding_entry_is_refused():
    """A formula exceeding the constant must not be quietly truncated, it must be refused."""
    dev = Entry(
        id=0xFFFF, slug="dev-entry", version=1, status="active",
        doc={"name": "A synthetic entry exceeding the constant"},
        params=[{"name": "x", "type": "bytes", "bits": (PAYLOAD_FIXED_BYTES + 1) * 8}],
    )
    with pytest.raises(EncodingError, match="wire format"):
        encode(dev, {"x": bytes(PAYLOAD_FIXED_BYTES + 1)}, KEY, check=False)


def test_same_entry_every_time_different_cipher_text():
    """ADR-001: the unpredictability comes from the nonce. Same entry, same
    key, completely different outputs."""
    entry = CORPUS.by_slug("ec-weierstrass-short")
    values = random_values(entry, random.Random(1))

    outputs = {encode(entry, values, KEY, check=False) for _ in range(50)}
    assert len(outputs) == 50, "the nonce repeats, so the keystream is reused"


def test_fixed_nonce_deterministic_result_gives():
    """Nonce sabitlenirse engine tamamen deterministiktir."""
    entry = CORPUS.by_slug("afin-sifre")
    values = random_values(entry, random.Random(2))
    nonce = b"\x01" * NONCE_BYTES

    a = encode(entry, values, KEY, nonce=nonce, check=False)
    b = encode(entry, values, KEY, nonce=nonce, check=False)
    assert a == b


def test_selector_identity_hides():
    """The same formula id has to become a different selector on every encryption.

    If the identity were written in the clear, the selector would be the same 2 bytes every time.
    """
    entry = CORPUS.by_slug("afin-sifre")
    values = random_values(entry, random.Random(3))

    selectors = set()
    for _ in range(200):
        blob = encode(entry, values, KEY, check=False)
        selectors.add(blob[NONCE_BYTES:NONCE_BYTES + SELECTOR_BYTES])

    # 200 draws from a 2^16 space; a collision is expected but it must not be constant.
    assert len(selectors) > 150
    assert entry.id.to_bytes(SELECTOR_BYTES, "big") not in selectors or len(selectors) > 1


def test_different_formulas_same_with_the_key_does_not_mix():
    entry_a = CORPUS.by_slug("afin-sifre")
    entry_b = CORPUS.by_slug("vigenere")

    blob = encode(entry_a, random_values(entry_a, random.Random(4)), KEY, check=False)
    back, _ = decode(CORPUS, blob, KEY, check=False)
    assert back.id == entry_a.id != entry_b.id


# ────────────────────────── integrity and tampering ──────────────────────────

def test_wrong_key_is_refused():
    entry = CORPUS.by_slug("ecdsa-imza")
    blob = encode(entry, random_values(entry, random.Random(5)), KEY, check=False)

    with pytest.raises(VerificationError):
        decode(CORPUS, blob, b"\x00" * 32, check=False)


@pytest.mark.parametrize("region", ["nonce", "selector", "payload", "tag"])
def test_tampering_is_caught(region):
    """A single bit change in any region of the ciphertext has to be refused."""
    entry = CORPUS.by_slug("rsa-modexp")
    blob = bytearray(encode(entry, random_values(entry, random.Random(6)), KEY, check=False))

    position = {
        "nonce": 0,
        "selector": NONCE_BYTES,
        "payload": NONCE_BYTES + SELECTOR_BYTES,
        "tag": len(blob) - 1,
    }[region]
    blob[position] ^= 0x01

    with pytest.raises(VerificationError):
        decode(CORPUS, bytes(blob), KEY, check=False)


def test_truncated_text_is_refused():
    entry = CORPUS.by_slug("afin-sifre")
    blob = encode(entry, random_values(entry, random.Random(7)), KEY, check=False)

    with pytest.raises(Exception):
        decode(CORPUS, blob[:-1], KEY, check=False)


def test_wrong_length_text_is_refused():
    with pytest.raises(Exception, match="wrong ciphertext length"):
        decode(CORPUS, b"\x00" * (OVERHEAD_BYTES - 1), KEY)
    with pytest.raises(Exception, match="wrong ciphertext length"):
        decode(CORPUS, b"\x00" * (CIPHERTEXT_BYTES + 1), KEY)


# ────────────────────────── constraint enforcement ──────────────────────────

def test_constraint_violation_encryption_prevents():
    """The affine cipher has the constraint m < 26; 30 must not be accepted."""
    entry = CORPUS.by_slug("afin-sifre")
    with pytest.raises(ConstraintViolation, match="alphabet"):
        encode(entry, {"m": 30, "a": 7, "b": 3}, KEY)


def test_valid_values_constraint_through_the_control_passes():
    entry = CORPUS.by_slug("afin-sifre")
    blob = encode(entry, {"m": 7, "a": 7, "b": 3}, KEY)
    back, values = decode(CORPUS, blob, KEY)
    assert back.slug == "afin-sifre"
    assert values["m"] == 7
    assert "a" not in values and "b" not in values  # secret, not carried


def test_affine_gcd_constraint_is_applied():
    entry = CORPUS.by_slug("afin-sifre")
    with pytest.raises(ConstraintViolation, match="invertible"):
        encode(entry, {"m": 5, "a": 13, "b": 4}, KEY)  # gcd(13, 26) = 13
    encode(entry, {"m": 5, "a": 7, "b": 4}, KEY)  # gcd(7, 26) = 1, sorun yok


# ────────────────────────── the Engine interface ──────────────────────────

def test_engine_interface():
    engine = Engine(CORPUS, os.urandom(32))
    blob = engine.encrypt("afin-sifre", {"m": 12, "a": 7, "b": 5})
    entry, values = engine.decode(blob)
    assert entry.slug == "afin-sifre"
    assert values["m"] == 12


def test_engine_short_key_refuses():
    with pytest.raises(ValueError, match="16 bytes"):
        Engine(CORPUS, b"kisa")


# ────────────────────────── the sampler ──────────────────────────

@pytest.mark.parametrize("entry", ENTRIES, ids=entry_id)
def test_every_entry_samples(entry):
    """After ADR-006 the WHOLE corpus has to sample automatically.

    The values produced have to satisfy the constraints and really encrypt.
    """
    values = sample(entry, random.Random(entry.id), max_rejections=2000)
    blob = encode(entry, values, KEY)
    back, _ = decode(CORPUS, blob, KEY)
    assert back.id == entry.id


def test_equality_constraint_by_decoding_holds():
    """'rate + capacity == width' is satisfied by solving, not by random trials."""
    entry = CORPUS.by_slug("sunger-yapisi")

    plan = equality_plan(entry, random.Random(0))
    assert plan, "no plan was produced for the equality constraint"
    expr, variable = plan[0]
    assert expr == "rate + capacity == width"
    assert variable in {"rate", "capacity", "width"}

    for seed in range(20):
        v = sample(entry, random.Random(seed), max_rejections=2000)
        assert v["rate"] + v["capacity"] == v["width"]
        assert v["rate"] > 0 and v["capacity"] > 0


def test_equality_plan_linear_not_constraint_does_not_pick():
    """If g(v) is not linear, no solution should be attempted."""
    entry = Entry(
        id=0xFF01, slug="non-linear", version=1, status="active",
        doc={"name": "test"},
        params=[
            {"name": "x", "type": "uint", "bits": 8},
            {"name": "y", "type": "uint", "bits": 8},
        ],
        constraints=[{"expr": "x * x == y", "reason": "square", "severity": "error"}],
    )
    for _, name in equality_plan(entry, random.Random(0)):
        assert name != "x", "the expression is not linear in x and should not have been solved"


def test_decode_full_unsplit_root_refuses():
    """In the constraint 2*x == y, an odd y has no integer solution for x."""
    assert _solve("2 * x == y", "x", {"y": 7}) is None
    assert _solve("2 * x == y", "x", {"y": 8}) == 4


def test_equality_difference_equality_not_constraints_none():
    assert equality_gap("x < 5", {"x": 3}) is None
    assert equality_gap("x == 5", {"x": 3}) == -2
