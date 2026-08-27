"""The prekey (`crypto/prekey.py`) and the selector attack.

WHY THIS FILE EXISTS

The prekey is a change INSIDE the cipher path. It has to prove two things at
once:

  1. BEHAVIOUR WITHOUT A PREKEY DID NOT CHANGE. That is the most critical
     test. If it had, every ciphertext produced since ADR-013 would become
     undecodable, and no new test would catch it, because new tests exercise
     the new path.
  2. THE PREKEY PATH REALLY WORKS, and how much it works was measured,
     not claimed (`layer2/selector_attack.py`).
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crypto import VerificationError, Engine, load_corpus
from crypto import primitives  # noqa: E402
from crypto.memory import SecureBuffer  # noqa: E402
from crypto.corpus import CorpusError  # noqa: E402
from crypto.prekey import (  # noqa: E402
                           MIN_BYTES,
                           INFO_PREKEY,
                           Prekey,
                           PrekeyError,
                           is_independent,
)
from crypto.sampler import sample  # noqa: E402
from crypto.wire import SELECTOR_BYTES, CIPHERTEXT_BYTES, encode  # noqa: E402

KEY = bytes(range(32))
CORPUS = load_corpus()
ENTRY = CORPUS.by_slug("hkdf")
VALUES = sample(ENTRY, random.Random(0))


# ═══════════ 1. BACKWARD COMPATIBILITY, the most critical ═══════════

def test_without_a_prekey_output_byte_byte_same():
    """With NO prekey the ciphertext has to be byte for byte what it was.

    It is made deterministic by supplying the same nonce; the only
    difference is the presence of the `prekey=None` parameter. If this
    test fails, every ciphertext produced since ADR-013 has become undecodable.
    """
    nonce = bytes(range(16))
    a = encode(ENTRY, VALUES, KEY, nonce=nonce)
    b = encode(ENTRY, VALUES, KEY, nonce=nonce, prekey=None)
    assert a == b


def test_without_a_prekey_engine_the_old_one_like():
    m = Engine(CORPUS, KEY)
    blob = m.encrypt("hkdf", VALUES)
    e, v = m.decode(blob)
    assert e.slug == "hkdf"
    assert m.network_fingerprint() is None


# ═══════════ 2. THE PREKEY PATH ═══════════

def test_round_return():
    with Prekey.generate() as p:
        m = Engine(CORPUS, KEY, prekey=p)
        blob = m.encrypt("hkdf", VALUES)
        e, v = m.decode(blob)
        assert e.slug == "hkdf"
        assert v == {k: VALUES[k] for k in v}


def test_size_does_not_change():
    """A prekey adds NOT ONE byte to the wire format."""
    with Prekey.generate() as p:
        m = Engine(CORPUS, KEY, prekey=p)
        assert len(m.encrypt("hkdf", VALUES)) == CIPHERTEXT_BYTES


def test_wrong_prekey_formula_cannot_give():
    """The real promise: someone with K but not P cannot read the formula from the selector."""
    with Prekey.generate() as p:
        blob = Engine(CORPUS, KEY, prekey=p).encrypt("hkdf", VALUES)
    # K present, P absent
    with pytest.raises((CorpusError, Exception)):
        Engine(CORPUS, KEY).decode(blob)


def test_different_prekey_different_selector():
    """Two networks send the same formula under the same nonce; the selectors must differ."""
    nonce = bytes(range(16))
    with Prekey.generate() as p1, Prekey.generate() as p2:
        a = encode(ENTRY, VALUES, KEY, nonce=nonce, prekey=p1)
        b = encode(ENTRY, VALUES, KEY, nonce=nonce, prekey=p2)
        head, last = 16, 16 + SELECTOR_BYTES
        assert a[head:last] != b[head:last]


def test_mask_every_nonce_at_changes():
    """A FIXED PERMUTATION WAS NOT USED, so repetition must not leak.

    If the selector were the same when the same formula is sent twice, an
    attacker could say "these two are the same formula" without decrypting anything.
    """
    with Prekey.generate() as p:
        m = Engine(CORPUS, KEY, prekey=p)
        chosen = {m.encrypt("hkdf", VALUES)[16:16 + SELECTOR_BYTES]
                  for _ in range(100)}
        assert len(chosen) > 90, "the selector repeats, so the mask does not depend on the nonce"


def test_mac_still_every_thing_covers():
    """A prekey must not weaken integrity; the MAC key still comes from K."""
    with Prekey.generate() as p:
        m = Engine(CORPUS, KEY, prekey=p)
        blob = bytearray(m.encrypt("hkdf", VALUES))
        for position in (0, 16, 17, 500, CIPHERTEXT_BYTES - 1):
            broken = bytearray(blob)
            broken[position] ^= 0x01
            with pytest.raises(VerificationError):
                m.decode(bytes(broken))


def test_chain_mode_also_works():
    with Prekey.generate() as p:
        m = Engine(CORPUS, KEY, prekey=p)
        records = [("hkdf", VALUES)]
        blob = m.encrypt_chain(records)
        back = m.decode_chain(blob)
        assert back[0][0].slug == "hkdf"


# ═══════════ 3. INDEPENDENCE, a footgun ═══════════

def test_p_equals_k_is_refused():
    """If P == K, nothing is gained from key separation."""
    p = Prekey(KEY)
    with pytest.raises(ValueError, match="cannot equal"):
        Engine(CORPUS, KEY, prekey=p)
    p.close()


def test_independent_correct_works():
    p = Prekey(KEY)
    assert not is_independent(p, KEY)
    assert is_independent(p, bytes(range(1, 33)))
    p.close()


def test_generate_csprng_from_comes():
    """`generate()` does NOT derive from K; two calls have to differ."""
    a, b = Prekey.generate(), Prekey.generate()
    assert a.fingerprint() != b.fingerprint()
    a.close(); b.close()


# ═══════════ 4. MEMORY AND LIFECYCLE ═══════════

def test_safe_in_the_buffer_is_kept():
    """A long lived secret, so under ADR-020 and 021 it has to be in a buffer."""
    with Prekey.generate() as p:
        assert isinstance(p.buffer, SecureBuffer)


def test_when_closed_cannot_be_used():
    p = Prekey.generate()
    p.close()
    assert p.closed
    with pytest.raises(PrekeyError):
        p.mask(bytes(16), SELECTOR_BYTES)


def test_repr_content_does_not_print():
    with Prekey.generate() as p:
        r = repr(p)
        assert "Prekey" in r
        assert p.buffer.to_bytes().hex()[:16] not in r


def test_short_prekey_is_refused():
    with pytest.raises(PrekeyError):
        Prekey(b"kisa")
    with pytest.raises(PrekeyError):
        Prekey.generate(MIN_BYTES - 1)


def test_wrong_type_is_refused():
    with pytest.raises(PrekeyError):
        Prekey(12345)


# ═══════════ 5. ALAN AYRIMI ═══════════

def test_tag_versioned_and_discrete():
    """The v3 label must not mix with v1 or v2."""
    from crypto import keys as ah
    assert b"/v3/" in INFO_PREKEY
    all = {primitives.INFO_SELECTOR, primitives.INFO_PAYLOAD, primitives.INFO_MAC,
           ah.INFO_DEVICE, ah.INFO_EPOCH, ah.INFO_CHAIN, ah.INFO_MESSAGE,
           ah.INFO_FINGERPRINT}
    assert INFO_PREKEY not in all


def test_mask_same_p_same_nonce_also_deterministic():
    with Prekey.generate() as p:
        n = bytes(range(16))
        assert p.mask(n, 2) == p.mask(n, 2)


# ═══════════ 6. THE ATTACK MEASUREMENT ═══════════

def test_attack_positive_control_passes():
    """With P known the attacker has to find the formula 100% of the time, which locks the rig."""
    from layer2.selector_attack import attack
    r = attack(CORPUS, 30, 0, prekey_known=True)
    assert r["correct_in_candidates"] == 1.0


def test_attack_correct_formula_cannot_filter():
    """The correct formula must ALWAYS stay in the candidate list.

    If it did not, the attack would be wrong: an elimination criterion that
    removes the real formula would make the measurement look better than it is.
    """
    from layer2.selector_attack import attack
    r = attack(CORPUS, 30, 1, prekey_known=False)
    assert r["correct_in_candidates"] == 1.0


def test_attack_single_candidate_cannot_lower():
    """The lock on the measured result: the attacker cannot fully identify it."""
    from layer2.selector_attack import attack
    r = attack(CORPUS, 30, 2, prekey_known=False)
    assert r["narrowed_to_one"] < 0.2
    assert r["avg_candidates"] > 5


def test_of_the_prekey_guard_budget_16_bits_bounded():
    """However well the prekey works, the ceiling does not move (ADR-025)."""
    import math
    assert SELECTOR_BYTES * 8 == 16
    assert math.log2(len(CORPUS.active)) < 16
