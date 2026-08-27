"""The testable claims of `docs/security-argument.md`.

WHY THIS FILE EXISTS

A security argument is prose, and prose rots: the code changes and the
document stays. Some of the claims in the argument are **machine testable**:
the scheme definition, MAC coverage, domain separation, the sizes. Leaving
the testable parts untested turns the document into a lie over time.

What cannot be tested (the reduction steps, the PRF assumptions) stays in the
document, marked there as "this is not a proof".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from crypto import VerificationError, Engine, load_corpus  # noqa: E402
from crypto import primitives# noqa: E402
from crypto.wire import (  # noqa: E402
                         NONCE_BYTES,
                         PAYLOAD_FIXED_BYTES,
                         SELECTOR_BYTES,
                         CIPHERTEXT_BYTES,
                         TAG_BYTES,
)

KEY = bytes(range(32))
CORPUS = load_corpus()
ENGINE = Engine(CORPUS, KEY)
DOC = ROOT / "docs" / "security-argument.md"


# ═══════════════ §1 the scheme definition ═══════════════

def test_envelope_sizes_with_the_document_same():
    """The document says `16 + 2 + 1289 + 32 = 1339`. What does the code say?"""
    assert NONCE_BYTES == 16
    assert SELECTOR_BYTES == 2
    assert PAYLOAD_FIXED_BYTES == 1289
    assert TAG_BYTES == 32
    assert NONCE_BYTES + SELECTOR_BYTES + PAYLOAD_FIXED_BYTES + TAG_BYTES \
        == CIPHERTEXT_BYTES == 1339


def test_document_this_sizes_writes():
    """If the document and the code diverge, the document becomes a lie."""
    text = DOC.read_text(encoding="utf-8")
    assert "16 + 2 + 1289 + 32 = 1339" in text


def test_nonce_fresh_and_128_bit():
    """A different nonce on every encryption, which is what the birthday bound rests on."""
    nonce_set = {ENGINE.encrypt_text("same")[:NONCE_BYTES]
                 for _ in range(200)}
    assert len(nonce_set) == 200
    assert all(len(n) == 16 for n in nonce_set)


def test_same_message_two_times_different_cipher_text():
    """The determinism comes from the nonce, not from the algorithm."""
    a = ENGINE.encrypt_text("the same message")
    b = ENGINE.encrypt_text("the same message")
    assert a != b
    assert ENGINE.decrypt_text(a) == ENGINE.decrypt_text(b) == "the same message"


# ═══════════════ §3 domain separation ═══════════════

def test_three_sub_key_independent():
    """`M`, `KS` and `Km` come from the same PRK under different labels and must not collide."""
    nonce = primitives.new_nonce()
    m, ks, km = primitives.subkeys(KEY, nonce, 64)
    assert len(m) == SELECTOR_BYTES
    assert len(ks) == 64
    assert len(km) == 32
    # None may be a prefix of another (which would happen if they were cut from one stream)
    assert not ks.startswith(m)
    assert not ks.startswith(km)
    assert not km.startswith(m)


def test_nonce_when_it_changes_all_sub_keys_changes():
    a = primitives.subkeys(KEY, primitives.new_nonce(), 64)
    b = primitives.subkeys(KEY, primitives.new_nonce(), 64)
    assert all(x != y for x, y in zip(a, b))


def test_key_when_it_changes_all_sub_keys_changes():
    nonce = primitives.new_nonce()
    a = primitives.subkeys(KEY, nonce, 64)
    b = primitives.subkeys(bytes(range(1, 33)), nonce, 64)
    assert all(x != y for x, y in zip(a, b))


def test_tags_versioned_and_discrete():
    """The v1 (message) and v2 (hierarchy) labels must not mix."""
    from crypto import keys as ah
    v1 = {primitives.INFO_SELECTOR, primitives.INFO_PAYLOAD, primitives.INFO_MAC}
    v2 = {ah.INFO_DEVICE, ah.INFO_EPOCH, ah.INFO_CHAIN, ah.INFO_MESSAGE,
          ah.INFO_FINGERPRINT}
    assert len(v1) == 3 and len(v2) == 5
    assert not (v1 & v2)
    assert all(b"/v1/" in e for e in v1)
    assert all(b"/v2/" in e for e in v2)


# ═══════════════ §5 MAC coverage ═══════════════
#
# The document's most critical claim: the tag is taken over `H = N ‖ Cs ‖ Cp`,
# so the nonce and the selector are covered too. With incomplete coverage an
# attacker could change the nonce and force the receiver onto a different keystream.

@pytest.mark.parametrize("name, position", [
    ("nonce", 0),
    ("nonce sonu", NONCE_BYTES - 1),
    ("selector", NONCE_BYTES),
    ("selector sonu", NONCE_BYTES + SELECTOR_BYTES - 1),
    ("payload start", NONCE_BYTES + SELECTOR_BYTES),
    ("payload middle", NONCE_BYTES + SELECTOR_BYTES + 600),
    ("payload sonu", CIPHERTEXT_BYTES - TAG_BYTES - 1),
    ("tag start", CIPHERTEXT_BYTES - TAG_BYTES),
    ("end of tag", CIPHERTEXT_BYTES - 1),
])
def test_mac_every_region_covers(name, position):
    """A single bit change in EVERY region of the envelope has to be refused."""
    blob = bytearray(ENGINE.encrypt_text("a MAC coverage check"))
    blob[position] ^= 0x01
    with pytest.raises(VerificationError):
        ENGINE.decrypt_text(bytes(blob))


def test_nonce_if_changed_is_refused():
    """If the nonce were not covered this would pass, and it would be a disaster."""
    blob = ENGINE.encrypt_text("a nonce check")
    fake = bytearray(blob)
    fake[:NONCE_BYTES] = os.urandom(NONCE_BYTES)
    with pytest.raises(VerificationError):
        ENGINE.decrypt_text(bytes(fake))


def test_tag_without_verifying_parsing_none():
    """What closes off the padding oracle class of attacks.

    A text with a broken tag has to give the same error type WHATEVER its
    content is; parsing must never begin.
    """
    errors = set()
    for body in (bytes(PAYLOAD_FIXED_BYTES), b"\xFF" * PAYLOAD_FIXED_BYTES,
                 os.urandom(PAYLOAD_FIXED_BYTES)):
        blob = (primitives.new_nonce() + b"\x01\x02" + body + bytes(TAG_BYTES))
        try:
            ENGINE.decrypt_text(blob)
        except Exception as e:                    # noqa: BLE001
            errors.add(type(e).__name__)
    assert errors == {"VerificationError"}, errors


def test_tag_comparison_fixed_time_function_uses():
    """`compare_digest` rather than `==`, verified in the source."""
    source = (ROOT / "crypto" / "primitives.py").read_text(encoding="utf-8")
    assert "hmac.compare_digest" in source


# ═══════════════ §6 length gizleme ═══════════════

@pytest.mark.parametrize("length", [1, 2, 10, 100, 500, 1000, 1024])
def test_every_length_same_cipher_text_size(length):
    """The document's main claim: the length does not leak."""
    assert len(ENGINE.encrypt_text("a" * length)) == CIPHERTEXT_BYTES


def test_different_formulas_same_size():
    """Not only text; every corpus entry is the same size too."""
    from crypto.sampler import sample_or_free
    import random

    rng = random.Random(0)
    sizes = set()
    for e in list(CORPUS.active)[:15]:
        try:
            values, _ = sample_or_free(e, rng, max_rejections=100)
        except Exception:                          # an entry that cannot be sampled
            continue
        sizes.add(len(ENGINE.encrypt(e.slug, values, check=False)))
    assert sizes == {CIPHERTEXT_BYTES}, sizes


# ═══════════════ §7 memory — protected / unprotected ═══════════════

def test_long_lived_secrets_is_protected():
    """The document says "all the long lived secrets". Is that true?"""
    from crypto.keys import KeyChain, master_key_buffer
    from crypto.memory import SecureBuffer
    from crypto.handshake import Handshake, Identity

    with master_key_buffer() as master:
        assert isinstance(master, SecureBuffer)

    with Identity.generate() as who:
        assert isinstance(who.buffer, SecureBuffer)
        peer = Handshake(who, Identity.generate().public, initiator=True)
        assert isinstance(peer._ephemeral, SecureBuffer)
        peer._ephemeral.close()

    z = KeyChain(os.urandom(32))
    assert isinstance(z._chain, SecureBuffer)
    z.close()


def test_document_the_unprotected_also_counts():
    """The document has to say PLAINLY that the plaintext is not protected.

    The most dangerous state for a security document is not writing down what is missing.
    """
    text = DOC.read_text(encoding="utf-8")
    for expected in ("Plaintext is not protected in memory",
                     "payload_ks",
                     "no formal proof"):
        assert expected in text, f"the document does not say {expected!r}"


def test_document_pair_way_prf_assumption_states():
    """The assumption that surfaced in the analysis has to be named in the document."""
    text = DOC.read_text(encoding="utf-8")
    assert "DUAL PRF" in text or "dual PRF" in text
    assert "TLS 1.3" in text


# ═══════════════ §4 the birthday bound ═══════════════

def test_birthday_day_of_the_bound_arithmetic():
    """Is the table in the document computed correctly? q² / 2^129."""
    import math
    for q_us, expected_exp in ((20, -89), (32, -65), (48, -33), (56, -17)):
        q = 2 ** q_us
        probability = q * q / (2 ** 129)
        assert math.isclose(math.log2(probability), expected_exp, abs_tol=0.5), (
            f"q=2^{q_us}: hesap 2^{math.log2(probability):.1f}, "
            f"belge 2^{expected_exp}")
