"""A network specific derived corpus, each network with its own formula set.

WHAT WAS ASKED FOR

"Different derived operations per network, so the ciphers do not get mixed up."

WHAT IT GIVES AND WHAT IT DOES NOT, and the distinction matters

Mixing was NOT being prevented by the corpus in the first place. Network A's
message does not decode in B, because the tag (MAC) is computed with a 256
bit key and fails under the wrong one. That is enough on its own, and a
corpus difference ADDS nothing: a corpus id carries at most 16 bits (ADR-025)
while the MAC is 256.
So what a network specific corpus does give:

  + WATERMARK, the real gain. Every network's corpus derives
    deterministically from that network's root secret. If a corpus file leaks,
    it is clear which network it came from. That is exactly what a canary
    trap looks for: the leaked THING showing its source.

  + OPERATIONAL COMPARTMENTALISATION. Because networks have different formula
    pools, one network's operator cannot accidentally interpret another's
    traffic with their own corpus. It protects against accidents, not attackers.

  + AGREEMENT WITHOUT TRANSPORT. The corpus seed derives from the network's
    root secret, so two ends produce the SAME corpus without exchanging a
    single byte. No corpus files need distributing.

  x IT GIVES NO SECRECY. The corpus itself is not a secret (ADR-025), and
    nothing here treats a hoped-for secret as a security parameter.

  x IT DOES NOT CHANGE THE MESSAGE SIZE. Derived entries scale parameter
    widths; the wire format is identical.

THE GENERATOR IS NOT MERSENNE TWISTER

The corpus stream comes from `HkdfGenerator`: the `random.Random` interface,
with the entropy coming from HKDF. The first version used a plain
`random.Random` and justified it with "the seed goes through HKDF". The
justification was correct but answered the wrong question: the root secret
was protected, the generator itself was not. Details in `HkdfGenerator`.

NO MATHEMATICS IS GENERATED

Only `derivatives` is used, never `generate` (structural). A derived entry
INHERITS its mathematics from its parent, where it has been verified
(ADR-026 §6). A structural entry carries unverified mathematics, and putting
it into a corpus that will carry a network's real traffic would not be
honest. Structural entries belong in the decoy pool (ADR-012).

AN ARCHITECTURAL BOUNDARY

This module is in `layer2`, NOT in `crypto`. `crypto/network.py` only
produces the seed (pure HKDF); the code that builds the corpus lives here.
The cipher path never imports `layer2`, which is the project's basic rule.
"""

from __future__ import annotations

import random

from crypto import primitives
from crypto.corpus import Corpus, load_corpus

from .exam import _make_entry, exam_1_4
from .generator import learn, derivatives

DEFAULT_COUNT = 12


INFO_STREAM = b"kripto/v4/ag/korpus-akis"


class HkdfGenerator(random.Random):
    """The `random.Random` interface, over an HKDF stream INSTEAD OF Mersenne Twister.

    NEDEN VAR

    The first version generated the corpus with
    `random.Random(int.from_bytes(seed))` and that was a gap: **Mersenne
    Twister is not a CSPRNG.** Anyone who sees 624 consecutive 32 bit outputs
    fully reconstructs the internal state and computes past and future output.

    In that version the danger was JUSTIFIED with "the seed goes through
    HKDF, so there is no way back to the root secret". True, but it answered
    the wrong question: the root secret was protected, the GENERATOR itself
    was not. From a leaked corpus one could reconstruct the MT state and
    compute every entry the network makes. It was removed, not justified.

    NASIL

    The stream comes from `HKDF-Expand(PRK, "korpus-akis" ‖ counter)` blocks.
    `choice`, `choices` and `sample` work exactly as they do on the parent
    `random.Random`; only the entropy source changed. Being one way, seeing
    the output does not let the state be reconstructed.

    HONEST LIMIT: this is not a speed optimisation, it is the opposite. HKDF
    means one HMAC round per block. Corpus generation is a rare operation so
    the cost is irrelevant; in a hot loop the choice would be arguable.
    """

    __slots__ = ("_prk", "_buffer", "_position", "_counter")

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError(f"the seed must be bytes, got: {type(seed).__name__}")
        if len(seed) < 16:
            raise ValueError(f"the seed must be at least 16 bytes, got: {len(seed)}")
        self._prk = primitives.hkdf_extract(salt=b"", ikm=bytes(seed))
        self._buffer = b""
        self._position = 0
        self._counter = 0
        # `Random.__init__` calls `seed()`; the state was built above.
        super().__init__()

    def seed(self, a=None, version: int = 2) -> None:  # noqa: D102, ARG002
        """Called by `Random.__init__`. The seed only comes from the constructor."""
        return None

    def getstate(self):
        raise NotImplementedError(
            "HkdfGenerator state is not exported. State being portable is "
            "the very problem we are closing off in MT")

    def setstate(self, state) -> None:
        raise NotImplementedError("HkdfGenerator state cannot be set from outside")

    def _bytes(self, n: int) -> bytes:
        while len(self._buffer) - self._position < n:
            self._buffer = self._buffer[self._position:] + primitives.hkdf_expand(
                self._prk, INFO_STREAM + self._counter.to_bytes(8, "big"), 64)
            self._position = 0
            self._counter += 1
        output = self._buffer[self._position:self._position + n]
        self._position += n
        return output

    def getrandbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("the bit count cannot be negative")
        if k == 0:
            return 0
        n = (k + 7) // 8
        return int.from_bytes(self._bytes(n), "big") >> (n * 8 - k)

    def random(self) -> float:
        # A 53 bit mantissa, the same resolution `Random.random` gives.
        return (int.from_bytes(self._bytes(7), "big") >> 3) * 2 ** -53


def _rng(seed: bytes) -> random.Random:
    """A deterministic generator from a byte seed, over an HKDF stream."""
    return HkdfGenerator(seed)


def net_entries(seed: bytes, base: Corpus | None = None,
                count: int = DEFAULT_COUNT, *,
                elimination: bool = True) -> list[dict]:
    """Network specific derived entries, as raw dicts.

    With `eleme=True` the entries go through the engine's own gates and the
    failures are DISCARDED, so the number returned can be smaller than
    `adet`. A network's corpus is better short than corrupt.
    """
    base = base if base is not None else load_corpus()
    rng = _rng(seed)
    profile = learn(base)
    raws = derivatives(base, profile, count, rng)
    if not elimination:
        return raws

    report = exam_1_4(raws, base, seed=0)
    elapsed = {s.slug for s in report.passing}
    return [h for h in raws if h["slug"] in elapsed]


def net_corpus(seed: bytes, base: Corpus | None = None,
               count: int = DEFAULT_COUNT, *,
               base_included: bool = True, elimination: bool = True) -> Corpus:
    """The corpus a network uses: the base corpus plus its own derivatives.

    `temel_dahil=False` leaves the network with only its own derivatives. The
    default is `True`: there is nothing to gain by throwing away verified real
    mathematics, and the derivatives already link to their parents through `related`.
    """
    base = base if base is not None else load_corpus()
    raws = net_entries(seed, base, count, elimination=elimination)
    entries = [_make_entry(h) for h in raws]
    if base_included:
        entries = list(base) + entries
    return Corpus(entries)


def watermark(corpus: Corpus) -> frozenset[int]:
    """The corpus's network specific identity: the set of derived entry ids.

    To find which network a leaked corpus came from: generate a corpus from
    each candidate network's seed and compare the watermarks. A match gives
    the source.

    This is NOT PROOF. Two networks could pick the same ids by chance, and a
    leaker can change the ids. It is a marker that helps trace, not a
    signature for a courtroom.
    """
    return frozenset(e.id for e in corpus
                     if "derived" in (e.doc.get("tags") or []))
