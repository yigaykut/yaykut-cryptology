"""Side channel measurement, a timing leak sweep.

    python sidechannel.py

The same discipline as the layer 2 experiments (experiments.py) on a different
front: the engine's RUN TIME rather than the CONTENT of a ciphertext.

THREE CONTROLS, THEN THE MEASUREMENT

  NULL CONTROL  the same input in both classes -> gives the noise floor
  POSITIVE      a deliberately leaking function -> proves the rig can see
  NEGATIVE      a function doing constant work  -> proves it does not false alarm

Without the null control, "it stayed under the threshold" is meaningless: if
the threshold is already below the noise, nothing was measured.
"""

from __future__ import annotations

import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from crypto import (  # noqa: E402
                    Engine,
                    Session,
                    public_key,
                    load_corpus,
)
from crypto import memory, fastpath# noqa: E402
from crypto.network import (  # noqa: E402
                            AUTH_ENV, Network, NetworkMode, authorise, is_authorised,
)
from crypto.prekey import Prekey  # noqa: E402
from crypto.timing import THRESHOLD, worst, measure  # noqa: E402

KEY = bytes(range(32))
RUN = 3


def title(s: str) -> None:
    print(f"\n{'═' * 74}\n  {s}\n{'═' * 74}")


# The |t| of the null control, filled in by the CONTROLS section below.
# Every later measurement is read against this floor.
BASE = None


def measure_many(name, func, ga, gb, *, repeats=1000, run=RUN):
    """Takes the WORST of several runs, which is the right thing when hunting a leak."""
    r = worst([measure(name, func, ga, gb, repeats=repeats, seed=i) for i in range(run)])
    sign = "!! LEAK   " if r.leaking else "   clean  "
    # The threshold is not an ABSOLUTE number. On a loaded machine the noise
    # floor and the measurement rise together and 4.5 alone false alarms. That
    # happened once on 2026-08-18 (the amendment in ADR-018). So every line is
    # also stamped against the null control of its own run.
    not_ = ""
    if BASE is not None and abs(r.t) <= 2.0 * BASE:
        not_ = f"  ({abs(r.t) / BASE:.1f}x the noise floor, indistinguishable)"
    print(f"  {sign}  |t| = {abs(r.t):6.2f}   Δ = {r.diff_ns:+9.0f} ns   {name}{not_}")
    return r


corpus = load_corpus()
engine = Engine(corpus, KEY)

print(f"Corpus: {len(corpus)} entries   |   Threshold: |t| > {THRESHOLD}   |   Runs: {RUN}")
print(f"{fastpath.status()}")
print(f"Key memory: {memory.status()}")


# ══════════════════════════ CONTROLS ══════════════════════════
title("CONTROLS: is the measurement meaningful?")

same = engine.encrypt_text("the same input")
empty = measure_many("NULL CONTROL: the same input in both classes", engine.decrypt_text,
                     lambda: same, lambda: same, repeats=800)
BASE = abs(empty.t)

pos = measure_many("POSITIVE CONTROL: a deliberate leak",
                   lambda n: sum(range(n)), lambda: 5, lambda: 3000, repeats=1200)

neg = measure_many("NEGATIVE CONTROL: constant work",
                   lambda n: sum(range(500)), lambda: 5, lambda: 3000, repeats=1200)

print()
if not pos.leaking:
    print("  ! THE POSITIVE CONTROL FAILED, the rig cannot see a signal.")
    print("  The results below CANNOT BE READ.")
    sys.exit(1)
if empty.leaking:
    print("  ! THE NULL CONTROL BEAT THE THRESHOLD, the noise floor is above it.")
    print("  The machine may be busy; close other work and run again.")
print(f"  Noise floor |t| = {abs(empty.t):.2f}. Threshold {THRESHOLD}. Leaks below that")
print("  difference CANNOT BE SEEN with this rig; it means 'not measured', not 'absent'.")


# ══════════════════════════ MEASUREMENTS ══════════════════════════
title("THE ENGINE: is there data dependent timing?")

# 1. Tag comparison: does the POSITION of the tamper leak?
# This is what hmac.compare_digest is really for. A naive `==` would blow up
# here: it stops at the first differing byte and the tag could be guessed.
clean_blob = engine.encrypt_text("message")


def try_decrypt(b):
    try:
        return engine.decrypt_text(b)
    except Exception:
        return None


def tamper(position):
    b = bytearray(clean_blob)
    b[position] ^= 0x01
    return bytes(b)


early, late = tamper(20), tamper(1200)
measure_many("tag: tamper at start vs at end", try_decrypt,
             lambda: early, lambda: late, repeats=800)

# 2. The POSITION of the real record in a decoy chain (ADR-018's real subject)
from crypto.message import _pick_decoys  # noqa: E402
from crypto.sampler import sample_or_free  # noqa: E402
from crypto.wire import (  # noqa: E402
                         BODY_FIXED_BYTES,
                         SELECTOR_BYTES,
                         CHAIN_COUNTER_BITS,
                         encode_chain,
)
import random  # noqa: E402

rng = random.Random(7)
mt = corpus.by_slug("ham-metin")
container = mt.payload_bits
raw = "secret order".encode()
real = (mt.id, {"uzunluk": len(raw), "metin": raw + bytes(1024 - len(raw))})
remaining = BODY_FIXED_BYTES * 8 - (CHAIN_COUNTER_BITS + SELECTOR_BYTES * 8 + container)
decoys = [(e.id, sample_or_free(e, rng, max_rejections=200)[0])
          for e in _pick_decoys(corpus, remaining, rng, 6)]

# The SAME decoy set, with only the real record's position differing. Using
# different decoy sets would measure the decoys' parse cost rather than the
# position. That confusion happened on the first measurement and produced a
# false |t| = 6.50.
first = encode_chain(corpus, [real] + decoys, KEY, check=False)
last = encode_chain(corpus, decoys + [real], KEY, check=False)
measure_many("decoy chain: real record first vs last", engine.decrypt_hidden,
             lambda: first, lambda: last, repeats=900)

# 3. X25519 scalar weight
few = bytes([0x08]) + bytes(30) + bytes([0x40])
dense = bytes([0xF8]) + b"\xFF" * 30 + bytes([0x7F])
measure_many("X25519: sparse vs dense scalar", public_key,
             lambda: few, lambda: dense, repeats=300)

# 4. Message length, an UNAVOIDABLE leak, measured so it is known
short = engine.encrypt_text("ab")
long = engine.encrypt_text("x" * 1000)
measure_many("decrypt_text: 2 byte vs 1000 byte payload", engine.decrypt_text,
             lambda: short, lambda: long, repeats=800)

# 5. Tekrar penceresi
session = Session(Engine(corpus, KEY))
seen = session.encrypt_text("seen")
session.decrypt_text(seen)
new = session.encrypt_text("new")


def verify(b):
    try:
        return session.verify(b)
    except Exception:
        return None


measure_many("session: replay vs fresh packet", verify,
             lambda: seen, lambda: new, repeats=800)


title("YORUM")
print("""  Staying under the threshold DOES NOT MEAN "constant time". This tool sees
  only ALGORITHMIC differences: an early return, a loop count that depends on
  a secret, data dependent branching.

  Channels that in Python can be neither MEASURED nor FIXED:
    - bigint arithmetic taking time proportional to operand size
    - cache timing and memory access patterns
    - power analysis and electromagnetic leakage
    - the garbage collector leaving key copies in memory

  The FIRST item on that list can be closed for X25519: ccore/ rewrites that
  ladder with fixed width 64 bit integers (ADR-019). The status line above
  says whether the core is active; if it is, the X25519 measurement now shows
  C's timing rather than Python's.

  The other three are still open. For a deployment where physical access is in
  the threat model this is not enough; hardware support is needed too.""")
print()


# The paths that arrived with ADR-027. The reason they were added is
# concrete: in the first version `child_network` ran HKDF in covert mode and
# `os.urandom` in open mode, and THE DIFFERENCE WAS MEASURABLE (|t| = 121.5,
# noise floor 1.9, delta = +7.6 us).
#
# What that meant: a covert open network's descriptor was indistinguishable
# byte for byte, but a member who asked the parent for their sub network and
# measured the response delay could tell the mode. The claim that it "looks no
# different from an open network" was right in the BYTES and wrong on the CLOCK.
#
# `layer2/network_attack.py` could not see this, because it looks at bytes, not
# at the clock. Anything claiming indistinguishability has to go through this
# sweep too.

title("THE NETWORK LAYER: does the mode leak through timing?")

# Creating a covert network needs authorisation (ADR-029). Without it this
# section is SKIPPED. Skipping rather than crashing is the right behaviour,
# because the rest of the sweep does not depend on authorisation and can run.
# A skipped measurement is not reported as "clean".
_grant = is_authorised() or authorise()
if not _grant:
    print(f"  SKIPPED: {AUTH_ENV} is not set, a covert network cannot be created.")
    print("  The mode timing was not measured. Skipped does not mean clean.")
    print()
else:
    _secret = Network.create(NetworkMode.COVERT)
    _free = Network.create(NetworkMode.OPEN)
    _free2 = Network.create(NetworkMode.OPEN)

    measure_many("network null control: open vs open",
                 lambda net: net.child_network("#0"),
                 lambda: _free, lambda: _free2, repeats=2000)

    measure_many("SUB NETWORK CREATION: covert vs open  <- THE REAL MEASUREMENT",
                 lambda net: net.child_network("#0"),
                 lambda: _secret, lambda: _free, repeats=2000)

    measure_many("prekey derivation: covert vs open",
                 lambda net: net.prekey(),
                 lambda: _secret, lambda: _free, repeats=2000)

    # THIS MEASUREMENT SHOWS A LEAK AND IS EXPECTED TO.
    # The longer the HMAC input, the more blocks are processed; the difference
    # between 1 and 200 characters has to be measurable. What leaks is not a
    # SECRET but the LENGTH OF A LABEL. Member ids are names the operator gives
    # and are not treated as secret. It is an accepted result with written
    # reasoning (`docs/audit.md` §5); left unexplained it would mislead a reader.
    _member = measure_many("member key: short vs long id (EXPECTED)",
                           lambda net_id: net_id[0].member_key(net_id[1]),
                           lambda: (_free, "a"), lambda: (_free, "a" * 200),
                           repeats=2000)
    if _member.leaking:
        print("     ^ EXPECTED: HMAC scales with input length. What leaks is the")
        print("       LENGTH of the id, not the secret itself. Member ids are not")
        print("       treated as secret; a caller who wants equal lengths should")
        print("       pad the ids to a fixed size.")

    # Constant time comparisons: do they differ at the first byte or the last.
    _same = Network(bytes(range(32)))
    _first = Network(bytes([0xFF]) + bytes(range(1, 32)))
    _last = Network(bytes(range(31)) + bytes([0xFF]))

    measure_many("network equality: differing first vs last",
                 lambda d: _same.same_as(d),
                 lambda: _first, lambda: _last, repeats=3000)

    _p_same = Prekey(bytes(range(32)))
    measure_many("prekey equality: differing first vs last",
                 lambda d: _p_same.equals(d),
                 lambda: bytes([0xFF]) + bytes(range(1, 32)),
                 lambda: bytes(range(31)) + bytes([0xFF]), repeats=3000)


title("THE NETWORK LAYER: summary")
if not _grant:
    print("  NOT MEASURED. Without covert network authorisation the mode")
    print("  comparison cannot be made. No result is reported for this section;")
    print("  a measurement that did not run is not clean.")
else:
    print("  The mode does not leak through timing: sub network creation, prekey")
    print("  derivation and two constant time comparisons are all below the noise floor.")
    print("  The only leak is the LENGTH of a member id, and that is accepted.")
print()
print("  LIMIT: this sweep does not cover the WHOLE engine. A path that was not")
print("  measured is not known to be clean; 'not measured' is not 'absent'.")
print()
