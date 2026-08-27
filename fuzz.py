"""Fuzzing: how the decoder behaves on malformed and hostile input.

    python fuzz.py [rounds] [seed]

NE ARANIYOR

There is a single invariant and every campaign tests it:

    Every input that is not genuine must be refused with a RECOGNISED error.

"Recognised error" means `CryptoError` and its subclasses. Anything outside
that is a finding:

  - `IndexError`, `struct.error`, `ValueError`: a parser boundary was
    denetimi yapmadan okuyor demektir.
  - `MemoryError` or a hang: the attacker can burn resources through a length field.
  - **Silent success**, the worst of all. If a forged ciphertext returns a
    value, the genuineness check has been punched through.

NEDEN SADECE RASTGELE BAYT YETMEZ

Random bytes catch on the tag and NEVER REACH the parser; that kind of
fuzzing only tests HMAC, which OpenSSL wrote. The interesting territory is
past the tag: a ciphertext produced with a valid key but hostile INSIDE.
An attacker cannot normally get there, but an implementation bug, a key
leak, or a mode added later could take them there. The fourth campaign
(`dusmanca_payload`) hammers exactly that spot, and that is where the
findings come from.

REPRODUCTION
Every finding is reported with its seed, and `python fuzz.py 1000 <seed>`
reproduces the same sequence.
"""

from __future__ import annotations

import io
import os
import random
import sys
import traceback


def _utf8_output() -> None:
    """Switches the console to UTF-8; on Windows cp1254 cannot print the box drawing.

    NOT DONE AT MODULE LEVEL: it broke output capture for a pytest run that
    does `import fuzz`. It is only wrapped when running as a script.
    """
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


from crypto import (  # noqa: E402
                    KeyManagementError,
                    CryptoError,
                    Engine,
                    Session,
                    load_corpus,
)
from crypto import primitives, curve  # noqa: E402
from crypto.frame import FRAME_BYTES, MAX_SEQ, VERSION  # noqa: E402
from crypto.wire import (  # noqa: E402
                         PAYLOAD_FIXED_BYTES,
                         SELECTOR_BYTES,
                         CIPHERTEXT_BYTES,
)

KEY = bytes(range(32))
BASE_POINT = bytes([9] + [0] * 31)


class Finding:
    def __init__(self, campaign: str, ne: str, entry: bytes, trace: str) -> None:
        self.campaign, self.ne, self.entry, self.trace = campaign, ne, entry, trace

    def __str__(self) -> str:
        head = self.entry[:32].hex() if self.entry else "(none)"
        return (f"\n  [{self.campaign}] {self.ne}\n"
                f"    input (first 32 bytes): {head}\n"
                f"    {self.trace}")


def _try(findings, campaign, name, func, entry=b"", *,
         success_accept=False):
    """Calls the function; only CryptoError is accepted.

    With `basari_kabul=False` a successful return is also a finding, because
    the input is not a genuine ciphertext and should not return a value.
    """
    try:
        func()
    except CryptoError:
        return                                   # expected and correct
    except RecursionError as e:
        findings.append(Finding(campaign, f"{name}: recursion overflow", entry, repr(e)))
    except Exception as e:                       # noqa: BLE001, deliberate
        trace = traceback.format_exc(limit=3).strip().splitlines()[-1]
        findings.append(Finding(
            campaign, f"{name}: UNEXPECTED error {type(e).__name__}", entry, trace))
    else:
        if not success_accept:
            findings.append(Finding(
                campaign, f"{name}: SILENT SUCCESS, a forged input was accepted",
                entry, "the genuineness check was punched through"))


def _wrap(sel_id: int, payload_pt: bytes, key: bytes = KEY) -> bytes:
    """Produces a ciphertext with an arbitrary interior and a VALID TAG.

    The same as the last three lines of `wire.encode`. The point is to be
    able to hammer the parser past the tag, which is unreachable normally.
    """
    payload_pt = payload_pt[:PAYLOAD_FIXED_BYTES].ljust(PAYLOAD_FIXED_BYTES, b"\x00")
    nonce = primitives.new_nonce()
    sel_mask, ks, mac_key = primitives.subkeys(key, nonce, len(payload_pt))
    selector = primitives.xor(sel_id.to_bytes(SELECTOR_BYTES, "big"), sel_mask)
    head = nonce + selector + primitives.xor(payload_pt, ks)
    return head + primitives.tag(mac_key, head)


# ══════════════════════════ CAMPAIGNS ══════════════════════════

def campaign_random(engine, rng, round, findings):
    """Entirely random bytes. They should catch on the tag."""
    for _ in range(round):
        n = rng.choice([0, 1, 16, 50, CIPHERTEXT_BYTES - 1,
                        CIPHERTEXT_BYTES, CIPHERTEXT_BYTES + 1, 5000])
        blob = bytes(rng.getrandbits(8) for _ in range(n))
        for name, f in (("decode", engine.decode), ("decrypt_text", engine.decrypt_text),
                      ("decode_chain", engine.decode_chain),
                      ("decrypt_hidden", engine.decrypt_hidden),
                      ("read_frame", engine.read_frame)):
            _try(findings, "random", name, lambda f=f, b=blob: f(b), blob)


def campaign_bitflip(engine, rng, round, findings):
    """Bit flips in a valid ciphertext; the tag must ALWAYS catch them."""
    valid = engine.encrypt_text("bit flip target")
    for _ in range(round):
        b = bytearray(valid)
        for _ in range(rng.randint(1, 3)):
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        blob = bytes(b)
        if blob == valid:
            continue
        _try(findings, "bit-flip", "decrypt_text",
             lambda x=blob: engine.decrypt_text(x), blob)


def campaign_truncate(engine, rng, round, findings):
    """Truncation and extension."""
    valid = engine.encrypt_text("kesme hedefi")
    for _ in range(round):
        if rng.random() < 0.5:
            blob = valid[:rng.randrange(len(valid))]
        else:
            blob = valid + bytes(rng.getrandbits(8)
                                 for _ in range(rng.randint(1, 64)))
        _try(findings, "kesme/uzatma", "decrypt_text",
             lambda x=blob: engine.decrypt_text(x), blob)


def campaign_hostile_payload(engine, corpus, rng, round, findings):
    """A VALID TAG with a hostile interior, the interesting territory."""
    identities = [e.id for e in corpus.active]
    for _ in range(round):
        sel = rng.choice(identities + [0, 1, 0xFFFF, 0xFFFE, 0x0501])
        n = rng.choice([0, 1, FRAME_BYTES, FRAME_BYTES + 1, 64,
                        PAYLOAD_FIXED_BYTES])
        body = bytes(rng.getrandbits(8) for _ in range(n))
        blob = _wrap(sel, body)
        for name, f in (("decode", engine.decode), ("decrypt_text", engine.decrypt_text),
                      ("decode_chain", engine.decode_chain),
                      ("decrypt_hidden", engine.decrypt_hidden),
                      ("read_frame", engine.read_frame)):
            # These inputs pass the tag, so SUCCESS is also possible
            # (random bytes can represent a valid record). What is being
            # looked for is crashes, hangs and unexpected error types.
            _try(findings, "hostile-payload", name,
                 lambda f=f, b=blob: f(b), blob, success_accept=True)


def campaign_frame(engine, corpus, rng, round, findings):
    """The frame header: version and sequence number edges."""
    entry = corpus.by_slug("ham-metin")
    for _ in range(round):
        version = rng.choice([0, 1, VERSION, VERSION + 1, 255])
        order = rng.choice([0, 1, MAX_SEQ, MAX_SEQ - 1,
                            rng.randrange(1 << 64)])
        head = bytes([version]) + order.to_bytes(8, "big")
        body = bytes(rng.getrandbits(8) for _ in range(64))
        blob = _wrap(entry.id, head + body)
        _try(findings, "frame", "read_frame",
             lambda x=blob: engine.read_frame(x), blob, success_accept=True)
        _try(findings, "frame", "decode",
             lambda x=blob: engine.decode(x), blob, success_accept=True)


def campaign_session(engine, rng, round, findings):
    """The replay window: random sequence numbers, replays must be refused."""
    for _ in range(max(1, round // 40)):
        session = Session(engine, window=rng.choice([1, 8, 64, 4096]))
        seen = []
        for _ in range(40):
            if seen and rng.random() < 0.4:
                blob = rng.choice(seen)         # tekrar
                _try(findings, "session", "replay refused",
                     lambda x=blob: session.verify(x), blob)
            else:
                blob = session.encrypt_text("fresh")
                _try(findings, "session", "fresh packet",
                     lambda x=blob: session.verify(x), blob,
                     success_accept=True)
                seen.append(blob)


def campaign_curve(rng, round, findings):
    """X25519 and the handshake: arbitrary public keys."""
    from crypto.handshake import Handshake, Identity

    for _ in range(round):
        u = rng.choice([
            bytes(32),
            bytes([1] + [0] * 31),
            b"\xFF" * 32,
            ((1 << 255) - 19).to_bytes(32, "little"),
            bytes(rng.getrandbits(8) for _ in range(32)),
        ])
        g = bytes(rng.getrandbits(8) for _ in range(32))
        _try(findings, "curve", "x25519",
             lambda: curve.x25519(g, u), u, success_accept=True)
        _try(findings, "curve", "shared_secret",
             lambda: curve.shared_secret(g, u), u, success_accept=True)

    for _ in range(max(1, round // 20)):
        who = Identity.generate()
        try:
            against = bytes(rng.getrandbits(8) for _ in range(32))
            peer = Handshake(who, against, initiator=rng.random() < 0.5)
            ephemeral = bytes(rng.getrandbits(8) for _ in range(32))
            _try(findings, "curve", "handshake complete",
                 lambda: peer.complete(ephemeral), against, success_accept=True)
        finally:
            who.close()


# ══════════════════ POSITIVE CONTROL ══════════════════

def campaign_positive_control(findings):
    """Does the rig actually see errors?

    An uncontrolled "clean" result says nothing: the fuzzer might be calling
    nothing at all. Three defects that must certainly be caught are fed in
    here. If all three are not caught, every "clean" line above is
    worthless.

    The findings go to a SEPARATE list, so this campaign does not enter the
    report as a "finding" but as proof that the rig works.
    """
    local: list[Finding] = []

    def out_of_bounds():
        empty = b""
        return empty[5]                       # IndexError

    def silent_accept():
        return "forged plaintext"           # raises nothing

    def wrong_kind():
        int("this is not a number")         # ValueError

    _try(local, "control", "out of bounds read", out_of_bounds)
    _try(local, "control", "silent accept", silent_accept)
    _try(local, "control", "wrong type", wrong_kind)

    if len(local) != 3:
        findings.append(Finding(
            "POSITIVE CONTROL",
            f"THE RIG IS BROKEN, {len(local)} of 3 defects were caught",
            b"", "the 'clean' results of the other campaigns cannot be trusted"))
    return len(local)


# ══════════════════════════ THE RUN ══════════════════════════

def run(round: int = 400, seed: int | None = None) -> list[Finding]:
    seed = seed if seed is not None else int.from_bytes(os.urandom(4), "big")
    rng = random.Random(seed)
    corpus = load_corpus()
    engine = Engine(corpus, KEY)
    findings: list[Finding] = []

    print(f"Seed: {seed}   Rounds: {round}   Corpus: {len(corpus)} entries")
    print(f"To reproduce: python fuzz.py {round} {seed}\n")

    caught = campaign_positive_control(findings)
    stamp = "ok" if caught == 3 else "!! THE RIG IS BROKEN"
    print(f"  POSITIVE CONTROL: {caught} of 3 defects caught {stamp}\n")

    campaigns = [
        ("random bytes", lambda: campaign_random(engine, rng, round, findings)),
        ("bit flip", lambda: campaign_bitflip(engine, rng, round, findings)),
        ("kesme/uzatma", lambda: campaign_truncate(engine, rng, round, findings)),
        ("hostile payload",
         lambda: campaign_hostile_payload(engine, corpus, rng, round, findings)),
        ("frame", lambda: campaign_frame(engine, corpus, rng, round, findings)),
        ("session", lambda: campaign_session(engine, rng, round, findings)),
        ("curve", lambda: campaign_curve(rng, max(1, round // 4), findings)),
    ]

    for name, f in campaigns:
        once = len(findings)
        f()
        new = len(findings) - once
        sign = f"!! {new} findings" if new else "   clean"
        print(f"  {sign}   {name}")

    return findings


def main() -> int:
    round = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else None

    print(f"\n{'═' * 74}\n  FUZZING: what does the decoder do with broken input?\n{'═' * 74}")
    findings = run(round, seed)

    print(f"\n{'═' * 74}")
    if not findings:
        print("  No findings.\n")
        print("  AN HONEST NOTE: this does not mean 'no bugs', it means 'none")
        print("  found with this seed and these campaigns'. Fuzzing is evidence")
        print("  of presence, not evidence of absence.")
        return 0

    print(f"  {len(findings)} FINDINGS\n{'═' * 74}")
    for b in findings[:20]:
        print(b)
    if len(findings) > 20:
        print(f"\n  ... and {len(findings) - 20} more findings")
    return 1


if __name__ == "__main__":
    _utf8_output()
    raise SystemExit(main())
