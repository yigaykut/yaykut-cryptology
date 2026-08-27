"""An engine walkthrough.

    python demo.py

It shows end to end what layer 1 does: encryption, decryption, the effect of
the nonce, tamper detection and the known length leak.
"""

from __future__ import annotations

import io
import os
import random
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from crypto import (  # noqa: E402
                    KeyChain,
                    VerificationError,
                    Handshake,
                    SecureChannel,
                    Identity,
                    public_key,
                    handshake_unpack,
                    handshake_pack,
                    private_key,
                    ConstraintViolation,
                    Engine,
                    SamplingError,
                    OVERHEAD_BYTES,
                    Session,
                    CIPHERTEXT_BYTES,
                    ReplayError,
                    master_key,
                    device_key,
                    epoch_key,
                    load_corpus,
                    text_capacity,
                    sample,
                    sample_or_free,
                    fingerprint,
                    hard_constraints,
)
from crypto.primitives import NONCE_BYTES, SELECTOR_BYTES  # noqa: E402


def title(s: str) -> None:
    print(f"\n{'─' * 72}\n{s}\n{'─' * 72}")


corpus = load_corpus()
key = os.urandom(32)
engine = Engine(corpus, key)

title(f"Corpus: {len(corpus)} entries loaded")
for e in list(corpus)[:5]:
    print(f"  0x{e.id:04X}  {e.payload_bytes:>5} bytes  {e.name}")
print(f"  ... and {len(corpus) - 5} more entries")


title("1. Encrypt and decrypt")
entry = corpus.by_slug("ec-weierstrass-short")
values = {"p": 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F,
          "a": 0, "b": 7}

blob = engine.encrypt(entry.id, values)
back, decrypted = engine.decode(blob)

print(f"  Formula     : {entry.name}  (0x{entry.id:04X})")
print(f"  Ciphertext  : {len(blob)} bytes")
print(f"    nonce     : {blob[:NONCE_BYTES].hex()}")
print(f"    selector  : {blob[NONCE_BYTES:NONCE_BYTES + SELECTOR_BYTES].hex()}")
print(f"    payload   : {blob[NONCE_BYTES + SELECTOR_BYTES:NONCE_BYTES + SELECTOR_BYTES + 8].hex()}...")
print(f"    tag       : {blob[-32:][:8].hex()}...")
print(f"  Decoded back: 0x{back.id:04X}  a={decrypted['a']}  b={decrypted['b']}")
print(f"  Correct?    : {back.id == entry.id and decrypted['b'] == 7}")


title("2. Same entry, same key, a different output every time")
print("  The unpredictability comes from the nonce; the algorithm is fully deterministic (ADR-001).\n")
for i in range(3):
    b = engine.encrypt(entry.id, values)
    sel = b[NONCE_BYTES:NONCE_BYTES + SELECTOR_BYTES].hex()
    print(f"  {i + 1}.  selector={sel}   first 16 bytes={b[:16].hex()}")
print(f"\n  The real id is 0x{entry.id:04X} every time, but the selector is always different.")


title("3. Tamper detection")
blob = engine.encrypt(entry.id, values)
for region, position in [("nonce", 0), ("selector", NONCE_BYTES), ("payload", NONCE_BYTES + 4), ("tag", len(blob) - 1)]:
    broken = bytearray(blob)
    broken[position] ^= 0x01
    try:
        engine.decode(bytes(broken))
        print(f"  {region:<10} one bit flipped -> PASSED  (THIS IS A BUG)")
    except VerificationError:
        print(f"  {region:<10} one bit flipped -> refused ok")

try:
    Engine(corpus, os.urandom(32)).decode(blob)
    print("  wrong key       -> PASSED  (THIS IS A BUG)")
except VerificationError:
    print("  wrong key       -> refused ok")


title("4. Constraints are enforced")
affine = corpus.by_slug("afin-sifre")
try:
    engine.encrypt(affine.id, {"m": 30, "a": 7, "b": 3})
except ConstraintViolation as e:
    print(f"  m=30 refused: {e.reason}")
try:
    engine.encrypt(affine.id, {"m": 5, "a": 13, "b": 3})
except ConstraintViolation as e:
    print(f"  a=13 refused: {e.reason}")
b = engine.encrypt(affine.id, {"m": 7, "a": 7, "b": 3})
_, v = engine.decode(b)
print(f"  m=7, a=7 accepted and decoded back: m={v['m']}")
print(f"  did the key (a, b) come back? {'a' in v}  <- secret parameters are not carried")

retired = [e for e in corpus if e.status == "retired"]
if retired:
    e = retired[0]
    try:
        engine.encrypt(e.id, {p["name"]: 0 for p in e.params})
        print(f"  encrypting with {e.name} -> PASSED  (THIS IS A BUG)")
    except Exception as error:
        print(f"\n  Encrypting with a retired entry ({e.name}) was refused ok")
        print(f"    {str(error).split('.')[0]}.")


title("5. The length leak is closed (ADR-007)")
print("  The payload is padded to a fixed size for every formula. However small the")
print("  real data is, the text sent is always the same length:\n")
print(f"  {'formula':<34} {'real payload':>15} {'sent':>12}")
samples = ["afin-sifre", "aes-sbox", "ec-weierstrass-short", "rsa-modexp", "elgamal-sifreleme"]


def _encrypt(e):
    """0x0303 cannot be sampled under constraints (ADR-006); length needs none."""
    values, valid = sample_or_free(e, random.Random(e.id))
    return engine.encrypt(e.id, values, check=valid)


for slug in samples:
    e = corpus.by_slug(slug)
    print(f"  {e.name[:33]:<34} {e.payload_bytes:>12} bytes {len(_encrypt(e)):>7} bytes")

lengths = {len(_encrypt(e)) for e in corpus.active}
print(f"\n  Distinct lengths observed across the whole corpus: {len(lengths)}")
print(f"  Best accuracy obtainable from length: {100 / len(corpus.active):.1f}%"
      f"  (1/{len(corpus.active)}, which is chance)")
print(f"\n  The cost: the affine cipher's 1 byte of data travels as {CIPHERTEXT_BYTES} bytes.")


title("6. Sampler status, the layer 2 data pipeline")
hard = []
for e in corpus:
    try:
        sample(e, random.Random(e.id), max_rejections=2000)
    except SamplingError:
        hard.append(e)

print(f"  {len(corpus) - len(hard)}/{len(corpus)} entries sample automatically.")
if hard:
    print("\n  Entries that cannot be sampled, and the blocking constraints (measured rejection rate):")
    for e in hard:
        print(f"    0x{e.id:04X}  {e.name}")
        for expr, ratio in hard_constraints(e, random.Random(1)):
            print(f"          {ratio * 100:5.1f}% red  <-  {expr}")
    print("\n  These need the constraint guided sampler (ADR-006).")


title("7. Free text encryption")
print(f"  Capacity: {text_capacity(corpus)} bytes of UTF-8 in a single ciphertext\n")

for message in ["Hello", "Modern cryptography: keys, nonces, tags", "A" * 900]:
    blob = engine.encrypt_text(message)
    back = engine.decrypt_text(blob)
    display = message if len(message) <= 40 else f"{message[:18]}... ({len(message)} characters)"
    print(f"  “{display}”")
    print(f"     -> {len(blob)} bytes: {blob[:24].hex()}...")
    print(f"     <- \"{back if len(back) <= 40 else back[:18] + '...'}\"   equal: {back == message}")

print("\n  All three messages produced a ciphertext of the same length. The length")
print("  field lives inside the payload and is encrypted, so the message size does not leak.")

try:
    engine.decrypt_text(engine.encrypt("afin-sifre", {"m": 7, "a": 7, "b": 3}))
except Exception as error:
    print(f"\n  Trying to decode a formula carrying text as raw text was refused ok")
    print(f"    {str(error).split('.')[0]}.")


title("8. Replay protection (ADR-014)")
print("  The engine is stateless: give it the same packet twice and it decodes twice.")

record = engine.encrypt_text("FIRE AT WILL")
print(f"  Engine      : {engine.decrypt_text(record)!r}  ->  {engine.decrypt_text(record)!r}")
print("               the same packet passed twice; an attacker could record and replay it.\n")

session = Session(Engine(corpus, key))
record = session.encrypt_text("FIRE AT WILL")
print(f"  Session     : {session.decrypt_text(record)!r}")
try:
    session.decrypt_text(record)
except ReplayError as error:
    print(f"  Same packet: refused ok")
    print(f"    {str(error).split('.')[0]}.")

print("\n  The sequence number lives INSIDE the payload, encrypted and under the MAC.")
print("  From outside, not even the message count is visible:")
for i in range(3):
    b = session.encrypt_text("the same text")
    print(f"     #{session.engine.read_frame(b).seq}  {b[:20].hex()}...")
print(f"\n  All three are the same text, the same key, {CIPHERTEXT_BYTES} bytes, and none resemble each other.")


title("9. Key hierarchy and forward secrecy (ADR-015)")
master = master_key()
print(f"  master key     {fingerprint(master)}   (stays in the vault)")
for device in ("uav-01", "uav-02"):
    k = device_key(master, device)
    print(f"    {device:8s}     {fingerprint(k)}   epoch 202608 -> "
          f"{fingerprint(epoch_key(k, 202608))}")

a = Engine(corpus, device_key(master, "uav-01"))
b = Engine(corpus, device_key(master, "uav-02"))
try:
    b.decrypt_text(a.encrypt_text("position report"))
except VerificationError:
    print("\n  uav-02 could not open uav-01's message ok. If one device falls, the fleet is safe.")

chain = KeyChain(device_key(master, "uav-01"))
yesterday = Engine(corpus, chain.advance()).encrypt_text("yesterday's report")
for _ in range(3):
    chain.advance()
try:
    Engine(corpus, chain.message_key()).decrypt_text(yesterday)
except VerificationError:
    print(f"  The device was SEIZED today (chain step {chain.step}), and yesterday's report")
    print("  still could not be opened ok. Yesterday's key exists nowhere: forward secrecy.")


title("10. The X25519 handshake, backward secrecy (ADR-017)")

sa, sb = device_key(master, "uav-01"), device_key(master, "uav-02")
ka, kb = Identity.from_key(sa), Identity.from_key(sb)
preshared = epoch_key(master, 202608)          # loaded onto both ends at provisioning
ma, mb = Engine(corpus, preshared), Engine(corpus, preshared)

hs_a = Handshake(ka, kb.public, initiator=True)
hs_b = Handshake(kb, ka.public, initiator=False)

p1, p2 = handshake_pack(ma, hs_a), handshake_pack(mb, hs_b)
print(f"  The handshake packet is {len(p1)} bytes and cannot be told apart from an")
print(f"  ordinary ciphertext. An eavesdropper cannot even see a session being set up:")
print(f"     {p1[:32].hex()}...")

role_a, ef_a, trace_a = handshake_unpack(mb, p1)
role_b, ef_b, trace_b = handshake_unpack(ma, p2)
print(f"\n  {role_a:11s} {trace_a.hex().upper()}   ->  efemer {ef_a[:8].hex()}...")
print(f"  {role_b:11s} {trace_b.hex().upper()}   ->  efemer {ef_b[:8].hex()}...")

key_a, key_b = hs_a.complete(ef_b), hs_b.complete(ef_a)
print(f"\n  Four DHs combined. Confirmation code: {key_a.confirmation_code} = {key_b.confirmation_code}")
print(f"  Direction separation: what A sent = what B received  ->  "
      f"{key_a.sending == key_b.receiving}")

channel_a, channel_b = SecureChannel(corpus, key_a), SecureChannel(corpus, key_b)
message = "COORDINATES 41.0082 28.9784"
print(f"\n  Kanal: {channel_b.decrypt_text(channel_a.encrypt_text(message))!r}")

# Backward secrecy, even if the static keys leak
history = channel_a.encrypt_text("yesterday's position report")
channel_b.decrypt_text(history)
try:
    SecureChannel(corpus, Handshake(kb, ka.public, initiator=False).complete(
        public_key(private_key()))).decrypt_text(history)
except VerificationError:
    print("\n  Even with BOTH static keys compromised, the attacker cannot open")
    print("  this message ok. The ephemeral private keys were wiped, so ee is gone.")
print("  The backward secrecy gap left open in ADR-015 is closed.")

print()
