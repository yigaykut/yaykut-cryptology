# Security argument

**This is not a security proof.** It is a hand written reduction argument with
no machine checking. Its purpose is to make plain which assumptions the scheme
rests on and where each limit comes from, so an auditor can answer the question
"where do I push back".

`docs/audit.md` §5 carried the line "the AEAD security of the symmetric
construction is unproven". This document closes that line **partly**. The
argument is written, the assumptions are named, the bounds are counted. There
is still no formal proof.

Last updated 2026-08-20

---

## 1. The scheme, in full

Notation: `K` is the master key (256 bits), `P` the plaintext payload (fixed at
1289 bytes), `id` the formula identity (16 bits), `‖` concatenation, `⊕` XOR.

```
N   <-$ {0,1}^128                         fresh random nonce
PRK  = HMAC-SHA256(key = N, message = K)           HKDF-Extract
M    = HKDF-Expand(PRK, "kripto/v1/selector", 2)
KS   = HKDF-Expand(PRK, "kripto/v1/payload", 1289)
Km   = HKDF-Expand(PRK, "kripto/v1/mac", 32)

Cs   = id ⊕ M
Cp   = P  ⊕ KS
H    = N ‖ Cs ‖ Cp                        MAC coverage
T    = HMAC-SHA256(Km, H)

ciphertext = H ‖ T                        16 + 2 + 1289 + 32 = 1339 bytes
```

Decryption verifies `T` with a constant time comparison. **Not one byte is
interpreted before that check passes.**

### 1.1 The prekey variant (ADR-026)

If an optional, **independent** secret `P₀` (the prekey) is supplied, the
selector mask derives from `P₀` instead of `K`. Nothing else changes:

```
M   = HKDF-Expand(HKDF-Extract(N, P₀), "kripto/v3/onanahtar/selector", 2)
```

Without it, `M` derives from `K` as above and the output is **byte for byte**
identical to before (`test_without_a_prekey_output_byte_byte_same`).

**What changes:** an attacker who has `K` but not `P₀` reads the plaintext, but
**cannot read `id`** out of the selector.

**What does not change:** every confidentiality and integrity argument here.
`Cp` is still masked with `KS` derived from `K`, `T` is still taken with `Km`
derived from `K`, and MAC coverage is still `H = N ‖ Cs ‖ Cp`. `P₀` produces
only `M`.

**The limit was measured, not assumed.** With the corpus public, an attacker
holding `K` can decrypt `Cp` and try each formula's parameter layout. The
uncertainty in `id` goes from 0 bits up to **4.62 bits** (blind guessing is
5.73 bits, the attack strips 1.10). The architectural ceiling is still 16 bits,
because the selector is 2 bytes. Measured by `layer2/selector_attack.py`.

`P₀` **must not derive from `K`**. If it did, anyone who knows `K` could
compute `P₀` and the gain would be zero.

### 1.2 Network derivation and the escrow exception (ADR-027)

`crypto/network.py` **does not change the scheme**. It only says where `K` and
`P₀` come from. A network is nothing but one root secret `S`:

```
P₀        = HKDF(S, "kripto/v4/ag/onanahtar")
K_member(u) = HKDF(S, "kripto/v4/ag/uye" ‖ u)
```

This does **not** break §1.1's rule that `P₀` must not derive from `K`. The
rule was about someone with `K` being able to compute `P₀`. Here the two are
sibling branches off `S`, and since HKDF is one way there is no path from
`K_member` back to `S` and on to `P₀`. The structure is the same one `subkeys`
uses to produce three independent subkeys from a single PRK.

**The one real change to the argument's scope is an EXCEPTION.** Everywhere
else this document says "without the key you cannot read". In COVERT mode a
sub network's root secret derives as `S_c = HKDF(S_parent, "cocuk" ‖ label)`,
which means the **parent can regenerate the sub network's `K` and `P₀` and read
its traffic**. That is key escrow.

The escrow **adds no field to the message**. Ciphertext format, length and MAC
coverage are all identical, so none of the confidentiality, integrity or length
arguments in §3 to §6 change. The only thing that changes is who can compute
the KEY. The argument still says "without the key you cannot read"; ADR-027
adds "the network owner can compute the key one level down" alongside it.

`S` is therefore a **single point of failure**. If it is compromised, that
network's `P₀`, all its member keys, and in covert mode every first degree sub
network go with it.

Epoch rotation bounds that single point of failure without removing it:

```
S_d = HKDF(S, "kripto/v4/ag/donem" ‖ d)
```

Only `S_d` is loaded onto a device, `S` stays in the safe. If the device is
taken, the attacker reads only epoch `d`'s traffic, since there is no way back
from `S_d` to `S`. **But if `S` itself is compromised every epoch falls.** This
argument claims **no** forward secrecy against root compromise. The only thing
protecting the root is never putting it on a device, and that is an operational
decision, not a mechanism.

Whether a sub network's root secret was random or derived cannot be told apart
without `S_parent`, because HMAC is a PRF. That claim was measured too, in
`layer2/network_attack.py`: the real arm scored 47% [0.402 - 0.539], the
sabotage control 99%, the positive control 100%.

---

## 2. Assumptions, one of which deserves attention

**A1: HMAC-SHA256 is a PRF.** The standard assumption (Bellare 2006, given the
compression function is a PRF). `HKDF-Expand`, `Km` and the tag all rest on it.

**A2: HMAC-SHA256 is a DUAL PRF.** This assumption surfaced while writing the
argument and it is **worth stating**.

Look at `PRK = HMAC(key = N, message = K)`. HMAC's **key is the nonce**, a
public value, and its **message is the secret key**. HMAC is not being used in
the usual direction, as a PRF keyed by a secret. For `PRK` to be pseudorandom,
HMAC also has to be a PRF when keyed through its *second* argument.

This is by design in HKDF-Extract, and RFC 5869 says explicitly that the salt
may be public. Krawczyk's HKDF analysis (2010) treats it as a computational
extractor; Bellare and Lysyanskaya (2015) name the dual PRF assumption.
**TLS 1.3 rests on the same assumption**, so it is a respectable one, but it is
stronger than A1 and the scheme's security depends on it. It should be the
first thing an auditor knows.

**A3: `K` is 256 uniformly distributed bits.** `master_key()` takes it from the
operating system CSPRNG. On embedded targets this assumption **breaks easily**,
since many microcontrollers start with weak entropy at boot. The code carries
that warning in its docs.

**A4: A nonce is never repeated.** Examined numerically in §4.

---

## 3. Confidentiality (IND-CPA)

Under A1 and A2, `PRK` is pseudorandom, and under A1 so is
`KS = HKDF-Expand(PRK, …)`. So `Cp = P ⊕ KS` is indistinguishable from a
uniform string to the attacker. The same holds for `Cs = id ⊕ M`, so the
formula identity is secret too (ADR-005: security comes from the key, not from
keeping the corpus secret).

**Domain separation.** `M`, `KS` and `Km` derive from the same `PRK` under
different `info` labels. Under A1 those three outputs are independent
pseudorandom strings and none can substitute for another. The labels are
versioned with `v1`, and the hierarchy in `keys.py` uses `v2`, so cross level
mixing is closed off as well.

**Why this is not a standard AEAD.** The construction is a correctly assembled
stream cipher plus MAC, but it has **nowhere near the scrutiny** of
ChaCha20-Poly1305 or AES-GCM. The difference is not in the security level, it
is in exposure. Thousands of people have tried to break a real AEAD. For
production the recommended path is to swap the primitive; the envelope layer
stays exactly as it is.

---

## 4. Nonce collision, the numeric bound

The nonce is **random, not a counter**. That was deliberate: `encode` is
stateless, a counter needs state, and state synchronisation brings its own
class of failures.

The price is the birthday bound. After `q` messages the probability of at least
one collision is:

```
Pr[collision] <= q² / 2^129
```

| Messages q | Collision probability |
|---|---|
| 2^20 (about 1 million) | 2^-89 |
| 2^32 (about 4 billion) | 2^-65 |
| 2^48 | 2^-33 |
| 2^56 | 2^-17 |

**Why a collision is catastrophic.** If the same `N` is used for two messages
then `KS` is the same too, and `Cp₁ ⊕ Cp₂ = P₁ ⊕ P₂`. The key cancels out.
Corpus entry `0x0505` (VENONA) is exactly the historical case.

**Practical reading:** the bound is comfortable up to 2^48 messages. A device
sending 1000 messages a second would need about 9000 years to reach 2^48. Note
that this counts **per key**, so a single key across a fleet accumulates the
whole total. That is one of the reasons for the key hierarchy (ADR-015).

---

## 5. Integrity (INT-CTXT) and authenticated encryption

The Bellare and Namprempre (2000) composition theorem: **an IND-CPA secure
cipher plus a SUF-CMA secure MAC, composed encrypt-then-MAC, gives an IND-CCA
and AE secure scheme.**

- The cipher part is IND-CPA by §3.
- HMAC-SHA256 is SUF-CMA under A1.
- The order is **encrypt-then-MAC** and the tag is taken over `H = N ‖ Cs ‖ Cp`.

**Complete MAC coverage is critical.** The nonce is under the tag. If it were
not, an attacker could change `N` and force the receiver to derive a different
keystream. The selector is covered too; otherwise the formula identity could be
altered. In the code the coverage is a single line
(`head = nonce + selector + payload_ct`) and it is one of the most critical
lines in the scheme.

**Forgery probability:** the tag is 256 bits, so `2^-256` per attempt.

**No padding oracle.** If verification fails, no parsing happens at all, so
Vaudenay and Lucky13 style attacks do not apply. The comparison uses
`hmac.compare_digest` and is constant time (measured at |t| around 1.3 to 2.7,
threshold 4.5).

---

## 6. Length hiding, a property standard AE does NOT give

Standard AE definitions accept that length leaks; the ciphertext length depends
on the plaintext length. The fixed envelope buys a stronger property here:

> For **every** plaintext within capacity, the ciphertext distribution is the
> same.

So even when `|P₁| ≠ |P₂|` the ciphertexts are indistinguishable. This is the
project's real contribution and it was measured empirically: a classifier
looking at length dropped from 82.6% to 1.3%, against 1.9% chance.

**The limit is just as clear.** The property holds at the level of a **single
message**. The NUMBER of messages, the TIME they are sent and the INTERVALS
between packets all still leak. A fixed size envelope closes the size channel,
not the time channel (ADR-018).

---

## 7. Plaintext is not protected in memory, the exact list

ADR-021 said "plaintext is not protected". This is what that sentence means
concretely. During one `encrypt_text` call, these Python objects hold secret
material and **cannot be wiped**:

| Object | Contents | Why it cannot be wiped |
|---|---|---|
| `text` | plaintext | `str` is immutable |
| `raw = text.encode()` | plaintext | `bytes` is immutable |
| `payload_pt` | plaintext plus padding | `bytes` is immutable |
| `prk` | derived from the master key | `hashlib` returns `bytes` |
| `payload_ks` | keystream, **equivalent to the plaintext** | same |
| `mac_key` | tag key | same |

Decryption has the mirror image: `payload_pt`, `values["metin"]` and the
returned `str`.

**Why this was not closed.** The only way to close it was to move the HKDF
stream and the XOR into C, which means reimplementing SHA-256. That was
rejected (ADR-021). The project's rule is "never reimplement a primitive",
`hashlib` is already OpenSSL underneath, and the gain would be partial anyway,
because plaintext enters through the API boundary as a `str`.

**The half measure was deliberately avoided.** Putting the keystream in secure
memory while leaving the plaintext in `bytes` is *changing the lock on the door
while the window stays open*, and it looks safer than it is. That appearance is
more dangerous than an open gap.

**What is protected** (ADR-020, ADR-021): the master key, device and epoch
keys, the identity key, the ephemeral handshake key, the key chain, the shared
secret. In other words all the long lived secrets. The unprotected ones live
for a single message.

---

## 8. What the argument does not cover

| What | Status |
|---|---|
| Machine checked proof | **None.** No EasyCrypt or ProVerif model was written. |
| Formal analysis of the handshake | **None.** The Noise KK pattern is analysed in the literature, this variant is not. |
| Analysis of chain and decoy modes | **None.** The decoy chain (ADR-012) is an obfuscation layer and carries no security claim. |
| Multi user bounds | **None.** Bounds are given for a single key; for a fleet see the key hierarchy. |
| Side channel model | Out of scope, handled separately in ADR-018, 019 and 020. |
| Post quantum security | **None.** X25519 falls to Shor. The symmetric side keeps 128 bit security against Grover. |

---

## 9. Summary, one paragraph for an auditor

The scheme derives three subkeys from a fresh random nonce via HKDF, XORs the
plaintext with a keystream, and tags everything including the nonce with
HMAC-SHA256 in encrypt-then-MAC order. Confidentiality and integrity follow
from standard reductions (Bellare and Namprempre) under the assumption that
HMAC is a PRF **and a dual PRF**. Because the nonce is random the birthday
bound applies: up to 2^48 messages the collision probability is 2^-33. The
fixed envelope adds length hiding, which standard AE does not give. **There is
no formal proof, plaintext is not protected in memory, and this is not an
approved AEAD.**
