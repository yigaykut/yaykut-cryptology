# The Mathematics of the System

This document explains the mathematical method behind the cipher engine. High
school algebra is enough. Every number here comes from code that
`python -m pytest tests/` verifies.

The 34 formulas in the corpus (elliptic curves, RSA, LWE and so on) are the
system's **content**, not its method. They live in the CORPUS panel of
`python app.py`.

---

## 1. One trick: XOR

The whole system rests on a single operation, **XOR**, written `⊕`.

At bit level: 1 if the two bits **differ**, 0 if they are the same.

| a | b | a ⊕ b |
|---|---|-------|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

Put another way, it is **addition modulo 2**. `1 ⊕ 1 = 0` because 1+1 = 2 ≡ 0
(mod 2).

### Three properties

1. `a ⊕ 0 = a`, XOR with zero changes nothing
2. `a ⊕ a = 0`, XOR with itself cancels
3. Order does not matter: `a ⊕ b = b ⊕ a`, `(a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)`

### The key consequence

Something powerful falls out of those three:

```
(m ⊕ k) ⊕ k = m ⊕ (k ⊕ k)     [property 3, regroup]
             = m ⊕ 0            [property 2, k ⊕ k = 0]
             = m                 [property 1]
```

**The same operation both encrypts and decrypts.** There is no separate
decryption algorithm.

### With numbers

Let `m` be the letter 'A' = 65, and `k` = 92:

```
m = 65 = 01000001
k = 92 = 01011100
        ---------  XOR
c = 29 = 00011101      <- ciphertext

c = 29 = 00011101
k = 92 = 01011100
        ---------  XOR
    65 = 01000001      <- 'A' is back
```

You can check every column by hand: 1 if they differ, 0 if they match.

---

## 2. The cipher is nothing more than this

What the engine does:

```
ciphertext = (data) ⊕ (keystream)
```

The `keystream` is a byte sequence as long as the data, derived from the key
`κ` and the nonce `ν`, and indistinguishable from random. It comes from
HMAC-SHA256 run in counter mode.

The critical point: **if the stream really looks random, the output looks
random too.** Whatever the plaintext is.

The intuition: `m` is unknown, `k` is uniformly random. For `c = m ⊕ k` every
possible value of `c` is equally likely, so someone looking at `c` learns
nothing about `m`.

This is Shannon's 1949 **one time pad** result. The one difference here is that
the stream comes from a key rather than from real randomness.

---

## 3. Why the nonce is vital

Now the most dangerous mistake in this system, and it can be **proved in two
lines**.

Suppose two messages are encrypted with the same stream `k`:

```
c₁ = m₁ ⊕ k
c₂ = m₂ ⊕ k
```

XOR the two ciphertexts:

```
c₁ ⊕ c₂ = (m₁ ⊕ k) ⊕ (m₂ ⊕ k)
        = m₁ ⊕ m₂ ⊕ k ⊕ k        [reorder]
        = m₁ ⊕ m₂ ⊕ 0
        = m₁ ⊕ m₂
```

**The key drops out of the equation entirely.** The attacker now has the XOR of
two plaintexts without ever knowing the key. If they can guess one message,
they read the other directly.

### With numbers

`m₁` = "SALDIRI", `m₂` = "GERICEK", same stream:

```
c₁      = c97232458d0f62
c₂      = dd762c48871860
c₁ ⊕ c₂ = 14041e0d0a1702
m₁ ⊕ m₂ = 14041e0d0a1702   <- exactly the same
```

That is why a fresh `ν` is generated on every encryption and the stream derives
from it. Encrypt the same message with the same key a hundred times and you get
a hundred different outputs.

This mistake was really made in history. Repeated pads in Soviet traffic were
what the VENONA project rested on.

---

## 4. Selector masking

The identity `ι` that says which formula was used would be visible to everyone
if written in the clear. It is masked instead:

```
σ = ι ⊕ Ψκ(ν)
```

For the raw text entry `ι` = 0x0701. Suppose the mask `Ψκ(ν)` comes out as
0x13C3:

```
ι    = 0x0701 = 0000011100000001
mask = 0x13C3 = 0001001111000011
                ----------------  XOR
σ    = 0x14C2 = 0001010011000010
```

Decryption XORs with the same mask again:

```
σ ⊕ mask = 0x14C2 ⊕ 0x13C3 = 0x0701 = ι   ✓
```

The mask changes with every message, so `σ` does too. That is why the corpus
identities being numbered 1, 2, 3 leaks nothing.

---

## 5. Bit packing

Parameters are written as fixed width binary numbers. An `n` bit field holds
values from `0` to `2ⁿ − 1`:

| bits | range | why |
|---|---|---|
| 5 | 0 to 31 | 2⁵ = 32 |
| 8 | 0 to 255 | 2⁸ = 256 |
| 16 | 0 to 65535 | 2¹⁶ = 65536 |

Five bits are enough for a letter of the alphabet, since 26 ≤ 31.

### The raw text entry's arithmetic

```
length  :    16 bits
text    :  8192 bits   (1024 bytes × 8)
          ----------
total   :  8208 bits = 1026 bytes
padding :  2032 bits
          ----------
fixed   : 10240 bits = 1280 bytes
```

`8208 + 2032 = 10240` ✓

### Why fixed width

Variable length leaks the **magnitude** of a number. If `a = 3` were written in
two bits and `a = 1000000` in twenty, anyone looking at the length would know
roughly how big `a` is. At fixed width, 3 and 1000000 occupy the same space.

---

## 6. Padding and the length leak

This is the nicest piece of arithmetic in the project. Before padding was
added, each formula's payload was a different size and the ciphertext length
gave away which formula it was.

### How to compute the size of the leak

There are `N` formulas. Group them by length. The `k` formulas sharing a length
are **indistinguishable**, so the best an attacker can do is guess, and they
are right with probability `1/k`.

A group's total contribution:

```
k formulas × (1/k probability) = 1
```

Whatever the group size, the contribution is **1**. So:

```
best accuracy = (number of groups) / (number of formulas)
```

### On the current corpus

34 active entries, **29** distinct lengths. The colliding groups:

| payload | formulas |
|---|---|
| 96 bytes | 4 |
| 256 bytes | 2 |
| 4 bytes | 2 |

Check: 3 of the 29 groups are multi member (4+2+2 = 8 formulas), the other 26
are singletons. 26 + 8 = 34 ✓

```
ceiling = 29 / 34 = 85.3%
```

### After padding

Every payload is padded to 1280 bytes, so there is now **one single group**:

```
ceiling = 1 / 34 = 2.9%
```

That is chance level, the same as picking one of 34 at random.

> Historical note: the measurement in `docs/findings.md` gives an 82.4%
> ceiling. That run happened before the Caesar entry was retired and before the
> raw text entry was added. Same method, different corpus.

The distinguisher measured 82.6% before padding and **2.1%** after. So the leak
was real, and it is closed.

---

## 7. The tag: integrity

```
τ = HMAC(key, ν ‖ σ ‖ π)
```

The tag is a fingerprint over the whole ciphertext. On decryption it is
verified **first**, and only then is the data interpreted.

The order matters. Parsing unverified data opens a door for the attacker. Flip
one bit and the tag does not match, so nothing gets parsed.

The comparison is **constant time**. An ordinary byte by byte comparison stops
at the first difference, which would let an attacker guess the correct tag one
byte at a time by measuring how long it takes.

---

## 8. Entropy: why 128 bits is enough

The nonce is 16 bytes, 128 bits. Each bit is independent and equally likely, so:

```
possible nonces = 2¹²⁸ ≈ 3.4 × 10³⁸
```

The key is 32 bytes, 256 bits:

```
2²⁵⁶ ≈ 1.2 × 10⁷⁷
```

For comparison, the number of atoms in the observable universe is around 10⁸⁰.
Trying every key is physically impossible.

---

## 9. The statistics of Experiment 2

In layer 2 the model tried to tell ciphertext from random and scored **49.70%**
accuracy. Why does that mean "it could not tell them apart"?

The model saw 2000 test samples. If it were really guessing, it has a 50% shot
on each one. The standard error of a rate measured that way:

```
SE = √(p(1−p)/n) = √(0.25/2000) = 0.01118 = 1.118%
```

A 95% confidence interval is roughly ±1.96 standard errors:

```
1.96 × 1.118% = 2.19%

interval: 49.70% ± 2.19%  ->  [47.51% , 51.89%]
```

**50% is inside that interval.** The deviation observed is the size you would
expect from chance alone. There is no evidence of a leak.

Note the wording: this does not say "there is no leak", it says **"no leak was
found at this scale"**. Absence of evidence is not proof.

### Why the positive control is required

A result of 50% proves nothing on its own, because a broken model would also
give 50%. So a third experiment ran on deliberately corrupted data and the
model caught it at 100%. Only **after** the rig has proven it can see a signal
does 49.70% mean anything.

---

## 10. Bonus: the birthday bound

This is the most counterintuitive formula in the corpus, and high school
probability is enough to understand it.

How many people have to be in a room before two share a birthday, at 50%
probability? Intuition says about half of 365, so 180. The right answer is
**23**.

The formula:

```
n ≈ 1.177 √N
```

For 365 days: `1.177 × √365 = 1.177 × 19.1 = 22.5` ≈ 23 people ✓

Why the square root? Because what matters is not the number of people but the
number of **pairs**. With `n` people there are `n(n−1)/2` pairs, so the pair
count grows like `n²`. A collision is expected when `n² ≈ N`, that is
`n ≈ √N`.

### What this means in cryptography

Finding a collision in a 256 bit hash takes `2¹²⁸` operations, not `2²⁵⁶`. So
**collision resistance is half the digest length.**

| digest | collision cost |
|---|---|
| MD5 (128 bit) | 2⁶⁴ |
| SHA-1 (160 bit) | 2⁸⁰ |
| SHA-256 (256 bit) | 2¹²⁸ |

If you want 128 bit security you need a 256 bit digest. MD5 and SHA-1 were
abandoned precisely because that bound became reachable in practice.

---

## Summary

| Piece | Mathematics |
|---|---|
| Encryption | `data ⊕ stream`, XOR being its own inverse |
| Nonce | Changes the stream every message; a repeat is fatal via `c₁⊕c₂ = m₁⊕m₂` |
| Selector | `σ = ι ⊕ mask`, hides the identity |
| Packing | Fixed `n` bits gives `[0, 2ⁿ−1]` |
| Padding | Groups go from 29 to 1, ceiling from 85.3% to 2.9% |
| Tag | HMAC, verify before parse |
| Entropy | 2¹²⁸ nonces, 2²⁵⁶ keys |
| Measurement | Confidence interval 49.70% ± 2.19%, which contains 50% |

The whole system is built on one middle school operation. The security comes
not from the complexity of that operation but from the **unpredictability of
the keystream** and from never repeating a nonce.
