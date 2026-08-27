# How to Add a Formula to the Corpus

## 1. The mental picture first

This is the part that matters. Everything else is easy once it lands:

> **A corpus entry is a BLANK FORM DESIGN. It holds no real numbers.**

Think of a passport application form at a government office. The form itself
does not contain your details. It contains:

- A title: "Passport Application Form"
- Boxes: `Name [up to 30 letters]`, `Year of birth [4 digits]`
- Rules: "Year of birth must be after 1900"

The piece of paper that comes out when you fill it in is a different thing
entirely.

| | |
|---|---|
| **Corpus entry (the YAML file)** | The blank form design |
| **Values supplied at encryption time** | The filled in form |

So you do not write `a = 17` in the YAML. You write:

> "There will be a 256 bit number here, called `a`, reduced modulo `p`."

The actual value 17 appears months later when somebody encrypts something.
Right now you are only describing the **shape of the box**.

Once that picture is in place, all four blocks of the file make sense:

```
doc:          the form's title and description   (humans and the RAG read it)
params:       the boxes, and their sizes         (the engine reads it)  <- THE REAL WORK
constraints:  the rules for filling it in        (the engine reads it)
sampler:      how to fill it in at random        (the distinguisher reads it)
```

---

## 2. Step by step

```
1. Pick an id for your formula   (from the block table below)
2. Copy the template             _TEMPLATE.yaml.example
3. Rename it                     0501-my-formula.yaml
4. Fill in the doc block         free text, relax
5. Fill in the params block      <- the real work is here
6. Write the constraints         validity rules
7. Check it                      python corpus/validate.py
```

If step 7 gives an error, do not panic. The validator says which line is wrong
and why. Section 6 explains what the common messages mean.

### Id blocks

Ids are written in hex because it makes the block grouping easy to read.
`0x0101` is just `257`, but written this way you can see "block 01, entry 01".

| Block | Domain | Currently used |
|---|---|---|
| `0x0100`-`0x01FF` | Elliptic curves | `0x0101`-`0x0109` |
| `0x0200`-`0x02FF` | Modular arithmetic and RSA | `0x0201`-`0x020B` |
| `0x0300`-`0x03FF` | Hashes and MACs | `0x0301`-`0x0308` |
| `0x0400`-`0x04FF` | Lattices and post quantum | `0x0401`-`0x0406` |
| `0x0500`-`0x05FF` | Classical ciphers | `0x0502`-`0x0507` (`0x0501` retired) |
| `0x0600`-`0x06FF` | Symmetric and stream ciphers | `0x0601`-`0x0608` |
| `0x0700`-`0x07FF` | Transport (raw data, not a formula) | `0x0701` |
| `0x0800`-`0x08FF` | Protocols and proofs | `0x0801`-`0x0805` |

`0xFFFF` is **reserved**. The wire format's chain mode uses it, so no corpus
entry may take that id.

An id marked `retired` is still **taken**, and it is never reused (ADR-003).

Take the next free number in the block. **Never reuse an id that was used
once**, even if you delete the formula. The reason is in ADR-003.

---

## 3. The params block, where the real work is

For each parameter you answer three questions:

1. **What is it called?** `name` (use the symbol from the formula: `a`, `b`, `p`)
2. **What kind of thing is it?** `type`
3. **How many bits does it take?** `bits`

### Types

| type | what it is | example | required fields |
|---|---|---|---|
| `uint` | a plain integer | `42` | `bits` |
| `prime` | a prime, used as a modulus | `23` | `bits` |
| `field_element` | a number that lives in a mod p world | `17` mod 23 | `bits`, `mod` |
| `scalar` | a number modulo the group order | | `bits`, `mod` |
| `point` | a point (x, y) on a curve | | `bits`, `curve` |
| `enum` | a choice from a fixed list | `"oaep-sha256"` | `values` |
| `bytes` | a raw byte string | | `bits` |

**What is the difference between `uint` and `field_element`?** A `uint` is just
a number. A `field_element` is a number that knows which modulus it belongs to,
which is why you have to say `mod: p`. If you are not sure, pick `uint`.

### What `bits` means

How much space the number takes, which sets the largest value it can hold:

| `bits` | range | used for |
|---|---|---|
| `5` | 0 to 31 | a letter of the alphabet (A=0 ... Z=25) |
| `8` | 0 to 255 | a single byte |
| `32` | 0 to about 4 billion | the RSA public exponent `e` |
| `256` | 0 to about 10⁷⁷ | elliptic curve parameters |
| `2048` | astronomical | the RSA modulus `n` |

Pick the **smallest width that is enough**. A 26 letter alphabet needs
`bits: 5`; writing `bits: 256` wastes 251 bits.

The width is **fixed**, so small values take the same space. That is
deliberate: variable length would leak the magnitude of the number (ADR-004).

### `role`, does this value go into the ciphertext?

| `role` | meaning |
|---|---|
| `public` | Written into the ciphertext. **The default.** Most parameters are this. |
| `secret` | Not written; it is part of the key. The other side already knows it. |
| `derived` | Not written; it can be computed from the other parameters. |

The multiplier and shift in an affine cipher (`a`, `b`) are the typical case.
They are the key itself, so writing them into the ciphertext would hand the
cipher to everyone. Hence `role: secret`.

Only `public` parameters count toward the payload size.

### The ordering rule

**List order is ciphertext order.** And if one parameter refers to another
through `mod:`, the target has to come **before** it:

```yaml
# CORRECT
params:
  - name: p
    type: prime
    bits: 256
  - name: a
    type: field_element
    mod: p            # p is defined above
    bits: 256

# WRONG
params:
  - name: a
    type: field_element
    mod: p            # p comes later, the validator rejects this
    bits: 256
  - name: p
    type: prime
    bits: 256
```

---

## 4. constraints, the validity rules

The mathematical conditions the parameters have to satisfy. They are checked
before encryption and after decoding.

```yaml
constraints:
  - expr: "k < 26"
    reason: "The shift cannot exceed the alphabet size."
    severity: error       # error rejects, warning warns and continues
```

Inside `expr` you can use:

- The names you defined in `params` (`a`, `b`, `p`, `k` and so on)
- Arithmetic: `+  -  *  /  //  %  **`
- Comparison: `<  <=  >  >=  ==  !=`
- Logic: `and  or  not`
- These functions: `abs`, `min`, `max`, `pow`, `gcd`, `len`

**Nothing else** works. Calling other functions, importing, reading files, all
of it is rejected by the validator. That is deliberate: corpus files might one
day come from outside, and a constraint expression must never be able to run
arbitrary code.

Write a good `reason`. It is the message the user sees when the rule is broken.

---

## 5. sampler, generating random test data

So the layer 2 distinguisher can build training data, you say how to generate
valid parameters for this formula at random.

| `strategy` | what it does |
|---|---|
| `uniform_valid` | Generate at random, discard if the constraints fail, retry |
| `from_catalog` | Use only the known values listed under `catalog` |
| `mixed` | A combination of the two |

If in doubt write `uniform_valid` and move on. For most formulas that is the
right answer.

```yaml
sampler:
  strategy: uniform_valid
  max_rejections: 1000
```

> **Do not type large constants by hand.** Do not write the 256 bit constants
> of a standard curve like secp256k1 here from memory or by copy and paste.
> Give only its **name** under `catalog`; the values are resolved from a
> standard library and checked against known test vectors. Hand typed large
> constants are silently wrong and go unnoticed for weeks.

---

## 6. Common errors and what they mean

---

**`'mod: p' is not defined before this point; order is significant`**

You put `p` after `a`. Move the `p` block up.

---

**`type 'prime' requires a 'bits' field`**

You forgot the `bits:` line on that parameter. Say how many bits it takes.

---

**`id 0x0101 is already used by 0101-ec-weierstrass-short.yaml`**

Two files carry the same id. Take a free number from the block table.

---

**`constraint refers to unknown names: ['zzz']`**

A name in `expr` is not in the `params` block. Probably a typo (`pp` instead of
`p`), or you forgot to define that parameter.

---

**`function not allowed: 'foo'`**

You used something that is not on the list in section 4. Stick to the list.

---

**`payload size could not be computed, 'bits' is missing or invalid`**

A side effect of the `bits` error above. Fix `bits` and this goes away too.

---

**`filename does not match, expected: 0502-afin-sifre.yaml`**

Only a warning, nothing stops working. The convention is
`<id-hex>-<slug>.yaml`, so that scanning the file list tells you where each id
lives.

---

## 7. Check

```
python corpus/validate.py
```

The output also shows the payload size of each entry. Sizes differing wildly
from one another is a known gap, written up in ADR-002, and it is the
distinguisher's first target. Do not worry about it, it is intentional.
