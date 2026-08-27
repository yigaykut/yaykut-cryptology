# Contributing

This is a learning and research project. Contributions are welcome, but the
project has a few working rules that were chosen deliberately. They are the
first thing looked at in review.

## Setup

```bash
pip install -r requirements.txt
python ccore/build.py            # C core, optional
python -m pytest tests/ -q
```

Without the C core everything still runs in pure Python and the related
tests are skipped.

Covert network tests need a password (ADR-029):

```bash
CRYPTO_NETWORK_PASSWORD=...  python -m pytest tests/ -q
```

The password is **not stored in the repo in the clear**, only its salted
hash. If the variable is unset those tests are skipped and pytest counts
them separately.

---

## Five rules

### 1. Measure, do not claim

"This does not leak" is not accepted on its own. If you add a security
claim, add the **tool that measures it**. That is why every measurement
tool in the repo exists.

### 2. Every measurement needs a positive control

If a tool cannot catch a deliberately broken input, a clean result from
that tool means nothing. A blind distinguisher also scores 50%.

This is not decoration. Positive controls found **five real bugs** in this
project. One was in a gate of the exam itself, one was a control arm the
compiler had turned into constant time code, and one was a measurement
whose own premise was wrong.

### 3. Write down what is not verified

[`docs/audit.md`](docs/audit.md) §5 is the list of unverified claims and it
matters **more than §4**. If you cannot close a gap, do not pretend you
did. Put it there.

The same holds for docs. When a claim changes, the old one is **not
deleted**, it gets a dated amendment.

### 4. Architectural boundary: machine learning stays out of the cipher path

`crypto/` never imports `layer2/`. Layer 2 is an **attacker**, not a
component. If a neural network can learn to decrypt, the cipher is already
broken (ADR-001).

### 5. Decisions get recorded

Any change to the schema, the wire format or a security property needs a
decision record in [`docs/decisions.md`](docs/decisions.md): **context, the
decision, what it buys, what it does not buy, what is out of scope.** The
"what it does not buy" section is mandatory.

---

## Before you send a change

```bash
python corpus/validate.py           # corpus schema
python -m pytest tests/ -q          # tests
python fuzz.py                      # malformed input sweep
python demo.py                      # end to end walkthrough
```

If you touched the cipher path or the network layer, also run:

```bash
python sidechannel.py                  # timing leaks
python -m layer2.selector_attack
python -m layer2.network_attack        # needs CRYPTO_NETWORK_PASSWORD
```

> **Anything claiming indistinguishability has to go through the side
> channel sweep too.** This one was learned the hard way. A covert
> network's sub network was indistinguishable in the bytes but perfectly
> distinguishable on the clock, at |t| = 121.5. Indistinguishable bytes do
> not mean indistinguishable timing (ADR-028 §7).

---

## Style

- Code and docs are in **English**. Variable names, error messages,
  comments.
- Comments explain **why**, not **what**. The code already says what it
  does.
- If there is a limit or a known flaw, say so in the comment. This repo
  uses `HONEST LIMIT` and `WHAT THIS DOES NOT GIVE` headings on purpose.
- Do not introduce new cryptographic primitives. The current set is HKDF,
  HMAC-SHA256 and X25519. Adding one needs its own decision record.

## Found a vulnerability

Do not open an issue. Follow the process in [`SECURITY.md`](SECURITY.md).
