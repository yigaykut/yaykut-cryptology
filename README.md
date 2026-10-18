# Formula Codebook Cipher

Research and teaching code. It has not had a formal security audit.
Claims here are backed by measurements where possible, and
[`docs/audit.md`](docs/audit.md) keeps a separate list of the ones that
are not.

A cipher where the ciphertext carries **which formula** was used and the
parameters that formula takes. Formulas live in a corpus. Encryption hides
the formula identity with the key and writes the parameters next to it.

---

## Three layers

| Layer | Job | Role of machine learning |
|---|---|---|
| **1. Engine** | Encrypt and decrypt | None. Fully deterministic |
| **2. Auditor** | Try to break the cipher | Attacker and evaluator |
| **3. Assistant** | Search the corpus | Information retrieval |

Machine learning stays outside the cipher path. If a neural network can
learn to decrypt, the cipher is already broken, so a successful training
run is evidence of leakage rather than a feature.

---

## Quick start

```bash
pip install -r requirements.txt

python app.py              # desktop app
python demo.py                  # end to end walkthrough
python assistant.py               # search the corpus
python -m pytest tests/ -q      # 1085 tests
```

Covert network tests need a password. Without `CRYPTO_NETWORK_PASSWORD` they are
skipped rather than passed:

```bash
CRYPTO_NETWORK_PASSWORD=...  python -m pytest tests/ -q
```

---

## Wire format

```
┌──────────┬────────────┬──────────────────┬──────────┐
│  nonce   │  selector  │     payload      │   tag    │
│ 16 bytes │  2 bytes   │ 1289 bytes FIXED │ 32 bytes │
└──────────┴────────────┴──────────────────┴──────────┘
                every ciphertext: 1339 bytes

inside the payload:
┌────────┬──────────┬──────────────────────┬─────────┐
│ version│ sequence │ body                 │ padding │
│ 1 byte │ 8 bytes  │ up to 1280 bytes     │         │
└────────┴──────────┴──────────────────────┴─────────┘
```

* `selector = formula_id XOR HKDF(key, nonce)`, so the identity is hidden
* The payload is padded to a fixed size, so length leaks nothing
* Encrypt then MAC. Nothing is interpreted before the tag verifies
* Version and sequence live inside the payload, so they are encrypted and
  covered by the MAC

The only source of unpredictability is `os.urandom`. Encrypting the same
formula twice with the same key gives completely different output. Pass a
fixed nonce and the engine becomes deterministic.

The corpus is not secret. `corpus/` can be published and security comes
from the key alone.

---

## What the layers do

### Layer 1, engine

Frame format, sessions, key hierarchy, forward secrecy ratchet, chained
mode for carrying several formulas in one ciphertext, decoy chains,
network topology, canary traps, and multi block messages.

Replay protection sits in `Session` rather than `Engine`, because `Engine` is
stateless by design and hands the same plaintext back for the same
ciphertext every time.

An optional C core provides constant time X25519 and wipeable, page locked
key memory. The project runs in pure Python without it.

### Layer 2, auditor

A small neural distinguisher trained as an attacker, plus eleven
measurement tools. Every tool ships with a positive control: if the rig
cannot catch a deliberately broken input, its clean result is not
reported.

That rule earned its place. Positive controls found five real bugs during
development, including one in a test gate itself and one where the
compiler turned a deliberately data dependent control arm into constant
time code.

### Layer 3, assistant

BM25 search over the corpus with an evaluation harness. No language model
generates answers, because an unverifiable answer about cryptography is
worse than no answer.

---

## Tools

| Command | What it measures |
|---|---|
| `python corpus/validate.py` | Corpus entries against the schema |
| `python demo.py` | Encryption, tamper detection, constraints |
| `python experiments.py` | Layer 2 experiments, takes a few minutes |
| `python fuzz.py` | Decoder against malformed and hostile input |
| `python coverage_fuzz.py` | Coverage guided fuzzing via `sys.monitoring` |
| `python sidechannel.py` | Timing leaks, Welch t test |
| `python -m ccore.c_timing` | X25519 cycle counts from inside C |
| `python -m layer2.generator` | Generates new corpus-shaped entries |
| `python -m layer2.exam` | Puts generated entries through five gates |
| `python -m layer2.selector_attack` | How much the pre-key protects |
| `python -m layer2.network_attack` | Whether a covert network is detectable |
| `python -m layer2.canary_experiment` | Whether canary traps find the leaker |
| `python -m layer2.traffic` | What packet counts reveal |
| `python -m layer2.sampler_uniformity` | Whether the sampler is uniform |
| `python assistant.py "question"` | Corpus search, `--evaluate` scores it |
| `python app.py` | Desktop app |

### Desktop app

`python app.py` opens a window. No server and no browser: the Tkinter
interface calls `crypto.Motor` directly in the same process. Tkinter ships
with Python, so there is nothing extra to install.

The background is generated at runtime rather than loaded from image
files. Two help screens are built in: a symbol glossary and a corpus
browser that renders all 53 formulas as readable mathematics.

`webui.py` and `webui/` hold a local web server that does the same job in
a browser. You only need it for remote access.

---

## Networks

A network is a single root secret. Everything else derives from it.

```
S  (32 bytes)
├─ P            pre-key, hides the selector
├─ K_member(id) per member key
├─ T            seed for the network's own derived corpus
├─ S_child(tag) sub network root
└─ S_epoch(n)   epoch network, itself a full network
```

Three modes:

| Mode | Sub networks | Child root secret | Owner can read children |
|---|---|---|---|
| Open | allowed | `os.urandom` | no |
| Restricted | blocked | | |
| Covert | allowed | derived from parent | yes, first degree only |

Covert mode is **key escrow**, and the code says so. A child cannot tell
whether its root was random or derived, because HKDF output is
pseudorandom. That claim was measured at 47 percent accuracy against a
distinguisher whose sabotage control arm scored AUC 1.0.

Creating a covert network requires a password. That gate is policy, not
cryptography: anyone with the source can delete the check, and anyone with
their own secret can run the same derivation in their own code. What the
gate does buy is that the password is stored as a salted, iterated digest
rather than plaintext, so publishing this repository does not burn it.

---

## Corpus

53 formulas across eight blocks.

| Block | Area | Count |
|---|---|---|
| `0x01xx` | Elliptic curves | 9 |
| `0x02xx` | Modular arithmetic and RSA | 10 |
| `0x03xx` | Hashes and MACs | 8 |
| `0x04xx` | Lattices and post quantum | 6 |
| `0x05xx` | Classical ciphers | 6, one retired |
| `0x06xx` | Symmetric and stream | 8 |
| `0x07xx` | Transport, raw data | 1 |
| `0x08xx` | Protocols and proofs | 5 |

Caesar at `0x0501` was retired and its identity is permanently blocked.
Published entries never change. If a parameter schema changes, a new
identity is opened and old identities are never reused.

Adding a formula: [corpus/HOW-TO-ADD.md](corpus/HOW-TO-ADD.md)

---

## Layout

```
crypto/       Layer 1, the engine
layer2/       Layer 2, the auditor and its measurement tools
layer3/       Layer 3, corpus search
ccore/        Optional constant time C core for X25519
corpus/       Formula corpus, schema, validator
docs/         Decision records, audit pack, security argument
tests/        1085 tests
webui/        Optional web interface
app.py   Desktop app
```

---

## Documentation

* [`docs/audit.md`](docs/audit.md) is the audit pack. Section 4 lists
  what was verified and how. Section 5 lists what was not. Section 5
  matters more.
* [`docs/security-argument.md`](docs/security-argument.md) is a reduction
  argument with assumptions and numeric bounds. It is an argument, not a
  proof.
* [`docs/decisions.md`](docs/decisions.md) holds 30 decision records. Old
  decisions are never deleted. When a claim changes, a dated correction is
  added underneath it.

---

## Known gaps

* **Fixed padding costs bandwidth.** One byte of affine cipher data still
  travels as 1339 bytes. That is the price of closing the length leak.
* **Side channel coverage is partial.** `sidechannel.py` scans algorithmic
  timing and is currently clean, but cache timing and power analysis are
  out of reach from Python. Two channels were closed in C: bigint timing
  for X25519, and key wiping for ephemeral keys.
* **The symmetric path is not hardened.** `xor` is a byte loop in Python.
  Only X25519 and key memory moved to C.
* **Plaintext is not protected in memory.** Keys live in wipeable buffers,
  but the message itself enters the API as a Python `str` and cannot be
  erased.
* **Multi block messages leak length.** Splitting a long message across
  blocks reveals its size to within one block. Padding to a target block
  count closes it at the cost of bandwidth.
* **Canary traps are not collusion resistant.** Two leakers who compare
  codewords can frame an innocent member. The tooling measures and audits
  this rather than fixing it. Tardos codes would fix it.
* **Epoch rotation does not protect the root.** Compromising a device
  exposes one epoch. Compromising the root exposes all of them.
* **No independent audit and no machine checked proof.**
* **The scheme assumes a dual PRF.** `PRK = HMAC(key=nonce, msg=key)`
  requires HMAC to remain a PRF when keyed by its second argument. TLS 1.3
  relies on the same assumption, but it is stronger than plain PRF.
* **Envelope profiles are missing.** 1339 bytes does not fit LoRaWAN or
  Zigbee frames.
* **The replay window lives in memory** and resets when the process
  restarts.

---

## Scope of the evidence

The layer 2 results are not a security proof. They say that at the scale
tested, a 69k parameter model over 8k samples, no measurable leak was
found. Absence of evidence is not proof.

The same applies to the project as a whole:

| Present | Missing |
|---|---|
| Reduction argument with numeric bounds | Machine checked proof |
| 1085 tests, coverage guided fuzzing, gcov | Independent human audit |
| Timing scans and in-C cycle counts | Cache timing, power analysis |
| Measured indistinguishability results | Any guarantee beyond the sample |

The full list of unverified claims is in
[`docs/audit.md`](docs/audit.md) section 5. The point of this project
is that the list exists, not that it is short.

---

## License

MIT. See [LICENSE](LICENSE).
Security policy and reporting: [SECURITY.md](SECURITY.md).
Contributing rules: [CONTRIBUTING.md](CONTRIBUTING.md).
