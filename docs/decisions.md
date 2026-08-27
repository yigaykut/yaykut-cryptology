# Design Decisions

This file holds the answer to "why did we do it this way". When a decision
changes, the old one is not deleted. Its `Status` is updated and a new record
is opened.

---

## ADR-001: machine learning stays out of the cipher path

**Status:** Accepted · 2026-08-11

**Context.** The original idea was to have a RAG system pick the formula and to
teach a neural network to decrypt. The goal was to add chaos and
unpredictability to the system.

**Decision.** The encrypt and decrypt path is pure Python and fully
deterministic. AI is used only in the surrounding layers, for evaluation and
for the assistant.

**Reasoning.**

- Vector search is approximate and not invertible. Decryption needs exactness.
- Because of hubness in embedding space, some entries get picked far more often
  than others. That bias is not uniform and is open to frequency analysis.
  Worse, the bias correlates with semantic content, so it leaks the very thing
  it is meant to hide.
- **If a neural network can learn to decrypt, the cipher is already broken.**
  Successful training is proof that learnable structure remains between
  ciphertext and plaintext. A good cipher's output is indistinguishable from
  random noise.
- In ML, 99.9% accuracy is excellent. In decryption it is useless. A single
  wrong character turns the whole output into garbage.

**Where the unpredictability comes from.** The nonce. A fresh random value from
`os.urandom` on every encryption mixes into the selector alongside the key.
Encrypt the same formula twice with the same key and the outputs are entirely
different.

---

## ADR-002: the payload length leak is accepted in v1

**Status:** Accepted, deliberate gap · 2026-08-11

**Context.** Every formula has a different number of parameters at different
widths, so payload sizes differ. The measured range at the time was 96 to 517
bytes.

**The problem.** The selector is hidden with the key and the nonce, but **the
total length of the ciphertext gives away which formula was used**. An attacker
who sees 96 bytes concludes "this is a curve formula" without needing the key.
All the benefit of hiding the selector disappears.

**Decision.** Not fixed in v1. The gap is left open on purpose.

**Reasoning.** This will be the layer 2 distinguisher's first concrete target.
The model catching this leak is first hand proof that the "use AI as the
attacker" approach works. If a model fails to catch a gap that has already been
closed, we cannot tell whether it failed because it cannot see leaks or because
there was nothing to see.

**How to close it (v2).** Two options were considered and kept:

| Option | Leak | Cost |
|---|---|---|
| Pad every payload to the largest | Fully closed | 96 bytes of data travels as 517 |
| 2 or 3 size buckets (128/512/2048) | Drops from formula level to group level | Little waste, partial leak |

**When to close it.** After the distinguisher catches it, and before the system
goes into any real use.

**UPDATE 2026-08-12, the gap was measured.** The layer 2 distinguisher reached
**82.6%** accuracy at identifying the formula from the length, against an
analytic ceiling of 82.4%. The leak is therefore at its maximum: everything
extractable from length is being extracted, and 28 of 34 formulas are
identified exactly. Details and collision groups are in `docs/findings.md`.

**CLOSED 2026-08-12, see ADR-007.** Fixed padding was applied and the same
experiment repeated. Accuracy fell to **2.1%**, against a chance level of 2.9%.
This ADR is now a historical record; the gap is closed.

---

## ADR-003: corpus entries do not change once published

**Status:** Accepted · 2026-08-11

**Decision.** The distinction is whether a change **affects decoding**.

**Changes that need a new id** (semantic), with the old one going
`deprecated`:

- Anything in the `params` block: name, type, `bits`, `mod`, `role`, order
- A constraint's `expr` or `severity`
- Adding or removing a constraint

**Changes that only bump `version`** (non semantic), keeping the same id:

- The whole `doc` block (name, summary, notes, tags, references, `related`)
- A constraint's `reason` text, which is an error message, not a rule
- The `description` fields inside `params`
- The `sampler` block, which affects only test data generation, not the wire
  format

The `id` is frozen. Even when a formula is `retired` its id stays blocked and
is **never reused**.

**Reasoning.** The test is: would this change make a ciphertext produced
yesterday decode differently today? If the parameter schema changes, yes. And
it happens silently, producing not garbage but output that is *wrong yet looks
valid*. Fixing the wording of an error message changes no bytes at all.

**Implementation note.** On 2026-08-11 a character fix was applied to entries
`0x0101` and `0x0201`. Since `expr` and `severity` were untouched, both stayed
on the same id at `version: 2`.

---

## ADR-004: fixed width encoding

**Status:** Accepted · 2026-08-11

**Decision.** Every parameter is encoded at the fixed bit width declared in the
schema. Variable length encoding (varint) is not used.

**Reasoning.** Varint saves space but leaks the magnitude of the parameter. A
small `a` encodes short and that is visible from outside. In cryptography that
trade is not acceptable.

---

## ADR-005: the corpus is not secret

**Status:** Accepted · 2026-08-11

**Decision.** Nothing under `corpus/` counts as secret. The files can be
published openly without changing the security assumption.

**Reasoning.** Kerckhoffs's principle: even with the whole system in the
enemy's hands, security must come from the key alone. The first idea hid
formulas behind secret properties, like containing a letter between A and E or
being divisible by 11. That is security through obscurity and it provides
nothing. Keyed selector derivation replaced it, which is what lets the ids be
regular and sequential. The pattern is no longer a weakness.

---

## ADR-006: the sampler infers bounds and falls short on equality constraints

**Status:** Accepted, known limitation · 2026-08-11

**Context.** Layer 2's training data needs valid random parameter sets for
every formula in the corpus. The first implementation was pure rejection
sampling and it collapsed in testing: with a `length_bits <= 256` constraint on
a 32 bit parameter, the acceptance probability is 257/2³² ≈ 6×10⁻⁸.

**Decision.** Two layer sampling:

1. **Bound inference.** Single variable comparisons like `x < 26` or `x >= 3`
   are parsed and the sampling range narrowed. Only `severity: error`
   constraints are used, because forcing the warning level ones would mean no
   test data ever exercises a warning.
2. **Rejection sampling** for two variable constraints like `m < n`. Those
   typically have around 50% acceptance and pass within a few tries.

**First result.** 33 of 34 entries could be sampled automatically.

**The remaining gap at the time.** `0x0303`, the sponge construction. The
blocking constraint was found by measurement:

| Constraint | Measured rejection rate |
|---|---|
| `rate + capacity == width` | 100.0% |
| `capacity >= 2 * output_bits` | 77.5% |

A constraint demanding equality between independent variables is practically
never satisfied by uniform sampling.

**Difficulty is detected by measurement, not by guessing.** The first
implementation looked at the syntax and guessed "it contains `==` and has 2 or
more variables", which missed the one time pad entry, where the problem was not
equality but a narrow inequality. `hard_constraints()` now measures and ranks
the rejection rate of every constraint.

**CLOSED 2026-08-12, equality solving added.** The sampler now has three stages
and the **entire corpus (34/34)** samples automatically.

| Stage | What it does |
|---|---|
| 1. Bound inference | Narrows the sampling range from constraints like `x < 26` |
| 2. **Equality solving** | Computes one variable from constraints like `a + b == c` |
| 3. Rejection sampling | For whatever is left |

**The solving method is two point evaluation, not symbolic algebra.** If the
constraint's difference `g(v) = left - right` is linear in the chosen variable,
it has the form `g(v) = A·v + B`. The coefficients come from `B = g(0)` and
`A = g(1) - g(0)`, so the root is `v = -B/A`. Linearity is confirmed by
checking `g(2) = 2A + B`; if that fails, that variable is not solved. Roots
that do not divide evenly are rejected.

This covers every linear equality without writing a symbolic solver, and
because it reuses the existing safe evaluator it opens no new code execution
surface.

**The variable to solve for is chosen by measurement.** Which one matters. In
`rate + capacity == width`, solving for `width` gives `rate+capacity` and has a
good chance of staying in bounds; solving for `rate` gives `width-capacity`,
which usually comes out negative. The planner tests each candidate over 24
trials, measures how often it lands in bounds, and picks the best. For `0x0303`
it picks `capacity`.

---

## ADR-007: fixed padding, the payload is the same size for every formula

**Status:** Accepted and implemented · 2026-08-12

**Context.** The length leak left open deliberately in ADR-002 was measured by
layer 2. The distinguisher identified 28 of 34 formulas from the envelope size
alone, at 82.6% against an analytic ceiling of 82.4%.

**Decision.** The payload is zero padded to a fixed `PAYLOAD_FIXED_BYTES = 1280`.
Every ciphertext is **1330 bytes**, whatever the formula.

```
nonce(16) ‖ selector(2) ‖ payload(1280 FIXED) ‖ tag(32)
```

**The constant is NOT computed from the corpus.** If it were, adding a larger
formula would change the length of every old ciphertext and make them
undecodable. An entry that exceeds the constant is rejected explicitly, and
raising the constant needs a new wire format version.

**The padding is zeros, and it is encrypted.** Because it is XORed with the
keystream, the padding region is also indistinguishable from random, and it is
inside MAC coverage.

**Result, same experiment, after padding:**

| | Before padding | After padding |
|---|---|---|
| Analytic ceiling | 82.4% | **2.9%** (1/34) |
| Model accuracy | 82.6% | **2.1%** |
| Fully identified formulas | 28/34 | 1/34 |
| Distinct lengths | 28 | **1** |

**The cost.** The 1 byte of real data in a Caesar cipher travels as 1330 bytes,
an expansion of 1330×. The size bucket option considered in ADR-002 would have
reduced that waste but left a partial leak. Closing it fully was preferred.

**The guard.** The tests `test_all_entries_same_length` and
`test_length_ceiling_chance_to_level_dropped` fail if the padding is removed or
broken.

---

## ADR-008: BM25 rather than an embedding model for layer 3 search

**Status:** Accepted · 2026-08-12

**Context.** Layer 3 was planned as "RAG", and the first solution that comes to
mind is an embedding model. That means downloading about 500 MB of model plus
the `sentence-transformers` and `transformers` dependency chain.

**Decision.** A zero dependency BM25 was written. No embedding model was added.

**Reasoning, measured rather than assumed.** Before adding the dependency, a 25
question evaluation set was built and the quality of lexical search measured:

| Measure | Result |
|---|---|
| Recall@1 | **92.0%** |
| Recall@3 | **100.0%** |
| MRR | **0.960** |

All 25 questions were answered within the top three results. Adding a 500 MB
dependency to search of that quality does not pay for itself.

**Why BM25 is strong here.** The corpus is 34 entries full of technical terms:
ECDSA, Bellcore, Kasiski, LWE, VENONA. For queries like those, exact term match
is the strongest signal and BM25 measures exactly that. Embedding models win on
paraphrase and synonymy, and that was measured not to be decisive on this
corpus.

**The Turkish suffix problem and its solution.** To BM25, `şifre` and
`şifreleme` are different terms. Crude stemming (`şifreleme[:5]`) both merges
things wrongly and misses pairs like `asal` and `asallık`. **Prefix matching**
was used instead: two terms count as the same if one is a prefix of the other
(minimum 4 characters, with a 0.6 factor on an inexact match). With a 1652 term
vocabulary the cost is negligible.

Turkish specific lowercasing is also applied explicitly. Python's `.lower()`
turns `I` into `i`, where Turkish needs `ı`. Without that fix an `İmza` heading
would not match an `imza` query.

**Amendment 2026-08-26: the corpus and the layer moved to English.**
When the whole project was translated, the corpus entries and the evaluation
questions became English, so the two Turkish specific pieces above went with
them. The Turkish aware lowercasing was removed, since Python's `.lower()` is
correct for English, and the stopword list was replaced with an English one.

**Prefix matching stayed**, and that is the point worth recording: it was
introduced for Turkish agglutination but it earns its keep in English too, on
plurals and on pairs like `sign` and `signature`. A mechanism chosen for one
language turned out not to be tied to it.

The measurement was rerun on the English corpus and came out slightly better
than the Turkish one: Recall@1 92.0%, Recall@3 100.0%, MRR 0.953 against the
original 0.960. The thresholds were not touched.

**When to revisit.** If the corpus grows to a few hundred entries, or if
Recall@3 on the evaluation set drops below 95%. The test
`test_search_quality_holds_its_threshold` holds that threshold.

**Scope note.** This layer does not GENERATE text. It returns the relevant
entries with citations. Generation needs a language model and that is a
separate decision.

---

## ADR-009: the `0x0501` Caesar cipher is retired

**Status:** Implemented · 2026-08-12 · The project owner's decision

**Decision.** Entry `0x0501` was set to `retired`. The engine no longer
encrypts with it (`encode` refuses). The decoding path was left open so
previously produced ciphertexts stay readable.

**The file was NOT deleted.** Deleting it would free the id `0x0501`, and
ADR-003 requires that ids are never reused. If a freed id were later given to a
different formula, old ciphertexts would produce not garbage but output that is
*wrong yet looks valid*. Retirement is how you keep the file as a historical
record while blocking the id permanently.

**Technical note.** This change does not affect the engine's security level.
Corpus entries are the *content being carried*, not the cipher protecting the
message. Protection comes from the HKDF keystream and the HMAC tag. Having
Caesar in the catalog was not weakening the engine. The decision was applied
anyway, because the scope of the corpus is the project owner's call.

**Side effects.**

- The template (`_TEMPLATE.yaml.example`) used the Caesar example, and making a
  retired entry the teaching example would be inconsistent. The template moved
  to an affine cipher example and into the reserved `0x05FF` template slot.
- The old template used the id `0x0501`, so once the real entry existed anyone
  copying the template would hit an id collision. That latent defect was fixed
  in the same change.
- Tests used Caesar as the simple entry; they were switched to `afin-sifre`. A
  new test confirms that encrypting with a retired entry is refused.

---

## ADR-010: free text encryption, through a new corpus entry

**Status:** Implemented · 2026-08-12

**Context.** The engine was designed to carry "a formula plus its parameters".
Sending free text was wanted.

**Decision.** **No change to the engine.** A new corpus entry was added,
`0x0701 ham-metin`, whose parameters are the text itself (`bytes`, 1024 bytes)
and its real length (`uint`, 16 bits). A new id block was opened, `0x07xx` for
transport, because raw text is not a formula and belongs to none of the
existing blocks.

The convenience layer is `crypto/message.py`: `encrypt_text` and
`decrypt_text`, plus `Engine.encrypt_text` and `Engine.decrypt_text`.

**Why the engine did not change.** The mechanism was already general: a
selector plus typed parameters. Carrying text is a special case of that.
Adding a text specific code path to the engine would have split the one tested
path in two.

**Length privacy came for free.** The length field lives inside the payload,
and the payload is encrypted with the keystream. On top of that every
ciphertext is a fixed 1330 bytes under ADR-007. The result: a 1 character
message and a 1024 byte message look **completely identical** from outside.
Measured, with the shared byte ratio of two ciphertexts at chance level
(`test_length_field_cipher_in_the_text_open_not`).

**Limit: 1024 bytes in a single block.** Longer messages could be split, but
**the number of pieces gives away the message length**, which brings back part
of the leak ADR-007 closed. So it was capped at one block and an overflow is
refused with an explicit error. If multi block transport is wanted, how to
handle the length leak needs its own decision.

**Type confusion is refused.** Trying to `decrypt_text()` a ciphertext that
carries a formula does not silently return broken text, it raises. The other
direction works: a raw text entry can also be read with ordinary `decode()`.

**Encoding note.** Capacity is in BYTES. Non ASCII characters take 2 bytes in
UTF-8, so 1024 bytes is about 512 such characters. The error message says so
explicitly.

---

## ADR-011: chain mode, several formulas in one ciphertext

**Status:** Implemented · 2026-08-13

**Context.** The project's first note said the system would trigger which
**formulas** (plural) get used, and that the cipher was "only one part". The
engine was built single formula, which was an incomplete implementation of the
original design.

**Decision.** **Chain mode** was added to the wire format. The payload can now
carry a list of records:

```
[record count: 8 bits]
[ι₁: 16 bits][parameters of formula 1]
[ι₂: 16 bits][parameters of formula 2]
...
[zero padding]
```

When the selector carries the reserved id `0xFFFF`, the decoder expects a
chain.

**The wire format did NOT change.** From outside it is the same
`nonce ‖ σ ‖ π ‖ τ`, 1330 bytes total. The chain lives entirely inside the
payload. An observer cannot see how many records there are, which formulas they
are, or even whether it is a chain at all.

**Backward compatible.** Old single formula ciphertexts decode unchanged. Mode
confusion does not slip through silently: opening a chain with `decode()`, or
the reverse, raises an explicit error.

**`0xFFFF` is forbidden in the corpus.** If an entry took that id it would be
mistaken for a chain during decoding and silently shadowed. `Corpus.__init__`
refuses it.

**Security effect.** The chain itself puts up no new barrier against an outside
observer, since the payload is already encrypted with the keystream. The gain
is **combinatorial depth**: in a scenario where the payload is broken, the
attacker has to work out not just one formula but the order and the
combination. With 52 active formulas:

| chain length | possible orderings | blind guess hit rate |
|---|---|---|
| 1 | 52 | 1.9% |
| 2 | 2,704 | 0.037% |
| 3 | 140,608 | 0.0007% |
| 5 | 380,204,032 | 0.00000026% |

That matters if the payload ever leaks. It makes no difference to today's
measurements.

**Known limit.** A chain costs 24 bits of overhead, 8 bits of count plus a 16
bit id. The largest entry, `0x0207` ElGamal at 10240 bits, does not fit even on
its own: 10264 > 10240. It is refused with an explicit error. With the smallest
entry, 255 records fit, which is the counter's limit.

---

## ADR-012: random decoy chain

**Status:** Implemented · 2026-08-13 · On by default in the app

**Context.** ADR-011 brought chain mode, but the caller chose the formulas.
What was wanted was for **the combination to be picked automatically and at
random on every encryption**.

**Decision.** `encrypt_hidden()`: on each call it pulls random formulas from
the corpus, generates valid random values for each, and places the real message
at a **random position** among those records.

Same message, same key, five encryptions in a row, and each one gets a
different combination, a different position, and the same 1330 bytes.

**Decoding does not ask which mode.** The app tries the decoy chain first and
falls back to plain text. Since the tag is verified on both paths it is safe.

**Capacity.** The text entry is 8208 bits, and with the counter and ids there
are about 2008 bits left for decoys. The selection is capacity aware:
candidates are shuffled and taken while they fit, typically 5 to 7 decoys.

**This is a known technique.** It is called **chaff**: hiding real data among
fake records that cannot be told apart from it. Ronald Rivest set the idea out
systematically in "Chaffing and Winnowing" in 1998. The design here arrived at
the same place independently.

**What it buys:**

1. **Layer independence.** The soundness of the encryption stops being the only
   defence. If the keystream ever fails, through a nonce repeat, an
   implementation bug, or a weakness found later, the attacker still faces the
   question of which record is real. It reduces the fragility of a defence that
   hangs on a single point.

2. **The padding region is no longer zeros.** In plain mode the end of the
   payload is all zeros, and in a scenario where the keystream is broken that
   region gives away free information. Decoys fill it with valid records.
   Test: `test_covert_in_mode_zero_region_does_not_stay`.

3. **Combinatorial depth.** Even if the payload leaks, the attacker has to work
   out which formulas are present, in what order, and which one is real.

**Scope.** The distinguisher experiment we ran does not see this gain, because
that experiment measures the payload's distinguishability from outside and that
was already clean. Chaff's value shows up when the encryption fails, not when
it holds, so not being measured does not mean it does nothing.

---

## ADR-013: frame header and format version v2

**Status:** Implemented · 2026-08-15

**Context.** Two gaps pointed at the same place. First, the engine had no way
of telling whether it had seen a message before (ADR-014). Second, the format
not carrying its own version meant every future change would risk silent data
corruption.

Both are solved by adding a few bytes to the payload. The question is **where**.

**Decision.** A 9 byte frame header was placed at the start of the payload:

```
payload plaintext:
+---------+----------+----------------------+---------+
| version | sequence | body                 | padding |
| 1 byte  | 8 bytes  | (formula or chain)   |         |
+---------+----------+----------------------+---------+
```

**Why INSIDE the payload.** The sequence number could have gone in the nonce or
outside the envelope, as many protocols do. But then it would be visible in the
clear, and an eavesdropper could read how many messages were sent, at what
intervals, and whether two streams came from the same side. The metadata leak
ADR-007 closed would come back through the side door.

Inside the payload it is both encrypted with the keystream and inside MAC
coverage: it can neither be read nor modified from outside. The same goes for
the version byte, so even which version you use does not leak.

**The envelope paid the cost, not the body.** The largest corpus entry,
`0x0207 ElGamal`, is exactly **1280 bytes** and fills the body constant to the
brim. Taking the header out of the body would have meant removing ElGamal from
the corpus or trimming its parameters. The payload grew by 9 bytes instead:

| | v1 | v2 |
|---|---|---|
| body (formula data) | 1280 | **1280**, unchanged |
| frame header | | 9 |
| payload | 1280 | 1289 |
| ciphertext | 1330 | **1339** |

No corpus entry was changed. Capacity calculations now use `BODY_FIXED_BYTES`
instead of `PAYLOAD_FIXED_BYTES`.

**No cross version decoding.** A v1 ciphertext does not open with a v2 engine.
If the version byte does not match, `VersionError` is raised. Refusing
explicitly was preferred over silently returning corrupt data.

**This is not a length leak.** 1330 to 1339 is a change in the value of the
constant, not in its variability. Every ciphertext is still bit for bit the
same length.

---

## ADR-014: replay protection through a sliding window

**Status:** Implemented · 2026-08-15

**Context.** This was the most serious gap in the system. The engine did not
remember having seen a nonce before, so when an attacker captured a valid
packet and resent it hours later, MAC verification **passed**, because the
packet really had come from the side that knows the key.

On a command link that means recording a command and replaying it whenever you
like. Without ever knowing the key.

**Encryption alone cannot solve this.** Integrity says "this message was not
modified", not "I am seeing this message for the first time". The second one
needs **state**.

**Decision.** Every message carries an increasing sequence number in the frame
(ADR-013). The receiver keeps the numbers it has seen in a bitmask based
sliding window, the approach from RFC 4303 §3.4.3 (IPsec ESP).

**Why a window rather than "must always increase".** Network packets arrive out
of order. A strict increase rule would drop slightly delayed but legitimate
packets. A window gives flexibility in a bounded and auditable way: inside it
replays are caught, outside it the benefit of the doubt goes to rejection.

**The state is not in the engine.** `Engine` is stateless and stayed that way.
It does not generate sequence numbers and does not remember what it has seen.
All the state lives in the `Session` class that wraps the engine. The split is
deliberate, because the engine's determinism is what ADR-001 rests on.

**A rejected number is not written into the window.** Otherwise an attacker
could push the window forward with made up high numbers and get legitimate
messages dropped.

**Replay rejection is cheap.** `read_frame` does not decrypt the whole payload.
Because HKDF-Expand is sequential, only the first 9 bytes of stream are
produced. The CPU burning vector from a flood of replays is closed.

**Known limit.** The window lives in memory, so it resets when the process
restarts and old messages become acceptable again. It can be written to disk
with `state()` and `load_state()`, but doing so is the caller's
responsibility.

---

## ADR-015: key hierarchy and forward secrecy

**Status:** Implemented · 2026-08-15

**Context.** There was one static master key, supplied by hand. If a device was
taken, all traffic encrypted with that key, **past and future**, was open.

**Decision.** A three level hierarchy, entirely on top of the existing HKDF. No
new primitive was introduced.

```
master key                 (stays in the safe, never goes to a device)
  |- device key            HKDF(master, "device" ‖ id)
       |- epoch key        HKDF(device, "epoch" ‖ number)
            |- chain       advances one step per message
```

Three levels solve three different problems:

| Level | Problem | Gain |
|---|---|---|
| Device key | One device fell | Only that device opens, the fleet is safe |
| Epoch key | Planned rotation | Damage is bounded to one epoch |
| Chain | Recorded old traffic | **Forward secrecy** |

**How forward secrecy works.** Each step takes two derivations, the message key
and the chain's new state, and the old state is overwritten. Since HKDF is one
way there is no path from the new state back to the old. Even if the device is
taken **today**, traffic recorded yesterday cannot be opened, because
yesterday's key no longer exists anywhere.

**Forward only, not backward.** Whoever takes today's key also reads tomorrow's
messages. Backward secrecy needs a mutual key exchange (ECDH). The corpus has
elliptic curves in it, but the engine does not use them. **A deliberate gap,
written down in the README.**

**Wiping from memory is honestly limited.** `wipe()` only zeroes a `bytearray`.
In Python `bytes` is immutable and cannot be overwritten, and the garbage
collector may hold copies of a key in unexpected places. If physical seizure is
in the threat model, Python is not enough. Memory locking and secure zeroing
need C or Rust. Rather than hiding that, it is written both in the code and
here.

---

## ADR-016: envelope profiles deferred

**Status:** Deferred · 2026-08-15

**Context.** 1339 bytes is heavy on a narrowband link. LoRaWAN carries 51 to
242 bytes and Zigbee about 80. Embedded targets would need a smaller envelope,
128, 256 or 512 bytes.

**Decision: not done now.** Reasoning:

1. **There is no target platform.** Profile sizes should be derived from the
   maximum payload of the radio link. Without a chosen target, any numbers
   picked are arbitrary.
2. **It touches the structure broadly.** `PAYLOAD_FIXED_BYTES` stops being a
   module constant and becomes a parameter, spreading through encode, decode,
   chain, text and the interface. That is a high price for flexibility nobody
   is using.
3. **There is a trap worth knowing about.** If some devices in a fleet send 128
   bytes and others 1289, **the choice of profile becomes a fingerprint** and
   the length leak ADR-007 closed comes back at fleet level. When profiles do
   arrive, every device in a deployment has to use the same one.

To be opened when an embedded target is chosen.

---

## ADR-017: X25519 four way DH handshake

**Status:** Implemented · 2026-08-15

**Context.** ADR-015 gave forward secrecy but left the reverse open. All keys
derived one way from a single root, so if the root leaked, the **forward** part
of the chain leaked with it. The only way to close that is to inject fresh
randomness into the session key that is not in the root, which means a mutual
key exchange.

### Why X25519 and not NIST P-256

Layer 1 uses no external dependencies (see the header of `primitives.py`), so
ECDH was going to be written by hand too. The advice "do not write your own
curve arithmetic" is sound, but it does not apply equally to all curves. X25519
was designed **precisely so it can be implemented safely**:

| | X25519 | P-256 |
|---|---|---|
| Point validation | Not needed, every 32 bytes is valid | Mandatory; skip it and you get an invalid curve attack |
| Special cases | None, the ladder is branchless | Addition, doubling and the point at infinity are separate |
| Cofactor | Handled by scalar clamping | Must be dealt with by hand |
| Twist security | Yes | No |

Between two implementations written with the same care, the P-256 one is far
more likely to be wrong. RFC 7748 §5 gives the ladder as pseudocode, and
`crypto/curve.py` is a direct translation of it.

**Verification.** The §5.2 vectors of RFC 7748 pass, along with the iterated
vectors at 1 and 1000 rounds and the §6.1 key exchange vector. There is also a
cross check against the `cryptography` library on 25 random key pairs. That
library is **not a runtime dependency**, only a source of truth in the tests.

### Why four DHs

One is not enough. With only ephemerals there is no authentication and a man in
the middle gets in for free. With only statics every session produces the same
secret and forward secrecy is gone.

```
ee = DH(e_initiator, E_responder)    forward secrecy, ephemerals are wiped
es = DH(e_initiator, S_responder)    binds the initiator's ephemeral to an identity
se = DH(s_initiator, E_responder)    binds the responder's ephemeral to an identity
ss = DH(s_initiator, S_responder)    authentication, only these two

session = HKDF(salt = E_i ‖ E_r ‖ S_i ‖ S_r,  ikm = ee ‖ es ‖ se ‖ ss)
```

Because all four go into HKDF, **all four have to break**. The Noise
framework's KK pattern and Signal's X3DH have the same idea.

**Transcript binding.** HKDF's salt is all four public keys, so the session key
is bound to the full transcript of the handshake. That closes the unknown
key-share attack.

**Direction separation.** The two directions use different keys. With one key
in both directions the sequence numbers would collide and a packet sent by one
side would look like a replay in the other's window. The warning in ADR-014's
`Session` documentation is resolved here.

**A zero shared secret is refused.** If the peer sends a small order point, the
result comes out zero regardless of the private key, meaning the attacker chose
the shared secret (RFC 7748 §6.1).

### Transport: the handshake is a corpus entry too

`0x0805 x25519-el-sikisma`. The handshake message travels as **an ordinary
ciphertext** under the pre-shared symmetric key from the ADR-015 hierarchy. So
the handshake packet is also 1339 bytes and indistinguishable from the rest. An
eavesdropper cannot even see when a session is established.

That falls out of ADR-005: the protocol itself is part of the corpus.

**Identity provisioning.** `Identity.from_key()` derives the static X25519
identity from the symmetric hierarchy, so no separate key distribution is
needed. **The cost: anyone holding the master key can impersonate any device's
identity.** In fleet provisioning that is already true. If genuinely
independent identities are wanted, use `Identity.generate()` and record the
public keys separately. Both paths are supported.

### Known limit: constant time behaviour

The ladder is **algorithmically** constant time: a fixed number of steps,
arithmetic conditional swap, no branching. But Python's arbitrary width
integers run for different lengths of time depending on operand size, so it is
not **physically** constant time.

In a threat model where a timing attack is reachable, that is not enough. The
rest of the engine is in the same position (`primitives.xor` is a byte by byte
Python loop). The limit is not hidden; it is written in the code and in the
README.

---

## ADR-018: side channels, measured, what could be fixed was fixed, the rest written down

**Status:** Implemented · 2026-08-18

**Context.** Side channel resistance is needed if a defensive deployment is the
goal. But "I wrote it constant time" cannot be claimed by reading the source.
The compiler, the interpreter, the cache and the branch predictor all create
differences that are invisible there. **It cannot be said without measuring.**

### The measurement tool

`crypto/timing.py`, using the dudect method (Reparaz, Balasch, Verbauwhede
2016). Timings for two input classes are collected **in interleaved order**, a
Welch t-test is applied, and `|t| > 4.5` counts as a leak.

Interleaving is essential. Measured in blocks, oven warm up and garbage
collection load onto one class systematically and produce a **false leak**.

`python sidechannel.py` starts with three controls:

| Control | What it does | Expected |
|---|---|---|
| **Null** | the same input in both classes | gives the noise floor |
| **Positive** | a deliberately leaking function | `|t| >> 4.5` |
| **Negative** | a function doing constant work | `|t| < 4.5` |

Without the null control the sentence "it stayed under the threshold" is
meaningless. If the threshold is already below the noise, nothing was measured.

### The leak found: BitReader's position dependence

This was the most important finding, and it was **hard to spot by reading the
code**.

`BitReader` held the whole payload as **a single enormous Python integer**
(1280 bytes, 10240 bits) and did `(value >> shift) & mask` for each field. In
Python the cost of a bigint shift **depends on the shift amount**, which is to
say on the field's position within the payload.

The consequence was a real leak: the **order** of records in a chain changed
the parse time. In a decoy chain (ADR-012) the position of the real record is
exactly what needs to be hidden, and it was readable from the clock.

| Measurement | Before | After (6 independent trials) |
|---|---|---|
| Real record first vs last | **\|t\| = 32.32** | **0.99 to 3.01**, median 1.92 |
| `decode_chain` on its own | \|t\| = 7.97 | below the threshold |
| Noise floor (null control) | 3.03 | 0.86 to 1.72, median 1.39 |

**Amendment 2026-08-18: the single run number was misleading.** The "after"
column first carried 0.99 from a single run. Repeating the same measurement on
a loaded machine gave **\|t\| = 4.60**, above the threshold. But in that run
**the null control had also risen to 2.94**. The rig's own noise had gone up;
no leak had appeared.

The lesson matters more than the experiment: **a \|t\| value can only be read
alongside the null control OF THE SAME RUN.** The threshold is not an absolute
number, it is a measure relative to the noise floor. Across 6 independent
trials the two distributions overlap completely (null 0.86 to 1.72, real 0.99
to 3.01), so there is no distinguishable leak. `sidechannel.py` already prints
the null control on every run; the reader just has to not ignore it.

**The fix:** instead of one giant integer, only the bytes the field touches are
sliced. The cost now depends only on the **field width**, which comes from the
schema and is public anyway. The wire format did not change, this is purely an
implementation change. Side benefit: a noticeable speed up on large payloads.

### The second problem found: early return

`decrypt_hidden` broke out of the loop once it found the real record, so the
time depended on the record's position. That was removed; the loop now always
walks every record.

Honest note: the signal from that difference was below the parsing cost in
Python (\|t\| ≤ 3.4). So **the real leak was in BitReader**, not in the early
return. It was fixed anyway, because it was free, and because in a C port the
ratio reverses.

### Measured and clean

| What | \|t\| | Comment |
|---|---|---|
| Tag: tamper at start vs at end | 2.74 | `hmac.compare_digest` works |
| Decoy chain: real record first vs last | 0.99 to 3.01 | after the fix, 6 trials |
| X25519: sparse vs dense scalar | 1.58 | the ladder is branchless |
| `decrypt_text`: 2 byte vs 1000 byte payload | 1.18 | |
| Session: replay vs fresh packet | 1.68 | window check |

The tag row is the critical one. A naive `==` comparison would blow up here,
stopping at the first differing byte and letting the correct tag be guessed one
byte at a time.

### WHAT COULD NOT BE FIXED, and this is Python's limit rather than a gap

Passing this measurement does **NOT mean "side channel resistant"**. The tool
sees only algorithmic differences. Channels that in Python can be neither
measured nor fixed:

- **Bigint arithmetic taking time proportional to operand size.** The BitReader
  problem was one instance, and it was fixable because it was structural. The
  same cannot be said of the field arithmetic in the X25519 ladder.
- **Cache timing and memory access patterns.**
- **Power analysis and electromagnetic leakage.**
- **Keys not being wipeable from memory.** `bytes` is immutable and the garbage
  collector keeps copies in unexpected places. `wipe()` only zeroes a
  `bytearray`, and that limit is written in the code.

**If physical access is in the threat model, Python is not enough.** What would
be needed: a C or Rust implementation, memory locking (`mlock`), secure zeroing
(`memset_s` or `SecureZeroMemory`), a guarantee against being written to swap,
and a hardware crypto accelerator. None of that is in this project's scope, and
being out of scope is **written down explicitly** rather than hidden.

---

## ADR-019: the C core, X25519 rewritten constant time

**Status:** Accepted · 2026-08-18

**Context.** ADR-018 ran the side channel sweep and said two things. The one
measurable real leak, BitReader's position dependence, was fixed, but there is
a residue Python cannot close: **bigint arithmetic taking time proportional to
operand size**. The X25519 ladder sits right on top of that residue. At each
step, numbers of different sizes get multiplied depending on a bit of the
private key. Measuring |t| = 1.58 does not refute this, it only shows that
Python's interpreter noise buries the signal. The source of the leak is
structural and cannot be fixed in Python.

And the secret involved is not an ordinary session key, it is the **long lived
identity key**. If it leaks, every handshake past and future falls.

**Decision.** X25519 moved into its own C source (`ccore/crypto25519.c`). The
Python side loads it through ctypes via `crypto/fastpath.py`. **The library is
not required.** If it is missing, out of date, or fails its own self test, the
pure Python path in `crypto/curve.py` takes over.

**Reasoning, four design decisions.**

*1. Why only X25519 and not the whole engine.* The rest of the engine has no
secret dependent arithmetic. HMAC and SHA-256 are already in OpenSSL's C, the
tag comparison goes through `hmac.compare_digest` which is also C, and XOR and
field reads are fixed width. The ladder is the only structural leak left.
Moving the whole engine to C would mean maintenance burden and new bug surface
in places where it buys nothing.

*2. Why 12 limbs of 22 bits rather than ref10's 10 × 25.5.* Known
implementations unroll the multiplication by hand for speed. The result is fast
but cannot be verified by eye. The priority here is not speed but
**verifiability**: a uniform base, a plain double loop schoolbook
multiplication, and an overflow margin you can compute on paper.

    12 · 22 = 264 bits  ->  2^264 ≡ 19 · 512 = 9728 (mod p)
    limb < 2^22 -> product < 2^44 -> folded term < 2^57.3
    the busiest accumulator: 11 folded + 1 plain  <  2^60.7  <  2^63

The largest intermediate measured was 2^60.71, exactly matching the bound on
paper, leaving **2.29 bits** of headroom in int64. The borrow problem in
subtraction was closed by adding 1024·p, since p's top limb is 8191 and p
itself was not enough.

*3. Why ctypes and not a CPython extension.* An extension would tie the build
to a Python version and ABI. A plain shared library can also be used on an
embedded target, from another language, or directly from a test run. Layer 1's
"no external dependencies" rule stays intact too, since ctypes is in the
standard library.

*4. Why a self test before use.* A miscompiled cryptography library silently
producing wrong keys is more dangerous than no library at all.
`crypto25519_selftest()` runs the RFC 7748 vectors on the C side. The loader
**does not use** the library until that test passes, and `build.py` **deletes**
a library that fails it.

**Verification happened in two stages.**

*Stage one, without a compiler (2026-08-18).* When the code was written this
machine had no C compiler. Cryptography code that has never been compiled does
not count as written, so the arithmetic was verified separately.
`ccore/twin.py` is a line by line Python equivalent of the limb arithmetic in
the C file, with the same base, the same constants and the same carry passes.
The twin tests three things at once:

| What | How |
|---|---|
| Correctness | RFC 7748 §5.2 and §6.1 vectors, plus comparison against `curve.py` on 15 random and 7 edge inputs |
| Overflow margin | Every intermediate asserted against 2^63, so what is silent in C is loud here |
| Convergence | The three passes of `fe_carry`, and `fe_sub` never going negative |

The constants are checked for drift too. The test reads `P22`, `Q1024`, `LIMBS`,
`BASE` and `FOLD` out of the C source, compares them with the twin's, and
verifies the mathematical definition of each (is `P22` really p, is `FOLD`
really 2^264 mod p). A twin that drifted from the C would lose its value as
verification.

*Stage two, compiled (2026-08-19).* MinGW-w64 was installed and `build.py`
passed **on the first attempt**:

| Gate | Result |
|---|---|
| Compile, gcc 16.1.0 (MinGW-w64 UCRT), `-O2 -Wall -Wextra -pedantic -std=c99` | **0 warnings** |
| The library's own RFC 7748 self test, on the C side | passed |
| 50 cross checks against pure Python | passed |
| Commutativity check, a·(b·G) = b·(a·G), 10 rounds | passed |
| Test suite (3 previously skipped tests now run) | 724 passed |

That is the proof the twin earned its keep: **zero rounds of fixes were
needed.** 300 lines of hand written field arithmetic matching the RFC vectors
on first compile is not luck. The arithmetic had already been verified in
Python, so all that was left was syntax.

**Speed: 1.2×, and that is not a problem, it is the bill for the choice.**

| | time |
|---|---|
| Pure Python | 1.710 ms |
| C core | 1.396 ms |

That was expected: schoolbook multiplication is a 12×12 loop with 3 carry
passes after every operation. ref10 is about 20× faster than this. **Speed was
not the goal.** The record already gave verifiability as the reason, and here
is the bill. If speed is ever needed, the path is clear: tune the carry passes
per operation type (2 passes are enough for addition and subtraction), then
unroll the multiplication. The twin can verify the correctness of those changes
too.

**An unmeasurable gain, an honest negative result.**

The C core's timing benefit **could not be demonstrated** with
`sidechannel.py`:

| Path | Null control | Sparse vs dense scalar |
|---|---|---|
| Pure Python | 1.05 to 2.23 | 1.08 to 3.24 |
| C core | 1.17 to 2.98 | 1.40 to 2.99 |

In both configurations the measurement is indistinguishable from its own noise
floor. Not because C does nothing, but because **the rig lacks the
resolution**. The measurement is taken from Python and interpreter noise buries
the signal either way.

So the C core's assurance comes not from this measurement but from **the
structure of the code**: no data dependent branching, no data dependent memory
access, fixed width arithmetic. Proving it by measurement would require
measuring from inside C, with a hardware counter such as `rdtsc`. That was not
done, and not doing it is written here.

**Still out of scope** (ADR-018's list still stands). Moving to C does not
automatically give side channel resistance. All it gives is **the removal of
data dependent branching and variable time arithmetic**. Cache timing, power
analysis, electromagnetic leakage, memory locking (`mlock`) and a guarantee
against swap are none of them in this decision's scope. Whether the compiler
"optimises" the constant time code into something that is not was also not
verified; that would need inspecting the generated assembly.

---

## ADR-020: key material moved into wipeable memory

**Status:** Accepted · 2026-08-19

**Context.** ADR-018 left behind a list of things Python cannot fix. The last
item on it was:

> Keys cannot be wiped from memory. `bytes` is immutable and the garbage
> collector keeps copies in unexpected places.

In a defensive context that was the sharpest item on the list, because the
others (cache timing, power analysis) need an expert attacker and physical
access, while exploiting this one **only takes a memory dump**. A core dump, a
hibernation file, a swap file, the RAM of a seized device: in every one of
them the key was still sitting there, and Python had no way to erase it.

Once ADR-019 brought the C core, this stopped being Python's limit.

**Decision.** `SecureBuffer` in `crypto/memory.py` keeps key material in a
block allocated on the C side, **locked**, and **actually zeroed** when closed.
All three links of the chain are in C:

| Stage | Call | Gain |
|---|---|---|
| Generation | `crypto_random()` | The secret never becomes `bytes` |
| Use | `crypto25519(address, …)` | The secret is processed without leaving the buffer |
| Death | `crypto_wipe()` | Zeroing the compiler cannot elide |

Without all three the chain breaks. Once a secret has been a `bytes`, it stays
there.

**Reasoning, three details, each of them a source of silent failure.**

*1. Why zeroing is not `memset`.* In the sequence
`memset(p, 0, n); free(p);` the compiler may treat the zeroing as **dead code**
and drop it, and usually does. It is one of the rare places where a standard
optimisation turns directly into a vulnerability (CWE-14, "Compiler Removal of
Code to Clear Buffers"). The fix is to reach `memset` **through a volatile
function pointer**: the compiler cannot assume where the pointer points, so it
cannot drop the call.

*2. Why the lock is needed.* An unlocked page gets written to disk when the
operating system is short on memory. Even if the key is erased from RAM, **the
copy in the swap file remains**, and it stays there after the process dies.
`VirtualLock` on Windows and `mlock` on POSIX prevent that.

*3. Why a failed lock does not stay silent.* The lock does not hold in every
environment: the process working set limit on Windows, a low `RLIMIT_MEMLOCK`
on Linux. Reporting "locked" without actually locking is worse than not locking
at all, because it gives false confidence. `SecureBuffer.locked` and
`.guarantee` report the real state, and `build.py` prints it in its output.

**Where it was wired in.** The ephemeral handshake key (`Handshake._efemer`).
The choice is not arbitrary: **forward secrecy rests entirely on that key
dying.** It used to sit on a `bytearray`, which could be zeroed but not locked,
and the call `curve.public_key(bytes(...))` was copying the secret into `bytes`
anyway. Now `close()` is called at the end of `complete()`: the contents are
zeroed and the locked page released.

`Identity.secret` was **deliberately left as `bytes`**. The original API is
preserved. An identity key is loaded from disk and lives a long time; moving it
into a buffer would break the API and the gain would be small next to the
ephemeral case. That is a gap, and it is written here.

**A fourth gate.** `build.py` now puts the library through four checks, and the
new one is this: write a pattern into a buffer, call `wipe()`, and check it is
really zero. A library that says "wiped" without wiping gets **deleted**. The
same check also exists on the C side (`crypto_memory_selftest`) and the loader
calls it before using the library.

**What it does not close, and this list did not get shorter, it lost one item.**

- Calling `to_bytes()` produces a copy and **that copy cannot be wiped**. The
  method is deliberately not called "safe"; its docs carry the warning and a
  test pins it.
- A kernel crash dump can still contain locked pages. Turning that off is a
  separate process level setting (`PR_SET_DUMPABLE`, `SetErrorMode`) and is out
  of scope.
- Hibernation writes all of RAM to disk and the lock does not prevent it.
- Cache timing, power analysis, electromagnetic leakage: unchanged.

**Effect on the defence question.** The answer to "could this be used in
defence" moved from **"no"** to **"maybe, under these conditions"**. One
technical obstacle really was removed. What remains: certification
(administrative, and decisive on its own), independent audit, and the rest of
the list above.

---

## ADR-021: long lived keys moved into secure memory too

**Status:** Accepted · 2026-08-19

**Context.** ADR-020 brought the secure buffer but wired it only to the
**ephemeral** handshake key. Its own text said:

> `Identity.secret` was deliberately left as `bytes`. […] That is a gap, and it
> is written here.

The gap pointed the wrong way. An ephemeral key lives for milliseconds; **an
identity key sits in memory for the life of the device.** The one most likely
to land in a memory dump is the one that lives longest. The same was true of
ADR-015's key hierarchy and `KeyChain`.

**Decision.** Every long lived secret moved into `SecureBuffer`:

| Secret | Lifetime | Where |
|---|---|---|
| `Identity._buf` | the device's life | buffer, never becoming `bytes` on the `generate()` path |
| `KeyChain._chain` | a session | buffer, overwritten on every advance |
| `master_key_buffer()` | the fleet's life | buffer, randomness taken directly in C |
| `device_key_buffer()` and `epoch_key_buffer()` | long | buffer, except the HKDF intermediate |

**Reasoning: backward compatibility was not broken.** The constructor
`Identity(secret_bytes)` and the properties `.secret`, `.public` and `.trace`
still work, so code that loads a key from disk keeps running. `.secret` now
returns a **copy** and carries a warning in its docs: the returned `bytes`
cannot be wiped and `close()` does not affect it. The cryptographic path goes
through `.buffer` and the secret is never copied.

The old hierarchy functions that return `bytes` (`master_key`, `device_key`,
`epoch_key`) were **not removed**; the `_buffer` variants were added alongside
them.

**A weakness found along the way, and its fix.** The first implementation used
`malloc` plus `VirtualLock`. The silent problem: if two small buffers land on
the same 4 KB page, **closing one unlocks the other as well.** The lock is lost,
nobody says anything, and the "locked" claim becomes a lie. Allocation moved to
page granularity (`VirtualAlloc`, `mmap`), so every buffer gets its own page.
The cost is a minimum of 4 KB per buffer, which is irrelevant in practice since
keys are counted in tens. libsodium's `sodium_malloc` does the same thing for
the same reason.

**One behaviour changed, and the old one was a trap.** `KeyChain.close()` used
to zero the chain key but leave the object usable. `message_key()` would still
return a key, derived from a zeroed chain, meaning **the same key on every
closed chain**. Silently encrypting with the wrong key is far worse than
raising. Accessing a closed chain is now refused explicitly (`BufferError_`).
Its test was updated on those grounds rather than deleted.

**A rejected alternative: moving SHA-256 into C as well.**

`hkdf_expand` uses Python's `hmac` and `hashlib`, and those return `bytes`. So
**a derived key briefly exists as unwipeable `bytes` before it is copied into a
buffer.** The only way to close that was to move SHA-256 and HMAC into C too.
It was not done, for three reasons:

1. **It goes against the project's own rule.** The most repeated sentence in
   these records is "the primitives are standard, I did not write my own hash".
   Reimplementing SHA-256 would weaken that. *Implementing* a standard is not
   *designing* one, but it is still new bug surface.
2. **It already runs in C.** `hashlib` goes to OpenSSL, so there is no timing
   gain. The only gain would be in memory hygiene.
3. **The gain would be partial.** The message's **plaintext** already enters
   through the API boundary as a Python `str` or `bytes` and cannot be wiped.
   Closing the key derivation intermediate while leaving the plaintext open is
   changing the lock on the door and forgetting the window.

So the limit is written plainly: **the long lived copy is in wipeable memory,
the intermediate is not.** The intermediate becomes unreachable on the garbage
collector's first pass, which is a mitigation, not a guarantee.

**Still open.** The plaintext and the per message subkeys (`primitives.py`),
crash dumps, hibernation, cache timing, power analysis, electromagnetic
leakage. The list is collected in one place in `docs/audit.md`.

---

## ADR-022: fuzzing and a compile audit, two unverified claims closed

**Status:** Accepted · 2026-08-19

**Context.** `docs/audit.md` §5 opened with a list of unverified claims. Three
of its items were the kind I could close myself:

| Item | Status |
|---|---|
| HKDF not tested against RFC 5869 vectors | Closed the same day (`test_hkdf.py`) |
| Not verified that the compiler preserves constant time behaviour | **This record** |
| No fuzzing | **This record** |

The others (independent audit, a formal security reduction) are not things one
person can close alone.

---

### 1. The compile audit, `ccore/compile_audit.py`

**The problem.** The odd thing about writing constant time code is that **the
absence of branches in the source is not enough**. The compiler can recognise
mask arithmetic as "there is really an `if` here" and turn it into a branch. The
C standard does not forbid that, because the standard says nothing about
timing. For the same reason `memset` can be dropped (CWE-14).

**What was done.** The tool generates assembly with `-O2 -S -fverbose-asm`,
traces the condition of every conditional jump backwards, and classifies it.
Any branch that cannot be classified is reported as **REVIEW** and the tool
exits non zero. So this is not a list of noise, it is a **regression check**.

**Findings.** All 68 conditional branches were classified:

| Class | Count | Why it is safe |
|---|---|---|
| Loop counter | 34 | The condition comes from `ivtmp`, `i` or `k`, not secret data |
| Ladder counter | 1 | The INDEX of the bit (254 down to -1), not the bit itself |
| Null or size guard | 13 | Address validity and size, not content |
| Self test | 20 | Public test vectors, not on the cryptographic path |

**No data dependent branch was found.** Two further observations:

- gcc turned `fe_cswap`'s mask arithmetic into **`cmov`** (8 of them). That is
  branchless, so it is good news, but constant time behaviour there is **a
  microarchitectural observation, not an architectural guarantee**. The
  compiler chose `cmov` this time; the next version could choose a branch. That
  is exactly why the tool exists.
- `crypto_wipe` compiled to **an indirect jump through a volatile pointer**, so
  the wipe was not dropped. ADR-020's CWE-14 countermeasure verified in the
  assembly.

**A bug in the tool itself.** The first version's counter pattern was
`#.*(?:i|j|k|t)\s*$`, which also swallowed the comment `# gizli`, because
"gizli" ends in 'i' too. **A loose pattern silently classifies a real finding
as safe**, which is the most dangerous failure mode an audit tool can have. A
word boundary was added, along with tests that exercise the pattern's looseness
(`test_compile_audit.py`).

**Positive and negative controls.** The tool is given a deliberately leaking
file (an `if` on a secret bit) and confirmed to catch it, and confirmed not to
false alarm on a branchless version. An uncontrolled "clean" result says
nothing.

**A known limit, pinned by a test.** In a loop bounded by a runtime length, gcc
auto vectorises and adds "is the length enough" pre-tests. Those branches
depend on the length, not on secret data, but nothing in the assembly comment
says so, and the tool marks them REVIEW. That case does not arise in the real
core (`LIMBS = 12` is a constant), but the limit is documented.

---

### 2. Fuzzing, `fuzz.py`

**The invariant.** One sentence is tested: *every input that is not genuine
must be refused with a RECOGNISED error.* Recognised means `CryptoError` and
its subclasses. Anything outside that is a finding, and **silent success** is
the worst case of all.

**Why random bytes alone are not enough.** Random bytes catch on the tag and
never reach the parser, so that kind of fuzzing tests only HMAC, which OpenSSL
wrote. The interesting territory is past the tag. That is why the
`campaign_hostile_payload` campaign **produces the ciphertext itself, with the key**: a
valid tag over a hostile internal structure. The finding came from there.

**FINDING: `ValueError: division by zero` was leaking out of the decoder.**

Constraint expressions are written assuming valid values. During decoding the
values come from the ciphertext, so if a hostile payload produces `p = 0`:

```
0x0101  (4 * a**3 + 27 * b**2) % p != 0     ->  ValueError: division by zero
```

That error is **outside** the `CryptoError` hierarchy. The engine's contract is
that every refusal is a `CryptoError`, and an exception outside the contract
punches through the caller's `except CryptoError` block and takes the
application down.

There are **29 constraints** in the same shape, containing `%` or `/`, spread
across four blocks of the corpus.

**Exploitability, honestly assessed.** Not directly exploitable. Reaching this
requires a valid tag, which means the key. But (a) a faulty sender or corrupted
storage produces the same result, (b) breaking the API contract is a defect on
its own, and (c) if a mode is added later that parses before the tag, it
becomes a direct attack surface.

**The fix.** `check_all` now catches evaluation errors and **converts them to
`ConstraintViolation`**. The reasoning: a constraint that cannot be evaluated is
a constraint that is not satisfied. `p = 0` is not a valid prime in the first
place, and the expression blowing up is a symptom of that, not a separate
event. Warning level constraints come back as warnings rather than raising.

The caught set is deliberately **narrow**: `ValueError`, `TypeError`,
`ArithmeticError`. Catching `Exception` would hide a real engine bug behind
"constraint violation".

**Verification.** The same seed (`python fuzz.py 5000 1`) gave 4 findings before
the fix and is clean after. Four regression tests were added as well, at unit
level in the constraint evaluator and on the engine's real path with a 400
round hostile payload campaign.

**Positive control.** The fuzzer is given three defects it must catch (an out
of bounds read, a silent accept, a wrong type) and every run prints that it
caught all three. If it does not, every "clean" line is worthless.

**Coverage.** Seven campaigns: random bytes, bit flips, truncation and
extension, hostile payloads, frame edges, the replay window, and the curve and
handshake. They run in the test suite on a small budget every time, and by hand
with `python fuzz.py 5000 <seed>`.

**OUT of scope.** Coverage guided fuzzing (AFL, libFuzzer) was not done. The
campaigns were designed by hand, so they are limited to the attack shapes I
could think of. Fuzzing is **evidence of presence, not evidence of absence**.

---

## ADR-023: coverage guided fuzzing written by hand

**Status:** Accepted · 2026-08-20

**Context.** ADR-022 brought fuzzing and produced one real finding, but it also
added a new line to `docs/audit.md` §5:

> Coverage guided fuzzing (AFL, libFuzzer): **none.** The campaigns were
> designed by hand, so they are limited to the attack shapes I could think of.

That was ADR-022's own limit. Blind fuzzing produces random input and most of
it hits the same shallow path. Coverage guided fuzzing sets up a **feedback**
loop: which branches were taken is recorded, **an input that opens a new branch
is kept**, and it becomes the basis for later mutations. The search climbs into
regions of the program it has not seen before, on its own.

**Decision.** The tool was written by hand: `coverage_fuzz.py`.

*Why not an off the shelf tool.* The standard option is Atheris (Google, built
on libFuzzer), but it is **for Linux and macOS**. Installing it on Windows
needs clang and libFuzzer, and this machine has only MinGW gcc. The source
package was downloaded and would not build. Rather than waiting and writing
"could not be done", doing the essential part turned out cheaper, because since
Python 3.12 `sys.monitoring` hands over branch events directly.

**How it works.**

```
sys.monitoring BRANCH event  ->  (code, branch point, target point)
                             ->  hit count per run
                             ->  AFL bucket: 1,2,3,4-7,8-15,...,128+
a new (edge, bucket) pair    ->  the input joins the corpus
```

---

### The positive control exposed two real gaps

"Coverage guided" is an adjective, and adjectives have to be proved. The test
is the classic one: a bug triggers only when N bytes are hit in a row. Blind
search needs 256^N attempts; guided search should climb at linear cost, because
each correct byte opens a new branch.

**On the first run the guided search DID NOT FIND IT**, over 59,000 runs.
Without the control the tool would have gone on printing "clean" reports, and
that would have been an empty promise.

*Gap 1: there was no hit counter.* Coverage was kept as a SET of edges, so a
branch had either been taken or not. The comparison in the target sits inside a
**loop**, so for `i = 0,1,2,3` it is the same bytecode and the same edge. "I got
one byte right" and "I got two bytes right" were indistinguishable. AFL's
solution was added: hit counts are reduced into logarithmic buckets.

*Gap 2: there was no "write a random byte" operator.* The mutation set had bit
flips, interesting bytes and small arithmetic. Getting from `0x00` to `0xDE` by
bit flips takes six steps, and **the intermediate steps open no new coverage so
they are not kept in the corpus**, which dead ends the search. A single random
byte write makes every value directly reachable with probability 1/256.

With both fixed, the guided search found it.

### Corpus selection was measured, not guessed

On the four byte check, three seeds, 6 second runs:

| Strategy | Result |
|---|---|
| Uniform random | found it 1/3 |
| Pick from the last quarter | found it 1/3 |
| **70% newest entry** | **found it 3/3** |

The reason: as the corpus grows, uniform selection lowers the chance of picking
the deepest entry and the search circles in the shallow region it has already
exhausted. AFL solves this with energy scheduling; this is the plainest version
of it, exploit the TIP of the search and go back occasionally for diversity.

### Measured capability, and its limit

| Depth | Blind search cost | Guided, 3 seeds |
|---|---|---|
| 3 bytes | 2^24 | found 4/5 (3 s) |
| 4 bytes | 2^32 | found 2/3 (6 s) |
| 5 bytes | 2^40 | **found 3/3 (20 s)** |
| 6 bytes | 2^48 | 0/3 (40 s), not reached |

Blind search cannot find even 3 bytes in the same time (170,000 runs).

So the tool crosses **a 2^40 search space in 20 seconds** but cannot reach
2^48. The climb rate is roughly a few seconds per byte and grows with depth.
That is slow next to a fuzzer compiled in C, because the `sys.monitoring`
callback runs Python code at every branch.

---

### Result on the real targets

There are two targets, and the distinction is the same as ADR-022's:

- **raw ciphertext**, including the tag gate. Realistic but shallow.
- **payload past the tag**, where the fuzzer's data is enveloped with a valid
  key so mutation works directly on the payload and can reach deep into the
  parser.

**The seed corpus.** The most neglected part of coverage guided fuzzing. A
search starting from nothing has to stumble onto the correct length of 1339
bytes by chance and never gets past the tag gate. Real ciphertexts and sampled
records are given as seeds, and the difference is pinned by a test (seeded
coverage is more than three times the unseeded).

**Long run result** (240 s per target, seed 7):

| Target | Runs | Coverage | Corpus | Result |
|---|---|---|---|---|
| Raw ciphertext | 199,688 | 127 | 7 | clean |
| Payload past the tag | 9,424 | 183 -> **206** | 34 | clean |

The difference between the two rows is exactly the expected one. The raw target
**reached 127 coverage in its first 500 runs and stayed there**, because the
tag gate cannot be crossed, so all 199,000 runs walk the same shallow path. The
deep target had twenty times fewer runs and yet **kept increasing coverage**
throughout (183 to 206), meaning the search was still climbing. A longer run
would have seen more.

No new findings. The `ValueError` leak ADR-022 found was already fixed, and
coverage guidance does not reproduce it.

### Out of scope, explicitly

- **The inside of the C core is invisible.** `sys.monitoring` only watches
  Python bytecode, so branches inside `crypto25519.dll` are not counted. There
  is a separate tool for the C side (`ccore/compile_audit.py`), but it is
  static.
- **Coverage is measured at branch level, not path level.** Two different paths
  crossing the same set of branches are indistinguishable.
- **It is slow.** Hundreds to tens of thousands of runs per second rather than
  millions, depending on how heavy the target is.
- **Not finding something is not proof it is not there.** Fuzzing is evidence
  of presence; coverage guidance deepens the search without exhausting it.

---

## ADR-024: C coverage and the security argument

**Status:** Accepted · 2026-08-20

**Context.** Two of the remaining items in `docs/audit.md` §5 were still the
kind I could close:

- *"The INSIDE of the C core is not observed by coverage"*, which was ADR-023's
  own limit, since `sys.monitoring` only sees Python bytecode.
- *"The AEAD security of the symmetric construction is unproven"*, where no
  formal reduction argument had ever been written.

The rest (independent audit, cache timing, power analysis) need either a person
or hardware.

---

### 1. C coverage, `ccore/c_coverage.py`

A library instrumented with gcc's `--coverage` flag is built, the test suite is
pointed at it and run, and `gcov` reports how many times each line executed.

**Two obstacles along the way, both worth noting.**

*gcov cannot handle a non ASCII path.* The project lives under
`C:\Users\MSİ\...` and gcov's runtime assumes ASCII when creating the output
directory: `profiling: C:\Users\MSİ: Cannot create directory`. So the tool
copies the sources into an ASCII only directory and builds there. Finding that
took time, and it is written in the module's docs so nobody has to look for it
again.

*A test was leaking an environment variable.* The first measurement said 15
lines never ran, and the tests added afterwards **did not change the number at
all**. The cause: `test_broken_library_is_not_used` was **deleting**
`CRYPTO_CCORE` in its `finally` block. If the variable was set from outside,
which is exactly what `c_coverage.py` does, every test running AFTER that one
went to a different library, and the coverage measurement came out silently
wrong.

> **The lesson:** a test restoring the environment means **putting it back**,
> not resetting it. Fixed, with a regression lock
> (`test_environment_variable_is_not_leaked`).

**Result.**

| File | Lines (before -> after) | Branches (before -> after) |
|---|---|---|
| `crypto25519.c` | 100% (179 lines) | 90% (70 branches) |
| `safe.c` | 75.81% -> **82.26%** | 60.87% -> **76.09%** |

What raised the coverage was new tests. **Four reachable guard lines** that had
never run were found: `crypto_buffer_open(0, …)`, allocation failure,
`crypto_buffer_close(NULL, …)` and `crypto_random(NULL, …)`. They had never
been tested because the Python side already prevented them.

> An untested guard is a guard **not known to be correct**. If
> `if (p == NULL) return;` is written wrong, nothing tells you, until a null
> pointer arrives in production.

**The remaining 11 lines are documented as unreachable.** The tool has an
`UNREACHABLE` dictionary with a written reason for each line (CSPRNG failure,
the error branches of the self test, which only run on a BROKEN build, and in
that case the library is rejected anyway). The list matches on the line's TEXT
rather than its NUMBER, so it does not break on its own when code shifts. If an
unexplained line appears, the tool exits non zero, which makes it **a
commitment rather than a way of hiding things**.

**Honest limit:** even at 100% branch coverage this is not a proof of
CORRECTNESS. Every line having run does not say it produced the right answer.
The RFC vectors and the cross checks say that.

---

### 2. The security argument, `docs/security-argument.md`

The full definition of the scheme, its assumptions, the reductions and the
numeric bounds, in one document. **An argument, not a proof.** It was not
machine checked and the document says so in its first line.

**A finding that came out of writing it: the dual PRF assumption.**

```
PRK = HMAC-SHA256(key = N, message = K)
```

HMAC's **key is the nonce**, a public value, and its **message is the secret
key**. HMAC is not being used in the usual direction here. For `PRK` to be
pseudorandom, HMAC also has to be a PRF when keyed through its *second*
argument, which the literature calls a **dual PRF**, an assumption **stronger**
than plain PRF (Bellare and Lysyanskaya 2015).

This is by design in HKDF-Extract, and **TLS 1.3 rests on the same
assumption**, so it is respectable. But the scheme's security depends on it and
that was written nowhere in the code. It should be the first thing an auditor
knows.

**Other numeric results in the document:**

- Nonce collision (random nonce, not a counter): `q²/2^129`. At 2^32 messages
  that is 2^-65, at 2^48 it is 2^-33. It counts per key, which is one of the
  reasons for the key hierarchy.
- Forgery: 2^-256 per attempt.
- Length hiding, a property **standard AE does not give**. But only at single
  message level; message counts and timing still leak.
- The six unwipeable objects that hold the plaintext in memory, listed by name.

**The half measure was deliberately avoided.** Putting the keystream in secure
memory while leaving the plaintext in `bytes` is changing the lock on the door
and forgetting the window, and it looks safer than it is. That appearance is
more dangerous than an open gap.

**The document is tied to tests.** `tests/test_security.py` (32 tests)
verifies the argument's machine checkable claims: envelope sizes, nonce
freshness, domain separation, **the MAC covering every region of the
envelope**, length hiding, long lived secrets being in a buffer, even the
arithmetic of the birthday table. What the document counts as gaps is tested
too, because the most dangerous state for a security document is not writing
down what is missing.

What cannot be tested (the reduction steps, the PRF assumptions) stays in the
document, marked "this is not a proof". Prose rots, and leaving the testable
parts untested turns a document into a lie over time.

---

### Out of scope, and why

| What | Why it is not mine to do |
|---|---|
| Independent code audit | By definition it needs another person |
| Machine checked proof (EasyCrypt, ProVerif) | A separate toolchain and expertise, far beyond scope |
| Cache timing, power analysis, EM leakage | Needs hardware and a measurement rig |
| Protecting the plaintext in memory | Would require moving SHA-256 into C, rejected with reasons in ADR-021 |

---

## ADR-025: a generated corpus is a capability, not a security parameter

**Status:** Accepted · 2026-08-21

**Context.** Deciding to publish the repo raised a question, since publishing
the corpus makes the formulas visible. The proposal was this: have a model
generate NEW entries similar to the existing ones, give each network a
different set of formulas, so that **even if the key is compromised** the real
secrecy stays in the formula base. A spy detection idea came with it: give each
network member different (fake) information and see which version gets acted
on, to find the leaker.

The proposal makes three separate claims, and **they are not of equal quality**.
This record separates them.

---

### 1. The parts of the proposal that are real

**1.1 A separate key per network, compartmentalisation.** Correct, and already
possible through ADR-015's key hierarchy. One member being compromised does not
open all traffic. That is a usable gain today, and it has nothing to do with
formulas.

**1.2 A canary trap.** Giving each recipient a distinctly different variant and
finding the leaker from which one gets out is **a real technique with a name**:
canary trap, or barium meal; the tracing direction is called traitor tracing in
the literature. The proposal's "different location for each network" is the
classic form of it, and it **needs no AI**. What it needs is a per recipient key
(which exists) and a record of which variant went to whom.

> Note: n recipients does not require n separate messages. If the variants are
> distributed in a combinatorial group testing pattern, a single observation
> narrows the suspects to log₂(n). That was not built; building it deserves its
> own decision record.

**1.3 A larger decoy pool.** The decoy (chaff) chain in ADR-012 pulls random
formulas from the corpus on every message. As the corpus grows, the variety of
decoy combinations grows, **and that gain rests on no secrecy at all**:

| corpus | C(M, 6) decoy combinations | bits |
|---|---|---|
| 53 (today) | 22,957,480 | 24.5 |
| 86 (+33 generated) | 470,155,077 | 28.8 |
| 200 | 82,408,626,300 | 36.3 |
| 500 | 21,057,686,727,000 | 44.3 |

**This is the defensible use of a generated corpus.** It does not conflict with
Kerckhoffs: publish the pool and the gain still holds, because the gain comes
from volume, not from a secret.

---

### 2. The part of the proposal that is not real

**The claim:** *"Even if the key is found, formula based secrecy means it
cannot be decrypted."*

That claim fails for three separate reasons, and all three can be turned into
numbers.

**2.1 An architectural ceiling of 16 bits.** The selector in the wire format is
**2 bytes**. However many formulas get generated, the uncertainty that "which
formula" can carry is at most 2¹⁶.

```
real corpus (53 active)      ->   5.73 bits
+33 generated (86)           ->   6.43 bits
10,000 generated             ->  13.29 bits
theoretical ceiling (2^16)   ->  16.00 bits   <- the selector is 2 bytes
                                  ---------
symmetric key                -> 256.00 bits
```

The gap is **240 bits**. Corpus secrecy cannot replace the key. At best it adds
16 bits beside it. That ceiling is locked by
`test_selector_16_bit_corpus_secrecy_ceiling_puts`.

**2.2 The insider, where the proposal contradicts its own threat model.** The
scenario says there is a spy in the network. But to be in the network a member
needs **both the key and the corpus**, since a member without the corpus cannot
interpret the message. So the spy has the corpus.

> Formula secrecy does not work against exactly the adversary it was designed
> to catch.

Against an outside attacker who has stolen only the key it buys a delay. This
is **a code book**, not a cipher. Code books have historically fallen to known
plaintext and insider leaks, and both are present here.

**2.3 The real entropy is the generator's seed, not the size of the corpus.**
`generator.py` is deterministic, and the same seed gives the same corpus
(`test_same_seed_same_output` locks that). If the generator is published, all
the uncertainty of a "secret" corpus collapses to **a single integer**.
Generating 10,000 entries does not mean 13.29 bits, it means however many bits
the seed has, and the seed is on the command line.

This is ADR-001's back door: *machine learning stays out of the cipher path.*
If a generated corpus counts as a security parameter, the generator's output
distribution becomes one too, and ML has quietly entered the cipher path.

---

### 3. The decision

A generated corpus is **a capability, not a security parameter**.

- Generated entries live separately under `generated_corpus/` and do not mix
  into `corpus/` automatically.
- Entries are marked with a `generated` tag in `doc.tags`. The marker is
  **only in the `doc` block**, because the engine does not read that block and
  it never reaches the wire. `test_generated_marker_wire_a_does_not_leak` locks
  that: if the marker leaked into params or constraints, generated traffic
  would become distinguishable.
- Corpus secrecy was **not added** to the security argument
  (`docs/security-argument.md`). The argument still rests on the key.

---

### 4. What was built

**`layer2/generator.py`, a structural generator.** It learns the distributions
of parameter count, type, bit width, role, constraint shape and id block from
the 54 real entries, and samples new ones. Constraint templates are abstracted
over the AST using **the engine's own parser** (`crypto.constraints.parse`),
because writing a separate parser would produce expressions the engine does not
accept.

**What it does not generate: mathematics.** A generated entry is NOT a new
cryptographic formula. Its `latex` field is a placeholder assembled from the
parameters. A model that produces mathematically correct new formulas cannot be
trained on 54 examples, and claiming otherwise would be false. The `doc` block
is deliberately left as a **seam**.

**`layer2/exam.py`, five gates.** Schema, semantics, samplability, round trip,
indistinguishability. The exam uses **the engine's** criteria rather than the
generator's, because tying the generator and the validator to the same
assumptions would let them be wrong together.

**Measurement (40 entries, seed 0):**

| gate | failures |
|---|---|
| schema | 0 |
| semantics | 0 |
| samplability | 7 |
| round trip | 0 |
| **passing** | **33 / 40** |

The seven failures are the expected kind: generated constraints can contradict
each other (`x > 5000` and `x < 3`). Trying the sampler rather than proving the
contradiction is both correct and the method used elsewhere in this project.

**Gate 5, distinguishability.** The question: can a model look at a ciphertext
and say whether the entry came from the real or the generated corpus? That is a
direct precondition for network compartmentalisation. If network A's traffic is
distinguishable from B's, an attacker learns who is in which network without
breaking the key at all.

| arm | accuracy | 95% interval | AUC |
|---|---|---|---|
| real (genuine vs generated) | 0.5025 | [0.4679 to 0.5371] | 0.4883 |
| **control (sabotaged)** | **1.0000** | [0.9952 to 1.0000] | **1.0000** |

The interval contains 0.5, so **they were indistinguishable**. The positive
control at 100% shows the rig catches a signal when there is one, so the result
on the real arm means "indistinguishable" rather than "could not be measured".
The reason is known: the payload is XORed with the HKDF keystream, so the
structure of the plaintext is not visible in the envelope.

**What this measurement does not say:** that generated entries are "safe".
Safety comes from the envelope, not from the entry. The only thing measured is
that the entry **adds no extra leak to the envelope**.

---

### 5. The exam's own positive control, and the bug it found

The first four gates are fed six sabotaged entries that must not pass: an
invalid slug, an unknown type, a blocked id, a forward reference, a payload
overflow, and a contradictory constraint. Each must fail **at the expected
gate**.

On the first run the forward reference entry **passed** the exam. The fault was
mine: `analyze_params` returns `(bits, errors, warnings)` and I had discarded
`errors` with `_` and looked at `warnings`. The gate was seeing no semantic
errors at all, and no "passed" result would ever have given that away.

> You cannot trust a gate's verdict without testing the gate. Without the
> sabotage entries the 33/40 result would have been reported as it stood, and
> it would have been wrong.

---

### 6. The part that needs a human

| What | Why it is not mine to do |
|---|---|
| Mathematical meaning in the `doc` block | A language model could be attached, but there is no rig that automatically verifies the CORRECTNESS of what it generates. Nobody can audit 10,000 generated formulas. |
| The operational design of a canary trap | Who gets which variant and how the observation is gathered are operational decisions, not engineering ones |
| Network topology and key distribution | Who belongs to which network is a policy question |

---

## ADR-026: the prekey, separating the selector mask from the master key

**Status:** Accepted · 2026-08-22

**Context.** ADR-025 rejected corpus secrecy as a security parameter. But the
real problem that record pointed at was separate, and it was genuine:

```
PRK          = HKDF-Extract(salt = nonce, ikm = K)
selector msk = HKDF-Expand(PRK, "v1/selector")   <-- tied to K
payload  ks  = HKDF-Expand(PRK, "v1/payload")
mac      key = HKDF-Expand(PRK, "v1/mac")
```

All three subkeys derived from the same secret. The consequence: **if K is
exposed, which formula was carried is exposed too.** The message's content and
its metadata hung on the same secret, when the main gain this project claims is
metadata protection (`docs/audit.md` §1).

**Decision.** The selector mask derives from **an independent secret** when one
is supplied:

```
selector msk = HKDF-Expand(HKDF-Extract(nonce, P), "v3/onanahtar/selector")
```

P is called the **prekey**, and there is one per network.

---

### 1. Backward compatibility is not negotiable

With `onanahtar=None` the output is **byte for byte identical** to before.
`test_without_a_prekey_output_byte_byte_same` compares the two paths under the same
nonce and locks it.

That test exists for one reason: new tests exercise the new path. If the old
path broke silently, **no new test would catch it**, and every ciphertext
produced since ADR-013 would become undecodable.

---

### 2. What it buys

**Key separation.** Different purposes hang on different secrets. It is one
step past the domain separation done with HKDF's `info` field: now not just the
label but the **root secret** differs.

**Resistance to partial compromise.** Scenarios where K alone falls are real:
cryptanalysis, a single subkey leaking, a memory dump that catches K but not P.

**Group identity, which is the real gain.** P can be SHARED across a whole
network while K stays pairwise. So: a separate K with every member, but a
common P across the network. The network becomes a coherent group and members
cannot read each other's messages. **That is exactly the topology a canary trap
needs** (ADR-025 §1.2): pairwise K to send each member different information,
common P to know they are all part of the same network.

**Compartmentalisation between networks.** Network A's wire selector
distribution is independent of B's.

---

### 3. What it does not buy, and this was measured rather than claimed

`layer2/selector_attack.py` sets up this attack: the attacker has K but not P.
Anyone with K can already decrypt the payload, since the payload stream comes
from K. They hold the parameters and only lack which formula they belong to.
The corpus is public too (ADR-025). So they can try each candidate formula's
parameter layout and see which one parses consistently.

**Measurement (300 rounds, 53 active formulas):**

| arm | result |
|---|---|
| positive control (P known) | correct formula 100% |
| correct formula in the candidate list | 100% |
| **narrowed to a SINGLE candidate (full identification)** | **0%** |
| average candidate count | **24.66 / 53** |

In bits, which is the measure that actually means something:

```
NO prekey, K held          :  0.00 bits   (the attacker knows exactly)
prekey present + this attack:  4.62 bits
blind guessing (upper bound):  5.73 bits   (log2 53)
                               ---------
what the attack strips      :  1.10 bits
```

**The prekey works:** it protects 4.62 of the 5.73 bits of uncertainty
available. The parse consistency attack strips only 1.10 bits.

**But the ceiling did not move.** The total uncertainty across 53 formulas is
already 5.73 bits, and since the selector is 2 bytes the architectural ceiling
is 16 bits (ADR-025). The prekey **protects that small budget, it does not
enlarge it.** Nor does it protect the content: plaintext still hangs on K.

**It does not work against an insider.** A network member already has P,
otherwise they could not interpret the formula. What catches a spy is not
crypto, it is the canary trap. ADR-025 §2.2's argument applies unchanged.

---

### 4. Why not a fixed permutation

The wish for "different formula codes in each network" could have been met with
a fixed permutation (π_P: formula -> code). That was deliberately not done:

> A fixed permutation is **deterministic.** The same formula gets the same code
> in every message, and the attacker can say "these two are the same formula"
> without decrypting anything.

A nonce dependent mask does not leak that repetition.
`test_mask_every_nonce_at_changes` looks for selector repeats across 100
messages.

---

### 5. P has to be independent

If P is DERIVED from K nothing is gained, because whoever knows K computes P.
`Prekey.generate()` takes it straight from the CSPRNG and `Engine` rejects the
case P == K.

**Honest limit:** that check only catches the most obvious mistake. If P had
been derived from K with HKDF, `is_independent` would not catch it.
Independence is not something you can enforce, it is something you **commit
to**, which is why the document says so.

Since P is a long lived secret it is kept in a `SecureBuffer` (ADR-020 and
021), wipeable and in locked memory where possible.

---

### 6. Derived entries, the answer to "what do we do if we cannot generate mathematics"

ADR-025 said the structural generator cannot produce mathematics. Derived
generation is the honest way around that limit: **do not generate the
mathematics, inherit it.**

That is how it works in real life too. RSA-2048 and RSA-4096 are separate
entries but the same mathematics; P-256 and P-384 are the same equation at
different parameters. A derived entry does this: the parent entry's `latex`,
`summary` and constraint expressions carry over **unchanged**, and only the
parameter widths are scaled.

- The tag is `derived`, NOT `generated`, because a derived entry contains no
  generated mathematics.
- `doc.related` and `notes` point at the parent, so a reader knows where to
  verify the mathematics.
- It stays in the parent's id block, so the block convention is not broken.

**Measurement (40 entries, mixed mode, seed 0):**

| gate | failures |
|---|---|
| schema | 0 |
| semantics | 0 |
| samplability | 2 |
| round trip | 0 |
| **passing** | **38 / 40** |

That both failures are **structural** entries is not a coincidence: inheriting
the mathematics also inherits constraint satisfiability. All 20 derived entries
passed (`test_derivatives_exam_passes` locks that at a 90% threshold).

---

### 7. Out of scope

| What | Why |
|---|---|
| Distributing P to a network | Key distribution is a policy question, and the handshake already exists (ADR-017) |
| Rotating P | Meaningful but a separate decision; K's chain mode (ADR-015) is the model to follow |
| Meaning in a derived `doc` block via a language model | ADR-025's reasoning holds: unverifiable mathematics is worse than an honest placeholder |

---

## ADR-027: network topology, open, restricted and covert open networks

**Status:** Accepted · 2026-08-22

**Context.** ADR-026 defined WHAT a network is: a prekey P shared across the
network, a pairwise K per member. What it did not define was how networks
relate to EACH OTHER. Can a network be created inside a network? If so, does
the parent see it? Is the number of networks recorded anywhere?

**Decision.** Three modes. A network is nothing but a single root secret S, and
everything else derives from it with HKDF.

```
S  (32 bytes)
|- P              = HKDF(S, "v4/ag/onanahtar")        selector mask
|- K_member(who)  = HKDF(S, "v4/ag/uye" ‖ who)        pairwise key
|- T              = HKDF(S, "v4/ag/korpus-tohumu")    network specific corpus
|- S_c(label)     = HKDF(S, "v4/ag/cocuk" ‖ label)    sub network [covert mode only]
```

| Mode | Sub network | Sub network's root secret | Can the parent read it |
|---|---|---|---|
| OPEN | allowed | `os.urandom` | **no** |
| RESTRICTED | not allowed | | |
| COVERT | allowed | `HKDF(S, "cocuk" ‖ label)` | **yes, first degree** |

---

### 1. ADR-026's key separation is not broken

At first glance it looks broken, since P and K now come from the same root. It
is not, because they are **siblings**, not ancestor and descendant.

ADR-026's rule was "P must not derive FROM K", and the reason was that anyone
knowing K could compute P. Here `K_member = HKDF(S, ...)` is one way: even if
K_member is compromised, S cannot be recovered, so P does not fall. The
structure is the same one `subkeys` uses to produce three independent subkeys
from a single PRK.

`test_four_derived_also_from_each_other_different` locks that the four are all different,
and `Engine`'s P == K check locks the most obvious mistake.

---

### 2. Why a covert open network is indistinguishable

What reaches a member is a single root secret. In an open network it comes from
`os.urandom`, in a covert one from `HKDF(S_parent, ...)`. Since HMAC-SHA256 is
a pseudorandom function, the two are indistinguishable to anyone without
S_parent.

On top of that the descriptor is **fixed length** (38 bytes: 4 magic, 1
version, 1 mode, 32 root) and carries no field belonging to the parent. The
network's NAME does not go into the descriptor. If it did, the length would
vary from network to network and they could be separated without reading any
content at all.

**Why NO escrow field was added to the message.** Classic key escrow puts a
copy of the key, encrypted for the parent, into the message. That path was
rejected: the field grows the message, it is visible in the wire format, and
the secrecy ends at the first hexdump. Escrow by derivation adds no bytes at
all.

---

### 3. Measurement, not a claim (`layer2/network_attack.py`)

Everything a member holds (the 256 raw bits of the root secret, the mode byte
of the descriptor, the fingerprint of the derived prekey) is fed to a logistic
regression.

| arm | accuracy | 95% interval | AUC |
|---|---|---|---|
| control (sabotaged derivation) | 0.9900 | [0.9643, 0.9973] | 1.0000 |
| **real (covert vs open child)** | **0.4700** | **[0.4020, 0.5391]** | **0.4779** |

```
positive control (the parent has the secret) : 100%
```

**All three arms are necessary:**

- **The real arm** did not beat chance; its confidence interval contains 0.5.
- **The sabotage arm** proves the distinguisher IS NOT BLIND. Without it the
  47% on the real arm would mean nothing, because a distinguisher that sees
  nothing also gives 50%.
- **The positive control** proves covert mode actually works, that the parent
  really can re-derive the sub network.

**ON THE FIRST RUN THE SABOTAGE ARM FAILED (57%).** It showed two separate
defects at once: (a) the sabotage zeroed a single BIT, and that signal has a
theoretical ceiling of 75%, so even a perfect distinguisher could not reach
100%; (b) the logistic regression was not converging in 600 steps. Both were
fixed (two whole bytes, 6000 steps). Without the control arm the 47% on the
real arm would have been reported as "indistinguishable", and that would have
been **a correct number with empty evidence**.

---

### 4. "First degree only" is a consequence, not a policy

`child_network` **always returns an OPEN network**, even in covert mode. The
reason is not cryptographic, it is logical:

> A network object in covert mode tells its mode to whoever HOLDS it. If the
> sub network were given covert mode, its owner would see that, and the
> secrecy would already be over at that point.

Because sub networks are open, their children are born from `os.urandom` and
the root network cannot derive grandchildren. The requested "first degree only"
behaviour falls out of that choice on its own; there is no depth counter
anywhere. `test_grandchildren_is_invisible` locks it.

---

### 5. Why the number of networks is invisible

Because there is no ledger counting them. A network is a secret, not an
account, and `child_network` writes no record anywhere. Invisibility is not a
feature that was added, it is the consequence of keeping no records.

**That has a price, and the parent pays it:** the parent cannot count either.
It can only derive a sub network whose LABEL it knows. In practice the labels
are known, because the parent distributed the client that follows the counter
scheme (`scan`), but a member who modifies their client and picks a different
label drops out of view. This is not a gap cryptography can close, it is a
naming scheme problem, and it is written into `docs/audit.md` §5 as an open
item.

---

### 6. A network specific derived corpus (`layer2/network_corpus.py`)

What was asked for: different derived operations per network so the ciphers do
not get mixed up.

**Mixing was not being prevented by the corpus in the first place.** Network
A's message does not decode in B because the tag is computed with a 256 bit key
and fails under the wrong one. A corpus id carries at most 16 bits (ADR-025)
and adds nothing beside the MAC. `test_another_of_the_network_message_MAC_in_fails` keeps
that distinction on record.

The real gains of a network specific corpus are elsewhere:

| gain | what it gives |
|---|---|
| **watermark** | The corpus derives deterministically from the network's root secret, so a leaked corpus file shows which network it came from. Exactly what a canary trap is looking for. |
| **operational compartmentalisation** | One network's operator cannot accidentally interpret another network's traffic with their own corpus. It protects against accidents, not attackers. |
| **agreement without transport** | Because the seed derives from the root secret, two ends produce the same corpus without exchanging a single byte. |

**Only `derivatives` is used, not `generate` (structural).** A derived entry inherits
its mathematics from its parent, where it has been verified (ADR-026 §6). A
structural entry carries unverified mathematics and should not enter a corpus
that will carry real traffic. Its place is the decoy pool (ADR-012). Generated
entries also go through the engine's own gates, and failures are discarded.

**A Mersenne Twister warning.** Corpus generation uses `random.Random`, and MT
is NOT a CSPRNG. Someone who sees enough output can reconstruct its internal
state. That is why the seed is not S directly but
`HKDF(S, "korpus-tohumu")`. Even if the seed is fully compromised, S cannot be
recovered; the loss is bounded to the corpus, and the corpus is not treated as
an absolute secret anyway (ADR-025).

---

### 7. An architectural boundary

`crypto/network.py` only does HKDF derivation and DOES NOT IMPORT `layer2`. The
code that builds the corpus lives in `layer2/network_corpus.py`. The cipher
path not depending on layer 2 is a foundational rule of this project.

---

### 8. This is a backdoor, and it should be named

A covert open network means the parent can regenerate its sub networks' keys.
The name for that in the literature is **key escrow**. That it is undetectable,
because it adds no field to the message, does not make it less of a backdoor.
It makes it **better hidden**.

The reason for writing it down: whoever builds this capability and whoever uses
it should know what they are doing. The rest of the system says "members cannot
read each other". This mode adds the exception "but the network owner can read
one level down", and leaving the exception unwritten would not have made it go
away.

**The mechanism itself is not secret.** This file is public (ADR-025). What is
secret is not "does such a mode exist" but "is THIS network in that mode". That
is what conforms to Kerckhoffs.

---

### 9. Epoch rotation, the root in the safe, an epoch on the device

ADR-026 left prekey rotation as "not decided", and ADR-027 made the situation
worse with S, since now a single secret carries the whole network. It is being
closed, without a new primitive, by moving ADR-015's shape up to network level:

```
S_d = HKDF(S, "kripto/v4/ag/donem" ‖ d)
```

`Network.epoch(d)` returns a complete `Network` of its own: its own P, its own
member keys, its own corpus, its own sub networks. The mode is preserved
EXACTLY, so an epoch of a covert network is also covert. Otherwise rotation
would quietly turn off the observation capability.

**The epoch number comes from the calendar** (`epoch_number`), so two ends find
the same epoch without a handshake, for the same reason as `epoch_key`.

**WHAT IT GIVES.** The root secret stays in the safe and only that epoch's
network is loaded onto a device. If the device is taken, the attacker reads
only that epoch's traffic, and since there is no path from S_d back to S they
cannot derive another epoch. `test_epoch_from_the_network_to_the_root_no_way_back` locks that
end to end: after the root is closed the device keeps working and no new epoch
comes out of the root.

**WHAT IT DOES NOT GIVE, and this distinction has to be written.** It gives
**NO forward secrecy against root compromise.** Whoever takes S computes every
epoch. Epochs give compartmentalisation in time; they do not protect the root
secret itself. The only thing protecting the root is never putting it on a
device, which is an operational decision, not a mechanism.
`test_root_compromise_if_it_passes_ALL_epochs_fails` locks that LIMIT too, so that if
someone one day describes this as forward secrecy, the test shows the document
and the code saying the same thing.

**THE COST.** When the epoch changes so does the corpus, since the seed derives
from S. If you delete the root for forward secrecy, **your own archive becomes
unreadable**. That is what forward secrecy means, and it is written in the code
and here so it is not a surprise.

**Measured.** An epoch network is indistinguishable from a freshly created one,
in the third arm of `layer2/network_attack.py`, at 45.5 to 50.5% with AUC about
0.5. Rotation not giving itself away rests on the same HKDF argument, and it
was not left unmeasured.

---

### 10. Two measurement gates were bound to the wrong measure

Two separate fragilities came out, and both are different faces of the same
lesson.

**(a) The control arm was bound to accuracy.** The threshold
`accuracy >= 0.95` failed on one run: accuracy 0.9450, **AUC 0.9994**. The
distinguisher was not blind, the 0.5 decision threshold was not calibrated. A
logistic regression trained on few samples ranks correctly but does not
calibrate probabilities. The gate was moved to AUC, which is threshold
independent.

**(b) The chance arms were bound to a 95% confidence interval.** As a test gate
that is a category error: a test at α=0.05 fails on about 5% of runs even when
the null hypothesis is TRUE. Sure enough the epoch arm burned on one run in
three with nothing having changed in the network. The tests were converted to a
±3 standard deviation band (0.35 to 0.65), which cuts false alarms to about
0.3% while still catching a real distinguisher, since that would come out near
1.0. **The 95% interval stays in the report**, because that is the right tool
there.

The shared lesson: **a flaky security test is the worst kind.** The day it
fails because of a real leak, someone says "that flaky test again" and moves
on.

---

### 11. Out of scope

| What | Why |
|---|---|
| Label discovery | A naming scheme problem, not a cryptography problem (§5) |
| Traffic collection | Covert mode is a READ capability; obtaining the ciphertext is a separate job |
| Second degree observation | Deliberately excluded, for the reason in §4 |
| Forward secrecy against root compromise | §9 says it is not given and WHY; keeping the root in a safe is an operational decision, not a mechanism |

---

## ADR-028: closing the open items, the canary, long messages, measurement tools

**Status:** Accepted · 2026-08-23

**Context.** After ADR-027 the open items on the roadmap and in
`docs/audit.md` §5 were taken one by one. This record says how each one closed,
and which ones **did not close and why**. The list of what did not close
matters more than the list of what did.

---

### 1. The canary trap (`crypto/canary.py`)

This was the "not decided, an operational decision" line. What is an
operational decision is which piece of fake information to invent. **Who gets
which variant, and who comes out of a leak, is a mechanism**, and mechanisms
can be written.

Two regimes: one to one (n variants for n people) and **group testing**, where
each member gets a binary codeword and in each round the members split in two
according to that round's bit. For 500 members only two variants per round are
needed, and the lower bound on identification is ⌈log₂ n⌉.

**Measurement (50 members, 36 rounds, `layer2/canary_experiment.py`):**

| arm | result |
|---|---|
| negative control (no leak at all) | 100%, everyone is a suspect |
| one traitor, leaking every round | **100% full identification** |
| one traitor, in 50% of rounds | 100% (1.00 suspects on average) |
| one traitor, in 25% of rounds | 84% (1.31 suspects on average) |
| two traitors, random pair | 0% could frame someone |
| **two traitors, the WORST pair** | **2 innocents can be framed** |

**NOT COLLUSION RESISTANT, and that was not closed, it was made VISIBLE.**
Two traitors can compare their codes, see which bit is unique to each of them
in the rounds where they differ, construct a code neither of them has, and
accuse an innocent. There are four tools:

| tool | what it does |
|---|---|
| `collusion_exposure(a, b)` | who this pair could frame |
| `is_safe()` | whether no pair can frame anyone, scanning all pairs |
| `build_safe(...)` | adds rounds until nobody can be framed |
| `possible_framers(x)` | if x was accused, who could have fabricated it |

The last one is the most useful: when an identification comes out, whether the
accusation could have been fabricated is TESTABLE. A silent gap becomes an
auditable one. None of them sees a three way collusion; the answer for that is
Boneh-Shaw or Tardos codes, and it is out of scope.

**The default round margin was chosen by measurement**, not by feel. The
`--sweep` output (50 members): margin 0 gives 58% framing, margin 8 gives 10%,
margin 16 gives 0%. The default is one step beyond that (24), because a 0% from
limited sampling is not proof.

**TWO MEASUREMENT MISTAKES SURFACED WHILE WRITING THE TESTS.** The experiment
tool was sampling RANDOM pairs and reporting "0% framing", while
`worst_collusion`, which scans all pairs, was finding a gap. With 50 members
there are 1225 pairs, and hitting the worst one in 200 trials is unlikely. **A
real attacker CHOOSES the pair, they do not draw it at random.** The right
measure is the worst case, and it was added to the experiment as its own arm.
`worst_collusion` also took minutes in a pure Python loop; converting the codes
to integer bitmasks brought it to 10 ms.

---

### 2. Multi block long messages (`crypto/longmessage.py`)

This was another "not decided" line. A single frame carries 1024 bytes of text
and anything longer raised.

**Naive splitting is insecure**, and that is the real subject of this record.
Each block carries a valid MAC on its own, so an attacker can reorder the
blocks, drop the last ones, duplicate them, or splice in a block from another
message, all without knowing the key. None of the four looks like "corrupt
ciphertext". What comes out is silently WRONG YET VALID.

The solution: a header goes into each block's plaintext before encryption, so
it falls inside MAC coverage.

```
message_id(16) ‖ index(2) ‖ total(2) ‖ total_length(4) = 24 bytes
```

On decoding, the `message_id` has to be uniform, `total` consistent, the
indices exactly 0..total-1, and the block count equal to `total`. All four
attacks are tested separately.

**A step back from ADR-007, and it is written down.** A single frame was fixed
size and leaked no length at all. Across multiple blocks the length leaks at
**block resolution** (1000 bytes). There is no way to carry unbounded length at
a fixed size. `target_blocks` closes it partly: every length below the target
looks the same, at the cost of bandwidth, and the choice is left to the caller.

---

### 3. Traffic analysis (`layer2/traffic.py`)

This was the "packet count and send time channels, not decided" line. Once long
messages were added, measuring it became mandatory.

The observer is given not a single byte of ciphertext, only the block count and
the total byte count.

| arm | accuracy | AUC |
|---|---|---|
| negative control (same distribution) | 0.5000 | 0.5000 |
| **multi block, UNPADDED** | **1.0000** | **1.0000** |
| multi block, padded with `target_blocks=8` | 0.5000 | 0.5000 |
| single frame (ADR-007) | 0.5000 | 0.5000 |

The unpadded leak is **total**: the observer separates the classes 100% of the
time. That is not a bug, it is the measurement of the limit declared in §2.
Padding brings it down to chance, and ADR-007's single frame claim was
confirmed from a traffic observer's point of view too.

**The send TIME channel was not measured and cannot be:** this library does not
send packets. If a transport layer is written, it should be measured there.

---

### 4. Timing the C core with `rdtsc` (`ccore/timing_rdtsc.c`)

`docs/audit.md` §5 said "could not be measured, proof needs an rdtsc
measurement from inside C". It was done.

```
POSITIVE: deliberately data dependent function  |t| =  1337.62   (A 2237 / B 418867 cycles)
NULL:     the same scalar twice                 |t| =     0.03
X25519:   low vs high Hamming weight            |t| =     0.37   (2628 difference out of 1.2M cycles)
```

**X25519 shows no scalar dependent timing**, and that result only means
something because the positive control passed.

**TWO BUGS IN THE RIG SHOWED UP FIRST.**

**(a) The measurement order was biased.** A was measured first in every
iteration, so the per iteration overhead always landed on A. Negligible for
X25519 at 1.2M cycles, but it swamps the signal on small functions. The
positive control failed at |t| = 1.03 and the sign of the difference came out
BACKWARDS. Alternating the order every iteration cancels the bias on average.

**(b) The compiler turned the positive control into constant time code.** The
first version of the control was
`if ((scalar[i] >> b) & 1) t += ...`, and `gcc -O2` turned it into a
conditional move (cmov). A function written specifically to be data dependent
compiled to constant time: A 110451 cycles and B 110229, when A's popcount is 1
and B's is 256. **The rig was not blind, there was no difference to measure.**

This is ADR-022's compile audit confirmed from the other direction: the
compiler does not preserve the branch structure of the source. The good news is
that constant time code is preserved this way; the bad news is that **saying
"there is a branch in the source" proves nothing**. It was solved by moving the
data dependence into the loop's trip count, which the compiler cannot fix.

---

### 5. Sampler distribution uniformity (`layer2/sampler_uniformity.py`)

This sat in §5 as "partial". It was measured, but the real lesson was that
**the measurement's premise was wrong.**

The first version said "every skew not solved by an equality is a defect" and
reported 17 parameters as defects. Both parts were wrong:

* **Rejection sampling is uniform over the JOINT valid set.** The MARGINAL of a
  parameter coupled to others by constraints is generally not uniform, and does
  not need to be. If `p` has to be prime, p's marginal cannot be uniform.
* **The bucket count had to match the range.** `block_size` takes only the
  values 2 to 8, so with 16 buckets 9 of them are necessarily empty and
  chi-square calls it "skewed". The measurement's own bug was being reported as
  a finding.

The corrected measurement (300 samples per entry, a 4 second budget per entry):

```
parameters measured : 78 (16 of which appear in no constraint)
found skewed        : 9
  solved by equality (EXPECTED)          : 0
  constraint coupled, marginal (EXPECTED): 9
  APPEARING IN NO CONSTRAINT (REVIEW)    : 0
```

The one meaningful question left, whether an unconstrained parameter is skewed,
has the answer **no**. 16 entries could not produce enough samples within the
time budget (2048 bit primes) and are reported as "could not measure". A tool
hanging silently is worse than one giving an incomplete measurement.

---

### 6. The network corpus generator: Mersenne Twister removed

ADR-027 §6 justified using `random.Random` on the grounds that the seed goes
through HKDF so the root secret cannot be recovered. The reasoning was correct
but **it answered the wrong question**: the root secret was protected, the
GENERATOR itself was not. MT is not a CSPRNG. Someone who sees 624 consecutive
outputs reconstructs its internal state and computes every entry the network
has produced or will produce.

`layer2.network_corpus.HkdfGenerator` keeps the `random.Random` interface but
draws its entropy from an `HKDF-Expand(PRK, "korpus-akis" ‖ counter)` stream.
`choice`, `choices` and `sample` work unchanged. **The problem was removed
rather than justified.**

---

### 7. `child_network` was leaking the mode through timing, MEASURED and CLOSED

ADR-027 measured that a covert open network is indistinguishable from an open
one. That measurement looked at **bytes**. When the side channel sweep was
extended to the network layer, it turned out **the clock gives it away**:

```
child_network: covert vs open   |t| = 121.53   Δ = +7635 ns   (noise floor 1.92)
```

The covert branch ran HKDF while the open branch ran `os.urandom`. A member who
asks the parent for their sub network and measures the response delay would
learn the mode. So the claim "it looks no different from an open network" was
right in the bytes and **wrong on the clock**.
`layer2/network_attack.py` could not have seen this, because it looks at bytes.

The fix: both branches do one `os.urandom`, one root read and one HKDF, and
only the choice of which secret goes into the HKDF differs.

```
after the fix   |t| = 0.34 to 0.57   (noise floor 0.60 to 5.02)
```

Two tests lock it. One measures the timing against the noise floor of the same
run, the other is **structural**, counting that both branches call the same
primitives the same number of times, which does not depend on machine noise.

**The lesson:** anything claiming indistinguishability has to go through the
side channel sweep too. Indistinguishable bytes do not mean indistinguishable
timing.

---

### 8. What did not close, and why

| What | Why it did not close |
|---|---|
| Independent code audit | Needs a person. Not something that can be written. |
| Machine checked proof (EasyCrypt, ProVerif) | A separate toolchain and expertise, out of scope. |
| Mathematical correctness of generated entries | Cannot be automated (ADR-025). Unverifiable mathematics is worse than an honest placeholder. |
| Discovering sub network labels | A naming scheme problem, not a cryptography problem (ADR-027 §5). |
| Forward secrecy against root compromise | Not given, and why is written down (ADR-027 §9). Keeping the root in a safe is an operational decision. |
| A canary resistant to three way collusion | Needs Tardos or Boneh-Shaw codes; left out of scope in §1. |
| The send time channel | This library does not send packets, so there is nothing to measure (§3). |
| Member id length leaking through timing | HMAC scales with input length. What leaks is not a secret but a label's length, and member names are not treated as secret. A caller who wants equal lengths should pad. |
| Coverage not being measured at path level | It is measured at branch level; unchanged. |

---

## ADR-029: creating a covert open network needs authorisation

**Status:** Accepted · 2026-08-25

**Context.** COVERT is key escrow (ADR-027 §8): the network owner can read the
traffic of first degree sub networks. ADR-027 added it as a capability and left
it open to everyone. What was wanted: that capability in the owner's hands
only.

**Decision.** Constructing a `Network` OBJECT in `NetworkMode.COVERT` was put
behind a password. The password is not stored in the repo in plaintext, only a
salted HMAC-SHA256 digest iterated 100,000 times.

```
digest = HKDF-Expand( HMAC^100000(salt, password), "kripto/v6/ag/yetki", 32 )
```

---

### 1. THE LIMIT FIRST: this is NOT a cryptographic lock

This is the most important item in the record, and it goes at the top so nobody
thinks otherwise.

**Anyone with the source deletes the check.** It is one `if`. There is no way
to prevent that and claiming there is would be a lie.

**More fundamentally: the capability cannot be restricted.** Covert mode
amounts to "I derive the sub network's root secret from my own root secret":

```
S_child = HKDF(S_parent, "cocuk" ‖ label)
```

Anyone with their own secret writes those three lines in their own code. No
check can prevent that universally, and saying it could would misrepresent the
scheme.

**So what the gate actually does:**

| it does | it does not |
|---|---|
| Put THIS program's covert network creation behind a password | Restrict the capability universally |
| Prevent escrow being set up accidentally or casually | Stop someone who edits the source |
| Keep the password out of the repo in plaintext | Slow down a determined attacker |

---

### 2. THE REAL GAIN: the password does not enter the repo

The project is going to be public on GitHub (ADR-025). If the password were
written into the source in plaintext it **would burn the moment it was
published**, and the gate would die on the day it was born.

The repo holds only a salt and a digest.
`test_PASSWORD_SOURCE_IN_THE_TREE_PLAIN_TEXT_NOT` scans the whole source tree and
verifies the password appears in no file.

**That test FAILED on its first run, and it was right.** I had written
`" <password>"`, with a leading space, into the wrong-password test's parameter
list, and the password had entered the repo as a substring. The variants are
now derived at runtime from an environment variable.

---

### 3. WHERE the gate is, and why there

The check is in `Network.__init__`, not in `Network.create`. The reason: the
only way for a `Network` object to CARRY covert mode is through the
constructor. `create`, `from_descriptor` and a direct
`Network(root, mode=...)` all come down to it. If the gate were in `create`, a
direct construction would bypass it and the gate would be decoration.

All three covered paths are tested separately
(`test_covert_network_unauthorised_CANNOT_BE_CREATED`).

**`from_descriptor` needs authorisation too:** a covert mode descriptor carries
the root secret, and whoever reads it sees everything the parent sees.

---

### 4. Authorisation applies to CREATION, not to USE

A network that has already been created keeps working after authorisation is
turned off: `observe`, `epoch` and `child_network` all continue.

The opposite would be both pointless and dangerous. The owner would lose the
ability to read their own sub networks the moment they turned authorisation
off. `epoch()` is also called with an internal flag; if it asked for the
password again, epoch rotation would be unusable.

---

### 5. Tests and measurement tools SKIP, they do not count as passing

Because the password is not in the repo, the tests read it from an environment
variable:

```
CRYPTO_NETWORK_PASSWORD=...  python -m pytest tests/ -q
```

If it is unset, the tests that exercise covert mode are **skipped**. `skip` was
chosen over `xfail` because pytest counts skips separately and they do not show
up as quietly green.

```
without the password : 49 passed, 36 SKIPPED
with the password    : 85 passed
```

`layer2/network_attack.py` has to create a covert network, since what it
measures is whether a covert child can be told from an open one. Without
authorisation it **does not run and exits 2**. A measurement that did not run
is not a pass.

---

### 6. The work factor

100,000 rounds of HMAC-SHA256, about 0.5 s. Chosen by measurement: 50,000
rounds is 0.17 s and 200,000 is 0.98 s. Half a second is acceptable for a one
time unlock, and in the tests it is paid once per session.

A 10 character alphanumeric password is about 59.5 bits. For an offline
attacker holding the digest, brute force at this work factor is impractical.
**If the round count is lowered that sentence becomes false too**, and the
record must be updated.

---

### 7. Out of scope

| What | Why |
|---|---|
| A password change flow | It needs a new salt and digest written into the source, rare enough to do by hand |
| Multi user authorisation and roles | The design has a single owner; roles are a separate design |
| Protection against an attacker who edits the source | Impossible (§1) |
| Restricting the capability universally | Impossible (§1) |

---

## ADR-030: the gaps that only open once the project is shared

**Status:** Accepted · 2026-08-27

**Context.** Everything up to here was written for one machine and one author.
That assumption held quietly through twenty-nine records, and several
decisions leaned on it without ever saying so. Publishing the repository ends
it. Other people clone it, run the web interface, read the CI, and none of
them share the context that made the shortcuts safe.

So the question for this record is narrow: which parts stop being true the
moment the reader is somebody else? Three, and none of them is a break in the
cipher. They sit around it, which is the usual place.

---

### 1. The manifest was written and never read

`ccore/build.py` records the SHA-256 of the library it produced and of the
sources it produced it from. `docs/audit.md` cites that manifest as the answer
to "was this binary built from this source". The loader never opened it.

`crypto/fastpath.py` searched for `crypto25519.dll`, ran the RFC 7748
self-test and the memory test, and used whatever passed. Those tests ask
whether the library WORKS. Nothing asked where it came from.

The gap is documented rather than accidental, which is what makes it worth
recording. `.gitignore` carries this comment:

> A prebuilt .dll breaks the chain of trust.

The chain had no verifier at the end of it.

**Two things got through.**

*A library from somewhere else.* The binary is on the ignore list, so it never
travels with a clone. Whatever sits in `crypto/` on any given machine arrived
locally and nothing records how. `CRYPTO_CCORE` also points the search at any
directory on request. Loading a shared library runs its initialisation code,
so by the time a self-test could object, the library has already had control.

*A library older than its source.* This is the likelier one and it needs no
attacker. Edit `crypto25519.c`, forget to rebuild, and the old binary stays.
`EXPECTED_VERSION` does not move for an ordinary edit, so the self-test passes
and the timing numbers get credited to source that was never compiled. A
project whose entire argument is "measure it rather than claim it" was in a
position to measure the wrong artefact and not notice.

**Decision.** `_provenance()` runs before `ctypes.CDLL`, and refuses a library
that has no manifest beside it, does not match the digest in it, or was built
from a source that has since changed. A source file that is absent is skipped
rather than refused, because an installed copy without `ccore/` is a
legitimate case; a source that is present and differs is a refusal.

Refusing is not fatal. The caller drops to pure Python, which is correct and
merely unhardened. Between "slower" and "fast, and possibly not what the
source says", the choice is not close.

`CRYPTO_CCORE_UNVERIFIED=1` skips the check, for the one case that needs it:
editing the C and rebuilding in a loop, where the digests move every pass. The
condition attached to it is that `status()` announces it, because an
unverified core that looks identical to a verified one is worse than no check.

**What this is not.** It is not a signature. The manifest sits next to the
library and anyone who can replace one can replace both. It closes accident
and stale state, and it makes a substitution require a deliberate second step
instead of a file copy. Calling it tamper protection would be the same
overclaim ADR-029 §1 refused to make about the covert mode password.

---

### 2. Binding to loopback is less than it reads as

`webui.py` binds `127.0.0.1`, and that has been treated as meaning only this
machine can reach it. It does not quite mean that.

A page on the open web cannot READ a loopback response across origins. But an
attacker who resolves their own domain to 127.0.0.1 is same origin as far as
the browser is concerned, and from there `/api/key` and `/api/decrypt` answer
normally and the responses are readable. That is DNS rebinding, and the bind
address has no opinion about it. `/api/key` hands out a fresh 32 byte key on a
GET.

What still gives it away is the `Host` header, which carries the name the
browser was aimed at rather than the address it resolved to.

**Decision.** Every request is checked against `host_allowed()`, and only
`localhost`, `127.0.0.1` and `::1`, on this server's port, pass. Everything
else gets 403 before any handler runs. `tests/test_webui.py` walks the names
one by one, including the ones built to read as loopback while not being it
(`127.0.0.1.nip.io`, `localhost.evil.example.com`).

Alongside it, on every response: `Content-Security-Policy` naming `self` and
nothing else, `nosniff`, `no-referrer`, `X-Frame-Options: DENY`. The page
already pulls no outside resource, so the policy costs nothing and records
that fact where a browser will enforce it.

An unexpected exception used to be formatted into the response body. It now
goes to the operator's terminal and the client is told "internal error".
Exception text carries file paths, and sometimes pieces of the input.

The server had no tests at all before this record. It has twenty-seven now.

---

### 3. CI trusted names that their owners can move

The workflow used `actions/checkout@v4`. A tag is a name its owner can point
somewhere else, so that line meant "whatever that account publishes today".
Nothing in this repository would change if it changed.

**Decision.** The actions are pinned to commit hashes, with the release
written in a comment beside each, since a bare hash tells a reader nothing.
`persist-credentials: false` on checkout, which otherwise leaves the job token
in `.git/config` for every later step to read; nothing here pushes, so it is
not needed.

Pinning has a cost, and it is the obvious one: a pinned hash never picks up a
fix by itself. `.github/dependabot.yml` is the other half, weekly, so an
update arrives as a diff somebody reads rather than as a silent move under a
tag.

---

### 4. What stays open

The list is short and stays honest.

| Still open | Why it is left |
|---|---|
| The manifest is not signed | A signature needs a key with somewhere to live. Out of scope for a single author project, and a key beside the artefact it signs is decoration |
| `requirements.txt` has lower bounds, not pins | Hard pins on a project this size rot faster than they protect. The actions, which run with repository access, are pinned; the libraries are not |
| The web interface has no authentication | It is a local tool. The host guard is what stands in for it, and if the interface ever binds anything but loopback that is no longer enough |
| No supply chain attestation for the wheels | `pip install` from PyPI, trusted as PyPI |

None of these is a reason not to publish. They are the shape of what was
built, written down where a reader can find them.

---

## Roadmap

The table below separates what is finished, what is deferred, and what has
**not been decided**. The "not decided" rows are there on purpose: something
left out of scope looking like it was forgotten makes the list itself
misleading.

| Layer | Component | Status |
|---|---|---|
| | Corpus schema and validator | done |
| | Corpus entries (34 formulas, 6 blocks) | done |
| 1 | Engine core (encode/decode, selector, payload) | done |
| 1 | Test suite (196 tests) | done |
| 2 | Data generation pipeline (sampler, 33/34 entries) | done |
| 2 | Distinguisher model and training loop | done |
| 2 | Evaluation metrics (AUC, Wilson CI) | done |
| 2 | Experiment report (`docs/findings.md`) | done |
| 1 | Closing the length leak (ADR-007) | done |
| 3 | Chunking, BM25 search and evaluation (ADR-008) | done |
| 2 | Constraint guided sampler, 34/34 (ADR-006) | done |
| | `0x0501` Caesar retired (ADR-009) | done |
| 1 | Free text encryption (ADR-010) | done |
| 1 | Chain mode, multi formula ciphertext (ADR-011) | done |
| 1 | Random decoy chain (ADR-012) | done |
| 1 | Frame header, format v2 (ADR-013) | done |
| 1 | Replay protection (ADR-014) | done |
| 1 | Key hierarchy and forward secrecy (ADR-015) | done |
| 1 | Envelope profiles (ADR-016) | deferred, waiting on a target platform |
| 1 | X25519 four way DH handshake (ADR-017) | done |
| 2 | Experiments 1, 2 and 3 repeated on the v2 format | done |
| 2 | Collapse detection, AUC used instead of accuracy | done |
| 2 | Measuring the timing channel (ADR-018) | done |
| 1 | BitReader position dependence fixed (ADR-018) | done |
| 2 | Packet count channel (ADR-028 §3) | done, 100% unpadded, 50% padded |
| 2 | Send time channel | out of scope, the library does not send packets |
| 1 | X25519 C core and verification twin (ADR-019) | done, compiled, 0 warnings, three gates passed |
| 1 | Wipeable and locked key memory (ADR-020) | done, ephemeral key in a buffer |
| 1 | Long lived keys moved into buffers (ADR-021) | done, identity, chain, hierarchy |
| 1 | Moving SHA-256 and HMAC into C | rejected, reasoning in ADR-021 |
| | Audit package (`docs/audit.md`) | done |
| 1 | HKDF RFC 5869 vectors | done, the audit package surfaced the finding |
| 1 | Compile audit, branch sweep in the assembly (ADR-022) | done, 68/68 classified |
| 1 | Fuzzing (ADR-022) | done, 1 real finding, fixed |
| 1 | Coverage guided fuzzing (ADR-023) | done, by hand on `sys.monitoring` |
| 1 | C core coverage, gcov (ADR-024) | done, 100% and 82.26%, 4 guard lines tested |
| | Security argument (`docs/security-argument.md`) | done, an argument, not a proof |
| | Machine checked proof (EasyCrypt, ProVerif) | out of scope |
| 2 | Structural corpus generator (ADR-025) | done, 33/40 passed the exam |
| 2 | Distinguishability of the generated corpus (ADR-025) | done, 50.25%, control 100% |
| | Corpus secrecy as a security parameter | rejected, reasoning in ADR-025 |
| 1 | Canary trap and leaker identification (ADR-028 §1) | done, 100% identification on a full leak |
| 1 | Canary collusion resistance | none, but it is MEASURABLE and auditable |
| 1 | Three way collusion (Tardos, Boneh-Shaw) | out of scope, reasoning in ADR-028 §1 |
| 3 | Adding meaning to the `doc` block with a language model | not decided, cannot be verified |
| 1 | Prekey, separating the selector mask from K (ADR-026) | done, 4.62 of 5.73 bits protected |
| 2 | Derived entry generation, mathematics inherited (ADR-026) | done, 20/20 passed the exam |
| 1 | Prekey rotation | done, closed by the network epoch (ADR-027 §9) |
| 1 | Network topology, three modes (ADR-027) | done, open / restricted / covert open |
| 1 | Indistinguishability of a covert network (ADR-027) | done, 47%, control 99%, positive 100% |
| 2 | Network specific derived corpus, watermark (ADR-027) | done, deterministic and distinct per network |
| 1 | Discovering sub network labels | not decided, a naming scheme problem |
| 1 | Epoch rotation of the network root secret (ADR-027 §9) | done, calendar based, mode preserved |
| 1 | Indistinguishability of an epoch network (ADR-027 §9) | done, AUC about 0.5 |
| 1 | Forward secrecy against root compromise | not given, reasoning in ADR-027 §9 |
| | Independent code audit | needs a person |
| 1 | Timing the C core with `rdtsc` (ADR-028 §4) | done, \|t\| = 0.37, control 1337 |
| 1 | Multi block long message transport (ADR-028 §2) | done, four attacks tested |
| 1 | Sampler distribution uniformity (ADR-028 §5) | done, every unconstrained parameter is uniform |
| 1 | Mersenne Twister in the network corpus (ADR-028 §6) | done, replaced with an HKDF stream |
| 1 | `child_network` leaking the mode through timing (ADR-028 §7) | done, measured and closed |
| 1 | Covert network creation behind authorisation (ADR-029) | done, a policy gate, not a cryptographic one |
| 1 | Keeping the password out of the repo in plaintext (ADR-029 §2) | done, salted digest, scanned by a test |
| 1 | A password change flow | not decided, done by hand |
| 1 | Multi user authorisation and roles | out of scope, single owner design |
| 3 | Answer generation with a language model | not decided |
| 1 | C core provenance, manifest checked at load (ADR-030 §1) | done, refuses foreign, tampered and stale |
| 1 | Signing the build manifest | out of scope, a key needs somewhere to live |
| 1 | Host guard on the web interface (ADR-030 §2) | done, DNS rebinding closed, 27 tests |
| 1 | Security headers and error text on the web interface (ADR-030 §2) | done |
| | Authentication on the web interface | not needed, it is a loopback tool |
| | CI actions pinned to commits (ADR-030 §3) | done, Dependabot weekly |
| | Pinning the Python dependencies | not done, lower bounds kept, reasoning in ADR-030 §4 |
