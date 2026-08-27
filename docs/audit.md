# Audit package

**This document is not an audit.** I reviewed my own code, which is a self
assessment, not an audit. Its purpose is to make an independent audit
possible: to collect in one place what is claimed, what is verified, what is
not, and where to look.

After reading this an auditor should be able to answer "which claim do I test,
and how". If they cannot, the document is incomplete.

Last updated 2026-08-27 · 1121 tests · 30 decision records

---

## 1. Scope and threat model

### What is protected

| Asset | Against |
|---|---|
| Message content | An attacker who watches the network and records ciphertext |
| **Message metadata**, length, which formula, sequenced or not | An attacker doing traffic analysis |
| Session keys | An attacker who records traffic now and gets the key later |
| Message ordering and freshness | An attacker who replays a recorded packet |
| Long lived keys | Memory dumps, swap files, device seizure |

The **real contribution is the second row.** The encryption side is standard
primitives assembled correctly. What is original is the fixed envelope.

### Assumed attacker

- Sees the whole network, records packets, replays them, modifies them.
- Knows the entire corpus and source code (Kerckhoffs, ADR-005).
- Does not know the key.
- **Has no physical access to the device.** If that assumption is dropped, see
  section 6.

### Explicitly out of scope

- Power analysis, electromagnetic leakage, fault injection.
- Cache timing and memory access pattern attacks.
- Compromise of the endpoint itself (malware, a privileged debugger).
- Traffic timing and the packet **count** channel. The size channel is closed,
  the time channel is **open** (ADR-018).
- Key distribution and the supply chain.

---

## 2. Primitive inventory

An auditor's first question is "what did you write yourself". Here is the
answer.

| Primitive | Source | Standard | How it was verified |
|---|---|---|---|
| SHA-256 | `hashlib` (OpenSSL) | FIPS 180-4 | Not written here |
| HMAC-SHA256 | `hmac` (OpenSSL) | RFC 2104 | Not written here |
| HKDF extract/expand | **our code**, on top of `hmac` | RFC 5869 | RFC 5869 Appendix A vectors (A.1 to A.3, SHA-256) plus block boundary and domain separation tests |
| Constant time comparison | `hmac.compare_digest` | | Measured: \|t\| about 1.3 to 2.7, threshold 4.5 |
| CSPRNG | `os.urandom`; on the C path `rand_s` (Windows) or `/dev/urandom` | | Distribution and repetition tests (`test_memory.py`) |
| X25519 | **our code**, Python and C | RFC 7748 | RFC vectors (1 and 1000 iterations), 25 cross checks against `cryptography`, 50 C to Python cross checks |
| Symmetric encryption | **our own design**: HKDF stream ⊕ plaintext | | **Not** a standard AEAD, see section 6 |

**The last row is the one to look at.** The system does not use an approved
AEAD. It XORs a keystream produced by HKDF and tags it with HMAC, in
encrypt-then-MAC order. Assembled correctly this is sound, but it **has not
been scrutinised the way an AEAD has**. The recommended path for production is
to switch to ChaCha20-Poly1305, keeping the envelope layer exactly as it is.

---

## 3. Trusted computing base

Things that have to be correct for the system to be correct:

1. **The CPython interpreter and standard library**: `hashlib`, `hmac`,
   `os.urandom`, `ctypes`.
2. **OpenSSL**, for the SHA-256 and HMAC implementations.
3. **The operating system CSPRNG**: `/dev/urandom`, `RtlGenRandom`.
4. **The C compiler**, if `crypto25519.dll` was built. Whether the compiler
   "optimises" constant time code into something that is not, is **not
   verified** (section 5).
5. **The source in this repo**: one engine layer, 30 decision records.

Layer 2 (the neural network) and layer 3 (the RAG assistant) are **not in the
TCB**. They have no role in the cipher path (ADR-001), and the engine runs
unchanged if both are deleted. That is the most easily auditable property of
the architecture.

---

## 4. Verification matrix

| Claim | How it was verified | Where |
|---|---|---|
| Ciphertext length reveals nothing about content | Neural attacker: 82.6% down to **1.3%** (chance 1.9%) | `docs/findings.md`, Experiment 1 |
| Content is indistinguishable from random noise | AUC 0.478 to 0.518 over 6 runs, positive control AUC 1.0 | Experiment 2 |
| Sequenced and unsequenced packets are indistinguishable | AUC 0.496 to 0.513 over 6 runs | Experiment 3 |
| Tag comparison is constant time | Welch t, tamper at start vs at end: 1.3 to 2.7 | `sidechannel.py` |
| A decoy record's position cannot be read from timing | 32.32 down to 0.99 to 3.01 (noise floor 0.86 to 1.72) | ADR-018 |
| HKDF matches RFC 5869 | Appendix A vectors (A.1 to A.3) plus block boundary truncation tests | `test_hkdf.py` |
| X25519 matches RFC 7748 | RFC vectors, `cryptography` cross check, C to Python cross check | `test_curve.py`, `test_ccore.py` |
| The C field arithmetic does not overflow int64 | The Python twin asserts every intermediate against 2⁶³; the largest observed was 2⁶⁰·⁷¹ | `ccore/twin.py` |
| A covert network's sub network is indistinguishable from an open one's | Logistic distinguisher on 256 raw bits: **47%** [0.402 to 0.539], AUC 0.478. **Sabotage control 99%**, positive control 100% | `layer2/network_attack.py`, ADR-027 |
| A covert network really can read its sub network's traffic | End to end: a sub network member encrypts, the parent decrypts from the label alone | `test_network.py::test_covert_parent_sub_of_the_network_message_CAN_DECRYPT` |
| An open network cannot read its sub network's traffic | Same setup, every parent derivation gets a `VerificationError` | `test_network.py::test_open_parent_sub_of_the_network_message_CANNOT_DECRYPT` |
| Grandchildren are invisible, the first degree limit is structural | `child_network` always returns OPEN, so a grandchild is born from `os.urandom` | `test_network.py::test_grandchildren_is_invisible` |
| The network descriptor does not leak the mode | Fixed 38 bytes; the first 6 bytes of a covert and an open child are identical, and the mode byte reads OPEN in both | `test_network.py::test_finger_trace_mode_does_not_leak` |
| A network's own corpus is deterministic and differs between networks | Same seed gives the same watermark; a different network gives a disjoint one; derived entries round trip | `test_network.py`, `layer2/network_corpus.py` |
| Cross network mixing is stopped at the MAC, **not** by the corpus difference | Even with a shared corpus, network B cannot decrypt A's message | `test_network.py::test_another_of_the_network_message_MAC_in_fails` |
| There is no path from an epoch network back to the root secret | After the root is closed the device keeps working, and no new epoch can be produced from the root | `test_network.py::test_epoch_from_the_network_to_the_root_no_way_back` |
| An epoch network is indistinguishable from a freshly created one | Same distinguisher, third arm: 45.5 to 50.5%, AUC about 0.5 | `layer2/network_attack.py` |
| A message from one epoch cannot be decrypted in another | The prekey, member key and corpus seed all change together, giving `VerificationError` | `test_network.py::test_another_of_the_epoch_message_cannot_be_decoded` |
| X25519 shows no scalar dependent timing | `rdtsc` from inside C: \|t\| = 0.37 (2628 cycles difference out of 1.2M). **Positive control \|t\| = 1337**, noise floor 0.03 | `ccore/timing_rdtsc.c`, ADR-028 §4 |
| Sub network creation does not leak the mode through TIMING | Before the fix \|t\| = 121.5 (floor 1.9), after 0.34 to 0.57. A structural test also confirms both branches call the same primitives the same number of times | `sidechannel.py`, `test_network.py`, ADR-028 §7 |
| A lone traitor is found by the canary | Full identification of the leaking traitor in **100%** of rounds; in 25% of rounds the leaker had 84%. Negative control: with no observation nobody is suspect | `layer2/canary_experiment.py`, ADR-028 §1 |
| Multi block messages resist reorder, truncate, duplicate and splice | All four attacks tested separately; the block header is inside MAC coverage | `tests/test_longmessage.py` |
| `target_blocks` padding closes the length leak | Traffic observer: **100%** without padding, 50% with. A single frame is 50%, confirming ADR-007 | `layer2/traffic.py`, ADR-028 §3 |
| Unconstrained sampler parameters are uniformly distributed | 78 parameters, 16 of which appear in no constraint; zero found skewed. The measure itself was validated with two controls | `layer2/sampler_uniformity.py`, ADR-028 §5 |
| A covert network cannot be created without authorisation on any of the three paths | `create`, the constructor directly, and `from_descriptor` are each tested; the gate is in `__init__` | `test_network.py::test_covert_network_unauthorised_CANNOT_BE_CREATED`, ADR-029 §3 |
| Open and restricted modes need no authorisation | The gate applies only to covert mode; the other two build with authorisation off | `test_network.py::test_open_and_restricted_authorisation_DOES_NOT_NEED` |
| The password is **not** in the source tree in plaintext | Every .py, .md, .yaml, .c and .h file is scanned. It FAILED on its first run, correctly, because the password had leaked into a test parameter | `test_network.py::test_PASSWORD_SOURCE_IN_THE_TREE_PLAIN_TEXT_NOT`, ADR-029 §2 |
| Keys really are wiped from memory | Write, wipe, check for zeros, on both the C and Python sides | `test_memory.py`, `build.py` gate 4 |
| The compiler does not break constant time code | All 68 conditional branches classified, with positive and negative controls | `ccore/compile_audit.py`, `test_compile_audit.py` |
| Malformed input never escapes the exception hierarchy | 7 campaigns × 5000 rounds, with a positive control | `fuzz.py`, `test_fuzz.py` |
| Coverage guidance beats blind search | Measured at depth 3 to 5 bytes; blind search cannot even find 3 bytes in the same time | `coverage_fuzz.py`, `test_coverage_fuzz.py` |
| Every line of the C core runs | gcov: 100% and 82.26%; unreached lines are on a justified list | `ccore/c_coverage.py` |
| The MAC covers EVERY region of the envelope | A single bit flip at 9 positions, all rejected | `test_security.py` |
| Length hiding holds for every entry | 7 text lengths × 15 corpus entries, all 1339 bytes | `test_security.py` |
| Replay is rejected | Sliding window tests, including boundary cases | `test_session.py` |
| The ephemeral key dies after the handshake | Asserts `_ephemeral.closed` | `test_memory.py` |
| A chain cannot be rewound | Access to a closed chain is refused | `test_keys.py` |
| Generated corpus entries are indistinguishable from real ones | 50.25%, 95% interval [0.4679 to 0.5371]; positive control 100% | `layer2/exam.py`, gate 5 |
| The generated entry marker does not leak into the wire | The marker lives only in the `doc` block; params and constraints are scanned | `test_generator.py` |
| Output without a prekey is byte for byte identical to before | Two paths compared under the same nonce | `test_prekey.py` |
| The prekey protects the formula identity | 0 bits up to **4.62 bits** (blind is 5.73); the attack strips 1.10 bits, positive control 100% | `layer2/selector_attack.py` |
| The prekey does not weaken integrity | Tampering at 5 positions, all rejected | `test_prekey.py` |
| A C library that is foreign, tampered with, or older than its source is refused | Three refusals plus a control arm asserting the real library still loads; the order against `CDLL` is read out of the source | `test_ccore.py`, ADR-030 §1 |
| The web interface answers only to a loopback `Host` | 7 names accepted, 10 refused, including ones shaped to read as loopback (`127.0.0.1.nip.io`, `localhost.evil.example.com`); GET and POST both | `test_webui.py`, ADR-030 §2 |
| An unexpected server error does not describe itself to the client | The body carries no traceback and no path from this machine | `test_webui.py` |

**Test distribution** (1121 tests):

```
test_engine.py      300   test_network.py    85   test_render.py         70
test_canary.py       50   test_layer3.py     46   test_ccore.py          45
test_hidden.py       38   test_generator.py  35   test_memory.py         33
test_session.py      32   test_security.py   32   test_chain.py          31
test_handshake.py    29   test_app.py        29   test_layer2.py         28
test_webui.py        27   test_longmessage.py 24  test_fuzz.py           24
test_timing.py       23   test_prekey.py     23   test_keys.py           23
test_message.py      22   test_curve.py      22   test_hkdf.py           16
test_coverage_fuzz.py 14  test_compile_audit.py 8 test_traffic.py         6
test_sampler_uniformity.py 6
```

---

## 5. UNVERIFIED claims

This is the most important section. The table above says what was tested; this
one says what was **not**.

| What | Status | Why it matters |
|---|---|---|
| ~~HKDF was not tested against RFC 5869 vectors~~ | **CLOSED 2026-08-19** | Noticed while writing this document and closed the same day: `tests/test_hkdf.py`, 16 tests, passed first try. The first place the document earned its keep. |
| ~~Whether the compiler breaks constant time code~~ | **CLOSED 2026-08-19** | `ccore/compile_audit.py`: all 68 conditional branches classified, no data dependent branch, `crypto_wipe` not elided. Remaining caveat: `cmov` is a microarchitectural observation, not an architectural guarantee (ADR-022). |
| ~~The C core's timing advantage~~ | **CLOSED 2026-08-23** | `ccore/timing_rdtsc.c`, measuring with `rdtsc` from inside C. X25519 shows no scalar dependent timing (\|t\| = 0.37), and the positive control passes at \|t\| = 1337. TWO bugs in the rig showed up first: measurement order bias, and the compiler turning the positive control into constant time code (ADR-028 §4). |
| **AEAD security of the symmetric construction** | **PARTIAL**, 2026-08-20 | `docs/security-argument.md` has the reduction argument, the assumptions and the numeric bounds, and 32 tests confirm the document's testable claims. **There is still no machine checked proof.** |
| The scheme rests on a **dual PRF** assumption | **Open, documented** | `PRK = HMAC(key=nonce, message=K)`: HMAC has to be a PRF when keyed through its second argument too. TLS 1.3 rests on the same thing, but it is stronger than plain PRF (ADR-024). |
| Machine checked proof (EasyCrypt, ProVerif) | **None** | Needs a separate toolchain and expertise. Out of scope. |
| ~~Uniformity of the corpus sampler~~ | **CLOSED 2026-08-23** | `layer2/sampler_uniformity.py`: all 16 parameters that appear in no constraint are uniform. The measurement's FIRST PREMISE WAS WRONG and produced 17 false findings, because a variable coupled through a constraint has no obligation to be marginally uniform (ADR-028 §5). 16 entries hit the time budget and are reported as "could not measure". |
| **Coverage of the side channel sweep** | **EXTENDED 2026-08-23, still partial** | The network layer was added and **found a real leak**: `child_network` was leaking the mode through timing (\|t\| = 121.5). Fixed (ADR-028 §7). The engine is still not covered end to end, and a path that was not measured is not known to be clean. |
| **Corpus secrecy as a security parameter** | **REJECTED 2026-08-21** | Proposed, then rejected on measurement. The selector is 2 bytes, so the ceiling is **16 bits** against a 256 bit key. Also, a network member already has the corpus, so it does nothing against an insider. The real entropy is the generator's seed, not the size of the corpus (ADR-025). |
| MATHEMATICAL correctness of generated entries | **None, and it cannot be automated** | The generator produces structure, not mathematics. The `doc` block is a deliberate seam. Even with a language model attached, nobody can audit the correctness of 10,000 generated formulas (ADR-025). |
| **Independence of the prekey from K** | **A commitment, not a check** | `Engine` only rejects the case P == K. If P were derived from K with HKDF the check would not catch it. Independence is something you commit to, not something you can enforce (ADR-026). |
| ~~Prekey rotation~~ | **CLOSED 2026-08-22** | Closed by the network epoch (ADR-027 §9): P now derives from S, S rotates, so P rotates. |
| **Discovering sub network labels** | **None, and cryptography cannot close it** | A covert network owner can only derive a sub network whose LABEL they know. In practice they know it, because they shipped the client that follows the counter scheme, but a member who modifies their client drops out of view. This is a naming scheme problem (ADR-027 §5). |
| **Whether covert mode can COLLECT traffic** | Out of scope | A covert open network is a READ capability. Obtaining the ciphertext is a separate job that this system does not do, and the capability is useless if the traffic cannot be captured. |
| **Forward secrecy against root compromise** | **NONE, and not offered** | Epoch rotation (ADR-027 §9) gives compartmentalisation in time: if a device falls, only that epoch opens. But whoever gets S computes EVERY epoch. The only thing protecting the root is never putting it on a device, which is an operational decision, not a mechanism. |
| Archived traffic conflicts with forward secrecy | **Open, deliberate** | If you delete the root for forward secrecy, your own archive becomes unreadable too, since the epoch corpus also derives from S. That is what forward secrecy means, written down so it is not a surprise. |
| ~~The network corpus is generated with `random.Random`~~ | **CLOSED 2026-08-23** | The problem was removed rather than justified: `HkdfGenerator` keeps the `random.Random` interface but takes its entropy from an HKDF stream. The old rationale was correct but answered the wrong question, since the root secret was protected while the generator itself was not (ADR-028 §6). |
| **Canary collusion resistance** | **NONE, but measurable and auditable** | Two traitors can frame an innocent. On default settings the worst pair can target 1 to 2 innocents; `build_safe` scans it down to zero, and `possible_framers` tests whether an accusation could have been fabricated. A three way collusion is invisible to all of it, which would need Tardos or Boneh-Shaw codes (ADR-028 §1). |
| **Length leak in multi block messages** | **PRESENT, measured, partly closable** | The block count gives away the length at block resolution (1000 bytes), and a traffic observer separates the classes **100%** of the time on an unpadded message. `target_blocks` padding brings that down to chance but costs bandwidth. ADR-007's single frame guarantee does NOT hold across multiple blocks (ADR-028 §2-3). |
| Member id length leaks through timing | **Open, accepted** | HMAC scales with input length, so a 1 versus 200 character id gives \|t\| about 27. What leaks is not a secret but the LENGTH OF A LABEL, and member names are not treated as secret. A caller who wants equal lengths should pad the ids. |
| The send time channel | **Not measurable here, out of scope** | This library does not send packets. Inter packet delay is a property of the application and the network. If a transport layer is written, it should be measured there. |
| **Cryptographic value of the covert mode gate** | **NONE, and there cannot be any** | Anyone with the source deletes the check. More fundamentally the capability cannot be restricted at all: covert mode amounts to "I derive the sub network's secret from my own secret", and anyone with their own secret does that in their own code. The gate restricts the behaviour of THIS PROGRAM. Its real gain is that the password is not sitting in the repo in plaintext (ADR-029 §1-2). |
| Covert mode tests SKIP without the password | **Open, deliberate** | The password is not in the repo, so the tests read it from an environment variable and skip when it is missing. `skip` was chosen over `xfail` because pytest counts skips separately and they do not show up as quietly green. Even so, a run without the password has NO covert mode coverage. |
| Independent code audit | **None** | |
| ~~No fuzzing~~ | **CLOSED 2026-08-19** | `fuzz.py`, 7 campaigns, with a positive control. **One real finding:** the constraint evaluator was leaking `ValueError` outside the hierarchy. Fixed (ADR-022). |
| ~~No coverage guided fuzzing~~ | **CLOSED 2026-08-20** | `coverage_fuzz.py`, written by hand on `sys.monitoring` because Atheris does not run on Windows. With a positive control: it crosses a 2^40 search space in 20 seconds (ADR-023). |
| ~~The INSIDE of the C core is not observed~~ | **CLOSED 2026-08-20** | `ccore/c_coverage.py` with gcov: `crypto25519.c` 100% of lines, `safe.c` 82.26%. Four guard lines that had never run were found and tested; the remaining 11 are on a justified UNREACHABLE list (ADR-024). |
| Coverage is not measured at path level | **Open** | It is measured at branch level, so two different paths crossing the same set of branches are indistinguishable. |
| ~~The build manifest is written and never read~~ | **CLOSED 2026-08-27** | The loader now checks it before `ctypes.CDLL` and refuses a foreign, tampered or stale library (ADR-030 §1). The case that mattered was staleness: an edit to `crypto25519.c` without a rebuild credited every timing number to source that was never compiled, and nothing in the project could see it. |
| **The manifest is not signed** | **Open, bounded** | It sits beside the library, so whoever can replace one can replace both. It closes accident and staleness and makes a swap a deliberate second step. It is not tamper protection and is not described as any (ADR-030 §1). |
| ~~The web interface trusts the bind address alone~~ | **CLOSED 2026-08-27** | Loopback binding does not stop DNS rebinding: an attacker's domain pointed at 127.0.0.1 is same origin, and `/api/key` answers a GET. A `Host` check now runs before every handler (ADR-030 §2). |
| **The web interface has no authentication** | **Open, deliberate** | It is a local tool. The host guard stands in for authentication and only works because the server is loopback only. If it ever binds anything else, this line stops being true. |
| **The Python dependencies are not pinned** | **Open, deliberate** | `requirements.txt` carries lower bounds. Hard pins on a project this size go stale faster than they protect. The CI actions, which run with repository access, ARE pinned to commits (ADR-030 §3-4). |
| No supply chain attestation for the wheels | **Open** | `pip install` from PyPI, trusted as PyPI. Nothing here verifies a wheel's provenance. |

---

## 6. Where an auditor should look

If I were attacking my own code, these are the places I would go, in order:

1. **`crypto/primitives.py`, `subkeys`.** Three subkeys come out of a single
   HKDF call, separated by domain labels. Is the label separation correct, is
   the nonce genuinely fresh on every call, does `payload_len` reach the stream
   correctly. A nonce repeat here collapses the whole system.

2. **`crypto/wire.py`, `_open` and `_split`.** The claim that not one byte is
   interpreted before the tag is verified. Get the order wrong and a padding
   oracle class attack opens up (Vaudenay, Lucky13).

3. **`crypto/bitio.py`, `BitReader.read_int`.** The ADR-018 timing leak was
   here. It is fixed, but if the arithmetic at field boundaries is wrong the
   fields bleed into each other.

4. **`ccore/crypto25519.c`, `fe_carry` and `fe_tobytes`.** The claim that carry
   converges in three passes, and the direction of the conditional subtraction.
   The twin tests this in Python, but the C side **assumes** that arithmetic
   right shift is signed (there is a check for that inside the test).

5. **`crypto/session.py`, `ReplayWindow`.** Rejected sequence numbers are **not
   recorded** in the window. If they were, an attacker could push the window
   forward and drop legitimate packets. Is that subtlety right.

6. **`crypto/handshake.py`, `_derive`.** The order of the four DH operations
   and the contents of the HKDF salt (the four public keys). The order depends
   on the role, so if the two sides compute different orders the keys do not
   match, or worse, the identity binding weakens.

---

## 7. Reproduction

```bash
python -m pytest tests/ -q          # 1121 tests
python corpus/validate.py           # corpus consistency
python experiments.py               # layer 2 experiments (slow)
python sidechannel.py               # timing sweep
python ccore/build.py               # C core: build, 4 gates, manifest
python ccore/compile_audit.py       # branch sweep in the assembly
python fuzz.py 5000 <seed>          # fuzzing, long run
python coverage_fuzz.py 240 <seed>  # coverage guided fuzzing
python ccore/c_coverage.py          # C core coverage (gcov)
```

At the end `build.py` writes `crypto/crypto25519.manifest.json`:

```json
{
  "library_sha256": "…",
  "source_sha256": { "crypto25519.c": "…", "safe.c": "…" },
  "compiler": "gcc (MinGW-W64 …) 16.1.0",
  "platform": "…",
  "api_version": 2
}
```

**The loader reads this back** (ADR-030 §1). `crypto/fastpath.py` refuses a
library that has no manifest beside it, does not match `library_sha256`, or
was built from a source whose digest has since moved. The check runs before
`ctypes.CDLL`, since opening a shared library already runs code from it. A
refusal is not fatal: the pure Python path takes over. Until ADR-030 the
manifest was written and never read, so this section described a chain of
trust with nothing at the end of it.

**It is not a signature.** The manifest sits beside the library, and anyone
able to replace one can replace both. It closes accident and staleness, and it
turns a substitution into a deliberate second step. That is all it claims.

**This is not a reproducible build.** The same source through the same compiler
may not produce a byte identical binary, because of build paths and timestamps.
The manifest answers "from which source, with which compiler, on which
platform", not "is it the same". Real reproducibility is a separate job and it
was not done.

---

## 8. Change history

When a claim in this document changes, the old one is **not deleted**, a dated
amendment is added. The same rule applies to `docs/findings.md` and
`docs/decisions.md`, and two dated amendments already sit there (the model
collapse and the noise floor of the timing measurement).

**2026-08-21.** Treating corpus secrecy as a security parameter was proposed,
measured, and rejected, then added to §5 as a rejected claim (ADR-025). The
same round added `layer2/generator.py` and `layer2/exam.py`, and the exam's own
positive control found a bug in the exam itself, a reversed reading of
`analyze_params`'s return order. Fixed.

**2026-08-22.** The prekey was added (ADR-026): the selector mask can
optionally derive from an independent secret. The scheme definition in §1 and
`docs/security-argument.md` §1.1 were updated. The amount of protection was
MEASURED (`layer2/selector_attack.py`) at 4.62 out of 5.73 bits. The same round
added derived entry generation, where the mathematics is inherited rather than
generated.

**2026-08-22 (second round).** Network topology was added (ADR-027): open,
restricted and covert open modes. Covert mode is **key escrow** and was written
into §5 under that name. Its indistinguishability was MEASURED
(`layer2/network_attack.py`) with the real arm at 47% [0.402 to 0.539].

On the measurement's first run the **sabotage control arm failed at 57%** and
showed two separate defects at once: the sabotage signal had a theoretical
ceiling of 75%, and the logistic regression was not converging. Both were
fixed. Without the control arm, the 47% on the real arm would have been
reported as "indistinguishable", a correct number with no evidence behind it.

The same round fixed a silent loss of diagnostics in `tests/test_ccore.py`. The
subprocess output was being decoded as UTF-8, and when the machine's path
contained a non ASCII letter the reader thread died quietly and emptied the
diagnostic output (`errors="replace"`).

**2026-08-22 (third round).** Epoch rotation of the network root secret was
added (ADR-027 §9): `S_d = HKDF(S, "donem" ‖ d)`, numbered from the calendar,
preserving the mode. The §5 item "no rotation of the network root secret" is
closed, and in its place it now says explicitly that **no forward secrecy
against root compromise** is offered. What is not given needed to be written
down too.

The same round found TWO MEASUREMENT GATES bound to the wrong measure, and
fixed both (ADR-027 §10). The control arm moved from accuracy to **AUC**, and
the chance arms moved from a 95% confidence interval to a **±3 sd band**. The
second was a category error: a test at α=0.05 fails on 5% of runs even when the
null hypothesis is true, and it duly did. The 95% interval stays in the report
as it was.

**2026-08-23.** The open items on the roadmap and in §5 were handled in one
round (ADR-028). Closed: the canary trap mechanism, long multi block messages,
traffic analysis, `rdtsc` measurement from inside C, sampler uniformity, and
the Mersenne Twister in the network corpus.

**That round surfaced THREE REAL DEFECTS, all three caught by the tools' own
controls:**

1. `child_network` was leaking covert mode through TIMING (\|t\| = 121.5, noise
   floor 1.9). ADR-027's indistinguishability measurement was looking at bytes;
   this appeared once the side channel sweep was extended to the network layer.
   Fixed.

2. The sampler measurement's PREMISE was wrong and produced 17 false findings.
   A variable coupled through a constraint has no obligation to be marginally
   uniform.

3. The `rdtsc` rig's positive control produced no signal because the compiler
   had turned it into constant time code, which is ADR-022 confirmed from the
   other direction.

Also, the canary experiment's RANDOM pair sampling was understating collusion
risk, so the worst pair was added as its own arm.

**2026-08-25.** Creating a covert open network was put behind a password
(ADR-029). What goes at the top of that record matters more than its outcome:
**this is not a cryptographic lock and cannot be one.** Anyone with the source
deletes the check, and since covert mode amounts to deriving from your own
secret, the capability cannot be restricted universally. The gate's real gain is
that the password is not sitting in the repo in plaintext, so publishing the
repo does not burn it.

`test_PASSWORD_SOURCE_IN_THE_TREE_PLAIN_TEXT_NOT` **failed on its first run, and it
was right**. I had written the password as a substring into the wrong-password
test's parameter list. The variants are now derived at runtime.

**2026-08-27.** The assumption that this project runs on one machine for one
author was retired, because publishing ends it (ADR-030). Three gaps around the
cipher rather than in it were closed.

The build manifest was written by `ccore/build.py` and read by nothing. §7 of
this document cited it as the answer to "was this binary built from this
source", and the loader never opened it. `crypto/fastpath.py` now checks it
before `ctypes.CDLL`, and refuses a library with no manifest, a wrong digest,
or a source that has moved since the build. The stale case is the one that
mattered: an edit to `crypto25519.c` without a rebuild left every timing number
credited to source that was never compiled, and nothing in the project could
see it. Seven tests hold it, including a control arm asserting the real library
still passes.

The web interface bound to loopback, which reads as stronger than it is. DNS
rebinding makes an attacker's page same origin with a loopback server, and
`/api/key` hands out a key on a GET. A `Host` check now runs before every
handler. The server had no tests at all; it has 27.

The CI used `actions/checkout@v4`, a name its owner can move. The actions are
pinned to commit hashes with Dependabot to move them in a reviewable diff.

None of this touches the cipher, the wire format or key derivation, and no
claim in §4 changed as a result. What changed is the number of them that rest
on something checked. Four new entries went into §5 and into `SECURITY.md`: the
manifest is not signed, the interface has no authentication, the Python
dependencies are not pinned, and the wheels carry no attestation.
