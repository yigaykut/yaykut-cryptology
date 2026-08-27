# Security

## This project has not been audited

It is a research and learning project. It uses a symmetric construction
written from scratch and no independent review has been done. If you need
to protect a real secret, use an audited library: libsodium, `cryptography`
for Python, the Signal Protocol for messaging.

The repo is not a replacement for those. It exists to show how a security
claim can be measured.

---

## What is verified and what is not

Both are written down, separately:

- [`docs/audit.md`](docs/audit.md) **§4** is the verification matrix: every
  claim, how it was checked, and where.
- [`docs/audit.md`](docs/audit.md) **§5** lists the **unverified** claims.
  That section matters more than §4.
- [`docs/security-argument.md`](docs/security-argument.md) has the reduction
  argument, the assumptions and the numeric bounds. It is an argument, not
  a proof.

If you are looking for a vulnerability, start with §5. That is the list of
gaps that are already known.

### Known gaps that are not bugs

You do not need to report these. They are measured and the reasoning is
written down:

| Issue | Where |
|---|---|
| The corpus is not secret, and the formula id caps out at **16 bits** | ADR-025 |
| A covert open network is **key escrow**, which is a backdoor | ADR-027 §8 |
| The covert mode password is a policy gate, **not a cryptographic lock** | ADR-029 §1 |
| In multi block messages the length leaks at **block resolution** | ADR-028 §2-3 |
| The canary trap is **not collusion resistant**, two traitors can frame an innocent | ADR-028 §1 |
| Epoch rotation gives **no forward secrecy against root compromise** | ADR-027 §9 |
| The **length** of a member id leaks through timing | ADR-028 §8 |
| Cache timing and power analysis are out of scope | ADR-018, ADR-019 |
| There is no machine checked proof | ADR-024 |
| The build manifest is checked but **not signed**, so it stops accident and staleness, not a determined swap | ADR-030 §1 |
| The web interface has **no authentication**; the host guard stands in for it, and only because it is loopback only | ADR-030 §2 |
| The Python dependencies carry **lower bounds, not pins**. The CI actions are pinned | ADR-030 §4 |
| The PyPI wheels have **no supply chain attestation** | ADR-030 §4 |

---

## Reporting a vulnerability

If you found something that is **not** on the list above:

1. **Do not open a public issue.** Use GitHub
   [Security Advisories](https://docs.github.com/code-security/security-advisories)
   instead (repo page, *Security*, *Report a vulnerability*).
2. Say which file or function, what input, what you expected, what happened.
3. Attach a script that reproduces it if you can. The whole project is built
   on measuring rather than claiming, and a report closes much faster when it
   comes with a measurement.

This is a hobby project, so there is **no service level commitment**. No
guaranteed response time and no bounty.

---

## Tools that help when reporting

Every measurement tool in the repo ships with its own positive control, so
there is a rig ready for testing a claim:

```bash
python -m pytest tests/ -q         # 1121 tests
python corpus/validate.py          # corpus schema
python fuzz.py                     # malformed input sweep
python coverage_fuzz.py            # coverage guided fuzzing
python sidechannel.py              # timing leak sweep
python -m ccore.c_timing           # X25519 timing from inside C, via rdtsc
python -m layer2.exam              # generated entries through five gates
python -m layer2.selector_attack   # how much the prekey protects
python -m layer2.network_attack    # is a covert network distinguishable
python -m layer2.canary_experiment # does the canary find the leaker
python -m layer2.traffic           # what packet counts give away
```

> **The controls are deliberate.** Each tool has a positive control arm. If
> the rig cannot catch a deliberately planted flaw, the real result is not
> reported. Those controls caught five genuine bugs during the project. One
> was in a tool itself, another was a control arm the compiler had turned
> into constant time code.

### About the timing numbers

`sidechannel.py` and `ccore.c_timing` are noisy on shared or loaded machines,
so they are **not used as CI gates**. If you report a timing finding, include
the noise floor of your own run. An absolute `|t|` value on its own cannot be
interpreted.

---

## Supported versions

There are no release tags. Only the current tip of `main` counts. The
decision history lives in [`docs/decisions.md`](docs/decisions.md) as 29
records. Old decisions are never deleted, they get a dated amendment.
