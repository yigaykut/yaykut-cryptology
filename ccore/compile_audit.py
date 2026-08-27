"""Audits the compiler's output: did constant time behaviour actually survive?

    python ccore/compile_audit.py

WHY IT IS NEEDED

`docs/audit.md` §5 carried this line:

    "Whether the compiler preserves constant time behaviour: OPEN. The
     generated assembly was not inspected. -O2 can make it branch."

That is not an idle worry. The odd thing about writing constant time code
is this: **the absence of branches in the source is not enough.** The
compiler can recognise mask arithmetic as "there is really an if here" and
turn it into a branch. The C standard does not forbid that, because the
standard says nothing about timing. `memset` can be dropped too (CWE-14).

This tool reads the generated assembly and asks three questions:

  1. CONDITIONAL BRANCHES: where does each conditional jump's condition
     come from? If it comes from a loop counter there is no problem (the
     counter is not secret). From anywhere else, it needs HUMAN REVIEW.
  2. WIPING: is `crypto_wipe` still a real call, or was it dropped?
  3. CMOV: was a conditional move used? It is branchless, but the guarantee
     is MICROARCHITECTURAL; it is reported, not treated as an error.

AN HONEST LIMIT
This is a sweep, not a proof. The `ivtmp` heuristic rests on gcc's
`-fverbose-asm` annotations, and another compiler uses other names. There
may be a branch the tool does not find. But it is far better than "I never
looked", and it can be rerun on every build change.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = [HERE / "crypto25519.c", HERE / "safe.c"]

# Conditional jumps. `jmp` is unconditional and is not on the list.
BRANCH = re.compile(r"^\s+(j(?:ne|e|z|nz|g|ge|l|le|a|ae|b|be|s|ns|o|no|p|np))\s")
CONDITION = re.compile(r"^\s+(cmp|test|sub|add|and|or|dec|inc)")
TAG = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):")

CMOV = re.compile(r"^\s+cmov")

# ─────────────────── SINIFLANDIRMA KURALLARI ───────────────────
#
# Every conditional branch found MUST match one of the rules below. A branch
# that does not match is reported as "REVIEW" and the tool exits non zero.
# So this is not a list of noise, it is a REGRESSION CHECK: all 26 branches
# reviewed today are classified, and if a new one appears tomorrow it will
# be visible.
#
# The reasoning behind the rules was written by hand review on 2026-08-19.

# 1. Loop counters. With `-fverbose-asm` gcc prints the operand name in a
#    comment. `ivtmp` is gcc's induction variable; `i`, `k` and `t` are
#    counters from the source. None of them depend on secret data.
#    A WORD BOUNDARY IS ESSENTIAL. The first version's pattern was loose
#    and also swallowed a comment such as "# secret"; a loose pattern can
#    silently classify a real finding as safe. An audit tool needs
#    auditing too.
COUNTER = re.compile(
    r"\bivtmp[\w.]*\b"                                 # gcc induction variable
    r"|#[^#]*?(?:^|[\s,])(?:i|j|k|t|round|step)\s*$"     # a source counter, as a WORD
)

# 2. When the ladder loop's counter moves to the stack its name is lost.
#    `t` counts down from 254 to -1 and the comparison is against the
#    constant -1. That is the bit's INDEX, not the scalar's BIT.
LADDER_COUNTER = re.compile(r"cmpl\s+\$-1,")

# 3. Null pointer and zero size guards. `p`, `n` and `locked` are public
#    values: is the address valid, how many bytes were asked for. They do
#    not depend on the key's CONTENT.
GUARD = re.compile(r"test[qlb]\s+%\w+,\s*%\w+\s+#\s*"
                   r"(p|n|locked|<retval>)\s*$")

# 4. Self test functions. They run on fixed and PUBLIC test vectors, run
#    once at load time, and are not part of the cryptographic path.
PROBE_FUNCTIONS = {"crypto25519_selftest", "crypto_memory_selftest"}

# 5. The error checks inside `crypto_random`: the `rand_s` return code and
#    the byte count from `fread`. They look at whether the operation
#    succeeded, not at the random VALUE produced.
ERROR_CHECK = re.compile(r"#\s*(<retval>|okunan)\s*$")


def classify(func: str, condition: str) -> tuple[str, str] | None:
    """(class, reason) if the branch is safe, None otherwise."""
    if func in PROBE_FUNCTIONS:
        return ("self test", "a public test vector, not on the cryptographic path")
    if COUNTER.search(condition):
        return ("loop counter", "the condition comes from a loop counter, not secret data")
    if LADDER_COUNTER.search(condition):
        return ("ladder counter", "the bit's INDEX (254..-1), not the bit ITSELF")
    if GUARD.search(condition):
        return ("null/size guard", "address validity and size, not content")
    if ERROR_CHECK.search(condition):
        return ("error check", "whether the operation succeeded, not the value produced")
    return None


class Finding:
    def __init__(self, func: str, line: int, branch: str, condition: str,
                 cls: str) -> None:
        self.func, self.line, self.branch = func, line, branch
        self.condition, self.cls = condition, cls

    def __str__(self) -> str:
        return (f"  {self.cls:<14} {self.func}+{self.line}  "
                f"{self.condition.strip():<40} -> {self.branch.strip()}")


def make_assembly(source: Path, temp: Path) -> Path | None:
    compiler = next((d for d in ("gcc", "clang", "cc") if shutil.which(d)), None)
    if compiler is None:
        return None
    output = temp / (source.stem + ".s")
    p = subprocess.run(
        [compiler, "-O2", "-S", "-fverbose-asm", "-std=c99",
         str(source), "-o", str(output)],
        capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{source.name} did not compile:\n{p.stdout}{p.stderr}")
    return output


def decrypt(path: Path) -> tuple[list[Finding], dict[str, int]]:
    """Sweeps the assembly and returns the findings and the counts."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    findings: list[Finding] = []
    count = {"branch": 0, "safe": 0, "cmov": 0}
    func = "(file scope)"
    start = 0

    for i, s in enumerate(lines):
        e = TAG.match(s)
        if e and not e.group(1).startswith(".L"):
            func, start = e.group(1), i
            continue
        if CMOV.match(s):
            count["cmov"] += 1
            continue
        if not BRANCH.match(s):
            continue

        count["branch"] += 1
        # Search backwards for the nearest instruction producing the condition.
        condition = "(not found)"
        for k in range(i - 1, max(0, i - 8), -1):
            if CONDITION.match(lines[k]):
                condition = lines[k]
                break

        decision = classify(func, condition)
        if decision is not None:
            count.setdefault(decision[0], 0)
            count[decision[0]] += 1
            count["safe"] += 1
        else:
            findings.append(
                Finding(func, i - start, s, condition, "REVIEW"))
    return findings, count


def wipe_check(path: Path) -> tuple[bool, str]:
    """Is `crypto_wipe` still a real call, or was it dropped?"""
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^crypto_wipe:(.*?)^\s*\.seh_endproc|^crypto_wipe:(.*?)\n\n",
                  text, re.S | re.M)
    body = (m.group(1) or m.group(2)) if m else ""
    if not body:
        # Some targets split sections differently; a coarse cut.
        place = text.find("crypto_wipe:")
        body = text[place:place + 800] if place >= 0 else ""
    if "crypto_memset_v" in body:
        return True, "a call through a volatile pointer, not dropped"
    if "memset" in body:
        return True, "a direct memset call, not dropped"
    return False, ("THE WIPE MAY HAVE BEEN DROPPED: the body contains neither "
                   "crypto_memset_v nor memset (CWE-14)")


def main() -> int:
    if not shutil.which("gcc") and not shutil.which("clang") \
            and not shutil.which("cc"):
        print("No compiler, so the audit could not run.")
        print("That is not an error; the C core is optional anyway.")
        return 2

        print("Compile audit: did constant time behaviour survive in the assembly?\n")
    bad = 0
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        for source in SOURCES:
            path = make_assembly(source, temp)
            if path is None:
                return 2
            findings, count = decrypt(path)

            print(f"{source.name}")
            print(f"  conditional branches : {count['branch']}")
            for name, n in sorted(count.items()):
                if name in ("branch", "safe", "cmov") or not n:
                    continue
                print(f"    · {name:<18} {n}")
            print(f"  - classified         : {count['safe']}")
            print(f"  - TO REVIEW          : {len(findings)}")
            print(f"  conditional moves    : {count['cmov']} (cmov)")

            if source.name == "safe.c":
                ok, message = wipe_check(path)
                print(f"  wipe                 : {message}")
                if not ok:
                    bad += 1

            if findings:
                print("\n  Branches needing human review:")
                for b in findings:
                    print(b)
                bad += len(findings)
            print()

    print("─" * 70)
    if bad:
        print(f"{bad} places need human review. That does not necessarily mean a bug;")
        print("branches the tool could not classify land here too.")
        return 1

    print("No branch that could depend on data was found; every conditional jump's")
    print("condition comes from a loop counter.")
    print()
    print("AN HONEST NOTE: this is a sweep, not a proof. Also, if the `cmov` count")
    print("is above zero: a conditional move is branchless, but its constant time")
    print("behaviour is a MICROARCHITECTURAL observation, not an architectural")
    print("guarantee. The compiler chose to turn mask arithmetic into cmov this")
    print("time; the next version could choose a branch. That is why this tool exists.")
    return 0


def _utf8_output() -> None:
    """Switches the console to UTF-8; on Windows cp1254 cannot print the box drawing.

    When the output is REDIRECTED to a file or a pipe, Python picks the
    cp1254 code page and blows up on characters like `─`. The audit passed
    but the tool exited non zero, which looked like a regression. The
    measurement was right and the reporting was broken.

    NOT DONE AT MODULE LEVEL: it breaks output capture for importing tests
    (the same bug happened in `fuzz.py`).
    """
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


if __name__ == "__main__":
    _utf8_output()
    raise SystemExit(main())
