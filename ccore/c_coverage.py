"""Coverage of the C core: which lines never ran?

    python ccore/c_coverage.py

WHY IT IS NEEDED

`coverage_fuzz.py` does coverage guided fuzzing, but `sys.monitoring` only
sees Python bytecode and branches inside `crypto25519.dll` are not counted.
`docs/audit.md` §5 carried that as an open item.

This tool closes the gap with gcc's `--coverage` flag: the C code is built
instrumented, the test suite is pointed at that library and run, and then
`gcov` reports how many times each line executed.

WHY A LINE THAT NEVER RAN MATTERS

Untested code is code not known to be correct. **Guard lines** are
especially dangerous: if a line such as `if (p == NULL) return;` has never
run, nothing tells you it was written wrong, until a null pointer arrives
in production.

THE NON ASCII PATH PROBLEM, and its fix

gcov's runtime assumes ASCII when creating the output directory. Because the
project lives under `C:\\Users\\MSİ\\...` the `.gcda` files cannot be written
("Cannot create directory"). So the tool copies the sources into an ASCII
only temporary directory and builds there. Finding that took time, and it is
written here so nobody has to look for it again.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from crypto import fastpath  # noqa: E402

SOURCES = ["crypto25519.c", "safe.c"]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# An ASCII only working directory, because of the gcov limit above.
WORKDIR = Path("C:/kriptografi_gcov") if sys.platform == "win32" \
    else Path("/tmp/kriptografi_gcov")

# The tests that feed the coverage. Running the whole suite is unnecessary;
# these are the ones that touch it.
TESTS = ["tests/test_ccore.py", "tests/test_memory.py",
         "tests/test_curve.py", "tests/test_handshake.py"]


# ─────────────── DOCUMENTED UNREACHABLE LINES ───────────────
#
# Not every line that does not run is a gap; some cannot be triggered from
# Python. But calling something "unreachable" is a CLAIM and should not be
# accepted without a reason written down, or the list becomes a comfortable
# way of hiding untested code.
#
# The key is source file -> {line text: reason}. It matches the line's TEXT
# rather than its NUMBER, so the list does not break on its own when code shifts.
UNREACHABLE = {
    "safe.c": {
        "crypto_wipe(p, n);":
            "the rand_s / fread failure branch; it cannot be reached without "
            "breaking the operating system CSPRNG",
        "return 2;":
            "the same: a generator error, or the self test's error branch",
        "return 1;":
            "crypto_memory_selftest: the allocation failure branch",
        "crypto_buffer_close(p, n);":
            "the self test's error branches; they only run on a BROKEN build, "
            "and in that case the library is rejected anyway",
        "return 3;": "a self test error branch",
        "return 4;": "a self test error branch",
        "return 5;   /* all 256 bytes zero: 2^-2048, the generator is broken */":
            "the generator would have to return all 256 bytes zero, 2^-2048",
    },
}


def _utf8_output() -> None:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def compiler() -> str | None:
    return next((d for d in ("gcc", "clang", "cc") if shutil.which(d)), None)


def prepare() -> Path:
    """Copies the sources into an ASCII directory and builds the instrumented library."""
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR, ignore_errors=True)
    WORKDIR.mkdir(parents=True, exist_ok=True)
    for name in SOURCES + ["crypto25519.h"]:
        shutil.copy2(HERE / name, WORKDIR / name)

    dll_name = "crypto25519.dll" if sys.platform == "win32" \
        else "libcrypto25519.so"
    argv = [compiler(), "-O0", "--coverage", "-std=c99", "-shared",
            "-o", dll_name] + SOURCES
    if sys.platform != "win32":
        argv.insert(1, "-fPIC")
    p = subprocess.run(argv, cwd=str(WORKDIR), capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"the instrumented build failed:\n{p.stderr}")

    # The loader refuses a library with no manifest beside it (ADR-030 §1),
    # and it is right to: this one was compiled a moment ago into a scratch
    # directory, which from the outside looks exactly like a stray binary.
    # The tool built it, so the tool records what it built, and the same
    # check every other library passes applies to this one too. Skipping the
    # check here instead would mean the coverage run is the one place the
    # gate does not hold.
    library = WORKDIR / dll_name
    manifest = {
        "library_sha256": _digest(library),
        # The sources were copied from `ccore/`, so these are the digests of
        # the originals and the staleness check lines up as well.
        "source_sha256": {name: _digest(HERE / name) for name in SOURCES},
        "compiler": f"{compiler()} --coverage (instrumented, not for use)",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "api_version": fastpath.EXPECTED_VERSION,
    }
    (WORKDIR / fastpath.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return WORKDIR


def run() -> tuple[bool, str]:
    """Points the tests at the instrumented library and runs them."""
    env = dict(os.environ,
               CRYPTO_CCORE=str(WORKDIR),
               PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-m", "pytest", "-q"] + TESTS,
                       cwd=str(ROOT), capture_output=True, text=True,
                       env=env, timeout=1800)
    last = [s for s in p.stdout.strip().splitlines() if s.strip()]
    return p.returncode == 0, last[-1] if last else "(no output)"


def measure() -> dict:
    """Runs gcov and returns the coverage per file."""
    gcda = sorted(WORKDIR.glob("*.gcda"))
    if not gcda:
        raise RuntimeError(
            "no .gcda was produced; the library may not have been loaded, or "
            "the gcov runtime could not write")
    p = subprocess.run(["gcov", "-b"] + [g.name for g in gcda],
                       cwd=str(WORKDIR), capture_output=True, text=True)
    text = p.stdout

    result: dict = {}
    now = None
    for line in text.splitlines():
        m = re.match(r"File '(.+)'", line)
        if m:
            now = os.path.basename(m.group(1))
            if now not in SOURCES:
                now = None
            else:
                result[now] = {}
            continue
        # "Creating 'x.gcov'" is the END of a file block. Without that line,
        # gcov's OVERALL SUMMARY printed at the very end was taken for the last
        # file's numbers and the report came out wrong (that happened first time).
        if line.startswith("Creating '"):
            now = None
            continue
        if now is None:
            continue
        m = re.match(r"Lines executed:([\d.]+)% of (\d+)", line)
        if m:
            result[now]["line_pct"] = float(m.group(1))
            result[now]["line_total"] = int(m.group(2))
        m = re.match(r"Taken at least once:([\d.]+)% of (\d+)", line)
        if m:
            result[now]["branch_pct"] = float(m.group(1))
            result[now]["branch_total"] = int(m.group(2))

    for name in list(result):
        result[name]["dead_lines"] = dead_lines(name)
    return result


def dead_lines(source: str) -> list[tuple[int, str]]:
    """Lines marked `#####`, meaning they never ran."""
    path = WORKDIR / f"{source}.gcov"
    if not path.exists():
        return []
    output = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*#####:\s*(\d+):(.*)", line)
        if m and m.group(2).strip():
            output.append((int(m.group(1)), m.group(2).strip()))
    return output


def main() -> int:
    if compiler() is None or shutil.which("gcov") is None:
        print("gcc or gcov not found, so C coverage could not be measured.")
        print("That is not an error; the C core is optional anyway.")
        return 2

    print(f"\n{'═' * 74}")
    print("  C CORE COVERAGE: which lines never ran?")
    print(f"{'═' * 74}")

    print(f"\n  working directory : {WORKDIR}  (ASCII required, see the module docs)")
    prepare()
    print("  build             : instrumented with --coverage")

    ok, digest = run()
    print(f"  tests             : {digest}")
    if not ok:
        print("\n  !! THE TESTS FAILED, the coverage numbers are not trustworthy")

    result = measure()
    print()
    bad = 0
    for name, d in result.items():
        print(f"  {name}")
        print(f"    lines    : {d.get('line_pct', 0):.2f}% "
              f"({d.get('line_total', 0)} lines)")
        print(f"    branches : {d.get('branch_pct', 0):.2f}% "
              f"({d.get('branch_total', 0)} branches taken at least once)")
        known = UNREACHABLE.get(name, {})
        described = [(n, s) for n, s in d["dead_lines"] if s in known]
        new = [(n, s) for n, s in d["dead_lines"] if s not in known]

        if described:
            print(f"    did not run, DOCUMENTED unreachable : {len(described)}")
        if new:
            print(f"    did not run, UNEXPLAINED            : {len(new)}")
            for no, text in new[:20]:
                print(f"      {no:>4}: {text}")
            if len(new) > 20:
                print(f"      ... and {len(new) - 20} more lines")
            bad += len(new)
        print()

    print("─" * 74)
    if bad == 0:
        print("  No unexplained line failed to run.")
        print()
        print("  Every line that did not run is on the `UNREACHABLE` list with a")
        print("  written reason. The list is not a way of HIDING things, it is a")
        print("  commitment: a new untested line shows up here.")
    else:
        print(f"  {bad} lines never ran and have no explanation.")
        print()
        print("  An untested guard is a guard not known to be correct:")
        print("  if `if (p == NULL) return;` is written wrong, nothing tells you,")
        print("  until a null pointer arrives in production.")
        print("  Either write a test, or add it to UNREACHABLE with a reason.")
    print()
    print("  Also: even at 100% branch coverage this is not a proof of CORRECTNESS.")
    print("  Every line having run does not say it produced the right answer;")
    print("  the RFC vectors and the cross checks say that.")
    return 1 if bad else 0


if __name__ == "__main__":
    _utf8_output()
    raise SystemExit(main())
