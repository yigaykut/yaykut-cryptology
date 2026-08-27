"""Builds and runs `ccore/timing_rdtsc.c`.

The same pattern as `ccore/c_coverage.py`: a measurement that has to happen
on the C side, with Python only building it, running it, reading the result.

WHY A SEPARATE TOOL

`sidechannel.py` measures the engine from Python and `docs/audit.md` §5
wrote down the limit: a Python call costs hundreds of nanoseconds, so even
a scalar dependent branch in the ladder would stay under that noise. With
`rdtsc` the measurement happens inside C with no interpreter in the way.

    python -m ccore.c_timing
    python -m ccore.c_timing --samples 5000
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "timing_rdtsc.c"
CORE = ROOT / "crypto25519.c"

# The measurement depends on the compiler, so the flags sit here EXPLICITLY.
# `-O2`: the library is built that way too, and measuring at another level
# would be measuring a different program.
FLAGS = ["-O2", "-std=c11"]


def compiler() -> str | None:
    for name in ("gcc", "clang", "cc"):
        path = shutil.which(name)
        if path:
            return path
    return None


def compile(target: Path, cc: str) -> tuple[bool, str]:
    command = [cc, *FLAGS, "-I", str(ROOT), "-o", str(target),
               str(SOURCE), str(CORE), "-lm"]
    p = subprocess.run(command, capture_output=True, text=True,
                       errors="replace", timeout=300)
    return p.returncode == 0, (p.stderr or p.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--samples", type=int, default=2000,
                    help="number of samples (an X25519 call is about 1.2M "
                    "cycles, so 2000 samples takes about 8 s)")
    ap.add_argument("--warmup", type=int, default=200)
    a = ap.parse_args()

    cc = compiler()
    if not cc:
        print("\n  No compiler found (gcc, clang or cc).")
        print("  This measurement has to happen inside C; measuring from")
        print("  Python stays under the interpreter's noise.")
        print("  Without a compiler the measurement is SKIPPED, not a pass.\n")
        return 2

    if not SOURCE.is_file() or not CORE.is_file():
        print(f"\n  Kaynak eksik: {SOURCE.name} / {CORE.name}\n")
        return 2

    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / ("timing.exe" if sys.platform == "win32"
                               else "timing")
        print(f"\n  compiler  : {cc}")
        print(f"  flags     : {' '.join(FLAGS)}")

        ok, output = compile(target, cc)
        if not ok:
            print("\n  THE BUILD FAILED:\n")
            print(output[:2000])
            return 2
        if output.strip():
            print(f"\n  compiler warnings:\n{output[:1000]}")

        p = subprocess.run([str(target), str(a.samples), str(a.warmup)],
                           capture_output=True, text=True,
                           errors="replace", timeout=1800)
        print(p.stdout)
        if p.stderr.strip():
            print(p.stderr[:1000])
        return p.returncode


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
