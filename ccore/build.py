"""Builds, tests and installs the C core next to `crypto/`.

    python ccore/build.py

If no compiler is found it exits with a clear message and the project keeps
running in pure Python. If the build succeeds, FOUR gates follow:

  1. The library's own self test, the RFC 7748 vectors on the C side
  2. A cross check against pure Python, same result on random keys
  3. A commutativity check, a*(b*G) == b*(a*G)
  4. A memory check, write, wipe, is it really zero (ADR-020)

If any of the four fails the library is DELETED. Leaving a half correct
cryptography library on disk is worse than having none.

At the end `crypto/crypto25519.manifest.json` is written: the SHA-256 of the
sources and of the produced library, the compiler version, the platform.
It is there so an auditor can ask "did the library I hold really come from
this source" (docs/audit.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCES = [HERE / "crypto25519.c", HERE / "safe.c"]
TARGET_DIR = ROOT / "crypto"

sys.path.insert(0, str(ROOT))


def _target_name() -> str:
    if sys.platform == "win32":
        return "crypto25519.dll"
    if sys.platform == "darwin":
        return "libcrypto25519.dylib"
    return "libcrypto25519.so"


def _run(argv: list[str], cwd: Path) -> tuple[bool, str]:
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True)
    except (OSError, FileNotFoundError) as e:
        return False, str(e)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def _with_gcc(output: Path, temp: Path) -> tuple[bool, str]:
    """gcc / clang / cc — Unix ve MinGW."""
    for compiler in ("gcc", "clang", "cc"):
        if shutil.which(compiler) is None:
            continue
        argv = ([compiler, "-O2", "-Wall", "-Wextra", "-std=c99",
                 "-shared", "-o", str(output)]
                + [str(k) for k in SOURCES])
        if sys.platform != "win32":
            argv.insert(1, "-fPIC")
            argv.insert(1, "-fvisibility=hidden")
        ok, output_text = _run(argv, temp)
        if ok:
            _, version = _run([compiler, "--version"], temp)
            return True, version.splitlines()[0] if version else compiler
        return False, f"{compiler} failed:\n{output_text}"
    return False, "no gcc, clang or cc found"


def _with_msvc(output: Path, temp: Path) -> tuple[bool, str]:
    """MSVC, through setuptools' compiler finder.

    setuptools is used rather than calling `cl` directly, because it finds
    Visual Studio's environment variables (vcvars) itself and gives a clear
    error when it cannot.
    """
    try:
        from setuptools._distutils import ccompiler, errors
    except ImportError:
        return False, "setuptools is missing, the MSVC path could not be tried"

    c = ccompiler.new_compiler()
    if c.compiler_type != "msvc":
        return False, f"expected MSVC, got {c.compiler_type}"
    try:
        c.initialize()
    except Exception as e:                       # DistutilsPlatformError vb.
        return False, (f"the MSVC toolchain is not installed: {e}\n"
                       f"  Visual Studio Installer'da 'Desktop development "
                       f"with C++' component, or use MSYS2/MinGW "
                       f"gcc kurun.")
    try:
        objects = c.compile([str(k) for k in SOURCES],
                            output_dir=str(temp),
                            include_dirs=[str(HERE)],
                            extra_preargs=["/O2", "/W3"])
        c.link_shared_object(objects, str(output))
    except errors.DistutilsError as e:
        return False, f"MSVC build error: {e}"
    return True, "MSVC ile derlendi"


def compile(output: Path) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        if sys.platform == "win32":
            ok, message = _with_msvc(output, temp)
            if ok:
                return True, message
            ok2, message2 = _with_gcc(output, temp)
            if ok2:
                return True, message2
            return False, f"{message}\n{message2}"
        return _with_gcc(output, temp)


def probe() -> tuple[bool, str]:
    """Puts the built library through three gates."""
    from crypto import fastpath, curve

    if not fastpath.reload():
        return False, f"the library could not be loaded, {fastpath.status()}"

    rng = random.Random(20260818)
    for _ in range(50):
        g = bytes(rng.getrandbits(8) for _ in range(32))
        u = bytes(rng.getrandbits(8) for _ in range(32))
        c_result = fastpath.x25519(g, u)
        pure = curve._encode_u(curve._ladder(curve._clamp(g), curve._decode_u(u)))
        if c_result != pure:
            return False, (f"the cross check failed\n  secret={g.hex()}\n"
                           f"  u={u.hex()}\n  C  ={c_result.hex()}\n"
                           f"  saf={pure.hex()}")

    for _ in range(10):
        a = bytes(rng.getrandbits(8) for _ in range(32))
        b = bytes(rng.getrandbits(8) for _ in range(32))
        base = bytes([9] + [0] * 31)
        if fastpath.x25519(a, fastpath.x25519(b, base)) != \
           fastpath.x25519(b, fastpath.x25519(a, base)):
            return False, "the commutativity check failed: a*(b*G) != b*(a*G)"

    # The fourth gate: does secure memory really wipe (ADR-020).
    from crypto import memory
    pattern = bytes([0xA5]) * 64
    with memory.SecureBuffer(64) as t:
        t.write(pattern)
        if bytes(t.view()) != pattern:
            return False, "the secure buffer write check failed"
        t.wipe()
        if bytes(t.view()) != bytes(64):
            return False, "the secure buffer WIPE check failed"
        lock = "locked" if t.locked else "unlocked — the environment did not allow it"

    return True, f"50 cross, 10 commutativity and the memory check passed ({lock})"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _api_version() -> int:
    import re
    text = (HERE / "crypto25519.h").read_text(encoding="utf-8")
    return int(re.search(r"#define CRYPTO25519_VERSION (\d+)", text).group(1))


def main() -> int:
    print(f"source : {', '.join(k.name for k in SOURCES)}")
    for k in SOURCES:
        if not k.exists():
            print(f"ERROR: source file missing: {k}")
            return 1

    output = TARGET_DIR / _target_name()
    print(f"target : {output}")

    ok, message = compile(output)
    if not ok:
        print(f"\nCOULD NOT BUILD\n{message}\n")
        print("That is not an error, it is a gap: the project keeps running in")
        print("pure Python. The only thing lost is X25519's physical constant")
        print("time behaviour (see ADR-019).")
        return 2
    print(f"built  : {message}")

    passed, detail = probe()
    if not passed:
        output.unlink(missing_ok=True)
        print(f"\nA CHECK FAILED, the library was deleted.\n{detail}")
        return 3

    print(f"checks : {detail}")

    # The build manifest, for auditability (docs/audit.md).
    # An auditor has to be able to ask "did the .dll I hold really come from
    # this source"; the manifest is where that question starts.
    manifest = {
        "library_sha256": _digest(output),
        "source_sha256": {k.name: _digest(k) for k in SOURCES},
        "compiler": message,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "api_version": _api_version(),
    }
    manifest_path = TARGET_DIR / "crypto25519.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False),
                             encoding="utf-8")
    print(f"manifest: {manifest_path.name}  "
          f"(library {manifest['library_sha256'][:16]}…)")

    from crypto import fastpath
    print(f"status : {fastpath.status()}")
    print("\nDONE. From now on crypto.curve.x25519 uses the C core.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
