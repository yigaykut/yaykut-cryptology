"""Loads the compiled C core if there is one, and ignores it otherwise.

`crypto/curve.py` implements X25519 in pure Python. The algorithm is constant
time, but Python's arbitrary width integers take different amounts of time
depending on operand size, so it is not physically constant time.
`ccore/crypto25519.c` closes that gap. This module finds that library, tests
it, and uses it.

The design rule is: fail quietly, fall back quietly. If the library is
missing, stale, or fails its own self-test, nothing is raised. `x25519()`
returns None and the caller drops to the pure Python path. The reason is that
the C core is a hardening measure, not an accelerator, so its absence must not
break the project. But a badly built library silently producing wrong keys is
not acceptable either. The only safe path between those two is to test before
using and refuse to use it if the test fails.

There are two gates, in this order. The manifest written by `ccore/build.py`
says which library was built and from which sources; `_provenance()` checks
the binary still matches both, which catches a library from somewhere else
and a library built from source that has since been edited. That gate runs
before the library is opened, because opening it already runs its code. The
self-tests come after, and ask whether the library actually works.

ctypes rather than a C extension: a CPython extension would tie the build to a
Python version and ABI, while ctypes just loads a plain shared library. The
same .dll or .so can then be used on an embedded target, from another
language, or straight from a test run. It also keeps layer 1's "no external
dependencies" rule, since ctypes is in the standard library.

To install: `python ccore/build.py`. Without a compiler nothing breaks; the
project keeps running in pure Python, just without the timing hardening.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path

# Must match CRYPTO25519_VERSION in ccore/crypto25519.h. A mismatch means an old
# library is lying around, and it will not be used.
EXPECTED_VERSION = 2

# With this variable set the C core is never looked for. Tests use it to
# measure the pure path, and users can set it for comparison.
ENV_PURE = "CRYPTO_PURE"

# Skips the manifest check. It exists for one case: editing the .c files and
# rebuilding over and over, where the digests move on every pass. It is not a
# thing to leave set, so `status()` says out loud when it is.
ENV_UNVERIFIED = "CRYPTO_CCORE_UNVERIFIED"

KEY_BYTES = 32

_BASE = "crypto25519"

MANIFEST_NAME = f"{_BASE}.manifest.json"

# The C sources the manifest records a digest for. Their directory is found
# relative to this file, so a source edit without a rebuild is caught.
SOURCE_DIR = Path(__file__).resolve().parent.parent / "ccore"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _provenance(path: Path) -> str | None:
    """Check a library against the manifest written when it was built.

    Returns text on refusal, None when the library may be loaded.

    `ccore/build.py` records the SHA-256 of the library it produced and of the
    sources it produced it from. Until now nothing read that back, so the
    manifest documented a chain of trust without checking it. Two things get
    past an unchecked manifest, and both matter more than they sound:

    A library from somewhere else. `crypto25519.dll` is on the ignore list,
    so it never travels with a clone; whatever sits in `crypto/` came from
    the local machine and nothing says where. Loading a shared library runs
    its initialisation code, so this is checked BEFORE `CDLL`, not after.

    A stale library. Editing `crypto25519.c` and forgetting to rebuild leaves
    the old binary in place. The interface version does not move for an
    ordinary edit, so the self-test passes and every timing number gets
    attributed to source that was never compiled. That is the exact mistake
    this project exists to catch, and it was the one the loader could not see.

    A refusal is not fatal. The caller falls back to pure Python, which is
    correct, just not hardened. Wrong-but-fast is the one outcome worth
    refusing outright.
    """
    if os.environ.get(ENV_UNVERIFIED):
        return None

    manifest_path = path.parent / MANIFEST_NAME
    if not manifest_path.is_file():
        return (f"no {MANIFEST_NAME} beside it; a library of unknown origin "
                f"is not loaded (build it with: python ccore/build.py)")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"{MANIFEST_NAME} unreadable ({e})"

    recorded = manifest.get("library_sha256")
    if not isinstance(recorded, str):
        return f"{MANIFEST_NAME} records no library_sha256"

    try:
        actual = _digest(path)
    except OSError as e:
        return f"could not be read for hashing ({e})"

    if actual != recorded:
        return (f"does not match {MANIFEST_NAME} "
                f"(has {actual[:16]}…, manifest says {recorded[:16]}…); "
                f"rebuild with: python ccore/build.py")

    # Source side. A source that is not there cannot be compared, and an
    # installed copy without `ccore/` is a legitimate case, so a missing file
    # is skipped rather than refused. A source that IS there and differs means
    # the binary is stale.
    for name, source_digest in (manifest.get("source_sha256") or {}).items():
        source = SOURCE_DIR / name
        if not source.is_file():
            continue
        try:
            if _digest(source) != source_digest:
                return (f"was built from an older {name}; the source has "
                        f"changed since. Rebuild with: python ccore/build.py")
        except OSError:
            continue

    return None


def _library_names() -> list[str]:
    if sys.platform == "win32":
        return [f"{_BASE}.dll"]
    if sys.platform == "darwin":
        return [f"lib{_BASE}.dylib", f"{_BASE}.dylib"]
    return [f"lib{_BASE}.so", f"{_BASE}.so"]


def _candidate_paths() -> list[Path]:
    """Where to look for the library, in priority order.

    Next to the package comes first, because `build.py` writes there, so the
    library follows the project if it is moved.
    """
    roots = [Path(__file__).resolve().parent,
             Path(__file__).resolve().parent.parent / "ccore"]
    manual = os.environ.get("CRYPTO_CCORE")
    if manual:
        roots.insert(0, Path(manual))
    return [root / name for root in roots for name in _library_names()]


class _Core:
    """The loaded library and its state. Kept as a single instance."""

    def __init__(self) -> None:
        self.lib: ctypes.CDLL | None = None
        self.path: Path | None = None
        self.reason: str = "not attempted yet"

    # ---- loading ----

    def load(self) -> None:
        if os.environ.get(ENV_PURE):
            self.reason = f"{ENV_PURE} is set, pure Python requested"
            return

        candidates = _candidate_paths()
        found = [p for p in candidates if p.exists()]
        if not found:
            self.reason = ("no compiled core "
                           "(build it with: python ccore/build.py)")
            return

        for path in found:
            error = self._try(path)
            if error is None:
                self.lib = self._lib
                self.path = path
                self.reason = "loaded"
                return
            self.reason = f"{path.name}: {error}"

    def _try(self, path: Path) -> str | None:
        """Load and test the library. Returns text on failure, None on success."""
        # Provenance first. Everything below this line runs code from the
        # library, starting with its initialisation on CDLL, so the one check
        # that can be made without trusting it has to come before it.
        refusal = _provenance(path)
        if refusal is not None:
            return refusal

        try:
            lib = ctypes.CDLL(str(path))
        except OSError as e:
            return f"could not load ({e})"

        try:
            lib.crypto25519_version.restype = ctypes.c_int
            lib.crypto25519_version.argtypes = []
            lib.crypto25519_selftest.restype = ctypes.c_int
            lib.crypto25519_selftest.argtypes = []
            # c_void_p so both `bytes` and a secure buffer address can be
            # passed. Keeping the secret key out of a Python `bytes` object is
            # only possible if raw pointers are accepted.
            lib.crypto25519.restype = ctypes.c_int
            lib.crypto25519.argtypes = [ctypes.c_void_p,
                                        ctypes.c_void_p,
                                        ctypes.c_void_p]
            lib.crypto_wipe.restype = None
            lib.crypto_wipe.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.crypto_buffer_open.restype = ctypes.c_void_p
            lib.crypto_buffer_open.argtypes = [ctypes.c_size_t,
                                               ctypes.POINTER(ctypes.c_int)]
            lib.crypto_buffer_close.restype = None
            lib.crypto_buffer_close.argtypes = [ctypes.c_void_p,
                                                ctypes.c_size_t]
            lib.crypto_memory_selftest.restype = ctypes.c_int
            lib.crypto_memory_selftest.argtypes = []
            lib.crypto_random.restype = ctypes.c_int
            lib.crypto_random.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        except AttributeError as e:
            return f"expected function missing ({e})"

        version = lib.crypto25519_version()
        if version != EXPECTED_VERSION:
            return (f"interface version {version}, expected "
                    f"{EXPECTED_VERSION}; stale library, not used")

        # Test before use. A badly built library should not be used at all
        # rather than silently produce wrong keys.
        code = lib.crypto25519_selftest()
        if code != 0:
            return (f"failed its own self-test (code {code}); "
                    f"the RFC 7748 vector did not match, not used")

        # Secure memory needs testing too: a library that says it wiped and
        # did not is more dangerous than one that never wipes.
        code = lib.crypto_memory_selftest()
        if code != 0:
            return (f"failed the memory test (code {code}); "
                    f"wiping does not work, not used")

        self._lib = lib
        return None

    # ---- use ----

    def x25519(self, secret: bytes, u: bytes) -> bytes | None:
        if self.lib is None:
            return None
        out = ctypes.create_string_buffer(KEY_BYTES)
        self.lib.crypto25519(ctypes.cast(out, ctypes.c_void_p),
                             ctypes.cast(ctypes.c_char_p(bytes(secret)),
                                         ctypes.c_void_p),
                             ctypes.cast(ctypes.c_char_p(bytes(u)),
                                         ctypes.c_void_p))
        return out.raw[:KEY_BYTES]

    def x25519_address(self, secret_addr: int, u_addr: int,
                       out_addr: int) -> bool:
        """X25519 on raw addresses, so the secret never becomes `bytes`.

        The whole point of the secure buffer in `crypto/memory.py` runs
        through this path: the secret is used without leaving the locked
        block allocated in C.
        """
        if self.lib is None:
            return False
        self.lib.crypto25519(out_addr, secret_addr, u_addr)
        return True


_core = _Core()
_core.load()


# ───────────────────────── public interface ─────────────────────────

def ready() -> bool:
    """Whether the C core loaded and passed its tests."""
    return _core.lib is not None


def status() -> str:
    """One line of state for humans, used by the demo and the README."""
    if not ready():
        return f"C core NOT IN USE: {_core.reason}"
    if os.environ.get(ENV_UNVERIFIED):
        return (f"C core active UNVERIFIED ({ENV_UNVERIFIED} is set, "
                f"the manifest was not checked): {_core.path}")
    return f"C core active: {_core.path}"


def x25519(secret: bytes, u: bytes) -> bytes | None:
    """X25519 through the C core. Returns None if there is no core."""
    return _core.x25519(secret, u)


def lib() -> "ctypes.CDLL | None":
    """The loaded library object, used directly by `crypto/memory.py`."""
    return _core.lib


def x25519_address(secret_addr: int, u_addr: int, out_addr: int) -> bool:
    """X25519 on raw addresses. False if there is no core."""
    return _core.x25519_address(secret_addr, u_addr, out_addr)


def reload() -> bool:
    """Look for the library again.

    Lets you use a freshly built core without restarting the process, and
    lets tests compare the pure and fast paths.
    """
    global _core
    _core = _Core()
    _core.load()
    return ready()
