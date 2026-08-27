"""The C core: the twin arithmetic, the loader and the real library.

THE LOGIC OF THIS FILE

The C code may not be compiled on every machine, so the tests split into
three groups:

  1. TWIN TESTS, always run. `ccore/twin.py` is the line by line Python
     equivalent of the limb arithmetic in the C file. If this passes, the
     ARITHMETIC is correct and only C syntax and compiler risk remain.
  2. LOADER TESTS, always run. They check the project keeps working both
     when the library is missing and when it is broken.
  3. LIBRARY TESTS, run only if it was compiled (`skipif`). They check the
     compiled C gives the same result as pure Python.

The second group matters more than the first: the most dangerous state for a
cryptography library is not "missing" but "present and wrong".
"""

from __future__ import annotations

import os
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ccore import twin  # noqa: E402
from crypto import curve, fastpath# noqa: E402

h = bytes.fromhex
SOURCE = ROOT / "ccore" / "crypto25519.c"

BASE_POINT = bytes([9] + [0] * 31)


# ═══════════════════ 1. THE TWIN: is the arithmetic correct ═══════════════════

@pytest.mark.parametrize("scalar, u, expected", [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
])
def test_twin_rfc_vectors(scalar, u, expected):
    """RFC 7748 §5.2: the arithmetic C uses produces the standard."""
    assert twin.x25519(h(scalar), h(u)).hex() == expected


def test_twin_rfc_diffie_hellman():
    """RFC 7748 §6.1: a full key exchange scenario."""
    a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

    a_public = twin.x25519(a, BASE_POINT)
    b_public = twin.x25519(b, BASE_POINT)
    assert a_public.hex() == \
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert b_public.hex() == \
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert twin.x25519(a, b_public).hex() == shared
    assert twin.x25519(b, a_public).hex() == shared


def test_twin_pure_python_with_same():
    """The twin and crypto/curve.py must not diverge on random inputs.

    The two use COMPLETELY DIFFERENT arithmetic: curve.py works on Python's
    arbitrary width integers, the twin on 12 limbs in a fixed base. Giving
    the same result is an independent verification.
    """
    rng = random.Random(20260818)
    for _ in range(15):
        g = bytes(rng.getrandbits(8) for _ in range(32))
        u = bytes(rng.getrandbits(8) for _ in range(32))
        assert twin.x25519(g, u) == curve.x25519_pure(g, u)


@pytest.mark.parametrize("name, u", [
    ("zero", bytes(32)),
    ("one", bytes([1] + [0] * 31)),
    ("p-1", ((1 << 255) - 20).to_bytes(32, "little")),
    ("p", ((1 << 255) - 19).to_bytes(32, "little")),
    ("p+1", ((1 << 255) - 18).to_bytes(32, "little")),
    ("2^255-1", ((1 << 255) - 1).to_bytes(32, "little")),
    ("top bit set", bytes([9] + [0] * 30 + [0x80])),
])
def test_twin_edge_u_values(name, u):
    """The edges of reduction: around p, and the ignored top bit.

    Errors in limb arithmetic show up exactly here: if the carry does not
    converge, if the conditional subtraction goes the wrong way, or if the top bit is not masked.
    """
    g = bytes([1] + [0] * 31)
    assert twin.x25519(g, u) == curve.x25519_pure(g, u)


def test_twin_commutativity():
    """a*(b*G) == b*(a*G), Diffie-Hellman's only requirement."""
    rng = random.Random(3)
    for _ in range(5):
        a = bytes(rng.getrandbits(8) for _ in range(32))
        b = bytes(rng.getrandbits(8) for _ in range(32))
        assert twin.x25519(a, twin.x25519(b, BASE_POINT)) == \
               twin.x25519(b, twin.x25519(a, BASE_POINT))


# ═══════════════════ 1b. THE TWIN: the overflow margin ═══════════════════

def test_twin_limb_round_return():
    """No loss between the limb representation and an integer."""
    rng = random.Random(11)
    for _ in range(50):
        x = rng.randrange(twin.P)
        assert twin.limbs_to_int(twin.int_to_limbs(x)) == x


def test_twin_product_worst_state_does_not_overflow():
    """All limbs at the ceiling: acc[0] has to fit in int64.

    In C this overflow is SILENT: it produces a wrong key and nothing warns.
    Here it is measurable: the bound on paper is 2^60.7 and the real margin is about 2.3 bits.
    """
    en = [twin.MASK] * twin.LIMBS
    result = twin.fe_mul(en, en)          # the assertion is inside; it raises on failure
    assert twin.limbs_to_int(result) == \
        (twin.limbs_to_int(en) ** 2) % twin.P


def test_twin_overflow_guard_really_works():
    """The guard assertion is not fake: input past the bound has to be caught.

    Trusting a security check without testing it is worse than never writing
    the check at all, because it gives false confidence.
    """
    with pytest.raises(twin.OverflowGuard):
        twin._check_bounds([1 << 63], "fake")
    with pytest.raises(twin.OverflowGuard):
        twin._check_bounds([-(1 << 63)], "fake")


def test_twin_transport_three_in_rounds_converges():
    """fe_carry's three passes bring an input of multiplication size down."""
    rng = random.Random(5)
    for _ in range(30):
        h_ = [rng.randrange(1 << 60) for _ in range(twin.LIMBS)]
        expected = sum(v << (twin.BASE * i)
                       for i, v in enumerate(h_)) % twin.P
        twin.fe_carry(h_)               # raises OverflowGuard if it does not converge
        assert all(0 <= v <= twin.MASK for v in h_)
        assert twin.limbs_to_int(h_) == expected


def test_twin_subtraction_never_negative_does_not_fail():
    """fe_sub's 1024*p trick: a borrow must never be needed."""
    rng = random.Random(9)
    for _ in range(30):
        f = twin.int_to_limbs(rng.randrange(twin.P))
        g = twin.int_to_limbs(rng.randrange(twin.P))
        result = twin.fe_sub(f, g)    # raises OverflowGuard if it goes negative
        assert twin.limbs_to_int(result) == \
            (twin.limbs_to_int(f) - twin.limbs_to_int(g)) % twin.P


def test_twin_inverse_taking_chain():
    """Does the Fermat chain really compute z^(p-2)?"""
    rng = random.Random(13)
    for _ in range(5):
        x = rng.randrange(1, twin.P)
        t = twin.limbs_to_int(twin.fe_invert(twin.int_to_limbs(x)))
        assert t == pow(x, twin.P - 2, twin.P)
        assert x * t % twin.P == 1


def test_twin_of_zero_inverse_zero():
    """0^(p-2) = 0 — the ladder expects this at the point at infinity."""
    assert twin.limbs_to_int(twin.fe_invert(twin.fe_zero())) == 0


# ═══════════════════ 1c. Do the TWIN and the C SOURCE agree ═══════════════════

def _c_constant(name: str) -> list[int]:
    """Pulls an array constant out of the C source."""
    text = SOURCE.read_text(encoding="utf-8")
    template = re.compile(
        r"static const int64_t " + name + r"\[LIMBS\]\s*=\s*\{(.*?)\}", re.S)
    m = template.search(text)
    assert m, f"the constant {name} was not found in the C source"
    return [int(x) for x in re.findall(r"(\d+)L", m.group(1))]


def test_twin_c_with_same_constants_uses():
    """If the twin and the C source diverge, the twin's verification loses meaning.

    This test catches that divergence. The constants are not generated from
    one source (there is no shared constants file between C and Python), so
    their equality has to be tested.
    """
    assert _c_constant("P22") == twin.P22
    assert _c_constant("Q1024") == twin.Q1024

    text = SOURCE.read_text(encoding="utf-8")
    assert re.search(r"#define LIMBS (\d+)", text).group(1) == str(twin.LIMBS)
    assert re.search(r"#define BASE (\d+)", text).group(1) == str(twin.BASE)
    assert re.search(r"#define FOLD (\d+)L", text).group(1) == str(twin.FOLD)


def test_c_constants_mathematical_as_correct():
    """P22 really is p, Q1024 really is 1024*p, FOLD really is 2^264 mod p."""
    assert sum(v << (22 * i) for i, v in enumerate(twin.P22)) == twin.P
    assert sum(v << (22 * i) for i, v in enumerate(twin.Q1024)) == 1024 * twin.P
    assert (1 << 264) % twin.P == twin.FOLD
    # That borrowing is unnecessary rests on exactly this:
    assert all(q >= (1 << 22) for q in twin.Q1024)


# ═══════════════════ 2. THE LOADER ═══════════════════

def test_loader_no_time_does_not_raise():
    """`ready()` and `status()` work quietly even without the core."""
    assert isinstance(fastpath.ready(), bool)
    assert isinstance(fastpath.status(), str)
    assert fastpath.status()


def test_loader_absent_none_rotates():
    """`x25519` returns None rather than raising when the core is missing, so the caller can fall back."""
    result = fastpath.x25519(bytes(32), BASE_POINT)
    assert result is None or (isinstance(result, bytes) and len(result) == 32)


def test_pure_environment_variable_core_closes(monkeypatch):
    """With CRYPTO_PURE=1 the C path is fully disabled, for comparison."""
    monkeypatch.setenv(fastpath.ENV_PURE, "1")
    try:
        assert fastpath.reload() is False
        assert fastpath.x25519(bytes(32), BASE_POINT) is None
        assert fastpath.ENV_PURE in fastpath.status()
    finally:
        monkeypatch.delenv(fastpath.ENV_PURE, raising=False)
        fastpath.reload()


def test_broken_library_is_not_used(tmp_path, monkeypatch):
    """If random bytes are put there as a library, they must be quietly ignored.

    A cryptography library that is "present but wrong" is more dangerous than
    one that is missing; the loader's only correct behaviour is to refuse it.
    """
    # AN ENVIRONMENT VARIABLE LEAK, found while measuring C coverage on
    # 2026-08-20. This test used to DELETE CRYPTO_CCORE in its `finally`
    # block, when the variable may have been set from outside
    # (`ccore/c_coverage.py` does exactly that). Deleting it made every test
    # running AFTER this one go to a different library, and the coverage
    # measurement came out silently wrong.
    #
    # The lesson: a test restoring the environment means PUTTING IT BACK,
    # not resetting it.
    previous = os.environ.get("CRYPTO_CCORE")

    fake = tmp_path / fastpath._library_names()[0]
    fake.write_bytes(os.urandom(4096))
    monkeypatch.setenv("CRYPTO_CCORE", str(tmp_path))
    try:
        fastpath.reload()
        # The fake file is FIRST in the search order and still must not be picked.
        # (If a real library is installed the loader may move to it, which is fine.)
        assert fastpath._core.path != fake
    finally:
        if previous is None:
            monkeypatch.delenv("CRYPTO_CCORE", raising=False)
        else:
            monkeypatch.setenv("CRYPTO_CCORE", previous)
        fastpath.reload()


def test_environment_variable_is_not_leaked():
    """The regression lock for the leak above.

    A test breaking the environment changes WHAT the following tests check,
    and nothing warns. This test confirms the loader stays on the expected
    library throughout the C core tests.
    """
    expected = os.environ.get("CRYPTO_CCORE")
    if expected is None:
        pytest.skip("CRYPTO_CCORE is not set, so a leak cannot be observed")
    assert fastpath._core.path is not None
    assert str(fastpath._core.path).startswith(expected), (
        f"the loader is using {fastpath._core.path}, expected a library under "
        f"{expected}; a test may have leaked its environment")


def test_expected_version_with_the_header_same():
    """The version constant in Python must not diverge from the C header."""
    title = (ROOT / "ccore" / "crypto25519.h").read_text(encoding="utf-8")
    m = re.search(r"#define CRYPTO25519_VERSION (\d+)", title)
    assert m and int(m.group(1)) == fastpath.EXPECTED_VERSION


# ═══════════════════ 3. THE REAL LIBRARY (if compiled) ═══════════════════

not_compiled = pytest.mark.skipif(
    not fastpath.ready(),
    reason="the C core is not compiled (python ccore/build.py)")


@not_compiled
def test_c_pure_python_with_same():
    rng = random.Random(20260818)
    for _ in range(25):
        g = bytes(rng.getrandbits(8) for _ in range(32))
        u = bytes(rng.getrandbits(8) for _ in range(32))
        assert fastpath.x25519(g, u) == curve.x25519_pure(g, u)


@not_compiled
def test_c_twin_with_same():
    rng = random.Random(4)
    for _ in range(10):
        g = bytes(rng.getrandbits(8) for _ in range(32))
        u = bytes(rng.getrandbits(8) for _ in range(32))
        assert fastpath.x25519(g, u) == twin.x25519(g, u)


@not_compiled
def test_c_rfc_vector():
    assert fastpath.x25519(
        h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"


# ═══════════════════ 4. THE DISPATCH POINT ═══════════════════

def test_x25519_which_path_if_it_goes_go_same():
    """The public `x25519` and `x25519_pure` must not diverge.

    This test is meaningful on a compiled and an uncompiled machine alike: if
    compiled it compares two implementations, if not it checks the same path
    for consistency with itself.
    """
    rng = random.Random(17)
    for _ in range(10):
        g = bytes(rng.getrandbits(8) for _ in range(32))
        u = bytes(rng.getrandbits(8) for _ in range(32))
        assert curve.x25519(g, u) == curve.x25519_pure(g, u)


def test_verification_from_the_core_before():
    """An invalid key must give the same error with or without the core."""
    from crypto import KeyManagementError
    with pytest.raises(KeyManagementError):
        curve.x25519(b"kisa", BASE_POINT)
    with pytest.raises(KeyManagementError):
        curve.x25519(bytes(32), b"kisa")


@pytest.mark.skipif(
    sys.platform == "win32" and fastpath.ready(),
    reason=(
        "On Windows a loaded DLL cannot be relinked. `build.py` runs in a "
        "subprocess, but this pytest process holds the DLL open and the "
        "linker fails with LNK1104. Not a code bug, an OS limit."),
)
def test_create_script_compiler_absent_clean_comes_out():
    """`build.py` must exit cleanly and understandably on a machine with no compiler.

    The script's exit codes: 0 success, 2 no compiler, 3 a check failed.
    3 is never acceptable; if a library was produced it has to be correct.
    """
    # errors="replace": when the machine's path contains a non ASCII letter
    # (here "MSİ") the subprocess writes in the code page while the parent
    # decodes as UTF-8, and THE READER THREAD DIED SILENTLY. The result: if
    # the assert failed, the diagnostic output printed came back empty, so
    # the diagnostic vanished exactly when it was needed most.
    p = subprocess.run([sys.executable, str(ROOT / "ccore" / "build.py")],
                       capture_output=True, text=True, errors="replace",
                       timeout=600)
    assert p.returncode in (0, 2), (
        f"build.py exited with an unexpected code ({p.returncode}):\n"
        f"{p.stdout}\n{p.stderr}")


# ═══════════ 5. C GUARD SATIRLARI (gcov bulgusu 2026-08-20) ═══════════
#
# `ccore/c_coverage.py` came back on its first run with 75.81% line coverage
# for `safe.c`. Most of the 15 lines that did not run really are unreachable
# (malloc failure, the self test's error branches), but FOUR were reachable
# guard lines and had never been tested.
#
# An untested guard is a guard not known to be correct: if the line
# `if (p == NULL) return;` is written wrong, nothing tells you, until a null
# pointer arrives in production.

@not_compiled
def test_c_zero_sized_buffer_null_rotates():
    """`crypto_buffer_open(0, ...)` must return NULL rather than crash.

    The Python side already refuses size <= 0, so this line is only
    reachable by calling C directly.
    """
    import ctypes
    lib = fastpath.lib()
    lock = ctypes.c_int(7)                      # must be pulled to 0 if NULL is returned
    p = lib.crypto_buffer_open(0, ctypes.byref(lock))
    assert not p
    assert lock.value == 0


@not_compiled
def test_c_excessive_size_null_rotates():
    """If the allocation fails, NULL. It must not quietly return a broken pointer."""
    import ctypes
    lib = fastpath.lib()
    lock = ctypes.c_int(0)
    p = lib.crypto_buffer_open(ctypes.c_size_t(1 << 62), ctypes.byref(lock))
    assert not p, "1 EiB was allocated? Failure was expected."
    assert lock.value == 0


@not_compiled
def test_c_empty_pointer_guards():
    """Functions called with NULL must not crash.

    These lines had never run; now they do and their behaviour is pinned.
    """
    lib = fastpath.lib()
    lib.crypto_wipe(None, 32)                     # koruma: p == NULL
    lib.crypto_wipe(None, 0)
    lib.crypto_buffer_close(None, 32)            # koruma: p == NULL
    assert lib.crypto_random(None, 32) == 1    # koruma: p == NULL
    assert lib.crypto_memory_selftest() == 0       # still sound


@not_compiled
def test_c_zero_length_randomness_is_refused():
    """`crypto_random(p, 0)` must return an error, not a silent success."""
    import ctypes
    lib = fastpath.lib()
    lock = ctypes.c_int(0)
    p = lib.crypto_buffer_open(32, ctypes.byref(lock))
    assert p
    try:
        assert lib.crypto_random(p, 0) == 1
    finally:
        lib.crypto_buffer_close(p, 32)


@not_compiled
def test_c_wipe_zero_length_harmless():
    """`crypto_wipe(p, 0)` must do nothing, but must not blow up either."""
    import ctypes
    lib = fastpath.lib()
    lock = ctypes.c_int(0)
    p = lib.crypto_buffer_open(16, ctypes.byref(lock))
    assert p
    try:
        array = (ctypes.c_ubyte * 16).from_address(p)
        array[:] = b"\xAA" * 16
        lib.crypto_wipe(p, 0)                     # zero length: it must not touch anything
        assert bytes(array) == b"\xAA" * 16
        lib.crypto_wipe(p, 16)
        assert bytes(array) == bytes(16)
    finally:
        lib.crypto_buffer_close(p, 16)


# ─────────────────────────────────────────────────────────────────────
# PROVENANCE
#
# `ccore/build.py` records the SHA-256 of the library it built and of the
# sources it built it from. For a long time nothing read that back, so the
# manifest described a chain of trust that was never checked. These tests
# hold the check in place. They are the "present and wrong" case from the
# top of this file, in its two real forms: a library from somewhere else,
# and a library older than the source next to it.
# ─────────────────────────────────────────────────────────────────────

MANIFEST = ROOT / "crypto" / fastpath.MANIFEST_NAME


def _library_and_manifest(directory: Path, body: bytes | None = None) -> Path:
    """Copy the real library and its manifest into `directory`."""
    import json
    import shutil
    source = fastpath._core.path
    target = directory / source.name
    target.write_bytes(body if body is not None else source.read_bytes())
    shutil.copy(MANIFEST, directory / fastpath.MANIFEST_NAME)
    assert json.loads((directory / fastpath.MANIFEST_NAME).read_text("utf-8"))
    return target


@not_compiled
def test_the_real_library_passes_provenance():
    """The control arm. Without this the refusals below prove nothing."""
    assert fastpath._provenance(fastpath._core.path) is None


@not_compiled
def test_library_without_a_manifest_is_refused(tmp_path):
    """A library of unknown origin does not get loaded.

    `crypto25519.dll` is on the ignore list, so it never arrives with a
    clone. Whatever is sitting in `crypto/` came from somewhere local and
    nothing records where.
    """
    stray = tmp_path / fastpath._core.path.name
    stray.write_bytes(fastpath._core.path.read_bytes())
    reason = fastpath._provenance(stray)
    assert reason is not None
    assert "unknown origin" in reason


@not_compiled
def test_tampered_library_is_refused(tmp_path):
    """One flipped bit is enough. The digest is the whole point."""
    body = bytearray(fastpath._core.path.read_bytes())
    body[len(body) // 2] ^= 0x01
    target = _library_and_manifest(tmp_path, bytes(body))
    reason = fastpath._provenance(target)
    assert reason is not None
    assert "does not match" in reason


@not_compiled
def test_library_older_than_its_source_is_refused(tmp_path, monkeypatch):
    """The stale binary case, and the likelier of the two in practice.

    Editing `crypto25519.c` without rebuilding leaves the old library in
    place. The interface version does not move for an ordinary edit, so the
    self-test still passes and every timing number gets credited to source
    that was never compiled. That is the mistake this project exists to
    catch, and the loader used to be blind to it.
    """
    edited = tmp_path / "sources"
    edited.mkdir()
    (edited / SOURCE.name).write_bytes(SOURCE.read_bytes() + b"\n/* edited */\n")
    monkeypatch.setattr(fastpath, "SOURCE_DIR", edited)

    reason = fastpath._provenance(fastpath._core.path)
    assert reason is not None
    assert "older" in reason and SOURCE.name in reason


@not_compiled
def test_a_source_that_is_not_there_is_not_treated_as_a_mismatch(tmp_path,
                                                                monkeypatch):
    """An installed copy without `ccore/` is legitimate, not a failure.

    What cannot be compared is skipped. What CAN be compared is enforced,
    which is the previous test.
    """
    monkeypatch.setattr(fastpath, "SOURCE_DIR", tmp_path / "gone")
    assert fastpath._provenance(fastpath._core.path) is None


@not_compiled
def test_the_escape_hatch_works_and_is_announced(monkeypatch, tmp_path):
    """Skipping the check is allowed, staying quiet about it is not.

    Rebuilding the C in a loop moves the digests on every pass, so there has
    to be a way through. The condition is that `status()` says so, otherwise
    an unverified core looks exactly like a verified one.
    """
    edited = tmp_path / "sources"
    edited.mkdir()
    (edited / SOURCE.name).write_bytes(b"/* nothing like the real thing */\n")
    monkeypatch.setattr(fastpath, "SOURCE_DIR", edited)
    assert fastpath._provenance(fastpath._core.path) is not None

    monkeypatch.setenv(fastpath.ENV_UNVERIFIED, "1")
    assert fastpath._provenance(fastpath._core.path) is None
    assert "UNVERIFIED" in fastpath.status()


@not_compiled
def test_provenance_is_checked_before_the_library_is_opened():
    """Order matters: opening a shared library already runs code from it.

    Read from the source rather than by observation, because the failure
    this guards against is a reordering during a later edit, and by the time
    it is observable the code has already run.
    """
    source = (ROOT / "crypto" / "fastpath.py").read_text(encoding="utf-8")
    body = source.split("def _try(", 1)[1]
    assert body.index("_provenance(") < body.index("ctypes.CDLL(")
