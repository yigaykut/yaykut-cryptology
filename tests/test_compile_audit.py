"""The compile audit: the tool itself is being tested.

WHY THIS FILE EXISTS

`ccore/compile_audit.py` says "no data dependent branch found". That
sentence has two readings:

  1. There really is none.
  2. The tool does not know how to look.

The only way to separate the two is a POSITIVE CONTROL: give it a file it
must certainly catch, and see it caught. That is the same discipline the
project uses in the layer 2 experiments and the side channel sweep. An
uncontrolled "clean" result says nothing.

The tool's own pattern also turned out to be too loose once (a `# secret`
comment was taken for a counter), so a test that exercises the pattern's
looseness lives here too.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ccore"))

import compile_audit as dd  # noqa: E402

no_compiler = pytest.mark.skipif(
    not any(shutil.which(d) for d in ("gcc", "clang", "cc")),
    reason="no C compiler")

# COMPILER CALIBRATION
#
# The tests in this file exercise `compile_audit.py`'s assembly ANALYSER,
# and that analyser was calibrated against one particular compiler's output.
# Another version produces other assembly:
#
#   * the deliberate branch in the positive control file can be turned into
#     a conditional move and disappear on another version;
#   * the expected vectorisation false alarm may not appear;
#   * unrecognised branch shapes can show up in the real core.
#
# All three happened on the GitHub Actions runner. None is a code bug; they
# are a measurement tool running in an environment it was not calibrated for.
#
# Saying "clean" or "dirty" in an uncalibrated environment would be wrong, so
# it is SKIPPED. Skipped is not passed, and it means this tool is a LOCAL
# audit instrument.
not_calibrated = pytest.mark.skipif(
    bool(os.environ.get("CI")),
    reason="the compile audit is calibrated to the local compiler; SKIPPED in CI")


# A deliberate leak: branching on the VALUE of a secret byte.
# In constant time code this must never happen; the tool has to see it.
LEAKY = """
#include <stdint.h>
int leaky(const unsigned char *secret, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (secret[i] & 1)        /* A BRANCH ON A SECRET BIT */
            total += 3;
        else
            total += 1;
    }
    return total;
}
"""

# The same function with mask arithmetic, branchless.
# The length is FIXED: at a variable length gcc emits vectorisation
# pre-tests and the tool cannot classify them (see test_known_wrong_alarm).
CLEAN = """
#include <stdint.h>
int clean(const unsigned char *secret)
{
    int total = 0;
    for (int i = 0; i < 32; i++) {
        int b = secret[i] & 1;
        total += 1 + 2 * b;     /* no branch, arithmetic */
    }
    return total;
}
"""

# The same clean logic but with a RUNTIME length. gcc auto vectorises and
# adds "is n enough to vectorise" pre-tests. Those branches depend on `n`,
# and `n` is not secret, but the tool cannot tell that from the comment.
VECTORISED = """
#include <stdint.h>
int vectorised(const unsigned char *secret, int n)
{
    int total = 0;
    for (int i = 0; i < n; i++) {
        int b = secret[i] & 1;
        total += 1 + 2 * b;
    }
    return total;
}
"""


def _compile_and_read(source_text: str, name: str):
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        c = temp / f"{name}.c"
        c.write_text(source_text, encoding="utf-8")
        s = dd.make_assembly(c, temp)
        assert s is not None
        return dd.decrypt(s)


@no_compiler
@not_calibrated
def test_positive_control_the_leak_catches():
    """The deliberately leaking file must be marked REVIEW.

    If it is not caught, the sentence "no data dependent branch found" is worthless.
    """
    findings, count = _compile_and_read(LEAKY, "leaky")
    assert count["branch"] > 0
    assert findings, (
        "the tool DID NOT CATCH a deliberate leak, so its 'clean' reports "
        "are not trustworthy either")
    assert any(b.func == "leaky" for b in findings)


@no_compiler
@not_calibrated
def test_negative_control_clean_file_does_not_mark():
    """Branchless code must not raise a false alarm."""
    findings, _ = _compile_and_read(CLEAN, "clean")
    assert not findings, f"false alarm: {[str(b) for b in findings]}"


@no_compiler
@not_calibrated
def test_known_wrong_alarm_vectorisation():
    """A KNOWN LIMIT OF THE TOOL, documented rather than hidden.

    In a loop bounded by a runtime length, gcc auto vectorises and adds "is
    the length enough to vectorise" pre-tests. Those branches depend on the
    LENGTH, not on secret data, but nothing in the assembly comment says so,
    so the tool marks them REVIEW.

    This test PINS that behaviour. If the tool one day classifies them too,
    the test fails and somebody has to confirm the pattern did not simply
    get looser.

    The situation does not arise in the real core: `crypto25519.c` works
    with fixed lengths (LIMBS = 12), and the length dependent loops in
    `safe.c` keep the `ivtmp` name.
    """
    findings, _ = _compile_and_read(VECTORISED, "vectorised")
    assert findings, (
        "the expected false alarm disappeared; if the tool changed, whether "
        "this limit still holds has to be confirmed by hand")


@no_compiler
@not_calibrated
def test_real_core_clean():
    """The real claim: no unclassifiable branch in crypto25519.c or safe.c."""
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        for source in dd.SOURCES:
            s = dd.make_assembly(source, temp)
            findings, count = dd.decrypt(s)
            assert count["branch"] > 0, f"{source.name}: no branches at all, suspicious"
            assert not findings, (
                f"unclassifiable branch in {source.name}:\n"
                + "\n".join(str(b) for b in findings))


@no_compiler
def test_wipe_not_dropped():
    """CWE-14: `crypto_wipe` must not have been dropped by the compiler."""
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        s = dd.make_assembly(dd.HERE / "safe.c", temp)
        ok, message = dd.wipe_check(s)
        assert ok, message


# ───────────────── testing the tool's own patterns ─────────────────

def test_counter_pattern_covert_comment_does_not_swallow():
    """In the first version a comment like `# secret` was taken for a counter.

    The pattern was `#.*(?:i|j|k|t)\\s*$`, and it matched any comment whose
    last letter was one of those, `# secret` included. A loose pattern
    SILENTLY classifies a real finding as safe, which is the most dangerous
    failure mode an audit tool can have.
    """
    must_not_swallow = [
        "\tcmpb\t$0, (%rax)\t # secret",
        "\ttestq\t%rax, %rax\t # key",
        "\tcmpl\t$1, %eax\t # bit",
        "\ttestb\t$1, %r11b\t # swap",
    ]
    for s in must_not_swallow:
        assert dd.classify("some_function", s) is None, f"swallowed: {s!r}"


def test_counter_pattern_real_counter_recognises():
    should_tell = [
        "\tcmpq\t%r12, %rbp\t # ivtmp.311, tmp659",
        "\tcmpq\t%rsi, %rbx\t # n, i",
        "\tcmpq\t$4, %r9\t #, k",
    ]
    for s in should_tell:
        assert dd.classify("a_function", s) is not None, f"not recognised: {s!r}"


def test_selftest_functions_exempt():
    """Self test functions run on public vectors."""
    s = "\ttestl\t%eax, %eax\t # tmp213"
    assert dd.classify("crypto25519_selftest", s) is not None
    assert dd.classify("crypto_memory_selftest", s) is not None
    # but on the cryptographic path the same branch is NOT exempt
    assert dd.classify("ladder", s) is None
