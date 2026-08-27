"""LaTeX to Unicode conversion tests.

The most important one is the regression test at the end: when a new formula
is added to the corpus and the converter does not cover a construct in it, raw LaTeX appears on screen. The test catches that.
yakalar.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from render import latex_unicode  # noqa: E402
from crypto import load_corpus# noqa: E402

CORPUS = load_corpus()

# Traces that must not remain after conversion.
RESIDUE = re.compile(
    r"\\|\b(mathrm|mathbf|mathbb|mathrel|mathbin|mathcal|ell|quad|qquad"
    r"|big|bigl|bigr|left|right|frac|pmod|bmod|sqrt|text|oplus|equiv"
    r"|approx|cdot|varphi|lambda|sigma|alpha|beta)\b"
)


@pytest.mark.parametrize("entry", list(CORPUS), ids=lambda e: f"{e.id:04X}-{e.slug}")
def test_corpus_formula_fully_is_translated(entry):
    """Every corpus formula has to convert without leaving a residue."""
    source = entry.doc.get("latex", "")
    if not source:
        return
    output = latex_unicode(source)
    assert output, f"{entry}'s formula converted to nothing"
    residue = RESIDUE.search(output)
    assert not residue, (
        f"{entry}: conversion residue {residue.group(0)!r}\n"
        f"  source: {source}\n  output: {output}"
    )


# ────────────────────────── individual constructs ──────────────────────────

def test_upper_index():
    assert latex_unicode("y^2 = x^3") == "y² = x³"


def test_sub_index():
    assert latex_unicode("a_1 + a_2") == "a₁ + a₂"


def test_negative_upper():
    assert latex_unicode("e^{-1}") == "e⁻¹"


def test_greek_letters():
    assert latex_unicode(r"\varphi(n)") == "φ(n)"
    assert latex_unicode(r"\lambda \sigma \tau") == "λ σ τ"


def test_modular_display():
    assert latex_unicode(r"a \equiv b \pmod{n}") == "a ≡ b (mod n)"
    assert latex_unicode(r"c^d \bmod p") == "cᵈ mod p"


def test_fraction():
    assert latex_unicode(r"\frac{a}{b}") == "a/b"
    assert latex_unicode(r"\frac{y_2 - y_1}{x_2 - x_1}") == "(y₂ - y₁)/(x₂ - x₁)"


def test_square_root():
    assert latex_unicode(r"\sqrt{N}") == "√N"


def test_pair_line_set():
    # The letter p has a Unicode subscript form, the letter q does not.
    # A subscript with no equivalent is left as it is, with its marker.
    assert latex_unicode(r"\mathbb{F}_p") == "𝔽ₚ"
    assert latex_unicode(r"\mathbb{Z}_q") == "ℤ_q"


def test_writing_type_instructions_to_content_is_reduced():
    assert latex_unicode(r"\mathrm{HMAC}(K)") == "HMAC(K)"
    assert latex_unicode(r"\mathbf{b} = A\mathbf{s}") == "b = As"


def test_operators():
    assert latex_unicode(r"a \oplus b \cdot c") == "a ⊕ b · c"
    assert latex_unicode(r"\|z\| \le \beta") == "‖z‖ ≤ β"


def test_size_specifiers_is_dropped():
    assert latex_unicode(r"H\big((K \oplus o)\big)") == "H((K ⊕ o))"


def test_split_marker():
    assert latex_unicode(r"p \nmid a") == "p ∤ a"


def test_inner_in_set_correct_matches():
    """Nested braces have to close correctly."""
    assert latex_unicode(r"\mathrm{Enc}_{K}(m)") == "Enc_K(m)"


def test_untranslatable_upper_index_marked_stays():
    """A superscript with no Unicode equivalent has to be left undamaged."""
    output = latex_unicode("c^{d_p}")
    assert "d_p" in output and output.startswith("c^")


def test_empty_entry():
    assert latex_unicode("") == ""


def test_plain_text_unchanged():
    assert latex_unicode("b = As + e") == "b = As + e"
