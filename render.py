"""Turns LaTeX source into readable Unicode mathematics.

Corpus formulas are stored as LaTeX, because that is the canonical form and
it matches citations and publications. But showing `\\varphi(n) = (p-1)(q-1)`
on screen is unreadable. This module is the presentation layer: it does not
change the source, it converts the display.

It is NOT a full LaTeX parser. It covers only the constructs the corpus uses
and leaves what it cannot translate untouched. If a construct outside that
range is added, the test (`test_render.py`) catches it.
"""

from __future__ import annotations

import re

# -- symbol maps -----------------------------------------------------

SYMBOL = {
    # greek letters
    r"\alpha": "α", r"\beta": "β", r"\gamma": "γ", r"\delta": "δ",
    r"\epsilon": "ε", r"\zeta": "ζ", r"\eta": "η", r"\theta": "θ",
    r"\iota": "ι", r"\kappa": "κ", r"\lambda": "λ", r"\mu": "μ",
    r"\nu": "ν", r"\xi": "ξ", r"\pi": "π", r"\rho": "ρ",
    r"\sigma": "σ", r"\tau": "τ", r"\phi": "φ", r"\varphi": "φ",
    r"\chi": "χ", r"\psi": "ψ", r"\omega": "ω",
    r"\Delta": "Δ", r"\Sigma": "Σ", r"\Omega": "Ω", r"\Psi": "Ψ",
    r"\Gamma": "Γ", r"\Lambda": "Λ", r"\Phi": "Φ",
    # relations
    r"\equiv": "≡", r"\approx": "≈", r"\neq": "≠", r"\ne": "≠",
    r"\leq": "≤", r"\le": "≤", r"\geq": "≥", r"\ge": "≥",
    r"\in": "∈", r"\notin": "∉", r"\subset": "⊂", r"\subseteq": "⊆",
    r"\mid": "∣", r"\nmid": "∤", r"\sim": "∼", r"\propto": "∝",
    # operations
    r"\oplus": "⊕", r"\otimes": "⊗", r"\cdot": "·", r"\times": "×",
    r"\div": "÷", r"\pm": "±", r"\mp": "∓", r"\ast": "∗",
    r"\wedge": "∧", r"\vee": "∨", r"\lll": "⋘", r"\ggg": "⋙",
    # oklar
    r"\to": "→", r"\rightarrow": "→", r"\leftarrow": "←",
    r"\mapsto": "↦", r"\Rightarrow": "⇒", r"\iff": "⇔",
    # quantifiers
    r"\sum": "Σ", r"\prod": "Π", r"\int": "∫", r"\infty": "∞",
    r"\forall": "∀", r"\exists": "∃", r"\partial": "∂", r"\nabla": "∇",
    # special letters
    r"\ell": "ℓ", r"\hbar": "ℏ", r"\aleph": "ℵ", r"\emptyset": "∅",
    # dots and spacing
    r"\cdots": "⋯", r"\ldots": "…", r"\dots": "…", r"\vdots": "⋮",
    r"\quad": "  ", r"\qquad": "    ",
    r"\,": " ", r"\;": " ", r"\:": " ", r"\!": "", "\\ ": " ",
    # delimiters and escaped marks
    r"\|": "‖", r"\{": "{", r"\}": "}", r"\%": "%",
    r"\#": "#", r"\&": "&", r"\_": "_", r"\$": "$",
    r"\langle": "⟨", r"\rangle": "⟩",
    # size specifiers: no visual effect here, dropped
    r"\left": "", r"\right": "",
    r"\big": "", r"\Big": "", r"\bigg": "", r"\Bigg": "",
    r"\bigl": "", r"\bigr": "", r"\Bigl": "", r"\Bigr": "",
}

# double struck letters: \mathbb{Z} -> Z
DOUBLE_RULE = {
    "A": "𝔸", "C": "ℂ", "F": "𝔽", "N": "ℕ", "P": "ℙ",
    "Q": "ℚ", "R": "ℝ", "Z": "ℤ", "H": "ℍ", "E": "𝔼",
}

TOP = str.maketrans("0123456789+-=()ni*abcdefghjklmoprstuvwxyz",
                    "⁰¹²³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾ⁿⁱ*ᵃᵇᶜᵈᵉᶠᵍʰʲᵏˡᵐᵒᵖʳˢᵗᵘᵛʷˣʸᶻ")
ALT = str.maketrans("0123456789+-=()aehijklmnoprstuvx",
                    "₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎ₐₑₕᵢⱼₖₗₘₙₒₚᵣₛₜᵤᵥₓ")


def _set(text: str, i: int) -> tuple[str, int]:
    """Returns what is between the '{' at position i and its matching '}'."""
    if i >= len(text) or text[i] != "{":
        return text[i:i + 1], i + 1
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i + 1:j], j + 1
        j += 1
    return text[i + 1:], len(text)


def _map_index(body: str, table, sign: str) -> str:
    """Converts a super or subscript to Unicode, leaving it marked if it cannot."""
    try:
        translated = body.translate(table)
    except Exception:
        return f"{sign}({body})"
    if all(ord(c) > 127 or c in " *" for c in translated):
        return translated
    if len(body) == 1:
        return f"{sign}{body}"
    # already bracketed, do not wrap a second time
    if body.startswith("(") and body.endswith(")"):
        return f"{sign}{body}"
    return f"{sign}({body})"


def latex_unicode(source: str) -> str:
    """Turns LaTeX source into readable one line Unicode text."""
    if not source:
        return ""

    s = source

    # \frac{a}{b} -> a/b  (a side longer than one character gets brackets)
    def wrap(t: str) -> str:
        return t if len(t) <= 2 else f"({t})"

    while r"\frac" in s:
        i = s.index(r"\frac") + 5
        numerator, j = _set(s, i)
        denominator, k = _set(s, j)
        s = s[:i - 5] + f"{wrap(latex_unicode(numerator))}/{wrap(latex_unicode(denominator))}" + s[k:]

    # \pmod{q} -> (mod q)   \bmod -> mod
    while r"\pmod" in s:
        i = s.index(r"\pmod") + 5
        content, j = _set(s, i)
        s = s[:i - 5] + f"(mod {latex_unicode(content)})" + s[j:]
    s = s.replace(r"\bmod", "mod")

    # \sqrt{x} -> √x
    while r"\sqrt" in s:
        i = s.index(r"\sqrt") + 5
        content, j = _set(s, i)
        s = s[:i - 5] + "√" + latex_unicode(content) + s[j:]

    # \mathbb{Z} -> Z ; other font commands reduce to their content
    while r"\mathbb" in s:
        i = s.index(r"\mathbb") + 7
        content, j = _set(s, i)
        s = s[:i - 7] + DOUBLE_RULE.get(content.strip(), content) + s[j:]

    for command in (r"\mathrm", r"\mathbf", r"\mathit", r"\mathsf",
                    r"\mathcal", r"\mathrel", r"\mathbin", r"\text",
                    r"\operatorname"):
        while command in s:
            i = s.index(command) + len(command)
            content, j = _set(s, i)
            s = s[:i - len(command)] + content + s[j:]

    # replace symbols longest first (so \lll does not clash with \le)
    for command in sorted(SYMBOL, key=len, reverse=True):
        s = s.replace(command, SYMBOL[command])

    # superscripts and subscripts
    output, i = [], 0
    while i < len(s):
        c = s[i]
        if c in "^_" and i + 1 < len(s):
            body, j = _set(s, i + 1)
            table = TOP if c == "^" else ALT
            output.append(_map_index(body, table, c))
            i = j
        else:
            output.append(c)
            i += 1
    s = "".join(output)

    # leftover backslashes and extra whitespace
    s = re.sub(r"\\([a-zA-Z]+)", r"\1", s)
    s = re.sub(r"[ \t]{2,}", "  ", s).strip()
    return s
