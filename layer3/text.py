"""Text processing for search.

Two things matter here.

1. Suffixes. `cipher` and `ciphering` are different terms to BM25. A crude
   stemmer merges things it should not and misses pairs it should catch, so
   PREFIX MATCHING is used instead (see index.py): two terms count as the
   same when one is a prefix of the other. The corpus is small, so the cost
   is negligible and it is far safer than truncating stems.

2. Mathematics. Sentence splitting must not cut through a formula, so `$...$`
   and friends are pulled out before splitting and put back afterwards.
"""

from __future__ import annotations

import re

TOKEN = re.compile(r"[0-9a-z]+")

# Patterns that protect mathematical expressions. Sentence splitting does not
# reach inside them.
MATH = re.compile(r"\$[^$]*\$|\\\[[^\]]*\\\]|\\\([^)]*\\\)")

# High frequency words that contribute nothing to search.
STOPWORDS = frozenset("""
a an the and or but if then else of in on at to for from by with without
is are was were be been being do does did done have has had having
this that these those it its as so such than too very can could may might
must shall should will would not no nor only own same what which who whom
whose when where why how there here all any both each few more most other
some into over under again further once about against between during
""".split())


def normalize(text: str) -> str:
    """Lowercase for indexing."""
    return text.lower()


def tokens(text: str, *, drop_stopwords: bool = True) -> list[str]:
    """Split text into search terms."""
    raw = TOKEN.findall(normalize(text))
    if drop_stopwords:
        return [t for t in raw if t not in STOPWORDS and len(t) > 1]
    return raw


def split_sentences(text: str, *, min_length: int = 40) -> list[str]:
    """Split text into sentences WITHOUT CUTTING MATHEMATICS.

    If the dot inside '$y^2 = x^3 + ax + b$' is taken for a sentence end, the
    formula splits in two and both halves become meaningless. Math blocks are
    swapped for placeholders first and restored after the split.
    """
    kept: list[str] = []

    def stash(m: re.Match) -> str:
        kept.append(m.group(0))
        return f"\x00{len(kept) - 1}\x00"

    safe = MATH.sub(stash, text)

    pieces = re.split(r"(?<=[.!?:])\s+", safe)

    def restore(s: str) -> str:
        return re.sub(r"\x00(\d+)\x00", lambda m: kept[int(m.group(1))], s)

    sentences: list[str] = []
    buffer = ""
    for piece in pieces:
        piece = restore(piece).strip()
        if not piece:
            continue
        # Very short pieces mean nothing on their own, so they join the previous.
        buffer = f"{buffer} {piece}".strip() if buffer else piece
        if len(buffer) >= min_length:
            sentences.append(buffer)
            buffer = ""
    if buffer:
        if sentences:
            sentences[-1] = f"{sentences[-1]} {buffer}"
        else:
            sentences.append(buffer)
    return sentences
