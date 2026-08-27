"""Splits corpus entries into searchable chunks.

DESIGN DECISION: chunking follows structure rather than a fixed character
window. A corpus entry already comes divided into meaningful sections
(summary, notes, parameters, constraints), and cutting through those with a
blind window would both split formulas and scatter the context.

Every chunk carries which entry and which section it came from, so the
assistant can cite a source.
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto.corpus import Corpus, Entry

from .text import split_sentences


@dataclass(frozen=True)
class Chunk:
    """A single searchable piece of text."""

    entry_id: int
    slug: str
    section: str        # title | summary | notes | params | constraints
    text: str
    title: str          # the entry's name, for display
    latex: str = ""
    weight: float = 1.0

    @property
    def source(self) -> str:
        return f"0x{self.entry_id:04X} {self.title} > {self.section}"


def _chunk_entry(e: Entry) -> list[Chunk]:
    doc = e.doc
    name = doc.get("name", e.slug)
    latex = doc.get("latex", "")
    chunks: list[Chunk] = []

    def add(section: str, text: str, weight: float = 1.0) -> None:
        text = " ".join(text.split())
        if text:
            chunks.append(
                Chunk(e.id, e.slug, section, text, name, latex, weight)
            )

    # The title chunk: name, formula, domain and tags together. Short and
    # dense, so it carries a high weight and is what a "what is ECDSA" style
    # question hits.
    tags = " ".join(doc.get("tags", []))
    add("title", f"{name} {latex} {doc.get('domain', '')} {tags}", weight=2.0)

    add("summary", doc.get("summary", ""), weight=1.5)

    # Notes are long and cover several topics (traps, history, attacks). They
    # are split into sentence groups so a question about "the Bellcore attack"
    # is not diluted by unrelated sentences in the same entry.
    for i, sentence in enumerate(split_sentences(doc.get("notes", ""))):
        add(f"notes[{i + 1}]", sentence)

    # Parameter descriptions: terms like "private key" and "nonce" live here.
    param_text = " ".join(
        f"{p.get('name', '')} {p.get('description', '')}" for p in e.params
    )
    add("params", param_text, weight=0.8)

    # Constraint reasons: questions like "why does gcd have to be 1" land here.
    constraint_text = " ".join(
        f"{c.get('expr', '')} {c.get('reason', '')}" for c in e.constraints
    )
    add("constraints", constraint_text, weight=0.8)

    return chunks


def chunk_corpus(corpus: Corpus) -> list[Chunk]:
    """Splits the whole corpus into chunks."""
    return [c for e in corpus for c in _chunk_entry(e)]
