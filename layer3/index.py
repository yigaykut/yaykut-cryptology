"""BM25 search index.

Why BM25 and not embeddings:

The corpus is 34 entries full of technical terms, ECDSA, nonce, Kerckhoffs,
LWE, Bellcore. For queries like those EXACT TERM MATCH is the strongest
signal, and BM25 measures exactly that. Before downloading a 500 MB embedding
model the quality had to be measured; `python assistant.py --evaluate` does
that measurement.

An embedding model's real benefit is paraphrase and synonymy, such as a
question about "how do I store a password" finding the PBKDF2 entry. If the
measurement ever comes out insufficient, one should be added, keeping the
`Index.search()` interface unchanged.

SUFFIXES
`cipher` and `ciphering` are different terms to BM25. Crude stem truncation
both merges things wrongly and misses pairs it should catch. PREFIX MATCHING
is used instead: two terms count as the same when one is a prefix of the
other and they share at least PREFIX_MIN characters. The vocabulary is small,
so the cost is negligible.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from .chunk import Chunk
from .text import tokens

K1 = 1.5          # term frequency saturation
B = 0.75          # length normalisation
PREFIX_MIN = 4    # characters a prefix match has to share
PREFIX_PENALTY = 0.6  # weight factor for an inexact match


@dataclass
class Result:
    chunk: Chunk
    score: float
    matched: list[str]

    @property
    def entry_id(self) -> int:
        return self.chunk.entry_id


class Index:
    """BM25 search over chunks."""

    def __init__(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self._tf: list[Counter] = []
        self._length: list[int] = []
        self._df: Counter = Counter()
        self._postings: defaultdict[str, list[int]] = defaultdict(list)

        for i, c in enumerate(chunks):
            tf = Counter(tokens(c.text))
            self._tf.append(tf)
            self._length.append(sum(tf.values()))
            for term in tf:
                self._df[term] += 1
                self._postings[term].append(i)

        self.N = len(chunks)
        self.avg_length = (sum(self._length) / self.N) if self.N else 0.0
        self.vocabulary = sorted(self._df)

    # -- term matching ------------------------------------------------

    def _matches(self, query_term: str) -> list[tuple[str, float]]:
        """Vocabulary terms matching a query term, with their weights.

        An exact match weighs 1.0, a prefix relation weighs PREFIX_PENALTY.
        """
        out: list[tuple[str, float]] = []
        if query_term in self._df:
            out.append((query_term, 1.0))

        if len(query_term) >= PREFIX_MIN:
            for term in self.vocabulary:
                if term == query_term or len(term) < PREFIX_MIN:
                    continue
                if term.startswith(query_term) or query_term.startswith(term):
                    out.append((term, PREFIX_PENALTY))
        return out

    def _idf(self, term: str) -> float:
        n = self._df.get(term, 0)
        return math.log(1 + (self.N - n + 0.5) / (n + 0.5))

    # -- search -------------------------------------------------------

    def search(self, query: str, *, k: int = 5) -> list[Result]:
        """Returns the k chunks that best match the query."""
        query_terms = tokens(query)
        if not query_terms or self.N == 0:
            return []

        scores: defaultdict[int, float] = defaultdict(float)
        matched: defaultdict[int, set[str]] = defaultdict(set)

        for qt in query_terms:
            for term, weight in self._matches(qt):
                idf = self._idf(term)
                for i in self._postings[term]:
                    f = self._tf[i][term]
                    norm = 1 - B + B * (self._length[i] / self.avg_length)
                    contribution = idf * (f * (K1 + 1)) / (f + K1 * norm)
                    scores[i] += contribution * weight * self.chunks[i].weight
                    matched[i].add(term)

        ranked = sorted(scores.items(), key=lambda t: -t[1])[:k]
        return [
            Result(self.chunks[i], score, sorted(matched[i]))
            for i, score in ranked
            if score > 0
        ]

    def search_entries(self, query: str, *, k: int = 5) -> list[tuple[int, float, Result]]:
        """Returns results at ENTRY level rather than chunk level.

        When several chunks from the same entry match, the entry is listed
        once and its highest scoring chunk represents it. That is how a user
        gets an answer to "which formula".
        """
        raw = self.search(query, k=k * 4)
        best: dict[int, Result] = {}
        total: defaultdict[int, float] = defaultdict(float)

        for r in raw:
            total[r.entry_id] += r.score
            if r.entry_id not in best or r.score > best[r.entry_id].score:
                best[r.entry_id] = r

        ranked = sorted(total.items(), key=lambda t: -t[1])[:k]
        return [(eid, score, best[eid]) for eid, score in ranked]


def build_index(corpus) -> Index:
    from .chunk import chunk_corpus
    return Index(chunk_corpus(corpus))
