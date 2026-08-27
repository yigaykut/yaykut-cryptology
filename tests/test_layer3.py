"""Layer 3, search tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from layer3 import (  # noqa: E402
                    QUESTIONS,
                    Index,
                    build_index,
                    chunk_corpus,
                    evaluate,
                    normalize,
                    split_sentences,
                    tokens,
)
from layer3.text import STOPWORDS  # noqa: E402
from crypto import load_corpus  # noqa: E402

CORPUS = load_corpus()
INDEX = build_index(CORPUS)


# ---------------------------- text ----------------------------

def test_normalize_lowercases():
    assert normalize("SIGNATURE") == "signature"
    assert normalize("Signature") == "signature"


def test_corpus_title_matches_a_query():
    """The title 'ECDSA Signature Generation' should match a 'signature' query."""
    assert "signature" in tokens("ECDSA Signature Generation")


def test_stopwords_are_dropped():
    t = tokens("this and that for the nonce")
    assert "nonce" in t
    assert not (set(t) & STOPWORDS)


def test_single_letter_tokens_are_dropped():
    assert "a" not in tokens("a b nonce")


def test_math_expression_is_not_split():
    """The dot inside '$a. b$' must not be taken for a sentence end."""
    text = "This formula holds: $a. b$ is the expression. Then a second sentence follows."
    sentences = split_sentences(text, min_length=1)
    assert any("$a. b$" in s for s in sentences), sentences


def test_short_pieces_are_merged():
    sentences = split_sentences("Short. Short again. This is short too.", min_length=40)
    assert len(sentences) == 1


def test_empty_text_gives_empty_list():
    assert split_sentences("") == []


# ---------------------------- chunking ----------------------------

def test_every_entry_produces_chunks():
    chunks = chunk_corpus(CORPUS)
    covered = {c.entry_id for c in chunks}
    assert covered == {e.id for e in CORPUS}


def test_chunks_carry_source_information():
    for c in chunk_corpus(CORPUS):
        assert c.entry_id in CORPUS
        assert c.section
        assert c.text.strip()
        assert f"0x{c.entry_id:04X}" in c.source


def test_title_chunk_weighs_more():
    chunks = [c for c in chunk_corpus(CORPUS) if c.entry_id == 0x0101]
    title = next(c for c in chunks if c.section == "title")
    params = next(c for c in chunks if c.section == "params")
    assert title.weight > params.weight


def test_latex_is_kept_in_the_title_chunk():
    chunks = [c for c in chunk_corpus(CORPUS) if c.entry_id == 0x0101]
    title = next(c for c in chunks if c.section == "title")
    assert "y^2" in title.text


# ---------------------------- search ----------------------------

def test_exact_term_finds_the_right_entry():
    results = INDEX.search_entries("Bellcore", k=3)
    assert results[0][0] == 0x0204


def test_suffixed_query_still_matches():
    """A 'passwords' query should find the 'password' term via prefix matching."""
    results = INDEX.search_entries("how should I store passwords", k=3)
    assert 0x0304 in [eid for eid, _, _ in results]


def test_empty_query_gives_empty_results():
    assert INDEX.search("") == []
    assert INDEX.search("and the this") == []


def test_irrelevant_query_gives_nothing():
    assert INDEX.search("zzzqqqxxx", k=5) == []


def test_entry_level_results_are_unique():
    results = INDEX.search_entries("elliptic curve", k=5)
    ids = [eid for eid, _, _ in results]
    assert len(ids) == len(set(ids)), "the same entry was listed more than once"


def test_scores_are_in_descending_order():
    results = INDEX.search("nonce reuse key", k=8)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_k_limits_the_result_count():
    assert len(INDEX.search("cipher", k=3)) <= 3
    assert len(INDEX.search_entries("cipher", k=2)) <= 2


def test_empty_index_does_not_crash():
    empty = Index([])
    assert empty.search("anything at all") == []


# ------------------ quality regression guard ------------------

def test_search_quality_holds_its_threshold():
    """The measured quality must never drop again.

    The thresholds come from the 2026-08-12 measurement (Recall@1 92%,
    Recall@3 100%).

    2026-08-15: when the corpus grew from 34 to 53 entries, Recall@1 fell to
    88%. The cause was not the search logic but BM25's GLOBAL STATISTICS. New
    entries raised the document frequency of terms like "point", "addition"
    and "branchless", diluting their IDF, so a few answers that had been
    narrowly ahead slipped to second place. Recall@3 stayed at 100%, meaning
    the right answer is still in the top three for every question.

    The thresholds were NOT lowered; the measurement is already above them.
    Entry texts were not rewritten to improve the search result, because
    changing text to flatter the index would make the measurement meaningless.
    """
    r = evaluate(INDEX)
    assert r.recall1 >= 0.85, f"Recall@1 regressed: {r.recall1:.3f}"
    assert r.recall3 >= 0.95, f"Recall@3 regressed: {r.recall3:.3f}"
    assert r.mrr >= 0.90, f"MRR regressed: {r.mrr:.3f}"


def test_evaluation_questions_point_at_real_entries():
    """The question set must not have drifted from the corpus."""
    for question in QUESTIONS:
        for eid in question.expected:
            assert eid in CORPUS, (
                f"\"{question.text}\" points at a missing entry: 0x{eid:04X}")


@pytest.mark.parametrize("question", QUESTIONS, ids=lambda q: q.text[:40])
def test_every_question_is_answered_in_the_top_three(question):
    results = INDEX.search_entries(question.text, k=3)
    found = {eid for eid, _, _ in results}
    assert found & question.expected, (
        f"expected {[f'0x{e:04X}' for e in question.expected]}, "
        f"got {[f'0x{e:04X}' for e in found]}"
    )
