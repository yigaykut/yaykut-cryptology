"""layer3: the cryptography assistant, the R in RAG.

Search over the corpus. Approximate matching is LEGITIMATE here, because in
question answering the goal is relevance rather than invertibility. For why
the same approach is unacceptable on the cipher path, see ADR-001.

This layer does not GENERATE text; it returns the relevant corpus entries
with citations. Generation needs a language model and that is a separate
decision.
"""

from .evaluate import QUESTIONS, Question, Report, evaluate
from .index import Index, Result, build_index
from .text import normalize, split_sentences, tokens
from .chunk import Chunk, chunk_corpus

__all__ = [
    "Index", "Result", "build_index",
    "Chunk", "chunk_corpus",
    "normalize", "tokens", "split_sentences",
    "evaluate", "Report", "Question", "QUESTIONS",
]
