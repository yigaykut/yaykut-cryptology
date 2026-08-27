"""Measuring search quality.

"I built a RAG and it seems to work" is not an engineering statement. This
holds a hand written question set with expected answers, and reports quality
as a number. Whether an embedding model is worth adding is answered by
looking at this measurement.

Some questions deliberately AVOID THE OBVIOUS TERM (the password question
does not contain "PBKDF2"), because that is where lexical search struggles.
"""

from __future__ import annotations

from dataclasses import dataclass

from .index import Index


@dataclass(frozen=True)
class Question:
    text: str
    expected: frozenset[int]
    note: str = ""


# Each question's answer is the entry (or entries) covering that topic.
QUESTIONS: list[Question] = [
    Question("what happens if the same nonce is used twice in ECDSA",
             frozenset({0x0106})),
    Question("which curve form has complete branchless point addition",
             frozenset({0x0104})),
    Question("how is the length extension attack prevented",
             frozenset({0x0301, 0x0302})),
    Question("what is the Bellcore attack",
             frozenset({0x0204})),
    Question("which mistake did VENONA exploit",
             frozenset({0x0505})),
    Question("which cipher does Kasiski analysis break",
             frozenset({0x0503})),
    Question("what is the only nonlinear component of AES",
             frozenset({0x0602})),
    Question("which AES layer provides diffusion",
             frozenset({0x0603})),
    Question("which key derivation should be used when storing a password",
             frozenset({0x0304}), "the term PBKDF2 does not appear in the question"),
    Question("why should I use a 256 bit digest collision resistance",
             frozenset({0x0305})),
    Question("why is the public exponent chosen as 65537",
             frozenset({0x0203, 0x0201})),
    Question("Wiener attack small private exponent",
             frozenset({0x0203})),
    Question("lattice based learning with errors problem",
             frozenset({0x0401, 0x0402})),
    Question("fast polynomial multiplication with the number theoretic transform",
             frozenset({0x0402})),
    Question("key exchange open to a man in the middle attack",
             frozenset({0x0206})),
    Question("Shannon perfect secrecy proof",
             frozenset({0x0505})),
    Question("why is nonce reuse dangerous in counter mode",
             frozenset({0x0604})),
    Question("ARX design constant time stream cipher",
             frozenset({0x0605})),
    Question("Montgomery ladder side channel resistance",
             frozenset({0x0103})),
    Question("the multiplier key has to be coprime to 26",
             frozenset({0x0502})),
    Question("does the F function in a Feistel network have to be invertible",
             frozenset({0x0601})),
    Question("what is the capacity for in a sponge construction",
             frozenset({0x0303})),
    Question("speeding up RSA decryption with the Chinese remainder theorem",
             frozenset({0x0204})),
    Question("why do Carmichael numbers fool a primality test",
             frozenset({0x0205, 0x020A}),
             "0x020A was added to the corpus later and is directly about this: "
             "why Carmichael numbers pass the Fermat test and how Miller-Rabin "
             "closes that. The set was written when there was one answer and "
             "was left incomplete after the entry was added."),
    Question("why is a curve unusable when the discriminant is zero",
             frozenset({0x0101, 0x0102})),
]


@dataclass
class Report:
    recall1: float
    recall3: float
    recall5: float
    mrr: float
    failures: list[tuple[Question, list[int]]]

    @property
    def question_count(self) -> int:
        return len(QUESTIONS)


def evaluate(index: Index, questions: list[Question] | None = None, *, k: int = 5) -> Report:
    """Runs the question set and computes recall and MRR.

    MRR (mean reciprocal rank): a correct answer in first place contributes
    1.0, second place 0.5, third 0.33. It reduces ranking quality to a single
    number, which is more informative than just asking "is it in the top 5".
    """
    questions = questions or QUESTIONS
    r1 = r3 = r5 = 0
    mrr_total = 0.0
    failures: list[tuple[Question, list[int]]] = []

    for question in questions:
        results = index.search_entries(question.text, k=k)
        found = [eid for eid, _, _ in results]

        rank = next(
            (i + 1 for i, eid in enumerate(found) if eid in question.expected),
            None,
        )
        if rank is not None:
            mrr_total += 1 / rank
            r1 += rank <= 1
            r3 += rank <= 3
            r5 += rank <= 5
        if rank is None or rank > 3:
            failures.append((question, found[:3]))

    n = len(questions)
    return Report(r1 / n, r3 / n, r5 / n, mrr_total / n, failures)
