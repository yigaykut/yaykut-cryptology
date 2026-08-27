"""Cryptography assistant, search over the corpus.

    python assistant.py "nonce reuse in ECDSA"     a single query
    python assistant.py                            interactive
    python assistant.py --evaluate                 measure search quality

The assistant does not GENERATE text. It returns the relevant corpus entries
with citations, so every answer shows which section of which entry it came
from.
"""

from __future__ import annotations

import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from layer3 import evaluate, build_index  # noqa: E402
from crypto import load_corpus  # noqa: E402


def print_results(index, query: str, k: int = 4) -> None:
    results = index.search_entries(query, k=k)
    if not results:
        print("  No match found.\n")
        return

    for rank, (eid, score, best) in enumerate(results, 1):
        entry = CORPUS.get(eid)
        print(f"\n  {rank}. 0x{eid:04X}  {entry.name}   (score {score:.2f})")
        if entry.doc.get("latex"):
            print(f"     $ {entry.doc['latex']} $")
        print(f"     section : {best.chunk.section}")
        print(f"     matched terms: {', '.join(best.matched[:8])}")

        text = best.chunk.text
        print(f"     -- {text[:260]}{'...' if len(text) > 260 else ''}")
    print()


def print_evaluation(index) -> None:
    print("\n" + "=" * 74)
    print("  SEARCH QUALITY")
    print("=" * 74)

    r = evaluate(index)
    print(f"\n  Questions : {r.question_count}")
    print(f"  Recall@1  : {r.recall1 * 100:.1f}%   (correct entry first)")
    print(f"  Recall@3  : {r.recall3 * 100:.1f}%   (in the top three)")
    print(f"  Recall@5  : {r.recall5 * 100:.1f}%   (in the top five)")
    print(f"  MRR       : {r.mrr:.3f}   (1.0 means always first)")

    if r.failures:
        print(f"\n  {len(r.failures)} questions missed the top three:")
        for question, found in r.failures:
            expected = ", ".join(f"0x{e:04X}" for e in sorted(question.expected))
            got = ", ".join(f"0x{e:04X}" for e in found) or "-"
            print(f"\n    \"{question.text}\"")
            print(f"      expected : {expected}")
            print(f"      got      : {got}")
            if question.note:
                print(f"      note     : {question.note}")
    else:
        print("\n  Every question was answered in the top three.")

    print("\n" + "-" * 74)
    print("  Reading it: this measures lexical (BM25) search. The benefit of")
    print("  adding an embedding model shows up in the failing questions that")
    print("  contain no direct term. If the measurement is good enough there is")
    print("  no reason to add a 500 MB dependency.")
    print()


CORPUS = load_corpus()
INDEX = build_index(CORPUS)

if __name__ == "__main__":
    args = sys.argv[1:]

    if args and args[0] == "--evaluate":
        print_evaluation(INDEX)
        sys.exit(0)

    print(f"Corpus: {len(CORPUS)} entries, {len(INDEX.chunks)} chunks, "
          f"{len(INDEX.vocabulary)} terms")

    if args:
        query = " ".join(args)
        print(f"\nQuery: \"{query}\"")
        print_results(INDEX, query)
        sys.exit(0)

    print("Type a question, an empty line exits.\n")
    while True:
        try:
            query = input("? ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not query:
            break
        print_results(INDEX, query)
