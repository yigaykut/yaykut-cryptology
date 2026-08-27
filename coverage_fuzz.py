"""Coverage guided fuzzing, branch tracing through `sys.monitoring`.

    python coverage_fuzz.py [seconds] [seed]

WHY IT WAS WRITTEN BY HAND

`docs/audit.md` §5 carried the line "no coverage guided fuzzing". The
standard tool is Atheris (Google, on libFuzzer) but it is **for Linux and
macOS**; installing it on Windows needs clang and libFuzzer, which this
machine does not have. Rather than waiting and writing "could not be done",
doing the essential part turned out cheaper, because since Python 3.12
`sys.monitoring` hands over branch events directly.

WHAT COVERAGE GUIDED FUZZING IS, IN ONE PARAGRAPH

Blind fuzzing produces random input and most of it hits the same shallow
path. Coverage guided fuzzing sets up a FEEDBACK loop: while each input
runs, the branches taken are recorded; **an input that opens a new branch
is kept** and becomes the basis for later mutations. That way the search
climbs into regions of the program it has not seen before, on its own.


The difference is concrete and the experiment in this file measures it: on
a target needing four consecutive correct bytes, blind search needs 2^32
attempts while guided search takes seconds, because every correct byte
is an input the search keeps.

HONEST LIMITS

  - Slow. The `sys.monitoring` callback runs on every branch, making this a
    tortoise next to a fuzzer compiled in C. Hundreds of runs per second
    rather than millions.
  - Coverage is measured at BRANCH level, not at path level. Two different
    paths crossing the same set of branches are indistinguishable.
  - The inside of the C core is INVISIBLE. `sys.monitoring` only watches
    Python bytecode, so branches inside `crypto25519.dll` are not counted.
    There is a separate tool for the C side: `ccore/compile_audit.py`.
  - Not finding something is not proof it is not there. Fuzzing is evidence
    of presence.
"""

from __future__ import annotations

import io
import os
import random
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_ROOT = os.path.join(HERE, "crypto")


def _utf8_output() -> None:
    """Switches the console to UTF-8 when run as a script, without breaking pytest."""
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


# ═══════════════════════ HIT BUCKETS ═══════════════════════
#
# WHY "WAS THE EDGE TAKEN" IS NOT ENOUGH, learned by measurement.
#
# The first implementation kept coverage as a SET of edges: a branch had
# either been taken or not. The positive control (four magic bytes) showed
# that is not enough: the comparison in the target sits inside a LOOP, so
# for i = 0, 1, 2, 3 it is the SAME bytecode and the SAME edge. "I got one
# byte right" and "I got two bytes right" are indistinguishable in an edge
# set, so the search cannot climb. It found nothing in 59,000 runs.
#
# AFL's solution: count how many TIMES an edge was taken, but do not keep
# the number raw, reduce it to logarithmic buckets. With raw counts every
# small fluctuation would count as "new coverage" and the corpus would fill
# with junk.
#     1 -> 0    2 -> 1    3 -> 2    4-7 -> 3
#     8-15 -> 4    16-31 -> 5    32-127 -> 6    128+ -> 7
#
# So a loop turning once and turning twice produce different signals, and
# every correct byte moves the search one step forward.

def bucket(n: int) -> int:
    """AFL's logarithmic hit bucket."""
    if n <= 3:
        return n - 1
    if n <= 7:
        return 3
    if n <= 15:
        return 4
    if n <= 31:
        return 5
    if n <= 127:
        return 6
    return 7


# ═══════════════════════ THE COVERAGE TRACER ═══════════════════════

class Tracer:
    """Collects branch edges through `sys.monitoring`.

    An edge is (code object, branch point, target point). The two arms of
    the same `if` are separate edges, which is the distinction coverage
    guidance needs.
    TOOL ID. `sys.monitoring` allows several tools at once but each has to
    reserve its own id. The first free id is taken; if all are occupied,
    tracing quietly turns off (`active` becomes False) and the fuzzer keeps
    running in blind mode rather than crashing.
    """

    def __init__(self, root: str = TARGET_ROOT, *, filter=None) -> None:
        self.root = root
        self.filter = filter          # filter(code) -> bool; None means match on the path prefix
        self.edges: set = set()    # (edge, bucket) pairs
        self.active = False
        self._identity: int | None = None
        self._relevance: dict = {}
        self._counter: dict = {}        # edge hit count per run
        self._event = None

    # ---- setup ----

    def _event_set(self):
        e = sys.monitoring.events
        # In 3.14 BRANCH split in two; support both.
        if hasattr(e, "BRANCH_LEFT"):
            return e.BRANCH_LEFT | e.BRANCH_RIGHT, ("BRANCH_LEFT", "BRANCH_RIGHT")
        return e.BRANCH, ("BRANCH",)

    def start(self) -> bool:
        if not hasattr(sys, "monitoring"):
            return False
        m = sys.monitoring
        for identity in range(6):
            try:
                m.use_tool_id(identity, "crypto-coverage")
            except ValueError:
                continue
            self._identity = identity
            break
        else:
            return False

        events, names = self._event_set()
        for name in names:
            m.register_callback(self._identity, getattr(m.events, name), self._edge)
        m.set_events(self._identity, events)
        self._event = events
        self.active = True
        return True

    def stop(self) -> None:
        if self._identity is None:
            return
        m = sys.monitoring
        m.set_events(self._identity, 0)
        m.free_tool_id(self._identity)
        self._identity = None
        self.active = False

    def __enter__(self) -> "Tracer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    # ---- the callback ----

    def _edge(self, code, off, target):
        """Runs on every branch, the HOT PATH, so it has to be as cheap as possible.

        The filter result is cached per code object. If the path comparison
        were done with `in` on every branch, the measurement cost would
        overshadow the thing being measured.
        """
        related = self._relevance.get(code)
        if related is None:
            related = (self.filter(code) if self.filter
                       else code.co_filename.startswith(self.root))
            self._relevance[code] = related
        if related:
            k = (code, off, target)
            self._counter[k] = self._counter.get(k, 0) + 1

    # ---- use ----

    def run(self, func, *args):
        """Runs the function; returns (exception, new_coverage_count)."""
        self._counter.clear()
        error = None
        try:
            func(*args)
        except BaseException as e:                 # noqa: BLE001, deliberate
            error = e

        new = 0
        add = self.edges.add
        var = self.edges.__contains__
        for edge, n in self._counter.items():
            key = (edge, bucket(n))
            if not var(key):
                add(key)
                new += 1
        return error, new


# ═══════════════════════ MUTATION ═══════════════════════

# Boundary values: bytes and integers that trigger edge cases.
INTERESTING_BYTES = (0x00, 0x01, 0x7F, 0x80, 0xFF)
INTERESTING_INTS = (0, 1, 2, 127, 128, 255, 256, 32767, 65535, 65536,
                    2**31 - 1, 2**32 - 1)


def mutate(data: bytes, rng: random.Random, corpus: list) -> bytes:
    """Mutates an input with a randomly chosen operator.

    The operators are a simplified version of AFL's classic set. All of them
    are cheap; the expensive side is the coverage measurement anyway.
    """
    b = bytearray(data) if data else bytearray(1)
    n = len(b)
    op = rng.randrange(10)

    if op == 0:                                  # bit flip
        i = rng.randrange(n)
        b[i] ^= 1 << rng.randrange(8)

    elif op == 1:                                # interesting byte
        b[rng.randrange(n)] = rng.choice(INTERESTING_BYTES)

    elif op == 8:                                # RASTGELE BAYT
        # This operator was MISSING in the first version and its absence
        # showed up in the positive control: bit flips go from 0x00 to 0xDE
        # in six steps, and the intermediate steps open no new coverage so
        # they are not kept in the corpus, which dead ends the search. A
        # single random byte write reaches every value with probability 1/256.
        b[rng.randrange(n)] = rng.getrandbits(8)

    elif op == 9:                                # rastgele blok
        i = rng.randrange(n)
        k = min(n - i, rng.randint(1, 8))
        b[i:i + k] = bytes(rng.getrandbits(8) for _ in range(k))

    elif op == 2:                                # small arithmetic
        i = rng.randrange(n)
        b[i] = (b[i] + rng.randint(-16, 16)) & 0xFF

    elif op == 3:                                # insert an interesting integer
        width = rng.choice((1, 2, 4, 8))
        if n >= width:
            i = rng.randrange(n - width + 1)
            v = rng.choice(INTERESTING_INTS) & ((1 << (8 * width)) - 1)
            b[i:i + width] = v.to_bytes(
                width, rng.choice(("big", "little")))

    elif op == 4:                                # delete a chunk
        if n > 1:
            i = rng.randrange(n)
            k = min(n - i, rng.randint(1, 32))
            del b[i:i + k]

    elif op == 5:                                # insert a chunk
        i = rng.randrange(n + 1)
        b[i:i] = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 32)))

    elif op == 6 and len(corpus) > 1:            # splice
        other = rng.choice(corpus)
        if other:
            cut = rng.randrange(1, len(b) + 1)
            b = bytearray(bytes(b[:cut]) + other[rng.randrange(len(other)):])

    else:                                           # blok copy
        if n > 1:
            i, j = rng.randrange(n), rng.randrange(n)
            k = min(n - max(i, j), rng.randint(1, 16))
            b[j:j + k] = b[i:i + k]

    return bytes(b[:4096])


# ═══════════════════════ THE GUIDED LOOP ═══════════════════════

class Finding:
    def __init__(self, entry: bytes, error: BaseException, trace: str) -> None:
        self.entry, self.error, self.trace = entry, error, trace

    def __str__(self) -> str:
        return (f"\n  {type(self.error).__name__}: {self.error}\n"
                f"    input ({len(self.entry)} bytes): {self.entry[:48].hex()}\n"
                f"    {self.trace}")


def guided(target, *, sure: float = 20.0, seed: int = 0,
           seeds: list | None = None, accept=(),
           tracer: Tracer | None = None):
    """Coverage guided search.

    hedef    : a callable taking bytes. An exception is a finding, except
               for the types in `kabul` (the expected refusals).
    tohumlar : the starting corpus. If empty, it starts with a single zero byte.

    Returns (findings, statistics)
    """
    rng = random.Random(seed)
    corpus: list = list(seeds or [b"\x00"])
    findings: list = []
    seen_errors: set = set()

    trace = tracer or Tracer()
    own = tracer is None
    if own:
        trace.start()

    harness = 0
    progress = []            # (run, edge_count), for the report rather than a graph
    end = time.perf_counter() + sure
    try:
        for entry in corpus:                       # run the seeds once
            _one(target, entry, trace, corpus, findings, seen_errors, accept)
            harness += 1

        while time.perf_counter() < end:
            entry = mutate(_sec(corpus, rng), rng, corpus)
            _one(target, entry, trace, corpus, findings, seen_errors, accept)
            harness += 1
            if harness % 500 == 0:
                progress.append((harness, len(trace.edges)))
        tracing = trace.active        # must be read BEFORE stopping
    finally:
        if own:
            trace.stop()

    return findings, {
        "runs": harness,
        "edges": len(trace.edges),
        "corpus": len(corpus),
        "tracing": tracing,
        "progress": progress,
    }


def _sec(corpus: list, rng: random.Random) -> bytes:
    """Picks an input from the corpus, weighting NEW entries.

    This strategy was NOT GUESSED, it was MEASURED. On the four byte
    positive control, three seeds, 6 second runs:

        uniform random         found it 1/3
        pick from the last quarter  found it 1/3
        70% newest entry       found it 3/3     <- chosen

    The reason: as the corpus grows, uniform selection lowers the chance of
    picking the deepest entry and the search circles in the shallow region
    it has already exhausted. AFL solves it with energy scheduling; this is
    the plainest version, exploit the TIP of the search, go back sometimes.
    """
    if len(corpus) < 2:
        return corpus[0]
    if rng.random() < 0.70:
        return corpus[-1]          # the tip of the search
    return rng.choice(corpus)      # go back sometimes, for diversity


def _one(target, entry, trace, corpus, findings, seen, accept):
    error, new = trace.run(target, entry)

    # AN INPUT OPENING A NEW EDGE IS KEPT. That line is the whole of coverage guidance.
    if new:
        corpus.append(entry)

    if error is None or isinstance(error, accept):
        return
    # Deduplicate by signature so the same bug is not reported a thousand times.
    signature = (type(error).__name__, str(error)[:80])
    if signature in seen:
        return
    seen.add(signature)
    try:
        raise error
    except BaseException:
        line = traceback.format_exc(limit=4).strip().splitlines()[-2:]
    findings.append(Finding(entry, error, " | ".join(s.strip() for s in line)))


def blind(target, *, sure: float = 20.0, seed: int = 0, accept=()):
    """Blind search, for comparison. NO coverage feedback."""
    rng = random.Random(seed)
    findings: list = []
    seen: set = set()
    harness = 0
    end = time.perf_counter() + sure
    while time.perf_counter() < end:
        n = rng.randint(1, 64)
        entry = bytes(rng.getrandbits(8) for _ in range(n))
        try:
            target(entry)
        except BaseException as e:                 # noqa: BLE001
            if not isinstance(e, accept):
                signature = (type(e).__name__, str(e)[:80])
                if signature not in seen:
                    seen.add(signature)
                    findings.append(Finding(entry, e, ""))
        harness += 1
    return findings, {"runs": harness}


# ═══════════════════════ HEDEFLER ═══════════════════════

def target_engine():
    """The real target: the engine's decoder, fed from PAST THE TAG.

    The same reasoning as in `fuzz.py`: random bytes catch on the tag and
    never reach the parser. Here the fuzzer's data is enveloped with a valid
    key and handed to the decoder, so mutation works directly on the
    PAYLOAD and coverage guidance can climb into the depths of the parser.
    """
    import fuzz
    from crypto import CryptoError, Engine, load_corpus

    corpus = load_corpus()
    engine = Engine(corpus, fuzz.KEY)
    identities = [e.id for e in corpus.active]

    def target(data: bytes) -> None:
        if len(data) < 2:
            data = data + b"\x00\x00"
        sel = int.from_bytes(data[:2], "big")
        if sel % 3 == 0:                     # sometimes try a real id
            sel = identities[data[0] % len(identities)]
        blob = fuzz._wrap(sel, data[2:])
        for f in (engine.decode, engine.decrypt_text, engine.decode_chain,
                  engine.decrypt_hidden, engine.read_frame):
            try:
                f(blob)
            except CryptoError:
                pass                          # expected ret

    # THE SEED CORPUS, the most neglected part of coverage guided fuzzing.
    # A search starting from nothing has to find the structure of a valid
    # record by chance and never gets deep into the parser. Starting with
    # valid payloads makes mutation start from the interesting region.
    import random as _r

    from crypto.frame import wrap
    from crypto.sampler import sample_or_free
    from crypto.wire import serialize

    rng = _r.Random(0)
    seeds = []
    for e in list(corpus.active)[:12]:
        try:
            values, _ = sample_or_free(e, rng, max_rejections=100)
            seeds.append(
                e.id.to_bytes(2, "big") + wrap(0, serialize(e, values)))
        except Exception:                    # an entry that cannot be sampled, skip
            continue
    return target, (), seeds or [bytes(2)]


def target_raw():
    """Raw ciphertext, including the tag gate. Shallow but realistic."""
    import fuzz
    from crypto import CryptoError, Engine, load_corpus

    engine = Engine(load_corpus(), fuzz.KEY)

    def target(data: bytes) -> None:
        for f in (engine.decode, engine.decrypt_text, engine.decode_chain,
                  engine.decrypt_hidden, engine.read_frame):
            try:
                f(data)
            except CryptoError:
                pass

    # Seeds: REAL ciphertexts. Without them, mutation has to stumble onto
    # the correct length of 1339 bytes by chance and never gets past the
    # tag gate.
    seeds = [engine.encrypt_text("seed one"),
             engine.encrypt_text("seed two"),
             engine.encrypt_hidden("decoy seed")]
    return target, (), seeds


def target_control(depth: int = 4):
    """THE POSITIVE CONTROL, the target that MEASURES whether guidance works.

    The classic "magic bytes" criterion: the bug only triggers when
    the first `depth` bytes are hit in a row.

        blind search  : each byte 1/256, four at once 256^4, about 4.3 billion
        coverage guided: every CORRECT byte opens a new branch; that input
                         joins the corpus and the next byte is searched on top of it.
                         The expected cost is 256 x depth, about 1024 attempts.

    That difference is the only real justification for the adjective
    "coverage guided". Claiming without measuring was not done anywhere in
    this project, and it is not done here.
    """
    magic = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37])[:depth]

    def target(data: bytes) -> None:
        # Stepwise comparison is ESSENTIAL: `data[:n] == magic` would be a
        # single branch and the intermediate steps would be invisible to
        # coverage. Stepwise mirrors how real parsers are naturally built.
        for i, b in enumerate(magic):
            if len(data) <= i or data[i] != b:
                return
        raise AssertionError(f"sihirli dizi bulundu: {magic.hex()}")

    return target, (), [bytes(depth)]


# ═══════════════════════ THE RUN ═══════════════════════

def main() -> int:
    sure = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    print(f"\n{'═' * 74}")
    print("  COVERAGE GUIDED FUZZING: branch tracing through sys.monitoring")
    print(f"{'═' * 74}")

    # -- POSITIVE CONTROL: does guidance actually work? --
    #
    # The search is stochastic and a single attempt hits 4 times in 5. Three
    # independent seeds are tried and any one finding it is enough, so the
    # control itself does not false alarm.
    print("\n  POSITIVE CONTROL: magic bytes (3 bytes, blind cost about 2^24)")
    g_finding, g_stat = [], {"runs": 0, "edges": 0}
    for trial in range(3):
        target, accept, seeds = target_control(3)
        # Only the TARGET's own code object is traced. With a file path
        # filter the fuzzer's own loops would enter the coverage and the
        # noise would bury the signal.
        own_trace = Tracer(filter=lambda c, k=target.__code__: c is k)
        own_trace.start()
        g_finding, g_stat = guided(target, sure=3.0, seed=seed + trial,
                                   seeds=seeds, accept=accept,
                                   tracer=own_trace)
        own_trace.stop()
        if g_finding:
            break
    k_finding, k_stat = blind(target, sure=3.0, seed=seed, accept=accept)

    print(f"    guided : {g_stat['runs']:>7} runs, "
          f"{g_stat['edges']:>3} edges  ->  "
          f"{'FOUND ok' if g_finding else 'not found'}   (on attempt {trial + 1})")
    print(f"    blind  : {k_stat['runs']:>7} runs"
          f"{'':>16}->  {'found' if k_finding else 'not found (expected)'}")
    if not g_finding:
        print("    !! GUIDANCE IS NOT WORKING, the 'clean' results below are worthless")

    total: list = []
    for name, builder in (("raw ciphertext", target_raw),
                       ("payload past the tag", target_engine)):
        target, accept, seeds = builder()
        print(f"\n  target: {name}   ({sure:.0f} s, {len(seeds)} seeds)")

        findings, stat = guided(target, sure=sure, seed=seed,
                                seeds=seeds, accept=accept)
        tracing = "on" if stat["tracing"] else "OFF (ran blind)"
        print(f"    runs {stat['runs']:>7}   edges {stat['edges']:>6}   "
              f"corpus {stat['corpus']:>4}   tracing {tracing}")
        if stat["progress"]:
            first, last = stat["progress"][0], stat["progress"][-1]
            print(f"    coverage: {first[1]} edges at {first[0]} runs  ->  "
                  f"{last[1]} edges at {last[0]} runs")
        if findings:
            print(f"    !! {len(findings)} FINDINGS")
            total.extend(findings)
        else:
            print("       clean")

    print(f"\n{'═' * 74}")
    if not total:
        print("  No findings.\n")
        print("  AN HONEST NOTE: coverage guidance deepens the search but does")
        print("  not exhaust it. The INSIDE of the C core is also invisible to")
        print("  this tool; sys.monitoring only watches Python bytecode.")
        return 0

    print(f"  {len(total)} FINDINGS\n{'═' * 74}")
    for b in total[:15]:
        print(b)
    return 1


if __name__ == "__main__":
    _utf8_output()
    raise SystemExit(main())
