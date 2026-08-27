"""Corpus generator: new entries that are STRUCTURALLY similar to existing ones.

    python -m layer2.generator --count 40 --seed 0

WHAT IT PRODUCES AND WHAT IT DOES NOT. Do not use this module without reading
that distinction.

IT PRODUCES the entry's **structure**. Parameter count, types, bit widths,
roles, constraint shapes, id block, all sampled from distributions learned
from the 54 real entries. The output is a valid corpus entry that the engine
accepts, that passes the schema, and that can be sampled and round tripped.

IT DOES NOT PRODUCE the **mathematics**. A generated entry is NOT a new
cryptographic formula. Its `latex` field is a placeholder assembled from the
parameters, not a theorem. A model that produces mathematically correct new
cryptographic formulas cannot be trained on 54 examples, and claiming
otherwise would be false. The `doc` block is deliberately left as a SEAM: a
language model that wants to put meaning there can be attached later (see
ADR-025).

WHY THE DISTINCTION MATTERS

In this corpus, entries are the CONTENT being encrypted, not the encryption
algorithm. The envelope is the same for every entry: HKDF-SHA256 plus XOR
plus HMAC-SHA256. So a generated entry neither raises nor lowers the
envelope's security. It only does harm if it makes traffic DISTINGUISHABLE,
and the place that measures that is `layer2/exam.py`.

WHERE IT SAYS THE ENTRY WAS GENERATED

There is a `generated` tag in `doc.tags` and an explicit warning in
`doc.notes`. Those markers live in the `doc` block because **the engine never
reads that block and it never enters the wire format** (see
formula.schema.json). So the entry is marked for humans and unmarked in the
ciphertext. Putting the marker in params or constraints would make generated
entries distinguishable from the ciphertext, which is exactly what has to be
avoided.
"""

from __future__ import annotations

import argparse
import ast
import random
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.constraints import free_names, parse  # noqa: E402
from crypto.corpus import Corpus, load_corpus, param_bits  # noqa: E402

# Types usable in structural slots. `bytes`, `point` and `enum` cannot enter
# arithmetic constraints, so template binding only applies to numeric ones.
NUMERIC = {"prime", "field_element", "scalar", "uint"}

# Placeholder names in templates. `constraint_template` abstracts at most
# three variables, so the set is limited to those three.
SLOT_NAMES = {"X", "Y", "Z"}

# Ids that will never be assigned. 0x0501 belonged to the retired Caesar and
# is NEVER reused under ADR-003 and ADR-009; 0xFFFF belongs to chain mode.
BLOCKED = {0x0501, 0xFFFF}

# The ceiling an entry has to fit into. Anything over it is not generated.
# The engine would refuse it anyway, but filtering at generation is cheaper.
PAYLOAD_BIT_CEILING = 1289 * 8


# ══════════════════════ LEARNING ══════════════════════

@dataclass
class Profile:
    """Structural distributions learned from the real corpus.

    Every field is a Counter, so sampling is weighted and the structure of
    generated entries comes from the same distribution as the real ones.
    """

    domain_block: dict[str, int] = field(default_factory=dict)
    param_count: Counter = field(default_factory=Counter)
    constraint_count: Counter = field(default_factory=Counter)
    type_distribution: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    bit_distribution: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    role_distribution: Counter = field(default_factory=Counter)
    name_pool: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    templates: Counter = field(default_factory=Counter)
    used_ids: set[int] = field(default_factory=set)
    used_slugs: set[str] = field(default_factory=set)
    enum_pool: list[list[str]] = field(default_factory=list)

    @property
    def domains(self) -> list[str]:
        return sorted(self.domain_block)


def constraint_template(expr: str) -> str | None:
    """Strips the names out of a constraint expression, leaving a template.

    `p > 3`        -> `X > 3`
    `a % p != 0`   -> `X % Y != 0`
    `x1 % p != x2 % p` -> `X % Y != Z % Y`

    It uses the engine's OWN parser (`crypto.constraints.parse`). Writing a
    separate parser would let templates produce expressions the engine does
    not accept, and that is where the generator's guarantee of valid
    output comes from.

    Returns None for expressions that cannot be parsed or that contain a
    string constant; those are not templated (`padding != 'none'` is specific
    to one entry).
    """
    try:
        tree = parse(expr)
    except ValueError:
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and not isinstance(node.value, int):
            return None

    # In an expression like `gcd(e, phi) == 1`, `gcd` is an ast.Name too, and
    # turning it into a slot would give `X(e, phi)`, which the engine's
    # parser rightly refuses ("function not allowed"). Call targets stay AS
    # THEY ARE in the template; only variables become slots.
    call_targets = {d.func.id for d in ast.walk(tree)
                    if isinstance(d, ast.Call) and isinstance(d.func, ast.Name)}

    variables = [d for d in ast.walk(tree)
                 if isinstance(d, ast.Name) and d.id not in call_targets]

    mapping: dict[str, str] = {}
    for node in variables:
        if node.id not in mapping:
            mapping[node.id] = chr(ord("X") + len(mapping))
            if len(mapping) > 3:                      # no templates with 4+ slots
                return None
    if not mapping:                                   # a fully constant expression
        return None
    for node in variables:
        node.id = mapping[node.id]
    return ast.unparse(tree)


def learn(corpus: Corpus) -> Profile:
    """Extracts the structural profile from the real corpus."""
    p = Profile()
    block_counter: dict[str, Counter] = defaultdict(Counter)

    for e in corpus:
        p.used_ids.add(e.id)
        p.used_slugs.add(e.slug)

        domain = e.doc.get("domain", "unknown")
        block_counter[domain][e.id >> 8] += 1
        p.param_count[len(e.params)] += 1
        p.constraint_count[len(e.constraints)] += 1

        for prm in e.params:
            kind = prm["type"]
            p.type_distribution[domain][kind] += 1
            p.role_distribution[prm.get("role", "public")] += 1
            p.name_pool[kind][prm["name"]] += 1
            if "bits" in prm:
                p.bit_distribution[kind][prm["bits"]] += 1
            if kind == "enum" and prm.get("values"):
                p.enum_pool.append(list(prm["values"]))

        for k in e.constraints:
            s = constraint_template(k["expr"])
            if s:
                p.templates[s] += 1

    # A domain's id block: the block most of that domain's entries sit in.
    for domain, counter in block_counter.items():
        p.domain_block[domain] = counter.most_common(1)[0][0]
    return p


# ══════════════════════ GENERATION ══════════════════════

def _pick(counter: Counter, rng: random.Random):
    """Weighted sampling from a counter."""
    items = list(counter.keys())
    weight = [counter[o] for o in items]
    return rng.choices(items, weights=weight, k=1)[0]


def _free_id(block: int, used: set[int], rng: random.Random) -> int | None:
    """Finds a free id within a block."""
    candidate = [i for i in range(block << 8, (block << 8) + 256)
                 if i not in used and i not in BLOCKED and i != 0]
    return rng.choice(candidate) if candidate else None


def _make_params(domain: str, profile: Profile, rng: random.Random) -> list[dict]:
    """Produces the parameter list for a domain.

    The backward reference rule: `field_element` and `scalar` point at a
    modulus, and that modulus has to come BEFORE them. So when there is no
    modulus candidate the type falls back to `uint`, not to keep the schema
    happy but because the engine's read order genuinely depends on it.
    """
    count = _pick(profile.param_count, rng)
    types = profile.type_distribution.get(domain) or profile.type_distribution["modular-arithmetic"]

    params: list[dict] = []
    used_names: set[str] = set()
    modulus_candidates: list[str] = []

    for _ in range(count):
        kind = _pick(types, rng)
        if kind in ("field_element", "scalar") and not modulus_candidates:
            kind = "uint"
        if kind == "point":                 # binding `curve` is structurally
            kind = "bytes"                  # hard, so points are not generated

        name = _make_name(kind, profile, used_names, rng)
        used_names.add(name)

        prm: dict[str, Any] = {"name": name, "type": kind}
        if kind == "enum":
            prm["values"] = list(rng.choice(profile.enum_pool)) \
                if profile.enum_pool else ["a", "b"]
        else:
            prm["bits"] = _pick(profile.bit_distribution[kind], rng)
        if kind in ("field_element", "scalar"):
            prm["mod"] = rng.choice(modulus_candidates)

        prm["role"] = _pick(profile.role_distribution, rng)
        prm["description"] = f"A structural {kind} parameter."
        params.append(prm)

        if kind == "prime":
            modulus_candidates.append(name)

    return params


def _make_name(kind: str, profile: Profile, used: set[str],
               rng: random.Random) -> str:
    """Picks a non-colliding name from the real corpus's name pool."""
    pool = profile.name_pool.get(kind) or Counter({"x": 1})
    for _ in range(40):
        name = _pick(pool, rng)
        if name not in used:
            return name
    for extra in range(2, 60):                # pool exhausted, add a suffix
        name = f"{_pick(pool, rng)}{extra}"
        if name not in used:
            return name
    raise RuntimeError("name pool exhausted")


def _make_constraints(params: list[dict], profile: Profile,
                      rng: random.Random) -> list[dict]:
    """Binds templates to real parameter names.

    THE SATISFIABILITY OF GENERATED CONSTRAINTS IS NOT PROVED HERE. Templates
    can contradict each other (`X > 3` and `X < 2`). Satisfiability is tested
    WITH THE SAMPLER at stage 3 of `exam.py`. Trying rather than proving is
    both correct and the method used elsewhere in this project.
    """
    numeric = [p["name"] for p in params if p["type"] in NUMERIC]
    if not numeric or not profile.templates:
        return []

    target = _pick(profile.constraint_count, rng)
    constraints_out: list[dict] = []
    seen: set[str] = set()

    for _ in range(target * 4):
        if len(constraints_out) >= target:
            break
        template = _pick(profile.templates, rng)
        # Slots are X/Y/Z. Call targets such as `gcd` appear as free names
        # but are NOT slots and must not be bound.
        slots = sorted(a for a in free_names(template) if a in SLOT_NAMES)
        if len(slots) > len(numeric):
            continue
        chosen = rng.sample(numeric, len(slots))
        expr = template
        for slot, name in zip(slots, chosen):
            expr = _replace_slot(expr, slot, name)
        if expr in seen:
            continue
        seen.add(expr)
        constraints_out.append({
            "expr": expr,
            "reason": f"Structural constraint: {expr} must hold.",
            "severity": "error",
        })
    return constraints_out


def _replace_slot(expr: str, slot: str, name: str) -> str:
    """Replaces a slot name through the AST rather than by text search.

    Replacing the slot `X` with a plain `str.replace` would break names that
    contain the letter, such as `max`. Parsing and substituting is the only
    correct way.
    """
    tree = parse(expr)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == slot:
            node.id = name
    return ast.unparse(tree)


def _payload_bits(params: list[dict]) -> int:
    total = 0
    for p in params:
        if p.get("role", "public") != "public":
            continue
        b = param_bits(p)
        total += b if b else 0
    return total


def generate(profile: Profile, count: int, rng: random.Random) -> list[dict]:
    """Generates `count` structural entries, discarding oversized or colliding ones."""
    entries: list[dict] = []
    used_ids = set(profile.used_ids)
    used_slugs = set(profile.used_slugs)
    domains = profile.domains

    trial = 0
    while len(entries) < count and trial < count * 50:
        trial += 1
        domain = rng.choice(domains)
        params = _make_params(domain, profile, rng)
        if not params or _payload_bits(params) > PAYLOAD_BIT_CEILING:
            continue

        new_id = _free_id(profile.domain_block[domain], used_ids, rng)
        if new_id is None:
            continue
        slug = f"generated-{domain}-{new_id:04x}"
        if slug in used_slugs:
            continue

        used_ids.add(new_id)
        used_slugs.add(slug)
        entries.append({
            "id": new_id,
            "slug": slug,
            "version": 1,
            "status": "active",
            "doc": _make_doc(domain, params),
            "params": params,
            "constraints": _make_constraints(params, profile, rng),
            "sampler": {"strategy": "uniform_valid", "max_rejections": 1000},
        })
    return entries


def _make_doc(domain: str, params: list[dict]) -> dict:
    """The `doc` block, THE SEAM.

    The text here is NOT a mathematical claim and was not written as if it
    were. If a language model is attached, this is the place to change. `doc`
    is invisible to the engine and never reaches the wire, which is why the
    `generated` tag can sit here without leaking into the ciphertext.
    """
    names = [p["name"] for p in params]
    return {
        "name": f"Generated structure ({domain})",
        "latex": r"f(" + ",\\ ".join(names) + r") \equiv 0",
        "domain": domain,
        "summary": (
            "A structurally generated corpus entry. Parameter types, widths "
            "and constraint shapes were sampled from distributions learned "
            "from the real corpus."
        ),
        "notes": (
            "THIS ENTRY IS NOT A MATHEMATICAL FORMULA. The `latex` field is "
            "a placeholder assembled from the parameters, not a theorem. The "
            "entry is a valid STRUCTURE that the engine accepts; it has no "
            "meaning. To add meaning, change the `doc` block and remove the "
            "`generated` tag."
        ),
        "tags": ["generated", "structural", domain],
        "references": [],
    }


# ══════════════════════ DERIVED GENERATION ══════════════════════
#
# The structural generator cannot produce MATHEMATICS. A model that produces
# correct new cryptographic formulas cannot be trained on 54 examples. Derived
# generation is the HONEST way around that limit: do not generate the
# mathematics, inherit it.
#
# That is how it works in real life too. RSA-2048 and RSA-4096 are separate
# entries but the same mathematics; P-256 and P-384 are the same equation at
# different parameters. A derived entry does the same: the parent's latex,
# summary and constraint STRUCTURE carry over unchanged, and only the
# parameter widths are scaled.
#
# That is why derived entries carry the `derived` tag rather than `generated`,
# and link to the parent through `doc.related`, so a reader knows where to
# verify the mathematics.

# Width factors. Shrinking is included, because TRYING it in the exam rather
# than PROVING whether it breaks the constraints is this project's method
# (see exam.py).
FACTORS = (0.5, 1.5, 2.0, 3.0)

DERIVED_TYPES = NUMERIC | {"bytes"}


def derive(parent: Any, new_id: int, factor: float) -> dict | None:
    """Produces a derivative of a real entry with the parameter widths scaled.

    `parent` is an `Entry`. The mathematics does not change: `latex`,
    `summary` and the constraint expressions carry over unchanged. The only
    thing that changes is the bit widths.

    Returns None if it exceeds the schema limits (1..8192) or the payload
    ceiling.
    """
    params = []
    for p in parent.params:
        new = dict(p)
        if p["type"] in DERIVED_TYPES and "bits" in p:
            b = int(round(p["bits"] * factor))
            b = b - (b % 8) if p["type"] == "bytes" else b   # bytes: multiple of 8
            if not 1 <= b <= 8192:
                return None
            new["bits"] = b
        params.append(new)

    if _payload_bits(params) > PAYLOAD_BIT_CEILING:
        return None
    if params == list(parent.params):                  # the scaling changed nothing
        return None

    name = parent.doc.get("name", parent.slug)
    return {
        "id": new_id,
        "slug": f"derive-{parent.slug}-{factor:g}x".replace(".", ""),
        "version": 1,
        "status": "active",
        "doc": {
            "name": f"{name} - {factor:g}x width derivative",
            "latex": parent.doc.get("latex", ""),
            "domain": parent.doc.get("domain", "unknown"),
            "summary": parent.doc.get("summary", ""),
            "notes": (
                f"A DERIVED ENTRY. It INHERITS its mathematics from "
                f"0x{parent.id:04X} ({parent.slug}), where it has been "
                f"verified; no mathematics was generated here. The only thing "
                f"that changed is the parameter widths ({factor:g}x). The way "
                f"RSA-2048 and RSA-4096 are separate entries in real life."
                f"\n\n"
                + (parent.doc.get("notes") or "")
            ).strip(),
            "tags": sorted(set(parent.doc.get("tags", [])) | {"derived"}),
            "references": list(parent.doc.get("references", [])),
            "related": sorted(set(parent.doc.get("related", [])) | {parent.id}),
        },
        "params": params,
        "constraints": [dict(k) for k in parent.constraints],
        "sampler": dict(parent.sampler) or {"strategy": "uniform_valid",
                                            "max_rejections": 1000},
    }


def derivatives(corpus: Corpus, profile: Profile, count: int,
                rng: random.Random) -> list[dict]:
    """Produces derivatives from the real entries in the corpus."""
    used = set(profile.used_ids)
    active = corpus.active
    out: list[dict] = []

    trial = 0
    while len(out) < count and trial < count * 60:
        trial += 1
        parent = rng.choice(active)
        factor = rng.choice(FACTORS)
        block = (parent.id >> 8)
        new_id = _free_id(block, used, rng)
        if new_id is None:
            continue
        g = derive(parent, new_id, factor)
        if g is None or any(x["slug"] == g["slug"] for x in out):
            continue
        used.add(new_id)
        out.append(g)
    return out


# ══════════════════════ YAZMA ══════════════════════

def write_entries(entries: list[dict], directory: Path) -> list[Path]:
    """Writes the entries as YAML, named `{id:04x}-{slug}.yaml`."""
    import yaml

    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for g in entries:
        path = directory / f"{g['id']:04x}-{g['slug']}.yaml"
        path.write_text(
            yaml.safe_dump(g, allow_unicode=True, sort_keys=False, width=88),
            encoding="utf-8")
        paths.append(path)
    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=40)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mode", choices=("structural", "derived", "mixed"),
                    default="mixed",
                    help="structural: structure only, no mathematics. "
                    "derived: width variants of real entries, with the "
                    "mathematics INHERITED. mixed: half of each.")
    ap.add_argument("--directory", type=Path,
                    default=ROOT / "generated_corpus" / "formulas")
    a = ap.parse_args()

    corpus = load_corpus()
    profile = learn(corpus)
    print(f"\n  learned   : {len(corpus)} real entries")
    print(f"  domains   : {len(profile.domains)}")
    print(f"  templates : {len(profile.templates)} distinct constraint shapes")
    print(f"  name pool : {sum(len(v) for v in profile.name_pool.values())} names")
    print(f"  mode      : {a.mode}")

    rng = random.Random(a.seed)
    if a.mode == "structural":
        entries = generate(profile, a.count, rng)
    elif a.mode == "derived":
        entries = derivatives(corpus, profile, a.count, rng)
    else:
        half = a.count // 2
        entries = derivatives(corpus, profile, half, rng)
        # Keep the structural generator's ids from colliding with derived ones.
        p2 = learn(corpus)
        p2.used_ids |= {g["id"] for g in entries}
        p2.used_slugs |= {g["slug"] for g in entries}
        entries += generate(p2, a.count - half, rng)

    paths = write_entries(entries, a.directory)
    t = sum(1 for g in entries if "derived" in g["doc"]["tags"])
    print(f"\n  generated : {len(paths)} entries ({t} derived, "
          f"{len(paths) - t} structural) -> {a.directory}")
    print("\n  These entries HAVE NOT BEEN EXAMINED. Run `python -m layer2.exam`;")
    print("  an entry that fails the exam must not enter the corpus.")
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
