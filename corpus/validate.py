"""
Corpus validator.

    python corpus/validate.py

Checks:
  1. Every YAML entry matches formula.schema.json
  2. Semantic rules the schema cannot express (reference order, type and field
     agreement)
  3. Corpus wide rules (id and slug uniqueness, filename match, related links)
  4. Constraint expressions are safe and refer to defined names
  5. The payload size of each entry

Bit widths and parameter rules come from crypto.corpus, the SAME SOURCE the
engine uses. If the two drifted apart the wire format would break silently.

Returns 1 if it finds errors, 0 if clean.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto.constraints import parse as parse_constraint  # noqa: E402
from crypto.constraints import free_names  # noqa: E402
from crypto.corpus import analyze_params  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

CORPUS_DIR = Path(__file__).resolve().parent
SCHEMA_PATH = CORPUS_DIR / "formula.schema.json"
FORMULAS_DIR = CORPUS_DIR / "formulas"


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"  [ERROR]   {where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"  [WARNING] {where}: {msg}")

    @property
    def ok(self) -> bool:
        return not self.errors


def check_constraints(entry: dict, where: str, rep: Report) -> None:
    """Parse the constraint expressions without evaluating them.

    Uses the same whitelist as the engine, so anything that passes the
    validator is also accepted at run time.
    """
    param_names = {p.get("name") for p in entry.get("params", [])}
    for i, c in enumerate(entry.get("constraints", [])):
        expr = c.get("expr", "")
        at = f"{where} constraints[{i}]"
        try:
            parse_constraint(expr)
        except ValueError as e:
            rep.error(at, f"{e} -> {expr!r}")
            continue
        unknown = free_names(expr) - param_names
        if unknown:
            rep.error(
                at,
                f"constraint refers to unknown names: {sorted(unknown)} -> {expr!r}")


def main() -> int:
    rep = Report()

    if not SCHEMA_PATH.exists():
        print(f"schema not found: {SCHEMA_PATH}")
        return 1

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    files = [
        p for p in sorted(FORMULAS_DIR.glob("*.yaml")) + sorted(FORMULAS_DIR.glob("*.yml"))
        if not p.name.startswith("_")
    ]
    if not files:
        print(f"no entries found: {FORMULAS_DIR}")
        return 1

    by_id: dict[int, str] = {}
    by_slug: dict[str, str] = {}
    sizes: list[tuple[str, int, int, str]] = []
    all_related: list[tuple[str, int]] = []

    for path in files:
        where = path.name
        try:
            entry = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            rep.error(where, f"could not parse YAML: {e}")
            continue

        if not isinstance(entry, dict):
            rep.error(where, "the root of the file must be a mapping (key: value)")
            continue

        schema_errors = sorted(validator.iter_errors(entry), key=lambda e: list(e.path))
        for e in schema_errors:
            loc = ".".join(str(x) for x in e.path) or "(root)"
            rep.error(where, f"schema violation at {loc}: {e.message}")
        if schema_errors:
            continue  # with a broken schema the semantic checks are unreliable

        fid, slug = entry["id"], entry["slug"]

        if fid in by_id:
            rep.error(
                where,
                f"id 0x{fid:04X} is already used by {by_id[fid]}; "
                f"ids are NEVER reused")
        else:
            by_id[fid] = where
        if slug in by_slug:
            rep.error(where, f"slug {slug!r} is already used by {by_slug[slug]}")
        else:
            by_slug[slug] = where

        expected = f"{fid:04x}-{slug}.yaml"
        if path.name != expected:
            rep.warn(where, f"filename does not match, expected: {expected}")

        bits, errors, warnings = analyze_params(entry)
        for msg in errors:
            rep.error(where, msg)
        for msg in warnings:
            rep.warn(where, msg)

        check_constraints(entry, where, rep)

        sizes.append((f"0x{fid:04X}", bits, -(-bits // 8), entry["doc"]["name"]))

        for r in entry.get("doc", {}).get("related", []):
            all_related.append((where, r))

    for where, rid in all_related:
        if rid not in by_id:
            rep.warn(
                where,
                f"related: 0x{rid:04X} is not in the corpus "
                f"(fine if it has not been written yet)")

    print(f"\n{len(files)} entries checked.\n")

    if sizes:
        print("Payload sizes:")
        print(f"  {'id':<10} {'bits':>8} {'bytes':>8}  name")
        for fid_str, bits, byts, name in sorted(sizes, key=lambda x: x[1]):
            print(f"  {fid_str:<10} {bits:>8} {byts:>8}  {name}")
        if len(sizes) > 1:
            lo, hi = min(s[2] for s in sizes), max(s[2] for s in sizes)
            if lo != hi:
                print(f"\n  NOTE: sizes range from {lo} to {hi} bytes.")
                print("  That leaks which formula was used through the length of")
                print("  the ciphertext. Known and accepted, see docs/decisions.md ADR-002.")
        print()

    for w in rep.warnings:
        print(w)
    for e in rep.errors:
        print(e)

    if rep.ok:
        print(f"\nResult: CLEAN ({len(rep.warnings)} warnings)")
        return 0
    print(f"\nResult: {len(rep.errors)} errors, {len(rep.warnings)} warnings")
    return 1


if __name__ == "__main__":
    sys.exit(main())
