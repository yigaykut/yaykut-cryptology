"""Corpus loading and the parameter schema rules.

This module is the single source of truth for the wire format. How many bits a
parameter occupies, which fields are mandatory, and the reference ordering
rule are all defined here. The runtime engine and the authoring time validator
both read from it; letting the two drift apart would silently break the wire
format.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from .errors import CorpusError

# Types where the 'bits' field is mandatory. `point` derives it, `enum`
# computes it from values.
BITS_REQUIRED = {"prime", "field_element", "scalar", "uint", "bytes"}
# Types that must reference a modulus.
MOD_REQUIRED = {"field_element", "scalar"}
# Types usable as a modulus.
MOD_VALID_TARGETS = {"prime", "uint"}
# Prefix byte of the compressed SEC1 point encoding.
POINT_PREFIX_BITS = 8

# The id the wire format RESERVES for chain mode. No corpus entry may take it;
# if one did, decoding would mistake it for a chain and the entry would be
# silently shadowed. It lives here because it has to be checked while loading
# the corpus, and corpus.py cannot import wire.py, since the dependency runs
# the other way.
RESERVED_ID = 0xFFFF


def param_bits(p: dict) -> int | None:
    """How many bits a parameter takes on the wire.

    Returns None if it cannot be computed, for example a missing field.
    """
    t = p.get("type")
    if t in BITS_REQUIRED:
        b = p.get("bits")
        return b if isinstance(b, int) and b > 0 else None
    if t == "point":
        b = p.get("bits")
        return b + POINT_PREFIX_BITS if isinstance(b, int) and b > 0 else None
    if t == "enum":
        vals = p.get("values")
        if not vals:
            return None
        return max(1, math.ceil(math.log2(len(vals))))
    return None


def is_public(p: dict) -> bool:
    """Whether the parameter is written into the ciphertext.

    A parameter with no role is treated as public.
    """
    return p.get("role", "public") == "public"


@dataclass(frozen=True)
class Entry:
    """A single formula entry in the corpus."""

    id: int
    slug: str
    version: int
    status: str
    doc: dict[str, Any]
    params: list[dict[str, Any]]
    constraints: list[dict[str, Any]] = field(default_factory=list)
    sampler: dict[str, Any] = field(default_factory=dict)
    source: Path | None = None

    @property
    def name(self) -> str:
        return self.doc.get("name", self.slug)

    @property
    def public_params(self) -> list[dict[str, Any]]:
        """In wire order, only the parameters written to the ciphertext."""
        return [p for p in self.params if is_public(p)]

    @property
    def payload_bits(self) -> int:
        total = 0
        for p in self.public_params:
            b = param_bits(p)
            if b is None:
                raise CorpusError(
                    f"0x{self.id:04X} parameter {p.get('name')!r}: "
                    f"bit width could not be computed")
            total += b
        return total

    @property
    def payload_bytes(self) -> int:
        return (self.payload_bits + 7) // 8

    def param(self, name: str) -> dict[str, Any]:
        for p in self.params:
            if p.get("name") == name:
                return p
        raise CorpusError(f"entry 0x{self.id:04X} has no parameter {name!r}")

    def __str__(self) -> str:
        return f"0x{self.id:04X} ({self.slug})"


def analyze_params(entry: dict) -> tuple[int, list[str], list[str]]:
    """Check the semantic rules of the parameter block.

    JSON Schema cannot express these: field and type agreement, the backward
    reference rule, name uniqueness.

    Returns (payload_bits, errors, warnings).
    """
    errors: list[str] = []
    warnings: list[str] = []
    seen: dict[str, dict] = {}
    total_bits = 0

    for i, p in enumerate(entry.get("params", [])):
        name, ptype = p.get("name"), p.get("type")
        at = f"params[{i}] ({name})"

        if name in seen:
            errors.append(f"{at}: duplicate parameter name: {name!r}")

        if ptype in BITS_REQUIRED and p.get("bits") is None:
            errors.append(f"{at}: type {ptype!r} requires a 'bits' field")
        if ptype in MOD_REQUIRED and not p.get("mod"):
            errors.append(f"{at}: type {ptype!r} requires a 'mod' field")
        if ptype == "enum" and not p.get("values"):
            errors.append(f"{at}: type 'enum' requires a 'values' field")
        if ptype == "point" and not p.get("curve"):
            errors.append(f"{at}: type 'point' requires a 'curve' field")
        if ptype not in MOD_REQUIRED and p.get("mod"):
            warnings.append(
                f"{at}: 'mod' is meaningless on type {ptype!r} and is ignored")

        # Backward reference rule: the target must already be defined. This
        # makes circular references structurally impossible.
        ref = p.get("mod")
        if ref:
            if ref not in seen:
                errors.append(
                    f"{at}: 'mod: {ref}' is not defined before this point; "
                    f"order is significant")
            elif seen[ref].get("type") not in MOD_VALID_TARGETS:
                errors.append(
                    f"{at}: 'mod: {ref}' is a {seen[ref].get('type')!r}; "
                    f"a modulus must be one of {sorted(MOD_VALID_TARGETS)}")

        seen[name] = p

        if is_public(p):
            b = param_bits(p)
            if b is None:
                errors.append(
                    f"{at}: payload size could not be computed, "
                    f"'bits' is missing or invalid")
            else:
                total_bits += b

    return total_bits, errors, warnings


class Corpus:
    """Loaded entries, addressable by id."""

    def __init__(self, entries: list[Entry]) -> None:
        self._by_id: dict[int, Entry] = {}
        for e in entries:
            if e.id == RESERVED_ID:
                raise CorpusError(
                    f"{e.slug}: 0x{RESERVED_ID:04X} is reserved for the wire "
                    f"format's chain mode and cannot be a corpus entry id")
            if e.id in self._by_id:
                raise CorpusError(
                    f"id 0x{e.id:04X} defined twice: "
                    f"{self._by_id[e.id].slug} and {e.slug}")
            self._by_id[e.id] = e

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self) -> Iterator[Entry]:
        return iter(sorted(self._by_id.values(), key=lambda e: e.id))

    def __contains__(self, formula_id: int) -> bool:
        return formula_id in self._by_id

    def get(self, formula_id: int) -> Entry:
        try:
            return self._by_id[formula_id]
        except KeyError:
            raise CorpusError(
                f"no entry with id 0x{formula_id:04X} in the corpus") from None

    def by_slug(self, slug: str) -> Entry:
        for e in self._by_id.values():
            if e.slug == slug:
                return e
        raise CorpusError(f"no entry named {slug!r} in the corpus")

    @property
    def active(self) -> list[Entry]:
        """Entries usable for new encryption."""
        return [e for e in self if e.status == "active"]


DEFAULT_CORPUS_DIR = (Path(__file__).resolve().parent.parent
                      / "corpus" / "formulas")


def load_corpus(directory: Path | str | None = None) -> Corpus:
    """Load every .yaml entry in a directory.

    Files starting with an underscore are skipped, since those are templates.
    """
    directory = Path(directory) if directory else DEFAULT_CORPUS_DIR
    if not directory.is_dir():
        raise CorpusError(f"corpus directory not found: {directory}")

    entries: list[Entry] = []
    for path in (sorted(directory.glob("*.yaml"))
                 + sorted(directory.glob("*.yml"))):
        if path.name.startswith("_"):
            continue
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise CorpusError(f"{path.name}: could not parse YAML: {e}") from e
        if not isinstance(raw, dict):
            raise CorpusError(f"{path.name}: the file root must be a mapping")

        missing = {"id", "slug", "version",
                   "status", "doc", "params"} - raw.keys()
        if missing:
            raise CorpusError(
                f"{path.name}: required fields missing: {sorted(missing)}")

        entries.append(
            Entry(
                id=raw["id"],
                slug=raw["slug"],
                version=raw["version"],
                status=raw["status"],
                doc=raw["doc"],
                params=raw["params"],
                constraints=raw.get("constraints") or [],
                sampler=raw.get("sampler") or {},
                source=path,
            )
        )

    if not entries:
        raise CorpusError(f"no entries found in the corpus directory: {directory}")
    return Corpus(entries)
