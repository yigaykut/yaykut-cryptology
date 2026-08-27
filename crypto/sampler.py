"""Random parameter generation, the data source for layer 2.

The distinguisher's training data comes from here: for every formula in the
corpus, valid random parameter sets are generated, encrypted, and the model is
asked whether it is looking at real ciphertext or random noise.

Sampling is harder than it sounds. Plain rejection sampling does not work for
most entries. A constraint like 'length_bits <= 256' on a 32 bit parameter
accepts a random value with probability 257/2^32, about 6e-8, which would need
millions of attempts.

The answer has two layers:

  1. Bound inference from constraints. Single variable comparisons like
     'x < 26' are parsed and used to narrow the sampling range. That solves
     most entries in a single attempt.
  2. Rejection sampling for the rest. Two variable constraints like 'm < n'
     usually accept about half the time and pass within a few attempts.

What remains is constraints demanding EQUALITY between independent variables,
such as 'rate + capacity == width'. Those need a constraint directed sampler,
and `hard_constraints()` finds those entries by measuring rather than guessing.
"""

from __future__ import annotations

import ast
import random
from typing import Any

from .constraints import (
    check_all,
    equality_gap,
    evaluate,
    free_names,
    parse,
)
from .corpus import Entry, is_public, param_bits
from .errors import ConstraintViolation, SamplingError
from .wire import INT_TYPES, POINT_PREFIX_BITS

# Rejection rate above which a constraint counts as "hard".
HARD_THRESHOLD = 0.5


def _apply_bound(
    bounds: dict[str, tuple[int, int]], name: str,
    lo: int | None, hi: int | None,
) -> None:
    if name not in bounds:
        return
    cur_lo, cur_hi = bounds[name]
    if lo is not None:
        cur_lo = max(cur_lo, lo)
    if hi is not None:
        cur_hi = min(cur_hi, hi)
    bounds[name] = (cur_lo, cur_hi)


def bounds(entry: Entry) -> dict[str, tuple[int, int]]:
    """Derive a [low, high] range for every integer parameter.

    Only single variable comparisons of the form '<name> <op> <constant>' and
    '<constant> <op> <name>' are considered. Anything more complex is left to
    rejection sampling.

    Only severity=error constraints are used. Warning level ones must remain
    violable, otherwise sampling would never produce the test data that
    triggers a warning.
    """
    out: dict[str, tuple[int, int]] = {}
    for p in entry.params:
        if p["type"] in INT_TYPES:
            bits = param_bits(p)
            if bits:
                out[p["name"]] = (0, (1 << bits) - 1)

    for c in entry.constraints:
        if c.get("severity", "error") != "error":
            continue
        try:
            node = parse(c["expr"]).body
        except ValueError:
            continue
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue

        left, op, right = node.left, node.ops[0], node.comparators[0]

        # <name> <op> <constant>
        if (isinstance(left, ast.Name) and isinstance(right, ast.Constant)
            and isinstance(right.value, int)):
            name, k = left.id, right.value
            if isinstance(op, ast.Lt):
                _apply_bound(out, name, None, k - 1)
            elif isinstance(op, ast.LtE):
                _apply_bound(out, name, None, k)
            elif isinstance(op, ast.Gt):
                _apply_bound(out, name, k + 1, None)
            elif isinstance(op, ast.GtE):
                _apply_bound(out, name, k, None)
            elif isinstance(op, ast.Eq):
                _apply_bound(out, name, k, k)

        # <constant> <op> <name>
        elif (isinstance(right, ast.Name) and isinstance(left, ast.Constant)
              and isinstance(left.value, int)):
            name, k = right.id, left.value
            if isinstance(op, ast.Lt):
                _apply_bound(out, name, k + 1, None)
            elif isinstance(op, ast.LtE):
                _apply_bound(out, name, k, None)
            elif isinstance(op, ast.Gt):
                _apply_bound(out, name, None, k - 1)
            elif isinstance(op, ast.GtE):
                _apply_bound(out, name, None, k)
            elif isinstance(op, ast.Eq):
                _apply_bound(out, name, k, k)

    return out


def _random_value(
    p: dict, rng: random.Random, bound: tuple[int, int] | None = None
) -> Any:
    ptype = p["type"]
    bits = param_bits(p)
    if bits is None:
        raise SamplingError(
            f"{p.get('name')!r}: bit width could not be computed")

    if ptype in INT_TYPES:
        if bound is not None:
            lo, hi = bound
            if lo > hi:
                raise SamplingError(
                    f"{p['name']!r}: constraints conflict, the valid range is "
                    f"empty ({lo} > {hi})")
            return rng.randint(lo, hi)
        return rng.getrandbits(bits)

    if ptype == "bytes":
        nbytes = (bits + 7) // 8
        value = rng.getrandbits(bits)
        # write_bytes requires the unused bits of the last byte to be zero, so
        # the value is aligned here.
        return (value << (nbytes * 8 - bits)).to_bytes(nbytes, "big")

    if ptype == "enum":
        return rng.choice(p["values"])

    if ptype == "point":
        return (rng.getrandbits(bits - POINT_PREFIX_BITS), rng.getrandbits(1))

    raise SamplingError(f"{p.get('name')!r}: unknown type {ptype!r}")


def random_values(
    entry: Entry,
    rng: random.Random | None = None,
    *,
    include_secret: bool = True,
    use_bounds: bool = False,
) -> dict[str, Any]:
    """Random values matching the schema.

    With use_bounds=False, the default, values are drawn from the whole bit
    space and constraints are ignored. That is the right behaviour for
    serialisation tests, since round tripping does not depend on a value being
    valid.

    With use_bounds=True the ranges derived from constraints are used.
    """
    rng = rng or random.Random()
    limits = bounds(entry) if use_bounds else {}
    return {
        p["name"]: _random_value(p, rng, limits.get(p["name"]))
        for p in entry.params
        if include_secret or is_public(p)
    }


def _solve(expr: str, name: str, values: dict[str, Any]) -> int | None:
    """Solve an equality for one variable, or return None.

    If g(v) = left - right is linear in v then g(v) = A*v + B, with B = g(0)
    and A = g(1) - g(0). The root is v = -B / A when it divides exactly.
    Linearity is confirmed by checking g(2) = 2A + B.
    """
    try:
        g0 = equality_gap(expr, {**values, name: 0})
        if g0 is None:
            return None
        g1 = equality_gap(expr, {**values, name: 1})
        g2 = equality_gap(expr, {**values, name: 2})
    except (ValueError, TypeError, ZeroDivisionError):
        return None

    a = g1 - g0
    if a == 0 or (g2 - g1) != a:      # constant, or not linear
        return None
    root, rem = divmod(-g0, a)
    return root if rem == 0 else None


def equality_plan(
    entry: Entry, rng: random.Random | None = None, *, trials: int = 24
) -> list[tuple[str, str]]:
    """Decide which variable to solve for in each equality constraint.

    Candidate variables are tried and the rate at which the solution lands
    inside the bounds is measured; the best one wins. The choice matters: in
    'rate + capacity == width', solving for width gives (rate+capacity), which
    is reasonable, while solving for rate gives (width-capacity), which is
    usually negative.

    Returns [(expr, variable_to_solve)].
    """
    rng = rng or random.Random(0)
    limits = bounds(entry)
    plan: list[tuple[str, str]] = []
    reserved: set[str] = set()

    for c in entry.constraints:
        if c.get("severity", "error") != "error":
            continue
        expr = c["expr"]
        candidates = [n for n in free_names(expr)
                      if n in limits and n not in reserved]
        if not candidates:
            continue

        best, best_rate = None, 0.0
        for name in sorted(candidates):
            lo, hi = limits[name]
            hits = 0
            for _ in range(trials):
                values = random_values(entry, rng, use_bounds=True)
                root = _solve(expr, name, values)
                if root is not None and lo <= root <= hi:
                    hits += 1
            rate = hits / trials
            if rate > best_rate:
                best, best_rate = name, rate

        if best is not None:
            plan.append((expr, best))
            reserved.add(best)

    return plan


def sample(
    entry: Entry,
    rng: random.Random | None = None,
    *,
    max_rejections: int | None = None,
) -> dict[str, Any]:
    """Generate random values satisfying the constraints.

    Three stages:
      1. bound inference, from constraints like 'x < 26'
      2. equality solving, computing one variable in 'a + b == c'
      3. rejection sampling for whatever is left

    Raises SamplingError if nothing is found within max_rejections attempts.
    """
    rng = rng or random.Random()
    limit = max_rejections or entry.sampler.get("max_rejections", 1000)

    plan = equality_plan(entry, random.Random(entry.id))
    limits = bounds(entry) if plan else {}

    for _ in range(limit):
        values = random_values(entry, rng, use_bounds=True)

        ok = True
        for expr, name in plan:
            root = _solve(expr, name, values)
            lo, hi = limits[name]
            if root is None or not (lo <= root <= hi):
                ok = False
                break
            values[name] = root
        if not ok:
            continue

        try:
            check_all(entry.constraints, values, skip_unknown=True)
        except ConstraintViolation:
            continue
        return values

    raise SamplingError(
        f"{entry}: no values satisfying the constraints found in {limit} "
        f"attempts. Call hard_constraints() to see what is blocking.")


def sample_or_free(
    entry: Entry,
    rng: random.Random | None = None,
    *,
    max_rejections: int | None = None,
) -> tuple[dict[str, Any], bool]:
    """Try constrained sampling, and fall back to unconstrained values.

    An escape hatch for entries that would need a constraint directed sampler.
    Code walking the whole corpus should not stop because of one entry.

    Returns (values, constraints_satisfied). If the second value is False the
    values are invalid and encryption must use check=False.
    """
    rng = rng or random.Random()
    try:
        return sample(entry, rng, max_rejections=max_rejections), True
    except SamplingError:
        return random_values(entry, rng), False


def rejection_rates(
    entry: Entry,
    rng: random.Random | None = None,
    *,
    trials: int = 200,
) -> dict[str, float]:
    """Measure how many samples each constraint rejects on its own.

    Measurement rather than syntactic guessing: it says exactly which
    constraint is the bottleneck. This is the first place to look when
    sampling fails.
    """
    rng = rng or random.Random(0)
    counts = {c["expr"]: 0 for c in entry.constraints}
    if not counts:
        return {}

    for _ in range(trials):
        values = random_values(entry, rng, use_bounds=True)
        for c in entry.constraints:
            expr = c["expr"]
            if not free_names(expr) <= values.keys():
                continue
            try:
                if not evaluate(expr, values):
                    counts[expr] += 1
            except ValueError:
                counts[expr] += 1

    return {expr: n / trials for expr, n in counts.items()}


def hard_constraints(
    entry: Entry,
    rng: random.Random | None = None,
    *,
    trials: int = 200,
    threshold: float = HARD_THRESHOLD,
) -> list[tuple[str, float]]:
    """Constraints that block rejection sampling, with their rejection rates.

    An empty list means the sampling failure is not caused by any single
    constraint but by their combination.
    """
    return sorted(
        ((expr, rate) for expr, rate
         in rejection_rates(entry, rng, trials=trials).items()
         if rate > threshold),
        key=lambda t: -t[1],
    )
