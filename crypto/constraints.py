"""Safe parsing and evaluation of constraint expressions.

Corpus files may one day come from outside, so constraint expressions are
never run through eval(). What follows is a small interpreter: only
whitelisted AST nodes and functions are handled, nothing else runs.

The same whitelist is used by the validator at authoring time and by the
engine at runtime, so there is a single source of truth.
"""

from __future__ import annotations

import ast
import math
import operator
from typing import Any

from .errors import ConstraintViolation

# Permitted AST nodes.
SAFE_NODES = (
    ast.Expression, ast.BoolOp, ast.BinOp, ast.UnaryOp, ast.Compare,
    ast.Name, ast.Constant, ast.Load, ast.Call,
    ast.And, ast.Or, ast.Not, ast.USub, ast.UAdd,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn,
    ast.Tuple, ast.List,
)

SAFE_FUNCS = {
    "abs": abs,
    "min": min,
    "max": max,
    "pow": pow,
    "gcd": math.gcd,
    "len": len,
}

# Exponentiation is a denial of service vector: a ** a with a 2048 bit number
# eats all the memory. The ceiling is fixed, since real constraints always use
# small exponents.
MAX_EXPONENT = 64

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_CMPOPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


def parse(expr: str) -> ast.Expression:
    """Parse an expression and check it against the whitelist.

    Raises ValueError on a problem. Does not evaluate anything.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ValueError(f"could not parse expression: {e.msg}") from e

    for node in ast.walk(tree):
        if not isinstance(node, SAFE_NODES):
            raise ValueError(f"construct not allowed: {type(node).__name__}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) \
                    or node.func.id not in SAFE_FUNCS:
                name = getattr(node.func, "id", "?")
                raise ValueError(f"function not allowed: {name!r}")
    return tree


def free_names(expr: str) -> set[str]:
    """Variable names the expression refers to, excluding function names."""
    tree = parse(expr)
    return {n.id for n in ast.walk(tree)
            if isinstance(n, ast.Name)} - set(SAFE_FUNCS)


def _eval(node: ast.AST, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, env)

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ValueError(f"undefined name: {node.id!r}")
        return env[node.id]

    if isinstance(node, ast.UnaryOp):
        val = _eval(node.operand, env)
        if isinstance(node.op, ast.Not):
            return not val
        if isinstance(node.op, ast.USub):
            return -val
        return +val

    if isinstance(node, ast.BinOp):
        left = _eval(node.left, env)
        right = _eval(node.right, env)
        if isinstance(node.op, ast.Pow):
            if not isinstance(right, int) or right > MAX_EXPONENT or right < 0:
                raise ValueError(
                    f"exponent must be an integer between 0 and "
                    f"{MAX_EXPONENT}, got {right}")
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and right == 0:
            raise ValueError("division by zero")
        return _BINOPS[type(node.op)](left, right)

    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(_eval(v, env) for v in node.values)
        return any(_eval(v, env) for v in node.values)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, env)
        for op, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, env)
            if not _CMPOPS[type(op)](left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.Call):
        args = [_eval(a, env) for a in node.args]
        return SAFE_FUNCS[node.func.id](*args)

    if isinstance(node, (ast.Tuple, ast.List)):
        return [_eval(e, env) for e in node.elts]

    raise ValueError(f"node cannot be evaluated: {type(node).__name__}")


def evaluate(expr: str, values: dict[str, Any]) -> bool:
    """Evaluate a constraint against the given values."""
    return bool(_eval(parse(expr), values))


def equality_gap(expr: str, values: dict[str, Any]) -> Any | None:
    """For a `left == right` constraint, return (left - right).

    Returns None if the constraint is not an equality.

    The sampler uses this to solve equalities. If the gap function is linear
    in one variable, g(v) = A*v + B, evaluating at two points gives A and B and
    the root follows from v = -B/A. That is far more effective than sampling
    at random and hoping to hit it.
    """
    node = parse(expr).body
    if not (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
    ):
        return None
    return _eval(node.left, values) - _eval(node.comparators[0], values)


# Errors that can come out of EVALUATING a constraint. They mean "constraint
# not satisfied", not "the engine is broken":
#   ValueError      division by zero, huge exponent, math domain error
#   TypeError       an unexpected value type, such as comparing bytes
#   ArithmeticError overflow, including OverflowError
# The list is deliberately narrow. Catching `Exception` would hide a real
# engine bug behind a "constraint violation".
EVALUATION_ERRORS = (ValueError, TypeError, ArithmeticError)


def check_all(constraints, values, *, skip_unknown: bool = False) -> list[str]:
    """Check constraints in order.

    Violations at error level raise ConstraintViolation. Violations at warning
    level are collected and returned.

    With skip_unknown=True, constraints referring to names we have no value
    for are skipped silently. Decoding needs that: secret parameters are not
    written into the ciphertext, so constraints referring to them cannot be
    checked.
    """
    warnings: list[str] = []
    for c in constraints:
        expr = c["expr"]
        if skip_unknown and not free_names(expr) <= values.keys():
            continue

        level = c.get("severity", "error")
        try:
            ok = evaluate(expr, values)
        except EVALUATION_ERRORS as err:
            # Constraint could not be evaluated. Found by fuzzing, 2026-08-19.
            #
            # Constraint expressions are written assuming valid values. When
            # decoding, values come from the ciphertext, and a hostile or
            # corrupt payload producing `p = 0` made `... % p != 0` raise
            # `ValueError: division by zero`, which escaped the CryptoError
            # hierarchy entirely.
            #
            # That matters because the engine's contract is "every rejection
            # is a CryptoError". An exception outside the contract punches
            # through the caller's `except CryptoError` and takes the
            # application down.
            #
            # The right response: a constraint that cannot be evaluated is a
            # constraint that is not satisfied. `p = 0` is not a valid prime
            # anyway, and the expression blowing up is a symptom of that, not
            # a separate event.
            if level == "warning":
                warnings.append(
                    f"constraint could not be evaluated ({err})  "
                    f"(constraint: {expr})")
                continue
            raise ConstraintViolation(
                expr,
                f"{c['reason']} — could not evaluate the constraint with "
                f"these values ({type(err).__name__}: {err})",
            ) from err

        if not ok:
            if level == "warning":
                warnings.append(f"{c['reason']}  (constraint: {expr})")
            else:
                raise ConstraintViolation(expr, c["reason"])
    return warnings
