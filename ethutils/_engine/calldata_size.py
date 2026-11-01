"""Distinguish calculations with calldata length from simple length checks.

Expressions are classified by whether they contain CALLDATASIZE, calculate
with it, and produce a boolean. Results are cached by expression identity.
"""
from .. import opcodes as op

CACHE_SIZE = 2048
COMPARISONS = {op.EQ, op.LT, op.GT, op.SLT, op.SGT}
BOOLEAN_BINARY = {op.AND, op.OR, op.XOR}


def uses_size_arithmetic(value, memo):
    """Return whether value uses calldata length in a calculation such as addition or subtraction.

    Direct comparisons and boolean combinations count as length checks. memo
    stores reusable classifications for the expression and its children.
    """
    return _classify(value, memo)[1]


def _classify(value, memo):
    """Return (contains size, contains size calculation, is boolean)."""
    if isinstance(value, int):
        return False, False, value in (0, 1)
    key = id(value)
    if key in memo:
        return memo[key][1:]
    children = [_classify(arg, memo) for arg in value.args]
    size = value.op == op.CALLDATASIZE or any(c[0] for c in children)
    boolean = (value.op in COMPARISONS or value.op == op.ISZERO
               or (value.op in BOOLEAN_BINARY and all(c[2] for c in children)))
    calculation = (any(c[1] for c in children)
                   or (size and value.op != op.CALLDATASIZE and not boolean))
    if len(memo) >= CACHE_SIZE:
        memo.clear()
    memo[key] = (value, size, calculation, boolean)
    return size, calculation, boolean
