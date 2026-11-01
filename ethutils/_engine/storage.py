"""Classify expressions that read contract storage.

The categories distinguish storage fields, comparisons and further calculations.
This helps identify where function-selection checks give way to function work.
Results are cached by expression identity.
"""
from .. import opcodes as op

CACHE_SIZE = 2048


def power_of_two(value):
    """Return whether value is a positive integer with exactly one set bit."""
    return isinstance(value, int) and value > 0 and not value & (value - 1)


def classify(value, memo):
    """Return an expression category and whether it contains a storage read.

    term covers simple values and field extraction; zero_test covers subtraction;
    predicate covers comparisons and boolean combinations. Other expressions use
    calculation when they depend on storage, and free_computation otherwise.
    memo stores reusable results for the expression and its children.
    """
    if isinstance(value, int):
        return 'term', False
    key = id(value)
    if key in memo:
        return memo[key][1:]
    opcode, args = value.op, value.args
    children = [classify(x, memo) for x in args]
    storage = opcode == op.SLOAD or any(x[1] for x in children)
    kinds = [x[0] for x in children]
    if opcode == op.SLOAD:
        kind = 'term' if isinstance(args[0], int) else 'calculation'
    elif not args:
        kind = 'term'
    elif opcode in {op.AND, op.OR, op.XOR} and all(k == 'term' for k in kinds):
        kind = 'term'
    elif opcode == op.NOT and kinds[0] == 'term':
        kind = 'term'
    elif (opcode in {op.SHR, op.SHL, op.SAR, op.BYTE, op.SIGNEXTEND}
          and isinstance(args[0], int) and kinds[1] == 'term'):
        kind = 'term'
    elif opcode in {op.DIV, op.MOD} and kinds[0] == 'term' and power_of_two(args[1]):
        kind = 'term'
    elif (opcode == op.MUL and any(power_of_two(x) for x in args)
          and all(k == 'term' for k in kinds)):
        kind = 'term'
    elif opcode == op.SUB and all(k == 'term' for k in kinds):
        kind = 'zero_test'
    elif opcode == op.ISZERO and kinds[0] in {'term', 'zero_test', 'predicate'}:
        kind = 'predicate'
    elif opcode in {op.EQ, op.LT, op.GT, op.SLT, op.SGT} and all(k == 'term' for k in kinds):
        kind = 'predicate'
    elif (opcode == op.EQ and any(isinstance(x, int) and x == 0 for x in args)
          and all(k in {'term', 'zero_test', 'predicate'} for k in kinds)):
        kind = 'predicate'
    elif opcode in {op.AND, op.OR, op.XOR} and all(k in {'term', 'predicate'} for k in kinds):
        kind = 'predicate'
    else:
        kind = 'calculation' if storage else 'free_computation'
    if len(memo) >= CACHE_SIZE:
        memo.clear()
    memo[key] = (value, kind, storage)
    return kind, storage
