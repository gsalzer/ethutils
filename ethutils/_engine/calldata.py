"""Determine which expression bits depend on function arguments in call data.

The first four calldata bytes hold the function selector; argument bytes start
at offset four. Bit masks, shifts and byte extraction identify which input
bytes contribute to a result. Other operations combine their operands'
dependencies conservatively.
"""
from ..opcodes import (CALLDATALOAD, SLOAD, BYTE, SHR, SHL, AND, OR, XOR, NOT,
                     DIV, MUL)

WORD_MASK = (1 << 256) - 1
CACHE_SIZE = 1024


def uses_arguments(word, *, needed=WORD_MASK, memo=None):
    """Return whether the bits selected by needed can depend on calldata bytes from offset four.

    memo optionally supplies a reusable cache of expression-and-mask results.
    The cache holds up to CACHE_SIZE entries and retains the expressions it keys.
    """
    return _uses_arguments(word, needed, {} if memo is None else memo)


def _uses_arguments(value, mask, memo):
    # Propagate the demanded output-bit mask back to source calldata bytes.
    mask &= WORD_MASK
    if isinstance(value, int) or not mask:
        return False
    # Key by expression identity and keep the expression alive with its cached result.
    key = (id(value), mask)
    if key in memo:
        return memo[key][1]
    op, args = value.op, value.args
    if op == CALLDATALOAD:
        offset = args[0]
        # Low bits of overlapping words contain bytes after the selector.
        result = (not isinstance(offset, int) or offset >= 4 or
                  bool(mask & ((1 << (8 * (28 + offset))) - 1)))
    elif op == SLOAD or not args:
        # SLOAD represents the value stored in a slot; its address is a separate input.
        result = False
    elif op == BYTE and isinstance(args[0], int):
        index = args[0]
        result = index < 32 and _uses_arguments(args[1], (mask & 255) << (8 * (31 - index)), memo)
    elif op in {SHR, SHL} and isinstance(args[0], int):
        shift = args[0]
        result = shift < 256 and _uses_arguments(
            args[1], mask << shift if op == SHR else mask >> shift, memo)
    elif op == AND:
        constant = next((a for a in args if isinstance(a, int)), WORD_MASK)
        result = any(_uses_arguments(a, mask & constant, memo) for a in args)
    elif op == OR:
        constant = next((a for a in args if isinstance(a, int)), 0)
        result = any(_uses_arguments(a, mask & ~constant, memo) for a in args)
    elif op in {XOR, NOT}:
        result = any(_uses_arguments(a, mask, memo) for a in args)
    elif (op == DIV and isinstance(args[1], int) and args[1] > 0
          and args[1] & (args[1] - 1) == 0):
        result = _uses_arguments(args[0], mask << (args[1].bit_length() - 1), memo)
    elif op == MUL and any(isinstance(a, int) for a in args):
        constant = next(a for a in args if isinstance(a, int))
        if constant > 0 and constant & (constant - 1) == 0:
            result = any(_uses_arguments(a, mask >> (constant.bit_length() - 1), memo) for a in args)
        else:
            result = any(_uses_arguments(a, WORD_MASK, memo) for a in args)
    else:
        result = any(_uses_arguments(a, WORD_MASK, memo) for a in args)
    if len(memo) >= CACHE_SIZE:
        memo.clear()
    memo[key] = (value, bool(result))
    return bool(result)
