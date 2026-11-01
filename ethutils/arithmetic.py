"""Evaluate EVM arithmetic on 256-bit words.

Operands follow stack-pop order, with the top of the stack first. Results
are reduced modulo 2**256.
"""
from types import MappingProxyType
from . import opcodes as op

MASK = (1 << 256) - 1


def signed(value):
    """Interpret an unsigned 256-bit word as a two's-complement integer."""
    return value if value < 1 << 255 else value - (1 << 256)


def signed_divide(a, b):
    """Divide signed words, truncating toward zero; division by zero returns zero."""
    x, y = signed(a), signed(b)
    return (abs(x)//abs(y)) * (-1 if (x < 0) != (y < 0) else 1) if y else 0


def signed_modulo(a, b):
    """Return a signed remainder with the dividend's sign, or zero for divisor zero."""
    x, y = signed(a), signed(b)
    return (abs(x) % abs(y)) * (-1 if x < 0 else 1) if y else 0


def sign_extend(index, word):
    """Extend the sign of byte index (counted from the least significant byte)."""
    if index >= 32:
        return word
    bits = 8*(index+1)
    low_mask = (1 << bits)-1
    return word | (MASK ^ low_mask) if word & (1 << (bits-1)) else word & low_mask


EVALUATORS = MappingProxyType({
    op.ADD: lambda a, b: a+b,
    op.MUL: lambda a, b: a*b,
    op.SUB: lambda a, b: a-b,
    op.DIV: lambda a, b: a//b if b else 0,
    op.SDIV: signed_divide,
    op.MOD: lambda a, b: a % b if b else 0,
    op.SMOD: signed_modulo,
    op.ADDMOD: lambda a, b, m: (a+b) % m if m else 0,
    op.MULMOD: lambda a, b, m: (a*b) % m if m else 0,
    op.EXP: lambda a, b: pow(a, b, 1 << 256),
    op.SIGNEXTEND: sign_extend,
    op.LT: lambda a, b: int(a < b),
    op.GT: lambda a, b: int(a > b),
    op.SLT: lambda a, b: int(signed(a) < signed(b)),
    op.SGT: lambda a, b: int(signed(a) > signed(b)),
    op.EQ: lambda a, b: int(a == b),
    op.ISZERO: lambda a: int(a == 0),
    op.AND: lambda a, b: a & b,
    op.OR: lambda a, b: a | b,
    op.XOR: lambda a, b: a ^ b,
    op.NOT: lambda a: ~a,
    op.BYTE: lambda i, a: (a >> (8*(31-i))) & 255 if i < 32 else 0,
    op.SHL: lambda n, a: a << n if n < 256 else 0,
    op.SHR: lambda n, a: a >> n if n < 256 else 0,
    op.SAR: lambda n, a: signed(a) >> min(n, 256),
})


def evaluate(opcode: bytes, operands) -> int:
    """Evaluate unsigned 256-bit operands in stack-pop order and wrap the result.

    Unsupported opcodes raise ValueError; operand count must match the opcode.
    """
    try:
        function = EVALUATORS[opcode]
    except KeyError:
        raise ValueError(f'no concrete arithmetic operation for {opcode!r}') from None
    return function(*operands) & MASK
