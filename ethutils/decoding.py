"""Decode EVM byte sequences into instructions and locate their byte offsets."""
from collections.abc import Iterator
from dataclasses import dataclass
from .opcodes import BY_VALUE


@dataclass(frozen=True)
class Instruction:
    """An instruction with absolute byte offsets and an exclusive end.

    name is None for an undefined opcode. immediate contains only input bytes;
    truncated marks a PUSH whose operand extends past the decoding range.
    """
    pc: int
    opcode: int
    name: str | None
    immediate: bytes
    end: int
    truncated: bool = False


def require_bytes(code: bytes) -> None:
    """Raise TypeError when the bytecode argument has a type other than bytes."""
    if not isinstance(code, bytes):
        raise TypeError('bytecode must be bytes; use parse_hex() for hexadecimal text')


def parse_hex(text: str) -> bytes:
    """Decode hex text with an optional 0x or literal backslash-x prefix.

    Prefix matching is case-insensitive; bytes.fromhex handles whitespace and
    raises ValueError for malformed hex, including unresolved placeholders.
    """
    if not isinstance(text, str):
        raise TypeError('hexadecimal input must be str')
    text = text.strip()
    if text.startswith(('0x', '0X', '\\x', '\\X')):
        text = text[2:]
    return bytes.fromhex(text)


def disassemble(code: bytes, *, start: int = 0, end: int | None = None) -> Iterator[Instruction]:
    """Yield instructions from start up to end, with offsets into the original code.

    Decoding starts at the supplied offset. Undefined opcodes consume one byte;
    PUSH instructions consume their opcode and the available operand bytes.
    An incomplete PUSH is marked truncated. Invalid ranges raise ValueError
    when the iterator is consumed.
    """
    require_bytes(code)
    limit = len(code) if end is None else end
    if not 0 <= start <= limit <= len(code):
        raise ValueError('instruction range must satisfy 0 <= start <= end <= len(code)')
    pc = start
    while pc < limit:
        info = BY_VALUE[code[pc]]
        expected_end = pc + 1 + (info.immediate if info else 0)
        end = min(expected_end, limit)
        yield Instruction(pc, code[pc], info.name if info else None,
                          code[pc+1:end], end, expected_end > limit)
        pc = expected_end


def instruction_boundaries(code: bytes) -> list[int]:
    """Return instruction start offsets, followed by the input length for a complete final instruction.

    For a truncated final PUSH, the result ends at that instruction's start.
    """
    positions = []
    truncated = False
    for instruction in disassemble(code):
        positions.append(instruction.pc)
        truncated = instruction.truncated
    if not truncated:
        positions.append(len(code))
    return positions
