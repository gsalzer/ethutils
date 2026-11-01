"""Create bytecode fingerprints by removing metadata and replacing pushed constants."""
from .decoding import disassemble, require_bytes
from .opcodes import BY_VALUE, PUSH0


def normalize_pushes(code: bytes) -> bytes:
    """Replace every PUSH and its available operand bytes with a single PUSH0 byte.

    Other opcode bytes retain their order. Truncated PUSHes are included. The
    result provides a fingerprint for comparing instruction sequences.
    """
    return bytes(PUSH0[0] if BY_VALUE[i.opcode] and BY_VALUE[i.opcode].family == 'push'
                 else i.opcode for i in disassemble(code))


def skeleton(code: bytes) -> bytes:
    """Remove recognized compiler metadata and replace PUSH instructions and operands with PUSH0."""
    require_bytes(code)
    from .metadata import extract_metadata
    cursor = 0
    parts = []
    for start, size, _ in extract_metadata(code):
        parts.append(normalize_pushes(code[cursor:start]))
        cursor = start+size
    parts.append(normalize_pushes(code[cursor:]))
    return b''.join(parts)
