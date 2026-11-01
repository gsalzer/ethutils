"""Bytecode fixture assembly using the shared opcode definitions."""
from ethutils import opcodes as e


def properties_with_evidence(api, code, **kwargs):
    """Return summaries augmented with diagnostic evidence from the callback."""
    events = []
    report = api.properties(code, trace=events.append, **kwargs)
    evidence = {event['selector']: event for event in events
                if event['kind'] == 'function_analysis'}
    return report, {selector: {**summary, 'analysis': evidence[selector]}
                    for selector, summary in report.properties.items()}


class Assembly:
    """Small fixture assembler: byte opcodes and numeric PUSH data, labels."""
    def __init__(self):
        self.code, self.labels, self.fixups = bytearray(), {}, []

    def emit(self, *ops):
        for op in ops:
            self.code.extend(op if isinstance(op, bytes) else bytes([op]))
        return self

    def push(self, value, size=None):
        size = size or max(1, (value.bit_length()+7)//8)
        return self.emit(getattr(e, f"PUSH{size}"), *value.to_bytes(size, "big"))

    def target(self, label):
        self.fixups.append((len(self.code)+1, label))
        return self.emit(e.PUSH2, 0, 0)

    def label(self, name):
        self.labels[name] = len(self.code)
        return self.emit(e.JUMPDEST)

    def reject(self): return self.emit(e.PUSH0, e.PUSH0, e.REVERT)

    def build(self):
        code = self.code.copy()
        for offset, name in self.fixups: code[offset:offset+2] = self.labels[name].to_bytes(2, "big")
        return bytes(code)


def selector(a): return a.emit(e.PUSH0, e.CALLDATALOAD).push(224).emit(e.SHR)


def compare(a, value, label):
    return a.emit(e.DUP1).push(value).emit(e.EQ).target(label).emit(e.JUMPI)


def length_guard(a, fallback="fallback"):
    return a.push(4).emit(e.CALLDATASIZE, e.LT).target(fallback).emit(e.JUMPI)


def guard(a, continuation):
    return a.emit(e.CALLVALUE, e.ISZERO).target(continuation).emit(e.JUMPI).reject().label(continuation)



def raw_bytes(values):
    if isinstance(values, bytes):
        return values
    return b''.join(value if isinstance(value, bytes) else bytes([value]) for value in values)
