import sys
from ethutils import opcodes, metadata

def normalize_push(code):
    len_code, i, ops = len(code), 0, []
    while i < len_code:
        op = code[i]
        i += 1
        if op in opcodes.BYTECODES:
            opcode = opcodes.BYTECODES[op]
            if opcode.is_push():
                op = opcodes.PUSH0.code
                i += opcode.push_len()
        ops.append(op)
    return bytes(ops)

def skeletize(code):
    i, skeleton = 0, []
    for s,l,_ in metadata.metadata(code):
        skeleton.append(normalize_push(code[i:s]))
        i = s + l
    skeleton.append(normalize_push(code[i:]))
    return b''.join(skeleton)
