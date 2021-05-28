import sys
from ethutils import opcodes,section

def skeletize(code):
    components = section.decompose(code)
    skeleton = []
    for t,c in components:
        if t == section.META or t == section.DATA:
            # replace metahash and data by zeros
            skeleton.append(b'\x00' * len(c))
        elif t == section.CODE:
            # replace the arguments of push by zeros
            this = 0
            last = this
            while this < len(c):
                opcode = c[this]
                this += 1
                if opcode not in opcodes.BYTECODES:
                    continue
                i = min(opcodes.BYTECODES[opcode].push_len(),len(c)-this)
                if i > 0:
                    skeleton.append(c[last:this])
                    skeleton.append(b'\x00'*i)
                    this += i
                    last = this
            skeleton.append(c[last:])
        else:
            raise ValueError(f"Unknown structure type {t}")
    # remove trailing zeros
    return b''.join(skeleton).rstrip(b'\x00')
