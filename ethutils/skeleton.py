import sys             # system
import opcodes,section # ethutils

def skeletize(components):
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

def drop0x(hex):
    return (None if hex is None else
            hex[2:] if hex[0:2] == "0x" else
            hex
           )

def main_stdin():
    for line in sys.stdin:
        row = line.rstrip('\n').split(';')
        codeid = row[0]
        if codeid == 'codeid':
            print('codeid;skeleton')
            continue
        address = row[1]
        code = bytes.fromhex(drop0x(row[2]))
        sections = section.decompose(code)
        skeleton = skeletize(sections)
        print(f"{codeid};{skeleton.hex()}")

if __name__ == '__main__':
    sys.exit(main_stdin())

