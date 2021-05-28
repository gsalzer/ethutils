import sys
sys.path.append("..")
from ethutils import skeleton

def drop0x(hex):
    return (None if hex is None else
            hex[2:] if hex[0:2] == "0x" else
            hex
           )

for line in sys.stdin:
    row = line.rstrip('\n').split(';')
    codeid = row[0]
    if codeid == 'codeid':
        print('codeid;skeleton')
        continue
    address = row[1]
    code = bytes.fromhex(drop0x(row[2]))
    skel = skeleton.skeletize(code)
    print(f"{codeid};{skel.hex()}")

