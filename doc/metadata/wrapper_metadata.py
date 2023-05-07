import sys
sys.path.append("../..")

import ethutils.metadata

def drop0x(hex):
    return (None if hex is None else
            hex[2:] if hex[0:2] == "0x" else
            hex
           )

def solc(meta):
    version = meta.get("solc", "")
    if version:
        version = f"{int(version[0])}.{int(version[1])}.{int(version[2])}"
    return version

for line in sys.stdin:
    row = line.rstrip("\n").split(";")
    codeid = row[0]
    if codeid == "codeid":
        print("codeid;code_wo_meta;solc")
        continue
    address = row[1]
    code = bytes.fromhex(drop0x(row[2]))
    code_wo_meta,metas = ethutils.metadata.zeroMetadata(code)

    # Extract the version of the solc compiler
    # Should be the same in all metadata dicts
    version = ""
    for meta in metas:
        v = solc(meta)
        assert not version or v == version
        version = v
    
    print(f"{codeid};{code_wo_meta.hex()};{version}")
