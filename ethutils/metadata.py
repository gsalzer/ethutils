import io, re, cbor2, sys

BZZR0 = b'bzzr0'
BZZR1 = b'bzzr1'
IPFS  = b'ipfs'
KEY_RE = re.compile(BZZR0 + b'|' + BZZR1 + b'|' + IPFS)
MAX_METADATA_OFFSET = 50


def decodeMetadata(code, key):
    '''Return CBOR-encoded metadata located at the beginning of code'''
    try:
        fp = io.BytesIO(code)
        metadata = cbor2.load(fp)
        if isinstance(metadata,dict) and key in metadata:
            rest = fp.read()
            len_metadata = int.from_bytes(rest[:2],'big')
            if len(rest) >= 2 and len_metadata == len(code)-len(rest):
                return len_metadata+2, metadata
    except Exception:
        pass
    return 0, None


def zeroMetadata(code):
    metadatas = []
    code_wo_metadata = b''
    start_code = 0
    i = 0
    while True:
        # find the next key indicating metadata
        key_match = KEY_RE.search(code,i)
        if key_match is None:
            break
        key = key_match[0].decode('ascii')
        start_key = key_match.start()
        end_key = key_match.end()

        # Search backwards from the hash_keyword to find the start of the metadata.
        # In proper metadata, the key is preceded by at least 2 and followed
        # by at least 34 bytes
        found = False
        for start_metadata in range(start_key-2, max(start_key-MAX_METADATA_OFFSET,start_code)-1, -1):
            len_metadata,metadata = decodeMetadata(code[start_metadata:], key)
            end_metadata = start_metadata + len_metadata
            found = end_metadata >= end_key + 34
            if found:
                break
        if not found:
            i = start_key + 1
            continue

        metadatas.append(metadata)
        code_wo_metadata += code[start_code:start_metadata] + b'\x00'*len_metadata
        start_code = end_metadata
        i = end_metadata

    if start_code < len(code):
        code_wo_metadata += code[start_code:]

    return code_wo_metadata, metadatas



def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file with bytecode>")
        return 1

    with open(sys.argv[1]) as f:
        hexcode = f.read().strip()
    if hexcode[:2] == "0x":
        hexcode = hexcode[2:]
    bytecode = bytes.fromhex(hexcode)
    bytecode_wo_metadata, metadatas = zeroMetadata(bytecode)
    print(bytecode_wo_metadata.hex())
    for metadata in metadatas:
        print(metadata)
        if 'solc' in metadata:
            print(f"solc version: {int(metadata['solc'][0])}.{int(metadata['solc'][1])}.{int(metadata['solc'][2])}")



if __name__ == "__main__":
    sys.exit(main())

