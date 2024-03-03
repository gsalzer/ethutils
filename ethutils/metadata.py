import io, cbor2

def decode_cbor(code):
    fp = io.BytesIO(code)
    cbor = cbor2.load(fp)
    rest = fp.read()
    return cbor, rest

# CBOR structure must contain one of the following keys
# to be considered Solidity meta-data
META_ANY = ('bzzr0','bzzr1','ipfs','solc')

# sanity check: all keys in the Solidity meta-data must be
# among the following ones, otherwise raise exception.
META_ALL = ('bzzr0','bzzr1','ipfs','solc','experimental')

# CBOR structures must contain at most META_MAX keys
# to be considered Solidity meta-data
# maximal value for META_MAX: 23
META_MAX = 5

def metadata(code):
    len_code, i, metas = len(code), 0, []
    while i < len_code:
        if not (0xa1 <= code[i] <= 0xa0 + META_MAX):
            # not the start of a dict with 1 to META_MAX entries
            i += 1
            continue
        try: # to interpret code[i:] as a dict followed by its length
            cbor,rest = decode_cbor(code[i:])
            len_metadata = int.from_bytes(rest[:2],"big")
        except Exception:
            i += 1
            continue
        if (len_metadata == len_code-len(rest)-i
            and any(k in cbor for k in META_ANY)):
            if not all(k in META_ALL for k in cbor):
                raise ValueError(f"unknown key in {cbor}")
            metas.append((i, len_metadata+2, cbor))
            i += len_metadata+2
        else:
            i += 1
    return metas

def zeroMetadata(code):
    code_wo_metadata, code_start, metadatas = b"", 0, []
    for s,l,m in metadata(code):
        code_wo_metadata += code[code_start:s] + b"\x00"*l
        code_start = s + l
        metadatas.append(m)
    code_wo_metadata += code[code_start:]
    return code_wo_metadata, metadatas
