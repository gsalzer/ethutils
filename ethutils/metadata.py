"""Locate Solidity compiler metadata encoded as CBOR maps and replace its bytes with zeros."""
import io
from cbor2 import CBORDecoder
from .decoding import require_bytes

def decode_cbor(code):
    """Decode one CBOR value and return it with the unconsumed suffix.

    Decoder errors propagate to the caller.
    """
    with io.BytesIO(code) as fp:
        cbor = CBORDecoder(fp).decode()
        rest = fp.read()
    return cbor, rest

# At least one recognized compiler/content key is required.
META_ANY = ('bzzr0','bzzr1','ipfs','solc')

# A matching record with keys outside this set raises ValueError.
META_ALL = ('bzzr0','bzzr1','ipfs','solc','experimental')

# Scan only definite-length CBOR maps with 1 through META_MAX entries.
# The single-byte map-header check supports a maximum of 23 entries.
META_MAX = 5

def extract_metadata(code: bytes) -> list[tuple[int, int, dict]]:
    """Scan all byte offsets for Solidity CBOR maps followed by their length.

    Return (absolute start, total length, decoded dictionary) for each match;
    total length includes the two-byte big-endian length suffix. The scan covers
    the entire input, including code and embedded program bytes.
    Malformed candidates are skipped. A matching map with an unrecognized
    key raises ValueError.
    """
    require_bytes(code)
    len_code, i, metas = len(code), 0, []
    while i < len_code:
        advance = 1
        if 0xa1 <= code[i] <= 0xa0 + META_MAX:
            try:
                cbor, rest = decode_cbor(code[i:])
            except Exception:
                pass  # A malformed candidate leaves the one-byte advance intact.
            else:
                len_metadata = len_code - len(rest) - i
                if (len(rest) >= 2
                    and int.from_bytes(rest[:2], "big") == len_metadata
                    and any(k in cbor for k in META_ANY)):
                    if not all(k in META_ALL for k in cbor):
                        raise ValueError(f"unknown key in {cbor}")
                    advance = len_metadata + 2
                    metas.append((i, advance, cbor))
        i += advance
    return metas

def zero_metadata(code: bytes) -> bytes:
    """Replace recognized metadata with zero bytes, preserving input length and byte offsets."""
    parts, cursor = [], 0
    for start, length, _ in extract_metadata(code):
        parts.extend((code[cursor:start], b'\x00'*length))
        cursor = start+length
    parts.append(code[cursor:])
    return b''.join(parts)
