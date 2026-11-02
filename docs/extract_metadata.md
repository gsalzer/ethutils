# `extract_metadata`: Find compiler metadata

## Interface

```python
extract_metadata(code: bytes) -> list[tuple[int, int, dict]]
```

## Arguments and return value

`code` is a byte sequence to scan. The result contains `(start, length,
decoded)` tuples for recognized Solidity-style CBOR maps. Offsets are absolute,
and `length` includes the two-byte big-endian length suffix.

A candidate must contain a recognized compiler or content key. Malformed
candidates are ignored; a matching map with an unknown key raises `ValueError`.
Recognized enclosing blocks take precedence over blocks nested inside them.

## Example

```python
import cbor2
from ethutils import extract_metadata

payload = cbor2.dumps({"solc": b"\x00\x08\x1e"})
metadata = payload + len(payload).to_bytes(2, "big")
code = b"\x00" + metadata

extract_metadata(code)
# [(1, 12, {"solc": b"\x00\x08\x1e"})]
```
