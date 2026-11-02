# `zero_metadata`: Blank compiler metadata

## Interface

```python
zero_metadata(code: bytes) -> bytes
```

## Arguments and return value

`code` is bytecode as `bytes`. The result has exactly the same length: bytes in
recognized metadata records are replaced with zeroes and all other bytes remain
unchanged. This preserves offsets while removing metadata content.

## Example

```python
import cbor2
from ethutils import zero_metadata

payload = cbor2.dumps({"solc": b"v"})
metadata = payload + len(payload).to_bytes(2, "big")
code = b"\x60\x01" + metadata + b"\x00"

result = zero_metadata(code)
result == b"\x60\x01" + b"\x00" * len(metadata) + b"\x00"
# True
len(result) == len(code)
# True
```
