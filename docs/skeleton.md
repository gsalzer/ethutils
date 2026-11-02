# `skeleton`: Build a structural fingerprint

## Interface

```python
skeleton(code: bytes) -> bytes
```

## Arguments and return value

`code` is EVM bytecode as `bytes`. The result removes recognized metadata
records completely and replaces each PUSH plus its operand with `PUSH0`. It is
useful for comparing instruction structure, but matching skeletons do not prove
semantic equivalence.

## Example

```python
import cbor2
from ethutils import skeleton

payload = cbor2.dumps({"solc": b"v"})
metadata = payload + len(payload).to_bytes(2, "big")
code = bytes.fromhex("60015b") + metadata + bytes.fromhex("00")

skeleton(code).hex()
# "5f5b00"
```
