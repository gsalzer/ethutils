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
code = bytes.fromhex("6001ff") + metadata + bytes.fromhex("fe")

code.hex()
# '6001ffa164736f6c6341760008fe' # PUSH1 0x01, SELFDESTRUCT, {"solc": b"v"}, INVALID

skeleton(code).hex()
# "5ffffe" # PUSH0, SELFDESTRUCT, INVALID
```
