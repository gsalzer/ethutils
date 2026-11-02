# `runtime`: Extract deployed bytecode

## Interface

```python
runtime(code: bytes) -> bytes | None
```

## Arguments and return value

`code` is presumed creation bytecode. The result is the unique byte sequence
that structural analysis finds returned by the origin-zero program and accepted
as code at its entry. It includes associated data and metadata. The function
returns `None` when this evidence is missing or ambiguous.

## Example

```python
from ethutils import runtime

deployed = bytes.fromhex("6003565b00")
creation = bytes.fromhex("6005600c60003960056000f3") + deployed

runtime(creation) == deployed
# True
runtime(deployed)
# None
```
