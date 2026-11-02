# `normalize_pushes`: Remove pushed constants

## Interface

```python
normalize_pushes(code: bytes) -> bytes
```

## Arguments and return value

`code` is EVM bytecode as `bytes`. Every PUSH instruction, including its
available immediate bytes, becomes one `PUSH0` byte. Other instruction bytes
retain their order. The result is normally shorter and serves as a structural
fingerprint rather than executable replacement code.

## Example

```python
from ethutils import normalize_pushes

normalize_pushes(bytes.fromhex("60016112340100")).hex()
# "5f5f0100"
```
