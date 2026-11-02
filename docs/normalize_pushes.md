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

code = bytes.fromhex("60016112340100") # PUSH1 0x01, PUSH2 0x1234, ADD, STOP
normalize_pushes(code).hex()
# "5f5f0100" # PUSH0, PUSH0, ADD, STOP
```
