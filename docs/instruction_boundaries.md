# `instruction_boundaries`: Locate instruction starts

## Interface

```python
instruction_boundaries(code: bytes) -> list[int]
```

## Arguments and return value

`code` is complete EVM bytecode as `bytes`. The result contains every
instruction start. It also contains `len(code)` when the final instruction is
complete, making adjacent entries usable as instruction ranges. PUSH operand
positions are omitted. A truncated final PUSH contributes its own start but not
the input end.

## Examples

```python
from ethutils import instruction_boundaries

instruction_boundaries(bytes.fromhex("605b00"))
# [0, 2, 3]

instruction_boundaries(bytes.fromhex("6101"))
# [0]  (the PUSH2 operand is incomplete)
```
