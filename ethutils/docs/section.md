# `section`: Classify bytecode ranges

## Interface

```python
section(code: bytes) -> list[dict]
```

## Arguments and return value

`code` is an entire byte sequence, commonly creation bytecode. The result is a
sorted list of structural ranges with absolute `start` and exclusive `end`
offsets. Kinds include `code`, `data`, `returned`, and `meta`. Code and data
records identify their program `origin`; returned records also identify the
RETURN and CODECOPY evidence. Ranges may overlap.

Sectioning is structural inference. A reported range explains how bytes are
used by the analyzed program and is not a proof that every possible execution
was explored.

## Example

```python
from ethutils import section

section(bytes.fromhex("00aabb"))
# [{"kind": "code", "start": 0, "end": 1, "origin": 0}]
```

The trailing bytes have no established role and therefore have no record.
