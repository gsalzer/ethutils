# `disassemble`: Decode EVM instructions

## Interface

```python
disassemble(code: bytes, *, start: int = 0, end: int | None = None) -> Iterator[Instruction]
```

## Arguments and return value

`code` is EVM bytecode as `bytes`. `start` and `end` select a half-open byte
range; both are offsets in the original input. The function returns a lazy
iterator of `Instruction` records. Each record has `pc`, numeric `opcode`,
`name`, `immediate`, exclusive `end`, and `truncated` fields.

Unknown opcodes have `name=None`. A PUSH extending beyond `end` retains the
available operand bytes and has `truncated=True`. Invalid ranges raise
`ValueError` when the iterator is consumed.

## Example

```python
from ethutils import disassemble

rows = list(disassemble(bytes.fromhex("605b0c6101")))
[(i.pc, i.name, i.immediate.hex(), i.end, i.truncated) for i in rows]
# [(0, "PUSH1", "5b", 2, False),
#  (2, None, "", 3, False),
#  (3, "PUSH2", "01", 5, True)]
```
