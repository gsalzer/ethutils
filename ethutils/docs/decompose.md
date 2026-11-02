# `decompose`: Partition classified bytes

## Interface

```python
decompose(code: bytes) -> list[tuple[str, bytes]]
```

## Arguments and return value

`code` is a complete byte sequence. The result partitions it into ordered,
non-empty chunks tagged `"code"`, `"data"`, `"meta"`, or `""` when unclassified.
Concatenating the chunk values always reproduces the input.

Overlapping section records are resolved with metadata above code and code above
data. Uncovered portions of a broader data section remain data. Structural
boundaries are preserved even when adjacent chunks have the same tag.

## Example

```python
from ethutils import decompose

parts = decompose(bytes.fromhex("00aabb"))
[(tag, data.hex()) for tag, data in parts]
# [("code", "00"), ("", "aabb")]

b"".join(data for _, data in parts).hex()
# "00aabb"
```
