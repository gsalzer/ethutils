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

## Examples

### A simple one

```python
from ethutils import decompose

parts = decompose(bytes.fromhex("00aabb"))
[(tag, data.hex()) for tag, data in parts]
# [("code", "00"), ("", "aabb")]

b"".join(data for _, data in parts).hex()
# "00aabb"
```

### A more complex one


This uses the same creation bytecode as the `section` and `analyze_sections`
examples. The constructor copies and returns a runtime image containing one
instruction, ordinary data, compiler metadata, and trailing data.

```python
import cbor2
from ethutils import decompose

payload = cbor2.dumps({"solc": b"\x00\x08\x1e"})
metadata = payload + len(payload).to_bytes(2, "big")
runtime = b"\x00\xaa\xbb" + metadata + b"\xcc"
constructor = bytes.fromhex("6010600a5f3960105ff3")
creation = constructor + runtime

parts = decompose(creation)
[(tag, data.hex()) for tag, data in parts]
# [("code", "6010600a5f3960105ff3"),
#  ("code", "00"),
#  ("data", "aabb"),
#  ("meta", "a164736f6c634300081e000a"),
#  ("data", "cc")]

b"".join(data for _, data in parts) == creation
# True
```

The two adjacent `"code"` chunks remain separate because the first belongs to
the origin-zero constructor and the second is the entry instruction of the
runtime program at origin 10. The constructor's broader copied-data range does
not hide that runtime code or the metadata: code takes precedence over data,
and metadata takes precedence over both. The uncovered bytes on either side of
the metadata retain their `"data"` label.

