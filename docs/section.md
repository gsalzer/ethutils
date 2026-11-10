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

Copied data ranges are also examined for canonical top-level ABI dynamic
`bytes` values. Their payloads are weak program candidates: ABI structure
supplies an entry and image extent, but normal control-flow or nested
`CODECOPY`/`RETURN` evidence is still required before the payload is classified
as code. Accepted embedded programs overlap the enclosing data record.

## Examples

### A simple one

```python
from ethutils import section

section(bytes.fromhex("00aabb"))
# [{"kind": "code", "start": 0, "end": 1, "origin": 0}]
```

The trailing bytes have no established role and therefore have no record.

### A more complex one

The following creation bytecode copies a 16-byte runtime image from its own code
into memory and returns it. The runtime image contains one `STOP` instruction,
two arbitrary data bytes, a Solidity metadata record, and one trailing data
byte.

```python
import cbor2
from ethutils import section

payload = cbor2.dumps({"solc": b"\x00\x08\x1e"})
metadata = payload + len(payload).to_bytes(2, "big")
runtime = b"\x00\xaa\xbb" + metadata + b"\xcc"

# PUSH1 16, PUSH1 10, PUSH0, CODECOPY,
# PUSH1 16, PUSH0, RETURN
constructor = bytes.fromhex("6010600a5f3960105ff3")
creation = constructor + runtime

section(creation)
# [{"kind": "code", "start": 0, "end": 10, "origin": 0},
#  {"kind": "code", "start": 10, "end": 11, "origin": 10},
#  {"kind": "data", "start": 10, "end": 26, "origin": 0},
#  {"kind": "returned", "start": 10, "end": 26, "origin": 0,
#   "via": 9, "copy": 5},
#  {"kind": "meta", "start": 13, "end": 25,
#   "cbor": {"solc": b"\x00\x08\x1e"}}]
```

The records deliberately overlap:

- Bytes `[10, 26)` are data copied by the origin-zero constructor.
- The same range is returned by the constructor; `copy=5` and `via=9` identify
  the `CODECOPY` and `RETURN` instruction offsets that establish this.
- The returned image is also a program with origin 10. Its first byte,
  `[10, 11)`, is recognized as code.
- The metadata record occupies `[13, 25)` inside that returned image.

This overlap preserves the different structural roles of the same bytes.
`decompose` can be used when a single non-overlapping label per byte is needed.

