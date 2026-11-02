# `analyze_sections`: Explain structural discovery

## Interface

```python
analyze_sections(code: bytes, *, trace: bool = False) -> SectionAnalysis
```

## Arguments and return value

`code` is the complete byte sequence. `trace=True` retains additional
diagnostics about structural decisions. The result contains the same `sections`
as `section`, detected `programs`, `diagnostics`, and a `scope` description.

Each `Program` records its absolute origin, full image, source fragments,
discovery evidence, parent origin, entry classification, and recognized code
ranges. `to_dict()` converts bytes to hexadecimal strings for JSON output.

## Examples

### A simple one

```python
from ethutils import analyze_sections

report = analyze_sections(b"\x00")
report.sections
# [{"kind": "code", "start": 0, "end": 1, "origin": 0}]
[(p.origin, p.image.hex(), p.evidence) for p in report.programs]
# [(0, "00", "entry")]
```

### A more complex one

This is the same creation-bytecode example as used for `section`. The constructor
copies and returns a runtime image containing code, ordinary data, compiler
metadata, and trailing data.

```python
import cbor2
from ethutils import analyze_sections, section

payload = cbor2.dumps({"solc": b"\x00\x08\x1e"})
metadata = payload + len(payload).to_bytes(2, "big")
runtime = b"\x00\xaa\xbb" + metadata + b"\xcc"
constructor = bytes.fromhex("6010600a5f3960105ff3")
creation = constructor + runtime

report = analyze_sections(creation)

report.sections == section(creation)
# True

[(p.origin, p.image.hex(), p.evidence, p.parent) for p in report.programs]
# [(0, "6010600a5f3960105ff300aabba164736f6c634300081e000acc",
#   "entry", None),
#  (10, "00aabba164736f6c634300081e000acc",
#   "returned_copy", 0)]

runtime_program = report.programs[1]
runtime_program.fragments
# (Fragment(start=10, end=26, offset=0),)
runtime_program.entry_accepted
# True
runtime_program.code_ranges
# ((10, 11),)
```

The origin-zero `Program` represents the whole constructor input. The second
program begins at input offset 10 and contains only the returned runtime image.
Its `returned_copy` evidence and `parent=0` connect it to the constructor.

For JSON serialization, dataclasses and bytes are converted recursively:

```python
report.to_dict()["programs"][1]
# {"origin": 10,
#  "image": "00aabba164736f6c634300081e000acc",
#  "fragments": [{"start": 10, "end": 26, "offset": 0}],
#  "evidence": "returned_copy",
#  "parent": 0,
#  "entry_accepted": True,
#  "code_ranges": [[10, 11]]}
```

