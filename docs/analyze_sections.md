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

## Example

```python
from ethutils import analyze_sections

report = analyze_sections(b"\x00")
report.sections
# [{"kind": "code", "start": 0, "end": 1, "origin": 0}]
[(p.origin, p.image.hex(), p.evidence) for p in report.programs]
# [(0, "00", "entry")]
```
