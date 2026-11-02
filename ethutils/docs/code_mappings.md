# `code_mappings`: Enumerate program correspondences

## Interface

```python
code_mappings(code1: bytes, code2: bytes, *, allow_reuse: bool = True,
              trace: Callable[[dict], None] | None = None
              ) -> Iterator[tuple[tuple[int, int], ...]]
```

## Arguments and return value

The bytecode and `allow_reuse` arguments have the same meaning as for
`compatible`. The returned iterator lazily yields distinct compatible mappings.
Each mapping is a sorted tuple of `(origin1, origin2)` pairs. Trace events,
including a `mapping` event for every result, are emitted only while the
iterator is consumed.

Every detected program must be covered. Empty inputs have one empty mapping.
With reuse disabled, every physical origin must participate in a bijection.

## Examples

```python
from ethutils import code_mappings

list(code_mappings(b"\x00", b"\x00"))
# [((0, 0),)]

list(code_mappings(b"", b""))
# [()]
```
