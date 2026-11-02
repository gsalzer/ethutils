# `compatible`: Check program compatibility

## Interface

```python
compatible(code1: bytes, code2: bytes, *, allow_reuse: bool = True,
           trace: Callable[[dict], None] | None = None) -> bool
```

## Arguments and return value

`code1` and `code2` are complete byte sequences. With `allow_reuse=True`, one
program origin may correspond to several origins on the other side; `False`
requires a global one-to-one correspondence. `trace` receives property,
program-pair, structural, and final-decision events.

The result is true when the sectioned program structures admit a correspondence
and no compared behavior establishes a contradiction. Unknown observations are
compatible, so this is a conservative compatibility check rather than proof of
semantic equivalence.

## Example

```python
from ethutils import compatible

compatible(b"\x00", b"\x00")
# True

events = []
compatible(b"\x00", b"\x00", trace=events.append)
events[-1]
# {"kind": "overall_result", "compatible": True}
```
