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

## Examples

### Identical programs

```python
from ethutils import compatible

compatible(b"\x00", b"\x00")
# True

events = []
compatible(b"\x00", b"\x00", trace=events.append)
events[-1]
# {"kind": "overall_result", "compatible": True}
```

### Compatible properties and an established conflict

These three programs use the dispatcher from the `properties` example. Each
recognizes selector `0x12345678` and rejects unmatched calls. The first two
return different constants; the third writes to storage.

```python
from ethutils import compatible, properties

dispatcher = "5f3560e01c806312345678146012575f5ffd5b"

returns_42 = bytes.fromhex(
    dispatcher +
    "602a5f5260205ff3"  # store 42 in memory and return 32 bytes
)
returns_43 = bytes.fromhex(
    dispatcher +
    "602b5f5260205ff3"  # store 43 in memory and return 32 bytes
)
writes_storage = bytes.fromhex(
    dispatcher +
    "60015f5500"        # store 1 in storage slot 0, then stop
)

selector = bytes.fromhex("12345678")
properties(returns_42)[selector]
# {"delegatecall_only": None,
#  "rejects_nonzero_value": False,
#  "read_only": True,
#  "state_independent": True,
#  "scalar_storage_getter": False,
#  "return_size": 32}

properties(returns_43)[selector]
# The same property summary as returns_42.

compatible(returns_42, returns_43)
# True
```

The analysis observes that both functions return 32 bytes without reading or
changing state. It does not compare the concrete returned value, so the
difference between 42 and 43 does not establish a conflict.

The storage-writing version has a contradictory known property:

```python
properties(writes_storage)[selector]["read_only"]
# False

events = []
compatible(returns_42, writes_storage, trace=events.append)
# False

next(event for event in events
     if event["kind"] == "function_property" and not event["compatible"])
# {"kind": "function_property",
#  "origin1": 0,
#  "origin2": 0,
#  "selector": "12345678",
#  "property": "read_only",
#  "value1": True,
#  "value2": False,
#  "compared": True,
#  "compatible": False}
```

Here `read_only=True` versus `read_only=False` is an established behavioral
contradiction, so the programs are incompatible even though their structures
and selector sets correspond.


