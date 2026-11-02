# `properties_compatible`: Compare behavior summaries

## Interface

```python
properties_compatible(first: PropertyAnalysis, second: PropertyAnalysis, *,
                      trace: Callable[[dict], None] | None = None,
                      origin1: int | None = None,
                      origin2: int | None = None) -> bool
```

## Arguments and return value

`first` and `second` are results from `properties`. Optional origins are labels
included in trace events; they do not affect the decision. `trace` receives a
record for each selector-set, function-property, and non-selector-route check.

The function returns false for an established conflict: different selector
sets, unequal known function features, or incompatible known route behavior.
An unknown (`None` or `"unknown"`) observation does not create a conflict.


## Examples

### Equal analyses

```python
from ethutils import properties, properties_compatible

first = properties(b"\x00")
second = properties(b"\x00")

properties_compatible(first, second)
# True

events = []
properties_compatible(first, second, trace=events.append,
                      origin1=0, origin2=12)
events[0]
# {"kind": "selector_sets", "origin1": 0, "origin2": 12,
#  "selectors1": [], "selectors2": [], "compatible": True}
```

### Equal functions but conflicting call routes

The next two programs recognize the same selector, `0x12345678`, and run the
same selected function, which returns the 32-byte integer `42`. They differ only
in their fallback path: one reverts an unmatched call, while the other reaches
`STOP` successfully.

```python
from ethutils import properties, properties_compatible

dispatcher = "5f3560e01c80631234567814601257"
function = "5b602a5f5260205ff3"

rejects_unmatched = bytes.fromhex(
    dispatcher +
    "5f5ffd" +  # PUSH0, PUSH0, REVERT
    function
)

accepts_unmatched = bytes.fromhex(
    dispatcher +
    "505f00" +  # POP, PUSH0, STOP
    function
)

first = properties(rejects_unmatched)
second = properties(accepts_unmatched)
selector = bytes.fromhex("12345678")

first[selector] == second[selector]
# True

first.routes[0]
# {"category": "empty",
#  "behavior": "rejects",
#  "value_policy": "always_rejects"}

second.routes[0]
# {"category": "empty",
#  "behavior": "reaches_code",
#  "value_policy": "no_value_guard_observed"}
```

Matching selectors and function summaries are not sufficient: normalized
empty, short, and unmatched-call routes are part of the comparison.

```python
events = []
properties_compatible(first, second, trace=events.append,
                      origin1=0, origin2=100)
# False

next(event for event in events if not event["compatible"])
# {"kind": "route_behavior",
#  "origin1": 0,
#  "origin2": 100,
#  "category": "empty",
#  "property": "behavior",
#  "value1": "rejects",
#  "value2": "reaches_code",
#  "compared": True,
#  "compatible": False}
```

The origin values appear only as trace labels. The first established conflict
ends the comparison, so later route categories do not produce trace events.

