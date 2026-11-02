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

## Example

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
