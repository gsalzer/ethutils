# `properties`: Summarize function behavior

## Interface

```python
properties(code: bytes, *, origin: int = 0,
           limits: DispatchLimits | None = None,
           body_limits: BodyLimits | None = None,
           trace: Callable[[dict], None] | None = None) -> PropertyAnalysis
```

## Arguments and return value

`code` and `origin` identify a runtime program. `limits` bounds dispatcher
analysis; `body_limits` is applied independently to every discovered entry.
`trace` receives per-function evidence and final property diagnostics.

The result behaves as a mapping from four-byte selectors to summaries. Each
summary reports `delegatecall_only`, `rejects_nonzero_value`, `read_only`,
`state_independent`, `scalar_storage_getter`, and `return_size`. A Boolean
property is `None` when evidence is insufficient. `routes` describes empty,
short, and unmatched calls. `dispatch_complete` and `complete` distinguish
selector-discovery completion from completion of the entire analysis.

## Example

```python
from ethutils import properties

report = properties(b"\x00")
dict(report)
# {}
report.routes
# [{"category": "empty", "behavior": "reaches_code", ...}, ...]
report.complete, report.dispatch_complete
# (True, True)
```
