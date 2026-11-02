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

This dispatcher recognizes selector `0x12345678`. Its function body stores the
integer `42` in memory and returns it as one 32-byte EVM word. Calls with any
other selector, including calls shorter than four bytes, revert.

```python
from ethutils import properties

code = bytes.fromhex(
    "5f"          # PUSH0: calldata offset 0
    "35"          # CALLDATALOAD
    "60e01c"      # PUSH1 224, SHR: extract the selector
    "80"          # DUP1
    "6312345678"  # PUSH4 0x12345678
    "14"          # EQ
    "601257"      # PUSH1 18, JUMPI to the function
    "5f5ffd"      # unmatched call: PUSH0, PUSH0, REVERT
    "5b"          # function entry: JUMPDEST
    "602a5f52"    # store 42 at memory offset 0
    "60205ff3"    # return 32 bytes from memory offset 0
)

report = properties(code)

list(report)
# [b'\x124Vx']

report[bytes.fromhex("12345678")]
# {"delegatecall_only": None,
#  "rejects_nonzero_value": False,
#  "read_only": True,
#  "state_independent": True,
#  "scalar_storage_getter": False,
#  "return_size": 32}

report.routes
# [{"category": "empty", "behavior": "rejects",
#   "value_policy": "always_rejects"},
#  {"category": "short_1", "behavior": "rejects",
#   "value_policy": "always_rejects"},
#  {"category": "short_2", "behavior": "rejects",
#   "value_policy": "always_rejects"},
#  {"category": "short_3", "behavior": "rejects",
#   "value_policy": "always_rejects"},
#  {"category": "unmatched", "behavior": "rejects",
#   "value_policy": "always_rejects"}]

report.complete, report.dispatch_complete
# (True, True)
```

`rejects_nonzero_value` is `False` because the selected function does not check
`CALLVALUE` and succeeds for a witnessed nonzero value. It is nevertheless
`read_only` and `state_independent`: it neither reads external state nor causes
a persistent effect. `delegatecall_only` remains unknown because the bytecode
does not contain a recognizable library protection pattern.

