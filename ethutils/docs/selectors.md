# `selectors`: Discover function selectors

## Interface

```python
selectors(code: bytes, *, origin: int = 0,
          limits: DispatchLimits | None = None,
          trace: Callable[[dict], None] | None = None) -> SelectorAnalysis
```

## Arguments and return value

`code` is runtime bytecode. `origin` makes `code[origin:]` a program whose
program counter starts at zero. `limits` controls bounded symbolic exploration.
`trace`, when callable, receives one detailed `selector_diagnostics` event.

The returned sequence contains sorted four-byte selectors. Its `complete` flag
says whether discovery finished within the supported model and budgets;
`issues` explains incompleteness. Discoveries made before a limit is reached are
retained, so an empty or partial list is conclusive only when `complete` is true.

## Example

```python
from ethutils import selectors

report = selectors(b"\x00")  # STOP, with no dispatcher
list(report)
# []
report.complete
# True
report.to_dict()
# {"selectors": [], "complete": True, "issues": [], "scope": "..."}
```
