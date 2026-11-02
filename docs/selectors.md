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

The following bytecode implements a small dispatcher. It loads the first call
data word, shifts the leading four bytes into place, compares them with
`0x12345678`, and jumps to the function entry when they match. All other calls
revert.

```python
from ethutils import disassemble, selectors

code = bytes.fromhex(
    "5f"          # PUSH0: calldata offset 0
    "35"          # CALLDATALOAD
    "60e0"        # PUSH1 224
    "1c"          # SHR: retain the first four calldata bytes
    "80"          # DUP1
    "6312345678"  # PUSH4 0x12345678
    "14"          # EQ
    "6012"        # PUSH1 18: function entry
    "57"          # JUMPI
    "5f5ffd"      # PUSH0, PUSH0, REVERT
    "5b00"        # JUMPDEST, STOP
)

[(i.pc, i.name, i.immediate.hex()) for i in disassemble(code)]
# [(0, "PUSH0", ""),
#  (1, "CALLDATALOAD", ""),
#  (2, "PUSH1", "e0"),
#  (4, "SHR", ""),
#  (5, "DUP1", ""),
#  (6, "PUSH4", "12345678"),
#  (11, "EQ", ""),
#  (12, "PUSH1", "12"),
#  (14, "JUMPI", ""),
#  (15, "PUSH0", ""),
#  (16, "PUSH0", ""),
#  (17, "REVERT", ""),
#  (18, "JUMPDEST", ""),
#  (19, "STOP", "")]

report = selectors(code)
list(report)
# [b'\x124Vx']
report.complete
# True
report.to_dict()
# {"selectors": ["12345678"],
#  "complete": True,
#  "issues": [],
#  "scope": "selector_discovery; calldata_length>=4; stop_at_selected_entry"}
```

