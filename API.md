# API reference

The public API is available directly from `ethutils`:

```python
from ethutils import parse_hex, disassemble, selectors
```

This page is a compact index. Each function links to a dedicated page with its
arguments, return value, behavior, limitations, and examples.

## Conventions

- Bytecode arguments are `bytes`. Use `parse_hex` to convert hexadecimal text.
- Offsets are byte offsets. Range ends are exclusive.
- Analysis is bounded and conservative. Check `complete`,
  `dispatch_complete`, and `issues` before treating an absence as conclusive.
- Unknown behavioral observations do not establish incompatibility.
- A `trace` callback receives structured diagnostic dictionaries. Tracing does
  not change the result or increase analysis budgets.
- Result objects with `to_dict()` return JSON-ready data: bytes and byte-valued
  dictionary keys become hexadecimal strings without an `0x` prefix.
- TRON TVM opcodes `0xd0` through `0xdf` are enabled by default. Configure the
  process-wide setting before starting concurrent analysis using the functions
  below.

## Opcode dialect

### `set_tvm_opcodes_enabled`

```python
set_tvm_opcodes_enabled(enabled: bool) -> None
```

Enable or disable recognition of the TRON TVM opcode extensions in all shared
opcode lookup tables. Pass `False` for strict Ethereum EVM decoding. Opcode
byte constants remain available when recognition is disabled. Changing the
setting concurrently with analysis in another thread is unsupported.

### `tvm_opcodes_enabled`

```python
tvm_opcodes_enabled() -> bool
```

Return whether TRON TVM opcode recognition is currently enabled. The default is
`True`.

## Bytecode decoding

### [`parse_hex`](docs/parse_hex.md)

```python
parse_hex(text: str) -> bytes
```

Convert hexadecimal text to bytes.

### [`disassemble`](docs/disassemble.md)

```python
disassemble(code: bytes, *, start: int = 0,
            end: int | None = None) -> Iterator[Instruction]
```

Decode a byte range into EVM instruction records.

### [`instruction_boundaries`](docs/instruction_boundaries.md)

```python
instruction_boundaries(code: bytes) -> list[int]
```

Return instruction starts while excluding PUSH operand positions.

## Metadata and normalization

### [`extract_metadata`](docs/extract_metadata.md)

```python
extract_metadata(code: bytes) -> list[tuple[int, int, dict]]
```

Find and decode recognized Solidity-style CBOR metadata.

### [`zero_metadata`](docs/zero_metadata.md)

```python
zero_metadata(code: bytes) -> bytes
```

Replace recognized metadata with zeroes without changing offsets.

### [`normalize_pushes`](docs/normalize_pushes.md)

```python
normalize_pushes(code: bytes) -> bytes
```

Replace every PUSH instruction and its operand with one `PUSH0`.

### [`skeleton`](docs/skeleton.md)

```python
skeleton(code: bytes) -> bytes
```

Remove recognized metadata and normalize PUSH instructions.

## Selector and behavior analysis

### [`selectors`](docs/selectors.md)

```python
selectors(code: bytes, *, origin: int = 0,
          limits: DispatchLimits | None = None,
          trace: Callable[[dict], None] | None = None) -> SelectorAnalysis
```

Discover four-byte function selectors with bounded symbolic exploration.

### [`properties`](docs/properties.md)

```python
properties(code: bytes, *, origin: int = 0,
           limits: DispatchLimits | None = None,
           body_limits: BodyLimits | None = None,
           trace: Callable[[dict], None] | None = None) -> PropertyAnalysis
```

Summarize discovered functions and non-selector call routes.

## Structural sectioning

### [`section`](docs/section.md)

```python
section(code: bytes) -> list[dict]
```

Return overlapping code, data, returned-code, and metadata ranges. Copied data
is also examined for canonical top-level ABI `bytes` values; payloads become
code only when ordinary control-flow or nested-program evidence supports them.

### [`analyze_sections`](docs/analyze_sections.md)

```python
analyze_sections(code: bytes, *, trace: bool = False) -> SectionAnalysis
```

Return sections, detected program images, and structural diagnostics. Programs
discovered inside ABI byte strings use `abi_bytes` evidence; their diagnostics
identify the enclosing container, offset and length words, payload end, and
the CODECOPY that supplied the container.

### [`runtime`](docs/runtime.md)

```python
runtime(code: bytes) -> bytes | None
```

Infer the unique runtime image returned by creation bytecode.

### [`decompose`](docs/decompose.md)

```python
decompose(code: bytes) -> list[tuple[str, bytes]]
```

Partition input bytes into lossless code, data, metadata, and unclassified chunks.

## Program compatibility

### [`compatible`](docs/compatible.md)

```python
compatible(code1: bytes, code2: bytes, *, allow_reuse: bool = True,
           ignore_constructor_args: bool = False,
           trace: Callable[[dict], None] | None = None) -> bool
```

Check whether program structures correspond without an established behavioral
contradiction. The default `ignore_constructor_args=False` includes trailing
constructor data and programs found in it; ignoring the entire argument tail is
explicit opt-in behavior.

### [`code_mappings`](docs/code_mappings.md)

```python
code_mappings(code1: bytes, code2: bytes, *, allow_reuse: bool = True,
              ignore_constructor_args: bool = False,
              trace: Callable[[dict], None] | None = None
              ) -> Iterator[tuple[tuple[int, int], ...]]
```

Lazily enumerate compatible correspondences between program origins. For both
functions, `ignore_constructor_args=True` excludes the initial constructor's
entire trailing argument area, including all programs in it and their
descendants. Its default is `False` for both functions.

### [`properties_compatible`](docs/properties_compatible.md)

```python
properties_compatible(first: PropertyAnalysis, second: PropertyAnalysis, *,
                      trace: Callable[[dict], None] | None = None,
                      origin1: int | None = None,
                      origin2: int | None = None) -> bool
```

Compare two property analyses for established behavioral conflicts.

## Shared types

### `Instruction`

An immutable instruction record with `pc`, numeric `opcode`, `name`,
`immediate`, exclusive `end`, and `truncated` fields.

### `DispatchLimits`

Budgets for dispatcher exploration, including total instructions, admitted
states, per-path work, table enumeration, memory, expression size, and retained
trace length. Omitted fields use conservative defaults.

### `BodyLimits`

Instruction, state, per-path, memory, and expression limits applied
independently to each function entry.

### `SelectorAnalysis`

A sequence of sorted selector bytes with `complete`, `issues`, and `scope`
fields. It provides `to_dict()`.

### `PropertyAnalysis`

A mapping from selector bytes to function summaries. It also contains normalized
`routes`, `complete`, `dispatch_complete`, `issues`, and `scope`, and provides
`to_dict()`.

### `Fragment` and `Program`

`Fragment` maps an input range into a program image. `Program` records a detected
program's origin, image, fragments, discovery evidence, parent, entry
classification, and recognized code ranges. Discovery evidence is `entry`,
`returned_copy`, `created_copy`, `abi_bytes`, or `fragment`.

### `SectionAnalysis`

Contains `sections`, detected `programs`, structural `diagnostics`, and `scope`.
It provides `to_dict()`.
