# API reference

The public API is available directly from `ethutils`. Bytecode arguments are
`bytes`; hexadecimal strings are accepted only by `parse_hex`. Offsets are byte
offsets, and range ends are exclusive.

## Bytecode decoding

### `parse_hex(text: str) -> bytes`

Decode hexadecimal text. An optional `0x` prefix and ASCII whitespace are
accepted. Invalid or odd-length input raises `ValueError`.

### `disassemble(code: bytes, *, start: int = 0, end: int | None = None) -> Iterator[Instruction]`

Yield `Instruction` records for `code[start:end]`. Each record provides `pc`,
`opcode`, `name`, `immediate`, `end`, and `truncated`. Unknown opcodes have
`name=None`; a truncated PUSH retains the bytes that are actually present.

### `instruction_boundaries(code: bytes) -> list[int]`

Return instruction starts for the complete bytecode followed by its exact end
offset. PUSH operand bytes are not reported as instruction boundaries.

## Metadata and normalization

### `extract_metadata(code: bytes) -> list[tuple[int, int, dict]]`

Return recognized CBOR metadata blocks as `(start, length, decoded)` tuples.
Nested valid blocks take precedence over enclosing candidates.

### `zero_metadata(code: bytes) -> bytes`

Return a same-length copy in which recognized metadata blocks are replaced by
zero bytes.

### `normalize_pushes(code: bytes) -> bytes`

Replace every PUSH instruction and its immediate operand with a single `PUSH0`.
All other bytes are retained.

### `skeleton(code: bytes) -> bytes`

Remove recognized metadata and normalize PUSH instructions. The result is a
structural fingerprint, not a proof of semantic equivalence.

## Selector and behavior analysis

### `selectors(code: bytes, *, origin: int = 0, limits: DispatchLimits | None = None, trace: Callable[[dict], None] | None = None) -> SelectorAnalysis`

Discover four-byte function selectors. `origin` treats `code[origin:]` as a
separate program whose first byte has program counter zero. `limits` bounds the
symbolic search. When supplied, `trace` receives one `selector_diagnostics`
record containing entries, path outcomes, value guards, statistics, and limits.

`SelectorAnalysis` contains:

- `selectors: list[bytes]` — sorted selectors;
- `complete: bool` — whether discovery completed within the supported model;
- `issues: list[dict]` — reasons for incomplete exploration.

It implements `collections.abc.Sequence`, so it can be indexed and iterated.

### `properties(code: bytes, *, origin: int = 0, limits: DispatchLimits | None = None, body_limits: BodyLimits | None = None, trace: Callable[[dict], None] | None = None) -> PropertyAnalysis`

Discover selectors and explore each function body with independent body limits.
The optional `trace` callback receives `function_analysis` records followed by a
`property_diagnostics` record with entries, raw routes, guards, statistics, and
limits.

`PropertyAnalysis` contains:

- `properties: dict[bytes, dict]` — summaries keyed by selector;
- `routes: list[dict]` — normalized empty, short, and unmatched-call behavior;
- `complete: bool` — combined dispatcher and body completeness;
- `dispatch_complete: bool` — dispatcher-discovery completeness;
- `issues: list[dict]` — reasons for incomplete exploration.

Each function summary contains `delegatecall_only`, `rejects_nonzero_value`,
`read_only`, `state_independent`, `scalar_storage_getter`, and `return_size`.
Boolean observations are `True`, `False`, or `None` when unresolved.
`PropertyAnalysis` implements `collections.abc.Mapping` over its selector
summaries.

### `DispatchLimits(...)`

Configure dispatcher exploration budgets, including instruction, state, path,
memory, expression, and retained-trace limits. Omitted arguments use conservative
defaults.

### `BodyLimits(...)`

Configure the independently applied function-body exploration budgets.

## Structural sectioning

### `section(code: bytes) -> list[dict]`

Return overlapping structural ranges. Records identify their `kind`, absolute
`start` and `end`, and, for code associated with a program, its `origin`.

### `analyze_sections(code: bytes, *, trace: bool = False) -> SectionAnalysis`

Return structural sections and detected `Program` images. With `trace=True`, the
result also retains structural discovery diagnostics. `SectionAnalysis` contains
`sections`, `programs`, and `diagnostics`.

### `runtime(code: bytes) -> bytes | None`

Section presumed creation bytecode and return the code image returned by the
origin-zero program. Return `None` when sectioning does not establish a unique
candidate.

### `decompose(code: bytes) -> list[tuple[str, bytes]]`

Partition the complete input into ordered, non-overlapping fragments tagged
`"code"`, `"data"`, `"meta"`, or `""` for unclassified bytes. Concatenating the
fragment bytes reproduces the input exactly. Innermost code and metadata take
precedence; a partially decomposed data section leaves its remainder unclassified.

## Program compatibility

### `compatible(code1: bytes, code2: bytes, *, allow_reuse: bool = True, trace: Callable[[dict], None] | None = None) -> bool`

Return whether the sectioned program trees admit a correspondence without an
established behavioral contradiction. `allow_reuse=True` permits one-to-many and
many-to-one code reuse. The optional callback receives structured property,
program-pair, structural, mapping, and final-decision events.

### `code_mappings(code1: bytes, code2: bytes, *, allow_reuse: bool = True, trace: Callable[[dict], None] | None = None) -> Iterator[tuple[tuple[int, int], ...]]`

Lazily yield compatible correspondences between program origins. Each result is
a sorted tuple of `(origin1, origin2)` pairs. Trace events are emitted while the
iterator is consumed.

### `properties_compatible(first: PropertyAnalysis, second: PropertyAnalysis, *, trace: Callable[[dict], None] | None = None, origin1: int | None = None, origin2: int | None = None) -> bool`

Return `False` for established conflicts between selector sets, known function
features, or normalized non-selector routes. Unknown observations do not create
a conflict. Origins are optional labels included in trace events.

## Result serialization

`SelectorAnalysis`, `PropertyAnalysis`, and `SectionAnalysis` provide
`to_dict()`. The returned structures are JSON-ready: byte values and byte-valued
dictionary keys are converted to hexadecimal strings without an `0x` prefix.
