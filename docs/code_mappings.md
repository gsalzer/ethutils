# `code_mappings`: Enumerate program correspondences

## Interface

```python
code_mappings(code1: bytes, code2: bytes, *, allow_reuse: bool = True,
              ignore_constructor_args: bool = False,
              trace: Callable[[dict], None] | None = None
              ) -> Iterator[tuple[tuple[int, int], ...]]
```

## Arguments and return value

The bytecode, `allow_reuse`, and `ignore_constructor_args` arguments have
the same meaning as for `compatible`. The returned iterator lazily yields
distinct compatible mappings.
Each mapping is a sorted tuple of `(origin1, origin2)` pairs. Trace events,
including a `mapping` event for every result, are emitted only while the
iterator is consumed.

The default `ignore_constructor_args=False` retains the trailing constructor
data and programs contained in it. An explicit `True` omits the entire argument
tail, every program originating there, and their descendants.

Every detected program must be covered. Empty inputs have one empty mapping.
With reuse disabled, every physical origin must participate in a bijection.

## Examples

### Single programs and empty inputs

```python
from ethutils import code_mappings

list(code_mappings(b"\x00", b"\x00"))
# [((0, 0),)]

list(code_mappings(b"", b""))
# [()]
```

### Duplicated and shared child programs

Both byte sequences below are constructors with two possible return paths,
selected by `CALLVALUE`. Every path returns a one-byte `STOP` runtime. The first
constructor stores two physical copies of that runtime at origins 28 and 29;
the second makes both paths copy the same runtime at origin 28.

```python
from ethutils import analyze_sections, code_mappings

duplicated = bytes.fromhex(
    "3461001057"        # CALLVALUE selects one of two return paths
    "600161001c5f39"    # copy one byte from origin 28
    "60015ff3"          # return it
    "5b"
    "600161001d5f39"    # copy one byte from origin 29
    "60015ff3"          # return it
    "00"                # runtime at origin 28
    "00"                # runtime at origin 29
)


shared = bytes.fromhex(
    "3461001057"
    "600161001c5f39"    # first path copies origin 28
    "60015ff3"
    "5b"
    "600161001c5f39"    # second path also copies origin 28
    "60015ff3"
    "00"
)

[program.origin for program in analyze_sections(duplicated).programs]
# [0, 28, 29]

[program.origin for program in analyze_sections(shared).programs]
# [0, 28]

list(code_mappings(duplicated, shared))
# [((0, 0), (28, 28), (29, 28))]
```

The root programs correspond as `(0, 0)`. With reuse enabled, both physical
runtime copies on the left may correspond to the one shared runtime on the
right. The result therefore contains a many-to-one mapping.

Disabling reuse requires a bijection of physical origins, which these program
trees cannot provide:

```python
list(code_mappings(duplicated, shared, allow_reuse=False))
# []
```

Mapping trace events are emitted lazily while consuming the iterator:


```python
events = []
mappings = code_mappings(duplicated, shared, trace=events.append)
events
# []

list(mappings)
# [((0, 0), (28, 28), (29, 28))]

[event for event in events if event["kind"] == "mapping"]
# [{"kind": "mapping",
#   "mapping": [(0, 0), (28, 28), (29, 28)],
#   "compatible": True}]
```

