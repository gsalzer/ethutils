# ethutils

`ethutils` is a Python package for inspecting Ethereum Virtual Machine bytecode.
It disassembles and normalizes bytecode, extracts compiler metadata, identifies
code and data sections, discovers function selectors, performs bounded symbolic
behavior analysis, and compares the structure and observed behavior of programs.

## Installation

Install the latest version directly from GitHub:

```console
python -m pip install "git+https://github.com/gsalzer/ethutils.git"
```

For development, clone the repository and install it in editable mode:

```console
git clone https://github.com/gsalzer/ethutils.git
cd ethutils
python -m pip install -e .
```

Python 3.10 or newer is required.

## EVM and TVM opcodes

TRON TVM opcodes `0xd0` through `0xdf` are recognized by default in addition
to standard EVM opcodes. Disable them before analysis when strict Ethereum EVM
decoding is required:

```python
import ethutils

ethutils.set_tvm_opcodes_enabled(False)
ethutils.tvm_opcodes_enabled()  # False

ethutils.set_tvm_opcodes_enabled(True)  # Restore the default.
```

The setting is process-wide. Configure it before starting concurrent analysis;
changing it while another thread is analyzing bytecode is unsupported.

## Entry points

### Bytecode decoding

- `parse_hex` — Convert hexadecimal text to bytes.
- `disassemble` — Decode bytecode into EVM instruction records.
- `instruction_boundaries` — Locate instruction starts without treating PUSH operands as instructions.

### Metadata and normalization

- `extract_metadata` — Find and decode Solidity-style CBOR metadata blocks.
- `zero_metadata` — Replace recognized metadata bytes with zeroes while preserving offsets.
- `normalize_pushes` — Replace each PUSH instruction and its operand with one PUSH0.
- `skeleton` — Remove recognized metadata and normalize PUSH instructions.

### Selector and behavior analysis

- `selectors` — Discover four-byte function selectors with bounded symbolic exploration.
- `properties` — Summarize function behavior and non-selector call routes.

### Structural sectioning

- `section` — Return overlapping code, data, returned-code, and metadata ranges,
  including plausible programs embedded in canonical ABI `bytes` values.
- `analyze_sections` — Return sections, detected program images, discovery
  evidence, and structural diagnostics.
- `runtime` — Infer the runtime image returned by creation bytecode.
- `decompose` — Partition bytecode into lossless code, data, metadata, and unclassified chunks.

### Program compatibility

- `compatible` — Check for a structural correspondence without an established
  behavioral conflict; trailing constructor arguments can optionally be ignored.
- `code_mappings` — Enumerate compatible correspondences between program origins,
  with the same constructor-argument option.
- `properties_compatible` — Compare behavior summaries for established conflicts.

Compatibility includes trailing constructor arguments and any programs found in
them by default. Pass `ignore_constructor_args=True` explicitly when comparing
actual deployment initcode with compiler-generated argument-free initcode.

See [API.md](API.md) for the complete API reference, including arguments and
return values.

## Testing

Run the self-contained test suite from the repository root:

```console
python -m unittest discover -s tests -t .
```

## History

- Versions up to and including 0.1.3 used regular expressions to perform
  sectioning and selector extraction. This is faster than the symbolic
  execution approach chosen for 0.2.0 and later versions, but is less robust, as
  the expressions have to be updated when compilers generate new patterns.

- For the version used in our [ICBC 2024 paper](https://doi.org/10.1109/ICBC59979.2024.10634441), checkout the release tagged `icbc2024`.

- For the version used in our [EMSE 2024 paper](https://doi.org/10.1007/s10664-023-10414-8),
  checkout the release tagged `emse2024`.
