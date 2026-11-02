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

## Entry points

- `extract_metadata` — Find and decode Solidity-style CBOR metadata blocks.
- `zero_metadata` — Replace recognized metadata bytes with zero bytes.
- `skeleton` — Remove recognized metadata and normalize PUSH instructions.
- `section` — Return overlapping code, data, returned-code, and metadata sections.
- `decompose` — Partition input bytes into non-overlapping fragments tagged as code, data, or metadata.
- `runtime` — Infer runtime code from creation bytecode.
- `selectors` — Discover function selectors.
- `properties` — Summarize function and non-selector-route behavior.
- `compatible` — Check bytecodes for semantic compatibility by a structural and behavioral analysis.

See [API.md](API.md) for the complete API reference, including arguments and
return values.

## Testing

Run the self-contained test suite from the repository root:

```console
python -m unittest discover -s tests -t .
```

## History

- Versions up to and including 0.1.3 used regular expressions to perform
  sectioning and selector extraction. This is _much_ faster than the symbolic
  execution approach chosen for 0.2.0 and later versions, but is less robust, as
  the expressions have to be updated when compilers generate new patterns.

- For the version used in our [ICBC 2024 paper](https://doi.org/10.1109/ICBC59979.2024.10634441), checkout the release tagged `icbc2024`.

- For the version used in our [EMSE 2024 paper](https://doi.org/10.1007/s10664-023-10414-8),
  checkout the release tagged `emse2024`.
