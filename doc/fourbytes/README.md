# Extracting the function signatures from bytecode

Contracts adhering to the ABI standard identify each entry point by a function signature, which consists of four bytes obtained by hashing the function name and the parameter types.

`fourbytes.py` extracts all function signatures from a given bytecode.

## Required files

```
ethutils/opcodes.py
ethutils/section.py
ethutils/fourbytes.py
```

## Try it out

```bash
cd ethutils/doc/fourbytes      # go to the directory with the sample code
source ../../venv/bin/activate # activate the virtual environment
xzcat bytecodes.csv.xz | python wrapper_fourbytes.py > bytecodes_fsigs.csv
deactivate                     # deactivate the virtual environment
```

The file `bytecodes.csv` contains 100 contract codes from Ethereum's main chain as a semicolon-separated text file with header.
Each line contains the fields
```
codeid;account;code
```

`codeid` is a unique identifier for the bytecode.
`account` is one of the addresses on the chain where the code has been deployed.
`code` is the bytecode of the contract.


`bytecodes_fsigs.csv` is a semicolon-separated text file with header.
Each line contains the fields
```
codeid;signatures
```

E.g., the line
```
535998974;0x4a8eae10b7ee97a2c6a6212776f059a25e90e7f4;0x6080604052...0032
```
in `bytecodes.csv` yields the output
```
535998974;['6ba7c33b', 'c4552791']
```

## Using the code in a Python program

To extract signatures from within a Python script, use
```python
import ethutils.fourbytes
fsigs = ethutils.fourbytes.signatures(code) # code is a byte string
```
