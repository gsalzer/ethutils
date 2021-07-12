# Skeletizing bytecode

The skeleton is obtained from the bytecode by removing parts that do not affect functionality:
Solidity meta-data, constructor arguments and PUSH arguments are replaced by zeros, then trailing zeros are stripped.
(The rationale of replacing bytes by zeros instead of removing them is to ensure that tools like disassemblers still work on the skeleton.)
Two bytecodes are functionally equivalent if their skeletons are identical.

`skeleton.py` computes the skeleton of a given bytecode.

## Required files

```
ethutils/opcodes.py
ethutils/section.py
ethutils/skeleton.py
```

## Try it out

```bash
cd ethutils/doc/skeleton       # go to the directory with the sample code
source ../../venv/bin/activate # activate the virtual environment
xzcat bytecodes.csv.xz | python wrapper_skeleton.py > bytecodes_skeleton.csv
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


`bytecodes_skeleton.csv` is a semicolon-separated text file with header.
Each line contains the fields
```
codeid;skeleton
```

E.g., the line
```
535998974;0x4a8eae10b7ee97a2c6a6212776f059a25e90e7f4;0x6080604052...0032
```
in `bytecodes.csv` yields the output
```
535998974;6000600052...0072
```

## Using the code in a Python program

To skeletize bytecode from within a Python script, use
```python
import ethutils.skeleton
skel = ethutils.skeleton.skeletize(code) # code is a byte string
```
