# ethutils: Utilities for the Analysis of Ethereum Smart Contracts

## Installation on GNU/Linux and Unix

Make sure that you have `python3` on your system.
```bash
git clone https://github.com/gsalzer/ethutils.git # clone git repository
cd ethutils
python3 -m venv venv                              # set up a virtual environment for Python
source venv/bin/activate                          # ... and activate it
pip install wheel
pip install -r requirements.txt                   # install dependencies
```

## Initialization

Before running the examples below:
```bash
cd ethutils              # change to the top directory of the distribution
source venv/bin/activate # activate the virtual environment
```
Immediately after installation, you can skip the lines above, as you are already in the right directory and have activated the virtual environment.

When you are done:
```
deactivate               # deactivate the virtual environment
```

## Test data

The file `test/bytecodes.csv` contains 100 contract codes from Ethereum's main chain as a semicolon-separated text file with header.
Each line contains the fields
```
codeid;account;code
```

`codeid` is a unique identifier for the bytecode.
`account` is one of the addresses on the chain where the code has been deployed.
`code` is the bytecode of the contract.

## section.py: sectioning bytecodes

The bytecode of a contract may consist of several parts.
The first one is usually executable EVM code, followed by further code sections for contracts created by the first part as well as by data and meta-data sections.
`section.py` splits bytecode into a list of such sections, tagging each with one of the strings `code`, `data` or `meta`.

```bash
cd test
cat bytecodes.csv | python section.py > bytecodes_section.csv
```

`bytecodes_section.csv` is a semicolon-separated text file with header.
Each line contains the fields
```
codeid;sections
```

E.g., the line
```
535998974;0x4a8eae10b7ee97a2c6a6212776f059a25e90e7f4;0x6080604052...0032
```
in `test/bytecodes.csv` results in the output
```
535998974;[('code', '6080...56fe'), ('code', '6080...f3fe'), ('code', '6080...7373'), ('meta', 'a265...0032'), ('data', '4475...6564'), ('meta', 'a265...0032')]
```

To section bytecode from within a Python script, use
```python
import ethutils.section
code = b'\x60\x80\x00'
sections = ethutils.section.decompose(code)
```

## skeleton.py: skeletizing bytecodes

The skeleton of a bytecode is obtained by replacing `PUSH` arguments as well as data and meta-data by zeros and then stripping trailing zeros.
The computation of 

```
cd test
cat bytecodes.csv | python skeleton.py > bytecodes_skeleton.csv
```

`bytecodes_skeleton.csv` is a semicolon-separated text file with header.
Each line contains the fields
```
codeid;skeleton
```

E.g., the line
```
535998974;0x4a8eae10b7ee97a2c6a6212776f059a25e90e7f4;0x6080604052...0032
```
in `test/bytecodes.csv` results in the output
```
535998974;6000600052...0072
```

To section bytecode from within a Python script, use
```python
import ethutils.skeleton
code = b'\x60\x80\x00'
skel = ethutils.skeleton.skeletize(code)
```

