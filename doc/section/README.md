# Sectioning bytecode

The bytecode of a contract may consist of several parts.
The first one usually is executable EVM code, followed by further code sections for contracts created by the first part, as well as by data and meta-data sections.

`section.py` splits bytecode into a list of such sections, tagging each with one of the strings `code`, `data` or `meta`.
This utility is used to preprocess bytecode when computing its skeleton and extracting the function signatures.

## Required files

```
ethutils/metadata.py
ethutils/section.py
```

## Try it out

```bash
cd ethutils/doc/section        # go to the directory with the sample code
source ../../venv/bin/activate # activate the virtual environment
xzcat bytecodes.csv.xz | python wrapper_section.py > bytecodes_section.csv
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


`bytecodes_section.csv` is a semicolon-separated text file with header.
Each line contains the fields
```
codeid;sections
```

E.g., the line
```
535998974;0x4a8eae10b7ee97a2c6a6212776f059a25e90e7f4;0x6080604052...0032
```
in `bytecodes.csv` yields the output
```
535998974;[('code', '6080...56fe'), ('code', '6080...f3fe'), ('code', '6080...7373'), ('meta', 'a265...0032'), ('data', '4475...6564'), ('meta', 'a265...0032')]
```

## Using the code in a Python program

To section bytecode from within a Python script, use
```python
import ethutils.section
sections = ethutils.section.decompose(code) # code is a byte string
```
