# ethutils: Utilities for the Analysis of Ethereum Smart Contracts

## Installation on GNU/Linux and Unix

Before continuing, ensure that `python3` is installed.
```bash
git clone https://github.com/gsalzer/ethutils.git # clone git repository
cd ethutils
python3 -m venv venv                              # set up a virtual environment for Python
source venv/bin/activate                          # ... and activate it
pip install wheel
pip install -r requirements.txt                   # install dependencies
```

## Contents of the repository

* [Python scripts for manipulating bytecodes](ethutils)
* [Bash script for the rule-based classification of Solidity function headers](headers)
* [Documentation and code samples](doc)

