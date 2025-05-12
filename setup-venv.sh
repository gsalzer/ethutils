#!/bin/bash
# tested for python 3.12
python3 -m venv venv
source venv/bin/activate

# avoid spurious errors/warnings; the next two lines could be omitted
pip install --upgrade pip
pip install wheel

# install poetry
pip install poetry
poetry install
