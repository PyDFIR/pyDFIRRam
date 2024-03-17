# pyDFIRRam

## Description

todo: écrire

## Objectives

todo: traduire en anglais

1. Faciliter la recherche et le try and retry avec volatility
2. Parser plus facilement les outputs
3. Se concentrer sur la data plutot que sur la commandes
4. Utiliser comme un dataset
5. Pouvoir gerer plusieurs dump dans un meme programme

## Installation

You can install pyDFIRRam with the following commands :

```bash
$ python3 -m venv venv
$ source venv/bin/activate
$ git clone https://github.com/pyDFIR/pyDFIRRam
$ cd pyDFIRRam
$ poetry build
$ poetry install
```

## Usage

todo: écrire

You can use the library in multiple ways with :
- a Jupyter notebook
- a configuration file (CLI-like)
- a script

Kickstart the project by running :

```bash
$ poetry run jupyter notebook
```

# Examples

```python
from pyDFIRRam import windows
import os

# Check the documentation for the following parameters, those are important
winObj1 = windows(InvestFile=os.getcwd() + "memdump.mem", Outputformat="dataframe")

data1   = winObj1.PsList()
data1_1 = winObj1.PsList(pid=[4])
data1_1 = winObj1.PsList(pid=[4, 324, ...])

data1
data1_1
```

All supported features are documented, check it out on [our documentation](todo) !
