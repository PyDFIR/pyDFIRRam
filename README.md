# pyDFIRRam

## Description

todo: écrire

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)

## Installation
PyDFIRRam is build with poetry, so you need to install it.

You can install pyDFIRRam with the following commands :

1. Clone the repository : 
```bash
git clone https://github.com/pyDFIR/pyDFIRRam
```
2. Install it with poetry :
```bash
poetry install
```

## Usage

todo: écrire

You can use the library in multiple ways with :
- a Jupyter notebook
- a script

## Objectives

todo: traduire en anglais

1. Faciliter la recherche et le try and retry avec volatility
2. Parser plus facilement les outputs
3. Se concentrer sur la data plutot que sur la commandes
4. Utiliser comme un dataset
5. Pouvoir gerer plusieurs dump dans un meme programme




### Jupyter Notebook

Kickstart the project by running :

```bash
$ poetry run jupyter notebook
```

```Jupyter
from pathlib import Path
from pydfirram.modules import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.PsList().to_dataframe()
print(output)
```

# Examples

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.pslist()

# to get et list :
print(output.to_list())
# for a dataframe:
print(output.to_dataframe())

# Or it's possible to write it like this
print(win.pslist().to_json())
```

All supported features are documented, check it out on [our documentation](todo) !
