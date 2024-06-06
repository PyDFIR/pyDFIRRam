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
PyDFIRRam is build with poetry, so you need to install it.

You can install pyDFIRRam with the following commands :

```bash
$ git clone https://github.com/pyDFIR/pyDFIRRam
$ cd pyDFIRRam
$ poetry shell
$ poetry install
```

## Usage

todo: écrire

You can use the library in multiple ways with :
- a Jupyter notebook
- a script


### Jupyter Notebook

Kickstart the project by running :

```bash
$ poetry run jupyter notebook
```

```Jupyter
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem

DUMP_FILE = Path("THE DIRECTORY")
os = OperatingSystem.WINDOWS
dumpfile = Path(DUMP_FILE)
generic = Generic(os, dumpfile)
output = generic.PsList(pid=4).to_dataframe()
print(output)
```

# Examples

```python
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem

DUMP_FILE = Path("THE DIRECTORY")
os = OperatingSystem.WINDOWS
dumpfile = Path(DUMP_FILE)
generic = Generic(os, dumpfile)
output = generic.PsList(pid=4).to_dict()
print(output)
```

All supported features are documented, check it out on [our documentation](todo) !
