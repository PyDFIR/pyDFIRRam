# pyDFIRRam

[![PyPI version](https://badge.fury.io/py/pydfirram.svg)](https://badge.fury.io/py/pydfirram)
[![Build Status](https://travis-ci.org/pyDFIR/pyDFIRRam.svg?branch=main)](https://travis-ci.org/pyDFIR/pyDFIRRam)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

PyDFIRRam is a Python library designed to simplify and enhance memory forensics tasks. It provides tools to streamline research, parsing, and analysis of memory dumps, allowing users to focus on data rather than commands.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [Jupyter Lab](#jupyter-lab)
  - [Script](#script)
  - [Examples](#examples)
- [Objectives](#objectives)

## Installation
PyDFIRRam is built with Poetry, so you need to install it.

You can install pyDFIRRam with the following commands:

1. Clone the repository:
    ```bash
    git clone https://github.com/pyDFIR/pyDFIRRam
    ```
2. Install it with Poetry:
    ```bash
    poetry install
    ```

## Usage

You can use the library in multiple ways:
- In a Jupyter Lab environment
- In a script

### Jupyter Lab

Kickstart the project by running:

```bash
poetry run jupyter lab
```

In Jupyter Lab, you can use the library as follows:

```python
from pathlib import Path
from pydfirram.modules import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.PsList(pid=[4]).to_df(max_row=True) # max_row=True is an option on to_df to see all the content of the dataframe. All the content will be printed in your Jupyter output cell.
print(output)
```

### Script

You can also use the library in a Python script:

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.pslist()

# To get a list:
print(output.to_list())

# For a DataFrame:
print(output.to_df())

# Or convert it to JSON:
print(win.pslist().to_json())
```

All supported features are documented, check it out on [our documentation](todo) !

## Objectives

1. Facilitate research and the try-and-retry process with Volatility
2. Easily parse outputs
3. Focus on data rather than commands
4. Use as a dataset
5. Manage multiple dumps in the same program

