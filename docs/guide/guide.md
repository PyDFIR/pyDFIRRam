## How-to Guide for pyDFIRRam

### Introduction

Welcome to the How-to Guide for pyDFIRRam, a Python wrapper for the Volatility framework. This guide will help you get started with the package, configure it, and perform common tasks.

### Table of Contents

1. [Getting Started](#getting-started)


### Getting Started
#### Prerequisite
- Python3.10
#### Installation

To install pyDFIRRam, use pip:
```bash
pip install pydfirram
```

#### Basic Usage
```python
from pydfirram.modules.windows import Windws
wrap = Windows("dmp.raw")

data = wrap.<plugins>().<rendering>()
```
