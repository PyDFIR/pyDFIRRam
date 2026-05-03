# How-to Guide for pyDFIRRam

## Introduction

Welcome to the How-to Guide for pyDFIRRam, a Python wrapper for the Volatility framework. This guide will help you get started with the package, configure it, and perform common tasks.

## Table of Contents

1. [Getting Started](#getting-started)


## Getting Started
### Prerequisite
- Python3.10
### Installation

To install pyDFIRRam, use pip:
```bash
pip install pydfirram
```

### Basic Usage

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

wrap = Windows(Path("dmp.raw"))

# Explicit plugin execution (recommended); returns a Renderer
renderer = wrap.run_plugin("windows.pslist")
data = renderer.to_df()

# Optional: inspect the catalogue (cached per Volatility version / OS)
names = wrap.list_plugins()
```

Legacy `wrap.pslist()`-style attribute access is deprecated (see tutorial *Plugins (SDK API)*).
