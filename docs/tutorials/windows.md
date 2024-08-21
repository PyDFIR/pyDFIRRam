# How to Use pyDFIRRam for Windows

This guide provides a brief and concise demonstration of how to use the pyDFIRRam tool for Windows.

## Introduction

Currently, the project is under development. To use the Volatility-related functions for Windows, follow these steps:

### Initial Setup

First, create an object for your memory dump:

```python
from pydfirram.modules.windows import Windows
from pathlib import Path

dump = Path("/home/dev/image.dump")
win = Windows(dump)
```

### Listing Available Functions

The available functions are all the Volatility plugins (located in the Volatility plugin path).

To list all available functions:

```python
win.get_all_plugins()
```

You can use this function to retrieve all the plugins.

### Using Parameters

If you want to use Volatility parameters, refer to the plugin documentation. The parameters expected are generally the same with the same names.

For example, to use the `pslist` plugin with a parameter:

```python
win.pslist(pid=4).to_list()
```

### Note

On the return of the Volatility functions, a `Rendering` class is retrieved. This allows us to format our output as desired.