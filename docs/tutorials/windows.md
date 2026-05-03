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

### Listing and inspecting plugins

Qualified plugin names (e.g. `windows.pslist`) can be listed and checked without running them:

```python
win.list_plugins()                    # sorted qualified names for Windows + generic plugins
win.has_plugin("windows.pslist")
win.plugin_info("pslist")             # PluginDescriptor; use .fq_name for the canonical id
```

`get_all_plugins()` still returns a list of internal `PluginEntry` objects if you need the Volatility interface classes.

For the full plugin SDK (cache behaviour, migration), see the **[Plugins (SDK API)](plugins-sdk.md)** tutorial.

### Running plugins (recommended)

Use `run_plugin` with a **qualified** name; it returns a [`Renderer`](../reference/renderer.md) (`.to_list()`, `.to_df()`, `.to_json()`, etc.):

```python
win.run_plugin("windows.pslist", pid=4).to_list()
```

Parameters match those documented for the Volatility plugin.

### Legacy dynamic access (deprecated)

Calling plugins as attributes (e.g. `win.pslist(...)`) still works but emits a **`DeprecationWarning`**. Prefer `run_plugin("windows.pslist", ...)` for stable code.

### Note

`run_plugin` wraps the raw Volatility result in a **`Renderer`** so you can format output consistently. The underlying object is also available as `renderer.data` if needed.