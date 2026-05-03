# How to Use pyDFIRRam for Windows

This guide provides a brief and concise demonstration of how to use the pyDFIRRam tool for Windows.

## Introduction

Currently, the project is under development. To use the Volatility-related functions for Windows, follow these steps:

Install pyDFIRRam (add **`[pandas]`** if you use `.to_df()`):

```bash
pip install pydfirram
pip install "pydfirram[pandas]"   # optional, for DataFrames
```

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

Use `run_plugin` with a **qualified** name; it returns a [`Renderer`](../reference/renderer.md) (`.to_list()`, `.to_df()`, `.to_json()`, `.to_jsonl(path)`, `.to_csv(path)`, optional `.to_parquet(path)`, etc.):

```python
win.run_plugin("windows.pslist", pid=4).to_list()
```

Parameters match those documented for the Volatility plugin.

#### Export shape (small vs large results)

- **Small tables / notebooks**: use `.to_df()` (requires the optional **`pandas`** extra: `pip install "pydfirram[pandas]"`).
- **Large outputs / streaming to disk**: prefer `.to_jsonl(path)` or `.to_csv(path)` so you do not materialize everything as a single in-memory DataFrame. These use the standard library only (no pandas).
- **Batch / reporting**: when using a run workspace, write artefacts under the run’s **`tables/`** directory (see `RunWorkspacePaths.tables` in the workspace reference), e.g. `runs/<run_id>/tables/pslist.jsonl`.
- **Parquet**: `.to_parquet(path)` is optional behind the **`parquet`** extra (`pandas` + `pyarrow`); see the [Renderer](../reference/renderer.md) reference.

### Legacy dynamic access (deprecated)

Calling plugins as attributes (e.g. `win.pslist(...)`) still works but emits a **`DeprecationWarning`**. Prefer `run_plugin("windows.pslist", ...)` for stable code.

### Note

`run_plugin` wraps the raw Volatility result in a **`Renderer`** so you can format output consistently. The underlying object is also available as `renderer.data` if needed.