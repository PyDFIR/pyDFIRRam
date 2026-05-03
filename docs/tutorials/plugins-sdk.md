# Plugin discovery and explicit API

This tutorial describes the **stable** way to list, inspect, and execute Volatility 3 plugins through pyDFIRRam. Legacy dynamic attribute access (`instance.pslist()`, etc.) still works but emits a `DeprecationWarning`; new code should prefer the explicit calls below.

## How discovery is cached

`PluginRegistry` loads the Volatility plugin catalogue once per pair **(Volatility 3 package version, OS namespace)** (e.g. `windows`, `linux`). Multiple `Windows()` or `Generic(...)` instances reuse the same cached registry for that pair, so scans are not repeated on every wrapper construction.

If you need to force a fresh catalogue in tests, use `PluginRegistry.clear_cache()` (see API reference).

## Running a plugin

Use the **fully qualified Volatility name** when possible (recommended for scripts and stable SDK usage):

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

win = Windows(Path("memory.dump"))
df = win.run_plugin("windows.pslist").to_df()
```

`run_plugin` returns a [`Renderer`](../reference/renderer.md). The raw TreeGrid (or other Volatility result) is available as `renderer.data` if you need it.

For **small** result sets, `.to_df()` is convenient (optional **`pandas`** extra). For **large** outputs, use `.to_jsonl(path)` or `.to_csv(path)` to stream to disk without pandas. When you record batch artefacts, place files under the run’s **`tables/`** path (`RunWorkspacePaths.tables`). Optional `.to_parquet(path)` needs the **`parquet`** extra — see the Renderer reference.

You can pass keyword arguments expected by the Volatility plugin configuration (same names as in the Volatility CLI/docs):

```python
rows = win.run_plugin("windows.pslist", pid=[4]).to_list()
```

A **short name** (last segment of the qualified name, compared case-insensitively) often works, e.g. `"pslist"` instead of `"windows.pslist"`. If several plugins share the same short name, resolution raises `PluginNotFoundError` and you must use the qualified name.

The first argument can also be a `PluginEntry` or `PluginDescriptor` obtained from `get_plugin` / `plugin_info`.

## Listing and inspecting plugins

| Method | Purpose |
| ------ | ------- |
| `list_plugins(os_filter=None)` | Sorted list of **qualified** plugin names (e.g. `windows.pslist`). If `os_filter` is an `OperatingSystem` value, lists plugins for that OS; if `None`, uses the wrapper’s own OS. |
| `has_plugin(name)` | Whether `name` resolves (short or qualified) for the **current** wrapper’s OS registry. |
| `plugin_info(name)` | Returns an immutable `PluginDescriptor` (`fq_name`, `name`, `type`, `interface`). |

To work with legacy `PluginEntry` objects (as before):

- `get_all_plugins()` — list of `PluginEntry` for this wrapper’s OS (from cache).
- `get_plugin(name)` — resolve by short or qualified name; raises **`PluginNotFoundError`** if missing or ambiguous.

## Migration from dynamic attributes

| Before (deprecated) | After (recommended) |
| ------------------ | ------------------- |
| `windows.pslist().to_df()` | `windows.run_plugin("windows.pslist").to_df()` |
| `generic.pslist(pid=[4]).to_list()` | `generic.run_plugin("linux.pslist", pid=[4]).to_list()` (adjust qualified name for your OS) |

Accessing plugins as Python attributes (`win.pslist`, etc.) triggers a `DeprecationWarning` and should be phased out for production-style code.
