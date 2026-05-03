## Using pyDFIRRam for Linux or macOS

### Introduction

`pyDFIRRam` is a tool under development aimed at utilizing Volatility plugins for memory forensics on Linux and macOS systems.

### Initial Setup

1. **Installation**:
   - Ensure Python 3.10 (or compatible version) is installed.
   - Install `pyDFIRRam` using Poetry or manually. Example:
     ```
     pip install pydfirram
     ```
   - For `.to_df()`, add the optional **`pandas`** extra: `pip install "pydfirram[pandas]"`.

2. **Setting up a Profile**:
   - Currently, there's no direct method via Python interface to add a profile. If you have a profile, place it in the Volatility symbols directory:
     - For Linux/macOS:
       ```
       $HOME/.local/lib/python3.10/site-packages/volatility3/symbols/
       ```
     - For Poetry virtual environments:
       ```
       $HOME/.cache/pypoetry/virtualenvs/pydfirram-qv9SWnlF-py3.10/lib/python3.10/site-packages/volatility3/symbols/
       ```

### Using pyDFIRRam

3. **Creating an Object**:
   - Import necessary modules and create an object for your memory dump:
     ```python
     from pydfirram.core.base import Generic, OperatingSystem
     from pathlib import Path
     
     os = OperatingSystem.LINUX  # Set to OperatingSystem.MACOS for macOS
     dumpfile = Path("dump.raw")  # Replace with your actual memory dump path
     generic = Generic(os, dumpfile)
     ```

4. **Listing and inspecting plugins**:
   - Qualified names and metadata (cached per Volatility version and OS):
     ```python
     generic.list_plugins()                    # or list_plugins(os_filter=OperatingSystem.LINUX)
     generic.has_plugin("linux.pslist")
     generic.plugin_info("pslist")
     ```
   - Legacy list of `PluginEntry` objects:
     ```python
     generic.get_all_plugins()
     ```
   - See **[Plugins (SDK API)](plugins-sdk.md)** for cache details and migration.

5. **Running plugins**:
   - Use `run_plugin` with the **qualified** Volatility name for your OS; it returns a [`Renderer`](../reference/renderer.md) (`.to_list()`, `.to_df()`, `.to_json()`, `.to_jsonl(path)`, `.to_csv(path)`, optional `.to_parquet(path)`):
     ```python
     generic.run_plugin("linux.pslist", pid=[4]).to_list()
     ```
   - Refer to Volatility plugin documentation for parameter names and types.

6. **Export shape (small vs large results)**:
   - **Small tables / exploration**: `.to_df()` — install the **`pandas`** extra (`pip install "pydfirram[pandas]"`).
   - **Large outputs**: `.to_jsonl(path)` or `.to_csv(path)` to avoid holding the full result as one DataFrame; no pandas required for these two.
   - **Batch / reporting**: persist files under the run workspace **`tables/`** folder when you use structured runs (`RunWorkspacePaths.tables`, typically `runs/<run_id>/tables/`).
   - **Parquet** (optional): `.to_parquet(path)` with the **`parquet`** extra; details in the [Renderer](../reference/renderer.md) page.

7. **Legacy behaviour**:
   - Attribute-style access (`generic.pslist(...)`) still works but emits a **`DeprecationWarning`**. Prefer `run_plugin("linux.pslist", ...)` (or the correct qualified name on your image).

### Notes

- Ensure your memory dump file (`dump.raw` in the example) is correctly specified.
- Adjust paths and settings based on your specific environment and Python setup.
