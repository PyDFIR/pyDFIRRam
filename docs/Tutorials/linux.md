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

4. **Listing Available Functions**:
   - To list all available Volatility plugins:
     ```python
     generic.get_all_plugins()
     ```

5. **Using Plugins**:
   - Refer to Volatility plugin documentation for parameters. Example using `pslist` plugin:
     ```python
     generic.pslist(pid=[4]).to_list()
     ```

6. **Formatting Output**:
   - The return from Volatility functions provides a `Rendering` class, allowing customization of output format.

### Notes

- Ensure your memory dump file (`dump.raw` in the example) is correctly specified.
- Adjust paths and settings based on your specific environment and Python setup.
