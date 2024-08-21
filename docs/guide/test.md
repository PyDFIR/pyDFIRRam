# Test Documentation

## Project Structure
The project is organized as follows:
```bash
.
├── __init__.py
├── config.py
├── data
│   └── dump.raw
├── test_core_base.py
├── test_core_rendering.py
└── test_volatility_windows_function.py
```

### Files Description

- **config.py**
  This file contains configuration settings. You need to set the path of your dump file here before running the tests.

- **test_core_base.py**
  This script tests the core functionalities used in `pydfirram/core/base.py`.

- **test_core_rendering.py**
  This script tests the core functionalities used in `pydfirram/core/renderer.py`.

- **test_volatility_windows_function.py**
  This script tests all(Not All configuration an plugins for the moment) plugins of Volatility.

### Test Data
- **data/dump.raw**
  This is where your test dump file should be located.

## Running the Tests

### Prerequisites
1. Download the Windows XP image from the Volatility Foundation:
   [Win XP Image](https://downloads.volatilityfoundation.org/volatility3/images/win-xp-laptop-2005-06-25.img.gz).

2. Extract the downloaded image and place it in the `data` directory. Rename it to `dump.raw`.

### Configuration
1. Open `config.py`.
2. Set the path of your dump file in the configuration.

### Running the Tests
To run the tests, use the following command:
```bash
pytest
```

## Notes
- The current tests only support Windows architectures. Linux architectures are not supported yet.
