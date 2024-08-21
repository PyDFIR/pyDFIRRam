## Quick Installation Guide

This guide provides instructions for installing `pydfirram` from various sources and using all plugins available in the `volatility3` repository.

### Prerequisites 

Ensure you have the following installed:

- Python
- Poetry (for development)
- pip

### Installation Methods

#### From Source

To install `pydfirram` from the source on a standard Linux distribution, follow these steps:

1. Clone the repository:
    ```shell
    git clone https://github.com/pydfir/pydfirram
    ```

2. Navigate into the project directory:
    ```shell
    cd pydfirram
    ```

3. Create a virtual environment and activate it using Poetry:
    ```shell
    poetry shell
    ```

4. Install the dependencies:
    ```shell
    poetry install
    ```

#### From pip (Stable)

To install the stable version of `pydfirram` from pip, use the following command:

```shell
pip install pydfirram
```

#### From pip (Development)

To install the development version of `pydfirram` from the TestPyPI repository, use the following command:

```bash
pip install -i https://test.pypi.org/simple/ pydfirram
```

#### Using All Plugins

To use all plugins available in the `volatility3` repository, follow these steps:

1. Install `pydfirram`:
    ```bash
    pip install pydfirram
    ```

2. Clone the `volatility3` repository:
    ```bash
    git clone https://github.com/volatilityfoundation/volatility3
    ```

3. Navigate into the `volatility3` directory:
    ```bash
    cd volatility3
    ```

4. Install the plugins:
    ```bash
    pip install .
    ```

This setup ensures that you have access to all the plugins provided by the `volatility3` repository.