"""
This module provides utilities for hashing files.

Functions:
    get_hash(path: Path) -> str: Calculates and returns the SHA-256 hash of the specified file.
"""

import os
import hashlib
import pickle
from typing import Any, Dict, Tuple, Optional
from pathlib import Path
import mmap

def get_hash(path: Path) -> str:
    """
    Get the hash of a file.

    This method opens the specified file in binary mode and calculates the
    SHA-256 hash by traversing the file inblocks of 4096 bytes. The hash is
    updated at each iteration to include the contents of the processed block.

    Once the entire file has been processed, the method returns the SHA-256
    hash value in hexadecimal format.

    Note: This method is intended for internal use by the specific code and
    must not be called directly from other parts of the code.

    Args:
        path (Path): Path to the file.

    Returns:
        str: Hash of the file.
    """
    with open(path, "rb") as f:
        hash_obj = hashlib.sha256()
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
        return hash_obj.hexdigest()

def get_default_cache_dir() -> str:
    """
    Determines the default cache directory based on the operating system.

    :return: The path to the default cache directory as a string.
    :raises NotImplementedError: If the operating system is unsupported.
    """
    if os.name == 'nt':  # Windows
        return os.path.join(os.getenv('LOCALAPPDATA'), 'my_volatility_wrapper', 'cache')
    elif os.name == 'posix':  # Linux/MacOS
        return os.path.expanduser('~/.cache/my_volatility_wrapper')
    else:
        raise NotImplementedError(f"Unsupported OS: {os.name}")


def exist_in_cache(hash: str, plugin_name: str, kwargs: Optional[Dict[str, Any]] = None) -> Tuple[bool, Path]:
    """
    Check if a cache file exists based on the hash, plugin name, and optional keyword arguments.

    :param hash: The hash value to use in the cache file path.
    :param plugin_name: The name of the plugin used in the cache file path.
    :param kwargs: Optional dictionary of keyword arguments to be included in the cache file path.
    :return: A tuple containing a boolean indicating whether the cache file exists, 
             and the Path object representing the cache file location.
    """
    arguments = ''.join(f'{key}{value}' for key, value in (kwargs or {}).items())
    file_name = f"/{hash}{plugin_name}{arguments}"
    file_name = hashlib.md5(file_name.encode()).hexdigest()
    full_path = Path(get_default_cache_dir()) / file_name

    try:
        file_exists = full_path.is_file()
    except Exception as e:
        print(f"An error occurred while checking the file: {e}")
        file_exists = False

    return file_exists, full_path

def save_to_cache(cache_file: Path, data: Any) -> None:
    """
    Save the provided data to the specified cache file using Pickle for faster serialization.
    If the file or its parent directory does not exist, it will create them.

    :param cache_file: The file path where the data should be saved.
    :param data: The data to be saved.
    """
    # Ensure the directory exists before saving
    cache_file.parent.mkdir(parents=True, exist_ok=True)  # Create parent directories if they don't exist

    # Use pickle to serialize the data in binary format
    with cache_file.open('wb') as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)  # Faster binary serialization

def load_from_cache(cache_file: Path) -> Any:
    """
    Load data from the specified cache file using memory-mapped I/O for faster access.

    :param cache_file: The file path from which data should be loaded.
    :return: The loaded data.
    """
    # Use mmap for fast reading of the file
    with cache_file.open('rb') as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            return pickle.loads(mm)  # Deserialize using Pickle
