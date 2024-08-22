"""
This module provides utilities for hashing files.

Functions:
    get_hash(path: Path) -> str: Calculates and returns the SHA-256 hash of the specified file.
"""

import hashlib

from pathlib import Path
from typing import Any, Tuple


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
import os
import json
import hashlib
def get_default_cache_dir() -> str:
        """Détermine l'emplacement par défaut du cache selon le système d'exploitation."""
        if os.name == 'nt':  # Windows
            return os.path.join(os.getenv('LOCALAPPDATA'), 'my_volatility_wrapper', 'cache')
        elif os.name == 'posix':  # Linux/MacOS
            return os.path.expanduser('~/.cache/my_volatility_wrapper')
        else:
            raise NotImplementedError(f"Unsupported OS: {os.name}")
    
def exist_in_cache(hash: str, plugin_name: str, kwargs: dict[str, Any] | None = None) -> Tuple[bool, Path]:
    """
    Check if a cache file exists based on the hash, plugin name, and kwargs.

    :param hash: The hash value to be used in the cache file path.
    :param plugin_name: The name of the plugin used in the cache file path.
    :param kwargs: Optional keyword arguments to be included in the cache file path.
    :return: A tuple where the first element is a boolean indicating if the cache file exists,
             and the second element is the Path object of the cache file.
    """
    # Generate the cache file name
    arguments = ''.join(f'{key}{value}' for key, value in (kwargs or {}).items())
    file_name = f"/{hash}{plugin_name}{arguments}"
    file_name = hashlib.md5(file_name.encode()).hexdigest()
    full_path = Path(get_default_cache_dir() + file_name)

    # Check if the file exists and handle exceptions
    try:
        file_exists = full_path.is_file()
    except Exception as e:
        print(f"An error occurred while checking the file: {e}")
        file_exists = False

    return file_exists, full_path
def save_to_cache(cache_file,data) -> None:
        """Save the data to the cache file in JSON format."""
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=4)  # Pretty-print with indentation

def load_from_cache(cache_file) -> Any:
    """Load the data from the cache file."""
    with open(cache_file, 'r') as f:
        return json.load(f)

