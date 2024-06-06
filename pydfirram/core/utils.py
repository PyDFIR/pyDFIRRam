""" Todo: Add module docstring. """

import hashlib

from pathlib import Path


def get_hash(path: Path) -> str:
    """
    Get the hash of a file.

    This method opens the specified file in binary mode and calculates the SHA-256 hash by traversing the file in
    blocks of 4096 bytes. The hash is updated at each iteration to include the contents of the processed block.

    Once the entire file has been processed, the method returns the SHA-256 hash value in hexadecimal format.

    Note: This method is intended for internal use by the specific code and must not be called
    directly from other parts of the code.

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
