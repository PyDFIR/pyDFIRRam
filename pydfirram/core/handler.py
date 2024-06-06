"""Provides a file handler class that saves files directly to disk.

This module provides a file handler class that saves files directly to disk.
It is used by the Volatility3 CLI to save files to disk.

Example:
    The file handler class can be used as follows:

        $ python3
        >>> from volatility3.cli import create_file_handler
        >>> file_handler = create_file_handler("output")
        >>> file = file_handler("test.txt")
        >>> file.write(b"Hello, world!")
        >>> file.close()

Todo:
    * For now, this module only provides a file handler class
      that saves files directly to disk. In the future, it could
      be extended to provide other file handlers as well.
"""

import io
import os
import tempfile

from typing import Optional

from volatility3.framework import interfaces


def create_file_handler(output_dir: Optional[str]) -> type:
    """Create a file handler class that saves files directly to disk.

    Args:
        output_dir (str): The directory where the files should be saved.
                          If None, raises a TypeError.
    Returns:
        type: A file handler class that saves files directly to disk.
    """

    class CLIFileHandler(interfaces.plugins.FileHandlerInterface):
        """The FileHandler from Volatility3 CLI."""

        def _get_final_filename(self) -> str:
            """Gets the final filename for the saved file."""
            if output_dir is None:
                raise TypeError("Output directory is not a string")

            os.makedirs(output_dir, exist_ok=True)
            if self.preferred_filename is None:
                raise TypeError("No preferred filename")

            pref_name_array = self.preferred_filename.split(".")

            filename, extension = (
                os.path.join(output_dir, ".".join(pref_name_array[:-1])),
                pref_name_array[-1],
            )
            output_filename = f"{filename}.{extension}"

            if os.path.exists(output_filename):
                os.remove(output_filename)

            return output_filename

    class CLIDirectFileHandler(CLIFileHandler):
        """A file handler class that saves files directly to disk."""

        def __init__(self, filename: str):
            fd, temp_name = tempfile.mkstemp(
                suffix=".vol3", prefix="tmp_", dir=output_dir
            )

            self._file = io.open(fd, mode="w+b")
            CLIFileHandler.__init__(self, filename)

            for attr in dir(self._file):
                if not attr.startswith("_") and attr not in [
                    "closed",
                    "close",
                    "mode",
                    "name",
                ]:
                    setattr(self, attr, getattr(self._file, attr))

            self._name = temp_name

        def __getattr__(self, item):
            return getattr(self._file, item)

        @property
        def closed(self):
            """Returns whether the file is closed."""
            return self._file.closed

        @property
        def mode(self):
            """Returns the mode of the file."""
            return self._file.mode

        @property
        def name(self):
            """Returns the name of the file."""
            return self._file.name

        def close(self):
            """Closes and commits the file
            by moving the temporary file to the correct name.
            """
            # Don't overcommit
            if self._file.closed:
                return
            self._file.close()
            output_filename = self._get_final_filename()
            os.rename(self._name, output_filename)

    return CLIDirectFileHandler
