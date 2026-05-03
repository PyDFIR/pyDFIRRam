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
import re
import tempfile
import uuid

from typing import Optional, Any, Literal

from volatility3.framework.interfaces.plugins import (  # type: ignore
    FileHandlerInterface    as V3FileHandlerInterface,
)

from pydfirram.core.exceptions import (
    ArtifactAlreadyExistsError,
    InvalidPluginArgumentError,
    OutputHandlingError,
)


OutputCollisionPolicy = Literal["fail", "unique", "overwrite"]


def _sanitize_filename(filename: str) -> str:
    """Return a safe filename without directory traversal patterns."""
    candidate = filename.replace("\\", "/").strip()
    if not candidate or "\x00" in candidate:
        raise OutputHandlingError(
            "Nom de fichier de sortie invalide fourni par le plugin."
        )

    # Keep only the terminal component so user-provided paths cannot escape.
    candidate = candidate.split("/")[-1]
    if candidate in {"", ".", ".."}:
        raise OutputHandlingError(
            "Nom de fichier de sortie invalide fourni par le plugin."
        )

    # Keep portability and avoid shell-unfriendly characters.
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
    if sanitized in {"", ".", ".."}:
        raise OutputHandlingError(
            "Nom de fichier de sortie invalide fourni par le plugin."
        )
    return sanitized


def _build_unique_path(path: str) -> str:
    """Build a unique path by appending an incrementing numeric suffix."""
    base, extension = os.path.splitext(path)
    candidate = path
    index = 1
    while os.path.exists(candidate):
        candidate = f"{base}-{index}{extension}"
        index += 1
    return candidate


def _sanitize_run_id(run_id: str) -> str:
    """Return a safe run identifier for output subdirectories."""
    candidate = run_id.strip()
    if not candidate or "/" in candidate or "\\" in candidate:
        raise InvalidPluginArgumentError(
            "Identifiant d'execution invalide pour la collecte d'artefacts."
        )
    if candidate in {".", ".."}:
        raise InvalidPluginArgumentError(
            "Identifiant d'execution invalide pour la collecte d'artefacts."
        )
    return re.sub(r"[^A-Za-z0-9._-]", "_", candidate)


def create_file_handler(
    output_dir: Optional[str],
    *,
    collision_policy: OutputCollisionPolicy = "fail",
    run_id: Optional[str] = None,
) -> type:
    """Create a file handler class that saves files directly to disk.

    Args:
        output_dir (str): The base directory where extracted files should be
                          saved. A run-specific subdirectory is created below it.
                          If None, raises a TypeError.
        collision_policy (OutputCollisionPolicy): Behaviour when target file
                          already exists: "fail" (default), "unique", "overwrite".
        run_id (str): Optional run identifier. If omitted, a random run id is
                      generated to isolate extraction runs.
    Returns:
        type: A file handler class that saves files directly to disk.
    """
    if collision_policy not in {"fail", "unique", "overwrite"}:
        raise InvalidPluginArgumentError(
            "Politique de collision invalide. Valeurs supportees: "
            "'fail', 'unique', 'overwrite'."
        )

    effective_run_id = _sanitize_run_id(run_id) if run_id else uuid.uuid4().hex
    run_output_dir = (
        os.path.join(output_dir, effective_run_id)
        if output_dir is not None
        else None
    )

    class CLIFileHandler(V3FileHandlerInterface): # type: ignore
        """The FileHandler from Volatility3 CLI.
        """
        def _get_final_filename(self) -> str:
            """Gets the final filename for the saved file."""
            if run_output_dir is None:
                raise OutputHandlingError(
                    "Le dossier de sortie n'est pas configure correctement."
                )

            os.makedirs(run_output_dir, exist_ok=True)
            if self.preferred_filename is None:
                raise OutputHandlingError(
                    "Le plugin n'a pas fourni de nom de fichier de sortie."
                )

            safe_filename = _sanitize_filename(self.preferred_filename)
            output_filename = os.path.join(run_output_dir, safe_filename)
            if collision_policy == "unique":
                return _build_unique_path(output_filename)
            return output_filename

        def close(self) -> None:
            """ V3FileHandlerInterface require to implement this method """

    class CLIDirectFileHandler(CLIFileHandler):
        """A file handler class that saves files directly to disk.
        """
        def __init__(self, filename: str) -> None:
            if run_output_dir is None:
                raise OutputHandlingError(
                    "Le dossier de sortie n'est pas configure correctement."
                )
            os.makedirs(run_output_dir, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                suffix  = ".vol3",
                prefix  = "tmp_",
                dir     = run_output_dir,
            )

            # allow `io.open()` without using `with` context
            # pylint: disable=R1732
            self._file = io.open(fd, mode="w+b")
            CLIFileHandler.__init__(self, _sanitize_filename(filename)) # type: ignore

            for attr in dir(self._file):
                if not attr.startswith("_") and attr not in [
                    "closed",
                    "close",
                    "mode",
                    "name",
                ]:
                    setattr(self, attr, getattr(self._file, attr))

            self._name = temp_name

        def __getattr__(self, item: Any) -> Any:
            return getattr(self._file, item)

        ## properties

        @property
        def closed(self) -> bool:
            """Returns whether the file is closed."""
            return self._file.closed

        @property
        def mode(self) -> str:
            """Returns the mode of the file."""
            return self._file.mode

        @property
        def name(self) -> str:
            """Returns the name of the file."""
            return self._file.name

        ## methods

        def close(self) -> None:
            """Closes and commits the file
            by moving the temporary file to the correct name.
            """
            # Don't overcommit
            if self._file.closed:
                return
            self._file.close()
            output_filename = self._get_final_filename()
            if collision_policy == "overwrite":
                os.replace(self._name, output_filename)
                return

            if os.path.exists(output_filename):
                os.unlink(self._name)
                if collision_policy == "fail":
                    raise ArtifactAlreadyExistsError(
                        "Un artefact existe deja pour cette extraction: "
                        f"{output_filename}. Modifiez la politique de collision "
                        "ou le dossier de sortie."
                    )
                raise OutputHandlingError(
                    f"Politique de collision inconnue: {collision_policy}"
                )

            os.rename(self._name, output_filename)

    return CLIDirectFileHandler
