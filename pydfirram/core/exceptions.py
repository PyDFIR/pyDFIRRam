"""Custom exceptions used across pyDFIRRam."""


class PyDFIRRamError(Exception):
    """Base exception for all pyDFIRRam user-facing errors."""


class PluginNotFoundError(PyDFIRRamError):
    """Raised when an analyst requests a plugin that is unavailable."""


class PluginExecutionError(PyDFIRRamError):
    """Raised when a plugin fails during execution."""


class PluginTimeoutError(PluginExecutionError):
    """Raised when a plugin does not complete before timeout."""


class InvalidPluginArgumentError(PyDFIRRamError):
    """Raised when provided plugin arguments are invalid."""


class OutputHandlingError(PyDFIRRamError):
    """Raised when pyDFIRRam cannot render or persist plugin output."""


class ArtifactAlreadyExistsError(PyDFIRRamError):
    """Raised when output artifact path already exists and must not be overwritten."""


class VolatilityContextError(PyDFIRRamError):
    """Raised when volatility context creation or preparation fails."""


class WorkspaceConflictError(PyDFIRRamError):
    """Raised when a filesystem workspace path would clobber existing data."""
