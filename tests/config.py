import os
from pathlib import Path

DUMP_FILE_ENV_VAR = "PYDFIRRAM_DUMP_FILE"
_dump_file_value = os.getenv(DUMP_FILE_ENV_VAR, "").strip()

# Keep a deterministic Path object for tests importing DUMP_FILE.
DUMP_FILE = (
    Path(_dump_file_value).expanduser()
    if _dump_file_value
    else Path("data/dump.raw")
)
