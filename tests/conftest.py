import pytest

from tests.config import DUMP_FILE, DUMP_FILE_ENV_VAR


def pytest_collection_modifyitems(items):
    for item in items:
        if "requires_dump" not in item.keywords:
            continue

        if not DUMP_FILE.is_file():
            item.add_marker(
                pytest.mark.skip(
                    reason=(
                        "requires local dump file. "
                        f"Current path: {DUMP_FILE}. "
                        f"Set {DUMP_FILE_ENV_VAR} to a valid dump path."
                    )
                )
            )
