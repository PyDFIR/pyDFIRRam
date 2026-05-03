from pathlib import Path

import pytest

from pydfirram.core.handler import create_file_handler
from pydfirram.core.exceptions import ArtifactAlreadyExistsError


def test_existing_file_fails_by_default(tmp_path: Path) -> None:
    run_id = "run-default"
    run_dir = tmp_path / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    target_file = run_dir / "artifact.txt"
    target_file.write_bytes(b"existing")

    file_handler = create_file_handler(str(tmp_path), run_id=run_id)
    file_obj = file_handler("artifact.txt")
    file_obj.write(b"new-data")

    with pytest.raises(ArtifactAlreadyExistsError):
        file_obj.close()

    assert target_file.read_bytes() == b"existing"


def test_same_filename_twice_uses_unique_policy(tmp_path: Path) -> None:
    run_id = "run-unique"
    file_handler = create_file_handler(
        str(tmp_path),
        run_id=run_id,
        collision_policy="unique",
    )

    file_a = file_handler("artifact.txt")
    file_a.write(b"first")
    file_a.close()

    file_b = file_handler("artifact.txt")
    file_b.write(b"second")
    file_b.close()

    run_dir = tmp_path / run_id
    assert (run_dir / "artifact.txt").read_bytes() == b"first"
    assert (run_dir / "artifact-1.txt").read_bytes() == b"second"


def test_output_dir_is_created_when_missing(tmp_path: Path) -> None:
    base_output_dir = tmp_path / "missing" / "nested-output"
    run_id = "run-create-dir"
    assert not base_output_dir.exists()

    file_handler = create_file_handler(str(base_output_dir), run_id=run_id)
    file_obj = file_handler("artifact.txt")
    file_obj.write(b"payload")
    file_obj.close()

    assert (base_output_dir / run_id / "artifact.txt").read_bytes() == b"payload"


def test_path_traversal_filename_is_sanitized(tmp_path: Path) -> None:
    run_id = "run-safe-name"
    file_handler = create_file_handler(str(tmp_path), run_id=run_id)
    file_obj = file_handler("../../evil.txt")
    file_obj.write(b"safe")
    file_obj.close()

    expected = tmp_path / run_id / "evil.txt"
    assert expected.exists()
    assert expected.read_bytes() == b"safe"

    escaped = tmp_path.parent / "evil.txt"
    assert not escaped.exists()
