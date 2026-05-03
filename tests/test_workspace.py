"""Unit tests for structured run workspaces."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pydfirram.core.base import Context, Generic, OperatingSystem, PluginEntry, PluginType
from pydfirram.core.exceptions import (
    ArtifactAlreadyExistsError,
    InvalidPluginArgumentError,
    VolatilityContextError,
    WorkspaceConflictError,
)
from pydfirram.core.workspace import (
    ArtifactManager,
    MANIFEST_NAME,
    RUN_LAYOUT_PREFIX,
    RunManifest,
    RunStatus,
    WorkspaceManager,
)
from pydfirram.core.handler import create_file_handler


def test_run_status_values() -> None:
    assert RunStatus.SUCCESS.value == "success"
    assert RunStatus.FAILED.value == "failed"
    assert RunStatus.TIMEOUT.value == "timeout"


def test_workspace_manager_layout(tmp_path: Path) -> None:
    mgr = WorkspaceManager(tmp_path)
    run_id, paths = mgr.create_run_workspace()
    assert (tmp_path / RUN_LAYOUT_PREFIX / run_id).samefile(paths.root)
    assert paths.manifest == paths.root / MANIFEST_NAME
    for d in (paths.logs, paths.tables, paths.extracted, paths.tmp):
        assert d.is_dir()


def test_workspace_manager_duplicate_run_fails(tmp_path: Path) -> None:
    mgr = WorkspaceManager(tmp_path)
    run_id, paths = mgr.create_run_workspace("duplicate-id")
    assert run_id == "duplicate-id"

    with pytest.raises(WorkspaceConflictError):
        mgr.create_run_workspace("duplicate-id")


def test_workspace_invalid_policy(tmp_path: Path) -> None:
    with pytest.raises(InvalidPluginArgumentError):
        WorkspaceManager(tmp_path, collision_policy="overwrite")  # type: ignore[arg-type]


def test_sanitize_run_identifier_rejects_path(tmp_path: Path) -> None:
    mgr = WorkspaceManager(tmp_path)
    with pytest.raises(InvalidPluginArgumentError):
        mgr.planned_paths("foo/bar")


def test_run_manifest_shell_and_roundtrip(tmp_path: Path) -> None:
    from pydfirram.core.workspace import kwargs_to_manifest_dict

    kwargs = {"pid": [1, 2], "blob": Path("/tmp/a")}
    m = RunManifest.start_shell(
        run_id="abc",
        plugin_name="PsList",
        dump_path=tmp_path / "mem.raw",
        kwargs=kwargs,
    )
    m.finalize(status=RunStatus.SUCCESS, warnings=["note"])
    m.write_json(tmp_path / "manifest.json")
    restored = RunManifest.load(tmp_path / "manifest.json")
    assert restored.run_id == "abc"
    assert restored.plugin_arguments == kwargs_to_manifest_dict(kwargs)
    assert restored.status == RunStatus.SUCCESS


def test_run_manifest_finalize_duration(tmp_path: Path) -> None:
    manifest = RunManifest.start_shell(
        run_id="r1",
        plugin_name="Banners",
        dump_path=tmp_path / "d.raw",
    )
    assert manifest.started_at is not None
    manifest.finalize(status=RunStatus.FAILED, errors=["boom"], dump_sha256="deadbeef")
    assert manifest.dump_sha256 == "deadbeef"
    assert manifest.errors == ["boom"]


def test_run_manifest_compute_hash(tmp_path: Path) -> None:
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"hello")
    m = RunManifest.start_shell(run_id="h", plugin_name="p", dump_path=blob)
    digest = m.compute_dump_sha256()
    assert digest is not None and len(digest) == 64


def test_artifact_manager_propose_fail(tmp_path: Path) -> None:
    mgr_ws = WorkspaceManager(tmp_path)
    _, wp = mgr_ws.create_run_workspace()
    am = ArtifactManager(run_root=wp.root, collision_policy="fail")
    target = am.propose_table_path("out.csv")
    target.write_text("a")
    with pytest.raises(ArtifactAlreadyExistsError):
        am.propose_table_path("out.csv")


def test_artifact_manager_unique(tmp_path: Path) -> None:
    mgr_ws = WorkspaceManager(tmp_path)
    _, wp = mgr_ws.create_run_workspace()
    am = ArtifactManager(run_root=wp.root, collision_policy="unique")
    p1 = am.propose_table_path("t.csv")
    p1.write_text("1")
    p2 = am.propose_table_path("t.csv")
    assert p1 != p2
    assert p2.name.startswith("t-")


def test_artifact_manager_record_idempotent(tmp_path: Path) -> None:
    mgr_ws = WorkspaceManager(tmp_path)
    _, wp = mgr_ws.create_run_workspace()
    am = ArtifactManager(run_root=wp.root)
    wp.extracted.mkdir(exist_ok=True)
    fp = wp.extracted / "f.txt"
    fp.write_text("x")
    am.record_output(fp)
    am.record_output(fp)


def test_create_file_handler_temp_parent(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    fh = create_file_handler(
        str(out),
        use_run_subdirectory=False,
        temp_parent=str(staging),
    )
    fh_obj = fh("keep.txt")
    fh_obj.write(b"data")
    fh_obj.close()

    assert not list(staging.glob("tmp_*.vol3"))
    assert (out / "keep.txt").read_bytes() == b"data"


def test_context_workspace_requires_run_id(tmp_path: Path) -> None:
    mgr_ws = WorkspaceManager(tmp_path)
    _, wp = mgr_ws.create_run_workspace()
    plugin = PluginEntry(PluginType.GENERIC, "x", object)  # type: ignore[arg-type]

    with pytest.raises(VolatilityContextError):
        Context(
            OperatingSystem.WINDOWS,
            tmp_path / "dump.raw",
            plugin,
            workspace_paths=wp,
            workspace_run_id=None,  # type: ignore[arg-type]
        )


def test_generic_run_plugin_writes_manifest_on_failure(monkeypatch, tmp_path: Path) -> None:
    plugin = PluginEntry(PluginType.GENERIC, "pslist", object)  # type: ignore[arg-type]

    class FakeContext:
        class _Runnable:
            def run(self):
                raise RuntimeError("boom")

        def __init__(self, *_args, **_kwargs):
            pass

        def set_automagic(self) -> None:
            return None

        def set_context(self) -> None:
            return None

        def build(self):
            return self._Runnable()

        def add_arguments(self, context, _kwargs):
            return context

    import pydfirram.core.base as base_module

    monkeypatch.setattr(base_module, "Context", FakeContext)

    dump = tmp_path / "dump.raw"
    dump.write_bytes(b"x")
    generic = Generic(
        OperatingSystem.WINDOWS,
        dump,
        workspace_base=tmp_path,
    )

    with pytest.raises(RuntimeError):
        generic.run_plugin(plugin, foo=1)

    manifest_path = next((tmp_path / RUN_LAYOUT_PREFIX).rglob(MANIFEST_NAME))
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["status"] == RunStatus.FAILED.value
    assert data["plugin_name"] == "pslist"
    assert "python_version" in data
    assert "pydfirram_version" in data
    assert "volatility3_version" in data
