"""Tests pour les runtimes d’exécution de plugins."""

from __future__ import annotations

import sys

import pytest

from pydfirram.core.exceptions import PluginTimeoutError
from pydfirram.core.runtime import (
    InProcessRuntime,
    PluginInvocation,
    SubprocessRuntime,
    WORKER_RESULT_BASENAME,
)
from pydfirram.core.workspace import RunManifest, WorkspaceManager


def test_in_process_timeout_is_soft() -> None:
    """Le fil bloquant n’est pas tué : kind=soft."""

    def blocking() -> str:
        import time as _t

        _t.sleep(5.0)
        return "nope"

    inv = PluginInvocation(
        in_process_target=blocking,
        subprocess_job_payload=None,
        job_file_path=None,
        result_pickle_path=None,
        plugin_name="fake_block",
        stdout_path=None,
        stderr_path=None,
        timeout_cleanup=None,
    )
    rt = InProcessRuntime()

    with pytest.raises(PluginTimeoutError) as excinfo:
        rt.execute(inv, timeout_s=0.05)

    assert excinfo.value.timeout_kind == "soft"


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Timeout dur validé en priorité sous Linux/macOS uniquement.",
)
def test_subprocess_runtime_hard_timeout_via_stub(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PYDFIR_TEST_ALLOW_WORKER_STUB", "1")

    mgr = WorkspaceManager(tmp_path)
    run_id, paths = mgr.create_run_workspace()
    manifest = RunManifest.start_shell(
        run_id=run_id,
        plugin_name="stub_blocking",
        dump_path=tmp_path / "d.raw",
    )
    (tmp_path / "d.raw").write_bytes(b"z")
    manifest.write_json(paths.manifest)

    result_path = paths.tmp / WORKER_RESULT_BASENAME
    payload = {
        "__pydfir_test_stub__": "sleep",
        "__pydfir_sleep_s": 3600,
        "result_pickle_path": result_path.resolve().as_posix(),
    }
    job_path = paths.tmp / "job_exec.json"

    inv = PluginInvocation(
        in_process_target=lambda: None,
        subprocess_job_payload=payload,
        job_file_path=job_path,
        result_pickle_path=result_path,
        plugin_name="stub_blocking",
        stdout_path=paths.logs / "executor_stdout.log",
        stderr_path=paths.logs / "executor_stderr.log",
        timeout_cleanup=None,
    )
    rt = SubprocessRuntime(kill_grace_seconds=0.5)

    with pytest.raises(PluginTimeoutError) as excinfo:
        rt.execute(inv, timeout_s=0.2)

    assert excinfo.value.timeout_kind == "hard"
    assert excinfo.value.stderr_log_path is not None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Timeout dur validé en priorité sous Linux/macOS uniquement.",
)
def test_stub_worker_returns_quickly(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PYDFIR_TEST_ALLOW_WORKER_STUB", "1")

    mgr = WorkspaceManager(tmp_path)
    run_id, paths = mgr.create_run_workspace()

    manifest = RunManifest.start_shell(
        run_id=run_id,
        plugin_name="stub_ok",
        dump_path=tmp_path / "d.raw",
    )
    (tmp_path / "d.raw").write_bytes(b"z")
    manifest.write_json(paths.manifest)

    result_path = paths.tmp / WORKER_RESULT_BASENAME
    payload = {
        "__pydfir_test_stub__": "return",
        "__pydfir_value": 42,
        "result_pickle_path": result_path.resolve().as_posix(),
    }
    job_path = paths.tmp / "job_ok.json"

    inv = PluginInvocation(
        in_process_target=lambda: None,
        subprocess_job_payload=payload,
        job_file_path=job_path,
        result_pickle_path=result_path,
        plugin_name="stub_ok",
        stdout_path=paths.logs / "executor_stdout.log",
        stderr_path=paths.logs / "executor_stderr.log",
        timeout_cleanup=None,
    )

    rt = SubprocessRuntime()
    outcome = rt.execute(inv, timeout_s=5.0)

    assert outcome == 42
    assert (paths.logs / "executor_stdout.log").exists()
    assert (paths.logs / "executor_stderr.log").exists()
