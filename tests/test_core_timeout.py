import time
from types import SimpleNamespace

import pytest

from pydfirram.core.base import Generic, OperatingSystem, PluginEntry, PluginType
from pydfirram.core.exceptions import PluginTimeoutError


@pytest.fixture
def generic_without_plugins(monkeypatch, tmp_path):
    monkeypatch.setattr(Generic, "get_all_plugins", lambda self: [])
    dump = tmp_path / "fake.raw"
    dump.write_bytes(b"dump")
    return Generic(OperatingSystem.WINDOWS, dump)


def test_timeout_configuration_validation(monkeypatch, tmp_path):
    monkeypatch.setattr(Generic, "get_all_plugins", lambda self: [])
    dump = tmp_path / "fake.raw"
    dump.write_bytes(b"dump")

    with pytest.raises(ValueError):
        Generic(OperatingSystem.WINDOWS, dump, timeout=0)


def test_run_plugin_timeout_raises_and_cleans_temp_files(generic_without_plugins, monkeypatch, tmp_path):
    generic = generic_without_plugins
    generic.timeout = 0.05
    plugin = PluginEntry(PluginType.GENERIC, "slow_plugin", object())

    run_dir = tmp_path / "run-timeout"
    run_dir.mkdir(parents=True, exist_ok=True)
    temp_artifact = run_dir / "tmp_orphan.vol3"
    temp_artifact.write_bytes(b"orphan")

    class SlowRunnable:
        def run(self):
            time.sleep(0.2)
            return "never"

    def fake_build(_plugin, _kwargs, **_ignored):
        generic.context = SimpleNamespace(run_output_dir=run_dir)
        return SlowRunnable()

    monkeypatch.setattr(generic, "_build_runable_context", fake_build)

    with pytest.raises(PluginTimeoutError) as exc:
        generic.run_plugin(plugin)

    assert exc.value.timeout_kind == "soft"

    assert not temp_artifact.exists()
    assert not run_dir.exists()


def test_run_plugin_propagates_underlying_execution_errors(generic_without_plugins, monkeypatch, tmp_path):
    generic = generic_without_plugins
    generic.timeout = 0.5
    plugin = PluginEntry(PluginType.GENERIC, "failing_plugin", object())

    class FailingRunnable:
        def run(self):
            raise RuntimeError("volatility boom")

    def fake_build(_plugin, _kwargs, **_ignored):
        generic.context = SimpleNamespace(run_output_dir=tmp_path / "run-ok")
        return FailingRunnable()

    monkeypatch.setattr(generic, "_build_runable_context", fake_build)

    with pytest.raises(RuntimeError, match="volatility boom"):
        generic.run_plugin(plugin)


def test_run_plugin_per_call_timeout_overrides_default(generic_without_plugins, monkeypatch, tmp_path):
    generic = generic_without_plugins
    generic.timeout = 1.0
    plugin = PluginEntry(PluginType.GENERIC, "override_timeout", object())

    class SlowRunnable:
        def run(self):
            time.sleep(0.1)
            return "done"

    def fake_build(_plugin, _kwargs, **_ignored):
        generic.context = SimpleNamespace(run_output_dir=tmp_path / "run-override")
        return SlowRunnable()

    monkeypatch.setattr(generic, "_build_runable_context", fake_build)

    with pytest.raises(PluginTimeoutError) as exc:
        generic.run_plugin(plugin, timeout=0.01)

    assert exc.value.timeout_kind == "soft"
