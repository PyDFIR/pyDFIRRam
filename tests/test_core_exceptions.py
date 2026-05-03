from pathlib import Path

import pytest

import pydfirram.core.base as base_module
from pydfirram.core.base import (
    Context,
    Generic,
    OperatingSystem,
    PluginEntry,
    PluginRegistry,
    PluginType,
)
from pydfirram.core.exceptions import (
    InvalidPluginArgumentError,
    OutputHandlingError,
    PluginNotFoundError,
    PluginTimeoutError,
)
from pydfirram.core.handler import create_file_handler
from pydfirram.core.renderer import Renderer, TreeGrid_to_json
from pydfirram.core.runtime import default_execution_runtime


def _build_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generic:
    PluginRegistry.clear_cache()

    def _empty_registry(klass: type[PluginRegistry], operating_system: OperatingSystem) -> PluginRegistry:
        return PluginRegistry(operating_system, ())

    monkeypatch.setattr(PluginRegistry, "for_platform", classmethod(_empty_registry))

    generic = Generic.__new__(Generic)
    generic.os = OperatingSystem.WINDOWS
    generic.dump_file = tmp_path / "dump.raw"
    generic.dump_file.write_bytes(b"dump")
    generic.context = None
    generic.timeout = None
    generic.workspace_base = None
    generic.output_collision_policy = "fail"
    generic.manifest_include_dump_sha256 = False
    generic._run_manifest = None
    generic._artifact_manager = None
    generic.execution_runtime = default_execution_runtime()
    return generic


def test_get_plugin_raises_plugin_not_found_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    generic = _build_generic(tmp_path, monkeypatch)

    with pytest.raises(PluginNotFoundError):
        generic.get_plugin("missing_plugin")


def test_getattr_wraps_missing_plugin_with_chaining(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    generic = _build_generic(tmp_path, monkeypatch)

    with pytest.warns(DeprecationWarning):
        with pytest.raises(ValueError) as exc_info:
            generic.__getattr__("missing_plugin")

    assert isinstance(exc_info.value.__cause__, PluginNotFoundError)


def test_run_plugin_raises_timeout_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    generic = _build_generic(tmp_path, monkeypatch)
    plugin = PluginEntry(PluginType.GENERIC, "pslist", object)  # type: ignore[arg-type]

    class FakeContext:
        class _Runnable:
            def run(self):
                raise TimeoutError("slow")

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

    monkeypatch.setattr(base_module, "Context", FakeContext)

    with pytest.raises(TimeoutError):
        generic.run_plugin(plugin)


def test_run_plugin_raises_invalid_argument_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    generic = _build_generic(tmp_path, monkeypatch)
    plugin = PluginEntry(PluginType.GENERIC, "pslist", object)  # type: ignore[arg-type]

    class FakeContext:
        class _Runnable:
            def run(self):
                raise ValueError("bad arg")

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

    monkeypatch.setattr(base_module, "Context", FakeContext)

    with pytest.raises(ValueError):
        generic.run_plugin(plugin)


def test_run_plugin_raises_execution_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    generic = _build_generic(tmp_path, monkeypatch)
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

    monkeypatch.setattr(base_module, "Context", FakeContext)

    with pytest.raises(RuntimeError):
        generic.run_plugin(plugin)


def test_context_build_raises_volatility_context_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin = PluginEntry(PluginType.GENERIC, "pslist", object)  # type: ignore[arg-type]
    context = Context(OperatingSystem.WINDOWS, tmp_path / "dump.raw", plugin)

    monkeypatch.setattr(base_module, "V3UnsatisfiedException", RuntimeError)

    def fake_construct(*_args, **_kwargs):
        raise RuntimeError("unsatisfied")

    monkeypatch.setattr(base_module, "v3_construct_plugin", fake_construct)

    with pytest.raises(RuntimeError):
        context.build()


def test_create_file_handler_invalid_policy_raises_invalid_argument_error() -> None:
    with pytest.raises(InvalidPluginArgumentError):
        create_file_handler("/tmp", collision_policy="invalid")  # type: ignore[arg-type]


def test_renderer_to_list_raises_output_handling_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renderer = Renderer(data=object())

    def fake_render(self, _data):  # noqa: ARG001
        raise RuntimeError("render fail")

    monkeypatch.setattr(TreeGrid_to_json, "render", fake_render)

    with pytest.raises(OutputHandlingError) as exc_info:
        renderer.to_list()

    assert isinstance(exc_info.value.__cause__, RuntimeError)
