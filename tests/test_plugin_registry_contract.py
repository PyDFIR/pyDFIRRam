"""Tests de contrat autour du cache de découverte et de l'API registre."""

import pytest

from pydfirram.core.base import Generic, OperatingSystem, PluginRegistry
from pydfirram.core.exceptions import PluginNotFoundError


def test_registry_resolution_contract(generic_discovery_instance: Generic) -> None:
    assert generic_discovery_instance.has_plugin("pslist")
    names = generic_discovery_instance.list_plugins()
    assert isinstance(names, list)
    assert any(fn.lower().endswith(".pslist") for fn in names)
    desc = generic_discovery_instance.plugin_info("pslist")
    assert desc.name == "pslist"
    assert desc.fq_name


def test_list_plugins_os_filter(generic_discovery_instance: Generic) -> None:
    win = generic_discovery_instance.list_plugins(os_filter=OperatingSystem.WINDOWS)
    linux = generic_discovery_instance.list_plugins(os_filter=OperatingSystem.LINUX)
    assert isinstance(win, list) and isinstance(linux, list)
    assert generic_discovery_instance.list_plugins() == generic_discovery_instance.list_plugins(
        os_filter=OperatingSystem.WINDOWS,
    )
    assert any(x.lower().startswith("windows.") for x in win)
    if not any(x.lower().startswith("linux.") for x in linux):
        pytest.skip("Installation Volatility3 sans plugins linux.* — assertion ignorée.")


def test_plugin_info_missing_raises(generic_discovery_instance: Generic) -> None:
    with pytest.raises(PluginNotFoundError):
        generic_discovery_instance.plugin_info("__pydfirram_no_such_plugin__")


def test_discovery_cached_per_volatility_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("volatility3")
    PluginRegistry.clear_cache()
    dump = tmp_path / "minimal.raw"
    dump.write_bytes(b"y")

    orig_impl = PluginRegistry.__dict__["_raw_plugin_map"].__func__
    probe = {"calls": 0}

    def instrumented_raw_map() -> dict:
        probe["calls"] += 1
        return orig_impl()

    monkeypatch.setattr(
        PluginRegistry,
        "_raw_plugin_map",
        staticmethod(instrumented_raw_map),
    )

    gen_a = Generic(OperatingSystem.WINDOWS, dump)
    gen_b = Generic(OperatingSystem.WINDOWS, dump)
    _ = gen_a.plugins
    _ = gen_b.plugins
    assert probe["calls"] == 1

    _ = Generic(OperatingSystem.LINUX, dump).plugins
    assert probe["calls"] >= 2


@pytest.fixture
def generic_discovery_instance(tmp_path: Path) -> Generic:
    pytest.importorskip("volatility3")
    dump = tmp_path / "dump.raw"
    dump.write_bytes(b"x")
    return Generic(OperatingSystem.WINDOWS, dump)
