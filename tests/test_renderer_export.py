"""Tests exports Renderer (JSONL, CSV, intégrité options pandas)."""

from __future__ import annotations

import builtins
import json
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

from pydfirram.core.exceptions import OutputHandlingError
from pydfirram.core.renderer import Renderer


def _pandas_options_flat_snapshot() -> dict[str, Any]:
    """Instantané des options pandas agrégées (préfixes publics sous ``pd.options``)."""

    snapshot: dict[str, Any] = {}
    for group_name in dir(pd.options):
        if group_name.startswith("_"):
            continue
        grp = getattr(pd.options, group_name)
        keys_cb = getattr(grp, "keys", None)
        if keys_cb is None:
            continue
        for opt in keys_cb():
            full = f"{group_name}.{opt}"
            try:
                snapshot[full] = pd.get_option(full)
            except Exception:
                pass
    return snapshot


def test_renderer_to_jsonl_writes_lines(monkeypatch, tmp_path):
    rows = [{"a": 1, "nested": {"x": 2}}, {"b": "z"}]

    monkeypatch.setattr(Renderer, "to_list", lambda self: rows)
    outfile = tmp_path / "out.jsonl"
    resolved = Renderer(object()).to_jsonl(outfile)

    assert resolved == outfile.resolve()
    decoded = [
        json.loads(line) for line in outfile.read_text(encoding="utf-8").splitlines()
    ]
    assert decoded == rows


def test_renderer_to_csv_roundtrip_columns(monkeypatch, tmp_path):
    rows = [
        {"PID": 4, "Name": "System"},
        {"PID": 8, "Name": "spam", "__children": []},
    ]
    monkeypatch.setattr(Renderer, "to_list", lambda self: rows)
    outfile = tmp_path / "tbl.csv"

    Renderer(object()).to_csv(outfile)

    import csv

    rows_read = list(csv.DictReader(outfile.open(encoding="utf-8")))
    assert len(rows_read) == 2
    assert rows_read[0]["PID"] == "4"
    assert rows_read[0]["Name"] == "System"


def test_renderer_exports_leave_pandas_options_unchanged(monkeypatch, tmp_path):
    records = [{f"c{i}": f"v{r}_{i}" for i in range(3)} for r in range(5)]
    monkeypatch.setattr(Renderer, "to_list", lambda self: records)
    renderer = Renderer(object())

    opts_before = _pandas_options_flat_snapshot()

    with pd.option_context("display.max_rows", 12, "display.max_columns", 7):
        mid_rows = pd.get_option("display.max_rows")
        mid_cols = pd.get_option("display.max_columns")

        renderer.to_jsonl(tmp_path / "a.jsonl")
        renderer.to_csv(tmp_path / "b.csv")

        dataframe = renderer.to_df(max_row=True)
        rendered = repr(dataframe)

        assert pd.get_option("display.max_rows") == mid_rows
        assert pd.get_option("display.max_columns") == mid_cols

    assert _pandas_options_flat_snapshot() == opts_before

    assert "..." not in rendered
    assert "v4_2" in rendered


def test_renderer_to_df_without_pandas(monkeypatch):
    import pydfirram.core.renderer as renderer_mod

    monkeypatch.setattr(renderer_mod, "_pd", None)
    monkeypatch.setattr(renderer_mod, "RenderableDataFrame", None)

    renderer = Renderer(object())
    monkeypatch.setattr(renderer, "to_list", lambda: [{"k": 1}])

    with pytest.raises(OutputHandlingError) as excinfo:
        renderer.to_df()
    assert "pandas" in str(excinfo.value).lower()


def test_renderer_to_parquet_blocks_without_pyarrow(monkeypatch, tmp_path):
    real_import = builtins.__import__

    def fake_import(name, globals_=None, locals_=None, fromlist=(), level=0):
        if name == "pyarrow" or name.startswith("pyarrow."):
            raise ImportError("pyarrow désactivé pour le test")
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    renderer = Renderer(object())
    monkeypatch.setattr(renderer, "to_list", lambda: [{"x": 1}])

    with pytest.raises(OutputHandlingError) as excinfo:
        renderer.to_parquet(tmp_path / "x.parquet")
    assert "parquet" in str(excinfo.value).lower() or "pyarrow" in str(
        excinfo.value
    ).lower()


def test_renderer_to_parquet_writes_file(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")

    monkeypatch.setattr(Renderer, "to_list", lambda self: [{"PID": 4, "Name": "Sys"}])

    outfile = tmp_path / "out.parquet"
    Renderer(object()).to_parquet(outfile)

    assert outfile.exists() and outfile.stat().st_size > 0
