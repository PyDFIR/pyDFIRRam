from pydfirram.core.renderer import Renderer, TreeGrid_to_json


def test_renderer_to_list_uses_treegrid_serializer(monkeypatch):
    expected_data = [{"PID": 4, "Name": "System"}]

    def fake_render(self, grid):  # noqa: ARG001
        return {"data": expected_data}

    monkeypatch.setattr(TreeGrid_to_json, "render", fake_render)
    renderer = Renderer(data=object())

    assert renderer.to_list() == expected_data


def test_renderer_to_json_serializes_list(monkeypatch):
    monkeypatch.setattr(Renderer, "to_list", lambda self: [{"hello": "world"}])
    renderer = Renderer(data=object())

    assert renderer.to_json() == '[{"hello": "world"}]'


def test_renderer_to_df_builds_dataframe(monkeypatch):
    monkeypatch.setattr(Renderer, "to_list", lambda self: [{"PID": 4, "Name": "System"}])
    renderer = Renderer(data=object())
    dataframe = renderer.to_df()

    assert list(dataframe.columns) == ["PID", "Name"]
    assert dataframe.iloc[0]["PID"] == 4
