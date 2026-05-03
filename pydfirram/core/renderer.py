"""
This module provides utilities for rendering data in various formats,
specifically focusing on rendering Volatility framework data into JSON,
JSONL, CSV, and optionally pandas DataFrames.

Classes:
    TreeGrid_to_json: A class for rendering Volatility TreeGrid data into
                JSON-compatible structures.
    Renderer: A class for rendering data into lists, JSON strings,
                JSONL / CSV fichiers ou DataFrames pandas (pandas optionnel).
"""

from __future__ import annotations

import csv
import datetime
from collections.abc import Iterator, Mapping
from json import dumps
from pathlib import Path
from typing import Any

from loguru import logger
from volatility3.framework.interfaces.renderers import (  # type: ignore
    Disassembly as V3Disassembly,
    BaseAbsentValue as V3BaseAbsentValue,
    RenderOption as V3RenderOption,
    TreeGrid as V3TreeGrid,
    TreeNode as V3TreeNode,
)
from volatility3.framework.renderers.format_hints import (  # type: ignore
    HexBytes as V3HexBytes,
    MultiTypeData as V3MultiTypeData,
)
from volatility3.cli.text_renderer import (  # type: ignore
    CLIRenderer as V3CLIRenderer,
    optional as v3_optional,
    quoted_optional as v3_quoted_optional,
    hex_bytes_as_text as v3_hex_bytes_as_text,
    display_disassembly as v3_display_disassembly,
    multitypedata_as_text as v3_multitypedata_as_text,
)

from pydfirram.core.exceptions import OutputHandlingError

try:
    import pandas as _pd
except ImportError:  # pragma: no cover - tested via monkeypatch
    _pd = None


_PANDAS_INSTALL_HINT = (
    "pandas est requis pour cette opération. Installez l'extra dédié "
    "(ex. poetry add pandas / pip install 'pydfirram[pandas]')."
)

_PYARROW_PARQUET_HINT = (
    "L'export Parquet requiert l'extra parquet (pandas + pyarrow), "
    "par ex. pip install 'pydfirram[parquet]'."
)


def _require_pandas() -> Any:
    if _pd is None:
        raise OutputHandlingError(_PANDAS_INSTALL_HINT)
    return _pd


# allow no PascalCase naming style and "lambda may not be necessary"
# pylint: disable=W0108,C0103
# (todo) : switch to PascalCase
class TreeGrid_to_json(V3CLIRenderer):  # type: ignore
    """simple TreeGrid to JSON"""

    _type_renderers: Any = {
        V3HexBytes: lambda x: v3_quoted_optional(v3_hex_bytes_as_text)(x),
        V3Disassembly: lambda x: v3_quoted_optional(v3_display_disassembly)(x),
        V3MultiTypeData: lambda x: v3_quoted_optional(v3_multitypedata_as_text)(x),
        bytes: lambda x: v3_optional(lambda x: " ".join([f"{b:02x}" for b in x]))(x),
        datetime.datetime: lambda x: (
            x.isoformat() if not isinstance(x, V3BaseAbsentValue) else None
        ),
        "default": lambda x: x,
    }

    name = "JSON"
    structured_output = True

    def get_render_options(self) -> list[V3RenderOption]:
        """
        Get render options.
        """
        return []

    # (fixme): This method should return nothing as defined in V3CLIRenderer
    def render(self, grid: V3TreeGrid) -> dict[str, Any]:
        """
        Render the TreeGrid to JSON format.

        Args:
            grid (interfaces.renderers.TreeGrid): The TreeGrid to render.

        Returns:
            Dict: The JSON representation of the TreeGrid.
        """
        final_output: tuple[
            dict[str, dict[str, Any]],
            list[dict[str, Any]],
        ] = ({}, [])

        def visitor(
            node: V3TreeNode,
            accumulator: tuple[dict[str, Any], list[dict[str, Any]]],
        ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            """
            A visitor function to process each node in the TreeGrid.

            Args:
                node (V3TreeNode): The current node being visited.
                accumulator (Tuple[Dict[str, Any], List[Dict[str, Any]]]):
                    The accumulator containing the accumulated results.

            Returns:
                Tuple[Dict[str, Any], List[Dict[str, Any]]]: The updated
                    accumulator.
            """
            acc_map = accumulator[0]
            final_tree = accumulator[1]
            node_dict: dict[str, Any] = {"__children": []}

            for column_index, column in enumerate(grid.columns):
                renderer_fn = self._type_renderers.get(
                    column.type,
                    self._type_renderers["default"],
                )
                data = renderer_fn(list(node.values)[column_index])
                if isinstance(data, V3BaseAbsentValue):
                    data = None
                node_dict[column.name] = data

            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict
            return acc_map, final_tree

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(
                node=None,
                function=visitor,
                initial_accumulator=final_output,
            )
        return {"data": final_output[1]}


if _pd is not None:

    class RenderableDataFrame(_pd.DataFrame):
        """
        DataFrame avec affichage optionnellement non tronqué.

        Les options pandas globales restent intactes : si ``max_row`` est
        activé, ce sont uniquement des contextes locaux (:func:`pandas.option_context`)
        qui s'appliquent pendant les repr riches.
        """

        _metadata = ["_pydfirram_full_display"]

        @property
        def _constructor(self):
            return RenderableDataFrame

        def _with_local_display_context(self, render_callable):
            if getattr(self, "_pydfirram_full_display", False):
                with _pd.option_context(
                    "display.max_rows",
                    None,
                    "display.max_columns",
                    None,
                ):
                    return render_callable()
            return render_callable()

        def __repr__(self) -> str:
            return self._with_local_display_context(super().__repr__)

        def _repr_html_(self):  # type: ignore[override]
            return self._with_local_display_context(super()._repr_html_)

else:

    RenderableDataFrame = None  # type: ignore[misc,assignment]


def _export_rows(renderer: Renderer) -> list[dict[str, Any]]:
    data = renderer.to_list()
    if data is None:
        return []
    if isinstance(data, list):
        return [row if isinstance(row, dict) else {"value": row} for row in data]
    raise OutputHandlingError(
        "Format de données inattendu pour l'export (liste de dictionnaires attendue)."
    )


def _iter_export_dict_rows(renderer: Renderer) -> Iterator[dict[str, Any]]:
    for row in _export_rows(renderer):
        yield dict(row)


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return dumps(value, ensure_ascii=False, default=str)


def _jsonl_line(record: Mapping[str, Any]) -> str:
    return dumps(dict(record), ensure_ascii=False, default=str) + "\n"


class Renderer:
    """
    Affichage des sorties plugin Volatility en formats interchangeables.

    Les exports ``to_jsonl`` et ``to_csv`` restent dans la bibliothèque standard
    (pas de dépendance pandas). ``to_df`` exige l'extra optionnel *pandas*.
    """

    def __init__(self, data: Any) -> None:
        """
        Initialise le Renderer.

        Args:
            data (Any): données brutes TreeGrid ou équivalent Volatility.
        """
        self.data = data

    def to_list(self):
        """
        Rend la grille en liste de dictionnaires (structure JSON).

        Returns:
            list[dict] | None: racines arborescentes du TreeGrid sérialisé.

        Raises:
            OutputHandlingError: si la conversion échoue.
        """
        try:
            # (fixme) : `render()` should return nothing
            parsed_data: dict[str, Any] = TreeGrid_to_json().render(self.data)
            return parsed_data.get("data")
        except OutputHandlingError:
            raise
        except Exception as e:
            logger.error("Impossible de convertir la sortie plugin en liste.")
            raise OutputHandlingError(
                "Impossible de convertir la sortie plugin en liste exploitable."
            ) from e

    def file_render(self) -> None:
        """
        Exécute le rendu fichier interne TreeGrid_to_json (sans retour métier).

        Raises:
            OutputHandlingError: en cas d'échec pipeline artefact.
        """
        try:
            # (fixme) : `render()` return nothing
            TreeGrid_to_json().render(self.data)
        except Exception as e:
            logger.error("Impossible de rendre la sortie plugin en fichier.")
            raise OutputHandlingError(
                "Impossible de traiter les sorties artefacts du plugin."
            ) from e

    def to_json(self) -> str:
        """
        Sérialise toute la sortie en une chaîne JSON (tableau racine).

        Pour de gros volumes, préférez :meth:`to_jsonl`.

        Raises:
            OutputHandlingError: en cas d'échec.
        """
        try:
            data_as_dict = self.to_list()
            return dumps(data_as_dict)
        except OutputHandlingError:
            raise
        except Exception as e:
            logger.error("Impossible de convertir la sortie plugin en JSON.")
            raise OutputHandlingError(
                "Impossible de convertir la sortie plugin au format JSON."
            ) from e

    def to_jsonl(self, path: str | Path) -> Path:
        """
        Écrit la sortie en JSON Lines (un objet JSON par ligne, UTF‑8).

        N'alloue pas de DataFrame et ne dépend pas de pandas.

        Args:
            path: fichier de sortie.

        Returns:
            Path résolu utilisé pour l'écriture.
        """
        out = Path(path)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as handle:
                for row in _iter_export_dict_rows(self):
                    handle.write(_jsonl_line(row))
        except OutputHandlingError:
            raise
        except OSError as e:
            logger.error("Échec d'écriture JSONL: {}", path)
            raise OutputHandlingError(
                f"Impossible d'écrire le fichier JSONL: {path}"
            ) from e
        except Exception as e:
            logger.error("Erreur inattendue pendant l'export JSONL.")
            raise OutputHandlingError(
                "Export JSONL interrompu."
            ) from e
        return out.resolve()

    def to_csv(self, path: str | Path, *, delimiter: str = ",") -> Path:
        """
        Écrit un CSV standard (UTF‑8) depuis les lignes exportées.

        Valeurs composites (listes, dicts imbriqués, etc.) → JSON dans la cellule,
        comme pourrait le faire pandas sans imposer cette dépendance.

        Args:
            path: fichier de sortie.
            delimiter: séparateur de colonnes.

        Returns:
            Path résolu utilisé pour l'écriture.
        """
        out = Path(path)
        rows = _export_rows(self)
        keys: list[str] = sorted({k for rec in rows for k in rec})
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=keys, delimiter=delimiter)
                writer.writeheader()
                for row in rows:
                    writer.writerow({k: _csv_cell(row.get(k)) for k in keys})
        except OutputHandlingError:
            raise
        except OSError as e:
            logger.error("Échec d'écriture CSV: {}", path)
            raise OutputHandlingError(f"Impossible d'écrire le fichier CSV: {path}") from e
        except Exception as e:
            logger.error("Erreur inattendue pendant l'export CSV.")
            raise OutputHandlingError(
                "Export CSV interrompu."
            ) from e
        return out.resolve()

    def to_parquet(self, path: str | Path, **pandas_kwargs: Any) -> Path:
        """
        Export Parquet (optionnel).

        Dépendances : pandas + pyarrow (extra Poetry ``parquet``, ex.
        ``pip install 'pydfirram[parquet]'``).

        Pour de très gros jeux il peut être préférable d'écrire d'abord
        :meth:`to_csv` puis de convertir hors processus ; aucune obligation d'utiliser cette méthode.

        Args:
            path: fichier ``.parquet`` cible.
            **pandas_kwargs: arguments transmis à ``DataFrame.to_parquet``.

        Returns:
            Path résolu utilisé pour l'écriture.
        """
        try:
            import pyarrow as _pa  # type: ignore[import-not-found,unused-ignore]  # noqa: F401, PLC0415
        except ImportError as e:
            raise OutputHandlingError(_PYARROW_PARQUET_HINT) from e

        dataframe = self.to_df()
        resolved = Path(path)
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            dataframe.to_parquet(resolved, **pandas_kwargs)
        except OSError as ex:
            raise OutputHandlingError(
                f"Impossible d'écrire le fichier Parquet: {path}"
            ) from ex
        return resolved.resolve()

    def to_df(self, max_row: bool = False):
        """
        Construit un DataFrame pandas (extra optionnel).

        Raises:
            OutputHandlingError: si pandas est absent ou si la conversion échoue.

        Notes:
            N'altère pas ``pandas.options`` globalement ; uniquement ``option_context``
            local pour les repr riches lorsque ``max_row`` est vrai.

        Args:
            max_row: permet d'afficher toutes les lignes/colonnes dans les représentations
                IPython/notebook via un contexte local seulement.
        """
        _pd_mod = _require_pandas()
        if RenderableDataFrame is None:  # pragma: no cover
            raise OutputHandlingError(_PANDAS_INSTALL_HINT)
        try:
            data_as_dict = self.to_list()
            dataframe = RenderableDataFrame(data_as_dict)
            dataframe._pydfirram_full_display = max_row
            return dataframe
        except OutputHandlingError:
            raise
        except Exception as e:
            logger.error("Impossible de convertir la sortie plugin en DataFrame.")
            raise OutputHandlingError(
                "Impossible de convertir la sortie plugin en tableau d'analyse."
            ) from e


__all__ = [
    "Renderer",
    "TreeGrid_to_json",
]
if RenderableDataFrame is not None:
    __all__.append("RenderableDataFrame")
