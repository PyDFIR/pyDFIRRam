"""
This module provides utilities for rendering data in various formats,
specifically focusing on rendering Volatility framework data into JSON and
pandas DataFrames.

Classes:
    TreeGrid_to_json: A class for rendering Volatility TreeGrid data into
                JSON format.
    Renderer: A class for rendering data into human-readable formats such
                as lists, JSON strings, and pandas DataFrames.
"""

import datetime
from json import dumps
from typing import Any

import pandas as pd
from loguru import logger
from volatility3.framework.interfaces.renderers import (  # type: ignore
    Disassembly             as V3Disassembly,
    BaseAbsentValue         as V3BaseAbsentValue,
    RenderOption            as V3RenderOption,
    TreeGrid                as V3TreeGrid,
    TreeNode                as V3TreeNode,
)
from volatility3.framework.renderers.format_hints import (  # type: ignore
    HexBytes                as V3HexBytes,
    MultiTypeData           as V3MultiTypeData,
)
from volatility3.cli.text_renderer import (                 # type: ignore
    CLIRenderer             as V3CLIRenderer,
    optional                as v3_optional,
    quoted_optional         as v3_quoted_optional,
    hex_bytes_as_text       as v3_hex_bytes_as_text,
    display_disassembly     as v3_display_disassembly,
    multitypedata_as_text   as v3_multitypedata_as_text,
)


# allow no PascalCase naming style and "lambda may not be necessary"
# pylint: disable=W0108,C0103
# (todo) : switch to PascalCase

class TreeGrid_to_json(V3CLIRenderer):      # type: ignore
    """ simple TreeGrid to JSON
    """
    _type_renderers: Any = {
        V3HexBytes: lambda x: v3_quoted_optional(
            v3_hex_bytes_as_text,
        )(x),
        V3Disassembly: lambda x: v3_quoted_optional(
            v3_display_disassembly,
        )(x),
        V3MultiTypeData: lambda x: v3_quoted_optional(
            v3_multitypedata_as_text,
        )(x),
        bytes: lambda x: v3_optional(
            lambda x: " ".join([f"{b:02x}" for b in x])
        )(x),
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

    # (fixme) : this methods should return nothing as defined in V3CLIRenderer
    def render(self, grid: V3TreeGrid) -> list[V3TreeNode]:
        """
        Render the TreeGrid to JSON format.

        Args:
            grid (interfaces.renderers.TreeGrid): The TreeGrid to render.

        Returns:
            Dict: The JSON representation of the TreeGrid.
        """
        final_output: tuple[
            dict[str, list[V3TreeNode]],
            list[V3TreeNode],
        ] = ({}, [])


        def visitor(
            node: V3TreeNode,
            accumulator: tuple[dict[str,Any], list[dict[str,Any]]],
        ) -> tuple[dict[str,Any], list[dict[str,Any]]]:
            """
            A visitor function to process each node in the TreeGrid.

            Args:
                node (V3TreeNode): The current node being visited.
                accumulator (Tuple[Dict[str, Any], List[Dict[str, Any]]]):
                    The accumulator containing the accumulated results.

            Returns:
                Tuple[Dict[str,Any], List[Dict[str, Any]]]: The updated
                    accumulator.
            """
            acc_map = accumulator[0]
            final_tree = accumulator[1]
            node_dict: dict[str, Any] = {"__children": []}

            for column_index, column in enumerate(grid.columns):
                renderer = self._type_renderers.get(
                    key     = column.type,
                    default = self._type_renderers["default"],
                )
                data = renderer(
                    list(node.values)[column_index],
                )
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
                node                = None,
                function            = visitor,
                initial_accumulator = final_output,
            )
        return final_output[1]


class Renderer():
    """
    Class for rendering data in various formats.

    This class provides methods to render data into human-readable formats
    such as lists, JSON strings, and pandas DataFrames.

    Attributes:
        data (Any): The input data to be rendered.
    """

    def __init__(self, data: Any) -> None:
        """
        Initialize the Renderer with the provided data.

        Args:
            data (Any): The input data to be rendered.
        """
        self.data = data

    def to_list(self) -> dict[str,Any]:
        """
        Convert the data to a list format.

        This method attempts to render the input data using the
        TreeGrid_to_json class, and convert it to a dictionary.

        Returns:
            Dict: The rendered data in list format.

        Raises:
            Exception: If rendering the data fails.
        """
        try:
            # (fixme) : `render()` should return nothing
            return TreeGrid_to_json().render(self.data)
        except Exception as e:
            logger.error("Impossible to render data in dictionary form.")
            raise e

    def file_render(self)-> None:
        """
        Convert the data to a list format.

        This method attempts to render the input data using the
        TreeGrid_to_json class, and convert it to a dictionary.

        Returns:
            Dict: The rendered data in list format.

        Raises:
            Exception: If rendering the data fails.
        """
        try:
            # (fixme) : `render()` return nothing
            TreeGrid_to_json().render(self.data)
        except Exception as e:
            logger.error("Impossible to render data in dictionary form.")
            raise e

    def to_json(self) -> str:
        """
        Convert the data to a JSON string.

        This method first converts the data to a list format, and then
        serializes it to a JSON string.

        Returns:
            str: The data serialized as a JSON string.

        Raises:
            Exception: If converting the data to JSON fails.
        """
        try:
            data_as_dict = self.to_list()
            return dumps(data_as_dict)
        except Exception as e:
            logger.error("Unable to convert data to JSON.")
            raise e

    def to_df(self,max_row: bool = False) -> pd.DataFrame:
        """
        Convert the data to a pandas DataFrame.

        This method first converts the data to a list format, and then
        constructs a pandas DataFrame from it.

        Returns:
            pd.DataFrame: The data as a pandas DataFrame.

        Raises:
            Exception: If rendering the data as a DataFrame fails.
        """
        try:
            data_as_dict = self.to_list()
            if max_row:
                pd.set_option('display.max_rows', None)
                pd.set_option('display.max_columns', None)
            return pd.DataFrame(data_as_dict)
        except Exception as e:
            logger.error("Data cannot be rendered as a DataFrame.")
            raise e
