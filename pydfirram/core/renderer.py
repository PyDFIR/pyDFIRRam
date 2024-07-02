"""
This module provides utilities for rendering data in various formats, specifically
focusing on rendering Volatility framework data into JSON and pandas DataFrames.

Classes:
    TreeGrid_to_json: A class for rendering Volatility TreeGrid data into JSON format.
    Renderer: A class for rendering data into human-readable formats such as lists, 
              JSON strings, and pandas DataFrames.
"""

import datetime
from json import JSONEncoder,dumps,loads
from typing import Any, Tuple, List, Dict

import pandas as pd
from loguru import logger

from volatility3.framework.renderers import format_hints
from volatility3.framework import interfaces
from volatility3.cli import (
    text_renderer,
)


class TreeGrid_to_json(text_renderer.CLIRenderer):
    _type_renderers = {
        format_hints.HexBytes: lambda x: text_renderer.quoted_optional(
            text_renderer.hex_bytes_as_text
        )(x),
        interfaces.renderers.Disassembly: lambda x: text_renderer.quoted_optional(
            text_renderer.display_disassembly
        )(x),
        format_hints.MultiTypeData: lambda x: text_renderer.quoted_optional(
            text_renderer.multitypedata_as_text
        )(x),
        bytes: lambda x: text_renderer.optional(
            lambda x: " ".join([f"{b:02x}" for b in x])
        )(x),
        datetime.datetime: lambda x: x.isoformat()
        if not isinstance(x, interfaces.renderers.BaseAbsentValue)
        else None,
        "default": lambda x: x,
    }

    name = "JSON"
    structured_output = True

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        """
        Get render options.
        """
        pass

    def render(self, grid: interfaces.renderers.TreeGrid) -> Dict:
        """
        Render the TreeGrid to JSON format.

        Args:
            grid (interfaces.renderers.TreeGrid): The TreeGrid to render.

        Returns:
            Dict: The JSON representation of the TreeGrid.
        """
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])
        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            
            """
            A visitor function to process each node in the TreeGrid.

            Args:
                node (interfaces.renderers.TreeNode): The current node being visited.
                accumulator (Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]):
                    The accumulator containing the accumulated results.

            Returns:
                Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]: The updated accumulator.
            """
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}

            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
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
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)
        return final_output[1]


class Renderer:
    """
    Class for rendering data in various formats.

    This class provides methods to render data into human-readable formats such as lists,
    JSON strings, and pandas DataFrames.

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

    def to_list(self) -> Dict:
        """
        Convert the data to a list format.

        This method attempts to render the input data using the TreeGrid_to_json class,
        and convert it to a dictionary.

        Returns:
            Dict: The rendered data in list format.

        Raises:
            Exception: If rendering the data fails.
        """
        try:
            formatted = TreeGrid_to_json().render(self.data)
            return formatted
        except Exception as e:
            logger.error("Impossible to render data in dictionary form.")
            raise e

    def to_json(self) -> str:
        """
        Convert the data to a JSON string.

        This method first converts the data to a list format, and then serializes it
        to a JSON string.

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

        This method first converts the data to a list format, and then constructs
        a pandas DataFrame from it.

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
