"""todo"""

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
    """Class for rendering data in a tabular format.

    It is useful for displaying data in a human-readable format.
    This can be multiple types of data, such as a pandas DataFrame, python dict, ...
    """

    def __init__(self,data) -> None:
        self.data = data

    def to_list(self) -> Dict :
        """Render the data in a tabular format."""
        try:
            formatted = TreeGrid_to_json().render(self.data)
        except Exception as e:
            logger.error("Data cannot be rendered as a Dict.")
            raise e
        return formatted

    def to_json(self) -> Any:
        return dumps(self.to_list())

    def to_dataframe(self, data: Any) -> pd.DataFrame :
        """Render the data in a tabular format."""
        try:
            formatted = pd.DataFrame(TreeGrid_to_json().render(data))
        except Exception as e:
            logger.error("Data cannot be rendered as a DataFrame.")
            raise e
        return formatted
