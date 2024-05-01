import datetime, pandas
from graphviz import Digraph
from typing import Dict, Any, List, Tuple, Optional
import volatility3.symbols
from volatility3.framework.renderers import format_hints
from volatility3.framework import interfaces
from volatility3.cli import (
    text_renderer,
)


class JsonRenderer(text_renderer.CLIRenderer):
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
        pass

    def render(self, grid: interfaces.renderers.TreeGrid):
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
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


def parse_output(context):
    """
    Parse the output of executed commands.

    This method takes a dictionary of commands to execute, runs each constructed command,
    and renders the results as JSON. The results are stored back in the dictionary.

    :param commands_to_execute: A dictionary of commands to execute.
    :type commands_to_execute: dict
    :return: The updated dictionary with command results.
    :rtype: dict
    """
    return JsonRenderer().render(context)


def render_outputFormat(format_data, jsondata: dict):
    if format_data == "dataframe":
        try:
            return pandas.DataFrame(jsondata)
        except:
            print("Can't transform data to dataframe")
            return jsondata
    elif format_data == "json":
        return jsondata


def json_to_graph(res: list, graph=None, node_parent=None) -> Digraph:
    if graph is None:
        graph = Digraph()
    for parent in res:
        graph.node(str(parent["PID"]), label=parent["ImageFileName"])
        if node_parent is not None:
            graph.edge(str(node_parent["PID"]), str(parent["PID"]), label="SubProcess")
        for node in parent["__children"]:
            graph.node(str(node["PID"]), label=node["ImageFileName"])
            graph.edge(str(parent["PID"]), str(node["PID"]), label="SubProcess")
            if "__children" in node:
                json_to_graph(node["__children"], graph, node)
    return graph

    def __rename_pstree(self, node: dict) -> None:
        """
        Rename the nodes in the Tree provided.

        This method recursively renames the nodes in the provided tree by renaming
        the 'ImagefuncName' key to 'name' and '__children' key to 'children'.

        :param node: The node in the tree to be renamed.
        :type node: dict
        :return: None
        """
        if len(node["__children"]) == 0:
            node["children"] = node["__children"]
            node["name"] = node["ImagefuncName"]
            del node["__children"]
            del node["ImagefuncName"]
        else:
            node["children"] = node["__children"]
            node["name"] = node["ImagefuncName"]
            del node["__children"]
            del node["ImagefuncName"]
            for children in node["children"]:
                self.__rename_pstree(children)
