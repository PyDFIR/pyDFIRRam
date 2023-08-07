import volatility3.symbols
from volatility3.framework.renderers import format_hints
import datetime, io, tempfile, os
from typing import Dict, Any, List, Tuple,Optional


from volatility3.cli import (
    text_renderer,
)
from volatility3.framework import interfaces

class VolatilityUtils:
    @classmethod
    def create_file_handler(cls, output_dir: Optional[str]) -> type:
        """Create a file handler class that saves files directly to disk.
        Args:
            output_dir (str): The directory where the files should be saved. If None, raises a TypeError.
        Returns:
            type: A file handler class that saves files directly to disk.
        """
        class CLIFileHandler(interfaces.plugins.FileHandlerInterface):
            """The FileHandler from Volatility3 CLI."""

            def _get_final_filename(self) -> str:
                """Gets the final filename for the saved file."""
                if output_dir is None:
                    raise TypeError("Output directory is not a string")
                os.makedirs(output_dir, exist_ok=True)
                pref_name_array = self.preferred_filename.split('.')
                filename, extension = os.path.join(output_dir, '.'.join(pref_name_array[:-1])), pref_name_array[-1]
                output_filename = f"{filename}.{extension}"
                print(f"{output_filename} and directory = {output_dir}")
                if os.path.exists(output_filename):
                    os.remove(output_filename)
                return output_filename

        class CLIDirectFileHandler(CLIFileHandler):
            """A file handler class that saves files directly to disk."""

            def __init__(self, filename: str):
                fd, temp_name = tempfile.mkstemp(suffix='.vol3', prefix='tmp_', dir=output_dir)
                self._file = io.open(fd, mode='w+b')
                CLIFileHandler.__init__(self, filename)
                for attr in dir(self._file):
                    if not attr.startswith('_') and attr not in ['closed', 'close', 'mode', 'name']:
                        setattr(self, attr, getattr(self._file, attr))
                self._name = temp_name

            def __getattr__(self, item):
                return getattr(self._file, item)

            @property
            def closed(self):
                return self._file.closed

            @property
            def mode(self):
                return self._file.mode

            @property
            def name(self):
                return self._file.name

            def close(self):
                """Closes and commits the file (by moving the temporary file to the correct name)."""
                # Don't overcommit
                if self._file.closed:
                    return
                self._file.close()
                output_filename = self._get_final_filename()
                os.rename(self._name, output_filename)

        return CLIDirectFileHandler

    class JsonRenderer(text_renderer.CLIRenderer):
        _type_renderers = {
            format_hints.HexBytes: lambda x: text_renderer.quoted_optional(text_renderer.hex_bytes_as_text)(x),
            interfaces.renderers.Disassembly: lambda x: text_renderer.quoted_optional(text_renderer.display_disassembly)(x),
            format_hints.MultiTypeData: lambda x: text_renderer.quoted_optional(text_renderer.multitypedata_as_text)(x),
            bytes: lambda x: text_renderer.optional(lambda x: " ".join([f"{b:02x}" for b in x]))(x),
            datetime.datetime : lambda x: x.isoformat() if not isinstance(x, interfaces.renderers.BaseAbsentValue) else None,
            'default': lambda x: x
        }

        name = 'JSON'
        structured_output = True

        def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
            pass

        def render(self, grid: interfaces.renderers.TreeGrid):
            final_output: Tuple[Dict[str, List[interfaces.renderers.TreeNode]], List[interfaces.renderers.TreeNode]] = (
                {}, [])

            def visitor(node: interfaces.renderers.TreeNode,accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]) -> Tuple[
                Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
                acc_map, final_tree = accumulator
                node_dict: Dict[str, Any] = {'__children': []}

                for column_index in range(len(grid.columns)):
                    column = grid.columns[column_index]
                    renderer = self._type_renderers.get(column.type, self._type_renderers['default'])
                    data = renderer(list(node.values)[column_index])
                    if isinstance(data, interfaces.renderers.BaseAbsentValue):
                        data = None
                    node_dict[column.name] = data

                if node.parent:
                    acc_map[node.parent.path]['__children'].append(node_dict)
                else:
                    final_tree.append(node_dict)
                acc_map[node.path] = node_dict
                return acc_map, final_tree

            if not grid.populated:
                grid.populate(visitor, final_output)
            else:
                grid.visit(node=None, function=visitor, initial_accumulator=final_output)
            return final_output[1]