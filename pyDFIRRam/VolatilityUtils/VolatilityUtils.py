import pandas
import pyarrow.parquet as pq
import datetime, io, tempfile, os,json
from typing import Dict, Any, List, Tuple,Optional
import volatility3.symbols
from volatility3.framework.renderers import format_hints
from volatility3.framework import interfaces
from volatility3.cli import (
    PrintedProgress,
    MuteProgress,
    text_renderer,
)
from volatility3.framework import (
    automagic,
    contexts,
    plugins,
    constants
)



class VolatilityUtils:
    "Ci dessous renomme en class Handler"
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
    # Class in renderer
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
        #### Class in renderer
    class core :
        def save_file(self,out_dataframe,filename:str):
            if self.savefile:
                print(self.filename)
                with open(self.filename+".json", 'w',encoding="UTF-8") as fichier:
                    json.dump(out_dataframe, fichier)
            else:
                with open(filename, 'w',encoding="UTF-8") as fichier:
                    json.dump(out_dataframe,fichier)

        def in_cache(self, funcName):
            """
            Check if there is cached content for a specific function.

            This method reads the cached content from a file and returns the content
            in the appropriate output format.

            :param funcName: The name of the function to check for cached content.
            :type funcName: str
            :return: The cached content in the specified output format.
            :rtype: Depends on the format specified.
            """
            parquet_filename = self.cache_filename(funcName) + ".parquet"
            table = pq.read_table(parquet_filename)
            content = table.to_pandas()
            return self.render_outputFormat(content)


        def render_outputFormat(self,jsondata:dict):
            print("my format " +self.format)
            if self.format=="dataframe":
                    try:
                        print("To dataframe")
                        return pandas.DataFrame(jsondata)
                    except:
                        print("Can't transform data to dataframe")
                        return jsondata
            elif self.format == "json":
                return jsondata

        def build_context(self,investigation_file_path:str, plugin, context, base_config_path,args=None):
            """
            Build the context for running a plugin.
            This method constructs the context for running a plugin by setting various configuration options.
            It also uses automagic functionality and constructs the plugin using the specified arguments.
            :param investigation_file_path: Path to the investigation file.
            :type investigation_file_path: str
            :param plugin: The plugin to be run.
            :param context: The context to be used.
            :param base_config_path: Path to the base configuration file.
            :param args: Arguments for the plugin, defaults to None.
            :type args: dict, optional
            :return: The constructed plugin context.
            """
            avail_automagics = automagic.available(context)
            automagics = automagic.choose_automagic(avail_automagics,plugin)
            context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
            context.config['automagic.LayerStacker.single_location'] ="file://" +  investigation_file_path
            if args is not None:
                frind = (str(plugin).split(".")[-1])[:-2]
                for k,v in args.items():
                    plugged = self.allCommands[frind]["plugin"] +"."+ str(k)
                    print(int(v))
                    try :
                        print(plugged)
                        context.config[plugged] = v
                    except Exception as exxx:
                        print(exxx)
            try:
                if self.progress == PrintedProgress():
                    print("plugin: ", (str(plugin).split(".")[-1])[:-2])
                constructed = plugins.construct_plugin(context,automagics,plugin,base_config_path,self.progress,VolatilityUtils.create_file_handler(investigation_file_path))
                if self.progress == PrintedProgress():
                    print("")
            except Exception as e:
                print(e)
            return constructed

        def getPlugins(self) -> volatility3.framework:
            """
            Get the list of available plugins.

            This method imports the plugins and retrieves the list of available plugins.

            :return: The list of available plugins.
            :rtype: list
            """
            try:
                failures = volatility3.framework.import_files(plugins,True)
            except:
                print("Unable to get plugins")
            return volatility3.framework.list_plugins()

        def parse_output(self,commands_to_execute):
            """
            Parse the output of executed commands.

            This method takes a dictionary of commands to execute, runs each constructed command,
            and renders the results as JSON. The results are stored back in the dictionary.

            :param commands_to_execute: A dictionary of commands to execute.
            :type commands_to_execute: dict
            :return: The updated dictionary with command results.
            :rtype: dict
            """
            for runnable, command_entry in commands_to_execute.items():
                if command_entry['constructed']:
                    try:
                        result = VolatilityUtils.JsonRenderer().render(command_entry['constructed'].run())
                        command_entry['result'] = result
                    except Exception as e:
                        print(f"Error in run: {e}")
            return commands_to_execute

        def runner(self,dump_filepath,base_config_path,kb,args=None):
            for runable in kb:
                if args is not None:
                    context = contexts.Context()
                    kb[runable]['constructed'] = self.build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path,args=args)
                else:
                    context = contexts.Context()
                    kb[runable]['constructed'] = self.build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path)

            for runable in kb:
                if kb[runable]['constructed']:
                    try:
                        kb[runable]['result'] = kb[runable]['constructed'].run()
                        return kb
                    except Exception as exceptionHandler:
                        print("error in run\n Expception:",exceptionHandler)
                        pass
                    
        def run_commands(self,funcName,filename,args:list=None):
            self.cache_filename = filename
            args_added = ""
            if args:
                for k,v in args.items():
                    args_added += str(k) +str(v)
            else:
                args_added = ""

                # Ici a voir pour passer en parametre
                dump_filepath = self.dumpPath
                command = self.allCommands[funcName]["plugin"]

                plugin_list = self.getPlugins()
                command = {
                    funcName:{
                        'plugin':plugin_list[command]
                        }
                    }
                if not args :
                    kb = self.runner(dump_filepath,"plugins",command)
                    retkb = self.parse_output(kb)
                else:
                    kb =self.runner(dump_filepath,"plugins",command,args=args)
                    retkb = self.parse_output(kb)
                    for artifact in retkb:
                        artifact = {x.translate({32: None}): y for x, y in artifact.items()}

                retkb = retkb[funcName]['result']
                self.save_file(self,retkb,self.cache_filename+args_added)
                return self.render_outputFormat(self,retkb)