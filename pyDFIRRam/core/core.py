from datetime import datetime
import volatility3.plugins
import volatility3.symbols
import json,pandas
from pyDFIRRam.VolatilityUtils.VolatilityUtils import *
from pyDFIRRam.windows.windows import *
from pyDFIRRam import pyDFIRRam
from volatility3.cli import (
    PrintedProgress,
    MuteProgress
)

from volatility3.framework import (
    automagic,
    contexts,
    plugins,
    constants
)
import pandas as pd
import pyarrow.parquet as pq

class core():
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

    def getPlugins() -> volatility3.framework:
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
    
    def parse_output(commands_to_execute):
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
            dump_filepath = self.dumpPath
            command = self.allCommands[funcName]["plugin"]
            plugin_list = core.getPlugins()
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
            core.save_file(self,retkb,self.cache_filename+args_added)
            return core.render_outputFormat(self,retkb)