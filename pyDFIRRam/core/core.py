import pandas,json
import pyarrow.parquet as pq

from typing import Dict, Any, List, Tuple,Optional
import volatility3.symbols
from volatility3.framework import interfaces
from volatility3.cli import (
    PrintedProgress,

)
from volatility3.framework import (
    automagic,
    contexts,
    plugins,
    constants
)
from pyDFIRRam.utils.renderer.renderer import *
from pyDFIRRam.utils.handler.handler import *

def save_file(out_dataframe,filename:str,savefile,cache_filename):
    if savefile:
        with open(filename+".json", 'w',encoding="UTF-8") as fichier:
            json.dump(out_dataframe, fichier)
    else:
        with open(filename, 'w',encoding="UTF-8") as fichier:
            json.dump(out_dataframe,fichier)

def in_cache( funcName,cache_filename):
    """
    Check if there is cached content for a specific function.
    This method reads the cached content from a file and returns the content
    in the appropriate output format.
    :param funcName: The name of the function to check for cached content.
    :type funcName: str
    :return: The cached content in the specified output format.
    :rtype: Depends on the format specified.
    """
    parquet_filename = cache_filename(funcName) + ".parquet"
    table = pq.read_table(parquet_filename)
    content = table.to_pandas()
    return render_outputFormat(content)

def build_context(investigation_file_path:str, plugin, context, base_config_path,allCommands,progress,args=None):
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
            plugged = allCommands[frind]["plugin"] +"."+ str(k)
            print(int(v))
            try :
                print(plugged)
                context.config[plugged] = v
            except Exception as exxx:
                print(exxx)
    try:
        if progress == PrintedProgress():
            print("plugin: ", (str(plugin).split(".")[-1])[:-2])
        constructed = plugins.construct_plugin(context,automagics,plugin,base_config_path,progress,Handler.create_file_handler(investigation_file_path))
        if progress == PrintedProgress():
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
                result = JsonRenderer().render(command_entry['constructed'].run())
                command_entry['result'] = result
            except Exception as e:
                print(f"Error in run: {e}")
    return commands_to_execute
def runner(dump_filepath,base_config_path,kb,AllCommands,progress,context,args=None):
    for runable in kb:
        if args is not None:
            kb[runable]['constructed'] = build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path,AllCommands,progress=progress,args=args)
        else:
            kb[runable]['constructed'] = build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path,AllCommands,progress=progress)
    for runable in kb:
        if kb[runable]['constructed']:
            try:
                kb[runable]['result'] = kb[runable]['constructed'].run()
                return kb
            except Exception as exceptionHandler:
                print("error in run\n Expception:",exceptionHandler)
                pass

def parameters_context():
    pass        
def run_commands(funcName,filename,dumpPath,format,allCommands,progress,savefile,**kwargs):
    cache_filename = filename
    args_added = ""
    #Variable Args de debug
    args =None
    #Prendre en charge les kwargs pour les fonctions, mettre ensuite des definitions pour ces arguments
    # Pour ca il faut se referer a la docs pour savoir ce que nous pouvons prendre comme argument pour chaque fonction
    print(allCommands[funcName]["param"].keys())
    if kwargs:
        try:
            allPossibleArgs = set(allCommands[funcName]["param"].keys())
            kw = set(kwargs.keys())
            if kw.issubset(allPossibleArgs):
                value_key= list(kw)[0]
                value_kw = kwargs.get(value_key)
                value = allCommands[funcName]["param"][value_key]
                context = contexts.Context()
            else:
                print("Les arguments demandee sont:",allCommands[funcName]["param"])
        except Exception as e:
            print("Aucune de parametres n'est pris en charge par cette fonctions. Les parametres sont les suivantes",allPossibleArgs)
    try:
        context.config[allCommands[funcName]["param"][value_key]] = value_kw
    except:
        print("error")
    exit(1)
    context = contexts.Context()
    args_added = ""
    # Ici a voir pour passer en parametre
    dump_filepath = dumpPath
    command = allCommands[funcName]["plugin"]
    plugin_list = getPlugins()
    command = {
        funcName:{
            'plugin':plugin_list[command]
            }
        }
    if not args :
        kb = runner(dump_filepath,"plugins",command,allCommands,progress,context)
        retkb = parse_output(kb)
    else:
        kb =runner(dump_filepath,"plugins",command,args=args)
        retkb = parse_output(kb)
        for artifact in retkb:
            artifact = {x.translate({32: None}): y for x, y in artifact.items()}
    retkb = retkb[funcName]['result']
    #save_file(retkb,cache_filename+args_added,savefile,cache_filename)
    if funcName == "PsTree":
        format = "json"
        return json_to_graph(retkb)
    else:
        return render_outputFormat(format,retkb)
    
