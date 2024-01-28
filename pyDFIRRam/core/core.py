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

def in_cache( func_name,cache_filename):
    """
    Check if there is cached content for a specific function.
    This method reads the cached content from a file and returns the content
    in the appropriate output format.
    :param func_name: The name of the function to check for cached content.
    :type func_name: str
    :return: The cached content in the specified output format.
    :rtype: Depends on the format specified.
    """
    parquet_filename = cache_filename(func_name) + ".parquet"
    table = pq.read_table(parquet_filename)
    content = table.to_pandas()
    return render_outputFormat(content)

def build_basic_context(investigation_file_path,plugin,progress):
    context = contexts.Context()
    avail_automagics = automagic.available(context)
    automagics = automagic.choose_automagic(avail_automagics,plugin)
    context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
    context.config['automagic.LayerStacker.single_location'] ="file://" +  investigation_file_path
    try:
        if progress == PrintedProgress():
            print("plugin: ", (str(plugin).split(".")[-1])[:-2])
        constructed = plugins.construct_plugin(context,automagics,plugin,"plugins",progress,Handler.create_file_handler(investigation_file_path))
        if progress == PrintedProgress():
            print("")
        
        return constructed
    except Exception as e:
        print(e)

def build_context(investigation_file_path:str, plugin, context, base_config_path,all_commands,progress,args=None):
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
    ### Ci-dessous, a quoi ca sert ????????????????????????????????
    if args is not None:
        frind = (str(plugin).split(".")[-1])[:-2]
        for k,v in args.items():
            plugged = all_commands[frind]["plugin"] +"."+ str(k)
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
        return constructed
    except Exception as e:
        print(e)

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


    ### ICI ca ne parse pas uniquement l'output mais ca rerun tout. Mauvaise Optimisation !!!!
    print(commands_to_execute)
    for runnable, command_entry in commands_to_execute.items():
        if command_entry['constructed']:
            try:
                result = JsonRenderer().render(command_entry['constructed'].run())
                command_entry['result'] = result
            except Exception as e:
                print(f"Error in run: {e}")
    return commands_to_execute

def construct_plugins(dump_filepath,base_config_path,kb, all_commands,progress,context,**kwargs) -> dict:

    if kwargs :
        ...
    ## TODO : Il faut que je reprennent ici la gestion des kwargs plutot que de passer en parametre plus tard
    for runable in kb:
        ## ICI il faut que je fasse la gestiion de mes kwargs et que je build contxt
        kb[runable]['constructed'] = build_context(dump_filepath,kb[runable]['plugin'],base_config_path,all_commands,progress=progress)
    return kb

def runner(context):
    try:
        return context.run()
    except Exception as e:
        print(e)
        ...

def parameters_context(key,**kwargs):
    print(key,set(kwargs.keys()))

def run_commands(func_name,filename,dumpPath,format,all_commands,progress,savefile,**kwargs):
    
    ## TODO : Faire une fonction pour set le dict de commands
    dump_filepath = dumpPath
    command = all_commands[func_name]["plugin"]
    plugin_list = getPlugins()
    command = {
        func_name:{
            'plugin':plugin_list[command]
            }
        }
    my_context = build_basic_context(dump_filepath,"plugins")
    print(my_context)
    exit(1)
    context = construct_plugins(dump_filepath,"plugins",command,all_commands,progress)
    
    ## TODO : Ameliorer et microsegmenter la gestion des erreurs/fonctions
    if kwargs:
        try:
            all_possible_args = set(all_commands[func_name]["param"].keys())
            provided_args = set(kwargs.keys())
            if provided_args.issubset(all_possible_args):
                value_key = list(provided_args)[0]
                value_kw = kwargs.get(value_key)
                try:
                    ### TODO : Complexité algormithmique trop eleve e^e^x (donc trop lent)
                    for arg in provided_args:
                        print(arg)
                        context.config[all_commands[func_name]["param"][arg]] = value_kw
                    retkb = parse_output(runner(command,func_name))
                    for artifact in retkb:
                        artifact = {x.translate({32: None}): y for x, y in artifact.items()}
                except Exception as e:
                    print(f"Erreur lors de la configuration des arguments dans le contexte, les paramètres nécessaires sont : {all_possible_args}")
            else:
                print(f"Les arguments demandés sont : {all_possible_args}")
        except Exception as e:
            print(f"Aucun des paramètres n'est pris en charge par cette fonction. Les paramètres sont les suivants : {all_possible_args}")
    else:
    # Ici a voir pour passer en parametre
        kb = runner(commands=command, context=context)
        retkb = parse_output(kb)
    
    retkb = retkb[func_name]['result']
    #save_file(retkb,cache_filename+args_added,savefile,cache_filename)
    if func_name == "PsTree":
        format = "json"
        return json_to_graph(retkb)
    else:
        return render_outputFormat(format,retkb)
    
