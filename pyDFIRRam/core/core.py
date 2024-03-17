import pandas,json

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

def in_cache(func_name, cache_filename):
    """
    Check if there is cached content for a specific function.
    This method reads the cached content from a file and returns the content
    in the appropriate output format.
    :param func_name: The name of the function to check for cached content.
    :type func_name: str
    :param cache_filename: The filename for caching.
    :type cache_filename: str
    :return: The cached content in the specified output format.
    :rtype: Depends on the format specified.
    """
    target_filename = cache_filename + func_name + ".json" 
    with open(target_filename, 'r') as file:
        content = pandas.read_json(file)
    return render_output_format(content) 


def build_basic_context(investigation_file_path,base_config_path,plugin,progress=PrintedProgress(),parallelism=False):
    """
        Cette fonction va permettre de set le minimum pour le profil. Faire un context simplissime
    """
    context = contexts.Context()
    avail_automagics = automagic.available(context)
    automagics = automagic.choose_automagic(avail_automagics,plugin)
    context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
    context.config['automagic.LayerStacker.single_location'] ="file://" +  investigation_file_path
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



def build_context_args(context,**kwargs):
    for k,v in kwargs.items():
        try :
            context.config[k] = v
        except Exception as exxx:
                print(exxx)
    return context



def runner(context):
    try:
        ## TODO : Ici ce n'est pas le context que je run mais la partie constructed qui ressort du context
        return context.run()
    except Exception as e:
        print(e)
        ...

def run_commands(func_name,filename,dumpPath,format,all_commands,progress,savefile,**kwargs):
    
    ## TODO : Faire une fonction pour set le dict de commands
    command = all_commands[func_name]["plugin"]
    plugin_list = getPlugins()
    command = {
        func_name:{
            'plugin':plugin_list[command]
            }
        }
    my_context = build_basic_context(investigation_file_path=dumpPath,base_config_path="plugins", plugin=command[func_name]["plugin"], parallelism=False)
    if kwargs:
        #TODO : Ici il faut que je set les kwargs pour le context
        my_context = build_context_args(my_context,**kwargs)

    retkb = runner(my_context)
    before_formating = parse_output(retkb)
    return render_outputFormat(format,before_formating)
    
