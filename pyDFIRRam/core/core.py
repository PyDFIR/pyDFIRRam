import pandas, json

from typing import Dict, Any, List, Tuple, Optional
import volatility3.symbols
from volatility3.framework import interfaces
from volatility3.cli import (
    PrintedProgress,
)
from volatility3.framework import automagic, contexts, plugins, constants

from pyDFIRRam.utils.renderer.renderer import *
from pyDFIRRam.utils.handler.handler import *


def save_file(out_dataframe, filename: str, savefile, cache_filename):
    if savefile:
        with open(filename + ".json", "w", encoding="UTF-8") as fichier:
            json.dump(out_dataframe, fichier)
    else:
        with open(filename, "w", encoding="UTF-8") as fichier:
            json.dump(out_dataframe, fichier)


def build_basic_context(
    investigation_file_path,
    base_config_path,
    plugin,
    progress=PrintedProgress(),
):
    """
    Cette fonction va permettre de set le minimum pour le profil. Faire un context simplissime
    """
    context = contexts.Context()
    avail_automagics = automagic.available(context)
    automagics = automagic.choose_automagic(avail_automagics, plugin)
    context.config[
        "automagic.LayerStacker.stackers"
    ] = automagic.stacker.choose_os_stackers(plugin)
    context.config["automagic.LayerStacker.single_location"] = (
        "file://" + investigation_file_path
    )
    try:
        if progress == PrintedProgress():
            print("plugin: ", (str(plugin).split(".")[-1])[:-2])
        constructed = plugins.construct_plugin(
            context,
            automagics,
            plugin,
            base_config_path,
            progress,
            Handler.create_file_handler(investigation_file_path),
        )
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
        failures = volatility3.framework.import_files(plugins, True)
    except:
        print("Unable to get plugins")
    return volatility3.framework.list_plugins()


def build_context_args(context, **kwargs):
    for k, v in kwargs.items():
        try:
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

## TODO: Revoir les parametres passé dans cette fonction
def run_commands(
    func_name, filename, dumpPath, format_save, all_commands, progress, savefile, **kwargs
):
    ## TODO : Faire une fonction pour set le dict de commands
    command = all_commands[func_name]["plugin"]
    plugin_list = getPlugins()
    command = {func_name: {"plugin": plugin_list[command]}}
    my_context = build_basic_context(
        investigation_file_path=dumpPath,
        base_config_path="plugins",
        plugin=command[func_name]["plugin"],
    )
    if kwargs:
        # TODO : Ici il faut que je set les kwargs pour le context
        my_context = build_context_args(my_context, **kwargs)

    retkb = runner(my_context)
    before_formating = parse_output(retkb)
    return render_outputFormat(format_save, before_formating)
