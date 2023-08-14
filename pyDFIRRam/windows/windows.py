from datetime import datetime
import volatility3.plugins
import volatility3.symbols
import json,pandas,csv,pathlib
from pyDFIRRam.VolatilityUtils.VolatilityUtils import *
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

class windows(pyDFIRRam):
    def __init__(self,InvestFile,savefile:bool = False,Outputformat:str ="json",
                                filename:str ="defaultname",showConfig=False,outpath:str = os.getcwd(), progress:bool=False) -> None:
        """
        Initialize an instance of MyClass.

        :param InvestFile: Path to the investment file.
        :type InvestFile: str
        :param savefile: Flag to indicate whether to save the output to a file, defaults to False.
        :type savefile: bool
        :param Outputformat: Output format for saving data (json, dataframe), defaults to "json".
        :type Outputformat: str
        :param filename: Name of the output file, defaults to "defaultname".
        :type filename: str
        :param showConfig: Flag to display configuration details, defaults to False.
        :type showConfig: bool
        :param outpath: Path to the output directory, defaults to the current working directory.
        :type outpath: str
        :param progress: Flag to show progress, defaults to False.
        :type progress: bool
        :raises Exception: If there is an error during initialization.
        """
        try:
            os.path.isfile(InvestFile)
            self.cmds = [
                "PsList",
                "HiveList",
                "Crashinfo", # Verifier qu'il s'agit bien d'un crashDump
                "Envars",
                "VerInfo",
                "MutantScan",
                "BigPools",# Prends des arguments {tags, show-free}
                "HiveScan",
                "getSids",# Prends des arguments {pid}
                "VADinfo",# Prends des arguments {address, pid, dump,maxsize}
                "skeleton_key_check",
                "Sessions",# Prends des arguments {pid}
                "Strings",# Prends des arguments {pid, string-file}
                "GetSetviceSids",
                "WindowsInfo",
                "DllList",# Prends des arguments {pid, dump}
                "NetScan",# Prends des arguments {include-corrupt}
                "NetStat",# Prends des arguments {include-corrupt}
                "PoolScanner",
                "SSDT",
                "LsaDump",#idk
                "ModScan",# Prends des arguments {dump}
                "SymLinkScan",
                "PsScan",# Prends des arguments {physical, pid, dump}
                "PsTree",# Prends des arguments {physical, pid}
                "MBRScan",# Prends des arguments {full}
                "DumpFiles",# Prends des arguments {physaddr, virtaddr, pid}
                "VirtMap",
                "CmdLine",# Prends des arguments {pid}
                "LdrModules",# Prends des arguments {pid}
                "CacheDump",
                "FileScan",
                "Handles",# Prends des arguments {pid}
                "VadInfo",# Prends des arguments {address, pid, dump,maxsize}
                "DriverScan",
                "DeviceTree",
                "YaraScan",#idk
                "VadYaraScan",#idk
                "SvcScan",#idk
                "HashDump",
                "DriverIrp",
                "CallBacks",
                "Modules",
                "Malfind",
                "mftscan",
                "Memmap",
                "Privs",
                "UserAssist",
                "Hivescan",
                "PrintKey"
            ]
            self.filename = filename
            Outformat = Outputformat.lower()
            self.choice = [
                "json",
                "dataframe"
                ]
            self.savefile = savefile
            self.filename = filename
            self.dumpPath = InvestFile
            self.formatSave = "json"
            self.outpath = outpath +"/"
            if Outformat in self.choice:
                self.format = Outformat
            self.showconf = showConfig
            if Outformat in self.choice:
                self.format = Outformat
            else:
                print(f"{Outformat} non pris en charge. Les formats pris en charge sont :\n\t-xlsx\n\t-csv\n\t-json\n\t-parquet")
            if showConfig:
                self.__print_config()
            self.allCommands = self.__getFileContent(str(pathlib.Path(__file__).parent) + '/findCommands.json')
            self.temp, self.plateform = self.__definePlatforms()
            if progress:
                self.progress = PrintedProgress()
            else:
                self.progress = MuteProgress()
            self.infofn = ""
        except Exception as e:
            print(e)
        
    def __print_config(self):
        """
        Print the current configuration settings.

        This method prints the current configuration settings of the instance.

        :return: None
        """
        print(f"""
######################### Config #########################
Save file = {self.savefile}                             
format = {self.format}                                   
##########################################################""")
    
    
    def __definePlatforms(self)-> tuple:
        """
        Define platform-specific settings.

        This method determines the appropriate temporary directory path and platform name
        based on the operating system.

        :return: A tuple containing the temporary directory path and the platform name.
        :rtype: tuple[str, str]
        :raises Exception: If the operating system is not recognized.
        """
        varTempOS = os.name
        if varTempOS == 'nt':
            return "ici mettre le path du temp sous windows","windows"
        elif varTempOS == 'darwin':
            return "/tmp/","mac"
        elif varTempOS == 'posix':
            return "/tmp/","linux"
        else:
            raise Exception()

    
    def __getFileContent(self,filename) -> dict:
        """
        Get the content of a JSON file and return it as a dictionary.

        This method reads the content of a JSON file and parses it into a dictionary.

        :param filename: Path to the JSON file.
        :type filename: str
        :return: A dictionary containing the parsed JSON data.
        :rtype: dict
        """
        with open(filename,'r',encoding="UTF-8") as fichier:
            content = fichier.read()
        return json.loads(content)

    def __getattr__(self, key,*args,**kwargs):
        """
        Handle attribute access for commands.

        This method is called when an attribute that matches a command name is accessed.
        It returns a lambda function that calls the __run_commands method with the corresponding key.

        :param key: The attribute name (command name).
        :type key: str
        :param args: Positional arguments for the method call.
        :param kwargs: Keyword arguments for the method call.
        :return: A lambda function that executes the __run_commands method for the given key.
        """
        if key in self.cmds:
            return lambda : self.__run_commands(key)
        else:
            pass
    
    def __in_cache(self, funcName):
        """
        Check if there is cached content for a specific function.
    
        This method reads the cached content from a file and returns the content
        in the appropriate output format.
    
        :param funcName: The name of the function to check for cached content.
        :type funcName: str
        :return: The cached content in the specified output format.
        :rtype: Depends on the format specified.
        """
        parquet_filename = self.__cache_filename(funcName) + ".parquet"
        table = pq.read_table(parquet_filename)
        content = table.to_pandas()
        return self.__render_outputFormat(content)

    def __cache_filename(self,func):
        """
        Generate a cache filename based on function name and system information.

        This method generates a cache filename using the function name, system information,
        and a timestamp. The filename is used for storing cached content.

        :param func: The name of the function.
        :type func: str
        :return: The generated cache filename.
        :rtype: str
        """
        self.progress = MuteProgress()
        p = self.Info()
        self.progress = PrintedProgress()
        productSys = p["NtProductType"]
        dateOnSys = datetime.datetime.strptime(p["SystemTime"], "%Y-%m-%d %H:%M:%S")
        timestamp = str(int(dateOnSys.timestamp())) 
        filename = "/tmp/"+productSys+timestamp+func+".json"
        return filename

    def __save_file(self,out_dataframe,filename:str):
        if self.savefile:
            print(self.filename)
            with open(self.filename+".json", 'w',encoding="UTF-8") as fichier:
                json.dump(out_dataframe, fichier)
        else:
            with open(filename, 'w',encoding="UTF-8") as fichier:
                json.dump(out_dataframe,fichier)


    def __render_outputFormat(self,jsondata:dict):
        """
        Render JSON data in the specified output format.

        This method takes JSON data and renders it into the desired output format,
        which can be either "dataframe" or "json".

        :param jsondata: The JSON data to be rendered.
        :type jsondata: dict
        :return: The rendered data in the specified output format.
        :rtype: pandas.DataFrame or dict
        """
        if self.format=="dataframe":
            try:
                print("To dataframe")
                return pandas.DataFrame(jsondata)
            except:
                print("Can't transform data to dataframe")
                return jsondata
        elif self.format == "json":
            return jsondata

    def __rename_pstree(self,node:dict) -> None:
        """
        Rename the nodes in the Tree provided.

        This method recursively renames the nodes in the provided tree by renaming 
        the 'ImageFileName' key to 'name' and '__children' key to 'children'.

        :param node: The node in the tree to be renamed.
        :type node: dict
        :return: None
        """
        if len(node['__children']) == 0:
            node['children'] = node['__children']
            node['name'] = node['ImageFileName']
            del (node['__children'])
            del (node['ImageFileName'])
        else:
            node['children'] = node['__children']
            node['name'] = node['ImageFileName']
            del (node['__children'])
            del (node['ImageFileName'])
            for children in node['children']:
                self.__rename_pstree(children)
    def __build_context(self,investigation_file_path:str, plugin, context, base_config_path,args=None):
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

    def __getPlugins(self) -> volatility3.framework:
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
    
    def __parse_output(self,commands_to_execute):
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
    
    def __runner(self,dump_filepath,base_config_path,kb,args=None):
        for runable in kb:
            if args is not None:
                context = contexts.Context()
                kb[runable]['constructed'] = self.__build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path,args=args)
            else:
                context = contexts.Context()
                kb[runable]['constructed'] = self.__build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path)
        
        for runable in kb:
            if kb[runable]['constructed']:
                try:
                    kb[runable]['result'] = kb[runable]['constructed'].run()
                    return kb
                except Exception as exceptionHandler:
                    print("error in run\n Expception:",exceptionHandler)
                    pass
    
    def __run_commands(self,funcName,args:list = None):
        args_added = ""
        if args:
            for k,v in args.items():
                args_added += str(k) +str(v)
        if os.path.isfile(self.__cache_filename(funcName+args_added)):
            return self.__in_cache(funcName+args_added)
        else:
            dump_filepath = self.dumpPath
            command = self.allCommands[funcName]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                funcName:{
                    'plugin':plugin_list[command]
                    }
                }
            if not args :
                kb = self.__runner(dump_filepath,"plugins",command)
                retkb = self.__parse_output(kb)
            else:
                kb =self.__runner(dump_filepath,"plugins",command,args=args)
                retkb = self.__parse_output(kb)
                for artifact in retkb:
                    artifact = {x.translate({32: None}): y for x, y in artifact.items()}
            
            retkb = retkb[funcName]['result']
            self.__save_file(retkb,self.__cache_filename(funcName+args_added))
            return self.__render_outputFormat(retkb)

    def build_contextDump(self,dump_path, context, base_config_path:str, plugin:str, output_path:str):
        avail_automagics = automagic.available(context)
        automagics = automagic.choose_automagic(avail_automagics, plugin)
        context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
        context.config['automagic.LayerStacker.single_location'] = f"file://{dump_path}"
        constructed = plugins.construct_plugin(context, automagics, plugin, base_config_path,
                                               MuteProgress(), VolatilityUtils.create_file_handler(output_path))
        return constructed

    def DumpFiles(self, offset: list):
        data = []
        output_path = self.outpath
        offset_copy = offset.copy()
        for e in offset:
            for fn in os.listdir(output_path):
                if f"file.{hex(e)}" in fn:
                    if e in offset_copy:
                        offset_copy.remove(e)

        if offset_copy:
            for e in offset_copy:
                volatility3.framework.require_interface_version(2, 0, 0)
                output_path = self.outpath
                failures = volatility3.framework.import_files(plugins, True)
                plugin_list = volatility3.framework.list_plugins()
                base_config_path = "plugins"
                context = contexts.Context()
                context.config['plugins.DumpFiles.virtaddr'] = int(e)
                command = self.allCommands["DumpFiles"]["plugin"]
                plugin_list = self.__getPlugins()
                command = {
                    'DumpFiles': {
                        'plugin': plugin_list[command]
                    }
                }
                plugin_list = volatility3.framework.list_plugins()
                try:
                    constructed = self.build_contextDump(self.dumpPath, context, base_config_path,command["DumpFiles"]["plugin"], output_path)
                except Exception as e:
                    print(e)
                if constructed:
                    result = VolatilityUtils.JsonRenderer().render(constructed.run())
                    if len(result) < 1:
                        del context.config['plugins.DumpFiles.virtaddr']
                        context.config['plugins.DumpFiles.physaddr'] = int(e)
                        constructed = self.build_contextDump(self.dumpPath, context, base_config_path,
                                                    plugin_list['windows.dumpfiles.DumpFiles'], output_path)
                        result = VolatilityUtils.JsonRenderer().render(constructed.run())
                for artifact in result:
                    artifact = {x.translate({32: None}): y for x, y in artifact.items()}
                data.append(result)
        return result


    def AllPlugins(self,commandToExec=None,config_file=False) -> dict:
        """
        Exécute une série de plugins de Volatility3 sur un fichier d'instantané (dump).

        Cette méthode prend en entrée :
        :param dump_filepath: str
            Le chemin du fichier d'instantané à analyser.
        :param commandToExec: dict, optionnel (par défaut None)
            Un dictionnaire contenant les plugins à exécuter et leurs paramètres spécifiques.
            La structure du dictionnaire est la suivante :
            {
                'Plugin1': {
                    'plugin': PluginObject1,
                    'param1': value1,
                    'param2': value2,
                    ...
                },
                'Plugin2': {
                    'plugin': PluginObject2,
                    'param1': value3,
                    'param2': value4,
                    ...
                },
                ...
            }
            Le paramètre 'plugin' doit être un objet de plugin valide de Volatility3.

        :return: dict
            Un dictionnaire contenant les résultats des plugins exécutés.

        Cette méthode exécute les plugins spécifiés dans le dictionnaire 'commandToExec' sur le fichier d'instantané
        (dump) donné. Le processus se déroule en trois étapes :

        Étape 1 : Construction des contextes d'exécution pour chaque plugin.
            Les plugins spécifiés dans 'commandToExec' sont chargés dans un contexte d'exécution, en utilisant la méthode
            '__build_context', qui configure les automagics nécessaires et autres configurations pour l'exécution du plugin.

        Étape 2 : Exécution des plugins et rendu des résultats.
            Chaque plugin construit dans l'étape précédente est exécuté, et les résultats sont rendus sous forme de dictionnaires
            de données. Les résultats sont stockés dans le dictionnaire 'commandToExec'.

        Étape 3 : Traitement des résultats.
            Certains plugins peuvent avoir des clés de résultats non désirées. Dans cette étape, ces clés sont retirées pour
            obtenir un dictionnaire de résultats propre.

        Remarque : Cette méthode est destinée à être utilisée en interne par Volatility3 et ne doit pas être appelée
        directement depuis d'autres parties du code.

        :rtype: dict
        """

        ############################################################
        #                                                          #
        #   Changera a terme pour prendre en parametre             #
        #    un json ou un yaml qui lancera toute les fonctions    #
        ############################################################
        data=[]
        if config_file:
            self.format = "json"
        for funcName in commandToExec:
            if self.showconf:
                print("Fonction en cours: ",funcName)
            t= self.__run_commands(funcName)
            data.append(t)
        return data

    def Info(self)-> dict:
        if os.path.isfile(self.__cache_filename(funcName+args_added)):
            return self.__in_cache(funcName+args_added)
        else:
            dump_filepath = self.dumpPath
            plugin_list = self.__getPlugins()
            command = self.allCommands["WindowsInfo"]["plugin"]
            command = {
                'Info':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb = self.__parse_output(kb)
            retkb = retkb['Info']['result']
            header = ["Kernel Base", "DTB", "Symbols", "Is64Bit", "IsPAE", "layer_name", "memory_layer", "KdVersionBlock", "Major/Minor", "MachineType", "KeNumberProcessors", "SystemTime", "NtSystemRoot", "NtProductType", "NtMajorVersion", "NtMinorVersion", "PE MajorOperatingSystemVersion", "PE MinorOperatingSystemVersion", "PE Machine", "PE TimeDateStamp"]
            index = 0
            data = {}
            for k in header:
                data[k] = retkb[index]["Value"]
                index += 1 
            productSys = data["NtProductType"]
            dateOnSys = datetime.datetime.strptime(data["SystemTime"], "%Y-%m-%d %H:%M:%S")
            timestamp = str(int(dateOnSys.timestamp())) 
            self.filename = "/tmp/"+productSys+timestamp+"Info.json"
            self.__save_file(data,self.filename)
            self.infofn = self.filename
            return data

    #def PrintKey(self):
    #    return self.__run_commands("PrintKey")
    #def skeleton_key_check(self):
    #    return self.__run_commands("skeleton_key_check")
    #def Memmap(self):
    #    return self.__run_commands("Memmap")
    #def HashDump(self):
    #    return self.__run_commands("HashDump")
    #def YaraScan(self):
    #    return self.__run_commands("YaraScan")
    #def VadYaraScan(self):
    #    return self.__run_commands("VadYaraScan")
    #def LdrModules(self):
    #    return self.__run_commands("LdrModules")
    #def CacheDump(self):
    #    return self.__run_commands("CacheDump")
    #def LsaDump(self):
    #    return self.__run_commands("LsaDump")