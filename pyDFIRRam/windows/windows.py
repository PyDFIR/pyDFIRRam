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
)

class windows(pyDFIRRam):
    def __init__(self,InvestFile,savefile:bool = False,Outputformat:str ="json" ,
                                filename:str ="defaultname",showConfig=False,outpath:str = os.getcwd(), progress:bool=False) -> None:
        # En dev
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
            "MFTscan",
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
            print(f"""
######################### Config #########################
Save file = {self.savefile}                             
format = {self.format}                                   
##########################################################""") 
        getcwd = str(pathlib.Path(__file__).parent) + '/findCommands.json'
        with open(getcwd,'r',encoding="UTF-8") as fichier:
            content = fichier.read()
            self.allCommands = json.loads(content)
        nameos = os.name
        if nameos == 'nt':
            self.plateform= "windows"
            self.temp = ""
        elif nameos == 'posix':
            self.plateform = "linux"
            self.temp = "/tmp/"
        elif nameos == "darwin" : 
            self.plateform = "mac"
            self.filename = "/tmp/"
        else:
            raise Exception()
        if progress:
            self.progress = PrintedProgress()
        else:
            self.progress = MuteProgress()
        self.infofn = ""

    def __getattr__(self, key,*args,**kwargs):
        if key in self.cmds:
            return lambda : self.__run_commands(key)
        else:
            pass
    
    def __in_cache(self,funcName):
        with open(self.__cache_filename(funcName), "r",encoding="UTF-8") as file:
            content = json.load(file)
        return self.__render_outputFormat(content)
    def __cache_filename(self,func):
        self.progress = MuteProgress()
        p = self.Info()
        self.progress = PrintedProgress()
        productSys = p["NtProductType"]
        dateOnSys = datetime.datetime.strptime(p["SystemTime"], "%Y-%m-%d %H:%M:%S")
        timestamp = str(int(dateOnSys.timestamp())) 
        filename = "/tmp/"+productSys+timestamp+func+".json"
        return filename
    def __save_file(self,jsondata:dict,filename:str):
        if self.savefile:
            print(self.filename)
            with open(self.filename+".json", 'w',encoding="UTF-8") as fichier:
                json.dump(jsondata, fichier)
        else:
            with open(filename, 'w',encoding="UTF-8") as fichier:
                json.dump(jsondata,fichier)

    def __render_outputFormat(self,jsondata:dict):
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
            Rename les noeuds du Tree qui nous est envoyé

            :param : node
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
        Construit le contexte d'exécution pour un plugin spécifique dans Volatility3.
        Cette méthode prend en entrée plusieurs paramètres :
        :param investigation_file_path: str
            Le chemin du fichier d'investigation à utiliser.
        :param plugin: str
            Le nom du plugin à exécuter.
        :param context: dict
            Le contexte actuel d'exécution de Volatility3.
        :param base_config_path: str
            Le chemin de la configuration de base à utiliser.
        :return: object
            L'objet représentant le plugin construit dans le contexte de Volatility3.
        La méthode construit le contexte d'exécution en suivant ces étapes :
        1. Récupération des automagics disponibles dans le contexte.
        2. Sélection des automagics spécifiques requis pour le plugin.
        3. Configuration du contexte pour utiliser les stackers associés aux automagics sélectionnés.
        4. Configuration du contexte pour traiter un seul emplacement représenté par le fichier d'investigation.
        5. Construction du plugin en utilisant les automagics, le plugin lui-même, la configuration de base,
           un objet "PrintedProgress()" pour suivre le progrès, et un gestionnaire de fichiers spécifique.
        Si une exception est levée lors de la construction du plugin, elle sera affichée, mais ne stoppera pas
        l'exécution de la méthode.
        Note : Cette méthode est destinée à être utilisée en interne par Volatility3 et ne doit pas être appelée
        directement depuis d'autres parties du code.
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
    def __getPlugins(self) -> None:
        try:
            failures = volatility3.framework.import_files(plugins,True)
        except:
            print("Unable to get plugins")
        return volatility3.framework.list_plugins()
    def __parse_output(self,commandToExec):
        for runable in commandToExec:
            commandToExec_entry = commandToExec[runable]
            if commandToExec_entry['constructed']:
                try:
                    result = VolatilityUtils.JsonRenderer().render(commandToExec_entry['constructed'].run())
                    commandToExec_entry['result'] = result
                except Exception as e:
                    print(f"Error in run: {e}")
        return commandToExec
    
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
        if os.path.isfile(self.infofn):
            with open(self.infofn,"r",encoding="UTF-8") as file:
                content = json.load(file)
            return content
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