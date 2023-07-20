import volatility3.plugins
import volatility3.symbols
import json,pandas,csv,pathlib
from pyDFIRRam.volatility_utils.volatility_utils import *
from pyDFIRRam import pyDFIRRam 
from datetime import datetime
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
    def __init__(self,InvestFile,savefile:bool = False,Outputformat:str = "json",filename:str ="defaultname",showConfig=False) -> None:
        # En dev
        self.filename = filename
        format = Outputformat.lower()
        self.choice = [
            "json",
            "dataframe"
            ]
        self.savefile = savefile
        self.filename = filename
        self.dumpPath = InvestFile
        if format in self.choice:
            self.format = format
        else:
            print(f"{format} non pris en charge. Les formats pris en charge sont :\n\t-xlsx\n\t-csv\n\t-json\n\t-parquet")
        if showConfig:
            print(f"""
######################### Config #########################
Save file = {self.savefile}                             
format = {self.format}                                   
##########################################################""") 
        getcwd = str(pathlib.Path(__file__).parent) + '/findCommands.json'
        with open(getcwd,'r') as fichier:
            content = fichier.read()
            self.Allcommands = json.loads(content)
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
     
        self.progress = PrintedProgress()
        self.infofn = ""
    def __in_cache(self,funcName):
        with open(self.__cache_filename(funcName), "r") as file:
            content = json.load(file)
        return self.__render_outputFormat(content)
    def __cache_filename(self,func):
        self.progress = MuteProgress()
        p = self.Info()
        self.progress = PrintedProgress()
        productSys = p["NtProductType"]
        dateOnSys = datetime.strptime(p["SystemTime"], "%Y-%m-%d %H:%M:%S")
        timestamp = str(int(dateOnSys.timestamp())) 
        filename = "/tmp/"+productSys+timestamp+func+".json"
        return filename
    def __save_file(self,jsondata,filename):
        # Non testé 
        # # en dev
        if self.savefile:
            #if self.format == "xlsx":
            #    df = pandas.DataFrame(jsondata)
            #    df.to_excel(self.filename+".xlsx", index=False)
            #elif self.format == "csv":
            #    with open(self.filename+".csv", 'w', newline='') as fichier:
            #        if isinstance(jsondata[0], dict):
            #            # Si les données sont sous forme de dictionnaires, utilisez les clés comme en-têtes de colonnes.
            #            fieldnames = jsondata[0].keys()
            #            writer = csv.DictWriter(fichier, fieldnames=fieldnames)
            #            writer.writeheader()
            #            writer.writerows(jsondata)
            #        elif isinstance(jsondata[0], list):
            #            # Si les données sont sous forme de listes, écrivez directement les lignes dans le fichier CSV.
            #            writer = csv.writer(fichier)
            #            writer.writerows(jsondata)
            if self.format == "json":
                with open(self.filename+".json", 'w') as fichier:
                    json.dump(jsondata, self.filename)
            #elif self.format == "parquet":
            #    df = pandas.DataFrame(jsondata)
            #    df.to_parquet(self.filename+".parquet", engine='pyarrow')
            elif self.format == "dataframe":
                df = pandas.DataFrame(jsondata)
            else:
                print("le format n'a pas été renseigné ou contient des erreurs")
        else:
            with open(filename, 'w') as fichier:
                    json.dump(jsondata,fichier)  
    def __render_outputFormat(self,jsondata):
        if self.format=="dataframe":
            return pandas.DataFrame(jsondata)
        elif self.format == "json":
            return jsondata
    def __rename_pstree(self,node):
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

    def __build_context(self,investigation_file_path, plugin, context, base_config_path):
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
        try:
            if self.progress == PrintedProgress():
                print("plugin: ", (str(plugin).split(".")[-1])[:-2])
            constructed = plugins.construct_plugin(context,automagics,plugin,base_config_path,self.progress,volatility_utils.file_handler(investigation_file_path))
            if self.progress == PrintedProgress():
                print("")
        except Exception as e:
            print(e)
        return constructed
    
    def __getPlugins(self):
        try:
            failures = volatility3.framework.import_files(plugins,True)
        except:
            print("Unable to get plugins")
        return volatility3.framework.list_plugins()
    
    def AllPlugins(self,commandToExec: json = None) -> json:
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
        
        volatility3.framework.require_interface_version(2,0,0)
        dump_filepath = self.dumpPath 
        plugin_list = self.__getPlugins()
        commandToExec = {
            'PsList':{
                'plugin' :plugin_list['windows.pslist.PsList']
                },
            'CmdLine':{
                'plugin' :plugin_list['volatility3.framework.plugins.windows.cmdline.CmdLine']
                }
            }
        base_config_path = "plugins"
        # Step 1: Build contexts
        for runable in commandToExec:
            context = contexts.Context()
            commandToExec_entry = commandToExec[runable]
            commandToExec_entry['constructed'] = self.__build_context(dump_filepath, commandToExec_entry['plugin'], context, base_config_path)
        # Step 2: Render results for constructed contexts
        for runable in commandToExec:
            commandToExec_entry = commandToExec[runable]
            if commandToExec_entry['constructed']:
                try:
                    result = volatility_utils.DictRenderer().render(commandToExec_entry['constructed'].run())
                    commandToExec_entry['result'] = result
                except Exception as e:
                    print(f"Error in run: {e}")
        # Step 3: Process results and remove unwanted keys
        for runable in commandToExec:
            commandToExec_entry = commandToExec[runable]
            if runable != 'PsTree' and runable != 'UserAssist' and runable != 'DeviceTree':
                for artifact in commandToExec_entry['result']:
                    artifact = {x.translate({32: None}): y for x, y in artifact.items() if x != '__children'}
                    if 'Offset(V)' in artifact:
                        artifact['Offset'] = artifact.pop('Offset(V)')
                    if 'Tag' in artifact:
                        artifact['VTag'] = artifact.pop('Tag')
        # A changer, il faudra que je return dict propre :)
        if self.savefile:
            self.__save_file(commandToExec,self.filename)
        else:
            return commandToExec

    def __parse_output(self,commandToExec):
        for runable in commandToExec:
            commandToExec_entry = commandToExec[runable]
            if commandToExec_entry['constructed']:
                try:
                    result = volatility_utils.DictRenderer().render(commandToExec_entry['constructed'].run())
                    commandToExec_entry['result'] = result
                except Exception as e:
                    print(f"Error in run: {e}")
        return commandToExec
    def PsTree(self):
        """
        Exécute le plugin PsTree de Volatility3 sur un fichier d'instantané (dump).
    
        Cette méthode prend en entrée :
        :param dump_filepath: str
            Le chemin du fichier d'instantané à analyser.
    
        :return: dict
            Un dictionnaire contenant la structure arborescente des processus (PsTree) extraite du dump.
    
        Cette méthode exécute le plugin PsTree de Volatility3 sur le fichier d'instantané donné (dump).
        Le processus d'exécution se déroule en plusieurs étapes :
    
        Étape 1 : Construction du contexte d'exécution pour le plugin PsTree.
            Le plugin PsTree est chargé dans un contexte d'exécution, en utilisant la méthode '__build_context'.
            Cela configure les automagics nécessaires et autres configurations pour l'exécution du plugin.
    
        Étape 2 : Exécution du plugin PsTree.
            Le plugin PsTree construit dans l'étape précédente est exécuté, et le résultat est stocké dans le dictionnaire 'kb'
            sous la clé 'PsTree'.
    
        Étape 3 : Traitement du résultat.
            Si le résultat du plugin PsTree est disponible (non vide), la méthode renomme les clés du dictionnaire de résultats
            pour rendre la structure arborescente plus claire. Le résultat final est un dictionnaire représentant la structure
            arborescente des processus extraite du dump.
    
        Remarque : Cette méthode est destinée à être utilisée en interne par Volatility3 et ne doit pas être appelée
        directement depuis d'autres parties du code.
    
        :rtype: dict
        """
        if os.path.isfile(self.__cache_filename("PsTree")):
            return self.__in_cache("PsTree")
        else:
            dump_filepath = self.dumpPath
            volatility3.framework.require_interface_version(2,0,0)
            #Ci dessous a gerer plus tard (Gestion des erreurs)
            plugin_list = self.__getPlugins()
            #commandToExec soit a lire un fichier yaml soit a passer en argument
            command = self.Allcommands["PsTree"]["plugin"]
            command = {
                'PsTree':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            if kb['PsTree']['result']:
                pstree_artifact = volatility_utils.DictRenderer().render(kb['PsTree']['result'])
                for tree in pstree_artifact:
                    self.__rename_pstree(tree)
                self.__save_file(pstree_artifact,self.__cache_filename("PsTree"))
                print(pstree_artifact)
                return self.__render_outputFormat(pstree_artifact)
            else:
                print("Error")
    def __setContext(self,args):
        context = contexts.Context()
        for e in args:
            for k,v in e.items():
                context.config[k] = int(v)
        print(context.config['plugins.DumpFiles.physaddr'])
        return context
    def __runner(self,dump_filepath,base_config_path,kb,args=None):
        
        for runable in kb:
            if args:
                context = self.__setContext(args)
            else:
                context = contexts.Context()
            kb[runable]['constructed'] = self.__build_context(dump_filepath,kb[runable]['plugin'],context,base_config_path)
        for runable in kb:
            if kb[runable]['constructed']:
                try:
                    kb[runable]['result'] = kb[runable]['constructed'].run()
                    return kb
                except:
                    print("error in run")
                    pass

    def PsList(self):
        if os.path.isfile(self.__cache_filename("PsList")):
            return self.__in_cache("PsList")
        else:
            dump_filepath = self.dumpPath
            command = self.Allcommands["PsList"]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                'PsList':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb= self.__parse_output(kb)
            retkb = retkb['PsList']['result']
            self.__save_file(retkb,self.__cache_filename("PsList"))
            return self.__render_outputFormat(retkb)
    
    def CmdLine(self):
        if os.path.isfile(self.__cache_filename("PsList")):
            return self.__in_cache("PsList")
        else:
            dump_filepath = self.dumpPath
            command = self.Allcommands["CmdLine"]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                'CmdLine':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb = self.__parse_output(kb)
            retkb = retkb['CmdLine']['result']
            self.__save_file(retkb,self.__cache_filename("CmdLine"))
            return self.__render_outputFormat(retkb)
        
    def Info(self):
        if os.path.isfile(self.infofn):
            with open( self.infofn,"r") as file:
                content = json.load(file)
            return content
        else:
            dump_filepath = self.dumpPath
            plugin_list = self.__getPlugins()
            command = self.Allcommands["WindowsInfo"]["plugin"]
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
            dateOnSys = datetime.strptime(data["SystemTime"], "%Y-%m-%d %H:%M:%S")
            timestamp = str(int(dateOnSys.timestamp())) 
            filename = "/tmp/"+productSys+timestamp+"Info"+".json"
            self.__save_file(data,filename)
            self.infofn = filename
            return data
    def PsScan(self):
        if os.path.isfile(self.__cache_filename("PsScan")):
            return self.__in_cache("PsScan")
        else:
            dump_filepath = self.dumpPath
            command = self.Allcommands["PsScan"]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                'PsScan':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb = self.__parse_output(kb)
            retkb = retkb['PsScan']['result']
            self.__save_file(retkb,self.__cache_filename("PsScan"))
            return self.__render_outputFormat(retkb)
    
    def NetScan(self):
        if os.path.isfile(self.__cache_filename("NetScan")):
            with open(self.__cache_filename("NetScan"), "r") as file:
                content = json.load(file)
            return content
        else:
            dump_filepath = self.dumpPath
            command = self.Allcommands["NetScan"]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                'NetScan':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb = self.__parse_output(kb)
            retkb = retkb['NetScan']['result']
            self.__save_file(retkb,self.__cache_filename("NetScan"))
            return self.__render_outputFormat(retkb)
    def FileScan(self):
        if os.path.isfile(self.__cache_filename("FileScan")):
            with open(self.__cache_filename("FileScan"), "r") as file:
                content = json.load(file)
            return content
        else:
            dump_filepath = self.dumpPath
            command = self.Allcommands["FileScan"]["plugin"]
            plugin_list = self.__getPlugins()
            command = {
                'FileScan':{
                    'plugin':plugin_list[command]
                    }
                }
            kb = self.__runner(dump_filepath,"plugins",command)
            retkb = self.__parse_output(kb)
            retkb = retkb['FileScan']['result']
            self.__save_file(retkb,self.__cache_filename("FileScan"))
            return self.__render_outputFormat(retkb)
    def DumpFiles(self,offset:list):
        def DumpFiles_build_context(self,investigation_file_path, plugin, context, base_config_path,output_paths):
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
            try:
                if self.progress == PrintedProgress():
                    print("plugin: ", (str(plugin).split(".")[-1])[:-2])
                constructed = plugins.construct_plugin(context,automagics,plugin,base_config_path,self.progress,volatility_utils.file_handler(output_paths))
                if self.progress == PrintedProgress():
                    print("")
            except Exception as e:
                print(e)
            return constructed
        output_path = "/home/remnux/Desktop/project/2600/Sidequest/pyDFIR/"
        for e in offset:
            for fn in  os.listdir(output_path):
                if "file."+str(hex(e)) in fn:
                    if e in offset :
                        offset.remove(e)
        if offset:
            def build_context(dump_path, context, base_config_path, plugin, output_path):
                """This function is used to buid the context and construct each plugin
                   Return : The contructed plugin.
                """
                available_automagics = automagic.available(context)
                plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)
                automagics = automagic.choose_automagic(available_automagics, plugin)
                context.config['automagic.LayerStacker.stackers'] = automagic.stacker.choose_os_stackers(plugin)
                context.config['automagic.LayerStacker.single_location'] = "file://"+dump_path
                constructed = plugins.construct_plugin(context, automagics, plugin, base_config_path, MuteProgress(), volatility_utils.file_handler(output_path))
                return constructed
            data=[]
            for e in offset:
                volatility3.framework.require_interface_version(2, 0, 0)
                output_path = "/home/remnux/Desktop/project/2600/Sidequest/pyDFIR/"
                failures = volatility3.framework.import_files(plugins, True)
                plugin_list = volatility3.framework.list_plugins()
                base_config_path = "plugins"
                context = contexts.Context()
                context.config['plugins.DumpFiles.virtaddr'] = int(e)
                command = self.Allcommands["DumpFiles"]["plugin"]
                plugin_list = self.__getPlugins()
                command = {
                    'DumpFiles':{
                        'plugin':plugin_list[command]
                        }
                    }
                plugin_list = volatility3.framework.list_plugins()
                try:
                    constructed = build_context(self.dumpPath, context, base_config_path, command["DumpFiles"]["plugin"],output_path)
                except:
                    pass
                if constructed:
                    result = volatility_utils.DictRenderer().render(constructed.run())
                    if len(result) < 1:
                        del (context.config['plugins.DumpFiles.virtaddr'])
                        context.config['plugins.DumpFiles.physaddr'] = int(e)
                        constructed = build_context(self.dumpPath, context, base_config_path,
                                                    plugin_list['windows.dumpfiles.DumpFiles'], output_path)
                        result =volatility_utils.DictRenderer().render(constructed.run())
                for artifact in result:
                    artifact = {x.translate({32: None}): y
                                for x, y in artifact.items()}
                data.append(result)
            return result