from datetime import datetime
from typing import Any

# PyDFIRModules
from pyDFIRRam.core.core import run_commands, getPlugins, runner, build_basic_context
from pyDFIRRam.utils.handler.handler import *
from pyDFIRRam.utils.renderer.renderer import (
    parse_output,
    JsonRenderer,
    render_outputFormat,
    json_to_graph,
)
from pyDFIRRam import get_hash

from pyDFIRRam import pyDFIRRam
from volatility3.cli import PrintedProgress, MuteProgress
from volatility3.framework import (
    automagic,
    contexts,
    plugins,
)

import pathlib, json, os
import volatility3.plugins
import volatility3.symbols


class windows(pyDFIRRam):
    def __init__(
        self,
        memory_file: str ,
        savefile: bool = False,
        output_format: str = "json",
        funcName: str = "defaultname",
        showConfig=False,
        outpath=os.getcwd(),
        progress: bool = False,
    ) -> None:
        try:
            self.__validate_file(memory_file)
            self.__initialize_attributes(
                memory_file,
                savefile,
                output_format,
                funcName,
                showConfig,
                outpath,
                progress,
            )
        except FileNotFoundError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during initialization: {e}")

    def __validate_file(self, memory_file: str) -> None:
        if not os.path.isfile(memory_file):
            raise FileNotFoundError(f"The file {memory_file} does not exist.")

    def __initialize_attributes(
        self,
        memory_file: str,
        savefile: bool,
        output_format: str,
        funcName: str,
        showConfig: bool,
        outpath: str,
        progress: bool,
    ) -> None:
        self.cmds = [
            "DumpFiles",
            "PsList",
            "HiveList",
            "Crashinfo",  # Verifier qu'il s'agit bien d'un crashDump
            "Envars",
            "VerInfo",
            "MutantScan",
            "BigPools",  # Prends des arguments {tags, show-free}
            "HiveScan",
            "getSids",  # Prends des arguments {pid}
            "VADinfo",  # Prends des arguments {address, pid, dump,maxsize}
            "skeleton_key_check",
            "Sessions",  # Prends des arguments {pid}
            "Strings",  # Prends des arguments {pid, string-file}
            "GetSetviceSids",
            "WindowsInfo",
            "DllList",  # Prends des arguments {pid, dump}
            "NetScan",  # Prends des arguments {include-corrupt}
            "NetStat",  # Prends des arguments {include-corrupt}
            "PoolScanner",
            "SSDT",
            "LsaDump",  # idk
            "ModScan",  # Prends des arguments {dump}
            "SymLinkScan",
            "PsScan",  # Prends des arguments {physical, pid, dump}
            "PsTree",  # Prends des arguments {physical, pid}
            "MBRScan",  # Prends des arguments {full}
            "DumpFiles",  # Prends des arguments {physaddr, virtaddr, pid}
            "VirtMap",
            "CmdLine",  # Prends des arguments {pid}
            "LdrModules",  # Prends des arguments {pid}
            "CacheDump",
            "FileScan",
            "Handles",  # Prends des arguments {pid}
            "VadInfo",  # Prends des arguments {address, pid, dump,maxsize}
            "DriverScan",
            "DeviceTree",
            "YaraScan",  # idk
            "VadYaraScan",  # idk
            "SvcScan",  # idk
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
            "PrintKey",
        ]
        self.fileHash = get_hash(memory_file)
        outformat = output_format.lower()
        self.choice = ["json", "dataframe"]
        self.savefile = ""
        self.dumpPath = memory_file
        self.formatSave = "json" if outformat in self.choice else None
        self.outpath = os.path.join(outpath, "")  # Ensure proper directory path
        self.showconf = showConfig
        if outformat not in self.choice:
            print(
                f"{outformat} non pris en charge. Les formats pris en charge sont :\n\t-xlsx\n\t-csv\n\t-json\n\t-parquet"
            )
        else:
            self.format = outformat
        if showConfig:
            self.__print_config()
        self.allCommands = self.get_file_content(
            str(pathlib.Path(__file__).parent) + "/findCommands.json"
        )
        self.temp, self.plateform = self.__define_platforms()

        if progress:
            self.progress = PrintedProgress()
        else:
            self.progress = MuteProgress()
        self.infofn = ""

    def showFunctions(self) -> list:
        return self.cmds

    def __in_cache(self, funcName, **kwargs):
        """
        Check if there is cached content for a specific function.

        This method reads the cached content from a file and returns the content
        in the appropriate output format.

        :param funcName: The name of the function to check for cached content.
        :type funcName: str
        :return: The cached content in the specified output format.
        :rtype: Depends on the format specified.
        """
        ## TODO : Voir ici  pour laisser la possibilité de store au format parquet
        if kwargs:
            try:
                kwargs_key = set(kwargs.keys())
                kwargs_value = set(kwargs.values())
                print(kwargs_key, kwargs_value)
            except Exception as e:
                print(
                    f"Aucun des paramètres n'est pris en charge par cette fonction. Les paramètres sont les suivants : {self.choice}"
                )
        target_funcName = self.__cache_funcName(funcName)
        with open(target_funcName) as f:
            data = json.load(f)
        format_file = self.format
        if funcName == "PsTree":
            format_file = "json"
            return json_to_graph(data)
        else:
            return render_output_format(format_file, data)

    def __cache_filename(self, func):
        """
        Generate a cache funcName based on function name and system information.

        This method generates a cache funcName using the function name, system information,
        and a timestamp. The funcName is used for storing cached content.

        :param func: The name of the function.
        :type func: str
        :return: The generated cache funcName.
        :rtype: str
        """
        self.savefile = self.temp + self.fileHash + func + ".json"

    def get_file_content(self, funcName) -> dict:
        """
        Get the content of a JSON file and return it as a dictionary.

        This method reads the content of a JSON file and parses it into a dictionary.

        :param funcName: Path to the JSON file.
        :type funcName: str
        :return: A dictionary containing the parsed JSON data.
        :rtype: dict
        """
        with open(funcName, "r", encoding="UTF-8") as fichier:
            content = fichier.read()
        return json.loads(content)

    def __getattr__(self, key):
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
        if key not in self.cmds:
            raise ValueError(f"Unable to handle {key}")

        ## Ici il faut que je verifie si le fichier existe dèjà
        def parse_data_function(**kwargs):
            funcName = key
            self.__cache_filename(funcName)
            for k, v in kwargs.items():
                funcName += str(k)
                funcName += str(v)
            if os.path.isfile(funcName):
                return self.__in_cache(key)
            return run_commands(
                key,
                funcName,
                self.dumpPath,
                self.format,
                self.allCommands,
                self.progress,
                self.savefile,
                **kwargs,
            )

        return parse_data_function

    def __print_config(self):
        """
        Print the current configuration settings.

        This method prints the current configuration settings of the instance.

        :return: None
        """
        print(
            f"""
######################### Config #########################
Save file = {self.savefile}
format = {self.format}
##########################################################"""
        )

    def __define_platforms(self) -> tuple:
        """
        Define platform-specific settings.

        This method determines the appropriate temporary directory path and platform name
        based on the operating system.

        :return: A tuple containing the temporary directory path and the platform name.
        :rtype: tuple[str, str]
        :raises Exception: If the operating system is not recognized.
        """
        varTempOS = os.name
        if varTempOS == "nt":
            return " C:/WINDOWS/Temp", "windows"
        elif varTempOS == "darwin":
            return "/tmp/", "mac"
        elif varTempOS == "posix":
            return "/tmp/", "linux"
        else:
            raise Exception()

    def save_file(self, out_dataframe, funcName: str):
        if self.savefile:
            with open(self.savefile, "w", encoding="UTF-8") as fichier:
                json.dump(out_dataframe, fichier)
        else:
            with open(self.savefile, "w", encoding="UTF-8") as fichier:
                json.dump(out_dataframe, fichier)

    def AllPlugins(self, commandToExec=None, config_file=False) -> dict:
        data = []
        if config_file:
            self.format = "json"
        for funcName in commandToExec:
            if self.showconf:
                print("Fonction en cours: ", funcName)
            t = run_commands(funcName)
            data.append(t)
        return data

    def Info(self) -> dict:
        funcName = "Info"
        if os.path.isfile(funcName):
            with open(self.infofn, "r", encoding="UTF-8") as file:
                content = json.load(file)
            return content
        else:
            dump_filepath = self.dumpPath
            plugin_list = getPlugins()
            command = self.allCommands["WindowsInfo"]["plugin"]
            command = {"Info": {"plugin": plugin_list[command]}}
            self.progress = PrintedProgress()
            context = build_basic_context(
                dump_filepath, "plugin", command["Info"]["plugin"]
            )
            info = runner(context)
            retkb = parse_output(info)
            header = [
                "Kernel Base",
                "DTB",
                "Symbols",
                "Is64Bit",
                "IsPAE",
                "layer_name",
                "memory_layer",
                "KdVersionBlock",
                "Major/Minor",
                "MachineType",
                "KeNumberProcessors",
                "SystemTime",
                "NtSystemRoot",
                "NtProductType",
                "NtMajorVersion",
                "NtMinorVersion",
                "PE MajorOperatingSystemVersion",
                "PE MinorOperatingSystemVersion",
                "PE Machine",
                "PE TimeDateStamp",
            ]
            index = 0
            data = {}
            for k in header:
                data[k] = retkb[index]["Value"]
                index += 1
            productSys = data["NtProductType"]
            self.fileHash = self.fileHash + funcName + "." + self.formatSave
            #self.save_file(data, self.fileHash)
            self.infofn = self.fileHash
            return data
