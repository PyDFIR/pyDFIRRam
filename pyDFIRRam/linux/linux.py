from datetime import datetime
import pathlib,json

import volatility3.plugins
import volatility3.symbols

#PyDFIRModules
from pyDFIRRam.core.core import build_context,run_commands,getPlugins,runner,json_to_graph
from pyDFIRRam.utils.handler.handler import *
from pyDFIRRam.utils.renderer.renderer import parse_output,JsonRenderer,render_outputFormat


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

class linux(pyDFIRRam):
    def __init__(self, InvestFile, savefile:bool = False,Outputformat:str ="json",
                                filename:str ="defaultname", showConfig=False, outpath:str = os.getcwd(), progress:bool=False) -> None:
        """
        Initialize an instance of Windows.

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
            self.cmds = []
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
        parquet_filename = self.__cache_filename(funcName)
        with open(parquet_filename) as f:
            data = json.load(f)
        format_file = self.format
        if funcName == "PsTree":
            format_file = "json"
            return json_to_graph(data)
        else: 
            return render_outputFormat(format_file, data)

        """table = pq.read_table(parquet_filename)
        content = table.to_pandas()
        return self.render_outputFormat(content)"""
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
        #p = self.Info()
        self.progress = PrintedProgress()
        productSys = p["NtProductType"]
        dateOnSys = datetime.strptime(p["SystemTime"], "%Y-%m-%d %H:%M:%S")
        timestamp = str(int(dateOnSys.timestamp())) 
        filename = "/tmp/"+productSys+timestamp+func+".json"
        return filename
    
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
        if key in self.cmds:
            filename = self.__cache_filename(key)
            if os.path.isfile(filename):
                return lambda : self.__in_cache(key)
            else :
                return lambda : run_commands(key,filename,self.dumpPath,self.format,self.allCommands,self.progress,self.savefile)
            
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
    