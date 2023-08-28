import volatility3.plugins
import volatility3.symbols
import json,os,csv,pathlib
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

class linux(pyDFIRRam):
    def __init__(self,InvestFile,savefile:bool = False,Outputformat:str ="json" ,filename:str ="defaultname",showConfig=False,outpath:str = os.getcwd()) -> None:
        pass
        # En dev
        self.cmds = []
        self.filename = filename
        format = Outputformat.lower()
        self.choice = [
            "json",
            "dataframe"
            ]
        self.savefile = savefile
        self.filename = filename
        self.dumpPath = InvestFile
        self.formatSave = "json"
        self.outpath = outpath +"/"
        if format in self.choice:
            self.format = format
        else:
            print(f"{format} non pris en charge. Les formats pris en charge sont :\n\t-xlsx\n\t-csv\n\t-json\n\t-parquet")
        if showConfig:
            print(f"""
                    ######################### Config #########################
                        Save file = {self.savefile}                           
                        format = {self.format}                                     
                    ##########################################################
                    """) 
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