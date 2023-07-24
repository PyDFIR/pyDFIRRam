import argparse
import json
from pyDFIRRam import windows
def main():
    parser = argparse.ArgumentParser(description="Script pour exécuter différentes fonctions avec un fichier JSON.")
    parser.add_argument("config_file", help="Chemin du fichier JSON de configuration.")
    args = parser.parse_args()
    with open(args.config_file, "r") as file:
       config = json.load(file)
    obj = windows(config["Config"]["InvestigationFile"],showConfig=False,savefile=config["Config"]["SaveFile"],outpath=config["Config"]["output_path"],Outputformat=config["Config"]["output_format"],)
    for e in obj.AllPlugins(config["Command"],True):
        print(json.dumps(e,indent=2))
if __name__=="__main__":
    main()
