import argparse
import json
from pyDFIRRam import windows
def main():
    # Créer un parseur d'arguments
    parser = argparse.ArgumentParser(description="Script pour exécuter différentes fonctions avec un fichier JSON.")
    # Ajouter l'argument du fichier JSON
    parser.add_argument("config_file", help="Chemin du fichier JSON de configuration.")
    # Analyser les arguments de la ligne de commande
    args = parser.parse_args()
    print(args)
    with open(args.config_file, "r") as file:
       config = json.load(file)
    print(config["Config"]["InvestigationFile"],config["Config"]["SaveFile"])
    obj = windows(config["Config"]["InvestigationFile"],showConfig=True,savefile=config["Config"]["SaveFile"])
    print(config["Command"])
    obj.AllPlugins(config["Command"],True)
if __name__=="__main__":
    main()
