import re, subprocess, pandas, hashlib


class pyDFIRRam:
    def __init__(self) -> None:
        self.ram_info_struct = {"osinfo": "", "logs_dataframe": ""}

    def ram_info(self, file, savelogs, namefile) -> dict:
        """
        Analyse un fichier d'instantané (RAM dump) pour extraire des informations spécifiques.

        Cette méthode prend en entrée :
        :param file: str
            Le chemin du fichier d'instantané (RAM dump) à analyser.
        :param savelogs: bool
            Indique si les logs extraits doivent être sauvegardés dans un fichier.
        :param namefile: str
            Le nom du fichier dans lequel sauvegarder les logs (si savelogs=True).

        :return: dict
            Un dictionnaire contenant les informations extraites de l'instantané.

        Cette méthode analyse le fichier d'instantané (RAM dump) donné pour extraire des informations spécifiques.
        Le processus d'analyse se déroule en plusieurs étapes :

        Étape 1 : Identification du format du fichier.
            La méthode '__file_format' est utilisée pour déterminer le format du fichier (raw, formaté, etc.).

        Étape 2 : Extraction des chaînes de caractères.
            La méthode '__strings_info' est utilisée pour extraire les chaînes de caractères du fichier d'instantané.

        Étape 3 : Obtention des informations sur le système d'exploitation.
            La méthode '__insmod_info' analyse les chaînes de caractères pour récupérer des informations sur le système
            d'exploitation à partir des modules insmod.

        Étape 4 : Extraction des logs et sauvegarde facultative.
            La méthode '__grab_logs' analyse les chaînes de caractères pour extraire les logs. Les logs extraits peuvent
            être sauvegardés dans un fichier si 'savelogs' est True et 'namefile' est spécifié.

        Étape 5 : Construction du dictionnaire de résultats.
            Les informations extraites sont regroupées dans un dictionnaire 'ram_info_struct'.

        Remarque : Cette méthode est destinée à être utilisée en interne par le code spécifique et ne doit pas être appelée
        directement depuis d'autres parties du code.

        :rtype: dict
        """
        if "raw" in self.__file_format(file):
            strings_on_file = self.__strings_info(file)
            self.ram_info_struct["osinfo"] = self.__insmod_info(strings_on_file)
            self.ram_info_struct["logs_dataframe"] = self.__grab_logs(
                strings_on_file, savelogs, namefile
            )
            return self.ram_info_struct
        else:
            return None

    def __file_format(self, file) -> str:
        """
        Détermine le format d'un fichier d'instantané (RAM dump).

        Cette méthode prend en entrée :
        :param file: str
            Le chemin du fichier d'instantané à analyser.

        :return: str
            Le format du fichier d'instantané (raw, formaté, etc.).

        Cette méthode lit les premiers 8 octets du fichier d'instantané spécifié et compare le contenu avec un motif
        caractéristique pour déterminer le format du fichier. Les formats courants incluent les fichiers d'instantanés bruts
        et les fichiers d'instantanés formatés.

        Remarque : Cette méthode est destinée à être utilisée en interne par le code spécifique et ne doit pas être appelée
        directement depuis d'autres parties du code.

        :rtype: str
        """
        with open(file, "rb") as tested_file:
            chunk = tested_file.read(8)
            if chunk == b"\x00\x00\x00\x00\x00\x00\x00\x00":
                print("File Type is unknown and considered as raw")
                return "raw"

    ## TODO : Check si c'est pour linux
    def __grab_logs(self, raw_strings, savelogs=False, namefile="") -> pandas.DataFrame:
        """Grabs DTG|...|LOG_DESC logs, dumps to DF"""
        print("Generating DTG|SEQ_NUM|LOG_TYPE|LOG_LEVEL|LOG_DESC logs.")
        log_re = re.compile(
            "(\d{4}\-\d{2}\-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{3}Z)\|(.+)\|(.+)\|(.+)\|(.+)"
        )
        print(log_re.findall(raw_strings))

        dataFrame = pandas.DataFrame(
            log_re.findall(raw_strings),
            columns=["DTG", "SEQ_NUM", "LOG_TYPE", "LOG_LEVEL", "LOG_DESC"],
        )
        if savelogs == True:
            dataFrame.to_excel(
                namefile + ".xlsx",
                columns=["DTG", "SEQ_NUM", "LOG_TYPE", "LOG_LEVEL", "LOG_DESC"],
            )
        return dataFrame

    def __insmod_info(self, raw_strings) -> list:
        """
        Extrait les logs à partir des chaînes de caractères brutes et les convertit en DataFrame pandas.

        Cette méthode prend en entrée :
        :param raw_strings: str
            Les chaînes de caractères brutes contenant les logs à extraire.
        :param savelogs: bool, optionnel (par défaut False)
            Indique si les logs extraits doivent être sauvegardés dans un fichier Excel.
        :param namefile: str, optionnel (par défaut "")
            Le nom du fichier dans lequel sauvegarder les logs (si savelogs=True).

        :return: pandas.DataFrame
            Un DataFrame pandas contenant les logs extraits.

        Cette méthode utilise une expression régulière pour rechercher les logs dans les chaînes de caractères brutes.
        Les logs sont généralement au format "DTG|SEQ_NUM|LOG_TYPE|LOG_LEVEL|LOG_DESC".
        La méthode recherche ces motifs dans les chaînes de caractères et les stocke dans un DataFrame pandas.

        Si 'savelogs' est True et 'namefile' est spécifié, les logs extraits sont sauvegardés dans un fichier Excel portant
        le nom spécifié.

        Remarque : Cette méthode est destinée à être utilisée en interne par le code spécifique et ne doit pas être appelée
        directement depuis d'autres parties du code.

        :rtype: pandas.DataFrame
        """
        insmod_commands = re.findall(
            '.+insmod\s(lime)\-(\S+)\s"{0,1}(\S+)', raw_strings
        )
        if not any(insmod_commands):
            return [None, None]
        else:
            return list(set(command[1] for command in insmod_commands)), list(
                set(command[2] for command in insmod_commands)
            )

    def __strings_info(self, file):
        """
        Extrait les informations des modules insmod à partir des chaînes de caractères brutes.

        Cette méthode prend en entrée :
        :param raw_strings: str
            Les chaînes de caractères brutes contenant les commandes insmod à extraire.

        :return: list
            Une liste contenant deux listes : la liste des noms de modules insmod et la liste des arguments utilisés.

        Cette méthode recherche les commandes insmod dans les chaînes de caractères brutes et extrait les informations
        sur les modules insmod utilisés ainsi que leurs arguments associés.

        Le format typique des commandes insmod est "insmod lime-module argument1 argument2 ..." où "lime-module" est le nom du
        module insmod et les arguments sont optionnels.

        La méthode retourne une liste contenant deux éléments :
        - La première liste contient les noms uniques des modules insmod trouvés.
        - La deuxième liste contient les arguments uniques associés aux modules insmod trouvés.

        Si aucune commande insmod n'est trouvée, la méthode retourne [None, None].

        Remarque : Cette méthode est destinée à être utilisée en interne par le code spécifique et ne doit pas être appelée
        directement depuis d'autres parties du code.

        :rtype: list
        """
        print("Grabbing strings.")
        strings_proc = subprocess.Popen(
            "strings {}".format(file).split(), shell=False, stdout=subprocess.PIPE
        )
        return strings_proc.communicate()[0].decode()


def get_hash(file_path):
    """
    Calcule le hachage SHA-256 d'un fichier.

    Cette méthode prend en entrée :
    :param file_path: str
        Le chemin du fichier pour lequel calculer le hachage.

    :return: str
        La valeur du hachage SHA-256 en format hexadécimal.

    Cette méthode ouvre le fichier spécifié en mode binaire et calcule le hachage SHA-256 en parcourant le fichier par
    blocs de 4096 octets. Le hachage est mis à jour à chaque itération pour inclure le contenu du bloc traité.

    Une fois que tout le fichier a été traité, la méthode retourne la valeur du hachage SHA-256 en format hexadécimal.

    Remarque : Cette méthode est destinée à être utilisée en interne par le code spécifique et ne doit pas être appelée
    directement depuis d'autres parties du code.

    :rtype: str
    """
    with open(file_path, "rb") as f:
        hash_obj = hashlib.sha256()
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
        return hash_obj.hexdigest()
