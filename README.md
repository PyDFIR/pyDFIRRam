# Objectifs du projet
1. Faciliter la recherche et le try and retry avec volatility
2. Parser plus facilement les outputs
3. Se concentrer sur la data plutot que sur la commandes
4. Utiliser comme un dataset
5. Pouvoir gerer plusieurs dump dans un meme programme
# Utilisation
## Installation
python3 -m venv pydfirVenv
source pydfirVenv/bi,/activate
git clone https://github.com/pyDFIR/pyDFIRRam
cd pyDFIRRam
poetry build
poetry install

# Differentes facon d'utiliser
1. Jupyter notebook

```bash
poetry run jupyter notebood
```

2. Ficher de configuration (Outil CLI)
3. Developper directement dans un fichier 

# Exemples

```Python
from pyDFIRRam import windows
import os
winObj1 = windows(os.getcwd()+"memdump.mem") -> Les parametres ici sont tres importants voir documentations

data1 = winObj1.PsList()
data2 = winObj2.PsTree()
....
```

Les fonctionnalités prises en charge sont directement dans la documentation