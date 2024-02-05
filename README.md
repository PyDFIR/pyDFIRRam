# Objectifs du projet
1. Faciliter la recherche et le try and retry avec volatility
2. Parser plus facilement les outputs
3. Se concentrer sur la data plutot que sur la commandes
4. Utiliser comme un dataset
5. Pouvoir gerer plusieurs dump dans un meme programme

# Utilisation
## Installation
```bash
python3 -m venv pydfirVenv
source pydfirVenv/bin/activate
git clone https://github.com/pyDFIR/pyDFIRRam
cd pyDFIRRam
poetry build
poetry install
```
# Differentes facon d'utiliser
1. Jupyter notebook

```bash
poetry run jupyter notebook
```

2. Ficher de configuration (Outil CLI)
3. Developper directement dans un fichier 

# Exemples

```Python
from pyDFIRRam import windows
import os
winObj1 = windows(InvestFile=os.getcwd()+"memdump.mem",Outputformat="dataframe") -> Les parametres ici sont tres importants voir documentations

data1 = winObj1.PsList()
data1_1 = winObj1.PsList(pid=[4])
data1_1 = winObj1.PsList(pid=[4,324,...])

data1
data1_1
```

Les fonctionnalités prises en charge sont directement dans la documentation