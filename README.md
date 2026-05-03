# pyDFIRRam

[![CI](https://github.com/pyDFIR/pyDFIRRam/actions/workflows/ci.yml/badge.svg)](https://github.com/pyDFIR/pyDFIRRam/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/pydfirram.svg)](https://badge.fury.io/py/pydfirram)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**État du projet.** pyDFIRRam est un **SDK expérimental** pour orchestrer des plugins Volatility 3 sur des images mémoire. Il n’offre **ni isolation multi‑tenant ni garde‑fous de production** : chaque processus charge un dump dans un contexte Volatility classique, avec un **délai d’exécution des plugins borné** (`timeout` côté API). Utilisez‑le pour prototyper des chaînes d’analyse, pas comme service partagé entre clients.

PyDFIRRam encapsule les tâches d’analyse mémoire (recherche, parsing, sorties tabulaires) pour que vous restiez focalisé sur les données plutôt que sur la ligne de commande Volatility.

## Table des matières

- [Installation](#installation)
- [Tests](#tests)
- [Utilisation](#utilisation)
  - [Jupyter Lab](#jupyter-lab)
  - [Script](#script)
  - [Exemples](#exemples)
- [Objectifs](#objectifs)

## Installation

Le paquet s’installe avec `pip` ou [Poetry](https://python-poetry.org/).

```bash
pip install pydfirram
```

Outils optionnels (notebooks, dépendance `graphviz` Python ; le binaire système `dot` reste requis pour un rendu graphique) :

```bash
pip install "pydfirram[jupyter,viz]"
```

Avec Poetry, depuis le dépôt cloné :

```bash
poetry install
poetry install --extras jupyter --extras viz
```

## Tests

```bash
tox
```

ou directement :

```bash
pytest
```

Les tests d’intégration qui touchent un fichier dump local sont marqués `requires_dump` et sont ignorés tant que la variable d’environnement ne pointe pas vers un fichier valide :

```bash
export PYDFIRRAM_DUMP_FILE=/chemin/absolu/vers/memory.dump
pytest -m requires_dump
```

## Utilisation

- Dans un environnement Jupyter (extra `jupyter`)
- Dans un script Python

### Jupyter Lab

```bash
poetry run jupyter lab
```

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.PsList(pid=[4]).to_df(max_row=True)
print(output)
```

### Script

```python
from pathlib import Path
from pydfirram.modules.windows import Windows

dumpfile = Path(DUMP_FILE)
win = Windows(dumpfile)
output = win.pslist()

print(output.to_list())
print(output.to_df())
print(win.pslist().to_json())
```

La documentation détaillée : [pydfir.github.io/pyDFIRRam](https://pydfir.github.io/pyDFIRRam).

## Objectifs

1. Faciliter la recherche et l’itération avec Volatility
2. Parser simplement les sorties
3. Privilégier les données plutôt que les commandes
4. Servir de base pour des jeux de données dérivés
5. Analyser un dump à la fois dans un processus (pas de modèle multi‑locataire dans ce SDK)
