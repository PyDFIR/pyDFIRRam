## Handler

::: pydfirram.core.handler

## Politique d'extraction des fichiers

Le handler applique une politique **forensic-safe par défaut** :

- Les sorties sont écrites dans un sous-répertoire dédié à l'exécution :
  `<output_dir>/<run_id>/`.
- `run_id` est généré automatiquement si non fourni.
- Les noms de fichiers fournis par les plugins sont assainis pour empêcher
  les chemins malicieux (path traversal).
- Le comportement en cas de collision est configurable via `collision_policy` :
  - `fail` (défaut) : lève `FileExistsError` si le fichier existe déjà.
  - `unique` : crée un nouveau nom (`artifact.txt`, `artifact-1.txt`, etc.).
  - `overwrite` : autorise explicitement l'écrasement.

Exemple :

```python
from pydfirram.core.handler import create_file_handler

handler_cls = create_file_handler(
    "/tmp/pydfirram-output",
    collision_policy="unique",
)
```