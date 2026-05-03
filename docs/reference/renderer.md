## Renderer

### Formats recommandés

- **Petits résultats / exploration** : utilisez **`to_df()`** pour un `pandas.DataFrame` (installer l’extra **`pandas`** : `pip install 'pydfirram[pandas]'`).
- **Gros résultats** : préférez **`to_jsonl(path)`** ou **`to_csv(path)`** après un rendu en liste ; évite de charger tout le jeu dans un DataFrame unique. Ces méthodes n’emploient pas pandas.
- **`to_json()`** reste adapté lorsque tout le jeu tient aisément en une chaîne JSON.
- **Batch & reporting** : pour des sorties rejouables liées à un run, déposez les fichiers (`*.jsonl`, `*.csv`, etc.) sous le dossier **`tables`** du workspace (voir `RunWorkspacePaths.tables`, en pratique `runs/<run_id>/tables/`).
- **Parquet** : **`to_parquet(path)`** est disponible sous l’extra **`parquet`** (`pandas` + `pyarrow`) ; aucune obligation à l’installation par défaut.

### Notes

Sans pandas, **`to_df()`** soulève **`OutputHandlingError`** avec un message explicite. La bibliothèque **ne modifie pas** les **`pandas.options`** globaux : l’élargissement d’affichage éventuel pour les représentations riches passe uniquement par un contexte local (`pandas.option_context`).

### Référence API

::: pydfirram.core.renderer
