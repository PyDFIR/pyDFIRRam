"""Point d’entrée sous-processus pour exécuter un plugin avec timeout dur dans le parent.

Invocation :

    python -m pydfirram.core.plugin_worker /chemin/vers/job.json

Le parent définit ``PYDFIRRAM_PLUGIN_WORKER=1``. Ne pas invoquer sans job valide.

Tests : un stub ultra-minimal (« sleep » ou « return ») n’est pris en compte que si
la variable d’environnement ``PYDFIR_TEST_ALLOW_WORKER_STUB`` vaut ``1`` (voir tests).
"""

from __future__ import annotations

import json
import os
import pickle
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from pydfirram.core.base import Generic, OperatingSystem
from pydfirram.core.exceptions import PluginExecutionError
from pydfirram.core.runtime import InProcessRuntime
from pydfirram.core.runtime import WORKER_SUBPROCESS_ENV
from pydfirram.core.workspace import RunWorkspacePaths

_MARKER = WORKER_SUBPROCESS_ENV


def _paths_from_dict(raw: dict[str, str]) -> RunWorkspacePaths:
    return RunWorkspacePaths(
        root=Path(raw["root"]),
        manifest=Path(raw["manifest"]),
        logs=Path(raw["logs"]),
        tables=Path(raw["tables"]),
        extracted=Path(raw["extracted"]),
        tmp=Path(raw["tmp"]),
    )


def _run_test_stub(spec: dict[str, Any]) -> Any:
    if os.environ.get("PYDFIR_TEST_ALLOW_WORKER_STUB") != "1":
        raise PluginExecutionError(
            "Refus d'utiliser un stub worker (definir PYDFIR_TEST_ALLOW_WORKER_STUB=1 pour les tests)."
        )
    kind = spec.get("__pydfir_test_stub__")
    if kind == "sleep":
        time.sleep(float(spec.get("__pydfir_sleep_s", "5")))
        return "stub_done"
    if kind == "return":
        return spec.get("__pydfir_value", "ok")
    raise PluginExecutionError(f"Stub inconnu : {kind!r}")


def run_job(spec: dict[str, Any]) -> Any:
    """Exécute un job décrit dans *spec* (JSON)."""

    if os.environ.get(_MARKER) != "1":
        raise PluginExecutionError(
            "Refus : le worker attend la variable PYDFIRRAM_PLUGIN_WORKER=1 depuis le parent."
        )

    if "__pydfir_test_stub__" in spec:
        return _run_test_stub(spec)

    paths = _paths_from_dict(spec["paths"])
    workspace_base = Path(spec["workspace_base"]).resolve()
    dump_path = Path(spec["dump_path"]).resolve()

    generic = Generic(
        OperatingSystem(spec["operating_system"]),
        dump_path,
        timeout=None,
        workspace_base=workspace_base,
        output_collision_policy=spec["output_collision_policy"],
        manifest_include_dump_sha256=bool(spec.get("manifest_include_dump_sha256", False)),
        execution_runtime=InProcessRuntime(),
    )

    plugin = generic.get_plugin(spec["plugin_name"])
    plugin_kwargs: dict[str, Any] = dict(spec.get("plugin_kwargs", {}))
    run_id = str(spec["run_id"])

    return generic.run_plugin(
        plugin,
        timeout=None,
        _reuse_workspace=(run_id, paths),
        _finalize_workspace=False,
        **plugin_kwargs,
    )


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m pydfirram.core.plugin_worker JOB.json", file=sys.stderr)
        return 2

    job_path = Path(args[0]).expanduser().resolve()
    spec = json.loads(job_path.read_text(encoding="utf-8"))
    result_path = Path(spec["result_pickle_path"])
    result_path.unlink(missing_ok=True)

    try:
        outcome = run_job(spec)
    except BaseException:
        traceback.print_exc(file=sys.stderr)
        return 1

    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("wb") as handle:
        pickle.dump(outcome, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
