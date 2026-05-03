"""Isolation des exécutions de plugins (in-process ou sous-processus)."""

from __future__ import annotations

import abc
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from loguru import logger

from pydfirram.core.exceptions import PluginExecutionError, PluginTimeoutError


WORKER_SUBPROCESS_ENV = "PYDFIRRAM_PLUGIN_WORKER"

SUBPROCESS_JOB_BASENAME = "subprocess_executor_job.json"
WORKER_RESULT_BASENAME = "subprocess_executor_result.pkl"


@dataclass(frozen=True)
class PluginInvocation:
    """Paramètres partagés par les différentes implémentations de runtime."""

    in_process_target: Callable[[], Any]
    subprocess_job_payload: Optional[dict[str, Any]]
    job_file_path: Optional[Path]
    result_pickle_path: Optional[Path]
    plugin_name: str
    stdout_path: Optional[Path]
    stderr_path: Optional[Path]
    timeout_cleanup: Optional[Callable[[], None]]


class ExecutionRuntime(abc.ABC):
    """Stratégie d'exécution d'un plugin Volatility (soft vs hard timeout)."""

    @abc.abstractmethod
    def execute(self, invocation: PluginInvocation, *, timeout_s: Optional[float]) -> Any:
        """Exécute la cible et renvoie le résultat ou lève une exception."""


class InProcessRuntime(ExecutionRuntime):
    """Même processus, timeout via thread (interruption soft — ne tue pas le fil)."""

    def execute(self, invocation: PluginInvocation, *, timeout_s: Optional[float]) -> Any:
        if timeout_s is None:
            return invocation.in_process_target()

        result: dict[str, Any] = {"value": None, "error": None}

        def runner() -> None:
            try:
                result["value"] = invocation.in_process_target()
            except BaseException as exc:
                result["error"] = exc

        worker = threading.Thread(
            target=runner,
            name=f"volatility-run-{invocation.plugin_name}",
            daemon=True,
        )
        started_at = time.monotonic()
        worker.start()
        worker.join(timeout=timeout_s)

        if worker.is_alive():
            elapsed = time.monotonic() - started_at
            logger.error(
                "Volatility plugin '{}' timed out after {:.2f}s (configured timeout: {:.2f}s).",
                invocation.plugin_name,
                elapsed,
                timeout_s,
            )
            if invocation.timeout_cleanup is not None:
                invocation.timeout_cleanup()
            raise PluginTimeoutError(
                f"Le plugin '{invocation.plugin_name}' a depasse le delai ({timeout_s:.2f}s) "
                f"(mode soft : le fil d'execution sous-jacent peut encore tourner).",
                timeout_kind="soft",
            )

        if result["error"] is not None:
            raise result["error"]

        return result["value"]


class SubprocessRuntime(ExecutionRuntime):
    """Processus fils : le délai est appliqué avec arrêt du processus (timeout dur).

    Comportement validé en priorité sous Linux et macOS. Sous Windows, l'arrêt dur
    repose sur ``terminate`` / ``kill`` sans garantie d'équivalence complète avec POSIX.
    """

    def __init__(
        self,
        *,
        python_executable: Optional[str] = None,
        kill_grace_seconds: float = 2.0,
    ) -> None:
        self._python = python_executable or sys.executable
        self._kill_grace = kill_grace_seconds

    def _kill_process_tree(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is not None:
            return
        proc.terminate()
        deadline = time.monotonic() + self._kill_grace
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()

    def execute(self, invocation: PluginInvocation, *, timeout_s: Optional[float]) -> Any:
        if invocation.subprocess_job_payload is None or invocation.job_file_path is None:
            raise PluginExecutionError(
                "Runtime sous-processus : charge utile de job ou chemin de job manquant."
            )
        if invocation.stdout_path is None or invocation.stderr_path is None:
            raise PluginExecutionError(
                "Runtime sous-processus : chemins stdout/stderr requis pour conserver les journaux."
            )
        if invocation.result_pickle_path is None:
            raise PluginExecutionError(
                "Runtime sous-processus : chemin pickle de résultat requis."
            )

        invocation.job_file_path.parent.mkdir(parents=True, exist_ok=True)
        invocation.job_file_path.write_text(
            json.dumps(invocation.subprocess_job_payload, indent=2) + "\n",
            encoding="utf-8",
        )

        cmd = [
            self._python,
            "-m",
            "pydfirram.core.plugin_worker",
            str(invocation.job_file_path),
        ]
        env = os.environ.copy()
        env[WORKER_SUBPROCESS_ENV] = "1"

        stdout_path = invocation.stdout_path
        stderr_path = invocation.stderr_path
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)

        out_fp = stdout_path.open("w", encoding="utf-8", errors="replace")
        err_fp = stderr_path.open("w", encoding="utf-8", errors="replace")
        proc: subprocess.Popen[bytes]
        try:
            proc = subprocess.Popen(  # noqa: S603 - exécutable contrôlé localement par l’analyste
                cmd,
                stdout=out_fp,
                stderr=err_fp,
                env=env,
            )
        finally:
            out_fp.close()
            err_fp.close()

        try:
            if timeout_s is None:
                proc.wait()
            else:
                proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            logger.error(
                "Plugin '{}' sous-processus : depassement du delai {:.2f}s — arret du worker.",
                invocation.plugin_name,
                timeout_s if timeout_s is not None else float("nan"),
            )
            self._kill_process_tree(proc)
            if invocation.timeout_cleanup is not None:
                invocation.timeout_cleanup()
            raise PluginTimeoutError(
                f"Le plugin '{invocation.plugin_name}' a depasse le delai "
                f"({timeout_s:.2f}s) (timeout dur — processus worker termine ou tue). "
                f"Stderr conserve sous {stderr_path.as_posix()}.",
                timeout_kind="hard",
                stderr_log_path=stderr_path,
            )

        if proc.returncode != 0:
            tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise PluginExecutionError(
                "Echec du worker plugin (voir stderr dans le workspace). "
                f"Code de sortie={proc.returncode}. Extrait stderr:\n{tail}",
                subprocess_exit_code=proc.returncode,
                stderr_log_path=stderr_path,
            )

        result_path = invocation.result_pickle_path
        if not result_path.is_file():
            raise PluginExecutionError(
                "Le worker s'est termine sans fichier de resultat (pickle absent). "
                f"Consulter {stderr_path.as_posix()}.",
                subprocess_exit_code=proc.returncode,
                stderr_log_path=stderr_path,
            )

        import pickle

        with result_path.open("rb") as handle:
            return pickle.load(handle)


def default_execution_runtime() -> ExecutionRuntime:
    """Runtime par défaut : in-process pour compatibilité (notebooks / tests).

    Dans un worker fils (**PYDFIRRAM_PLUGIN_WORKER**), cette fonction renvoie
    toujours :class:`InProcessRuntime`.

    Pour appliquer un timeout *dur*, instancier explicitement :class:`SubprocessRuntime`.
    """
    if os.environ.get(WORKER_SUBPROCESS_ENV) == "1":
        return InProcessRuntime()
    return InProcessRuntime()


def recommended_subprocess_runtime() -> ExecutionRuntime:
    """Isolement par sous-processus (timeout dur), cible principale Linux/macOS.

    Sous Windows, retourne :class:`InProcessRuntime` : le comportement n'est pas
    considéré comme validé pour l'arrêt dur.
    """
    if sys.platform in {"linux", "darwin"}:
        return SubprocessRuntime()
    return InProcessRuntime()
