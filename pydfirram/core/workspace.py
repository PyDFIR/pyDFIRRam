"""Structured run workspaces under ``runs/<run_id>/``.

Each logical execution allocates a deterministic directory layout and a manifest
recording provenance metadata. Default collision handling is forensic-safe:

- Refusing clobber operations on existing ``runs/<run_id>/`` workspaces.
- Refusing undeclared overwrites inside a run when using :class:`ArtifactManager`.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Literal, Optional

import importlib.metadata

from pydfirram.core.exceptions import (
    ArtifactAlreadyExistsError,
    InvalidPluginArgumentError,
    WorkspaceConflictError,
)

CollisionPolicy = Literal["fail", "unique", "overwrite"]

RUN_LAYOUT_PREFIX = "runs"

MANIFEST_NAME = "manifest.json"


class RunStatus(str, Enum):
    """Outcome of an execution recorded in :class:`RunManifest`."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


def sanitize_run_identifier(run_id: str) -> str:
    """Normalize a caller-provided identifier for filesystem use."""
    candidate = run_id.strip()
    if not candidate or "/" in candidate or "\\" in candidate:
        raise InvalidPluginArgumentError(
            "Identifiant de run invalide pour le workspace (chemins refuses)."
        )
    if candidate in {".", ".."}:
        raise InvalidPluginArgumentError("Identifiant de run invalide.")
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)
    if sanitized in {"", ".", ".."}:
        raise InvalidPluginArgumentError("Identifiant de run invalide apres assainissement.")
    return sanitized


@dataclass(frozen=True)
class RunWorkspacePaths:
    """Filesystem locations for one run."""

    root: Path
    manifest: Path
    logs: Path
    tables: Path
    extracted: Path
    tmp: Path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _python_version() -> str:
    import sys

    return sys.version.split()[0]


def _package_version(package: str, fallback: str = "unknown") -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return fallback


def _volatility_version() -> str:
    try:
        import volatility3 as v3_module  # type: ignore[import-not-found]

        return str(getattr(v3_module, "__version__", "unknown"))
    except Exception:  # pragma: no cover - defensive import path
        return "unknown"


def kwargs_to_manifest_dict(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Make plugin kwargs JSON-serializable (best-effort)."""

    def _convert(val: Any) -> Any:
        if val is None or isinstance(val, (str, bool, int, float)):
            return val
        if isinstance(val, Path):
            return val.as_posix()
        if isinstance(val, dict):
            return {str(k): _convert(v) for k, v in val.items()}
        if isinstance(val, (list, tuple, set)):
            return [_convert(item) for item in val]
        if isinstance(val, Enum):
            return val.value
        return repr(val)

    return {str(key): _convert(value) for key, value in kwargs.items()}


@dataclass
class RunManifest:
    """Metadata persisted as ``runs/<run_id>/manifest.json``."""

    run_id: str
    plugin_name: str
    dump_path: str
    dump_sha256: Optional[str]
    started_at: Optional[str]
    ended_at: Optional[str]
    duration_seconds: Optional[float]
    status: Optional[RunStatus]
    plugin_arguments: dict[str, Any]
    output_files: list[str]
    errors: list[str]
    warnings: list[str]
    python_version: str
    pydfirram_version: str
    volatility3_version: str
    timeout_kind: Optional[str] = None

    @classmethod
    def start_shell(
        cls,
        *,
        run_id: str,
        plugin_name: str,
        dump_path: Path,
        kwargs: Optional[dict[str, Any]] = None,
    ) -> RunManifest:
        kwargs = kwargs or {}
        dump_str = dump_path.resolve().as_posix()
        return cls(
            run_id=run_id,
            plugin_name=plugin_name,
            dump_path=dump_str,
            dump_sha256=None,
            started_at=_utc_now_iso(),
            ended_at=None,
            duration_seconds=None,
            status=None,
            plugin_arguments=kwargs_to_manifest_dict(kwargs),
            output_files=[],
            errors=[],
            warnings=[],
            python_version=_python_version(),
            pydfirram_version=_package_version("pydfirram"),
            volatility3_version=_volatility_version(),
            timeout_kind=None,
        )

    def _started_dt(self) -> Optional[datetime]:
        if self.started_at is None:
            return None
        iso = self.started_at.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(iso).astimezone(timezone.utc)
        except ValueError:
            return None

    def finalize(
        self,
        *,
        status: RunStatus,
        ended_at: Optional[str] = None,
        errors: Optional[Iterable[str]] = None,
        warnings: Optional[Iterable[str]] = None,
        output_files: Optional[Iterable[str]] = None,
        dump_sha256: Optional[str] = None,
        artifact_outputs: Optional[Iterable[str]] = None,
    ) -> None:
        self.status = status
        self.ended_at = ended_at or _utc_now_iso()
        if errors is not None:
            self.errors = list(errors)
        if warnings is not None:
            self.warnings = list(warnings)
        if output_files is not None:
            self.output_files = sorted(set(output_files))
        elif artifact_outputs is not None:
            self.output_files = sorted(set(artifact_outputs))

        started = self._started_dt()
        self.duration_seconds = None
        if started is not None and self.ended_at:
            iso_end = self.ended_at.replace("Z", "+00:00")
            try:
                end_dt = datetime.fromisoformat(iso_end).astimezone(timezone.utc)
                self.duration_seconds = max(
                    0.0, (end_dt - started.astimezone(timezone.utc)).total_seconds()
                )
            except ValueError:
                self.duration_seconds = None

        if dump_sha256 is not None:
            self.dump_sha256 = dump_sha256

    def compute_dump_sha256(self, chunk_size: int = 65536) -> Optional[str]:
        path = Path(self.dump_path)
        if not path.is_file():
            return None
        h = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                if not chunk:
                    break
                h.update(chunk)
        self.dump_sha256 = h.hexdigest()
        return self.dump_sha256

    def to_serializable_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for f in fields(self):
            key = f.name
            val = getattr(self, key)
            if isinstance(val, RunStatus):
                val = val.value
            elif isinstance(val, Path):
                val = val.as_posix()
            payload[key] = val
        return payload

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_serializable_dict(), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> RunManifest:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if "status" in raw and raw["status"]:
            raw["status"] = RunStatus(str(raw["status"]))
        kw = {}
        manifest_fields = {f.name for f in fields(cls)}
        for key, val in raw.items():
            if key in manifest_fields:
                kw[key] = val
        return cls(**kw)


def relativize_existing_files(run_root: Path, dirs: Iterable[Path]) -> list[str]:
    """List files under workspace subfolders as POSIX paths relative to *run_root*."""
    collected: list[str] = []
    resolved_root = run_root.resolve()
    for base in dirs:
        if not base.exists():
            continue
        resolved_base = base.resolve()
        try:
            for path in resolved_base.rglob("*"):
                if path.is_dir():
                    continue
                if path.name == MANIFEST_NAME:
                    continue
                rel = path.relative_to(resolved_root)
                collected.append(rel.as_posix())
        except ValueError:
            continue
    return sorted(set(collected))


class WorkspaceManager:
    """Creates the canonical ``runs/<run_id>/`` directory tree."""

    def __init__(self, base_directory: Path, *, collision_policy: CollisionPolicy = "fail"):
        self.base_directory = Path(base_directory).expanduser().resolve()
        self.collision_policy = collision_policy
        if collision_policy != "fail":
            raise InvalidPluginArgumentError(
                "Politique de collision workspace invalide : seuls les dossiers exclusifs "
                "avec policy 'fail' sont supportes actuellement."
            )

    @property
    def runs_directory(self) -> Path:
        return self.base_directory / RUN_LAYOUT_PREFIX

    def planned_paths(self, run_id: str) -> RunWorkspacePaths:
        sanitized = sanitize_run_identifier(run_id)
        root = self.runs_directory / sanitized
        return RunWorkspacePaths(
            root=root,
            manifest=root / MANIFEST_NAME,
            logs=root / "logs",
            tables=root / "tables",
            extracted=root / "extracted",
            tmp=root / "tmp",
        )

    def create_run_workspace(self, run_id: Optional[str] = None) -> tuple[str, RunWorkspacePaths]:
        """Allocate *runs/<run_id>/* folders; refuses pre-existing workspaces."""
        rid = sanitize_run_identifier(run_id) if run_id else uuid.uuid4().hex
        paths = self.planned_paths(rid)
        if paths.root.exists():
            raise WorkspaceConflictError(
                f"Un workspace existe deja pour ce run_id: '{rid}' sous {paths.root}."
            )
        paths.logs.mkdir(parents=True)
        paths.tables.mkdir(parents=True)
        paths.extracted.mkdir(parents=True)
        paths.tmp.mkdir(parents=True)
        return rid, paths


class ArtifactManager:
    """Track outputs under one run workspace without silently overwriting."""

    def __init__(self, *, run_root: Path, collision_policy: CollisionPolicy = "fail"):
        self.run_root = Path(run_root).resolve()
        self.collision_policy = collision_policy
        self._records: dict[str, str] = {}

    def _posix_rel(self, path: Path) -> str:
        rel = Path(path).resolve().relative_to(self.run_root)
        return rel.as_posix()

    def path_for_workspace_relative(self, relative: str) -> Path:
        """Resolve *relative* (POSIX segments) beneath :attr:`run_root`."""
        if not relative.strip() or ".." in Path(relative).parts:
            raise ArtifactAlreadyExistsError("Chemin d'artefact relatif invalide.")
        return (self.run_root / relative.replace("\\", "/")).resolve(strict=False)

    def ensure_available(self, target: Path) -> None:
        """Fail fast if *target* already exists ("fail"), or defer to policy."""
        if self.collision_policy == "overwrite":
            return
        if not target.exists():
            return
        if self.collision_policy == "unique":
            return
        raise ArtifactAlreadyExistsError(
            f"Artefact deja present (policy={self.collision_policy}): {target}"
        )

    def propose_table_path(self, filename: str) -> Path:
        """Return tables/<sanitized basename> respecting collision policy."""
        safe = Path(filename).name.strip()
        if not safe:
            raise ArtifactAlreadyExistsError("Nom de table invalide.")
        target = self.run_root / "tables" / safe
        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True)
        self.ensure_available(target)

        candidate = target
        if self.collision_policy == "unique" and target.exists():
            base_stem = target.stem
            suffix = target.suffix
            n = 1
            candidate = parent / f"{base_stem}-{n}{suffix}"
            while candidate.exists():
                n += 1
                candidate = parent / f"{base_stem}-{n}{suffix}"
        return candidate

    def record_output(self, path: Path) -> str:
        """Register *path* relative to workspace (used for manifests)."""
        rel = self._posix_rel(path)
        canonical = str(path.resolve())
        if rel in self._records and self._records[rel] != canonical:
            raise ArtifactAlreadyExistsError(f"Doublon d'enregistrement manifeste pour {rel}")
        self._records[rel] = canonical
        return rel

    def outputs(self) -> list[str]:
        return sorted(self._records.keys())

