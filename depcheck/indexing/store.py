from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Self

from depcheck.model import AnalysisReport
from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ImportEvidence,
    ImportScanResult,
    ManifestParseResult,
    SourceLocation,
)
from depcheck.model import EvidenceBundle, ResolvedDependencyLink
from depcheck.indexing.models import INDEX_SCHEMA


class IndexStore:
    """SQLite 证据仓库；所有批量更新都在同一事务内提交。"""

    def __init__(self, project_root: Path, index_path: Path | None = None) -> None:
        self.project_root = Path(project_root).resolve()
        self._explicit_index_path = index_path is not None
        self.path = (
            Path(index_path).resolve()
            if index_path is not None
            else self.project_root / ".depcheck" / "index.sqlite3"
        )
        self.rebuilt = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = self._connect()
        self._prepare_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _prepare_database(self) -> None:
        existing_schema = self._existing_schema()
        if existing_schema is not None and existing_schema != INDEX_SCHEMA:
            self.connection.close()
            self._validate_rebuild_target()
            self.path.unlink()
            self.connection = self._connect()
            self.rebuilt = True
        self._initialize()
        self.set_metadata({"schema": INDEX_SCHEMA})
        self.connection.commit()

    def _existing_schema(self) -> str | None:
        tables = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if not tables:
            return None
        if "metadata" not in tables:
            return "legacy"
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema'"
        ).fetchone()
        return str(row[0]) if row is not None else "legacy"

    def _validate_rebuild_target(self) -> None:
        if not self.path.is_file():
            raise ValueError(f"index rebuild target is not a file: {self.path}")
        if self._explicit_index_path:
            if self.path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
                raise ValueError(
                    "explicit index path must use .db, .sqlite, or .sqlite3"
                )
            return
        cache_root = (self.project_root / ".depcheck").resolve()
        if self.path.parent != cache_root or self.path.name != "index.sqlite3":
            raise ValueError(f"refusing to rebuild unexpected cache path: {self.path}")

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK (kind IN ('python', 'manifest')),
                digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS imports (
                file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                module TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER,
                scope TEXT NOT NULL,
                import_kind TEXT NOT NULL,
                PRIMARY KEY (
                    file_path, module, line, column_number, scope, import_kind
                )
            );
            CREATE TABLE IF NOT EXISTS source_diagnostics (
                file_path TEXT NOT NULL REFERENCES files(path) ON DELETE CASCADE,
                code TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER
            );
            CREATE TABLE IF NOT EXISTS declarations (
                source_path TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER,
                raw_requirement TEXT NOT NULL,
                dependency_group TEXT NOT NULL,
                declaration_kind TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS manifest_diagnostics (
                code TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source_path TEXT,
                line INTEGER,
                column_number INTEGER
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL,
                package TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                locations_json TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS findings_package_idx
                ON findings(package, code);
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                project_root TEXT NOT NULL,
                language TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                manager TEXT NOT NULL,
                manifests_json TEXT NOT NULL,
                locks_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS normalized_declarations (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                display_name TEXT NOT NULL,
                purl TEXT,
                constraint_raw TEXT NOT NULL,
                constraint_scheme TEXT NOT NULL,
                constraint_normalized TEXT,
                source_path TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER,
                scope TEXT NOT NULL,
                declaration_kind TEXT NOT NULL,
                marker TEXT,
                metadata_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resolved_dependencies (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                display_name TEXT NOT NULL,
                purl TEXT,
                version TEXT NOT NULL,
                source_path TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER,
                direct INTEGER NOT NULL,
                integrity TEXT,
                instance_id TEXT
            );
            CREATE TABLE IF NOT EXISTS dependency_edges (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                parent_ecosystem TEXT NOT NULL,
                parent_package TEXT NOT NULL,
                parent_version TEXT NOT NULL,
                parent_instance_id TEXT,
                child_ecosystem TEXT NOT NULL,
                child_package TEXT NOT NULL,
                child_display_name TEXT NOT NULL,
                child_purl TEXT,
                child_version TEXT,
                child_instance_id TEXT
            );
            CREATE TABLE IF NOT EXISTS usages (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                language TEXT NOT NULL,
                reference TEXT NOT NULL,
                source_path TEXT NOT NULL,
                line INTEGER,
                column_number INTEGER,
                scope TEXT NOT NULL,
                usage_kind TEXT NOT NULL,
                mapped_ecosystem TEXT,
                mapped_package TEXT,
                mapped_display_name TEXT,
                mapped_purl TEXT,
                mapping_confidence TEXT NOT NULL,
                mapping_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS normalized_source_files (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                source_path TEXT NOT NULL,
                PRIMARY KEY(project_id, source_path)
            );
            CREATE TABLE IF NOT EXISTS capabilities (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                name TEXT NOT NULL,
                complete INTEGER NOT NULL,
                reason TEXT,
                PRIMARY KEY(project_id, name)
            );
            CREATE TABLE IF NOT EXISTS normalized_diagnostics (
                project_id TEXT NOT NULL REFERENCES projects(project_id)
                    ON DELETE CASCADE,
                code TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source_path TEXT,
                line INTEGER,
                column_number INTEGER
            );
            CREATE INDEX IF NOT EXISTS normalized_declarations_package_idx
                ON normalized_declarations(project_id, ecosystem, package);
            CREATE INDEX IF NOT EXISTS resolved_dependencies_package_idx
                ON resolved_dependencies(project_id, ecosystem, package);
            CREATE INDEX IF NOT EXISTS usages_package_idx
                ON usages(project_id, mapped_ecosystem, mapped_package);
            """
        )
        self.connection.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def metadata(self) -> dict[str, str]:
        rows = self.connection.execute("SELECT key, value FROM metadata")
        return {str(row["key"]): str(row["value"]) for row in rows}

    def set_metadata(self, values: Mapping[str, str]) -> None:
        self.connection.executemany(
            """
            INSERT INTO metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            sorted(values.items()),
        )

    def file_digests(self, kind: str) -> dict[str, str]:
        rows = self.connection.execute(
            "SELECT path, digest FROM files WHERE kind = ? ORDER BY path", (kind,)
        )
        return {str(row["path"]): str(row["digest"]) for row in rows}

    def remove_files(self, paths: Sequence[str]) -> None:
        self.connection.executemany(
            "DELETE FROM files WHERE path = ?", ((path,) for path in paths)
        )

    def replace_python_file(
        self,
        relative_path: str,
        digest: str,
        imports: Sequence[ImportEvidence],
        diagnostics: Sequence[Diagnostic],
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO files(path, kind, digest) VALUES (?, 'python', ?)
            ON CONFLICT(path) DO UPDATE SET kind = 'python', digest = excluded.digest
            """,
            (relative_path, digest),
        )
        self.connection.execute(
            "DELETE FROM imports WHERE file_path = ?", (relative_path,)
        )
        self.connection.execute(
            "DELETE FROM source_diagnostics WHERE file_path = ?", (relative_path,)
        )
        self.connection.executemany(
            """
            INSERT INTO imports(
                file_path, module, line, column_number, scope, import_kind
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    relative_path,
                    item.module,
                    item.source.line,
                    item.source.column,
                    item.scope,
                    item.kind,
                )
                for item in imports
            ),
        )
        self.connection.executemany(
            """
            INSERT INTO source_diagnostics(
                file_path, code, severity, message, line, column_number
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    relative_path,
                    item.code,
                    item.severity,
                    item.message,
                    item.source.line if item.source else None,
                    item.source.column if item.source else None,
                )
                for item in diagnostics
            ),
        )

    def load_imports(self) -> ImportScanResult:
        file_rows = list(
            self.connection.execute(
                "SELECT path FROM files WHERE kind = 'python' ORDER BY path"
            )
        )
        import_rows = self.connection.execute(
            """
            SELECT file_path, module, line, column_number, scope, import_kind
            FROM imports
            ORDER BY file_path, line, column_number, module
            """
        )
        diagnostic_rows = self.connection.execute(
            """
            SELECT file_path, code, severity, message, line, column_number
            FROM source_diagnostics
            ORDER BY file_path, line, code
            """
        )
        imports = tuple(
            ImportEvidence(
                module=str(row["module"]),
                source=SourceLocation(
                    self.project_root / str(row["file_path"]),
                    line=row["line"],
                    column=row["column_number"],
                ),
                scope=str(row["scope"]),
                kind=str(row["import_kind"]),
            )
            for row in import_rows
        )
        diagnostics = tuple(
            Diagnostic(
                code=str(row["code"]),
                severity=str(row["severity"]),
                message=str(row["message"]),
                source=SourceLocation(
                    self.project_root / str(row["file_path"]),
                    line=row["line"],
                    column=row["column_number"],
                ),
            )
            for row in diagnostic_rows
        )
        files = tuple(self.project_root / str(row["path"]) for row in file_rows)
        return ImportScanResult(imports=imports, diagnostics=diagnostics, files=files)

    def replace_manifests(
        self,
        result: ManifestParseResult,
        digests: Mapping[str, str],
    ) -> None:
        self.connection.execute("DELETE FROM files WHERE kind = 'manifest'")
        self.connection.execute("DELETE FROM declarations")
        self.connection.execute("DELETE FROM manifest_diagnostics")
        self.connection.executemany(
            "INSERT INTO files(path, kind, digest) VALUES (?, 'manifest', ?)",
            sorted(digests.items()),
        )
        self.connection.executemany(
            """
            INSERT INTO declarations(
                source_path, line, column_number, raw_requirement,
                dependency_group, declaration_kind
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    self._relative(item.source.path),
                    item.source.line,
                    item.source.column,
                    item.raw_requirement,
                    item.group,
                    item.kind,
                )
                for item in result.declarations
            ),
        )
        self.connection.executemany(
            """
            INSERT INTO manifest_diagnostics(
                code, severity, message, source_path, line, column_number
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    item.code,
                    item.severity,
                    item.message,
                    self._relative(item.source.path) if item.source else None,
                    item.source.line if item.source else None,
                    item.source.column if item.source else None,
                )
                for item in result.diagnostics
            ),
        )

    def load_manifests(self) -> ManifestParseResult:
        file_rows = list(
            self.connection.execute(
                "SELECT path FROM files WHERE kind = 'manifest' ORDER BY path"
            )
        )
        declaration_rows = self.connection.execute(
            """
            SELECT source_path, line, column_number, raw_requirement,
                   dependency_group, declaration_kind
            FROM declarations
            ORDER BY source_path, line, raw_requirement
            """
        )
        diagnostic_rows = self.connection.execute(
            """
            SELECT code, severity, message, source_path, line, column_number
            FROM manifest_diagnostics
            ORDER BY source_path, line, code
            """
        )
        declarations = tuple(
            PythonRequirement.from_requirement(
                str(row["raw_requirement"]),
                source=SourceLocation(
                    self.project_root / str(row["source_path"]),
                    line=row["line"],
                    column=row["column_number"],
                ),
                group=str(row["dependency_group"]),
                kind=str(row["declaration_kind"]),
            )
            for row in declaration_rows
        )
        diagnostics = tuple(
            Diagnostic(
                code=str(row["code"]),
                severity=str(row["severity"]),
                message=str(row["message"]),
                source=(
                    SourceLocation(
                        self.project_root / str(row["source_path"]),
                        line=row["line"],
                        column=row["column_number"],
                    )
                    if row["source_path"] is not None
                    else None
                ),
            )
            for row in diagnostic_rows
        )
        files = tuple(self.project_root / str(row["path"]) for row in file_rows)
        return ManifestParseResult(
            declarations=declarations,
            diagnostics=diagnostics,
            files=files,
        )

    def replace_analysis(self, report: AnalysisReport) -> None:
        self.connection.execute("DELETE FROM findings")
        self.connection.executemany(
            """
            INSERT INTO findings(
                code, package, severity, message, locations_json, details_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    item.code,
                    item.package.name,
                    item.severity,
                    item.message,
                    json.dumps(
                        [
                            location.to_dict(self.project_root)
                            for location in item.locations
                        ],
                        sort_keys=True,
                    ),
                    json.dumps(
                        {
                            **item.package.to_dict(),
                            **dict(item.details),
                        },
                        sort_keys=True,
                    ),
                )
                for item in report.findings
            ),
        )

    def replace_evidence(self, bundles: Sequence[EvidenceBundle]) -> None:
        """Replace the normalized repository snapshot inside the caller's transaction."""
        self.connection.execute("DELETE FROM projects")
        for bundle in bundles:
            project = bundle.project
            self.connection.execute(
                """
                INSERT INTO projects(
                    project_id, project_root, language, ecosystem, manager,
                    manifests_json, locks_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project.project_id,
                    project.root.as_posix(),
                    project.language,
                    project.ecosystem,
                    project.manager,
                    json.dumps(
                        [path.as_posix() for path in project.manifests],
                        sort_keys=True,
                    ),
                    json.dumps(
                        [path.as_posix() for path in project.locks],
                        sort_keys=True,
                    ),
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO normalized_declarations(
                    project_id, ecosystem, package, display_name, purl,
                    constraint_raw, constraint_scheme, constraint_normalized,
                    source_path, line, column_number, scope, declaration_kind,
                    marker, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        item.project_id,
                        item.package.ecosystem,
                        item.package.name,
                        item.package.display_name,
                        item.package.purl,
                        item.constraint.raw,
                        item.constraint.scheme,
                        item.constraint.normalized,
                        self._relative(item.source.path),
                        item.source.line,
                        item.source.column,
                        item.scope,
                        item.kind,
                        item.marker,
                        json.dumps(dict(item.metadata), sort_keys=True, default=str),
                    )
                    for item in bundle.declarations
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO resolved_dependencies(
                    project_id, ecosystem, package, display_name, purl, version,
                    source_path, line, column_number, direct, integrity, instance_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        item.project_id,
                        item.package.ecosystem,
                        item.package.name,
                        item.package.display_name,
                        item.package.purl,
                        item.version,
                        self._relative(item.source.path),
                        item.source.line,
                        item.source.column,
                        int(item.direct),
                        item.integrity,
                        item.instance_id,
                    )
                    for item in bundle.resolved
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO dependency_edges(
                    project_id, parent_ecosystem, parent_package, parent_version,
                    parent_instance_id, child_ecosystem, child_package,
                    child_display_name, child_purl, child_version, child_instance_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        item.project_id,
                        item.package.ecosystem,
                        item.package.name,
                        item.version,
                        item.instance_id,
                        link.package.ecosystem,
                        link.package.name,
                        link.package.display_name,
                        link.package.purl,
                        link.version,
                        link.instance_id,
                    )
                    for item in bundle.resolved
                    for link in (
                        item.dependency_links
                        or tuple(_legacy_link(child) for child in item.dependencies)
                    )
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO usages(
                    project_id, language, reference, source_path, line,
                    column_number, scope, usage_kind, mapped_ecosystem,
                    mapped_package, mapped_display_name, mapped_purl,
                    mapping_confidence, mapping_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        item.project_id,
                        item.language,
                        item.reference,
                        self._relative(item.source.path),
                        item.source.line,
                        item.source.column,
                        item.scope,
                        item.kind,
                        (
                            item.mapped_package.ecosystem
                            if item.mapped_package is not None
                            else None
                        ),
                        (
                            item.mapped_package.name
                            if item.mapped_package is not None
                            else None
                        ),
                        (
                            item.mapped_package.display_name
                            if item.mapped_package is not None
                            else None
                        ),
                        (
                            item.mapped_package.purl
                            if item.mapped_package is not None
                            else None
                        ),
                        item.mapping_confidence.value,
                        item.mapping_reason,
                    )
                    for item in bundle.usages
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO normalized_source_files(project_id, source_path)
                VALUES (?, ?)
                """,
                (
                    (project.project_id, self._relative(path))
                    for path in bundle.source_files
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO capabilities(project_id, name, complete, reason)
                VALUES (?, ?, ?, ?)
                """,
                (
                    (project.project_id, item.name, int(item.complete), item.reason)
                    for item in bundle.capabilities
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO normalized_diagnostics(
                    project_id, code, severity, message, source_path, line,
                    column_number
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        project.project_id,
                        item.code,
                        item.severity,
                        item.message,
                        self._relative(item.source.path) if item.source else None,
                        item.source.line if item.source else None,
                        item.source.column if item.source else None,
                    )
                    for item in bundle.diagnostics
                ),
            )

    def findings(
        self, *, package: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if limit < 1:
            raise ValueError("limit must be positive")
        sql = (
            "SELECT code, package, severity, message, locations_json, details_json "
            "FROM findings"
        )
        parameters: list[Any] = []
        if package is not None:
            sql += " WHERE package = ?"
            parameters.append(package)
        sql += " ORDER BY code, package, message LIMIT ?"
        parameters.append(limit)
        rows = self.connection.execute(sql, parameters)
        return [
            {
                "code": str(row["code"]),
                "package": str(row["package"]),
                "severity": str(row["severity"]),
                "message": str(row["message"]),
                "locations": json.loads(str(row["locations_json"])),
                "details": json.loads(str(row["details_json"])),
            }
            for row in rows
        ]

    def projects(self) -> list[dict[str, Any]]:
        capabilities: dict[str, dict[str, dict[str, Any]]] = {}
        for row in self.connection.execute(
            """
            SELECT project_id, name, complete, reason
            FROM capabilities
            ORDER BY project_id, name
            """
        ):
            capabilities.setdefault(str(row["project_id"]), {})[str(row["name"])] = {
                "complete": bool(row["complete"]),
                "reason": row["reason"],
            }
        source_files: dict[str, list[str]] = {}
        for row in self.connection.execute(
            """
            SELECT project_id, source_path
            FROM normalized_source_files
            ORDER BY project_id, source_path
            """
        ):
            source_files.setdefault(str(row["project_id"]), []).append(
                str(row["source_path"])
            )
        rows = self.connection.execute(
            """
            SELECT project_id, project_root, language, ecosystem, manager
            FROM projects
            ORDER BY project_id
            """
        )
        return [
            {
                "project_id": str(row["project_id"]),
                "root": str(row["project_root"]),
                "language": str(row["language"]),
                "ecosystem": str(row["ecosystem"]),
                "manager": str(row["manager"]),
                "capabilities": capabilities.get(str(row["project_id"]), {}),
                "source_file_count": len(source_files.get(str(row["project_id"]), [])),
                "source_files": source_files.get(str(row["project_id"]), []),
            }
            for row in rows
        ]

    def ecosystem_summary(self) -> dict[str, dict[str, int]]:
        rows = self.connection.execute(
            """
            SELECT p.ecosystem,
                   COUNT(DISTINCT p.project_id) AS project_count,
                   COUNT(DISTINCT d.rowid) AS declaration_count,
                   COUNT(DISTINCT u.rowid) AS usage_count,
                   COUNT(DISTINCT s.rowid) AS source_file_count
            FROM projects AS p
            LEFT JOIN normalized_declarations AS d
              ON d.project_id = p.project_id
            LEFT JOIN usages AS u
              ON u.project_id = p.project_id
            LEFT JOIN normalized_source_files AS s
              ON s.project_id = p.project_id
            GROUP BY p.ecosystem
            ORDER BY lower(p.ecosystem)
            """
        )
        return {
            str(row["ecosystem"]): {
                "project_count": int(row["project_count"]),
                "declaration_count": int(row["declaration_count"]),
                "usage_count": int(row["usage_count"]),
                "source_file_count": int(row["source_file_count"]),
            }
            for row in rows
        }

    def dependency_inventory(
        self,
        *,
        search: str | None = None,
        ecosystem: str | None = None,
        project_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """按发行包聚合声明、导入与 finding，只返回结构化证据。"""
        if limit < 1:
            raise ValueError("limit must be positive")
        project_count = self.connection.execute(
            "SELECT COUNT(*) FROM projects"
        ).fetchone()[0]
        if project_count:
            return self._normalized_dependency_inventory(
                search=search,
                ecosystem=ecosystem,
                project_id=project_id,
                limit=limit,
            )
        metadata = self.metadata()
        import_mapping = json.loads(metadata.get("import_mapping", "{}"))
        packages: dict[str, dict[str, Any]] = {}

        declaration_rows = self.connection.execute(
            """
            SELECT source_path, line, column_number, raw_requirement,
                   dependency_group, declaration_kind
            FROM declarations
            ORDER BY source_path, line, raw_requirement
            """
        )
        for row in declaration_rows:
            declaration = PythonRequirement.from_requirement(
                str(row["raw_requirement"]),
                source=SourceLocation(
                    self.project_root / str(row["source_path"]),
                    line=row["line"],
                    column=row["column_number"],
                ),
                group=str(row["dependency_group"]),
                kind=str(row["declaration_kind"]),
            )
            record = packages.setdefault(
                declaration.name, _empty_dependency(declaration.name)
            )
            record["declarations"].append(
                {
                    "requirement": declaration.raw_requirement,
                    "group": declaration.group,
                    "kind": declaration.kind,
                    "location": _row_location(row, "source_path"),
                }
            )

        import_rows = self.connection.execute(
            """
            SELECT file_path, module, line, column_number, scope, import_kind
            FROM imports
            ORDER BY module, file_path, line
            """
        )
        for row in import_rows:
            module = str(row["module"])
            package = str(import_mapping.get(module, module))
            record = packages.setdefault(package, _empty_dependency(package))
            record["imports"].append(
                {
                    "module": module,
                    "scope": str(row["scope"]),
                    "kind": str(row["import_kind"]),
                    "location": _row_location(row, "file_path"),
                }
            )

        for finding in self.findings(limit=10000):
            package = str(finding["package"])
            record = packages.setdefault(package, _empty_dependency(package))
            record["findings"].append(finding)

        needle = (search or "").strip().lower()
        results: list[dict[str, Any]] = []
        for package in sorted(packages):
            record = packages[package]
            if (
                needle
                and needle not in package.lower()
                and not any(
                    needle in str(item["module"]).lower() for item in record["imports"]
                )
            ):
                continue
            record["declared"] = bool(record["declarations"])
            record["imported"] = bool(record["imports"])
            results.append(record)
            if len(results) == limit:
                break
        return results

    def _normalized_dependency_inventory(
        self,
        *,
        search: str | None,
        ecosystem: str | None,
        project_id: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        projects = {
            str(row["project_id"]): row
            for row in self.connection.execute(
                "SELECT project_id, ecosystem, manager FROM projects"
            )
            if project_id is None or str(row["project_id"]) == project_id
        }
        records: dict[tuple[str, str, str], dict[str, Any]] = {}

        def record_for(
            row: sqlite3.Row,
            *,
            ecosystem_key: str = "ecosystem",
            package_key: str = "package",
            display_key: str = "display_name",
            purl_key: str = "purl",
        ) -> dict[str, Any] | None:
            row_project_id = str(row["project_id"])
            project = projects.get(row_project_id)
            if project is None:
                return None
            row_ecosystem = str(row[ecosystem_key])
            if ecosystem is not None and row_ecosystem.lower() != ecosystem.lower():
                return None
            package = str(row[package_key])
            key = (row_project_id, row_ecosystem.lower(), package)
            return records.setdefault(
                key,
                {
                    "project_id": row_project_id,
                    "ecosystem": row_ecosystem,
                    "manager": str(project["manager"]),
                    "package": package,
                    "display_name": str(row[display_key]),
                    "purl": row[purl_key],
                    "declared": False,
                    "imported": False,
                    "resolved_version": None,
                    "resolved_versions": [],
                    "declarations": [],
                    "usages": [],
                    "imports": [],
                    "findings": [],
                },
            )

        declaration_rows = self.connection.execute(
            """
            SELECT project_id, ecosystem, package, display_name, purl,
                   constraint_raw, constraint_scheme, constraint_normalized,
                   source_path, line, column_number, scope, declaration_kind,
                   marker, metadata_json
            FROM normalized_declarations
            ORDER BY project_id, ecosystem, package, source_path, line
            """
        )
        for row in declaration_rows:
            record = record_for(row)
            if record is None:
                continue
            record["declarations"].append(
                {
                    "constraint": {
                        "raw": str(row["constraint_raw"]),
                        "scheme": str(row["constraint_scheme"]),
                        "normalized": row["constraint_normalized"],
                    },
                    "scope": str(row["scope"]),
                    "kind": str(row["declaration_kind"]),
                    "marker": row["marker"],
                    "metadata": json.loads(str(row["metadata_json"])),
                    "location": _row_location(row, "source_path"),
                }
            )

        resolved_rows = self.connection.execute(
            """
            SELECT project_id, ecosystem, package, display_name, purl, version,
                   source_path, line, column_number, direct, integrity
            FROM resolved_dependencies
            ORDER BY project_id, ecosystem, package, version
            """
        )
        for row in resolved_rows:
            record = record_for(row)
            if record is not None:
                record["resolved_versions"].append(str(row["version"]))

        usage_rows = self.connection.execute(
            """
            SELECT project_id, language, reference, source_path, line,
                   column_number, scope, usage_kind, mapped_ecosystem,
                   mapped_package, mapped_display_name, mapped_purl,
                   mapping_confidence, mapping_reason
            FROM usages
            WHERE mapped_package IS NOT NULL
            ORDER BY project_id, mapped_ecosystem, mapped_package, source_path, line
            """
        )
        for row in usage_rows:
            record = record_for(
                row,
                ecosystem_key="mapped_ecosystem",
                package_key="mapped_package",
                display_key="mapped_display_name",
                purl_key="mapped_purl",
            )
            if record is None:
                continue
            usage = {
                "language": str(row["language"]),
                "reference": str(row["reference"]),
                "scope": str(row["scope"]),
                "kind": str(row["usage_kind"]),
                "mapping_confidence": str(row["mapping_confidence"]),
                "mapping_reason": row["mapping_reason"],
                "location": _row_location(row, "source_path"),
            }
            record["usages"].append(usage)
            record["imports"].append(usage)

        findings_by_identity: dict[
            tuple[str, str, str],
            list[dict[str, Any]],
        ] = {}
        legacy_python_findings: dict[str, list[dict[str, Any]]] = {}
        for finding in self.findings(limit=10000):
            details = finding.get("details", {})
            finding_project = details.get("project_id")
            finding_ecosystem = details.get("ecosystem")
            package = str(finding["package"])
            if finding_project and finding_ecosystem:
                key = (
                    str(finding_project),
                    str(finding_ecosystem).lower(),
                    package,
                )
                findings_by_identity.setdefault(key, []).append(finding)
            else:
                legacy_python_findings.setdefault(package, []).append(finding)

        needle = (search or "").strip().lower()
        results: list[dict[str, Any]] = []
        for key in sorted(records):
            record = records[key]
            versions = sorted(set(record["resolved_versions"]))
            record["resolved_versions"] = versions
            record["resolved_version"] = versions[0] if len(versions) == 1 else None
            record["declared"] = bool(record["declarations"])
            record["imported"] = bool(record["usages"])
            record["findings"] = findings_by_identity.get(key, [])
            if not record["findings"] and record["ecosystem"].lower() == "pypi":
                record["findings"] = legacy_python_findings.get(
                    record["package"],
                    [],
                )
            if needle and not _normalized_record_matches(record, needle):
                continue
            results.append(record)
            if len(results) == limit:
                break
        return results

    def _relative(self, path: Path) -> str:
        return Path(path).resolve().relative_to(self.project_root).as_posix()


def _empty_dependency(package: str) -> dict[str, Any]:
    return {
        "package": package,
        "declared": False,
        "imported": False,
        "resolved_version": None,
        "resolved_versions": [],
        "declarations": [],
        "imports": [],
        "findings": [],
    }


def _legacy_link(package: Any) -> ResolvedDependencyLink:
    return ResolvedDependencyLink(package=package)


def _normalized_record_matches(record: Mapping[str, Any], needle: str) -> bool:
    searchable = [
        record.get("package"),
        record.get("display_name"),
        record.get("purl"),
        *(
            usage.get("reference")
            for usage in record.get("usages", [])
            if isinstance(usage, Mapping)
        ),
    ]
    return any(needle in str(value).lower() for value in searchable if value)


def _row_location(row: sqlite3.Row, path_key: str) -> dict[str, Any]:
    location: dict[str, Any] = {"path": str(row[path_key])}
    if row["line"] is not None:
        location["line"] = int(row["line"])
    if row["column_number"] is not None:
        location["column"] = int(row["column_number"])
    return location
