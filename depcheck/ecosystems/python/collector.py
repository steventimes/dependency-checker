from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from depcheck.ecosystems.coverage import is_pylock_file
from depcheck.ecosystems.python.imports import ImportScanner
from depcheck.ecosystems.python.manifest import (
    IGNORED_DIRECTORIES,
    PythonManifestCollector,
    is_requirements_file,
    parser_map,
)
from depcheck.ecosystems.python.script import inline_script_files, parse_inline_script
from depcheck.ecosystems.python.source_policy import (
    bounded_uv_sources,
    source_assertion_digest,
    uv_source_origin,
)
from depcheck.ecosystems.registry import EcosystemPack, ProviderContext
from depcheck.ecosystems.static import discover_files, exclusions_for, read_text
from depcheck.filesystem import repository_operation
from depcheck.filesystem.positions import SourcePositions
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    ImportEvidence,
    ImportScanResult,
    ManifestParseResult,
    MappingConfidence,
    PackageRef,
    ProjectUnit,
    PythonRequirement,
    ResolvedDependency,
    ResolvedDependencyLink,
    SourceLocation,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.profiling import measured

DEFAULT_IMPORT_MAP: dict[str, str] = {
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "git": "gitpython",
    "jose": "python-jose",
    "jwt": "pyjwt",
    "mysqldb": "mysqlclient",
    "pil": "pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
}


_MANIFEST_RESULT = "python_manifest_result"
_USAGE_RESULT = "python_usage_result"
_LOCK_NAMES = frozenset({"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"})
_PYTHON_LOCK_EDGE_WORK = 100_000
_PYTHON_DIRECT_BINDING_WORK = 100_000
_UV_INHERITED_BYTES = 1_048_576


def named_component_roots(
    root: Path, settings: Mapping[str, object]
) -> tuple[Path, ...]:
    configured = settings.get("python_roots", ())
    roots = (
        [Path(p) for p in configured if isinstance(p, str)]
        if isinstance(configured, (list, tuple))
        else []
    )
    for path in discover_files(
        root,
        names=frozenset({"pyproject.toml"}),
        excluded_directories=exclusions_for(settings),
    ):
        try:
            data = tomllib.loads(read_text(path))
            name = data.get("project", {}).get("name") or data.get("tool", {}).get(
                "poetry", {}
            ).get("name")
            if (isinstance(name, str) and name.strip()) or "workspace" in data.get(
                "tool", {}
            ).get("uv", {}):
                roots.append(path.parent.relative_to(root))
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            continue
    return tuple(sorted(set(roots), key=lambda p: (len(p.parts), p.as_posix())))


def _component_exclusions(
    root: Path, project: ProjectUnit, settings: Mapping[str, object]
) -> tuple[str, ...]:
    exclusions = exclusions_for(settings, project.root)
    children = tuple(
        p.relative_to(project.root).as_posix()
        for p in named_component_roots(root, settings)
        if p != project.root and project.root in p.parents
    )
    return (*exclusions, *children)


class PythonProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        exclusions = exclusions_for(context.settings)
        source_files = ImportScanner(exclusions).discover_files(root)
        scripts = inline_script_files(root, exclusions, paths=source_files)
        script_paths = set(scripts)
        has_python_manifest = _has_manifest_candidate(
            root,
            exclusions,
            include_install_hints=False,
        )
        if not source_files and not has_python_manifest:
            return ()
        manifests = (
            tuple(
                PythonManifestCollector(
                    root,
                    exclusions,
                ).find_dependency_file()
            )
            if _has_manifest_candidate(root, exclusions)
            else ()
        )

        roots = named_component_roots(root, context.settings)
        paths = tuple(_relative(p, root) for p in manifests)

        def owner(path: Path) -> Path:
            return next(
                (p for p in reversed(roots) if p == path.parent or p in path.parents),
                Path("."),
            )

        active_roots = set(roots)
        active_roots.update(
            owner(p)
            for p in (
                *paths,
                *(_relative(p, root) for p in source_files if p not in script_paths),
            )
        )
        if not active_roots and not scripts:
            active_roots.add(Path("."))
        projects = []
        for relative_root in sorted(
            active_roots, key=lambda p: (len(p.parts), p.as_posix())
        ):
            relative_manifests = tuple(p for p in paths if owner(p) == relative_root)
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "PyPI", "python"),
                    root=relative_root,
                    language="python",
                    ecosystem="PyPI",
                    manager="python",
                    manifests=relative_manifests,
                    locks=tuple(
                        p
                        for p in relative_manifests
                        if p.name in _LOCK_NAMES
                        or is_pylock_file(p)
                        or (p.suffix.lower() == ".lock" and is_requirements_file(p))
                    ),
                )
            )
        projects.extend(
            ProjectUnit(
                project_id=ProjectUnit.stable_id(
                    script.relative_to(root), "PyPI", "pep723"
                ),
                root=script.parent.relative_to(root),
                language="python",
                ecosystem="PyPI",
                manager="pep723",
                manifests=(script.relative_to(root),),
            )
            for script in scripts
        )
        return tuple(projects)


class PythonManifestProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[DependencyDeclaration, ...]:
        result = _manifest_result(context, project)
        return tuple(
            _adapt_declaration(project.project_id, item) for item in result.declarations
        )


class PythonResolutionProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[ResolvedDependency, ...]:
        result = _manifest_result(context, project)
        direct_names = {
            item.name
            for item in result.declarations
            if item.kind == "direct" and item.group != "build"
        }
        resolved: list[ResolvedDependency] = []
        seen: set[tuple[str, str, str]] = set()
        locked_names = {i.name for i in result.declarations if i.kind == "locked"}
        overrides = {
            i.name: dict(i.origin)
            for i in result.declarations
            if i.kind in {"direct", "constraint"}
            and i.origin.get("public") is False
            and "inherited_uv_source" not in i.metadata
            and not (
                i.origin.get("kind") == "unknown" and i.metadata.get("uv_index_policy")
            )
        }
        for item in result.declarations:
            version = item.pinned_version
            if version is None or item.kind not in {"direct", "locked"}:
                continue
            if item.kind == "direct" and item.name in locked_names:
                continue
            metadata = dict(item.metadata)
            inherited_policy = metadata.get("inherited_source_policy")
            override = overrides.get(item.name, {})
            implicit = (
                item.kind == "locked"
                and item.origin.get("kind") == "registry"
                and "assertion" not in item.origin
                and item.origin.get("location") == "https://pypi.org/simple"
            )
            if (
                item.kind == "locked"
                and not implicit
                and isinstance(override.get("assertion"), dict)
                and "configured_indexes" in override["assertion"]
            ):
                # An explicit lock source is stronger than a global default policy.
                override = {}
            if implicit and isinstance(inherited_policy, dict):
                override = {**override, **inherited_policy}
                metadata["inherited_source_policy"] = inherited_policy
            origin = dict(override or item.origin)
            if "lock" in item.origin:
                origin["lock"] = item.origin["lock"]
            origin_key = json.dumps(origin, sort_keys=True)
            occurrence = None
            if metadata.get("python_kind") == "lock-record":
                occurrence = (
                    _relative(item.source.path, context.repository_root).as_posix()
                    + "\0"
                    + str(metadata["package_index"])
                )
                origin_key += "\0" + occurrence
                metadata["lock_origin"] = {
                    key: value for key, value in item.origin.items() if key != "lock"
                }
                if override:
                    metadata["declared_origin"] = override
            key = (item.name, version, origin_key)
            if key in seen:
                continue
            seen.add(key)
            resolved.append(
                ResolvedDependency(
                    project_id=project.project_id,
                    package=_package_ref(
                        item.name,
                        item.display_name,
                        public=origin.get("public") is True,
                    ),
                    version=version,
                    source=item.source,
                    direct=item.kind == "direct" and item.name in direct_names,
                    origin=origin,
                    instance_id=(
                        "lock:"
                        + str(metadata["lock_format"])
                        + ":"
                        + hashlib.sha256(occurrence.encode()).hexdigest()[:24]
                        if occurrence is not None
                        else None
                        if origin.get("public") is True
                        else "source:"
                        + hashlib.sha256(origin_key.encode()).hexdigest()[:24]
                    ),
                    metadata=metadata,
                )
            )
        return _python_lock_links(_python_direct_bindings(result, resolved))


def _python_direct_bindings(
    manifest: ManifestParseResult, records: list[ResolvedDependency]
) -> list[ResolvedDependency]:
    """Bind declarations to unique compatible occurrences without selecting a lock."""
    declarations = [
        item
        for item in manifest.declarations
        if item.kind == "direct" and item.group != "build"
    ]
    names = {item.name for item in declarations}
    candidates: dict[str, list[int]] = {}
    for index, record in enumerate(records):
        if (
            record.package.name in names
            and record.metadata.get("python_kind") == "lock-record"
        ):
            candidates.setdefault(record.package.name, []).append(index)
    matched: set[int] = set()
    unknown: dict[int, str] = {}
    budget = _PYTHON_DIRECT_BINDING_WORK
    for declaration in declarations:
        indices = candidates.get(declaration.name, [])
        if not indices:
            continue
        budget -= len(indices) * max(1, len(declaration.specifier))
        if budget < 0:
            matched.clear()
            unknown = {
                index: "work-budget-exceeded"
                for indices in candidates.values()
                for index in indices
            }
            break
        possible = []
        confirmed = []
        for index in indices:
            record = records[index]
            if (
                declaration.metadata.get("python_kind") == "pipenv-declaration"
                and record.metadata.get("lock_format") == "pipfile"
            ):
                category = declaration.metadata.get("pipenv_category")
                if category == "packages":
                    category = "default"
                elif category == "dev-packages":
                    category = "develop"
                if category != record.metadata.get("pipenv_category"):
                    continue
            version_match: bool | None
            try:
                # Include recorded prereleases as candidates, without choosing an
                # installer's prerelease policy. PEP 440 range exclusions remain.
                version_match = declaration.specifier.contains(
                    record.version, prereleases=True
                )
            except InvalidVersion:
                version_match = None
            source_match = _python_binding_source(declaration, record)
            if version_match is False or source_match is False:
                continue
            possible.append(index)
            if version_match is True and source_match is True:
                confirmed.append(index)
        if len(possible) == len(confirmed) == 1:
            matched.add(confirmed[0])
        else:
            reason = "ambiguous-or-unverified" if possible else "no-compatible-record"
            for index in possible or indices:
                unknown[index] = reason
    return [
        replace(
            record,
            direct=index in matched,
            metadata={
                **record.metadata,
                "directness_status": "matched-declaration"
                if index in matched
                else "unknown"
                if index in unknown
                else "not-bound-to-declaration",
                **(
                    {"directness_reason": unknown[index]}
                    if index in unknown and index not in matched
                    else {}
                ),
            },
        )
        if record.package.name in candidates
        and record.metadata.get("python_kind") == "lock-record"
        else record
        for index, record in enumerate(records)
    ]


def _python_binding_source(
    declaration: PythonRequirement, record: ResolvedDependency
) -> bool | None:
    original = record.metadata.get("lock_origin", record.origin)
    nonregistry = {"git", "url", "path", "editable", "directory", "workspace"}
    if declaration.origin.get("public") is True:
        if original.get("kind") in nonregistry:
            return False
        if original.get("public") is True and record.origin.get("public") is True:
            return True
    elif declaration.origin.get("kind") in nonregistry:
        if original.get("public") is True:
            return False
    # Redacted URLs, named indexes and local paths do not prove equal artifacts.
    return None


def _python_lock_request(
    name: str | None, value: object, lock_format: str
) -> tuple[str, SpecifierSet, object | None] | None:
    """Interpret only literal unconditional requests; never activate markers/extras."""
    if lock_format == "pdm":
        if not isinstance(value, str):
            return None
        requirement = Requirement(value)
        if requirement.marker or requirement.extras or requirement.url:
            return None
        return requirement.name, requirement.specifier, None
    if lock_format == "uv":
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("name"), str)
            or not value["name"].strip()
        ):
            return None
        if "marker" in value:
            # A present marker is conditional or malformed, even when falsy.
            return None
        for key in ("extra", "extras"):
            if key in value:
                extras = value[key]
                if not isinstance(extras, list) or not all(
                    isinstance(extra, str) and bool(extra.strip()) for extra in extras
                ):
                    return None
                if extras:
                    return None
        if set(value) - {"name", "version", "source", "marker", "extra", "extras"}:
            return None
        version = value.get("version")
        if "version" in value and (not isinstance(version, str) or not version.strip()):
            return None
        source = value.get("source")
        if "source" in value:
            if not isinstance(source, dict) or len(source) != 1:
                return None
            kind, location = next(iter(source.items()))
            if kind == "workspace":
                if location is not True:
                    return None
            elif (
                kind not in {"registry", "git", "url", "path", "directory", "editable"}
                or not isinstance(location, str)
                or not location.strip()
                or "[redacted]" in location
            ):
                # Equal redacted URLs do not prove equal source artifacts.
                return None
        return (
            value["name"],
            SpecifierSet("==" + version if version is not None else ""),
            source,
        )
    if lock_format != "poetry" or name is None:
        return None
    if isinstance(value, dict):
        if set(value) - {
            "version",
            "optional",
            "markers",
            "extras",
            "python",
            "platform",
        }:
            return None
        if "optional" in value and type(value["optional"]) is not bool:
            return None
        if value.get("optional") is True:
            return None
        # These fields establish conditions; malformed empty values cannot erase them.
        if any(key in value for key in ("markers", "python", "platform")):
            return None
        if "extras" in value:
            extras = value["extras"]
            if not isinstance(extras, list) or not all(
                isinstance(extra, str) and bool(extra.strip()) for extra in extras
            ):
                return None
            if extras:
                return None
        value = value.get("version", "*")
    if not isinstance(value, str) or not value.strip():
        return None
    from depcheck.ecosystems.python.parsers.pyproject import PyProjectParser

    constraint = PyProjectParser._convert_poetry_constraint(value.strip())
    if constraint is None:
        return None
    if constraint == "*":
        constraint = ""
    elif constraint and constraint[0].isdigit():
        constraint = "==" + constraint
    return name, SpecifierSet(constraint), None


def _python_lock_links(
    records: list[ResolvedDependency],
) -> tuple[ResolvedDependency, ...]:
    """Bind unique lock-local assertions within one shared lookup budget per lock."""
    candidates: dict[tuple[Path, str], list[ResolvedDependency]] = {}
    budgets: dict[Path, int] = {}
    for record in records:
        if record.metadata.get("python_kind") == "lock-record":
            candidates.setdefault((record.source.path, record.package.name), []).append(
                record
            )
            budgets.setdefault(record.source.path, _PYTHON_LOCK_EDGE_WORK)
    result = []
    for record in records:
        if record.metadata.get("python_kind") != "lock-record":
            result.append(record)
            continue
        metadata = dict(record.metadata)
        if metadata.get("lock_format") in {"pipfile", "pylock"}:
            # Pipenv has no recorded graph. Pylock selectors are audit-only
            # assertions; neither supplies required installation edges.
            metadata["dependency_status"] = (
                "informational-only"
                if metadata.get("lock_format") == "pylock"
                else "uncollected"
            )
            result.append(replace(record, metadata=metadata))
            continue
        package = metadata.get("context", {}).get("package", {})
        raw = package.get("dependencies", [])
        lock_format = str(metadata.get("lock_format"))
        requests: Iterable[tuple[str | None, object]]
        if lock_format == "poetry" and isinstance(raw, dict):
            requests = raw.items()
        elif isinstance(raw, list):
            requests = ((None, value) for value in raw)
        else:
            requests = ((None, raw),)
        unresolved = 0
        targets: dict[str | None, ResolvedDependency] = {}
        for name, value in requests:
            budgets[record.source.path] -= 1
            if budgets[record.source.path] < 0:
                unresolved += 1
                continue
            try:
                request = _python_lock_request(name, value, lock_format)
                if request is None:
                    unresolved += 1
                    continue
                required, specifier, requested_source = request
                choices = candidates.get(
                    (record.source.path, str(canonicalize_name(required))), []
                )
                budgets[record.source.path] -= len(choices)
                if budgets[record.source.path] < 0:
                    unresolved += 1
                    continue
                matching = []
                for candidate in choices:
                    context = candidate.metadata.get("context", {}).get("package", {})
                    if candidate.metadata.get("details_omitted"):
                        # An uninspected sibling can shadow an apparently unique match.
                        matching.append(candidate)
                        continue
                    if lock_format == "pdm" and "extras" in context:
                        extras = context["extras"]
                        if not isinstance(extras, list) or not all(
                            isinstance(extra, str) and bool(extra.strip())
                            for extra in extras
                        ):
                            matching.append(candidate)
                            continue
                        if extras:
                            continue
                    if (
                        requested_source is not None
                        and context.get("source") != requested_source
                    ):
                        continue
                    if specifier.contains(candidate.version, prereleases=True):
                        matching.append(candidate)
                if len(matching) != 1:
                    unresolved += 1
                    continue
                target = matching[0]
                context = target.metadata.get("context", {}).get("package", {})
                extras = context.get("extras", [])
                if (
                    target.metadata.get("details_omitted")
                    or target.metadata.get("lock_origin", {}).get("kind") == "unknown"
                    or (
                        lock_format == "pdm"
                        and (
                            not isinstance(extras, list)
                            or not all(
                                isinstance(extra, str) and bool(extra.strip())
                                for extra in extras
                            )
                        )
                    )
                    or any(key in context for key in ("marker", "markers"))
                    or (
                        "resolution-markers" in context
                        and context["resolution-markers"] != []
                    )
                ):
                    unresolved += 1
                    continue
                targets[target.instance_id] = target
            except (
                InvalidRequirement,
                InvalidSpecifier,
                InvalidVersion,
                TypeError,
                ValueError,
            ):
                unresolved += 1
        incomplete = (
            bool(unresolved)
            or bool(metadata.get("details_omitted"))
            or budgets[record.source.path] < 0
        )
        metadata["dependency_status"] = "incomplete" if incomplete else "recorded"
        if unresolved:
            metadata["unresolved_dependency_requests"] = unresolved
        if budgets[record.source.path] < 0:
            metadata["dependency_work_limit"] = True
        result.append(
            replace(
                record,
                dependencies=tuple(target.package for target in targets.values()),
                dependency_links=tuple(
                    ResolvedDependencyLink(
                        target.package, target.version, target.instance_id
                    )
                    for target in targets.values()
                ),
                metadata=metadata,
            )
        )
    return tuple(result)


class PythonUsageProvider:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
    ) -> tuple[UsageEvidence, ...]:
        result = _usage_result(context, project)
        return tuple(_adapt_usage(project.project_id, item) for item in result.imports)


class PythonUsageMapper:
    def __init__(self, import_mapping: Mapping[str, str] | None = None) -> None:
        configured = import_mapping or {}
        self._configured = {
            key.lower(): str(canonicalize_name(value))
            for key, value in configured.items()
        }
        self._known = {
            key.lower(): str(canonicalize_name(value))
            for key, value in DEFAULT_IMPORT_MAP.items()
        }

    def map(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        usage: UsageEvidence,
    ) -> UsageEvidence:
        del context, project
        reference = usage.reference.lower()
        if reference in self._configured:
            name = self._configured[reference]
            confidence = MappingConfidence.CONFIGURED
            reason = "project import mapping"
        elif reference in self._known:
            name = self._known[reference]
            confidence = MappingConfidence.EXACT
            reason = "built-in Python import mapping"
        else:
            name = str(canonicalize_name(reference))
            confidence = MappingConfidence.INFERRED
            reason = "inferred distribution name from top-level Python import"
        return replace(
            usage,
            mapped_package=_package_ref(name, name),
            mapping_confidence=confidence,
            mapping_reason=reason,
        )


class PythonEvidenceCollector:
    @repository_operation("context.repository_root")
    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        return collect_python_bundle(
            context.repository_root,
            project,
            pack,
            context.settings,
        )


def create_python_pack(
    import_mapping: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="PyPI",
        detector=PythonProjectDetector(),
        manifest_provider=PythonManifestProvider(),
        resolution_provider=PythonResolutionProvider(),
        usage_provider=PythonUsageProvider(),
        usage_mapper=PythonUsageMapper(import_mapping),
        capabilities=frozenset(
            {
                "compatibility",
                "manifest",
                "mapping",
                "resolution",
                "security",
                "update_preview",
                "usage",
            }
        ),
        collector=PythonEvidenceCollector(),
    )


@measured("collection.python")
def collect_python_bundle(
    repository_root: Path,
    project: ProjectUnit,
    pack: EcosystemPack,
    settings: Mapping[str, object] | None = None,
) -> EvidenceBundle:
    root = Path(repository_root).resolve()
    project_root = root / project.root
    exclusions = _component_exclusions(root, project, settings or {})
    if project.manager == "pep723":
        script = root / project.manifests[0]
        bundle = adapt_python_bundle(
            root,
            project,
            pack,
            filter_python_manifest(
                parse_inline_script(script), (settings or {}).get("python_version")
            ),
            ImportScanner(exclusions).scan_files(project_root, [script]),
        )
        return replace(
            bundle,
            capabilities=tuple(
                _status(capability.name, False)
                if capability.name in {"usage", "mapping"}
                else capability
                for capability in bundle.capabilities
            ),
            diagnostics=(
                *bundle.diagnostics,
                Diagnostic(
                    code="usage.script-helper-coverage-unknown",
                    severity="warning",
                    message="Only this independent script is scanned; imported local helpers and runner injection remain outside its usage scope. Zero observed imports do not establish an unused requirement.",
                    source=SourceLocation(script),
                ),
            ),
        )
    workspace = _uv_workspace_root(root, project_root)
    manifest_result = (
        PythonManifestCollector(
            project_root,
            exclusions,
            configuration_root=root,
            configuration_start=workspace,
        ).collect()
        if project.manifests
        else ManifestParseResult()
    )
    manifest_result = _inherit_uv_workspace_sources(
        root, project_root, workspace, manifest_result
    )
    manifest_result = filter_python_manifest(
        manifest_result,
        (settings or {}).get("python_version"),
    )
    scanner = ImportScanner(exclusions)
    source_files = scanner.discover_files(project_root)
    scripts = set(inline_script_files(project_root, exclusions, paths=source_files))
    usage_result = scanner.scan_files(
        project_root, [path for path in source_files if path not in scripts]
    )
    bundle = adapt_python_bundle(
        root,
        project,
        pack,
        manifest_result,
        usage_result,
    )
    if workspace is not None:
        diagnostic = Diagnostic(
            code="resolution.uv-workspace-activation-unknown",
            severity="warning",
            message="uv workspace members share an installation environment and lock. Component ownership describes declarations and source; lock activation and cross-member availability are unknown.",
            source=SourceLocation(workspace / "pyproject.toml"),
        )
        bundle = replace(
            bundle,
            capabilities=tuple(_status(c.name, False) for c in bundle.capabilities),
            diagnostics=(*bundle.diagnostics, diagnostic),
            evidence_files=tuple(
                dict.fromkeys(
                    (
                        *bundle.evidence_files,
                        workspace / "pyproject.toml",
                        *(
                            (workspace / "uv.lock",)
                            if (workspace / "uv.lock").is_file()
                            else ()
                        ),
                    )
                )
            ),
        )
    return bundle


def _uv_workspace_root(root: Path, project_root: Path) -> Path | None:
    """Locate a shared-environment boundary without guessing active lock subsets."""
    for parent in (project_root, *project_root.parents):
        if parent != root and root not in parent.parents:
            break
        path = parent / "pyproject.toml"
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(read_text(path))
            uv = data.get("tool", {}).get("uv", {})
            if uv.get("managed") is False:
                return None
            if "workspace" in uv:
                if parent == project_root:
                    return parent
                relative = project_root.relative_to(parent).as_posix()
                return (
                    None
                    if _uv_membership(uv["workspace"], relative) is False
                    else parent
                )
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            continue
    return None


def _uv_membership(workspace: object, relative: str) -> bool | None:
    from depcheck.ecosystems.configuration.workspaces import _workspace_pattern

    if not isinstance(workspace, dict):
        return None
    members, excluded = workspace.get("members"), workspace.get("exclude", [])
    if (
        not isinstance(members, list)
        or not isinstance(excluded, list)
        or len(members) + len(excluded) > 1024
        or not all(isinstance(p, str) for p in [*members, *excluded])
    ):
        return None
    patterns = [_workspace_pattern(p) for p in [*members, *excluded]]
    if any(p is None for p in patterns):
        return None
    try:
        return any(
            p is not None and p.fullmatch(relative) for p in patterns[: len(members)]
        ) and not any(
            p is not None and p.fullmatch(relative) for p in patterns[len(members) :]
        )
    except ValueError:
        return None


def _inherit_uv_workspace_sources(
    root: Path,
    project_root: Path,
    workspace: Path | None,
    manifest: ManifestParseResult,
) -> ManifestParseResult:
    """Capture workspace source policy without claiming an active installation."""
    if workspace is None or workspace == project_root:
        return manifest
    path = workspace / "pyproject.toml"
    member_path = project_root / "pyproject.toml"
    try:
        text = read_text(path)
        uv = tomllib.loads(text).get("tool", {}).get("uv", {})
        member_uv = tomllib.loads(read_text(member_path)).get("tool", {}).get("uv", {})
        sources = bounded_uv_sources(uv.get("sources", {}))
        local = bounded_uv_sources(member_uv.get("sources", {}))
        membership = _uv_membership(
            uv.get("workspace"), project_root.relative_to(workspace).as_posix()
        )
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        sources = local = None
        membership = None
        text = ""
    positions = SourcePositions.toml(path, text)
    declarations = []
    uncertain = False
    budget = _UV_INHERITED_BYTES
    source_origins: dict[str, dict] = {}
    source_digests: dict[str, str] = {}
    for item in manifest.declarations:
        if (
            item.source.path != member_path
            or item.kind == "environment"
            or "uv_index_policy" not in item.metadata
        ):
            declarations.append(item)
            continue
        if local is not None and item.name in local:
            declarations.append(item)
            continue
        if sources is not None and item.name not in sources:
            declarations.append(item)
            continue
        unknown = membership is not True or sources is None or local is None
        key: tuple[str, ...] = ("tool", "uv", "sources")
        if unknown:
            origin = {
                "kind": "unknown",
                "public": False,
                "assertion": {"uv_workspace_policy_unverified": True},
            }
            uncertain = True
        elif sources is not None and item.name in sources:
            name, value = sources[item.name]
            if item.name not in source_origins:
                source_origins[item.name] = uv_source_origin(value)
            origin = source_origins[item.name]
            if origin.get("details_omitted") or origin.get("source_validation"):
                unknown = uncertain = True
            key = (*key, name)
        else:
            declarations.append(item)
            continue
        budget -= (
            len(json.dumps([origin, item.origin], ensure_ascii=True).encode()) + 512
        )
        omitted = budget < 0
        if omitted:
            origin = {
                "kind": "unknown",
                "public": False,
                "assertion": {"uv_workspace_policy_details_omitted": True},
            }
            if sources is not None and item.name in sources:
                if item.name not in source_digests:
                    source_digests[item.name] = source_assertion_digest(
                        sources[item.name][1]
                    )
                origin["source_assertion_sha256"] = source_digests[item.name]
            unknown = uncertain = True
        location = positions.key(*key)
        declarations.append(
            replace(
                item,
                origin=origin,
                metadata={
                    **item.metadata,
                    "inherited_uv_source": {
                        "configuration_file": path.relative_to(root).as_posix(),
                        "line": location.line,
                        "column": location.column,
                        "origin_base": workspace.relative_to(root).as_posix(),
                        "membership": "confirmed" if membership is True else "unknown",
                        "selection": "unverified" if unknown else "inherited",
                        "activation": "unknown",
                        **(
                            {"original_origin_status": "omitted-by-budget"}
                            if omitted
                            else {"original_origin": dict(item.origin)}
                        ),
                    },
                },
            )
        )
    diagnostics = manifest.diagnostics
    if uncertain:
        diagnostics = (
            *diagnostics,
            Diagnostic(
                "manifest.uv-workspace-source-policy-unknown",
                "warning",
                "Workspace membership or source tables are ambiguous, invalid or over budget; affected member sources remain unverified.",
                SourceLocation(path),
            ),
        )
    return replace(
        manifest,
        declarations=tuple(declarations),
        diagnostics=diagnostics,
        files=tuple(dict.fromkeys((*manifest.files, path))),
    )


def filter_python_manifest(
    manifest_result: ManifestParseResult,
    python_version: object | None,
) -> ManifestParseResult:
    """Apply target-Python markers before any scan or index consumes evidence."""
    if python_version is None:
        return manifest_result
    version = Version(str(python_version))
    environment = {
        "python_version": f"{version.major}.{version.minor}",
        "python_full_version": str(version),
    }
    diagnostics = list(manifest_result.diagnostics)
    active: list[PythonRequirement] = []
    for item in manifest_result.declarations:
        if item.kind == "environment":
            # Hatch environments have their own interpreter/marker context.
            active.append(item)
            continue
        try:
            applies = item.is_active(environment)
        except (UndefinedComparison, UndefinedEnvironmentName, InvalidVersion) as exc:
            diagnostic = Diagnostic(
                code="manifest.marker-evaluation-unknown",
                severity="error",
                message=f"{item.raw_requirement}: marker applicability is unknown: {exc}",
                source=item.source,
            )
            if diagnostic not in diagnostics:
                diagnostics.append(diagnostic)
            # Retain the declaration without asserting its activation.
            applies = True
        if applies:
            active.append(item)
    return ManifestParseResult(
        declarations=tuple(active),
        diagnostics=tuple(diagnostics),
        files=manifest_result.files,
    )


def adapt_python_bundle(
    repository_root: Path,
    project: ProjectUnit,
    pack: EcosystemPack,
    manifest_result: ManifestParseResult,
    usage_result: ImportScanResult,
) -> EvidenceBundle:
    """Adapt cached Python scanner results without reading the repository again."""
    root = Path(repository_root).resolve()
    context = ProviderContext(
        root,
        {
            _MANIFEST_RESULT: manifest_result,
            _USAGE_RESULT: usage_result,
        },
    )

    declarations = (
        pack.manifest_provider.collect(context, project)
        if pack.manifest_provider is not None
        else ()
    )
    resolved = (
        pack.resolution_provider.collect(context, project)
        if pack.resolution_provider is not None
        else ()
    )
    raw_usages = (
        pack.usage_provider.collect(context, project)
        if pack.usage_provider is not None
        else ()
    )
    usages = (
        tuple(pack.usage_mapper.map(context, project, usage) for usage in raw_usages)
        if pack.usage_mapper is not None
        else raw_usages
    )

    component_manifests = sorted(
        {
            item.source.path
            for item in declarations
            if item.kind == "direct"
            and item.scope != "build"
            and item.source.path.name == "pyproject.toml"
        }
    )
    component_diagnostics = (
        (
            Diagnostic(
                code="analysis.python-component-scope-ambiguous",
                severity="error",
                message=(
                    "Multiple Python dependency roots share an aggregate project ID; "
                    "their installation scopes cannot be compared safely. "
                    "Scan each component root separately."
                ),
                source=next(
                    item.source
                    for item in declarations
                    if item.source.path == component_manifests[0]
                ),
            ),
        )
        if len(component_manifests) > 1
        else ()
    )
    manifest_complete = _complete(
        (*manifest_result.diagnostics, *component_diagnostics)
    )
    usage_complete = (
        not component_diagnostics
        and _complete(usage_result.diagnostics)
        and not any(item.code == "usage.dynamic" for item in usage_result.diagnostics)
    )
    mapping_complete = usage_complete and all(
        item.mapping_confidence is not MappingConfidence.UNKNOWN for item in usages
    )
    source_diagnostics = tuple(
        Diagnostic(
            code="resolution.python-source-unverified",
            severity="warning",
            message=f"{item.package.name}: {item.origin.get('kind', 'unknown')} source does not establish a public PyPI identity; public registry checks are skipped.",
            source=item.source,
        )
        for item in resolved
        if item.origin.get("public") is not True
    )
    conditional_locks = any(
        item.metadata.get("conditional")
        or item.origin.get("lock", {}).get("conditional")
        for item in resolved
    )
    incomplete_edges = [
        item
        for item in resolved
        if item.metadata.get("dependency_status") in {"incomplete", "uncollected"}
    ]
    unknown_bindings = [
        item for item in resolved if item.metadata.get("directness_status") == "unknown"
    ]
    binding_diagnostics = (
        (
            Diagnostic(
                "resolution.python-directness-unknown",
                "warning",
                "Python lock occurrences cannot be uniquely bound to compatible direct declarations; source, version or occurrence evidence is ambiguous, unverified or over budget. This does not establish installation or active scope.",
                unknown_bindings[0].source,
            ),
        )
        if unknown_bindings
        else ()
    )
    edge_diagnostics = (
        (
            Diagnostic(
                "resolution.python-lock-edges-unknown",
                "warning",
                "Python lock dependency edges are uncollected, conditional, ambiguous, unsupported or over budget; only literal unconditional unique requests can supply edges.",
                incomplete_edges[0].source,
            ),
        )
        if incomplete_edges
        else ()
    )
    environment_requirements = [
        item for item in declarations if item.kind == "environment"
    ]
    environment_diagnostics = (
        (
            Diagnostic(
                "resolution.hatch-environment-activation-unknown",
                "warning",
                "Hatch requirements belong to separate environments; inheritance, marker activation and installation are not selected.",
                environment_requirements[0].source,
            ),
        )
        if environment_requirements
        else ()
    )
    capabilities = (
        _status("manifest", manifest_complete),
        _status(
            "resolution",
            manifest_complete
            and not source_diagnostics
            and not conditional_locks
            and not any(
                d.code == "resolution.pylock-activation-unknown"
                for d in manifest_result.diagnostics
            )
            and not incomplete_edges
            and not environment_requirements
            and not unknown_bindings,
        ),
        _status("usage", usage_complete),
        _status("mapping", mapping_complete),
    )
    return EvidenceBundle(
        project=project,
        declarations=declarations,
        resolved=resolved,
        usages=usages,
        diagnostics=(
            *manifest_result.diagnostics,
            *component_diagnostics,
            *source_diagnostics,
            *edge_diagnostics,
            *binding_diagnostics,
            *environment_diagnostics,
            *usage_result.diagnostics,
        ),
        capabilities=capabilities,
        source_files=usage_result.files,
        evidence_files=manifest_result.files,
    )


def _manifest_result(
    context: ProviderContext,
    project: ProjectUnit,
) -> ManifestParseResult:
    cached = context.settings.get(_MANIFEST_RESULT)
    if isinstance(cached, ManifestParseResult):
        return cached
    if project.manager == "pep723":
        return parse_inline_script(context.repository_root / project.manifests[0])
    project_root = context.repository_root / project.root
    workspace = _uv_workspace_root(context.repository_root, project_root)
    result = (
        PythonManifestCollector(
            project_root,
            exclusions_for(context.settings, project.root),
            configuration_root=context.repository_root,
            configuration_start=workspace,
        ).collect()
        if project.manifests
        else ManifestParseResult()
    )
    return _inherit_uv_workspace_sources(
        context.repository_root,
        project_root,
        workspace,
        result,
    )


def _usage_result(
    context: ProviderContext,
    project: ProjectUnit,
) -> ImportScanResult:
    cached = context.settings.get(_USAGE_RESULT)
    if isinstance(cached, ImportScanResult):
        return cached
    return ImportScanner(exclusions_for(context.settings, project.root)).scan_detailed(
        context.repository_root / project.root
    )


def _adapt_declaration(
    project_id: str,
    declaration: PythonRequirement,
) -> DependencyDeclaration:
    normalized = str(declaration.specifier)
    custom_category = (
        declaration.metadata.get("python_kind") == "pipenv-declaration"
        and declaration.metadata.get("category_kind") == "custom"
    )
    return DependencyDeclaration(
        project_id=project_id,
        package=_package_ref(
            declaration.name,
            declaration.display_name,
            public=declaration.origin.get("public") is True,
        ),
        constraint=VersionConstraint(
            raw=normalized,
            scheme="pep440",
            normalized=normalized or None,
        ),
        source=declaration.source,
        scope="unknown" if custom_category else _scope(declaration.group),
        kind=(
            "conditional"
            if custom_category and declaration.kind == "direct"
            else declaration.kind
        ),
        marker=str(declaration.marker) if declaration.marker is not None else None,
        metadata={
            **dict(declaration.metadata),
            "extras": list(declaration.extras),
            "raw_requirement": declaration.raw_requirement,
            "group": declaration.group,
            "origin": dict(declaration.origin),
        },
    )


def _adapt_usage(project_id: str, usage: ImportEvidence) -> UsageEvidence:
    return UsageEvidence(
        project_id=project_id,
        language="python",
        reference=usage.module,
        source=usage.source,
        scope=usage.scope,
        kind=usage.kind,
    )


def _package_ref(name: str, display_name: str, *, public: bool = True) -> PackageRef:
    canonical = str(canonicalize_name(name))
    return PackageRef(
        ecosystem="PyPI",
        name=canonical,
        display_name=display_name,
        purl=f"pkg:pypi/{quote(canonical, safe='')}" if public else None,
    )


def _scope(group: str) -> str:
    if group == "dev" or group.startswith(("dev:", "development")):
        return "development"
    if group.startswith("optional:"):
        return "optional"
    return group


def _complete(diagnostics: Sequence[Diagnostic]) -> bool:
    return not any(item.severity == "error" for item in diagnostics)


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name=name,
        state=CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        reason=None if complete else f"{name} evidence is incomplete",
    )


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path


def _has_manifest_candidate(
    root: Path,
    excluded_directories: Sequence[str] = (),
    *,
    include_install_hints: bool = True,
) -> bool:
    install_hint_names = {
        "CMakeLists.txt",
        "Dockerfile",
        "Makefile",
        "dockerfile",
        "makefile",
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if not name.startswith(".")
            and name not in IGNORED_DIRECTORIES
            and not _excluded_child(
                root,
                Path(dirpath) / name,
                excluded_directories,
            )
        ]
        if any(
            (
                name in parser_map
                and (include_install_hints or name not in install_hint_names)
            )
            or is_requirements_file(Path(name))
            or is_pylock_file(Path(name))
            for name in filenames
        ):
            return True
    return False


def _excluded_child(
    root: Path,
    path: Path,
    excluded_directories: Sequence[str],
) -> bool:
    from depcheck.ecosystems.static import is_excluded

    return is_excluded(path.relative_to(root), excluded_directories)
