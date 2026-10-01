from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from depcheck.model import Diagnostic, SourceLocation
from depcheck.ecosystems.javascript_aliases import (
    AliasResolution,
    resolve_package_import,
)
from depcheck.ecosystems.javascript_packages import (
    dependency_identity,
    package_ref as _package_ref,
    registry_name,
)
from depcheck.ecosystems.javascript_pnpm import collect_pnpm_lock
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    ProjectUnit,
    ResolvedDependency,
    ResolvedDependencyLink,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_json,
    read_text,
)

_LOCK_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
)
_SOURCE_SUFFIXES = frozenset({".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"})
_DEPENDENCY_SECTIONS = (
    ("dependencies", "runtime"),
    ("devDependencies", "development"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)
_NODE_BUILTINS = frozenset(
    {
        "assert",
        "assert/strict",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "dns/promises",
        "domain",
        "events",
        "fs",
        "fs/promises",
        "http",
        "http2",
        "https",
        "inspector",
        "inspector/promises",
        "module",
        "net",
        "os",
        "path",
        "path/posix",
        "path/win32",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "readline/promises",
        "repl",
        "stream",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "string_decoder",
        "timers",
        "timers/promises",
        "tls",
        "tty",
        "url",
        "util",
        "util/types",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)


@dataclass(frozen=True, slots=True)
class _JsToken:
    kind: str
    value: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class _ModuleLoad:
    reference: str
    line: int
    column: int
    kind: str


class NpmProjectDetector:
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        projects: list[ProjectUnit] = []
        for manifest in discover_files(
            root,
            names=frozenset({"package.json"}),
            excluded_directories=exclusions_for(context.settings),
        ):
            project_root = manifest.parent
            relative_root = project_root.relative_to(root)
            if relative_root == Path(""):
                relative_root = Path(".")
            locks = tuple(
                (relative_root / name) if relative_root != Path(".") else Path(name)
                for name in _LOCK_NAMES
                if (project_root / name).is_file()
            )
            if not any(path.name == "pnpm-lock.yaml" for path in locks):
                for parent in project_root.parents:
                    if parent != root and root not in parent.parents:
                        break
                    candidate = parent / "pnpm-lock.yaml"
                    if candidate.is_file():
                        locks = (*locks, candidate.relative_to(root))
                        break
            relative_manifest = (
                relative_root / "package.json"
                if relative_root != Path(".")
                else Path("package.json")
            )
            language = (
                "typescript"
                if (project_root / "tsconfig.json").is_file()
                else "javascript"
            )
            projects.append(
                ProjectUnit(
                    project_id=ProjectUnit.stable_id(relative_root, "npm", "npm"),
                    root=relative_root,
                    language=language,
                    ecosystem="npm",
                    manager="npm",
                    manifests=(relative_manifest,),
                    locks=locks,
                )
            )
        return tuple(
            sorted(
                projects,
                key=lambda item: (len(item.root.parts), item.root.as_posix()),
            )
        )


class NpmEvidenceCollector:
    def __init__(self, mappings: Mapping[str, str] | None = None) -> None:
        self.mappings = {
            str(key).lower(): str(value).lower()
            for key, value in (mappings or {}).items()
        }

    def collect(
        self,
        context: ProviderContext,
        project: ProjectUnit,
        pack: EcosystemPack,
    ) -> EvidenceBundle:
        del pack
        root = context.repository_root
        project_root = root / project.root
        manifest = project_root / "package.json"
        diagnostics: list[Diagnostic] = []
        declarations: tuple[DependencyDeclaration, ...] = ()
        document: Mapping[str, object] = {}
        manifest_complete = True
        try:
            document = read_json(manifest)
            declarations = self._declarations(project, manifest, document)
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        resolved: tuple[ResolvedDependency, ...] = ()
        resolution_complete = True
        pnpm_lock = next(
            (root / path for path in project.locks if path.name == "pnpm-lock.yaml"),
            None,
        )
        supported_lock = next(
            (
                project_root / name
                for name in ("package-lock.json", "npm-shrinkwrap.json")
                if (project_root / name).is_file()
            ),
            None,
        )
        if supported_lock is not None:
            try:
                resolved = self._resolved(project, supported_lock, declarations)
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(
                    _diagnostic("lock.invalid", str(exc), supported_lock)
                )
        elif pnpm_lock is not None:
            try:
                evidence = collect_pnpm_lock(pnpm_lock, project, declarations, root)
                resolved = evidence.resolved
                diagnostics.extend(evidence.diagnostics)
                resolution_complete = not evidence.diagnostics
            except StaticReadError as exc:
                resolution_complete = False
                diagnostics.append(_diagnostic("lock.invalid", str(exc), pnpm_lock))
        elif (project_root / "yarn.lock").is_file():
            resolution_complete = False
            lock = project_root / "yarn.lock"
            diagnostics.append(
                _diagnostic(
                    "lock.unsupported",
                    f"static resolution for {lock.name} is not implemented",
                    lock,
                    severity="warning",
                )
            )

        usages, source_files, usage_diagnostics, usage_complete = self._usages(
            project,
            project_root,
            exclusions_for(context.settings, project.root),
            document.get("imports"),
            {
                str(item.metadata["installation_name"]): item.package.name
                for item in declarations
            },
        )
        diagnostics.extend(usage_diagnostics)
        capabilities = (
            _status("manifest", manifest_complete),
            _status("resolution", resolution_complete),
            _status("usage", usage_complete),
            _status("mapping", usage_complete),
        )
        return EvidenceBundle(
            project=project,
            declarations=declarations,
            resolved=resolved,
            usages=usages,
            diagnostics=tuple(diagnostics),
            capabilities=capabilities,
            source_files=source_files,
        )

    def _declarations(
        self,
        project: ProjectUnit,
        manifest: Path,
        document: Mapping[str, object],
    ) -> tuple[DependencyDeclaration, ...]:
        declarations: list[DependencyDeclaration] = []
        seen: set[tuple[str, str]] = set()
        identities: dict[str, str] = {}
        for section, scope in _DEPENDENCY_SECTIONS:
            values = document.get(section, {})
            if not isinstance(values, Mapping):
                raise StaticReadError(f"{section} must be a package-to-version object")
            for display_name, raw_constraint in sorted(values.items()):
                if (
                    not isinstance(display_name, str)
                    or not isinstance(raw_constraint, str)
                    or not display_name.strip()
                ):
                    raise StaticReadError(
                        f"{section} entries require non-empty names and string specifiers"
                    )
                installed_name = display_name.lower()
                name, constraint = dependency_identity(installed_name, raw_constraint)
                if identities.setdefault(installed_name, name) != name:
                    raise StaticReadError(
                        f"Conflicting registry identities for npm alias {installed_name}"
                    )
                key = (installed_name, scope)
                if key in seen:
                    continue
                seen.add(key)
                declarations.append(
                    DependencyDeclaration(
                        project_id=project.project_id,
                        package=_package_ref(name),
                        constraint=VersionConstraint(
                            raw_constraint, "semver", constraint
                        ),
                        source=SourceLocation(manifest, 1, 1),
                        scope=scope,
                        kind="direct",
                        metadata={
                            "section": section,
                            "installation_name": installed_name,
                        },
                    )
                )
        return tuple(declarations)

    def _resolved(
        self,
        project: ProjectUnit,
        lock: Path,
        declarations: Sequence[DependencyDeclaration],
    ) -> tuple[ResolvedDependency, ...]:
        document = read_json(lock)
        direct = {
            str(item.metadata["installation_name"]): item.package.name
            for item in declarations
        }
        direct_paths = {f"node_modules/{alias}" for alias in direct}
        packages = document.get("packages")
        if "packages" in document and not isinstance(packages, Mapping):
            raise StaticReadError("lockfile packages must be an object")
        resolved: list[ResolvedDependency] = []
        if isinstance(packages, Mapping):
            nodes: dict[str, tuple[str, str, Mapping[object, object]]] = {}
            for lock_path, raw in sorted(packages.items()):
                if not isinstance(lock_path, str) or not isinstance(raw, Mapping):
                    raise StaticReadError("lockfile package entries must be objects")
                name = _lock_package_name(lock_path)
                version = raw.get("version")
                if name is None or not isinstance(version, str) or not version:
                    continue
                expected = (
                    direct.get(name) if lock_path == f"node_modules/{name}" else None
                )
                identity = raw.get("name", expected or name)
                if not isinstance(identity, str):
                    raise StaticReadError("lockfile package name must be a string")
                name = registry_name(identity)
                if expected is not None and name != expected:
                    raise StaticReadError(
                        f"lockfile registry identity disagrees at {lock_path}"
                    )
                nodes[lock_path] = (name, version, raw)
            for lock_path, (name, version, raw) in sorted(nodes.items()):
                dependencies = raw.get("dependencies", {})
                links: list[ResolvedDependencyLink] = []
                if isinstance(dependencies, Mapping):
                    for child in sorted(dependencies):
                        if not isinstance(child, str):
                            continue
                        child_name = child.lower()
                        child_path = _resolve_lock_dependency(
                            lock_path, child_name, nodes
                        )
                        child_version = (
                            nodes[child_path][1] if child_path is not None else None
                        )
                        if child_path is not None:
                            child_name = nodes[child_path][0]
                        links.append(
                            ResolvedDependencyLink(
                                package=_package_ref(child_name),
                                version=child_version,
                                instance_id=child_path,
                            )
                        )
                resolved.append(
                    ResolvedDependency(
                        project_id=project.project_id,
                        package=_package_ref(name),
                        version=version,
                        source=SourceLocation(lock, 1, 1),
                        direct=lock_path in direct_paths,
                        integrity=(
                            str(raw["integrity"])
                            if isinstance(raw.get("integrity"), str)
                            else None
                        ),
                        dependencies=tuple(link.package for link in links),
                        instance_id=lock_path,
                        dependency_links=tuple(links),
                    )
                )
            return tuple(resolved)
        dependencies = document.get("dependencies", {})
        if not isinstance(dependencies, Mapping):
            raise StaticReadError("lockfile dependencies must be an object")
        self._walk_legacy_lock(
            project,
            lock,
            dependencies,
            direct,
            resolved,
            parent_instance="",
            top_level=True,
        )
        return tuple(resolved)

    def _walk_legacy_lock(
        self,
        project: ProjectUnit,
        lock: Path,
        dependencies: Mapping[object, object],
        direct: Mapping[str, str],
        resolved: list[ResolvedDependency],
        *,
        parent_instance: str,
        top_level: bool,
    ) -> None:
        for raw_name, raw in sorted(
            dependencies.items(), key=lambda item: str(item[0])
        ):
            if not isinstance(raw_name, str) or not isinstance(raw, Mapping):
                continue
            installed_name = raw_name.lower()
            version = raw.get("version")
            name, version = (
                dependency_identity(installed_name, version)
                if isinstance(version, str)
                else (installed_name, version)
            )
            if (
                top_level
                and installed_name in direct
                and isinstance(raw.get("version"), str)
                and str(raw["version"]).startswith("npm:")
                and name != direct[installed_name]
            ):
                raise StaticReadError(
                    f"lockfile registry identity disagrees for {installed_name}"
                )
            identity = raw.get(
                "name", direct.get(installed_name, name) if top_level else name
            )
            if not isinstance(identity, str):
                raise StaticReadError("lockfile package name must be a string")
            name = registry_name(identity)
            if (
                top_level
                and installed_name in direct
                and name != direct[installed_name]
            ):
                raise StaticReadError(
                    f"lockfile registry identity disagrees for {installed_name}"
                )
            children = raw.get("dependencies", {})
            instance_id = (
                f"{parent_instance}/node_modules/{installed_name}"
                if parent_instance
                else f"node_modules/{installed_name}"
            )
            child_links: list[ResolvedDependencyLink] = []
            if isinstance(children, Mapping):
                for child, child_raw in sorted(children.items()):
                    if not isinstance(child, str) or not isinstance(child_raw, Mapping):
                        continue
                    child_version = child_raw.get("version")
                    child_name = child.lower()
                    if isinstance(child_version, str):
                        child_name, child_version = dependency_identity(
                            child_name, child_version
                        )
                    identity = child_raw.get("name", child_name)
                    if not isinstance(identity, str):
                        raise StaticReadError("lockfile package name must be a string")
                    child_name = registry_name(identity)
                    child_links.append(
                        ResolvedDependencyLink(
                            package=_package_ref(child_name),
                            version=child_version
                            if isinstance(child_version, str)
                            else None,
                            instance_id=f"{instance_id}/node_modules/{child.lower()}",
                        )
                    )
            if isinstance(version, str) and version:
                resolved.append(
                    ResolvedDependency(
                        project.project_id,
                        _package_ref(name),
                        version,
                        SourceLocation(lock, 1, 1),
                        direct=top_level and installed_name in direct,
                        dependencies=tuple(link.package for link in child_links),
                        instance_id=instance_id,
                        dependency_links=tuple(child_links),
                    )
                )
            if isinstance(children, Mapping):
                self._walk_legacy_lock(
                    project,
                    lock,
                    children,
                    direct,
                    resolved,
                    parent_instance=instance_id,
                    top_level=False,
                )

    def _usages(
        self,
        project: ProjectUnit,
        project_root: Path,
        excluded_directories: Sequence[str] = (),
        imports: object = None,
        installation_names: Mapping[str, str] | None = None,
    ) -> tuple[tuple[UsageEvidence, ...], tuple[Path, ...], list[Diagnostic], bool]:
        usages: list[UsageEvidence] = []
        diagnostics: list[Diagnostic] = []
        complete = True
        source_files = tuple(
            path
            for path in discover_files(
                project_root,
                suffixes=_SOURCE_SUFFIXES,
                excluded_directories=excluded_directories,
            )
            if _nearest_package_root(path.parent, project_root) == project_root
        )
        source_paths = frozenset(source_files)
        alias_resolutions: dict[str, AliasResolution] = {}
        for path in source_files:
            try:
                text = read_text(path)
            except StaticReadError as exc:
                complete = False
                diagnostics.append(_diagnostic("source.invalid", str(exc), path))
                continue
            tokens, ambiguous_count = _lex_javascript(text)
            loads, dynamic_count = _module_loads(tokens)
            for load in loads:
                package_name = _import_package(load.reference)
                mapped_name = self.mappings.get(
                    load.reference.lower()
                ) or self.mappings.get(package_name or "")
                confidence = (
                    MappingConfidence.CONFIGURED
                    if mapped_name is not None
                    else MappingConfidence.EXACT
                )
                reason = (
                    "project import mapping"
                    if mapped_name is not None
                    else "literal npm package specifier"
                )
                if load.reference.startswith("#") and mapped_name is None:
                    if load.reference not in alias_resolutions:
                        alias_resolutions[load.reference] = resolve_package_import(
                            load.reference,
                            imports,
                            project_root,
                            source_paths,
                            builtin_names=_NODE_BUILTINS,
                        )
                    alias = alias_resolutions[load.reference]
                    if alias.kind in {"local", "builtin"}:
                        continue
                    if alias.kind == "package":
                        package_name = alias.target
                        reason = alias.reason
                    else:
                        complete = False
                        source = SourceLocation(path, load.line, load.column)
                        usages.append(
                            UsageEvidence(
                                project_id=project.project_id,
                                language=project.language,
                                reference=load.reference,
                                source=source,
                                scope=_source_scope(path, project_root),
                                kind=load.kind,
                                mapping_confidence=MappingConfidence.UNKNOWN,
                                mapping_reason=alias.reason,
                            )
                        )
                        diagnostics.append(
                            Diagnostic(
                                "mapping.alias-unsupported",
                                "warning",
                                alias.reason,
                                source,
                            )
                        )
                        continue
                if package_name is None and mapped_name is None:
                    continue
                mapped_name = (
                    mapped_name
                    or (installation_names or {}).get(package_name or "")
                    or package_name
                )
                assert mapped_name is not None
                usages.append(
                    UsageEvidence(
                        project_id=project.project_id,
                        language=project.language,
                        reference=load.reference,
                        source=SourceLocation(path, load.line, load.column),
                        scope=_source_scope(path, project_root),
                        kind=load.kind,
                        mapped_package=_package_ref(mapped_name),
                        mapping_confidence=confidence,
                        mapping_reason=reason,
                    )
                )
            if dynamic_count:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        "usage.dynamic",
                        f"{dynamic_count} non-literal module loads could not be mapped",
                        path,
                        severity="warning",
                    )
                )
            if ambiguous_count:
                complete = False
                diagnostics.append(
                    _diagnostic(
                        "usage.ambiguous",
                        f"{ambiguous_count} ambiguous JavaScript lexical constructs "
                        "prevented exact module mapping",
                        path,
                        severity="warning",
                    )
                )
        return tuple(usages), source_files, diagnostics, complete


def create_npm_pack(
    mappings: Mapping[str, str] | None = None,
) -> EcosystemPack:
    return EcosystemPack(
        ecosystem="npm",
        detector=NpmProjectDetector(),
        capabilities=frozenset(
            {"manifest", "mapping", "resolution", "security", "usage"}
        ),
        collector=NpmEvidenceCollector(mappings),
    )


def _lock_package_name(lock_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in lock_path:
        return None
    name = lock_path.rsplit(marker, 1)[1].strip("/")
    return name.lower() if name else None


def _import_package(reference: str) -> str | None:
    value = reference.strip()
    if not value or value.startswith((".", "/", "#")):
        return None
    if value.startswith("node:"):
        return None
    if value in _NODE_BUILTINS:
        return None
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else None
    return value.split("/", 1)[0].lower()


def _resolve_lock_dependency(
    parent_path: str,
    child_name: str,
    nodes: Mapping[str, object],
) -> str | None:
    parent = PurePosixPath(parent_path)
    while True:
        candidate = (parent / "node_modules" / child_name).as_posix()
        if candidate in nodes:
            return candidate
        if str(parent) in {"", "."}:
            break
        parent = parent.parent
    return None


def _lex_javascript(text: str) -> tuple[tuple[_JsToken, ...], int]:
    """Tokenize only the bounded syntax needed for static module evidence."""
    tokens: list[_JsToken] = []
    incomplete = 0
    index = 0
    line = 1
    column = 1

    def advance(count: int = 1) -> None:
        nonlocal index, line, column
        end = min(index + count, len(text))
        for character in text[index:end]:
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
        index = end

    while index < len(text):
        character = text[index]
        if character.isspace():
            advance()
            continue
        if index == 0 and text.startswith("#!", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] not in "\r\n":
                advance()
            continue
        if text.startswith("/*", index):
            advance(2)
            closed = False
            while index < len(text):
                if text.startswith("*/", index):
                    advance(2)
                    closed = True
                    break
                advance()
            if not closed:
                incomplete += 1
            continue
        if character in {"'", '"'}:
            quote_character = character
            token_line = line
            token_column = column
            value: list[str] = []
            safe = True
            closed = False
            advance()
            while index < len(text):
                character = text[index]
                if character == quote_character:
                    advance()
                    closed = True
                    break
                if character in "\r\n":
                    break
                if character == "\\":
                    advance()
                    if index >= len(text):
                        break
                    escaped = text[index]
                    if escaped in {"\\", "'", '"', "/"}:
                        value.append(escaped)
                    else:
                        safe = False
                    advance()
                    continue
                value.append(character)
                advance()
            if not closed:
                incomplete += 1
                break
            if not safe:
                incomplete += 1
            if closed and safe:
                tokens.append(
                    _JsToken("string", "".join(value), token_line, token_column)
                )
            continue
        if character == "`":
            advance()
            closed = False
            interpolated = False
            while index < len(text):
                if text[index] == "\\":
                    advance(2)
                    continue
                if text.startswith("${", index):
                    interpolated = True
                    incomplete += 1
                    break
                if text[index] == "`":
                    advance()
                    closed = True
                    break
                advance()
            if interpolated:
                break
            if not closed:
                incomplete += 1
                break
            continue
        if character == "/" and _can_start_regex(tokens):
            advance()
            closed = False
            in_character_class = False
            while index < len(text):
                character = text[index]
                if character == "\\":
                    advance(2)
                    continue
                if character in "\r\n":
                    break
                if character == "[":
                    in_character_class = True
                elif character == "]":
                    in_character_class = False
                elif character == "/" and not in_character_class:
                    advance()
                    while index < len(text) and (
                        text[index].isalnum() or text[index] in {"_", "$"}
                    ):
                        advance()
                    closed = True
                    break
                advance()
            if not closed:
                incomplete += 1
                break
            continue
        if character == "<" and _looks_like_jsx_start(
            text,
            index,
            tokens[-1] if tokens else None,
        ):
            incomplete += 1
            break
        if character.isalpha() or character in {"_", "$"}:
            token_line = line
            token_column = column
            start = index
            while index < len(text) and (
                text[index].isalnum() or text[index] in {"_", "$"}
            ):
                advance()
            tokens.append(
                _JsToken("identifier", text[start:index], token_line, token_column)
            )
            continue
        tokens.append(_JsToken("punctuation", character, line, column))
        advance()
    return tuple(tokens), incomplete


def _can_start_regex(tokens: Sequence[_JsToken]) -> bool:
    if not tokens:
        return True
    previous = tokens[-1]
    if previous.kind == "punctuation":
        return (
            previous.value in "([{=,:;!?&|+-*%^~<>"
            or previous.value == ")"
            and _closes_control_condition(tokens)
        )
    return previous.value in {
        "await",
        "case",
        "delete",
        "in",
        "instanceof",
        "of",
        "return",
        "throw",
        "typeof",
        "void",
        "yield",
    }


def _closes_control_condition(tokens: Sequence[_JsToken]) -> bool:
    depth = 0
    for index in range(len(tokens) - 1, -1, -1):
        token = tokens[index]
        if token.value == ")":
            depth += 1
            continue
        if token.value != "(":
            continue
        depth -= 1
        if depth != 0:
            continue
        keyword = tokens[index - 1] if index else None
        return (
            keyword is not None
            and keyword.kind == "identifier"
            and keyword.value in {"catch", "for", "if", "switch", "while", "with"}
        )
    return False


def _looks_like_jsx_start(
    text: str,
    index: int,
    previous: _JsToken | None,
) -> bool:
    cursor = index + 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or not (text[cursor].isalpha() or text[cursor] == "/"):
        return False
    if previous is None:
        return True
    if previous.kind == "punctuation":
        return previous.value in "=([{,:;!&|?"
    return previous.value in {"return", "yield"}


def _module_loads(
    tokens: Sequence[_JsToken],
) -> tuple[tuple[_ModuleLoad, ...], int]:
    loads: list[_ModuleLoad] = []
    dynamic_count = 0
    seen: set[tuple[str, int, int, str]] = set()

    def add(token: _JsToken, kind: str) -> None:
        key = (token.value, token.line, token.column, kind)
        if key in seen:
            return
        seen.add(key)
        loads.append(_ModuleLoad(token.value, token.line, token.column, kind))

    for index, token in enumerate(tokens):
        if token.kind != "identifier" or token.value not in {
            "export",
            "import",
            "require",
        }:
            continue
        previous = tokens[index - 1] if index else None
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.value == "require":
            if previous is not None and previous.value == ".":
                continue
            if following is None or following.value != "(":
                continue
            argument = tokens[index + 2] if index + 2 < len(tokens) else None
            closing = tokens[index + 3] if index + 3 < len(tokens) else None
            if (
                argument is not None
                and argument.kind == "string"
                and closing is not None
                and closing.value == ")"
            ):
                add(argument, "regular")
            else:
                dynamic_count += 1
            continue
        if token.value == "import":
            if following is not None and following.value == ".":
                continue
            if following is not None and following.value == "(":
                argument = tokens[index + 2] if index + 2 < len(tokens) else None
                closing = tokens[index + 3] if index + 3 < len(tokens) else None
                if (
                    argument is not None
                    and argument.kind == "string"
                    and closing is not None
                    and closing.value == ")"
                ):
                    add(argument, "dynamic")
                else:
                    dynamic_count += 1
                continue
            if following is not None and following.kind == "string":
                add(following, "regular")
                continue
        specifier = _from_specifier(tokens, index)
        if specifier is not None:
            add(specifier, "regular")
    return tuple(loads), dynamic_count


def _from_specifier(
    tokens: Sequence[_JsToken],
    start: int,
) -> _JsToken | None:
    opening = tokens[start]
    for index in range(start + 1, min(len(tokens), start + 257)):
        token = tokens[index]
        if token.value == ";":
            return None
        if (
            index > start + 1
            and token.kind == "identifier"
            and token.value in {"export", "import"}
        ):
            return None
        if (
            token.line > opening.line
            and token.kind == "identifier"
            and token.value
            in {"class", "const", "function", "if", "let", "return", "var"}
        ):
            return None
        if token.value != "from":
            continue
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        return (
            following if following is not None and following.kind == "string" else None
        )
    return None


def _nearest_package_root(path: Path, boundary: Path) -> Path:
    current = path
    while current != boundary and boundary in current.parents:
        if (current / "package.json").is_file():
            return current
        current = current.parent
    return boundary


def _source_scope(path: Path, root: Path) -> str:
    parts = {item.lower() for item in path.relative_to(root).parts}
    return (
        "test" if parts & {"__tests__", "spec", "specs", "test", "tests"} else "runtime"
    )


def _diagnostic(
    code: str,
    message: str,
    path: Path,
    *,
    severity: str = "error",
) -> Diagnostic:
    return Diagnostic(code, severity, message, SourceLocation(path))


def _status(name: str, complete: bool) -> Capability:
    return Capability(
        name,
        CapabilityState.COMPLETE if complete else CapabilityState.INCOMPLETE,
        None if complete else f"{name} evidence is incomplete",
    )
