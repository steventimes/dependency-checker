from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from depcheck.model import Diagnostic, SourceLocation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    MappingConfidence,
    PackageRef,
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
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dgram",
        "dns",
        "events",
        "fs",
        "http",
        "https",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "querystring",
        "readline",
        "stream",
        "string_decoder",
        "timers",
        "tls",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
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
        manifest_complete = True
        try:
            document = read_json(manifest)
            declarations = self._declarations(project, manifest, document)
        except StaticReadError as exc:
            manifest_complete = False
            diagnostics.append(_diagnostic("manifest.invalid", str(exc), manifest))

        resolved: tuple[ResolvedDependency, ...] = ()
        resolution_complete = True
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
        elif any(
            (project_root / name).is_file() for name in ("yarn.lock", "pnpm-lock.yaml")
        ):
            resolution_complete = False
            lock = next(
                project_root / name
                for name in ("yarn.lock", "pnpm-lock.yaml")
                if (project_root / name).is_file()
            )
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
        for section, scope in _DEPENDENCY_SECTIONS:
            values = document.get(section, {})
            if not isinstance(values, Mapping):
                continue
            for display_name, raw_constraint in sorted(values.items()):
                if not isinstance(display_name, str) or not isinstance(
                    raw_constraint, str
                ):
                    continue
                name = display_name.lower()
                key = (name, scope)
                if key in seen:
                    continue
                seen.add(key)
                declarations.append(
                    DependencyDeclaration(
                        project_id=project.project_id,
                        package=_package_ref(name),
                        constraint=VersionConstraint(
                            raw_constraint, "semver", raw_constraint
                        ),
                        source=SourceLocation(manifest, 1, 1),
                        scope=scope,
                        kind="direct",
                        metadata={"section": section},
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
        direct = {item.package.name for item in declarations}
        packages = document.get("packages")
        resolved: list[ResolvedDependency] = []
        if isinstance(packages, Mapping):
            nodes: dict[str, tuple[str, str, Mapping[object, object]]] = {}
            for lock_path, raw in sorted(packages.items()):
                if not isinstance(lock_path, str) or not isinstance(raw, Mapping):
                    continue
                name = _lock_package_name(lock_path)
                version = raw.get("version")
                if name is None or not isinstance(version, str) or not version:
                    continue
                nodes[lock_path] = (name, version, raw)
            for lock_path, (name, version, raw) in sorted(nodes.items()):
                dependencies = raw.get("dependencies", {})
                children = (
                    tuple(
                        _package_ref(str(child).lower())
                        for child in sorted(dependencies)
                        if isinstance(child, str)
                    )
                    if isinstance(dependencies, Mapping)
                    else ()
                )
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
                        direct=(name in direct and lock_path == f"node_modules/{name}"),
                        integrity=(
                            str(raw["integrity"])
                            if isinstance(raw.get("integrity"), str)
                            else None
                        ),
                        dependencies=children,
                        instance_id=lock_path,
                        dependency_links=tuple(links),
                    )
                )
            return tuple(resolved)
        dependencies = document.get("dependencies", {})
        if isinstance(dependencies, Mapping):
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
        direct: set[str],
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
            name = raw_name.lower()
            version = raw.get("version")
            children = raw.get("dependencies", {})
            instance_id = (
                f"{parent_instance}/node_modules/{name}"
                if parent_instance
                else f"node_modules/{name}"
            )
            child_refs = (
                tuple(_package_ref(str(child).lower()) for child in sorted(children))
                if isinstance(children, Mapping)
                else ()
            )
            child_links = (
                tuple(
                    ResolvedDependencyLink(
                        package=_package_ref(str(child).lower()),
                        version=(
                            str(child_raw["version"])
                            if isinstance(child_raw, Mapping)
                            and isinstance(child_raw.get("version"), str)
                            else None
                        ),
                        instance_id=f"{instance_id}/node_modules/{str(child).lower()}",
                    )
                    for child, child_raw in sorted(
                        children.items(), key=lambda item: str(item[0])
                    )
                    if isinstance(child, str)
                )
                if isinstance(children, Mapping)
                else ()
            )
            if isinstance(version, str) and version:
                resolved.append(
                    ResolvedDependency(
                        project.project_id,
                        _package_ref(name),
                        version,
                        SourceLocation(lock, 1, 1),
                        direct=top_level and name in direct,
                        dependencies=child_refs,
                        instance_id=instance_id,
                        dependency_links=child_links,
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
                if package_name is None:
                    continue
                mapped_name = self.mappings.get(
                    load.reference.lower()
                ) or self.mappings.get(package_name)
                confidence = (
                    MappingConfidence.CONFIGURED
                    if mapped_name is not None
                    else MappingConfidence.EXACT
                )
                mapped_name = mapped_name or package_name
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
                        mapping_reason=(
                            "project import mapping"
                            if confidence is MappingConfidence.CONFIGURED
                            else "literal npm package specifier"
                        ),
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


def _package_ref(name: str) -> PackageRef:
    canonical = name.lower()
    return PackageRef(
        ecosystem="npm",
        name=canonical,
        display_name=name,
        purl=f"pkg:npm/{quote(canonical, safe='/')}",
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
    if value.split("/", 1)[0] in _NODE_BUILTINS:
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
