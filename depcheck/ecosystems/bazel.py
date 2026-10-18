"""Bounded Bzlmod declaration inventory; never evaluate Starlark or run Bazel."""

from __future__ import annotations

import ast
import io
import json
from pathlib import Path
import re
import tokenize
from typing import Any

from depcheck.bounded_io import repository_operation
from depcheck.ecosystems.base import EcosystemPack, ProviderContext
from depcheck.ecosystems.static import (
    StaticReadError,
    discover_files,
    exclusions_for,
    read_text,
)
from depcheck.model import (
    Capability,
    CapabilityState,
    DependencyDeclaration,
    Diagnostic,
    EvidenceBundle,
    PackageRef,
    ProjectUnit,
    SourceLocation,
    VersionConstraint,
)
from depcheck.source_locations import SourcePositions, parse_python_ast

_NAME = re.compile(r"[a-z](?:[a-z0-9._-]*[a-z0-9])?\Z")
_FIELDS = frozenset(
    {"name", "version", "repo_name", "dev_dependency", "max_compatibility_level"}
)
_UNKNOWN = object()
_MAX_TOKENS = 100_000
_MAX_NODES = 100_000
_MAX_RECORDS = 10_000
_MAX_CONTEXT_BYTES = 8 * 1024 * 1024
_MAX_DIAGNOSTICS = 64


class BazelProjectDetector:
    @repository_operation("context.repository_root")
    def detect(self, context: ProviderContext) -> tuple[ProjectUnit, ...]:
        root = context.repository_root
        projects = []
        for manifest in discover_files(
            root,
            names=frozenset({"MODULE.bazel"}),
            excluded_directories=exclusions_for(context.settings),
        ):
            relative = manifest.parent.relative_to(root)
            lock = manifest.with_name("MODULE.bazel.lock")
            projects.append(
                ProjectUnit(
                    ProjectUnit.stable_id(relative, "Bazel", "bzlmod"),
                    relative,
                    "starlark",
                    "Bazel",
                    "bzlmod",
                    (manifest.relative_to(root),),
                    (lock.relative_to(root),)
                    if lock.exists() or lock.is_symlink()
                    else (),
                )
            )
        return tuple(projects)


class BazelEvidenceCollector:
    @repository_operation("context.repository_root")
    def collect(
        self, context: ProviderContext, project: ProjectUnit, pack: EcosystemPack
    ) -> EvidenceBundle:
        del pack
        root = context.repository_root
        manifest = root / project.manifests[0]
        declarations: list[DependencyDeclaration] = []
        diagnostics: list[Diagnostic] = []
        try:
            text = read_text(manifest)
            positions = SourcePositions(manifest, text)
            tree, strings = _syntax_tree(text, manifest)
            context_bytes = 0
            for statement in tree.body:
                source = positions.ast_node(statement)
                if len(diagnostics) >= _MAX_DIAGNOSTICS:
                    diagnostics.append(
                        _gap("Bzlmod diagnostic budget exceeded", source)
                    )
                    break
                if (
                    isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                ):
                    continue  # A docstring is not a dependency call.
                call = statement.value if isinstance(statement, ast.Expr) else None
                if not isinstance(call, ast.Call) or not isinstance(
                    call.func, ast.Name
                ):
                    diagnostics.append(
                        _gap(
                            "Only literal top-level bazel_dep calls are collected; other statements remain unevaluated.",
                            source,
                        )
                    )
                    continue
                if call.func.id == "module":
                    continue  # Module identity is not a dependency or installed version.
                if call.func.id != "bazel_dep":
                    diagnostics.append(
                        _gap(
                            f"{call.func.id} dependency semantics are not collected.",
                            source,
                        )
                    )
                    continue
                declaration, problems = _declaration(project, call, positions, strings)
                diagnostics.extend(problems)
                if declaration is None:
                    continue
                context_bytes += (
                    256
                    + len(declaration.package.name.encode())
                    + len(json.dumps(declaration.metadata, ensure_ascii=False).encode())
                )
                if (
                    len(declarations) >= _MAX_RECORDS
                    or context_bytes > _MAX_CONTEXT_BYTES
                ):
                    diagnostics.append(
                        _gap(
                            "Bzlmod declaration/context budget exceeded; retained inventory is incomplete.",
                            source,
                        )
                    )
                    break
                declarations.append(declaration)
        except (StaticReadError, SyntaxError, ValueError, RecursionError) as exc:
            diagnostics.append(
                Diagnostic(
                    "manifest.invalid-bzlmod",
                    "error",
                    str(exc),
                    SourceLocation(manifest),
                )
            )
        manifest_complete = not diagnostics
        for relative in project.locks:
            path = root / relative
            try:
                read_text(path)
            except StaticReadError as exc:
                diagnostics.append(
                    Diagnostic(
                        "manifest.invalid-bzlmod-lock",
                        "error",
                        str(exc),
                        SourceLocation(path),
                    )
                )
            diagnostics.append(
                _gap(
                    "Bazel lockfile contents are not interpreted as selected or installed module versions.",
                    SourceLocation(path),
                )
            )
        diagnostics.append(
            Diagnostic(
                "resolution.bazel-module-graph-unknown",
                "warning",
                "bazel_dep versions are source requests. Module selection, registries, overrides, extensions, root/dev/nodep conditions and the installed graph remain unknown.",
                SourceLocation(manifest),
            )
        )
        return EvidenceBundle(
            project,
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            evidence_files=tuple(
                root / p for p in (*project.manifests, *project.locks)
            ),
            capabilities=(
                Capability(
                    "manifest",
                    CapabilityState.COMPLETE
                    if manifest_complete
                    else CapabilityState.INCOMPLETE,
                ),
                Capability(
                    "resolution",
                    CapabilityState.INCOMPLETE,
                    "Bazel module selection and installed versions are unknown",
                ),
                Capability(
                    "usage",
                    CapabilityState.UNSUPPORTED,
                    "Bazel build/source usage is not collected",
                ),
                Capability(
                    "mapping",
                    CapabilityState.UNSUPPORTED,
                    "Bazel module names do not establish source or package-manager ownership",
                ),
            ),
        )


def _syntax_tree(
    text: str, path: Path
) -> tuple[ast.Module, dict[tuple[int, int], tokenize.TokenInfo]]:
    strings = {}
    try:
        for count, token in enumerate(
            tokenize.generate_tokens(io.StringIO(text).readline), 1
        ):
            if count > _MAX_TOKENS:
                raise StaticReadError("Bzlmod token budget exceeded")
            if token.type == tokenize.STRING:
                strings[token.start] = token
    except (tokenize.TokenError, IndentationError) as exc:
        raise StaticReadError(f"Unsupported Bzlmod syntax: {exc}") from exc
    tree = parse_python_ast(text)
    if any(count > _MAX_NODES for count, _ in enumerate(ast.walk(tree), 1)):
        raise StaticReadError("Bzlmod AST node budget exceeded")
    return tree, strings


def _literal(
    node: ast.AST,
    positions: SourcePositions,
    strings: dict[tuple[int, int], tokenize.TokenInfo],
) -> Any:
    if isinstance(node, ast.Constant):
        if type(node.value) in {bool, int, type(None)}:
            return node.value
        if isinstance(node.value, str):
            location = positions.ast_node(node)
            token = strings.get((location.line or 0, (location.column or 0) - 1))
            # Python's AST is only a syntax reader here. Reject escapes, prefixes
            # and implicit concatenation rather than guessing Starlark semantics.
            if (
                token
                and token.string.startswith(("'", '"'))
                and "\\" not in token.string
                and token.start[0] == token.end[0] == node.lineno == node.end_lineno
                and node.end_col_offset is not None
                and len(token.string.encode()) == node.end_col_offset - node.col_offset
            ):
                return node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
        and type(node.operand.value) is int
    ):
        return (
            -node.operand.value if isinstance(node.op, ast.USub) else node.operand.value
        )
    return _UNKNOWN


def _declaration(
    project: ProjectUnit,
    call: ast.Call,
    positions: SourcePositions,
    strings: dict[tuple[int, int], tokenize.TokenInfo],
) -> tuple[DependencyDeclaration | None, list[Diagnostic]]:
    source = positions.ast_node(call)
    keywords = {item.arg: item.value for item in call.keywords if item.arg}
    if call.args or len(keywords) != len(call.keywords):
        return None, [
            _gap(
                "Positional, expanded or duplicate bazel_dep arguments are ambiguous; no dependency is chosen.",
                source,
            )
        ]
    values = {
        key: _literal(value, positions, strings)
        for key, value in keywords.items()
        if key in _FIELDS
    }
    name = values.get("name", _UNKNOWN)
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return None, [
            _gap(
                "Bazel dependency name is not a supported literal module name.", source
            )
        ]
    dynamic = [key for key, value in values.items() if value is _UNKNOWN]
    invalid = []
    for key, value in values.items():
        expected = {
            "name": (str,),
            "version": (str,),
            "repo_name": (str, type(None)),
            "dev_dependency": (bool,),
            "max_compatibility_level": (int,),
        }[key]
        if value is not _UNKNOWN and type(value) not in expected:
            invalid.append(key)
    unknown = set(keywords) - _FIELDS
    diagnostics = []
    if dynamic or invalid or unknown:
        diagnostics.append(
            _gap(
                "Dynamic, invalid or unsupported bazel_dep arguments leave selection and affected fields unknown.",
                source,
            )
        )
    version = values.get("version", "")
    dev = values.get("dev_dependency", False)
    return DependencyDeclaration(
        project.project_id,
        PackageRef("Bazel", name, name),
        VersionConstraint(version if isinstance(version, str) else "", "bazel"),
        positions.ast_node(keywords["name"]),
        scope="development" if dev is True else "build" if dev is False else "unknown",
        kind="conditional",
        metadata={
            "mechanism": "bazel_dep",
            "activation": "unknown",
            "arguments": {
                key: value for key, value in values.items() if value is not _UNKNOWN
            },
            "dynamic_arguments": dynamic,
            "invalid_arguments": invalid,
            "uncollected_arguments": bool(unknown),
        },
    ), diagnostics


def _gap(message: str, source: SourceLocation) -> Diagnostic:
    return Diagnostic("manifest.bazel-uncollected", "warning", message, source)


def create_bazel_pack() -> EcosystemPack:
    return EcosystemPack(
        "Bazel",
        BazelProjectDetector(),
        collector=BazelEvidenceCollector(),
        capabilities=frozenset({"manifest"}),
    )
