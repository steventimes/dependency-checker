"""Bounded, flow-insensitive Python callable propagation over selected sources.

The caller supplies module ownership and entries. No target module is imported.
Names, aliases, lexical shadowing, callbacks and returned callables participate
in a monotone fixed point. Dynamic dispatch remains explicit incomplete evidence.
"""

from __future__ import annotations

import ast
import hashlib
import io
import tokenize
from collections import defaultdict
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from depcheck.bounded_io import read_bytes
from depcheck.evidence_input import objects, read_evidence_json, text
from depcheck.external_evidence import project_call_graph
from depcheck.path_policy import require_within_project
from depcheck.source_locations import parse_python_ast

MAX_SOURCES = 512
MAX_AST_NODES = 100000
MAX_FACTS = 100000
MAX_ROUNDS = 64


class _Scope:
    def __init__(
        self,
        identifier: str,
        module: str,
        parent: _Scope | None,
        *,
        kind: str = "module",
    ) -> None:
        self.identifier = identifier
        self.module = module
        self.parent = parent
        self.kind = kind
        self.bindings: dict[str, set[str]] = defaultdict(set)
        self.locals: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self.parameters: list[str] = []
        self.returns: set[str] = set()
        self.statements: list[ast.stmt] = []


class _Analysis:
    def __init__(self, root: Path, spec: dict[str, Any]) -> None:
        self.root = root
        self.spec = spec
        self.scopes: dict[str, _Scope] = {}
        self.modules: dict[str, _Scope] = {}
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, int, int], dict[str, Any]] = {}
        self.hashes: dict[str, str] = {}
        self.paths: dict[str, str] = {}
        self.owners: dict[str, str | None] = {}
        self.diagnostics: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.unresolved: dict[tuple[str, int, int], dict[str, Any]] = {}
        self.changed = False
        self.facts = 0

    def gap(self, code: str, module: str, node: ast.AST, message: str) -> None:
        line = getattr(node, "lineno", 1)
        self.diagnostics[(code, module, line)] = {
            "code": code,
            "severity": "warning",
            "path": self.paths[module],
            "line": line,
            "message": message,
        }
        if len(self.diagnostics) > 1024:
            raise ValueError("Python call diagnostic budget exhausted")

    def load(self) -> None:
        sources = objects(
            self.spec.get("sources"), "Python analysis sources", maximum=MAX_SOURCES
        )
        total_bytes = 0
        total_nodes = 0
        parsed = []
        for source in sources:
            relative = Path(text(source.get("path"), "Python source path"))
            module = text(source.get("module"), "Python module identity")
            if relative.is_absolute() or module in self.modules:
                raise ValueError(
                    "Python sources need relative paths and unique module identities"
                )
            candidate = self.root / relative
            require_within_project(
                self.root, candidate, operation="read selected Python call source"
            )
            raw = read_bytes(candidate, max_bytes=1024 * 1024)
            total_bytes += len(raw)
            if total_bytes > 16 * 1024 * 1024:
                raise ValueError("Python call source byte budget exhausted")
            try:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
                tree = parse_python_ast(raw.decode(encoding))
            except (SyntaxError, ValueError, RecursionError) as exc:
                raise ValueError(
                    f"Cannot parse selected Python source {relative}: {exc}"
                ) from exc
            total_nodes += sum(1 for _ in ast.walk(tree))
            if total_nodes > MAX_AST_NODES:
                raise ValueError("Python call AST budget exhausted")
            pending: list[tuple[ast.AST, int]] = [(tree, 0)]
            while pending:
                current, depth = pending.pop()
                if depth > 64:
                    raise ValueError("Python call AST depth budget exhausted")
                pending.extend(
                    (child, depth + 1) for child in ast.iter_child_nodes(current)
                )
            owner = source.get("package_purl")
            if owner is not None:
                package_url = PackageURL.from_string(
                    text(owner, "Python source package PURL")
                )
                if not package_url.version:
                    raise ValueError(
                        "Source package ownership requires a versioned PURL"
                    )
                owner = package_url.to_string()
            self.owners[module] = owner
            self.paths[module] = relative.as_posix()
            self.hashes[relative.as_posix()] = hashlib.sha256(raw).hexdigest()
            scope = _Scope(f"{module}:<module>", module, None)
            self.modules[module] = scope
            self.scopes[scope.identifier] = scope
            self.node(scope.identifier, scope, tree, kind="module")
            parsed.append((scope, tree.body))
        for scope, statements in parsed:
            self.collect(scope, statements)

    def node(
        self, identifier: str, scope: _Scope, node: ast.AST, *, kind: str = "function"
    ) -> str:
        self.nodes.setdefault(
            identifier,
            {
                "id": identifier,
                "symbol": identifier,
                "kind": kind,
                "package_purl": self.owners.get(scope.module),
                "location": {
                    "path": self.paths[scope.module],
                    "line": getattr(node, "lineno", 1),
                },
                "identity_provenance": "explicit-source-module-map",
            },
        )
        if len(self.nodes) > MAX_FACTS:
            raise ValueError("Python call node budget exhausted")
        return identifier

    def collect(self, scope: _Scope, statements: list[ast.stmt]) -> None:
        scope.statements = statements

        # Gather lexical stores before resolving names, including stores after calls.
        def stores(node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope.locals.add(node.name)
                return
            if isinstance(node, ast.Global):
                scope.globals.update(node.names)
            elif isinstance(node, ast.Nonlocal):
                scope.nonlocals.update(node.names)
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                scope.locals.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                scope.locals.update(
                    alias.asname
                    or (
                        alias.name.split(".")[0]
                        if isinstance(node, ast.Import)
                        else alias.name
                    )
                    for alias in node.names
                )
            for child in ast.iter_child_nodes(node):
                stores(child)

        for statement in statements:
            stores(statement)
        scope.locals -= scope.globals | scope.nonlocals

        def definitions(statement: ast.stmt) -> None:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                parent = scope
                # Class namespaces are not lexical enclosing scopes of methods.
                lexical_parent = scope.parent if scope.kind == "class" else scope
                prefix = scope.identifier.split(":", 1)[1]
                qualified = (
                    statement.name
                    if scope.kind == "module"
                    else f"{prefix}.{statement.name}"
                )
                identifier = f"{scope.module}:{qualified}"
                if identifier in self.scopes:
                    self.gap(
                        "calls.redefinition",
                        scope.module,
                        statement,
                        "Repeated definitions are merged conservatively; execution order is unknown.",
                    )
                    return
                child = _Scope(
                    identifier,
                    scope.module,
                    lexical_parent,
                    kind="class" if isinstance(statement, ast.ClassDef) else "function",
                )
                self.scopes[identifier] = child
                parent.bindings[statement.name].add(identifier)
                self.node(identifier, child, statement, kind=child.kind)
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    arguments = statement.args
                    child.parameters = [
                        arg.arg for arg in (*arguments.posonlyargs, *arguments.args)
                    ]
                    child.locals.update(
                        arg.arg
                        for arg in (
                            *arguments.posonlyargs,
                            *arguments.args,
                            *arguments.kwonlyargs,
                        )
                    )
                    if (
                        arguments.vararg
                        or arguments.kwarg
                        or arguments.defaults
                        or arguments.kw_defaults
                    ):
                        self.gap(
                            "calls.signature-incomplete",
                            scope.module,
                            statement,
                            "Default, keyword-only or variadic argument binding is incomplete.",
                        )
                    if scope.kind == "class" and child.parameters:
                        child.bindings[child.parameters[0]].add(
                            f"instance:{scope.identifier}"
                        )
                if statement.decorator_list:
                    self.gap(
                        "calls.decorators",
                        scope.module,
                        statement,
                        "Decorators can replace callable identity; retained definitions are candidates.",
                    )
                if isinstance(statement, ast.ClassDef) and statement.bases:
                    self.gap(
                        "calls.inheritance-dispatch",
                        scope.module,
                        statement,
                        "Inherited methods and metaclass dispatch are not resolved.",
                    )
                self.collect(child, statement.body)
                return
            for field in ("body", "orelse", "finalbody"):
                for item in getattr(statement, field, []):
                    if isinstance(item, ast.stmt):
                        definitions(item)
            if isinstance(statement, (ast.Try, ast.TryStar)):
                for handler in statement.handlers:
                    for item in handler.body:
                        definitions(item)

        for statement in statements:
            definitions(statement)

    def lookup(self, scope: _Scope, name: str) -> set[str]:
        if name in scope.globals:
            return set(self.modules[scope.module].bindings.get(name, ()))
        if name in scope.locals or name in scope.bindings:
            return set(scope.bindings.get(name, ()))
        if scope.parent is not None:
            return self.lookup(scope.parent, name)
        return set()

    def bind(self, scope: _Scope, name: str, values: set[str]) -> None:
        target = self.modules[scope.module] if name in scope.globals else scope
        if name in scope.nonlocals:
            target = scope.parent or scope
            while target.parent is not None and name not in target.locals:
                target = target.parent
        before = len(target.bindings[name])
        target.bindings[name].update(values)
        added = len(target.bindings[name]) - before
        self.facts += added
        self.changed |= bool(added)
        if self.facts > MAX_FACTS:
            raise ValueError("Python callable propagation fact budget exhausted")

    def imported(self, module: str, member: str | None = None) -> set[str]:
        qualified = f"{module}.{member}" if member else module
        if member is not None and (
            qualified in self.modules
            or any(name.startswith(qualified + ".") for name in self.modules)
        ):
            return {f"module:{qualified}"}
        if module in self.modules:
            if member is None:
                return {f"module:{module}"}
            if member in self.modules[module].bindings:
                return set(self.modules[module].bindings[member])
            if f"{module}.{member}" in self.modules:
                return {f"module:{module}.{member}"}
            return set()
        if member is None and any(
            name.startswith(module + ".") for name in self.modules
        ):
            return {f"module:{module}"}
        return {f"external:{module}" + (f".{member}" if member else "")}

    def expression(self, scope: _Scope, node: ast.AST | None) -> set[str]:
        if isinstance(node, ast.Name):
            return self.lookup(scope, node.id)
        if isinstance(node, ast.Attribute):
            values = set()
            for base in self.expression(scope, node.value):
                if base.startswith("module:"):
                    values.update(self.imported(base[7:], node.attr))
                elif base.startswith("external:"):
                    values.add(f"{base}.{node.attr}")
                elif base.startswith("instance:"):
                    identifier = f"{base[9:]}.{node.attr}"
                    if identifier in self.scopes:
                        values.add(identifier)
            return values
        if isinstance(node, ast.Call):
            targets = self.expression(scope, node.func)
            results = set()
            key = (scope.identifier, node.lineno, node.col_offset)
            observed_target = False
            for target in targets:
                if target.startswith("module:"):
                    continue
                if target.startswith("external:"):
                    self.nodes.setdefault(
                        target,
                        {
                            "id": target,
                            "symbol": target[9:],
                            "kind": "external-symbol",
                            "package_purl": None,
                            "identity_provenance": "imported-name-only; distribution-unknown",
                        },
                    )
                    self.gap(
                        "calls.external-library-source",
                        scope.module,
                        node,
                        "External callable bodies are unavailable; the imported symbol name is a candidate only.",
                    )
                elif target not in self.scopes:
                    continue
                else:
                    callee = self.scopes[target]
                    if callee.kind == "class":
                        results.add(f"instance:{target}")
                        self.gap(
                            "calls.constructor-dispatch",
                            scope.module,
                            node,
                            "Constructor, descriptor and special-method dispatch are incomplete.",
                        )
                    else:
                        results.update(callee.returns)
                        bound_method = isinstance(node.func, ast.Attribute) and any(
                            item.startswith("instance:")
                            for item in self.expression(scope, node.func.value)
                        )
                        parameters = (
                            callee.parameters[1:] if bound_method else callee.parameters
                        )
                        for parameter, argument in zip(parameters, node.args):
                            self.bind(
                                callee, parameter, self.expression(scope, argument)
                            )
                        for keyword in node.keywords:
                            if keyword.arg in parameters:
                                self.bind(
                                    callee,
                                    keyword.arg,
                                    self.expression(scope, keyword.value),
                                )
                edge_key = (*key[:1], target, *key[1:])
                self.edges[edge_key] = {
                    "source": scope.identifier,
                    "target": target,
                    "kind": "inferred",
                    "location": {
                        "path": self.paths[scope.module],
                        "line": node.lineno,
                        "byte_column": node.col_offset + 1,
                    },
                    "dispatch": "flow-insensitive-callable-candidate",
                    "activation": "unknown",
                }
                observed_target = True
                if len(self.edges) > MAX_FACTS:
                    raise ValueError("Python call edge budget exhausted")
            if not observed_target:
                self.unresolved[key] = {
                    "scope": scope.identifier,
                    "path": self.paths[scope.module],
                    "line": node.lineno,
                    "byte_column": node.col_offset + 1,
                    "expression_kind": type(node.func).__name__,
                    "status": "unresolved",
                }
            else:
                self.unresolved.pop(key, None)
            for argument in (*node.args, *(keyword.value for keyword in node.keywords)):
                self.expression(scope, argument)
            return results
        if isinstance(node, ast.IfExp):
            self.expression(scope, node.test)
            return self.expression(scope, node.body) | self.expression(
                scope, node.orelse
            )
        if isinstance(
            node,
            (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.Lambda),
        ):
            self.gap(
                "calls.dynamic-scope",
                scope.module,
                node,
                "Comprehension and lambda scopes are not propagated.",
            )
            return set()
        if node is not None:
            for child in ast.iter_child_nodes(node):
                self.expression(scope, child)
        return set()

    def statement(self, scope: _Scope, node: ast.stmt) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                self.expression(scope, decorator)
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                self.bind(
                    scope,
                    alias.asname or alias.name.split(".")[0],
                    self.imported(
                        alias.name if alias.asname else alias.name.split(".")[0]
                    ),
                )
            return
        if isinstance(node, ast.ImportFrom):
            prefix = node.module or ""
            if node.level:
                parts = scope.module.split(".")
                is_package = Path(self.paths[scope.module]).name == "__init__.py"
                base = parts if is_package else parts[:-1]
                if node.level > len(base):
                    self.gap(
                        "calls.relative-import",
                        scope.module,
                        node,
                        "Relative import escapes the supplied module map.",
                    )
                    return
                prefix = ".".join(
                    base[: len(base) - node.level + 1] + ([prefix] if prefix else [])
                )
            for alias in node.names:
                if alias.name == "*":
                    self.gap(
                        "calls.wildcard-import",
                        scope.module,
                        node,
                        "Wildcard exports are not resolved.",
                    )
                    continue
                self.bind(
                    scope, alias.asname or alias.name, self.imported(prefix, alias.name)
                )
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            values = self.expression(scope, node.value)
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    self.bind(scope, target.id, values)
                else:
                    self.gap(
                        "calls.structured-assignment",
                        scope.module,
                        node,
                        "Destructuring and attribute/subscript assignments are not propagated.",
                    )
            return
        if isinstance(node, ast.Return):
            values = self.expression(scope, node.value)
            if not values <= scope.returns:
                scope.returns.update(values)
                self.changed = True
            return
        if isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.TryStar,
                ast.With,
                ast.AsyncWith,
                ast.Match,
            ),
        ):
            self.gap(
                "calls.conditional-activation",
                scope.module,
                node,
                "Branch/exception/loop execution is unknown; callable candidates are merged.",
            )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                self.statement(scope, child)
            elif isinstance(child, ast.ExceptHandler):
                for statement in child.body:
                    self.statement(scope, statement)
            else:
                self.expression(scope, child)

    def run(self) -> dict[str, Any]:
        self.load()
        converged = False
        rounds = 0
        for rounds in range(1, MAX_ROUNDS + 1):
            self.changed = False
            for scope in self.scopes.values():
                for statement in scope.statements:
                    self.statement(scope, statement)
            if not self.changed:
                converged = True
                break
        coverage = {
            "state": "incomplete",
            "fixed_point": "converged" if converged else "budget-exhausted",
            "rounds": rounds,
            "unresolved_call_count": len(self.unresolved),
            "limitations": [
                "flow-insensitive",
                "dynamic-dispatch",
                "reflection",
                "decorators",
                "metaclasses",
                "native-extensions",
                "external-library-bodies",
                "runtime-activation",
            ],
        }
        graph = {
            "schema": "depcheck.call-graph.v1",
            "tool": {"name": "depcheck-python-static", "version": "1"},
            "mode": "source-callable-propagation",
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
            "entries": self.spec.get("entries", []),
            "vulnerability_symbols": self.spec.get("vulnerability_symbols", []),
            "source_hashes": self.hashes,
            "coverage": coverage,
        }
        tables, metadata = project_call_graph(graph)
        return {
            "graph": graph,
            "tables": tables,
            "metadata": metadata,
            "unresolved_calls": list(self.unresolved.values()),
            "diagnostics": list(self.diagnostics.values()),
        }


def analyze_python_calls(
    root: Path, analysis_file: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Invalid Python call evidence pagination")
    spec, digest = read_evidence_json(root, analysis_file)
    if spec.get("schema") != "depcheck.python-call-analysis.v1":
        raise ValueError(
            "Expected depcheck.python-call-analysis.v1 with explicit source/module ownership"
        )
    result = _Analysis(root, spec).run()
    tables = {
        **result["tables"],
        "unresolved_calls": result["unresolved_calls"],
        "diagnostics": result["diagnostics"],
    }
    return {
        "schema": "depcheck.python-calls.v1",
        "read_only": True,
        "input": {"path": analysis_file, "sha256": digest},
        "metadata": result["metadata"],
        "tables": {
            name: rows[offset : offset + limit] for name, rows in tables.items()
        },
        "counts": {name: len(rows) for name, rows in tables.items()},
        "offset": offset,
        "next_offset": offset + limit
        if any(len(rows) > offset + limit for rows in tables.values())
        else None,
        "security": "not-evaluated",
        "finding_effect": "none",
    }
