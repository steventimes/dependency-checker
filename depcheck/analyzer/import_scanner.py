from __future__ import annotations

import ast
import json
import logging
import os
import sys
import tokenize
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import ClassVar

from depcheck.model import Diagnostic, ImportEvidence, ImportScanResult, SourceLocation

logger = logging.getLogger(__name__)


class _ImportVisitor(ast.NodeVisitor):
    """提取导入位置，并跟踪只影响依赖分类的控制流上下文。"""

    def __init__(self, path: Path, scope: str) -> None:
        self.path = path
        self.scope = scope
        self.kind = "regular"
        self.imports: list[ImportEvidence] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record(alias.name, node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:
            self._record(node.module, node)

    def visit_If(self, node: ast.If) -> None:
        if self._is_type_checking(node.test):
            self._visit_with_kind(node.body, "typing")
            for child in node.orelse:
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        if any(self._handles_import_error(handler.type) for handler in node.handlers):
            self._visit_with_kind(node.body, "optional")
            for handler in node.handlers:
                self.visit(handler)
            for child in (*node.orelse, *node.finalbody):
                self.visit(child)
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        module: str | None = None
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ) and (
            isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            )
        ):
            module = node.args[0].value
        if module:
            self._record(module, node, kind="dynamic")
        self.generic_visit(node)

    def _record(self, module: str, node: ast.AST, *, kind: str | None = None) -> None:
        top_level = module.split(".", 1)[0]
        self.imports.append(
            ImportEvidence(
                module=top_level,
                source=SourceLocation(
                    self.path,
                    line=getattr(node, "lineno", None),
                    column=(getattr(node, "col_offset", 0) + 1),
                ),
                scope=self.scope,
                kind=self.kind if self.kind != "regular" else (kind or "regular"),
            )
        )

    def _visit_with_kind(self, nodes: list[ast.stmt], kind: str) -> None:
        previous = self.kind
        self.kind = kind
        for node in nodes:
            self.visit(node)
        self.kind = previous

    @staticmethod
    def _is_type_checking(node: ast.expr) -> bool:
        return (isinstance(node, ast.Name) and node.id == "TYPE_CHECKING") or (
            isinstance(node, ast.Attribute)
            and node.attr == "TYPE_CHECKING"
            and isinstance(node.value, ast.Name)
            and node.value.id == "typing"
        )

    @staticmethod
    def _handles_import_error(node: ast.expr | None) -> bool:
        if isinstance(node, ast.Name):
            return node.id in {"ImportError", "ModuleNotFoundError"}
        if isinstance(node, ast.Tuple):
            return any(_ImportVisitor._handles_import_error(item) for item in node.elts)
        return False


class ImportScanner:
    IGNORED_DIRECTORIES: ClassVar[set[str]] = {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }

    def __init__(self, excluded_directories: Iterable[str] = ()) -> None:
        self.excluded_directories = tuple(excluded_directories)

    def scan_directory(self, path: Path) -> set[str]:
        """兼容旧接口：返回所有作用域中出现过的第三方顶层模块。"""
        return {item.module for item in self.scan_detailed(path).imports}

    def discover_files(self, root: Path) -> tuple[Path, ...]:
        """公开稳定的文件发现边界，供增量索引复用。"""
        return tuple(self._iter_python_files(Path(root)))

    def scan_files(self, root: Path, paths: list[Path]) -> ImportScanResult:
        """只解析调用方指定的文件，同时保持完整扫描的过滤语义。"""
        project_root = Path(root)
        local_modules = self._get_local_modules(project_root)
        imports: list[ImportEvidence] = []
        diagnostics: list[Diagnostic] = []
        files: list[Path] = []
        seen_files: set[Path] = set()

        for raw_path in paths:
            file_path = Path(raw_path)
            if file_path in seen_files:
                continue
            seen_files.add(file_path)
            files.append(file_path)
            scope = self._scope_for_file(file_path, project_root)
            file_imports, file_diagnostics = self._scan_file_detailed(file_path, scope)
            diagnostics.extend(file_diagnostics)
            imports.extend(
                item
                for item in file_imports
                if item.module not in sys.stdlib_module_names
                and item.module not in local_modules
                and item.module != "__future__"
            )

        unique: list[ImportEvidence] = []
        seen_imports: set[tuple[object, ...]] = set()
        for item in imports:
            key = (
                item.module,
                item.source.path,
                item.source.line,
                item.source.column,
                item.scope,
                item.kind,
            )
            if key not in seen_imports:
                seen_imports.add(key)
                unique.append(item)

        return ImportScanResult(tuple(unique), tuple(diagnostics), tuple(files))

    def scan_detailed(self, path: Path) -> ImportScanResult:
        root = Path(path)
        local_modules = self._get_local_modules(root)
        imports: list[ImportEvidence] = []
        diagnostics: list[Diagnostic] = []
        files: list[Path] = []

        for file_path in self._iter_python_files(root):
            files.append(file_path)
            scope = self._scope_for_file(file_path, root)
            file_imports, file_diagnostics = self._scan_file_detailed(file_path, scope)
            diagnostics.extend(file_diagnostics)
            imports.extend(
                item
                for item in file_imports
                if item.module not in sys.stdlib_module_names
                and item.module not in local_modules
                and item.module != "__future__"
            )

        # 同一位置的重复 AST 证据只保留一次，但同一包在不同文件的位置全部保留。
        unique: list[ImportEvidence] = []
        seen: set[tuple[object, ...]] = set()
        for item in imports:
            key = (
                item.module,
                item.source.path,
                item.source.line,
                item.source.column,
                item.scope,
                item.kind,
            )
            if key not in seen:
                seen.add(key)
                unique.append(item)

        logger.info(
            "Scanned %s files. Found %s third-party import locations.",
            len(files),
            len(unique),
        )
        return ImportScanResult(tuple(unique), tuple(diagnostics), tuple(files))

    def generate_dot(self, project_root: Path, output_file: Path):
        """Generates a Graphviz .dot file for visualization."""
        graph_data = self._scan_for_graph(project_root)
        local_modules = self._get_local_modules(project_root)

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("digraph DepGraph {\n")
                f.write("  rankdir=LR;\n")
                f.write('  node [fontname="Helvetica"];\n')
                f.write("  edge [fontsize=10];\n\n")
                f.write("  // Styles\n")
                f.write('  node [shape=box, style=filled, fillcolor="#E3F2FD"];\n')

                for file_path, imports in graph_data.items():
                    node_id = f"file_{file_path.replace('/', '_').replace('.', '_')}"
                    f.write(f'  "{node_id}" [label="{file_path}"];\n')

                    for imported in imports:
                        imp_node = f"pkg_{imported}"
                        if imported in local_modules:
                            f.write(
                                f'  "{imp_node}" [shape=ellipse, style=filled, '
                                f'fillcolor="#FFF3E0", label="{imported}"];\n'
                            )
                            f.write(
                                f'  "{node_id}" -> "{imp_node}" '
                                f'[style=dashed, color="grey"];\n'
                            )
                        else:
                            f.write(
                                f'  "{imp_node}" [shape=ellipse, style=filled, '
                                f'fillcolor="#E8F5E9", label="{imported}"];\n'
                            )
                            f.write(f'  "{node_id}" -> "{imp_node}" [color="black"];\n')

                f.write("}\n")
            logger.info(f"Dependency graph saved to {output_file}")
        except (OSError, UnicodeError) as exc:
            logger.error(f"Failed to write graph file: {exc}")
            raise

    def _scan_for_graph(self, root: Path) -> dict[str, set[str]]:
        mapping: dict[str, set[str]] = {}
        for file_path in self._iter_python_files(root):
            rel_path = file_path.relative_to(root).as_posix()
            mapping[rel_path] = self.scan_file_(file_path)
        return mapping

    def _scan_file_detailed(
        self, path: Path, scope: str
    ) -> tuple[list[ImportEvidence], list[Diagnostic]]:
        if path.suffix == ".ipynb":
            return self._scan_notebook_detailed(path, scope)
        try:
            # tokenize.open 遵循 PEP 263，避免把合法的非 UTF-8 Python 文件误判为损坏。
            with tokenize.open(path) as handle:
                tree = ast.parse(handle.read(), filename=str(path))
        except SyntaxError as exc:
            return [], [
                Diagnostic(
                    code="source.syntax-error",
                    severity="error",
                    message=f"Python 语法错误：{exc.msg}",
                    source=SourceLocation(path, line=exc.lineno, column=exc.offset),
                )
            ]
        except (OSError, UnicodeError) as exc:
            return [], [
                Diagnostic(
                    code="source.read-error",
                    severity="error",
                    message=f"无法读取 Python 源文件：{exc}",
                    source=SourceLocation(path),
                )
            ]

        visitor = _ImportVisitor(path, scope)
        visitor.visit(tree)
        return visitor.imports, []

    def _scan_notebook_detailed(
        self, path: Path, scope: str
    ) -> tuple[list[ImportEvidence], list[Diagnostic]]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            return [], [
                Diagnostic(
                    code="source.notebook-read-error",
                    severity="error",
                    message=f"无法读取 notebook：{exc}",
                    source=SourceLocation(path),
                )
            ]
        cells = payload.get("cells") if isinstance(payload, Mapping) else None
        if not isinstance(cells, list):
            return [], [
                Diagnostic(
                    code="source.notebook-format-error",
                    severity="error",
                    message="notebook 缺少 cells 数组",
                    source=SourceLocation(path),
                )
            ]

        imports: list[ImportEvidence] = []
        diagnostics: list[Diagnostic] = []
        line_offset = 0
        for cell_number, cell in enumerate(cells, start=1):
            if not isinstance(cell, Mapping) or cell.get("cell_type") != "code":
                continue
            raw_source = cell.get("source", "")
            if isinstance(raw_source, str):
                source = raw_source
            elif isinstance(raw_source, list) and all(
                isinstance(part, str) for part in raw_source
            ):
                source = "".join(raw_source)
            else:
                diagnostics.append(
                    Diagnostic(
                        code="source.notebook-format-error",
                        severity="error",
                        message=f"notebook 第 {cell_number} 个代码单元的 source 无效",
                        source=SourceLocation(path, line=line_offset + 1),
                    )
                )
                line_offset += 2
                continue

            sanitized = _sanitize_notebook_source(source)
            try:
                tree = ast.parse(sanitized, filename=str(path))
            except SyntaxError as exc:
                diagnostics.append(
                    Diagnostic(
                        code="source.notebook-syntax-error",
                        severity="error",
                        message=(
                            f"notebook 第 {cell_number} 个代码单元语法错误：{exc.msg}"
                        ),
                        source=SourceLocation(
                            path,
                            line=line_offset + (exc.lineno or 1),
                            column=exc.offset,
                        ),
                    )
                )
            else:
                ast.increment_lineno(tree, line_offset)
                visitor = _ImportVisitor(path, scope)
                visitor.visit(tree)
                imports.extend(visitor.imports)
            line_offset += max(source.count("\n") + 1, 1) + 1
        return imports, diagnostics

    def _get_local_modules(self, root: Path) -> set[str]:
        local_modules: set[str] = set()
        if not root.exists():
            return local_modules

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_path(
                    Path(dirpath) / dirname,
                    root,
                )
            ]
            current_dir = Path(dirpath)
            if "__init__.py" in filenames or "__init__.pyi" in filenames:
                local_modules.add(current_dir.name)
            for filename in filenames:
                suffix = Path(filename).suffix
                if suffix not in {".py", ".pyi"} or filename.startswith("."):
                    continue
                module_name = Path(filename).stem
                if module_name != "__init__":
                    local_modules.add(module_name)

            # src 布局允许无 __init__.py 的命名空间包。
            if current_dir.name == "src":
                local_modules.update(
                    name for name in dirnames if not name.startswith(".")
                )
        return local_modules

    def _iter_python_files(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not self._should_ignore_path(
                    Path(dirpath) / dirname,
                    root,
                )
            ]
            current_dir = Path(dirpath)
            for filename in sorted(filenames):
                if filename.startswith(".") or Path(filename).suffix not in {
                    ".ipynb",
                    ".py",
                    ".pyi",
                }:
                    continue
                yield current_dir / filename

    def _should_ignore_dir(self, name: str) -> bool:
        return name.startswith(".") or name in self.IGNORED_DIRECTORIES

    def _should_ignore_path(self, path: Path, root: Path) -> bool:
        if self._should_ignore_dir(path.name):
            return True
        from depcheck.ecosystems.static import is_excluded

        return is_excluded(path.relative_to(root), self.excluded_directories)

    @staticmethod
    def _scope_for_file(path: Path, root: Path) -> str:
        relative = path.relative_to(root)
        lowered_parts = {part.lower() for part in relative.parts[:-1]}
        lowered_name = relative.name.lower()
        if (
            lowered_parts.intersection({"test", "tests"})
            or lowered_name.startswith("test_")
            or lowered_name.endswith("_test.py")
            or lowered_name == "conftest.py"
        ):
            return "test"
        return "runtime"

    def scan_file_(self, path: Path) -> set[str]:
        """兼容图生成接口：返回文件中的第三方导入，不过滤本地模块。"""
        imports, diagnostics = self._scan_file_detailed(Path(path), "runtime")
        for diagnostic in diagnostics:
            logger.warning("Partial scan for %s: %s", path, diagnostic.message)
        return {
            item.module
            for item in imports
            if item.module not in sys.stdlib_module_names
            and item.module != "__future__"
        }


def _sanitize_notebook_source(source: str) -> str:
    """移除 IPython magic/shell 行，同时保留逻辑行号。"""
    lines = source.splitlines(keepends=True)
    first_code = next((line.lstrip() for line in lines if line.strip()), "")
    if first_code.startswith("%%"):
        return "".join("\n" if line.endswith("\n") else "" for line in lines)

    sanitized: list[str] = []
    for line in lines:
        if line.lstrip().startswith(("%", "!", "?")):
            sanitized.append("\n" if line.endswith("\n") else "")
        else:
            sanitized.append(line)
    return "".join(sanitized)
