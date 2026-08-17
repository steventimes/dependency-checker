from __future__ import annotations

import ast
import tokenize

from packaging.requirements import InvalidRequirement

from depcheck.model import (
    PythonRequirement,
    Diagnostic,
    ManifestParseResult,
    SourceLocation,
)

from .base_parser import BaseDependencyParser


class SetupPyParser(BaseDependencyParser):
    """静态读取 setup() 字面量参数；绝不执行不受信任的项目代码。"""

    def parse(self) -> dict[str, str | None]:
        return {
            item.name: self._normalize_version(str(item.specifier))
            for item in self.parse_detailed().declarations
            if item.kind == "direct" and item.group != "build"
        }

    def parse_detailed(self) -> ManifestParseResult:
        if not self.path.is_file():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"setup.py 不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )
        try:
            with tokenize.open(self.path) as handle:
                tree = ast.parse(handle.read(), filename=str(self.path))
        except SyntaxError as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-setup-py",
                        severity="error",
                        message=f"setup.py 语法错误：{exc.msg}",
                        source=SourceLocation(
                            self.path, line=exc.lineno, column=exc.offset
                        ),
                    ),
                ),
                files=(self.path,),
            )
        except (OSError, UnicodeError) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.read-error",
                        severity="error",
                        message=f"无法读取 setup.py：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and self._is_setup_call(node.func)
        ]
        if not calls:
            diagnostics.append(
                Diagnostic(
                    code="manifest.setup-call-not-found",
                    severity="warning",
                    message="setup.py 中没有可识别的 setup() 调用",
                    source=SourceLocation(self.path),
                )
            )

        for call in calls:
            keywords = {item.arg: item.value for item in call.keywords if item.arg}
            self._append_sequence(
                keywords.get("install_requires"),
                "runtime",
                declarations,
                diagnostics,
            )
            self._append_sequence(
                keywords.get("tests_require"),
                "dev:test",
                declarations,
                diagnostics,
            )
            self._append_sequence(
                keywords.get("setup_requires"),
                "build",
                declarations,
                diagnostics,
            )
            self._append_extras(
                keywords.get("extras_require"), declarations, diagnostics
            )

        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _append_sequence(
        self,
        node: ast.AST | None,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if node is None:
            return
        try:
            values = ast.literal_eval(node)
        except (ValueError, TypeError):
            diagnostics.append(self._dynamic(node, group))
            return
        if not isinstance(values, (list, tuple, set)):
            diagnostics.append(self._dynamic(node, group))
            return
        for value in values:
            self._append_requirement(
                value,
                group,
                node,
                declarations,
                diagnostics,
            )

    def _append_extras(
        self,
        node: ast.AST | None,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        if node is None:
            return
        try:
            groups = ast.literal_eval(node)
        except (ValueError, TypeError):
            diagnostics.append(self._dynamic(node, "extras_require"))
            return
        if not isinstance(groups, dict):
            diagnostics.append(self._dynamic(node, "extras_require"))
            return
        for group, values in groups.items():
            if not isinstance(group, str) or not isinstance(values, (list, tuple, set)):
                diagnostics.append(self._dynamic(node, "extras_require"))
                continue
            for value in values:
                self._append_requirement(
                    value,
                    f"optional:{group}",
                    node,
                    declarations,
                    diagnostics,
                )

    def _append_requirement(
        self,
        value: object,
        group: str,
        node: ast.AST,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
    ) -> None:
        location = SourceLocation(
            self.path,
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", 0) + 1,
        )
        if not isinstance(value, str):
            diagnostics.append(
                Diagnostic(
                    code="manifest.invalid-requirement",
                    severity="error",
                    message=f"setup.py 的 {group} 依赖必须是字符串",
                    source=location,
                )
            )
            return
        try:
            declarations.append(
                PythonRequirement.from_requirement(
                    value,
                    source=location,
                    group=group,
                )
            )
        except InvalidRequirement as exc:
            diagnostics.append(
                Diagnostic(
                    code="manifest.invalid-requirement",
                    severity="error",
                    message=f"无效 setup.py 依赖 {value!r}：{exc}",
                    source=location,
                )
            )

    def _dynamic(self, node: ast.AST, field: str) -> Diagnostic:
        return Diagnostic(
            code="manifest.dynamic-setup-py",
            severity="error",
            message=f"setup.py 的 {field} 不是静态字面量，无法安全解析",
            source=SourceLocation(
                self.path,
                line=getattr(node, "lineno", None),
                column=getattr(node, "col_offset", 0) + 1,
            ),
        )

    @staticmethod
    def _is_setup_call(node: ast.expr) -> bool:
        return (isinstance(node, ast.Name) and node.id == "setup") or (
            isinstance(node, ast.Attribute) and node.attr == "setup"
        )
