from __future__ import annotations

import ast
import configparser
import logging

from packaging.requirements import InvalidRequirement

from depcheck.ecosystems.python.parsers import BaseDependencyParser
from depcheck.filesystem.positions import SourcePositions, parse_python_ast
from depcheck.model import (
    Diagnostic,
    ManifestParseResult,
    PythonRequirement,
    SourceLocation,
)

_SETUP_REQUIREMENT_GROUPS = (
    ("install_requires", "runtime"),
    ("tests_require", "dev:test"),
    ("setup_requires", "build"),
)


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
            text = self._read_python()
            tree = parse_python_ast(text)
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
        positions = SourcePositions(self.path, text)
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
            for keyword in call.keywords:
                if keyword.arg is None:
                    diagnostics.append(
                        Diagnostic(
                            code="manifest.dynamic-setup-py",
                            severity="error",
                            message="setup.py keyword unpacking is not collected; dependency declarations may be incomplete.",
                            source=positions.ast_node(keyword),
                        )
                    )
            keywords = {item.arg: item.value for item in call.keywords if item.arg}
            for option, group in _SETUP_REQUIREMENT_GROUPS:
                self._append_sequence(
                    keywords.get(option), group, declarations, diagnostics, positions
                )
            self._append_extras(
                keywords.get("extras_require"), declarations, diagnostics, positions
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
        positions: SourcePositions,
    ) -> None:
        if node is None:
            return
        try:
            values = ast.literal_eval(node)
        except (ValueError, TypeError):
            diagnostics.append(self._dynamic(node, group, positions))
            return
        if not isinstance(values, (list, tuple, set)):
            diagnostics.append(self._dynamic(node, group, positions))
            return
        nodes = node.elts if isinstance(node, (ast.List, ast.Tuple)) else []
        for index, value in enumerate(values):
            self._append_requirement(
                value,
                group,
                nodes[index] if nodes else None,
                declarations,
                diagnostics,
                positions,
            )

    def _append_extras(
        self,
        node: ast.AST | None,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
    ) -> None:
        if node is None:
            return
        try:
            groups = ast.literal_eval(node)
        except (ValueError, TypeError):
            diagnostics.append(self._dynamic(node, "extras_require", positions))
            return
        if not isinstance(groups, dict):
            diagnostics.append(self._dynamic(node, "extras_require", positions))
            return
        value_nodes = (
            {
                ast.literal_eval(key): value
                for key, value in zip(node.keys, node.values)
                if key is not None
            }
            if isinstance(node, ast.Dict)
            else {}
        )
        for group, values in groups.items():
            if not isinstance(group, str) or not isinstance(values, (list, tuple, set)):
                diagnostics.append(self._dynamic(node, "extras_require", positions))
                continue
            group_node = value_nodes.get(group)
            nodes = (
                group_node.elts if isinstance(group_node, (ast.List, ast.Tuple)) else []
            )
            for index, value in enumerate(values):
                self._append_requirement(
                    value,
                    f"optional:{group}",
                    nodes[index] if nodes else None,
                    declarations,
                    diagnostics,
                    positions,
                )

    def _append_requirement(
        self,
        value: object,
        group: str,
        node: ast.AST | None,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
    ) -> None:
        location = positions.ast_node(node)
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

    def _dynamic(
        self, node: ast.AST, field: str, positions: SourcePositions
    ) -> Diagnostic:
        return Diagnostic(
            code="manifest.dynamic-setup-py",
            severity="error",
            message=f"setup.py 的 {field} 不是静态字面量，无法安全解析",
            source=positions.ast_node(node),
        )

    @staticmethod
    def _is_setup_call(node: ast.expr) -> bool:
        return (isinstance(node, ast.Name) and node.id == "setup") or (
            isinstance(node, ast.Attribute) and node.attr == "setup"
        )


logger = logging.getLogger(__name__)


class _InterpolationBudget(configparser.BasicInterpolation):
    """Keep BasicInterpolation semantics while charging before output allocation."""

    def __init__(self) -> None:
        self.remaining = 1024 * 1024
        self.steps = 100_000

    def _interpolate_some(self, parser, option, accum, rest, section, mapping, depth):
        self.steps -= 1
        if self.steps < 0:
            raise configparser.InterpolationError(
                option, section, "Interpolation work budget exhausted"
            )
        return super()._interpolate_some(  # type: ignore[misc]
            parser, option, accum, rest, section, mapping, depth
        )

    def before_get(self, parser, section, option, value, defaults):
        budget = self

        class Parts(list):
            def append(self, item):
                budget.remaining -= len(item.encode("utf-8")) + 1
                if budget.remaining < 0:
                    raise configparser.InterpolationError(
                        option, section, "Interpolation output budget exhausted"
                    )
                super().append(item)

        parts = Parts()
        self._interpolate_some(parser, option, parts, value, section, defaults, 1)
        return "".join(parts)


class SetupCfgParser(BaseDependencyParser):
    def parse(self) -> dict[str, str | None]:
        return {
            item.name: self._normalize_version(str(item.specifier))
            for item in self.parse_detailed().declarations
            if item.kind == "direct" and item.group != "build"
        }

    def parse_detailed(self) -> ManifestParseResult:
        declarations: list[PythonRequirement] = []
        diagnostics: list[Diagnostic] = []
        if not self.path.exists():
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.not-found",
                        severity="error",
                        message=f"setup.cfg 不存在：{self.path}",
                        source=SourceLocation(self.path),
                    ),
                )
            )

        config = configparser.ConfigParser(interpolation=_InterpolationBudget())
        try:
            text = self._read_text()
            config.read_string(text)
            values = [
                (option, group, config.get("options", option))
                for option, group in _SETUP_REQUIREMENT_GROUPS
                if config.has_option("options", option)
            ]
            extras = (
                config.items("options.extras_require")
                if config.has_section("options.extras_require")
                else []
            )
        except (OSError, UnicodeError, configparser.Error) as exc:
            return ManifestParseResult(
                diagnostics=(
                    Diagnostic(
                        code="manifest.invalid-setup-cfg",
                        severity="error",
                        message=f"无法解析 setup.cfg：{exc}",
                        source=SourceLocation(self.path),
                    ),
                ),
                files=(self.path,),
            )

        resolved = {("options", option): value for option, _, value in values}
        resolved.update(
            {("options.extras_require", group): value for group, value in extras}
        )
        positions = SourcePositions.ini(self.path, text, config, resolved)
        for option, group, value in values:
            self._append_lines(
                value,
                group,
                declarations,
                diagnostics,
                positions,
                "options",
                option,
            )
        for group, value in extras:
            self._append_lines(
                value,
                f"optional:{group}",
                declarations,
                diagnostics,
                positions,
                "options.extras_require",
                group,
            )

        return ManifestParseResult(
            declarations=tuple(declarations),
            diagnostics=tuple(diagnostics),
            files=(self.path,),
        )

    def _append_lines(
        self,
        value: str,
        group: str,
        declarations: list[PythonRequirement],
        diagnostics: list[Diagnostic],
        positions: SourcePositions,
        section: str,
        option: str,
    ) -> None:
        for index, raw_line in enumerate(value.splitlines()):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                declarations.append(
                    PythonRequirement.from_requirement(
                        line,
                        source=positions.value(section, option, index),
                        group=group,
                    )
                )
            except InvalidRequirement as exc:
                diagnostics.append(
                    Diagnostic(
                        code="manifest.invalid-requirement",
                        severity="error",
                        message=f"无效依赖声明 {line!r}：{exc}",
                        source=positions.value(section, option, index),
                    )
                )
