from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .service import DependencyAgentService

try:
    from mcp.server.fastmcp import Context, FastMCP
except ModuleNotFoundError:  # 普通 CLI 安装不强制携带 MCP 的 HTTP/ASGI 依赖。
    FastMCP = None  # type: ignore[assignment,misc]
    Context = Any  # type: ignore[assignment,misc]


@dataclass(frozen=True, slots=True)
class RootPolicy:
    """把 MCP 文件访问限制在启动时确定的规范化根目录中。"""

    allowed_roots: tuple[Path, ...]

    def __init__(self, allowed_roots: Sequence[Path]) -> None:
        normalized = tuple(
            dict.fromkeys(Path(path).resolve() for path in allowed_roots)
        )
        if not normalized:
            raise ValueError("at least one allowed root is required")
        object.__setattr__(self, "allowed_roots", normalized)

    def resolve(self, value: str) -> Path:
        raw = Path(value)
        candidate = (
            raw.resolve()
            if raw.is_absolute()
            else (self.allowed_roots[0] / raw).resolve()
        )
        if any(
            candidate == root or root in candidate.parents
            for root in self.allowed_roots
        ):
            if not candidate.is_dir():
                raise ValueError(f"project root is not a directory: {candidate}")
            return candidate
        raise PermissionError(f"project root is outside the MCP allowlist: {candidate}")


def create_server(
    *,
    allowed_roots: Sequence[Path] | None = None,
    max_results: int = 50,
) -> Any:
    """创建只读优先的 FastMCP 服务；调用方决定 stdio 或测试传输。"""
    if FastMCP is None:
        raise RuntimeError(
            "MCP support is not installed; install the 'depcheck[agent]' extra"
        )
    if max_results < 1 or max_results > 200:
        raise ValueError("max_results must be between 1 and 200")
    fixed_policy = RootPolicy(tuple(allowed_roots)) if allowed_roots else None
    server = FastMCP(
        "depcheck",
        instructions=(
            "Index and query multi-ecosystem dependency evidence. Tools never modify source "
            "or dependency manifests; update tools return previews only."
        ),
    )

    async def service(
        project_root: str,
        context: Context,
    ) -> DependencyAgentService:
        policy = fixed_policy or await _client_root_policy(context)
        return DependencyAgentService(
            policy.resolve(project_root),
            max_results=max_results,
        )

    @server.tool()
    async def index_repository(
        project_root: str = ".",
        context: Context = None,
    ) -> dict[str, Any]:
        """Incrementally index dependency declarations, imports, and findings."""
        return (await service(project_root, context)).index_repository()

    @server.tool()
    async def scan_repository(
        project_root: str = ".",
        context: Context = None,
    ) -> dict[str, Any]:
        """Refresh offline dependency hygiene; security is explicitly skipped."""
        return (await service(project_root, context)).scan_repository()

    @server.tool()
    async def repository_context(
        project_root: str = ".",
        context: Context = None,
    ) -> dict[str, Any]:
        """Return index freshness, completeness, Git HEAD, and evidence counts."""
        return (await service(project_root, context)).repository_context()

    @server.tool()
    async def query_dependencies(
        query: str | None = None,
        project_root: str = ".",
        limit: int = 20,
        ecosystem: str | None = None,
        project_id: str | None = None,
        context: Context = None,
    ) -> dict[str, Any]:
        """Search compact package inventory by distribution or import name."""
        return (await service(project_root, context)).query_dependencies(
            query,
            ecosystem=ecosystem,
            project_id=project_id,
            limit=limit,
        )

    @server.tool()
    async def explain_dependency(
        package: str,
        project_root: str = ".",
        ecosystem: str | None = None,
        project_id: str | None = None,
        context: Context = None,
    ) -> dict[str, Any]:
        """Explain why a dependency is present with declarations and import evidence."""
        return (await service(project_root, context)).explain_dependency(
            package,
            ecosystem=ecosystem,
            project_id=project_id,
        )

    @server.tool()
    async def dependency_impact(
        package: str,
        project_root: str = ".",
        ecosystem: str | None = None,
        project_id: str | None = None,
        context: Context = None,
    ) -> dict[str, Any]:
        """List files, scopes, usage count, and findings affected by a dependency."""
        return (await service(project_root, context)).dependency_impact(
            package,
            ecosystem=ecosystem,
            project_id=project_id,
        )

    @server.tool()
    async def plan_dependency_updates(
        updates: dict[str, str],
        project_root: str = ".",
        add_missing: bool = False,
        ecosystem: str | None = None,
        project_id: str | None = None,
        context: Context = None,
    ) -> dict[str, Any]:
        """Generate requirements update previews without writing any manifest."""
        return (await service(project_root, context)).plan_dependency_updates(
            updates,
            add_missing=add_missing,
            ecosystem=ecosystem,
            project_id=project_id,
        )

    return server


async def _client_root_policy(context: Context) -> RootPolicy:
    if context is None:
        raise PermissionError("the MCP client did not provide repository roots")
    result = await context.request_context.session.list_roots()
    roots: list[Path] = []
    for root in result.roots:
        parsed = urlsplit(str(root.uri))
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            continue
        candidate = Path(unquote(parsed.path))
        if candidate.is_dir():
            roots.append(candidate)
    if not roots:
        raise PermissionError("the MCP client did not provide a local repository root")
    return RootPolicy(tuple(roots))


def _environment_roots() -> tuple[Path, ...]:
    value = os.environ.get("DEPCHECK_ALLOWED_ROOTS", "")
    if not value.strip():
        return ()
    return tuple(Path(item) for item in value.split(os.pathsep) if item.strip())


def cli(argv: Sequence[str] | None = None) -> None:
    """运行 stdio MCP；官方 SDK 会保护协议 stdout 不受普通输出污染。"""
    parser = argparse.ArgumentParser(
        prog="depcheck-mcp",
        description="Serve depcheck's read-only multi-ecosystem tools over MCP stdio.",
    )
    parser.add_argument(
        "--allow-root",
        action="append",
        default=[],
        help="Allow access to this repository root; may be repeated",
    )
    parser.add_argument("--max-results", type=int, default=50)
    args = parser.parse_args(argv)
    roots = (
        tuple(Path(item) for item in args.allow_root)
        if args.allow_root
        else _environment_roots()
    )
    create_server(allowed_roots=roots or None, max_results=args.max_results).run(
        transport="stdio"
    )


if __name__ == "__main__":
    cli()
