"""Bounded reverse paths through qualified, indexed dependency instances."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

Node = tuple[str, str, str | None, str | None]


def dependency_origins(
    project_id: str,
    package: str,
    ecosystem: str,
    graph: dict[str, Any],
    *,
    limit: int,
    depth: int,
) -> dict[str, Any]:
    if not 1 <= limit <= 100 or not 1 <= depth <= 64:
        raise ValueError("origin limit must be 1..100 and depth must be 1..64")
    diagnostics: list[dict[str, str]] = []

    def diagnostic(code: str, message: str) -> None:
        if not any(d["code"] == code for d in diagnostics):
            diagnostics.append(
                {"code": code, "severity": "warning", "message": message}
            )

    def key(row: dict[str, Any], prefix: str = "") -> Node:
        return (
            row[prefix + "ecosystem"].lower(),
            row[prefix + "package"],
            row[prefix + "version"],
            row[prefix + "instance_id"],
        )

    nodes = {key(row): row for row in graph["nodes"]}
    by_package: dict[tuple[str, str], list[Node]] = defaultdict(list)
    by_version: dict[tuple[str, str, str | None], list[Node]] = defaultdict(list)
    for node in nodes:
        by_package[node[:2]].append(node)
        by_version[node[:3]].append(node)
    parents: dict[Node, set[Node]] = defaultdict(set)
    for edge in graph["edges"]:
        parent = key(edge, "parent_")
        child = key(edge, "child_")
        candidates = (
            (
                ([child] if child in nodes else [])
                if child[3] is not None
                else by_version.get(child[:3], [])
            )
            if child[2] is not None
            else []
        )
        if parent not in nodes or len(candidates) != 1:
            diagnostic(
                "origins.edge-unresolved",
                "Some indexed edges do not identify a unique resolved instance.",
            )
            continue
        parents[candidates[0]].add(parent)
    declarations: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for declaration in graph["declarations"]:
        declarations[(declaration["ecosystem"].lower(), declaration["package"])].append(
            {
                k: declaration[v]
                for k, v in (
                    ("path", "source_path"),
                    ("line", "line"),
                    ("column", "column_number"),
                )
                if declaration[v] is not None
            }
        )
    roots = {n for n, row in nodes.items() if row["direct"] and n[:2] in declarations}
    targets = sorted(by_package.get((ecosystem.lower(), package), []), key=repr)

    def identity(node: Node) -> dict[str, str]:
        row = nodes[node]
        return {
            "project_id": project_id,
            "ecosystem": row["ecosystem"],
            "package": node[1],
            **({"version": node[2]} if node[2] is not None else {}),
            **({"instance": node[3]} if node[3] is not None else {}),
        }

    queue: deque[tuple[Node, ...]] = deque((n,) for n in targets)
    paths: list[dict[str, Any]] = []
    visited = 0
    truncated = bool(graph["truncated"])
    while queue:
        reverse = queue.popleft()
        visited += 1
        if visited > 100_000:
            truncated = True
            break
        current = reverse[-1]
        if current in roots:
            if len(paths) == limit:
                truncated = True
                break
            paths.append(
                {
                    "nodes": [identity(n) for n in reversed(reverse)],
                    "declarations": declarations[current[:2]],
                }
            )
        following = [
            p for p in sorted(parents.get(current, ()), key=repr) if p not in reverse
        ]
        if len(reverse) >= depth and following:
            truncated = True
            continue
        queue.extend((*reverse, parent) for parent in following)
        if len(queue) > 100_000:
            truncated = True
            break
    if truncated:
        diagnostic(
            "origins.truncated",
            "Graph size, path count, depth or traversal budget limited the result.",
        )
    reached = {
        tuple(
            p["nodes"][-1].get(k)
            for k in ("ecosystem", "package", "version", "instance")
        )
        for p in paths
    }
    if not targets or any(
        tuple(
            identity(n).get(k) for k in ("ecosystem", "package", "version", "instance")
        )
        not in reached
        for n in targets
    ):
        diagnostic(
            "origins.unrooted",
            "Some target instances have no observed path from an owning direct declaration.",
        )
    if not graph["resolution_complete"]:
        diagnostic(
            "origins.resolution-incomplete",
            "Indexed resolution evidence is incomplete.",
        )
    return {
        "schema": "depcheck.agent.dependency-origins.v1",
        "paths": paths,
        "complete": not diagnostics,
        "truncated": truncated,
        "limits": {"paths": limit, "depth": depth, "traversal": 100_000},
        "diagnostics": diagnostics,
    }
