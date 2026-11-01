"""Classify static Python source assertions without resolving or contacting them."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any
from urllib.parse import urlsplit


def redact_source(value: Any) -> Any:
    """Remove URL credentials before retaining assertions, including nested tables."""
    if isinstance(value, dict):
        return {
            key: "[redacted]"
            if str(key).lower()
            in {"password", "token", "secret", "api_key", "access_token"}
            else redact_source(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_source(item) for item in value]
    if not isinstance(value, str):
        return value
    # Operate on text as well as valid URLs: parser errors may quote malformed URLs.
    value = re.sub(r"(\b[A-Za-z][A-Za-z0-9+.-]*://)[^\s/]*@", r"\1[redacted]@", value)
    return re.sub(r"([?&#][^\s=&#]+)=([^\s&#]*)", r"\1=[redacted]", value)


class PipenvSources:
    """Classify a Pipenv source table once; never resolve or contact an index."""

    def __init__(self, sources: Any) -> None:
        self.named: dict[str, dict[str, Any]] = {}
        self.default = python_origin(None, implicit_public=True)
        self.problem: str | None = None
        if sources is None or sources == []:
            return
        if not isinstance(sources, list) or any(
            not isinstance(s, dict) for s in sources
        ):
            self.problem = "invalid-source-table"
            return
        for source in sources:
            name = source.get("name")
            if isinstance(name, str):
                if name in self.named:
                    self.problem = "duplicate-source-name"
                    return
                self.named[name] = python_origin({"registry": source.get("url")})
        self.default = python_origin({"registry": sources[0].get("url")})

    def origin(self, value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            local = {k: value[k] for k in ("git", "path", "file", "url") if k in value}
            if local:
                if "path" in local and "editable" in value:
                    local["editable"] = value["editable"]
                origin = python_origin(local)
                origin["assertion"] = redact_source(
                    {
                        k: value[k]
                        for k in ("git", "path", "file", "url", "ref", "editable")
                        if k in value
                    }
                )
                return origin
        explicit = isinstance(value, dict) and "index" in value
        selected = value.get("index") if explicit else None
        if self.problem:
            assertion: dict[str, Any] = {"pipenv_source_state": self.problem}
            if explicit:
                assertion["index"] = selected
            return python_origin(assertion)
        if explicit:
            return (
                self.named.get(selected, python_origin({"index": selected}))
                if isinstance(selected, str) and selected
                else python_origin({"index": selected})
            )
        return self.default


def python_origin(value: Any, *, implicit_public: bool = False) -> dict[str, Any]:
    original = value
    value = redact_source(value)
    if value is None and implicit_public:
        return {
            "kind": "registry",
            "public": True,
            "location": "https://pypi.org/simple",
        }
    if not isinstance(value, dict):
        return {"kind": "unknown", "public": False, "assertion": value}
    if isinstance(value.get("path"), str) and isinstance(
        value.get("editable", False), bool
    ):
        return {
            "kind": "editable" if value.get("editable") else "path",
            "public": False,
            "assertion": value,
        }
    keys = [
        k
        for k in (
            "editable",
            "path",
            "directory",
            "git",
            "url",
            "registry",
            "workspace",
            "index",
        )
        if k in value
    ]
    if len(keys) != 1:
        return {"kind": "unknown", "public": False, "assertion": value}
    kind = keys[0]
    location = value[kind]
    public = False
    if kind == "registry" and isinstance(location, str):
        try:
            url = urlsplit(original[kind])
            public = (
                url.scheme == "https"
                and url.netloc == "pypi.org"
                and url.path.rstrip("/") == "/simple"
                and not url.query
                and not url.fragment
            )
        except ValueError:
            pass
    return {"kind": kind, "public": public, "assertion": value}


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
