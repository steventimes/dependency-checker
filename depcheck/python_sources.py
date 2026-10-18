"""Classify static Python source assertions without resolving or contacting them."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


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
                origin["assertion"] = {
                    k: value[k]
                    for k in ("git", "path", "file", "url", "ref", "editable")
                    if k in value
                }
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
            url = urlsplit(location)
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
