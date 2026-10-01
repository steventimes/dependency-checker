"""Bounded YAML data parsing for generated lockfiles."""

from __future__ import annotations

from collections.abc import Hashable
from typing import Any

import yaml
from yaml.events import AliasEvent

from depcheck.ecosystems.static import StaticReadError


class _LockLoader(yaml.SafeLoader):
    # pnpm uses YAML 1.2 names; YAML 1.1 would turn names such as `on` into bools.
    # Keep implicit scalars as strings and validate each consumed field explicitly.
    yaml_implicit_resolvers: dict = {}

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            raise StaticReadError("YAML aliases are not supported in lockfiles")
        self._nodes += 1
        self._depth += 1
        try:
            if self._nodes > 200_000 or self._depth > 64:
                raise StaticReadError("YAML lockfile exceeds the node or nesting limit")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Hashable, Any]:
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise StaticReadError("YAML mapping keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def read_lock_yaml(text: str) -> dict[str, Any]:
    loader = _LockLoader(text)
    try:
        document = loader.get_single_data()
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        raise StaticReadError(f"Invalid lockfile YAML: {exc}") from exc
    finally:
        loader.dispose()
    if not isinstance(document, dict):
        raise StaticReadError("Lockfile YAML root must be a mapping")
    return document
