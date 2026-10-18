"""Registry identities shared by npm and pnpm evidence collectors."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from semver import Version as SemVersion

from depcheck.ecosystems.static import StaticReadError, read_text
from depcheck.model import Diagnostic, PackageRef, SourceLocation

_PACKAGE = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+")


def package_ref(name: str, *, public: bool = True) -> PackageRef:
    return PackageRef(
        "npm",
        name.lower(),
        name,
        f"pkg:npm/{quote(name.lower(), safe='/')}" if public else None,
    )


def registry_name(name: str) -> str:
    if not _PACKAGE.fullmatch(name) or name.startswith((".", "_")):
        raise StaticReadError(f"Invalid npm registry package name: {name!r}")
    return name


def exact_version(version: str) -> bool:
    """Validate canonical registry versions within node-semver's native limits."""
    if len(version) > 256 or not version.isascii():
        return False
    try:
        parsed = SemVersion.parse(version)
    except ValueError:
        return False
    return max(parsed.major, parsed.minor, parsed.patch) <= 2**53 - 1


def dependency_identity(name: str, specifier: str) -> tuple[str, str]:
    if not specifier.startswith("npm:"):
        return name, specifier
    target = specifier[4:]
    package, separator, constraint = target.rpartition("@")
    if not separator or not package:
        package, constraint = target, "*"
    return registry_name(package), constraint or "*"


def _url_origin(value: str, kind: str) -> dict[str, Any]:
    """Keep source locations without persisting URL credentials or query tokens."""
    try:
        if len(value) > 4096 or "${" in value or any(ord(c) < 32 for c in value):
            raise ValueError("unsupported URL")
        url = urlsplit(value.removeprefix("git+"))
        if not url.hostname or url.scheme not in {"https", "http", "ssh", "git"}:
            raise ValueError("unsupported URL")
        host = url.hostname
        if ":" in host:
            host = f"[{host}]"
        if url.port is not None and url.port != {"https": 443, "http": 80}.get(
            url.scheme
        ):
            host += f":{url.port}"
        return {
            "kind": kind,
            "public": (
                kind == "registry"
                and url.scheme == "https"
                and url.hostname == "registry.npmjs.org"
                and url.port in {None, 443}
                and url.username is None
                and url.password is None
                and url.path.rstrip("/") == ""
                and not url.query
                and not url.fragment
            ),
            "location": urlunsplit((url.scheme, host, url.path, "", "")),
        }
    except ValueError:
        return {"kind": "unknown", "public": False, "reason": "unsupported-source-url"}


def _request_kind(value: str) -> str:
    if value.startswith(
        ("file:", "link:", "workspace:", "./", "../", "/", "~/", "\\")
    ) or re.match(r"[A-Za-z]:[\\/]", value):
        return "path"
    if value.startswith(
        ("git:", "git+", "git@", "github:", "gitlab:", "bitbucket:", "gist:")
    ):
        return "git"
    if value.startswith(("http:", "https:")):
        return "url"
    if "/" in value:
        return "git"
    if value.endswith((".tgz", ".tar.gz")):
        return "path"
    return (
        "registry" if re.fullmatch(r"[A-Za-z0-9*^~<>=| ._+\-]*", value) else "unknown"
    )


class NpmSources:
    """Bounded repository registry candidates; omit authentication fields."""

    def __init__(self, repository_root: Path, project_root: Path) -> None:
        self.files: list[Path] = []
        self.configurations: list[dict[str, list[dict[str, Any]]]] = []
        self.diagnostics: list[Diagnostic] = []
        self.incomplete = False
        self.ambiguous: set[str] = set()
        remaining = 256
        directory = project_root
        for _ in range(64):
            path = directory / ".npmrc"
            if path.exists() or path.is_symlink():
                self.files.append(path)
                config: dict[str, list[dict[str, Any]]] = {}
                try:
                    if path.is_symlink():
                        raise StaticReadError(
                            "Aliased npm registry configuration is unsupported"
                        )
                    text = read_text(path, max_bytes=262144)
                    for line, raw in enumerate(text.splitlines(), 1):
                        if line > 4096:
                            raise StaticReadError(
                                "npm registry configuration exceeds the line budget"
                            )
                        value = raw.strip()
                        if not value or value.startswith(("#", ";")):
                            continue
                        key, separator, value = value.partition("=")
                        key = key.strip().lower()
                        if key in {"userconfig", "globalconfig"}:
                            raise StaticReadError(
                                "Indirect npm configuration is not evaluated"
                            )
                        if not (
                            key.startswith("registry") or key.endswith(":registry")
                        ):
                            continue  # Authentication and unrelated settings are never retained.
                        if (
                            not separator
                            or re.fullmatch(r"registry|@[a-z0-9._~-]+:registry", key)
                            is None
                        ):
                            raise StaticReadError(
                                "Unsupported npm registry configuration key"
                            )
                        remaining -= 1
                        if remaining < 0:
                            raise StaticReadError(
                                "npm registry configuration exceeds the entry budget"
                            )
                        value = value.split(" #", 1)[0].split(" ;", 1)[0].strip()
                        if (
                            len(value) >= 2
                            and value[0] == value[-1]
                            and value[0] in {'"', "'"}
                        ):
                            value = value[1:-1]
                        origin = _url_origin(value, "registry")
                        origin["source"] = {
                            "path": path.relative_to(repository_root).as_posix(),
                            "line": line,
                            "key": key,
                        }
                        config.setdefault(key, []).append(origin)
                        if origin["kind"] == "unknown":
                            raise StaticReadError(
                                "Dynamic or unsupported npm registry location"
                            )
                except StaticReadError as exc:
                    self.incomplete = True
                    self.diagnostics.append(
                        Diagnostic(
                            "source.registry-incomplete",
                            "warning",
                            str(exc),
                            SourceLocation(path),
                        )
                    )
                self.configurations.append(config)
            if directory == repository_root:
                break
            directory = directory.parent
        else:
            self.incomplete = True
            self.diagnostics.append(
                Diagnostic(
                    "source.registry-incomplete",
                    "warning",
                    "npm configuration ancestry exceeds the 64-directory budget",
                    SourceLocation(project_root),
                )
            )

    def registry(self, name: str) -> dict[str, Any]:
        scope = (
            name.split("/", 1)[0] + ":registry" if name.startswith("@") else "registry"
        )
        assertions = [
            a
            for config in self.configurations
            for a in config.get(scope, config.get("registry", []))
        ]
        origin: dict[str, Any] = {
            "kind": "registry",
            "public": True,
            "location": "https://registry.npmjs.org/",
            "basis": "npm-default",
            "external_configuration": "not-evaluated",
        }
        if assertions:
            origin.update({k: v for k, v in assertions[0].items() if k != "source"})
            origin.update(
                basis="repository-registry-candidates",
                configuration_assertions=assertions,
            )
        conflict = (
            len(
                {
                    (a["kind"], a["public"], a.get("location", "").rstrip("/"))
                    for a in assertions
                }
            )
            > 1
        )
        if conflict and scope not in self.ambiguous:
            self.ambiguous.add(scope)
            self.diagnostics.append(
                Diagnostic(
                    "source.registry-ambiguous",
                    "warning",
                    "Repository registry candidates disagree; active npm workspace/configuration precedence is unknown",
                    SourceLocation(self.files[0]),
                )
            )
        if self.incomplete or conflict:
            origin.update(
                kind="unknown",
                public=False,
                reason="incomplete-or-ambiguous-registry-configuration",
            )
        return origin

    def declaration_origin(self, name: str, specifier: str) -> dict[str, Any]:
        kind = _request_kind(specifier)
        return (
            self.registry(name)
            if kind == "registry"
            else {"kind": kind, "public": False, "basis": "package-json-request"}
        )

    def resolution_origin(
        self,
        name: str,
        version: str,
        raw: Mapping[Any, Any],
        requests: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        origin = self.registry(name)
        resolved = raw.get("resolved")
        if raw.get("link") is True:
            origin = {"kind": "path", "public": False, "basis": "lock-link"}
        elif "link" in raw and raw["link"] is not False:
            origin = {"kind": "unknown", "public": False, "basis": "invalid-lock-link"}
        elif "resolved" in raw:
            if not isinstance(resolved, str) or not resolved:
                origin = {
                    "kind": "unknown",
                    "public": False,
                    "basis": "invalid-lock-source",
                }
            elif resolved.startswith(
                ("https://registry.npmjs.org/", "http://registry.npmjs.org/")
            ):
                url = urlsplit(resolved)
                expected = f"{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz"
                if (
                    unquote(url.path).removeprefix("/") == expected
                    and not url.query
                    and not url.fragment
                ):
                    origin["lock_source"] = "default-registry-alias"
                else:
                    origin.update(
                        kind="unknown",
                        public=False,
                        reason="lock-source-identity-unverified",
                    )
                origin["resolved_location"] = urlunsplit(
                    (url.scheme, url.netloc, url.path, "", "")
                )
            elif resolved == f"{name}/-/{name.rsplit('/', 1)[-1]}-{version}.tgz":
                origin["lock_source"] = "relative-registry-tarball"
            else:
                kind = _request_kind(resolved)
                origin = (
                    _url_origin(resolved, kind)
                    if kind in {"url", "git"}
                    else {"kind": kind, "public": False}
                )
                origin["basis"] = "lock-source"
        else:
            kind = _request_kind(version)
            if kind != "registry":
                origin = (
                    _url_origin(version, kind)
                    if kind in {"url", "git"}
                    else {"kind": kind, "public": False}
                )
                origin["basis"] = "lock-version-source"
            else:
                origin["lock_source"] = "not-provided"
        if not exact_version(version):
            origin.update(public=False, reason="non-canonical-registry-version")
        if any(not request.get("public") for request in requests):
            origin.update(
                public=False,
                request_kinds=sorted({str(r.get("kind", "unknown")) for r in requests}),
            )
            if origin["kind"] == "registry" and any(
                r.get("kind") != "registry" for r in requests
            ):
                origin.update(
                    kind="unknown",
                    reason="lock-source-unconfirmed-for-non-registry-request",
                )
        return origin


_NODE_BUILTINS = frozenset(
    {
        "assert",
        "assert/strict",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "dns/promises",
        "domain",
        "events",
        "fs",
        "fs/promises",
        "http",
        "http2",
        "https",
        "inspector",
        "inspector/promises",
        "module",
        "net",
        "os",
        "path",
        "path/posix",
        "path/win32",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "readline/promises",
        "repl",
        "stream",
        "stream/consumers",
        "stream/promises",
        "stream/web",
        "string_decoder",
        "timers",
        "timers/promises",
        "tls",
        "tty",
        "url",
        "util",
        "util/types",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
    }
)


def _import_package(reference: str) -> str | None:
    value = reference.strip()
    if not value or value.startswith((".", "/", "#")):
        return None
    if value.startswith(("node:", "astro:")) or _external_reference(value):
        return None
    if value in _NODE_BUILTINS:
        return None
    if value.startswith("@"):
        parts = value.split("/")
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else None
    return value.split("/", 1)[0].lower()


def _external_reference(reference: str) -> bool:
    if reference.startswith(("node:", "astro:")):
        return False
    return reference.startswith("//") or ":" in reference.split("/", 1)[0]
