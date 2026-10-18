"""Static package-change signals and explicit public registry identity checks."""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests  # type: ignore[import-untyped]
from packaging.utils import canonicalize_name

from depcheck._version import USER_AGENT
from depcheck.evidence_input import parse_evidence_json, read_evidence_json

LIFECYCLE = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
    "prepack",
    "postpack",
}
_CAPABILITIES = {
    "network-transfer": {"curl", "wget", "fetch", "Invoke-WebRequest", "iwr"},
    "shell-execution": {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"},
    "native-build": {"node-gyp", "cmake", "make", "gcc", "clang", "cc", "cargo"},
    "package-manager": {"npm", "pnpm", "yarn", "pip", "pip3", "uv", "npx"},
}


def _scripts(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict) or len(scripts) > 1024:
        raise ValueError("Package scripts must be a bounded object")
    results = {}
    for name, command in scripts.items():
        if (
            not isinstance(name, str)
            or not isinstance(command, str)
            or len(command) > 16384
        ):
            raise ValueError(
                "Package script names and commands must be bounded strings"
            )
        try:
            words = shlex.split(command)
            parse_status = "posix-token-candidates"
        except ValueError:
            words = []
            parse_status = "unknown-shell-syntax"
        capabilities = sorted(
            capability
            for capability, executables in _CAPABILITIES.items()
            if any(word in executables for word in words)
        )
        results[name] = {
            "command": command,
            "lifecycle": name in LIFECYCLE,
            "capabilities": capabilities,
            "tokenization": parse_status,
            "activation": "unknown",
            "executed": False,
            "maliciousness": "not-established",
        }
    return results


def compare_package_behavior(
    root: Path, before_file: str, after_file: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if limit < 1 or offset < 0:
        raise ValueError("Invalid package comparison pagination")
    before, before_digest = read_evidence_json(root, before_file)
    after, after_digest = read_evidence_json(root, after_file)
    scripts_before, scripts_after = _scripts(before), _scripts(after)
    rows = []
    for name in sorted(scripts_before.keys() | scripts_after.keys()):
        old, new = scripts_before.get(name), scripts_after.get(name)
        if old != new:
            rows.append(
                {
                    "kind": "package-script",
                    "name": name,
                    "before": old,
                    "after": new,
                    "change": "added"
                    if old is None
                    else "removed"
                    if new is None
                    else "changed",
                }
            )
    for field in (
        "name",
        "version",
        "repository",
        "publishConfig",
        "bin",
        "gypfile",
        "os",
        "cpu",
        "engines",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "overrides",
        "resolutions",
    ):
        if before.get(field) != after.get(field):
            rows.append(
                {
                    "kind": "package-metadata",
                    "name": field,
                    "before": before.get(field),
                    "after": after.get(field),
                }
            )
    return {
        "schema": "depcheck.package-behavior-diff.v1",
        "read_only": True,
        "inputs": [
            {"path": before_file, "sha256": before_digest},
            {"path": after_file, "sha256": after_digest},
        ],
        "changes": rows[offset : offset + limit],
        "total": len(rows),
        "offset": offset,
        "next_offset": offset + limit if len(rows) > offset + limit else None,
        "behavior_status": "configuration-only",
        "shell_dialect": "unknown; POSIX token candidates only",
        "dataflow_status": "not-analyzed",
        "maliciousness": "not-established",
        "artifact_contents": "not-analyzed",
    }


def compare_package_names(
    package: str, references: list[str], ecosystem: str
) -> list[dict[str, str]]:
    if (
        len(references) > 1000
        or len(package) > 214
        or any(len(item) > 214 for item in references)
    ):
        raise ValueError("Name comparison exceeds its budget")
    if ecosystem not in {"PyPI", "npm"}:
        raise ValueError("Name comparison supports PyPI and npm")
    normalize = (
        (lambda name: str(canonicalize_name(name)))
        if ecosystem == "PyPI"
        else (lambda name: name)
    )
    target = normalize(package)
    rows = []
    for reference in dict.fromkeys(references):
        candidate = normalize(reference)
        if target == candidate:
            continue
        # Keep scopes intact and never treat a bare npm homonym as equivalent.
        if ecosystem == "npm" and target.startswith("@") != candidate.startswith("@"):
            mechanism = (
                "scope-omission-candidate"
                if target.split("/")[-1] == candidate.split("/")[-1]
                else None
            )
        else:
            mechanism = None
            if len(target) == len(candidate):
                differences = [
                    i
                    for i, pair in enumerate(zip(target, candidate))
                    if pair[0] != pair[1]
                ]
                if len(differences) == 1:
                    mechanism = "single-substitution"
                elif len(differences) == 2:
                    a, b = differences
                    if (
                        b == a + 1
                        and target[a] == candidate[b]
                        and target[b] == candidate[a]
                    ):
                        mechanism = "adjacent-transposition"
            elif abs(len(target) - len(candidate)) == 1:
                longer, shorter = (
                    (target, candidate)
                    if len(target) > len(candidate)
                    else (candidate, target)
                )
                if any(
                    longer[:i] + longer[i + 1 :] == shorter for i in range(len(longer))
                ):
                    mechanism = "single-insertion-or-deletion"
        if mechanism:
            rows.append(
                {
                    "package": package,
                    "reference": reference,
                    "mechanism": mechanism,
                    "status": "advisory-only; no identity merge or automatic replacement",
                }
            )
    return rows


def verify_registry_package(
    ecosystem: str,
    package: str,
    *,
    version: str | None = None,
    allow_network: bool = False,
) -> dict[str, Any]:
    if not allow_network:
        raise ValueError("Public registry lookup requires explicit allow_network=true")
    if ecosystem == "PyPI":
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,212}[A-Za-z0-9])?", package
        ):
            raise ValueError("Invalid PyPI project name")
        normalized = str(canonicalize_name(package))
        endpoint = (
            f"https://pypi.org/pypi/{quote(normalized, safe='')}"
            + (f"/{quote(version, safe='')}" if version else "")
            + "/json"
        )
    elif ecosystem == "npm":
        if (
            not re.fullmatch(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+", package)
            or len(package) > 214
        ):
            raise ValueError("Invalid npm package name")
        normalized = package
        endpoint = f"https://registry.npmjs.org/{quote(package, safe='')}" + (
            f"/{quote(version, safe='')}" if version else ""
        )
    else:
        raise ValueError("Registry identity checks support PyPI and npm")
    if version is not None and (not version or len(version) > 256):
        raise ValueError("Version must be a non-empty bounded string")
    result: dict[str, Any] = {
        "schema": "depcheck.registry-identity.v1",
        "ecosystem": ecosystem,
        "package": normalized,
        "version": version,
        "endpoint": endpoint,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "existence": "unknown",
        "source_trust": "not-established",
        "maliciousness": "not-established",
        "installation_status": "not-attempted",
    }
    session = requests.Session()
    session.trust_env = (
        False  # No netrc, ambient registry credentials or target configuration.
    )
    try:
        with session.get(
            endpoint,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=10,
            stream=True,
            allow_redirects=False,
        ) as response:
            result["http_status"] = response.status_code
            if response.status_code == 404:
                result["existence"] = "not-found-at-queried-source"
            elif response.status_code == 200:
                chunks = []
                size = 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > 8 * 1024 * 1024:
                        raise ValueError("Registry response byte budget exhausted")
                    chunks.append(chunk)
                metadata = parse_evidence_json(b"".join(chunks))
                info = metadata.get("info") if ecosystem == "PyPI" else metadata
                if (
                    not isinstance(info, dict)
                    or normalize_name(info.get("name"), ecosystem) != normalized
                ):
                    raise ValueError(
                        "Registry response identity does not match the query"
                    )
                result["existence"] = "reported-present"
                result["metadata"] = {
                    field: info[field]
                    for field in (
                        "name",
                        "version",
                        "license",
                        "requires_python",
                        "deprecated",
                        "repository",
                    )
                    if field in info
                }
                result["reported_version"] = info.get("version")
                result["version_query_status"] = (
                    "not-requested"
                    if version is None
                    else "literal-match"
                    if version == info.get("version")
                    else "registry-returned-version; requested-label-or-normalization-not-verified"
                )
    except (requests.RequestException, OSError, ValueError) as exc:
        result["diagnostic"] = str(exc)
    finally:
        session.close()
    return result


def normalize_name(value: Any, ecosystem: str) -> str | None:
    return (
        str(canonicalize_name(value))
        if isinstance(value, str) and ecosystem == "PyPI"
        else value
        if isinstance(value, str)
        else None
    )
