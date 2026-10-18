"""Inspect an external CycloneDX JSON inventory without promoting it to source usage."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote

from packaging.utils import canonicalize_name
from packageurl import PackageURL

from depcheck.snapshots import read_evidence_json

_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "Cargo",
}


def inspect_sbom(
    root: Path, path: str, *, limit: int, offset: int = 0
) -> dict[str, Any]:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    data, digest = read_evidence_json(root, path)
    if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") not in {
        "1.4",
        "1.5",
        "1.6",
        "1.7",
    }:
        raise ValueError("Only CycloneDX JSON 1.4 through 1.7 is supported")
    raw = data.get("components", [])
    if (
        not isinstance(raw, list)
        or len(raw) > 20_000
        or not all(isinstance(c, dict) for c in raw)
    ):
        raise ValueError("SBOM components must be a bounded list of objects")
    diagnostics: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    references: dict[str, dict[str, Any]] = {}
    fallback_owner = "sbom:" + digest[:16]
    for index, component in enumerate(raw):
        name = component.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("SBOM component name must be a non-empty string")
        reported_reference = component.get("bom-ref")
        reference = (
            reported_reference
            if reported_reference is not None
            else f"unreferenced:{index}"
        )
        if not isinstance(reference, str) or not reference or reference in references:
            raise ValueError(
                "SBOM component references must be unique non-empty strings"
            )
        properties = _properties(component)
        details = _component_details(component)
        group = _is_dependency_group(component)
        purl = component.get("purl")
        package_url = _parse_purl(purl) if purl is not None else None
        identity = _purl_identity(package_url) if package_url is not None else None
        if identity is None:
            ecosystem = properties.get("depcheck:identity:ecosystem", "unknown")
            identity = {"ecosystem": ecosystem, "package": name}
            if ecosystem == "unknown" and not group:
                diagnostics.append(
                    _diagnostic(
                        "sbom.identity-unknown",
                        reference,
                        "No supported package URL or ecosystem identity",
                    )
                )
        if package_url is not None:
            for field in ("qualifiers", "subpath"):
                if value := getattr(package_url, field):
                    identity[field] = value
            if package_url.qualifiers or package_url.subpath:
                diagnostics.append(
                    _diagnostic(
                        "sbom.identity-qualified",
                        reference,
                        "Package URL qualifiers or subpath require identity dimensions beyond the local package/version profile",
                    )
                )
            if package_url.type not in _ECOSYSTEMS:
                diagnostics.append(
                    _diagnostic(
                        "sbom.purl-type-unsupported",
                        reference,
                        "Package URL type is retained without a supported ecosystem mapping",
                    )
                )
        identity["project_id"] = (
            properties.get("depcheck:identity:project-id") or fallback_owner
        )
        if "depcheck:identity:instance" in properties:
            identity["instance"] = properties["depcheck:identity:instance"]
        reported_version = component.get("version")
        if reported_version is not None and (
            not isinstance(reported_version, str) or not reported_version
        ):
            raise ValueError("SBOM component version must be a non-empty string")
        if (
            identity.get("version")
            and reported_version
            and identity["version"] != reported_version
        ):
            identity.pop("version")
            diagnostics.append(
                _diagnostic(
                    "sbom.version-ambiguous",
                    reference,
                    "Component and package URL versions disagree",
                )
            )
        elif reported_version:
            identity["version"] = reported_version
        if not identity.get("version") and not group:
            diagnostics.append(
                _diagnostic(
                    "sbom.version-unknown",
                    reference,
                    "Exact reported version is unknown",
                )
            )
        declared_ecosystem = properties.get("depcheck:identity:ecosystem")
        if declared_ecosystem and declared_ecosystem != identity["ecosystem"]:
            diagnostics.append(
                _diagnostic(
                    "sbom.identity-ambiguous",
                    reference,
                    "Package URL and ecosystem property disagree",
                )
            )
        if component.get("components"):
            diagnostics.append(
                _diagnostic(
                    "sbom.nested-components-unsupported",
                    reference,
                    "Nested assemblies are not collected by this profile",
                )
            )
        record = {
            **details,
            "bom_ref": reported_reference,
            "kind": "dependency-group" if group else "package",
            "identity": identity,
            "purl": purl,
            "package_url": dict(package_url._asdict()) if package_url else None,
            "name": name,
            "source_pointer": f"/components/{index}",
            "assertion": component,
            "identity_provenance": "sbom-asserted",
            "dependencies": [],
            "dependency_groups": [],
            "direct": None
            if group
            else {"true": True, "false": False}.get(
                properties.get("depcheck:dependency:direct", "")
            ),
        }
        components.append(record)
        if reported_reference is not None:
            references[reference] = record
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be an object")
    application = metadata.get("component", {})
    if not isinstance(application, dict):
        raise ValueError("SBOM metadata.component must be an object")
    _properties(application)
    application_details = _component_details(application)
    application_ref = application.get("bom-ref")
    if "bom-ref" in application and (
        not isinstance(application_ref, str)
        or not application_ref
        or application_ref in references
    ):
        raise ValueError("SBOM application reference must be a unique non-empty string")
    dependencies = data.get("dependencies", [])
    if not isinstance(dependencies, list) or len(dependencies) > 20_001:
        raise ValueError("SBOM dependencies must be a bounded list")
    edge_count = 0
    application_dependencies: list[str] = []
    group_memberships: dict[str, set[str]] = {}
    seen_entries: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or not isinstance(
            dependency.get("ref"), str
        ):
            raise ValueError("SBOM dependency entry must have a ref")
        reference = dependency["ref"]
        if reference in seen_entries:
            raise ValueError("SBOM dependency entries must have unique refs")
        seen_entries.add(reference)
        targets = dependency.get("dependsOn", [])
        if not isinstance(targets, list) or not all(
            isinstance(t, str) for t in targets
        ):
            raise ValueError("SBOM dependsOn must be a list of references")
        edge_count += len(targets)
        if edge_count > 100_000:
            raise ValueError("SBOM dependency edges exceed the limit")
        if reference not in references and reference != application_ref:
            diagnostics.append(
                _diagnostic(
                    "sbom.edge-unresolved", reference, "Dependency source is absent"
                )
            )
        for target in targets:
            if target not in references:
                diagnostics.append(
                    _diagnostic(
                        "sbom.edge-unresolved", target, "Dependency target is absent"
                    )
                )
            if reference in references:
                references[reference]["dependencies"].append(target)
                if (
                    references[reference]["kind"] == "dependency-group"
                    and target in references
                ):
                    group_memberships.setdefault(target, set()).add(reference)
            elif reference == application_ref:
                application_dependencies.append(target)
                if (
                    target in references
                    and references[target]["kind"] != "dependency-group"
                ):
                    references[target]["direct"] = True
    for reference, groups in group_memberships.items():
        references[reference]["dependency_groups"] = sorted(groups)
    tools = metadata.get("tools", [])
    if isinstance(tools, dict):
        components_tools = tools.get("components", [])
        services_tools = tools.get("services", [])
        if not isinstance(components_tools, list) or not isinstance(
            services_tools, list
        ):
            raise ValueError("SBOM tool components and services must be arrays")
        tools = [*components_tools, *services_tools]
    if not isinstance(tools, list) or not all(isinstance(t, dict) for t in tools):
        raise ValueError("SBOM tools must be a list or components object")
    complete = not diagnostics
    package_components = [
        component for component in components if component["kind"] != "dependency-group"
    ]
    quality_fields = {
        "package_url": lambda item: bool(item["purl"]),
        "version": lambda item: bool(item["identity"].get("version")),
        "bom_reference": lambda item: bool(item["bom_ref"]),
        "scope": lambda item: bool(item["scope"]),
        "license_assertion": lambda item: bool(item["licenses"]),
        "hash_assertion": lambda item: bool(item["assertion"].get("hashes")),
        "evidence_assertion": lambda item: bool(item["assertion"].get("evidence")),
    }
    more = len(components) > offset + limit
    return {
        "schema": "depcheck.agent.sbom-inventory.v1",
        "read_only": True,
        "provenance": {
            "path": path,
            "sha256": digest,
            "format": "CycloneDX",
            "spec_version": data["specVersion"],
            "authority": "external-sbom-assertion",
            "tools": [
                {k: t[k] for k in ("name", "version") if isinstance(t.get(k), str)}
                for t in tools
            ],
        },
        "components": components[offset : offset + limit],
        "application": {
            **application_details,
            "bom_ref": application_ref,
            "name": application.get("name"),
            "dependencies": application_dependencies,
        },
        "total": len(components),
        "offset": offset,
        "next_offset": offset + limit if more else None,
        "truncated": more,
        "capabilities": {
            "inventory": {"state": "complete" if complete else "incomplete"},
            "resolution": {
                "state": "complete"
                if complete
                and all(
                    c["kind"] == "dependency-group" or c["identity"].get("version")
                    for c in components
                )
                else "incomplete"
            },
            "usage": {
                "state": "unsupported",
                "reason": "SBOM inventory does not establish source usage or execution",
            },
            "security": {
                "state": "skipped",
                "reason": "No vulnerability lookup was performed",
            },
        },
        "diagnostics": diagnostics,
        "quality": {
            "profile": "reported-component-fields-v1",
            "component_count": len(package_components),
            "fields": {
                field: {
                    "reported": sum(bool(present(item)) for item in package_components),
                    "missing": sum(not present(item) for item in package_components),
                }
                for field, present in quality_fields.items()
            },
            "format_validation": "supported-projection; not-full-schema",
            "license_validation": "assertions-retained; legal-compliance-not-evaluated",
            "hash_validation": "assertions-retained; artifact-bytes-not-verified",
            "scope_semantics": "producer-assertion; no development/build exclusion applied",
            "overall_score": None,
        },
    }


def _component_details(component: dict[str, Any]) -> dict[str, Any]:
    component_type = component.get("type")
    if "type" in component and (
        not isinstance(component_type, str) or not component_type
    ):
        raise ValueError("SBOM component type must be a non-empty string")
    scope = component.get("scope")
    if "scope" in component and scope not in ("required", "optional", "excluded"):
        raise ValueError("SBOM component scope must be required, optional or excluded")
    return {
        "component_type": component_type,
        "scope": scope,
        "properties": component.get("properties", []),
        "licenses": _licenses(component.get("licenses", [])),
    }


def _is_dependency_group(component: dict[str, Any]) -> bool:
    # Trivy's language result nodes group packages; their edges are not a
    # declaration that every child is a direct dependency of the source project.
    if component.get("type") != "application" or "purl" in component:
        return False
    values: dict[str, list[str]] = {}
    for prop in component.get("properties", []):
        name = prop["name"]
        if name.startswith("depcheck:identity:"):
            return False
        values.setdefault(name, []).append(prop["value"])
    classes = values.get("aquasecurity:trivy:Class", [])
    types = values.get("aquasecurity:trivy:Type", [])
    return classes == ["lang-pkgs"] and len(types) == 1 and bool(types[0].strip())


def _licenses(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("SBOM licenses must be a list")
    for entry in value:
        if not isinstance(entry, dict) or ("license" in entry) == (
            "expression" in entry
        ):
            raise ValueError("SBOM license entry needs a license or expression")
        if "expression" in entry:
            if (
                not isinstance(entry["expression"], str)
                or not entry["expression"].strip()
            ):
                raise ValueError("SBOM license expression must be a non-empty string")
            continue
        license_value = entry["license"]
        if not isinstance(license_value, dict) or not any(
            key in license_value for key in ("id", "name")
        ):
            raise ValueError("SBOM license needs an id or name")
        for key in ("id", "name"):
            if key in license_value and (
                not isinstance(license_value[key], str)
                or not license_value[key].strip()
            ):
                raise ValueError("SBOM license id and name must be non-empty strings")
    return value


def _properties(component: dict[str, Any]) -> dict[str, str]:
    values = component.get("properties", [])
    if not isinstance(values, list):
        raise ValueError("SBOM component properties must be a list")
    result = {}
    for prop in values:
        if not isinstance(prop, dict) or not all(
            isinstance(prop.get(k), str) for k in ("name", "value")
        ):
            raise ValueError("SBOM properties require string names and values")
        if prop["name"].startswith("depcheck:"):
            if prop["name"] in result:
                raise ValueError("SBOM identity properties must be unique")
            result[prop["name"]] = prop["value"]
    return result


def _parse_purl(value: Any) -> PackageURL:
    if not isinstance(value, str) or not value.startswith("pkg:"):
        raise ValueError("SBOM package URL must use the pkg scheme")
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ValueError("Malformed SBOM package URL")
    try:
        coordinate = value.split("#", 1)[0].split("?", 1)[0]
        if any(c.isspace() for c in value) or "//" in coordinate[4:].lstrip("/"):
            raise ValueError("Unencoded whitespace or empty namespace segment")
        decoded = unquote(value, errors="strict")
        decoded.encode("utf-8", errors="strict")
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
            raise ValueError("Control character in coordinate")
        # The library's normalization discards duplicate qualifiers and dot
        # subpaths, and folds legacy npm names. Preserve assertions before any
        # normalization so these inputs cannot acquire a different identity.
        keys: set[str] = set()
        query = value.split("#", 1)[0].partition("?")[2]
        for entry in query.split("&") if query else ():
            key, separator, _ = entry.partition("=")
            key = key.lower()
            if (
                not separator
                or re.fullmatch(r"[a-z][a-z0-9._-]*", key) is None
                or key in keys
            ):
                raise ValueError("Invalid or duplicate qualifier key")
            keys.add(key)
        parsed = PackageURL.from_string(value, normalize_purl=False)
        if re.fullmatch(r"[a-z][a-z0-9.-]*", parsed.type) is None:
            raise ValueError("Invalid package type")
        namespace = (
            [unquote(s, errors="strict") for s in parsed.namespace.split("/")]
            if parsed.namespace
            else []
        )
        subpath = (
            [unquote(s, errors="strict") for s in parsed.subpath.strip("/").split("/")]
            if parsed.subpath
            else []
        )
        if any(not s or "/" in s for s in namespace) or any(
            not s or s in {".", ".."} or "/" in s for s in subpath
        ):
            raise ValueError("Invalid namespace or subpath segment")
        name = unquote(parsed.name, errors="strict")
        if parsed.type in {"pypi", "cargo"} and namespace:
            raise ValueError("Namespace is prohibited for this package type")
        if parsed.type in {"maven", "golang"} and not namespace:
            raise ValueError("Namespace is required for this package type")
        if (
            parsed.type == "npm"
            and namespace
            and (
                len(namespace) != 1
                or not namespace[0].startswith("@")
                or len(namespace[0]) == 1
            )
        ):
            raise ValueError("npm namespace must be a scope")
        if parsed.type in {"pypi", "cargo", "npm", "maven"} and "/" in name:
            raise ValueError("Unsupported package name separator")
        return PackageURL(
            type=parsed.type,
            namespace="/".join(namespace) or None,
            name=name,
            version=unquote(parsed.version, errors="strict")
            if parsed.version
            else None,
            qualifiers=parsed.qualifiers,
            subpath="/".join(subpath) or None,
            normalize_purl=False,
        )
    except ValueError as error:
        raise ValueError("Malformed SBOM package URL coordinate") from error


def _purl_identity(package_url: PackageURL) -> dict[str, Any] | None:
    package_type = package_url.type
    if package_type not in _ECOSYSTEMS:
        return None
    name = package_url.name
    if package_type == "maven":
        name = package_url.namespace + ":" + name
    elif package_type in {"npm", "golang"} and package_url.namespace:
        name = package_url.namespace + "/" + name
    elif package_type == "pypi":
        name = str(canonicalize_name(name))
    identity = {"ecosystem": _ECOSYSTEMS[package_type], "package": name}
    if package_url.version:
        identity["version"] = package_url.version
    return identity


def _diagnostic(code: str, reference: str, message: str) -> dict[str, str]:
    return {
        "code": code,
        "severity": "warning",
        "bom_ref": reference,
        "message": message,
    }
