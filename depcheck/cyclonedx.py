"""CycloneDX inventory projection with qualified identities and dependency edges."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from depcheck._version import __version__
from depcheck.model import PackageIdentity, ScanResult


def build_cyclonedx(
    result: ScanResult,
    *,
    timestamp: str | None = None,
    serial_number: str | None = None,
) -> dict[str, Any]:
    component_by_identity: dict[PackageIdentity, dict[str, Any]] = {}
    reference_by_identity: dict[PackageIdentity, str] = {}
    direct_identities: set[PackageIdentity] = set()
    for bundle in result.bundles:
        resolved_names = {item.package.name for item in bundle.resolved}
        for resolution in bundle.resolved:
            identity = resolution.identity
            if resolution.direct:
                direct_identities.add(identity)
            reference = _component_reference(identity)
            reference_by_identity[identity] = reference
            component_by_identity[identity] = _component(
                identity,
                reference,
                direct=resolution.direct,
            )
            if resolution.origin:
                component_by_identity[identity]["properties"].append(
                    {
                        "name": "depcheck:source:origin",
                        "value": json.dumps(dict(resolution.origin), sort_keys=True),
                    }
                )
        for declaration in bundle.declarations:
            if declaration.kind in {"constraint", "hint"} or (
                declaration.package.name in resolved_names
                and declaration.kind not in {"conditional", "checksum"}
            ):
                continue
            identity = PackageIdentity(
                declaration.project_id,
                declaration.package.ecosystem,
                declaration.package.name,
                purl=declaration.package.purl,
            )
            reference = _component_reference(identity)
            if declaration.kind in {"direct", "local"}:
                direct_identities.add(identity)
            reference_by_identity.setdefault(identity, reference)
            component = component_by_identity.setdefault(
                identity,
                _component(identity, reference, direct=identity in direct_identities),
            )
            if identity in direct_identities:
                component.pop("scope", None)
                for prop in component["properties"]:
                    if prop["name"] == "depcheck:dependency:direct":
                        prop["value"] = "true"
                        break
            if declaration.kind in {"conditional", "checksum"}:
                component["properties"].append(
                    {
                        "name": "depcheck:checksum-assertion"
                        if declaration.kind == "checksum"
                        else "depcheck:conditional-declaration",
                        "value": json.dumps(
                            {
                                "scope": declaration.scope,
                                "marker": declaration.marker,
                                "constraint": declaration.constraint.raw,
                                "source": declaration.source.to_dict(result.root),
                                "metadata": dict(declaration.metadata),
                            },
                            sort_keys=True,
                        ),
                    }
                )
                if identity not in direct_identities:
                    component["scope"] = "optional"

    project_ref = "application:" + quote(result.root.name or "repository", safe="-._~")
    direct_refs = sorted(
        {reference_by_identity[identity] for identity in direct_identities}
    )
    dependency_entries = [{"ref": project_ref, "dependsOn": direct_refs}]
    for bundle in result.bundles:
        for resolution in bundle.resolved:
            identity = resolution.identity
            children = []
            for link in resolution.dependency_links:
                target = PackageIdentity(
                    resolution.project_id,
                    link.package.ecosystem,
                    link.package.name,
                    link.version,
                    link.instance_id,
                    link.package.purl,
                )
                component_ref = reference_by_identity.get(target)
                if component_ref is None:
                    candidates = [
                        value
                        for key, value in reference_by_identity.items()
                        if key.project_id == target.project_id
                        and key.ecosystem.lower() == target.ecosystem.lower()
                        and key.name == target.name
                        and (target.version is None or key.version == target.version)
                    ]
                    component_ref = candidates[0] if len(candidates) == 1 else None
                if component_ref is not None:
                    children.append(component_ref)
            dependency_entries.append(
                {
                    "ref": reference_by_identity[identity],
                    "dependsOn": sorted(set(children)),
                }
            )

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial_number or f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "depcheck",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": project_ref,
                "name": result.root.name or "repository",
            },
        },
        "components": [
            component_by_identity[identity]
            for identity in sorted(
                component_by_identity,
                key=lambda item: item.sort_key,
            )
        ],
        "dependencies": dependency_entries,
    }


def _component_reference(identity: PackageIdentity) -> str:
    # purl 标识发布包；bom-ref 还必须区分项目和安装实例。
    reference = (
        "urn:depcheck:"
        f"{quote(identity.project_id, safe='')}:"
        f"{quote(identity.ecosystem, safe='')}:"
        f"{quote(identity.name, safe='')}"
    )
    if identity.version:
        reference += f"@{quote(identity.version, safe='-._~+')}"
    if identity.instance:
        reference += f"#instance={quote(identity.instance, safe='-._~/')}"
    return reference


def _component(
    identity: PackageIdentity,
    reference: str,
    *,
    direct: bool,
) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": reference,
        "name": identity.name,
        "properties": [
            {
                "name": "depcheck:identity:project-id",
                "value": identity.project_id,
            },
            {
                "name": "depcheck:identity:ecosystem",
                "value": identity.ecosystem,
            },
            {"name": "depcheck:dependency:direct", "value": str(direct).lower()},
        ],
    }
    if identity.version:
        component["version"] = identity.version
    if identity.instance:
        component["properties"].append(
            {"name": "depcheck:identity:instance", "value": identity.instance}
        )
    if identity.purl:
        purl = identity.purl
        if identity.version:
            purl += f"@{quote(identity.version, safe='-._~+')}"
        component["purl"] = purl
    return component
