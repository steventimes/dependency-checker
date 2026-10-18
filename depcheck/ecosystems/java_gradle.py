"""Static Gradle script declarations and configuration-qualified lock inventory."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

from depcheck.ecosystems.gradle import literal_gradle_calls
from depcheck.ecosystems.maven_identity import package_ref as _package_ref
from depcheck.ecosystems.static import read_text
from depcheck.model import (
    DependencyDeclaration,
    Diagnostic,
    ProjectUnit,
    ResolvedDependency,
    SourceLocation,
    VersionConstraint,
)

from .java_common import _diagnostic, _is_exact_version, _valid_maven_coordinate

_GRADLE_CONFIGURATIONS = {
    "api": "runtime",
    "implementation": "runtime",
    "compile": "runtime",
    "compileOnly": "optional",
    "runtimeOnly": "runtime",
    "annotationProcessor": "build",
    "kapt": "build",
    "testImplementation": "test",
    "testCompile": "test",
    "testRuntimeOnly": "test",
    "classpath": "build",
}


_GRADLE_LOCK_NAMES = ("gradle.lockfile", "buildscript-gradle.lockfile")


def _parse_gradle(
    project: ProjectUnit,
    manifest: Path,
    repository_root: Path,
) -> tuple[tuple[DependencyDeclaration, ...], list[Diagnostic]]:
    calls, diagnostics = literal_gradle_calls(
        read_text(manifest), manifest, _GRADLE_CONFIGURATIONS
    )
    declarations: list[DependencyDeclaration] = []
    for call in calls:
        group, separator, remainder = call.notation.partition(":")
        artifact, version_separator, version = remainder.partition(":")
        if not separator or not _valid_maven_coordinate(group, artifact):
            diagnostics.append(
                _diagnostic(
                    "manifest.invalid-dependency",
                    f"Unresolved Gradle coordinate identity: {call.notation[:160]}",
                    call.source,
                    severity="warning",
                )
            )
            continue
        classifier = extension = None
        literal = call.literal and "$" not in call.notation
        if literal:
            version, extension_separator, extension_value = version.partition("@")
            extension = extension_value if extension_separator else None
            version, classifier_separator, classifier_value = version.partition(":")
            classifier = classifier_value if classifier_separator else None
        constraint = "constraints" in call.contexts
        scope = _GRADLE_CONFIGURATIONS.get(call.configuration, "unknown")
        if call.wrapper in {"platform", "enforcedPlatform"} or constraint:
            scope = "build"
        declarations.append(
            DependencyDeclaration(
                project.project_id,
                _package_ref(f"{group}:{artifact}"),
                VersionConstraint(
                    version if version_separator else "",
                    "gradle-required",
                    version if version_separator and literal else None,
                ),
                call.source,
                scope=scope,
                kind="constraint" if constraint else "conditional",
                metadata={
                    "configuration": call.configuration,
                    "gradle_kind": call.wrapper
                    or ("constraint" if constraint else "dependency"),
                    "notation": call.notation,
                    "literal": literal,
                    "activation": "unknown",
                    "ownership": "lexical-script",
                    "contexts": list(call.contexts),
                    "call_source": call.call_source.to_dict(repository_root),
                    **({"classifier": classifier} if classifier is not None else {}),
                    **({"extension": extension} if extension is not None else {}),
                },
            )
        )
    diagnostics.append(
        _diagnostic(
            "manifest.gradle-evaluation-uncollected",
            "Only bounded literal configuration calls are inventoried. Evaluated script ownership, settings, plugins, catalogs and custom build logic remain uncollected.",
            manifest,
            severity="warning",
        )
    )
    return tuple(declarations), diagnostics


def _merge_gradle_lock(
    project: ProjectUnit,
    lock: Path,
    existing: Sequence[ResolvedDependency],
) -> tuple[list[ResolvedDependency], list[Diagnostic]]:
    resolved = list(existing)
    diagnostics: list[Diagnostic] = []
    occurrences: dict[str, int] = {}
    for line_number, raw_line in enumerate(read_text(lock).splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinate, separator, raw_configurations = line.partition("=")
        coordinate = coordinate.strip()
        parts = coordinate.split(":")
        source = SourceLocation(
            lock, line_number, len(raw_line) - len(raw_line.lstrip()) + 1
        )
        configurations = [name.strip() for name in raw_configurations.split(",")]
        if (
            len(parts) != 3
            or not all(parts)
            or not separator
            or not all(configurations)
            or not _valid_maven_coordinate(parts[0], parts[1])
            or not _is_exact_version(parts[2])
            or "$" in parts[2]
        ):
            if len(diagnostics) < 20:
                diagnostics.append(
                    _diagnostic(
                        "lock.gradle-invalid-entry",
                        "Malformed or unsupported Gradle lock assertion; no version was inferred.",
                        source,
                        severity="warning",
                    )
                )
            continue
        group, artifact, version = parts
        package = _package_ref(f"{group}:{artifact}")
        key = hashlib.sha256(
            json.dumps(
                [lock.name, package.name, version, sorted(configurations)]
            ).encode("utf-8")
        ).hexdigest()[:24]
        occurrences[key] = occurrences.get(key, 0) + 1
        resolved.append(
            ResolvedDependency(
                project.project_id,
                package,
                version,
                source,
                instance_id=f"gradle-lock:{key}:{occurrences[key]}",
                origin={
                    "kind": "gradle-lock",
                    "lock_kind": "buildscript"
                    if lock.name.startswith("buildscript-")
                    else "project",
                    "configurations": configurations,
                    "selection": "unknown",
                    "installed": "unknown",
                },
            )
        )
    return resolved, diagnostics
