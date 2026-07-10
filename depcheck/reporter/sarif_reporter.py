from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .scan_summary import ScanSummary


class SarifReporter:
    SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
    VERSION = "2.1.0"

    RULES = {
        "DEP-MISSING": {
            "name": "Missing dependency",
            "shortDescription": "Imported package is not declared",
            "fullDescription": (
                "A Python package appears in imports but is missing from supported "
                "dependency manifests."
            ),
            "defaultLevel": "error",
        },
        "DEP-UNUSED": {
            "name": "Unused dependency",
            "shortDescription": "Declared package is not imported",
            "fullDescription": (
                "A dependency is declared in a supported manifest but no matching "
                "import was detected in scanned source files."
            ),
            "defaultLevel": "warning",
        },
        "DEP-VULNERABILITY": {
            "name": "Known vulnerability",
            "shortDescription": "Dependency has a known vulnerability",
            "fullDescription": "OSV reported a known vulnerability for a declared dependency.",
            "defaultLevel": "error",
        },
        "DEP-COMPAT-CONFLICT": {
            "name": "Compatibility conflict",
            "shortDescription": "Declared version conflicts with transitive requirements",
            "fullDescription": (
                "PyPI metadata indicates the declared dependency version cannot satisfy "
                "a dependent package requirement."
            ),
            "defaultLevel": "error",
        },
        "DEP-COMPAT-MISSING": {
            "name": "Missing transitive dependency",
            "shortDescription": "Required transitive dependency is not declared",
            "fullDescription": (
                "PyPI metadata indicates a package requirement that is not declared in "
                "the scanned dependency manifests."
            ),
            "defaultLevel": "error",
        },
        "DEP-COMPAT-UNCONSTRAINED": {
            "name": "Unconstrained dependency",
            "shortDescription": "Declared dependency has no version constraint",
            "fullDescription": (
                "A dependency is declared without a version constraint while another "
                "package requires a specific compatible range."
            ),
            "defaultLevel": "warning",
        },
    }

    def build(
        self,
        *,
        summary: ScanSummary,
        project_root: Path,
        dependency_files: Sequence[Path],
        vulnerabilities: Mapping[str, Sequence[Mapping[str, Any]]],
        compatibility: object | None = None,
    ) -> dict[str, Any]:
        manifests = self._artifact_uris(project_root, dependency_files)
        results: list[dict[str, Any]] = []

        for package in summary.missing:
            results.append(
                self._result(
                    "DEP-MISSING",
                    f"Package '{package}' is imported but not declared.",
                    manifests,
                    {"package": package, "riskType": "missing"},
                )
            )

        for package in summary.unused:
            results.append(
                self._result(
                    "DEP-UNUSED",
                    f"Package '{package}' is declared but was not imported.",
                    manifests,
                    {"package": package, "riskType": "unused"},
                )
            )

        for package, issues in sorted(vulnerabilities.items()):
            for issue in issues:
                vuln_id = str(issue.get("id") or "unknown")
                message = f"Package '{package}' has vulnerability {vuln_id}."
                if issue.get("summary"):
                    message += f" {issue['summary']}"
                if issue.get("fix_version"):
                    message += f" Upgrade to {issue['fix_version']}."
                results.append(
                    self._result(
                        "DEP-VULNERABILITY",
                        message,
                        manifests,
                        {
                            "package": package,
                            "riskType": "vulnerability",
                            "vulnerabilityId": vuln_id,
                            "fixVersion": issue.get("fix_version"),
                        },
                    )
                )

        if compatibility is not None:
            results.extend(self._compatibility_results(manifests, compatibility))

        return {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "depcheck",
                            "rules": [self._rule(rule_id, data) for rule_id, data in self.RULES.items()],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "properties": summary.to_dict(),
                        }
                    ],
                    "results": results,
                }
            ],
        }

    def _compatibility_results(self, manifests: list[str], compatibility: object) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for conflict in getattr(compatibility, "conflicts", []) or []:
            results.append(
                self._result(
                    "DEP-COMPAT-CONFLICT",
                    (
                        f"Package '{conflict.package}' is declared as {conflict.declared}, "
                        f"but '{conflict.required_by}' requires {conflict.required}."
                    ),
                    manifests,
                    {
                        "package": str(conflict.package),
                        "riskType": "compatibility_conflict",
                        "declared": conflict.declared,
                        "required": conflict.required,
                        "requiredBy": conflict.required_by,
                    },
                )
            )

        for gap in getattr(compatibility, "missing", []) or []:
            results.append(
                self._result(
                    "DEP-COMPAT-MISSING",
                    f"Package '{gap.package}' is required by '{gap.required_by}' ({gap.required}) but is not declared.",
                    manifests,
                    {
                        "package": str(gap.package),
                        "riskType": "compatibility_missing",
                        "required": gap.required,
                        "requiredBy": gap.required_by,
                    },
                )
            )

        for gap in getattr(compatibility, "unconstrained", []) or []:
            results.append(
                self._result(
                    "DEP-COMPAT-UNCONSTRAINED",
                    f"Package '{gap.package}' is unconstrained, but '{gap.required_by}' requires {gap.required}.",
                    manifests,
                    {
                        "package": str(gap.package),
                        "riskType": "compatibility_unconstrained",
                        "required": gap.required,
                        "requiredBy": gap.required_by,
                    },
                )
            )

        return results

    def _rule(self, rule_id: str, data: dict[str, str]) -> dict[str, Any]:
        return {
            "id": rule_id,
            "name": data["name"],
            "shortDescription": {"text": data["shortDescription"]},
            "fullDescription": {"text": data["fullDescription"]},
            "defaultConfiguration": {"level": data["defaultLevel"]},
        }

    def _result(
        self,
        rule_id: str,
        message: str,
        manifests: list[str],
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        rule = self.RULES[rule_id]
        return {
            "ruleId": rule_id,
            "level": rule["defaultLevel"],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": manifests[0] if manifests else "."}
                    }
                }
            ],
            "properties": properties,
        }

    def _artifact_uris(self, project_root: Path, dependency_files: Sequence[Path]) -> list[str]:
        uris: list[str] = []
        for file_path in dependency_files:
            try:
                uris.append(file_path.resolve().relative_to(project_root.resolve()).as_posix())
            except ValueError:
                uris.append(file_path.as_posix())
        return uris
