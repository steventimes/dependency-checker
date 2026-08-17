from __future__ import annotations

import argparse
from collections import Counter
import json
import random
import resource
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.indexing import RepositoryIndexer
from depcheck.security.osv_client import OSVScanResult


class CountingOSV:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def scan(self, packages: Mapping[str, str]) -> OSVScanResult:
        return self.scan_ecosystem(packages, "PyPI")

    def scan_ecosystem(
        self,
        packages: Mapping[str, str],
        ecosystem: str,
    ) -> OSVScanResult:
        coordinates = dict(packages)
        self.calls.append((ecosystem, coordinates))
        return OSVScanResult({}, (), coordinates)


def build_fixture(
    root: Path,
    *,
    projects: int,
    files_per_project: int,
    seed: int,
    depth: int,
) -> None:
    rng = random.Random(seed)
    for index in range(projects):
        suffix = rng.randrange(1000, 9999)
        _python_project(root / f"python-{index}", files_per_project, suffix)
        _npm_project(root / f"web-{index}", files_per_project, suffix, depth)
        _go_project(root / f"go-{index}", files_per_project, suffix)
        _maven_project(root / f"java-{index}", files_per_project, suffix)
        _conan_project(root / f"cpp-{index}", files_per_project)


def run_benchmark(
    *,
    projects: int,
    files_per_project: int,
    seed: int,
    depth: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="depcheck-benchmark-") as temp_dir:
        root = Path(temp_dir)
        build_fixture(
            root,
            projects=projects,
            files_per_project=files_per_project,
            seed=seed,
            depth=depth,
        )
        fixture_files = tuple(path for path in root.rglob("*") if path.is_file())
        total_bytes = sum(path.stat().st_size for path in fixture_files)
        max_depth = max(
            len(path.relative_to(root).parent.parts) for path in fixture_files
        )
        npm_lock_entries = sum(
            max(
                0,
                len(json.loads(path.read_text(encoding="utf-8"))["packages"]) - 1,
            )
            for path in root.rglob("package-lock.json")
        )

        osv = CountingOSV()
        scan_started = time.perf_counter()
        scan = RepositoryScanner(osv_client=osv).scan(
            root,
            RepositoryScanOptions(security=True),
        )
        scan_seconds = time.perf_counter() - scan_started
        ecosystems = sorted({bundle.project.ecosystem for bundle in scan.bundles})
        projects_by_ecosystem = dict(
            sorted(Counter(bundle.project.ecosystem for bundle in scan.bundles).items())
        )
        required_ecosystems = {"Conan", "Go", "Maven", "PyPI", "npm"}
        missing_ecosystems = sorted(required_ecosystems - set(ecosystems))
        if missing_ecosystems:
            raise RuntimeError(
                "fixture scan missed ecosystems: " + ", ".join(missing_ecosystems)
            )
        if not osv.calls:
            raise RuntimeError("fixture produced no offline OSV batches")
        npm_duplicate_versions = 0
        npm_dependency_edges = 0
        for bundle in scan.bundles:
            if bundle.project.ecosystem.lower() != "npm":
                continue
            versions: dict[str, set[str]] = {}
            for dependency in bundle.resolved:
                versions.setdefault(dependency.package.name, set()).add(
                    dependency.version
                )
                npm_dependency_edges += len(dependency.dependencies)
            npm_duplicate_versions += sum(
                1 for package_versions in versions.values() if len(package_versions) > 1
            )
        if npm_duplicate_versions < 1:
            raise RuntimeError("fixture produced no repeated npm package versions")
        if npm_dependency_edges < 1:
            raise RuntimeError("fixture produced no npm parent-child dependency edges")

        indexer = RepositoryIndexer()
        cold_started = time.perf_counter()
        cold = indexer.refresh(root)
        cold_seconds = time.perf_counter() - cold_started
        hot_started = time.perf_counter()
        hot = indexer.refresh(root)
        hot_seconds = time.perf_counter() - hot_started
        cold_scanned = cold.scanned_python_files + cold.parsed_manifest_files
        hot_reused = hot.reused_python_files + hot.reused_manifest_files
        if cold_scanned < 1:
            raise RuntimeError("cold index did not scan any files")
        if hot_reused < 1 or hot.status != "current":
            raise RuntimeError("hot index did not reuse the cold result")
        reuse_denominator = (
            hot_reused + hot.scanned_python_files + hot.parsed_manifest_files
        )
        peak_rss_kb, peak_rss_source = _peak_rss()

        return {
            "schema": "depcheck.benchmark.v1",
            "config": {
                "seed": seed,
                "depth": depth,
                "project_groups": projects,
                "files_per_project": files_per_project,
            },
            "correctness": {
                "passed": True,
                "ecosystems": ecosystems,
                "project_count": len(scan.bundles),
                "projects_by_ecosystem": projects_by_ecosystem,
            },
            "fixture": {
                "scanned_files": len(fixture_files),
                "total_bytes": total_bytes,
                "max_depth": max_depth,
                "npm_lock_entries": npm_lock_entries,
            },
            "scan": {
                "wall_seconds": scan_seconds,
                "process_peak_rss_kb": peak_rss_kb,
                "process_peak_rss_source": peak_rss_source,
                "osv_batches": len(osv.calls),
                "npm_duplicate_version_packages": npm_duplicate_versions,
                "npm_dependency_edges": npm_dependency_edges,
            },
            "index": {
                "cold": {
                    "wall_seconds": cold_seconds,
                    "scanned_files": cold_scanned,
                    "status": cold.status,
                },
                "hot": {
                    "wall_seconds": hot_seconds,
                    "reused_files": hot_reused,
                    "status": hot.status,
                },
                "reuse_ratio": (
                    hot_reused / reuse_denominator if reuse_denominator else 0.0
                ),
            },
        }


def _peak_rss() -> tuple[int, str]:
    status = Path("/proc/self/status")
    if status.is_file():
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmHWM:"):
                fields = line.split()
                if len(fields) >= 2 and fields[1].isdigit():
                    return max(1, int(fields[1])), "proc-status-vmhwm"
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return (value if value > 0 else 1), "getrusage"


def _python_project(root: Path, files: int, suffix: int) -> None:
    root.mkdir(parents=True)
    (root / "requirements.txt").write_text(
        f"requests==2.32.3\nbenchmark-helper-{suffix}==1.0.0\n",
        encoding="utf-8",
    )
    for index in range(files):
        (root / f"module_{index}.py").write_text(
            "import requests\n" + f"VALUE = {index}\n",
            encoding="utf-8",
        )


def _npm_project(root: Path, files: int, suffix: int, depth: int) -> None:
    root.mkdir(parents=True)
    package = f"benchmark-lib-{suffix}"
    leaves = {f"benchmark-leaf-{suffix}-{index}": "1.0.0" for index in range(files)}
    (root / "package.json").write_text(
        json.dumps({"dependencies": {package: "1.0.0"}}),
        encoding="utf-8",
    )
    packages: dict[str, Any] = {
        "": {"dependencies": {package: "1.0.0"}},
        f"node_modules/{package}": {
            "version": "1.0.0",
            "dependencies": {
                "benchmark-parent": "1.0.0",
                "benchmark-shared": "1.0.0",
                **leaves,
            },
        },
        "node_modules/benchmark-parent": {
            "version": "1.0.0",
            "dependencies": {"benchmark-shared": "2.0.0"},
        },
        "node_modules/benchmark-shared": {"version": "1.0.0"},
        "node_modules/benchmark-parent/node_modules/benchmark-shared": {
            "version": "2.0.0"
        },
    }
    packages.update(
        {
            f"node_modules/{name}": {"version": version}
            for name, version in leaves.items()
        }
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": f"benchmark-web-{suffix}",
                "lockfileVersion": 3,
                "packages": packages,
            }
        ),
        encoding="utf-8",
    )
    for index in range(files):
        (root / f"module_{index}.js").write_text(
            f"import value from '{package}';\nexport default value;\n",
            encoding="utf-8",
        )
    deep_root = root
    for level in range(depth):
        deep_root /= f"level_{level}"
    deep_root.mkdir(parents=True)
    (deep_root / "deep_module.js").write_text(
        f"import value from '{package}';\nexport default value;\n",
        encoding="utf-8",
    )


def _go_project(root: Path, files: int, suffix: int) -> None:
    root.mkdir(parents=True)
    module = f"example.com/benchmark/lib{suffix}"
    (root / "go.mod").write_text(
        f"module example.com/benchmark/service{suffix}\n\ngo 1.22\n\nrequire {module} v1.2.3\n",
        encoding="utf-8",
    )
    (root / "go.sum").write_text(
        f"{module} v1.2.3 h1:benchmark\n",
        encoding="utf-8",
    )
    for index in range(files):
        (root / f"module_{index}.go").write_text(
            f'package benchmark\n\nimport _ "{module}/pkg"\n',
            encoding="utf-8",
        )


def _maven_project(root: Path, files: int, suffix: int) -> None:
    source = root / "src" / "main" / "java" / "benchmark"
    source.mkdir(parents=True)
    (root / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion><dependencies>"
        f"<dependency><groupId>org.benchmark</groupId><artifactId>lib{suffix}</artifactId>"
        "<version>1.0.0</version></dependency></dependencies></project>",
        encoding="utf-8",
    )
    for index in range(files):
        (source / f"Module{index}.java").write_text(
            f"package benchmark;\nimport org.benchmark.lib{suffix}.Client;\n",
            encoding="utf-8",
        )


def _conan_project(root: Path, files: int) -> None:
    root.mkdir(parents=True)
    (root / "conanfile.txt").write_text(
        "[requires]\nfmt/10.2.1\n",
        encoding="utf-8",
    )
    (root / "conan.lock").write_text(
        json.dumps({"requires": ["fmt/10.2.1"]}),
        encoding="utf-8",
    )
    for index in range(files):
        (root / f"module_{index}.cpp").write_text(
            "#include <fmt/format.h>\n",
            encoding="utf-8",
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic offline depcheck monorepo benchmark"
    )
    parser.add_argument("--projects", type=int, default=8)
    parser.add_argument("--files-per-project", type=int, default=25)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--depth", type=int, default=8)
    args = parser.parse_args(argv)
    if args.projects < 1 or args.files_per_project < 1 or args.depth < 1:
        parser.error("projects, files-per-project, and depth must be positive")
    result = run_benchmark(
        projects=args.projects,
        files_per_project=args.files_per_project,
        seed=args.seed,
        depth=args.depth,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
