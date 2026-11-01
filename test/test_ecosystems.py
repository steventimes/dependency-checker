"""Cross-ecosystem ownership, bounded expansion, and configuration evidence."""

import json
from pathlib import Path

import pytest
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import MappingConfidence


@pytest.mark.parametrize("ecosystem", ["npm", "Maven"])
def test_manifest_columns_count_unicode_characters(tmp_path, ecosystem):
    if ecosystem == "npm":
        name, text, token = (
            "package.json",
            '{"description":"中文","dependencies":{"tool":"1.0.0"}}',
            '"tool"',
        )
    else:
        name, text, token = (
            "pom.xml",
            "<project><!-- 中文 --><dependencies><dependency><groupId>example</groupId><artifactId>tool</artifactId><version>1</version></dependency></dependencies></project>",
            "<dependency>",
        )
    (tmp_path / name).write_text(text)
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    source = result.bundles[0].declarations[0].source
    assert source.line == 1
    assert text[source.column - 1 :].startswith(token)


@pytest.mark.parametrize("directory", ["site-packages", "dist-packages"])
def test_installed_libraries_do_not_become_repository_evidence(tmp_path, directory):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "app.py").write_text("import requests\n")
    (tmp_path / "package.json").write_text("{}")
    installed = tmp_path / "artifacts/environment/lib/python3.12" / directory
    installed.mkdir(parents=True)
    (installed / "pyproject.toml").write_text('[project]\ndependencies=["bogus==1"]\n')
    (installed / "library.py").write_text("import yaml\n")
    (installed / "package.json").write_text('{"dependencies":{"bogus":"1.0.0"}}')
    (installed / "library.js").write_text("import bogus from 'bogus';\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.findings
    assert {d.package.name for b in result.bundles for d in b.declarations} == {
        "requests"
    }
    assert {p for b in result.bundles for p in b.source_files} == {tmp_path / "app.py"}


def test_small_manifest_expansion_is_bounded(tmp_path):
    from depcheck.ecosystems.python.parsers.pyproject import PyProjectParser

    (tmp_path / "pom.xml").write_text(
        "<project><properties><a>${a}${a}</a></properties></project>"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(
        d.code == "manifest.invalid" and "cycle" in d.message
        for d in result.diagnostics
    )

    groups = ["[dependency-groups]", 'g0 = ["requests==2"]']
    groups.extend(
        f'g{i} = [{{include-group="g{i - 1}"}}, {{include-group="g{i - 1}"}}]'
        for i in range(1, 40)
    )
    (tmp_path / "pyproject.toml").write_text("\n".join(groups))
    parsed = PyProjectParser(tmp_path / "pyproject.toml").parse_detailed()
    assert 0 < len(parsed.declarations) < 20_000
    assert [
        sum(d.group == f"dev:g{i}" for d in parsed.declarations) for i in range(4)
    ] == [1, 2, 4, 8]
    assert [d.code for d in parsed.diagnostics] == ["manifest.group-limit"]

    repeated = " || ".join(["*"] * 100)
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                section: {"example": repeated}
                for section in (
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                )
            }
        )
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    assert not any(f.code == "declaration.conflict" for f in result.findings)
    assert not any(
        d.code == "analysis.constraint-intersection-unknown" for d in result.diagnostics
    )


def test_tool_usage_preserves_inventory_and_unused_candidates(tmp_path: Path) -> None:
    from depcheck.config import load_project_config

    (tmp_path / "requirements.txt").write_text("ruff==0.11.0\nrequests==2.31.0\n")
    (tmp_path / ".depcheck.toml").write_text(
        '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
        'package="ruff"\nscope="test"\nreason="CI lint command"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {
        f.package.name for f in result.findings if f.code == "dependency.unused"
    } == {"requests"}
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == {"ruff", "requests"}
    assert {d.package.name for d in bundle.resolved} == {"ruff", "requests"}
    usage = bundle.usages[0]
    assert usage.kind == "tool"
    assert usage.mapping_confidence is MappingConfidence.CONFIGURED
    assert usage.mapping_reason == "CI lint command"
    assert usage.source.path == tmp_path / ".depcheck.toml"
    from depcheck.ecosystems.preparation import apply_tool_usage

    assert (
        apply_tool_usage(bundle, load_project_config(tmp_path).tool_usage, tmp_path)
        == bundle
    )


def test_tool_usage_does_not_cross_project_or_ecosystem(tmp_path: Path) -> None:
    for directory in ("one", "two"):
        project = tmp_path / directory
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"shared":"1.0.0"}}')
    (tmp_path / "requirements.txt").write_text("shared==1.0.0\n")
    (tmp_path / ".depcheck.toml").write_text(
        '[[tool-usage]]\necosystem="npm"\nproject-id="npm:npm:one"\n'
        'package="shared"\nscope="runtime"\nreason="Entry point"\n'
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    unused = {
        f.package.project_id for f in result.findings if f.code == "dependency.unused"
    }
    assert unused == {"npm:npm:two", "pypi:python:."}


@pytest.mark.parametrize("dynamic", [False, True])
def test_tool_usage_unmatched_build_and_incomplete_boundaries(
    tmp_path: Path, dynamic: bool
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=["requests==2.31.0"]\n'
        '[build-system]\nrequires=["setuptools==80.9.0"]\n'
    )
    (tmp_path / ".depcheck.toml").write_text(
        "".join(
            '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
            f'package="{package}"\nscope="test"\nreason="CI tool"\n'
            for package in ("setuptools", "absent")
        )
    )
    if dynamic:
        (tmp_path / "app.py").write_text(
            "import importlib\nimportlib.import_module(name)\n"
        )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    unmatched = [
        d for d in result.diagnostics if d.code == "config.tool-usage-unmatched"
    ]
    assert len(unmatched) == 1 and "absent" in unmatched[0].message
    assert not any(f.code == "dependency.missing" for f in result.findings)
    assert not result.bundles[0].usages
    if dynamic:
        assert result.capability("dependency_hygiene").state == "incomplete"
        assert not any(f.code == "dependency.unused" for f in result.findings)


@pytest.mark.parametrize(
    "ecosystem,manifest,lock,content",
    [
        (
            "npm",
            "package.json",
            "package-lock.json",
            '{"dependencies":{"secret":"1.0.0"}}',
        ),
        (
            "Go",
            "go.mod",
            "go.sum",
            "module example.com/app\nrequire example.com/secret v1.0.0\n",
        ),
        ("Maven", "build.gradle", "gradle.lockfile", "dependencies {}\n"),
        (
            "Maven",
            "build.gradle.kts",
            "buildscript-gradle.lockfile",
            "dependencies {}\n",
        ),
    ],
)
def test_external_lock_symlink_is_incomplete(
    tmp_path: Path, ecosystem: str, manifest: str, lock: str, content: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / manifest).write_text(content)
    external = tmp_path / lock
    external.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/secret":{"version":"1.0.0"}}}'
    )
    (root / lock).symlink_to(external)
    result = RepositoryScanner().scan(
        root, RepositoryScanOptions(security=False, enabled_ecosystems=(ecosystem,))
    )
    assert not result.capability("dependency_hygiene").complete
    assert any("symlink" in d.message for d in result.diagnostics)
