from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.analyzer.pyproject_parser import PyProjectParser
from depcheck.analyzer.pipfile_parser import PipfileParser
from depcheck.analyzer.lockfile_parser import LockfileParser
from depcheck.analyzer.setupcfg_parser import SetupCfgParser
from depcheck.analyzer.setup_py_parser import SetupPyParser
from depcheck.compatibility.checker import (
    CompatibilityChecker,
    CompatibilityConflict,
    CompatibilityReport,
)
from depcheck.compatibility.pypi_client import PyPIFetchResult
from depcheck.compatibility.pyproject_updater import PyprojectUpdater
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.model import (
    AnalysisReport,
    Capability,
    CapabilityState,
    DependencyDeclaration,
    EvidenceBundle,
    Finding,
    MappingConfidence,
    PackageIdentity,
    PackageRef,
    ProjectUnit,
    PythonRequirement,
    ScanResult,
    SourceLocation,
    UsageEvidence,
    VersionConstraint,
)
from depcheck.security.osv_client import OSVClient


def test_legacy_python_manifest_locations_distinguish_repeated_values(tmp_path):
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text(
        '# requests = ">=2"\n[packages]\n"requests" = ">=2"\n[dev-packages]\n"requests" = "<3"\n'
    )
    parsed = PipfileParser(pipfile).parse_detailed()
    assert [(d.group, d.source.line, d.source.column) for d in parsed.declarations] == [
        ("runtime", 3, 1),
        ("dev", 5, 1),
    ]
    cfg = tmp_path / "setup.cfg"
    cfg.write_bytes(
        (
            "# requests>=2\r\n[metadata]\r\ndescription = requests>=2\r\n[options]\r\ninstall_requires =\r\n    requests>=2\r\n    # ignored\r\n    requests<3\r\n\r\n[options.extras_require]\r\ntest =\r\n    requests>=2\r\n    invalid !\r\n"
        ).encode()
    )
    parsed = SetupCfgParser(cfg).parse_detailed()
    assert [(d.group, d.source.line, d.source.column) for d in parsed.declarations] == [
        ("runtime", 6, 5),
        ("runtime", 8, 5),
        ("optional:test", 12, 5),
    ]
    assert (parsed.diagnostics[0].source.line, parsed.diagnostics[0].source.column) == (
        13,
        5,
    )


@pytest.mark.parametrize("name", ["poetry.lock", "pdm.lock", "uv.lock", "Pipfile.lock"])
def test_python_lock_locations_follow_structural_package_identity(tmp_path, name):
    path = tmp_path / name
    if name == "Pipfile.lock":
        content = '{\n  "_meta": {"note":"requests"},\n  "default": {\n    "requests": {"version":"==2.31.0"}\n  },\n  "develop": {\n    "\\u0072equests": {"version":"==2.32.0"}\n  }\n}\n'
        expected = [(4, 5), (7, 5)]
    else:
        content = '# decoy requests\n[[package]]\nname = "requests"\nversion = "2.31.0"\n[[package]]\nname = "requests"\nversion = "2.32.0"\n'
        expected = [(3, 8), (6, 8)]
    path.write_text(content)
    parsed = LockfileParser(path).parse_detailed()
    if name == "uv.lock":
        assert [d.code for d in parsed.diagnostics] == [
            "resolution.uv-lock-selection-unknown"
        ]
    else:
        assert not parsed.diagnostics
    assert [d.pinned_version for d in parsed.declarations] == ["2.31.0", "2.32.0"]
    assert [(d.source.line, d.source.column) for d in parsed.declarations] == expected


def test_uv_lock_preserves_environment_and_package_context_without_evaluating_it(
    tmp_path,
):
    path = tmp_path / "uv.lock"
    path.write_text(
        'version=1\nrevision=5\nrequires-python=">=3.9"\n'
        "resolution-markers=[\"sys_platform == 'win32'\", \"sys_platform != 'win32'\"]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\n'
        'source={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform == 'win32'\"]\n"
        'dependencies=[{name="bar", marker="python_version < \'3.12\'", extra=["test"]}]\n'
        '[[package]]\nname="foo"\nversion="2.0.0"\n'
        'source={registry="https://pypi.org/simple"}\n'
        "resolution-markers=[\"sys_platform != 'win32'\"]\n"
    )
    parsed = LockfileParser(path).parse_detailed()
    assert [d.pinned_version for d in parsed.declarations] == ["1.0.0", "2.0.0"]
    first, second = parsed.declarations
    assert first.source.line == 6 and second.source.line == 12
    assert first.marker is None and second.marker is None
    context = first.origin["lock"]
    assert context["format"] == "uv" and context["activation"] == "unknown"
    assert context["conditional"] is True
    assert context["root"]["requires-python"] == ">=3.9"
    assert context["root"]["revision"] == 5
    assert context["package"]["resolution-markers"] == ["sys_platform == 'win32'"]
    assert context["package"]["dependencies"][0]["marker"] == "python_version < '3.12'"
    assert context["package"]["dependencies"][0]["extra"] == ["test"]
    assert first.origin["public"] is True
    assert second.origin["lock"]["package_index"] == 1
    assert any(
        d.code == "resolution.uv-lock-selection-unknown" for d in parsed.diagnostics
    )
    assert LockfileParser(path).parse() == {"foo": None}


def test_uv_lock_mixed_invalid_context_preserves_readable_siblings_and_sources(
    tmp_path,
):
    path = tmp_path / "uv.lock"
    path.write_text(
        'version=2\nrequires-python="not-a-range"\nsupported-markers=[false]\n'
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        'dependencies=[{name="bar", marker="sys_platform == \'win32\'"}]\n'
        '[[package]]\nname="bar"\nversion="2.0.0"\nsource={registry="https://private.example/simple"}\n'
        'resolution-markers="unrecognized"\noptional-dependencies=false\n'
        '[[package]]\nname="baz"\nversion="3.0.0"\ndependencies=[{marker="missing name"}]\n'
    )
    original = path.read_bytes()
    parsed = LockfileParser(path).parse_detailed()
    assert [(d.name, d.pinned_version) for d in parsed.declarations] == [
        ("foo", "1.0.0"),
        ("bar", "2.0.0"),
        ("baz", "3.0.0"),
    ]
    assert [d.origin["public"] for d in parsed.declarations] == [True, False, False]
    assert all(d.origin["lock"]["conditional"] for d in parsed.declarations)
    errors = [d for d in parsed.diagnostics if d.severity == "error"]
    assert len(errors) == 6
    assert sorted(d.source.line for d in errors if d.source.line is not None) == [
        1,
        2,
        3,
        13,
        18,
    ]
    assert any(
        "optional-dependencies" in d.message and d.source.line is None for d in errors
    )
    assert LockfileParser(path).parse() == {"foo": None, "bar": None, "baz": None}
    assert path.read_bytes() == original


def test_uv_lock_large_inventory_qualifies_package_and_context_omissions(
    tmp_path, monkeypatch
):
    import json
    import depcheck.analyzer.lockfile_parser as locks

    monkeypatch.setattr(locks, "_MAX_UV_PACKAGES", 1024)
    path = tmp_path / "uv.lock"
    path.write_text(
        'version=1\nrequires-python=">=3.9"\n'
        "resolution-markers=[\"sys_platform == 'win32'\", \"sys_platform != 'win32'\"]\n"
        + "".join(
            f'[[package]]\nname="package{i}"\nversion="1.0.0"\n'
            'source={registry="https://pypi.org/simple"}\n'
            'dependencies=[{name="shared", version="2.0.0", marker="python_version >= \'3.11\'"}]\n'
            for i in range(1500)
        )
    )
    original = path.read_bytes()
    parsed = LockfileParser(path).parse_detailed()
    assert len(parsed.declarations) == 1024
    assert all(d.origin["lock"]["conditional"] for d in parsed.declarations)
    retained = [
        d.origin["lock"]
        for d in parsed.declarations
        if not d.origin["lock"].get("details_omitted")
    ]
    assert 0 < len(retained) < len(parsed.declarations)
    assert sum(len(json.dumps(context).encode()) for context in retained) <= 256 * 1024
    assert parsed.declarations[-1].origin["lock"]["details_omitted"] is True
    assert {d.code for d in parsed.diagnostics} >= {
        "manifest.uv-lock-package-limit",
        "resolution.uv-lock-context-limit",
        "resolution.uv-lock-selection-unknown",
    }
    assert path.read_bytes() == original


def test_uv_forks_do_not_create_flat_compatibility_conflicts_or_registry_requests(
    tmp_path,
):
    path = tmp_path / "uv.lock"
    path.write_text(
        "version=1\nresolution-markers=[\"python_version < '3.12'\", \"python_version >= '3.12'\"]\n"
        '[[package]]\nname="foo"\nversion="1.0.0"\nsource={registry="https://pypi.org/simple"}\n'
        '[[package]]\nname="foo"\nversion="2.0.0"\nsource={registry="https://pypi.org/simple"}\n'
    )

    class NoNetwork:
        def __getattr__(self, name):
            raise AssertionError(
                "conditional lock must not seed a flat candidate graph"
            )

    report = CompatibilityChecker(client=NoNetwork()).check_detailed(
        LockfileParser(path).parse_detailed()
    )
    assert (
        not report.conflicts and not report.suggestions and not report.selected_versions
    )
    assert not report.complete
    assert any(
        d.code == "compatibility.uv-lock-selection-unknown" for d in report.diagnostics
    )


@pytest.mark.parametrize(
    "placeholder,valid", [("%(deps)s", True), ("%(missing)s", False)]
)
def test_setup_cfg_interpolation_keeps_unmatched_positions_unknown(
    tmp_path, placeholder, valid
):
    path = tmp_path / "setup.cfg"
    path.write_text(
        f"[DEFAULT]\ndeps = requests>=2\n[options]\ninstall_requires = {placeholder}\n"
    )
    parsed = SetupCfgParser(path).parse_detailed()
    if valid:
        assert parsed.declarations[0].name == "requests"
        assert parsed.declarations[0].source.line is None
    else:
        assert parsed.diagnostics[0].code == "manifest.invalid-setup-cfg"


def test_setup_py_positions_follow_literal_nodes_without_execution(tmp_path):
    path = tmp_path / "setup.py"
    marker = tmp_path / "executed"
    text = (
        f'open({str(marker)!r}, "w").write("unexpected")\n'
        'label = "中文"; setup(install_requires=["requests>=2",\n'
        '    "requests<3"], extras_require={"test": ["ignored>=1"],\n'
        '    "test": ["requests>=2", "pytest>=9"]})\n'
    )
    path.write_text(text, encoding="utf-8")
    parsed = SetupPyParser(path).parse_detailed()
    assert not parsed.diagnostics
    assert [(d.name, d.source.line) for d in parsed.declarations] == [
        ("requests", 2),
        ("requests", 3),
        ("requests", 4),
        ("pytest", 4),
    ]
    assert (
        parsed.declarations[0].source.column
        == text.splitlines()[1].index('"requests') + 1
    )
    assert not marker.exists()


def test_pipfile_lock_rejects_duplicate_source_or_package_keys(tmp_path):
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        '{"default":{"requests":{"version":"==2.31.0"},"requests":{"version":"==2.32.0"}}}'
    )
    parsed = LockfileParser(path).parse_detailed()
    assert not parsed.declarations
    assert parsed.diagnostics[0].code == "manifest.invalid-lockfile"


@pytest.mark.parametrize("metadata", [None, []])
def test_malformed_pipenv_lock_metadata_does_not_imply_public_origin(
    tmp_path, metadata
):
    import json

    path = tmp_path / "Pipfile.lock"
    path.write_text(
        json.dumps(
            {"_meta": metadata, "default": {"requests": {"version": "==2.31.0"}}}
        )
    )
    parsed = LockfileParser(path).parse_detailed()
    assert parsed.declarations[0].origin["public"] is False


def test_direct_reference_cannot_become_public_through_source_override(tmp_path):
    declaration = PythonRequirement.from_requirement(
        "requests @ https://private.example/requests.whl",
        source=SourceLocation(tmp_path / "Pipfile"),
        origin={
            "kind": "registry",
            "public": True,
            "location": "https://pypi.org/simple",
        },
    )
    assert declaration.origin["public"] is False
    assert (
        declaration.origin["assertion"]["url"] == "https://private.example/requests.whl"
    )


def test_pyproject_declarations_keep_group_and_include_source_positions(tmp_path):

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '# decoy "requests>=2"\n'
        "[project]\n"
        'name = "example"\n'
        "dependencies = [\n"
        '    "requests>=2",\n'
        '    "requests<3",\n'
        "]\n"
        "[project.optional-dependencies]\n"
        'test = ["requests>=2", "pytest>=9"]\n'
        "[dependency-groups]\n"
        'base = ["requests>=2"]\n'
        'ci = [{include-group = "base"}, "mypy>=1"]\n'
        "[build-system]\n"
        'requires = ["setuptools>=83"]\n'
        "[tool.poetry.dependencies]\n"
        'requests = "^2.31"\n'
        "[tool.poetry.group.tests.dependencies]\n"
        '"requests" = {version = "^2.32"}\n'
        "[tool.pdm.dev-dependencies]\n"
        'lint = ["ruff>=0.6"]\n'
    )

    parsed = PyProjectParser(manifest).parse_detailed()

    assert not parsed.diagnostics
    assert [
        (d.name, d.group, d.source.line, d.source.column) for d in parsed.declarations
    ] == [
        ("requests", "runtime", 5, 5),
        ("requests", "runtime", 6, 5),
        ("requests", "optional:test", 9, 9),
        ("pytest", "optional:test", 9, 24),
        ("setuptools", "build", 14, 13),
        ("requests", "dev:base", 11, 9),
        ("requests", "dev:ci", 11, 9),
        ("mypy", "dev:ci", 12, 33),
        ("requests", "runtime", 16, 1),
        ("requests", "dev:tests", 18, 1),
        ("ruff", "dev:lint", 20, 9),
    ]


def test_pep735_group_names_and_repeated_includes_follow_order(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[dependency-groups]\nTest_Group=["requests>=2"]\n'
        'ci=["pytest>=8",{include-group="test.group"},'
        '{include-group="TEST--group"},"requests<3"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert not parsed.diagnostics
    assert [(d.raw_requirement, d.group) for d in parsed.declarations] == [
        ("requests>=2", "dev:Test_Group"),
        ("pytest>=8", "dev:ci"),
        ("requests>=2", "dev:ci"),
        ("requests>=2", "dev:ci"),
        ("requests<3", "dev:ci"),
    ]
    assert [d.source.line for d in parsed.declarations] == [2, 3, 2, 2, 3]


def test_uv_legacy_dev_is_appended_after_standard_group_expansion(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.uv]\ndev-dependencies=["pyyaml==6.0.2","pyyaml==6.0.2"]\n'
        '[dependency-groups]\nDEV=["pytest==8.3.0"]\nci=[{include-group="dev"},{include-group="DEV"}]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert not parsed.diagnostics
    assert [(d.name, d.group) for d in parsed.declarations] == [
        ("pytest", "dev:DEV"),
        ("pytest", "dev:ci"),
        ("pytest", "dev:ci"),
        ("pyyaml", "dev:DEV"),
        ("pyyaml", "dev:DEV"),
    ]
    assert [d.source.line for d in parsed.declarations] == [4, 4, 4, 2, 2]
    assert (
        parsed.declarations[-1].source.column != parsed.declarations[-2].source.column
    )


def test_uv_legacy_dev_does_not_define_a_standard_include_target(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[tool.uv]\ndev-dependencies=["pyyaml==6.0.2"]\n'
        '[dependency-groups]\nci=[{include-group="dev"},"pytest==8.3.0"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert [(d.name, d.group) for d in parsed.declarations] == [
        ("pytest", "dev:ci"),
        ("pyyaml", "dev:dev"),
    ]
    assert any(d.code == "manifest.group-not-found" for d in parsed.diagnostics)


def test_uv_legacy_dev_preserves_marker_extras_and_source_origin(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[tool.uv]\ndev-dependencies=[\"pyyaml[libyaml]==6.0.2; python_version >= '3.11'\"]\n"
        '[tool.uv.sources]\npyyaml={path="./vendor/pyyaml"}\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert not parsed.diagnostics and len(parsed.declarations) == 1
    item = parsed.declarations[0]
    assert (
        item.extras == ("libyaml",) and str(item.marker) == 'python_version >= "3.11"'
    )
    assert item.group == "dev:dev" and item.source.line == 2
    assert item.origin["public"] is False


def test_uv_legacy_dev_uses_the_group_context_budget(tmp_path, monkeypatch):
    import depcheck.analyzer.pyproject_parser as parser_module

    monkeypatch.setattr(parser_module, "DEFAULT_MAX_BYTES", 1600)
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[tool.uv]\ndev-dependencies=["
        + ",".join('"pyyaml==6.0.2"' for _ in range(20))
        + "]\n"
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert 0 < len(parsed.declarations) < 20
    assert [d.code for d in parsed.diagnostics] == ["manifest.group-limit"]


@pytest.mark.parametrize("configuration", ["tool=[]\n", "[tool]\nuv=[]\n"])
def test_invalid_uv_configuration_keeps_valid_project_requirements(
    tmp_path, configuration
):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        configuration + '[project]\nname="demo"\ndependencies=["requests==2"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert [d.name for d in parsed.declarations] == ["requests"]
    assert any(
        d.code == "manifest.invalid-dependency-table" for d in parsed.diagnostics
    )


@pytest.mark.parametrize(
    "legacy", ['"pyyaml==6"', '[7,{include-group="test"},"pyyaml==6.0.2"]']
)
def test_invalid_uv_legacy_entries_preserve_known_siblings(tmp_path, legacy):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[project]\ndependencies=["requests==2"]\n[tool.uv]\ndev-dependencies='
        + legacy
        + "\n"
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert [d.name for d in parsed.declarations] == (
        ["requests", "pyyaml"] if legacy.startswith("[") else ["requests"]
    )
    assert parsed.diagnostics


@pytest.mark.parametrize(
    "item",
    [
        '{include-group="base",unknown=true}',
        "{include-group=7}",
        '{include-group="absent"}',
        '{include-group="bad group"}',
    ],
)
def test_pep735_invalid_includes_keep_valid_siblings(tmp_path, item):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[dependency-groups]\nbase=["requests==2"]\nci=[' + item + ',"pytest==8"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert parsed.diagnostics and all(
        d.source.path == manifest for d in parsed.diagnostics
    )
    assert [(d.name, d.group) for d in parsed.declarations] == [
        ("requests", "dev:base"),
        ("pytest", "dev:ci"),
    ]


def test_pep735_normalized_name_collisions_are_not_resolved_by_order(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[dependency-groups]\nTest_Group=["requests==2"]\n'
        'test-group=["requests==3"]\nci=[{include-group="test.group"},"pytest==8"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert any(d.code == "manifest.group-ambiguous" for d in parsed.diagnostics)
    assert [(d.name, d.group) for d in parsed.declarations] == [
        ("requests", "dev:Test_Group"),
        ("requests", "dev:test-group"),
        ("pytest", "dev:ci"),
    ]


def test_pep735_cycle_uses_normalized_group_names(tmp_path):
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        '[dependency-groups]\nGroup_A=[{include-group="group.b"}]\n'
        'group-b=[{include-group="GROUP--A"}]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert not parsed.declarations
    assert any(d.code == "manifest.group-cycle" for d in parsed.diagnostics)


@pytest.mark.parametrize("invalid_name", ["bad group", ".hidden", "trailing-", ""])
def test_pep735_invalid_group_names_preserve_valid_source_entries(
    tmp_path, invalid_name
):
    import json

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "[dependency-groups]\n"
        + json.dumps(invalid_name)
        + '=["unknown==1"]\ngood=["requests==2"]\n'
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert [(d.name, d.group) for d in parsed.declarations] == [
        ("requests", "dev:good")
    ]
    assert [d.code for d in parsed.diagnostics] == ["manifest.invalid-group-name"]
    assert parsed.diagnostics[0].source.line == 2


def test_pep735_group_context_and_diagnostic_expansion_are_bounded(
    tmp_path, monkeypatch
):
    import depcheck.analyzer.pyproject_parser as parser_module

    manifest = tmp_path / "pyproject.toml"
    monkeypatch.setattr(parser_module, "DEFAULT_MAX_BYTES", 1600)
    manifest.write_text(
        "[dependency-groups]\n"
        + ("long-" * 16)
        + "group=["
        + ",".join('"requests==2"' for _ in range(20))
        + "]\n"
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert 0 < len(parsed.declarations) < 20
    assert [d.code for d in parsed.diagnostics] == ["manifest.group-limit"]
    monkeypatch.setattr(parser_module, "DEFAULT_MAX_BYTES", 8 * 1024 * 1024)
    manifest.write_text(
        "[dependency-groups]\n" + "".join(f'"invalid {n}"=[]\n' for n in range(100))
    )
    parsed = PyProjectParser(manifest).parse_detailed()
    assert (
        len(parsed.diagnostics) == 65
        and parsed.diagnostics[-1].code == "manifest.group-limit"
    )


def test_python_manifest_collection_preserves_same_line_occurrences(tmp_path):
    from depcheck.ecosystems.python_manifest import PythonManifestCollector

    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('[project]\ndependencies=["requests==2","requests==2"]\n')
    parsed = PythonManifestCollector(tmp_path).collect()
    assert len(parsed.declarations) == 2
    assert parsed.declarations[0].source.column != parsed.declarations[1].source.column
    from depcheck.engine import RepositoryScanner, RepositoryScanOptions

    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(f.code == "declaration.duplicate" for f in result.findings)


def test_python_manifest_overlapping_entry_files_do_not_repeat_physical_assertions(
    tmp_path,
):
    from depcheck.ecosystems.python_manifest import PythonManifestCollector

    (tmp_path / "requirements.txt").write_text("-r requirements-base.txt\n")
    (tmp_path / "requirements-base.txt").write_text("requests==2\nrequests==2\n")
    parsed = PythonManifestCollector(tmp_path).collect()
    assert len(parsed.declarations) == 2
    assert [d.source.line for d in parsed.declarations] == [1, 2]


@pytest.mark.parametrize(
    "content,line,column",
    [
        ('project.dependencies = ["requests>=2"]\n', 1, 25),
        ('["project"]\r\ndependencies = [\r\n\t"requests>=2",\r\n]\r\n', 3, 2),
        ('project = {dependencies = ["requests>=2"]}\n', 1, 28),
    ],
)
def test_pyproject_dotted_inline_and_crlf_locations(tmp_path, content, line, column):

    path = tmp_path / "pyproject.toml"
    path.write_bytes(content.encode())
    item = PyProjectParser(path).parse_detailed().declarations[0]
    assert (item.source.line, item.source.column) == (line, column)


def test_pyproject_invalid_requirement_diagnostic_points_at_entry(tmp_path):

    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\ndependencies = [\n    "not a requirement!",\n]\n')
    parsed = PyProjectParser(path).parse_detailed()
    assert len(parsed.diagnostics) == 1
    diagnostic = parsed.diagnostics[0]
    assert diagnostic.code == "manifest.invalid-requirement"
    assert (diagnostic.source.line, diagnostic.source.column) == (3, 5)


def test_pyproject_escaped_multiline_and_quoted_group_positions(tmp_path):

    path = tmp_path / "pyproject.toml"
    path.write_text(
        "[project]\n"
        "dependencies = [\n"
        '  """requests>=2; python_version >= \\"3.11\\"""",\n'
        "]\n"
        "[project.optional-dependencies]\n"
        '"test.group" = [\n'
        "  'requests>=2',\n"
        "]\n"
    )
    parsed = PyProjectParser(path).parse_detailed()
    assert not parsed.diagnostics
    assert [(d.group, d.source.line, d.source.column) for d in parsed.declarations] == [
        ("runtime", 3, 3),
        ("optional:test.group", 7, 3),
    ]
    assert str(parsed.declarations[0].marker) == 'python_version >= "3.11"'


def test_pyproject_include_cycle_diagnostic_points_at_reference(tmp_path):

    path = tmp_path / "pyproject.toml"
    path.write_text(
        '[dependency-groups]\nfirst = [{include-group="second"}]\nsecond = [{include-group="first"}]\n'
    )
    parsed = PyProjectParser(path).parse_detailed()
    diagnostic = next(d for d in parsed.diagnostics if d.code == "manifest.group-cycle")
    assert (diagnostic.source.line, diagnostic.source.column) == (3, 26)


def test_poetry_explicit_dependency_tables_keep_header_position(tmp_path):

    path = tmp_path / "pyproject.toml"
    path.write_text(
        "[tool.poetry.dependencies.requests]\n"
        'version = "^2.31"\n'
        '[tool.poetry.group."test.group".dependencies.pytest]\n'
        'version = "^9"\n'
    )
    parsed = PyProjectParser(path).parse_detailed()
    assert not parsed.diagnostics
    assert [
        (d.name, d.group, d.source.line, d.source.column) for d in parsed.declarations
    ] == [("requests", "runtime", 1, 1), ("pytest", "dev:test.group", 3, 1)]


@pytest.mark.parametrize(
    "command,expected",
    [
        (
            "RUN pip install requests==2.31.0 && groupadd --gid 10001 worker",
            {"requests"},
        ),
        (
            "RUN pip install --require-hashes -r requirements.lock && rm -rf /build && useradd --uid 10001 worker",
            set(),
        ),
        ("RUN pip install requests==2.31.0; rm -rf /wheels", {"requests"}),
        (
            "RUN pip install --target staging requests==2.31.0 | tee install.log",
            {"requests"},
        ),
    ],
)
def test_pip_install_hints_stop_before_shell_commands(tmp_path, command, expected):
    from depcheck.analyzer.pip_install_parser import PipInstallParser

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(command + "\n")
    parser = PipInstallParser(dockerfile)
    assert set(parser.parse()) == expected
    assert {d.name for d in parser.parse_detailed().declarations} == expected


@pytest.mark.parametrize(
    "filename",
    [
        "requirements.lock",
        "requirements-dev.lock",
        "runtime-requirements.lock",
        "build-requirements.lock",
    ],
)
def test_compiled_requirements_locks_keep_pins_hashes_and_markers(tmp_path, filename):
    from depcheck.ecosystems.python_manifest import PythonManifestCollector

    path = tmp_path / filename
    path.write_text(
        'urllib3==2.8.0; python_version >= "3.11" \\\n'
        "    --hash=sha256:" + "a" * 64 + " \\\n"
        "    --hash=sha256:" + "b" * 64 + "\n"
    )
    parsed = PythonManifestCollector(tmp_path).collect()
    assert not parsed.diagnostics
    assert len(parsed.declarations) == 1
    declaration = parsed.declarations[0]
    assert declaration.kind == "locked"
    assert declaration.pinned_version == "2.8.0"
    assert declaration.marker is not None
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles[0].resolved[0].version == "2.8.0"
    assert result.bundles[0].project.locks == (Path(filename),)


def test_compiled_requirements_lock_ranges_remain_incomplete(tmp_path):
    (tmp_path / "requirements.lock").write_text("urllib3>=2\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert any(d.code == "manifest.invalid-lock-entry" for d in result.diagnostics)


def test_package_identity_preserves_resolved_instances() -> None:
    first = PackageIdentity("npm:app:.", "npm", "react", "18.3.1", "node_modules/react")
    second = PackageIdentity(
        "npm:app:.", "npm", "react", "19.1.1", "packages/ui/node_modules/react"
    )

    assert first != second
    assert len({first, second}) == 2
    assert first.coordinates == (
        "npm:app:.",
        "npm",
        "react",
        "18.3.1",
        "node_modules/react",
    )


def test_scan_result_never_reports_pass_when_a_capability_was_skipped() -> None:
    result = ScanResult(
        root=Path("/workspace"),
        capabilities=(
            Capability("dependency_hygiene", CapabilityState.COMPLETE),
            Capability("security", CapabilityState.SKIPPED, "offline"),
        ),
    )

    assert result.complete is False
    assert result.status == "incomplete"
    assert result.to_dict()["capabilities"]["security"] == {
        "state": "skipped",
        "reason": "offline",
    }


def test_findings_fail_a_complete_scan_without_making_it_incomplete() -> None:
    result = ScanResult(
        root=Path("/workspace"),
        capabilities=(Capability("dependency_hygiene", CapabilityState.COMPLETE),),
        findings=(
            Finding(
                code="dependency.missing",
                package=PackageIdentity("pypi:python:.", "PyPI", "requests"),
                severity="error",
                message="requests is imported but not declared",
            ),
        ),
    )

    assert result.complete is True
    assert result.status == "fail"
    assert result.risk_count == 1


def test_evidence_bundle_uses_the_same_qualified_package_model() -> None:
    project = ProjectUnit("pypi:python:.", Path("."), "python", "PyPI", "python")
    package = PackageRef("PyPI", "requests", "requests", "pkg:pypi/requests")
    declaration = DependencyDeclaration(
        project.project_id,
        package,
        VersionConstraint(">=2", "pep440", ">=2"),
        SourceLocation(Path("pyproject.toml"), 8),
    )
    usage = UsageEvidence(
        project.project_id,
        "python",
        "requests",
        SourceLocation(Path("app.py"), 1),
        mapped_package=package,
        mapping_confidence=MappingConfidence.EXACT,
    )
    bundle = EvidenceBundle(
        project,
        declarations=(declaration,),
        usages=(usage,),
        capabilities=(Capability("usage", CapabilityState.COMPLETE),),
    )

    payload = bundle.to_dict(Path("."))
    assert payload["declarations"][0]["project_id"] == "pypi:python:."
    assert payload["usages"][0]["mapping_confidence"] == "exact"


def test_python_requirement_keeps_markers_and_exact_pins() -> None:
    requirement = PythonRequirement.from_requirement(
        'requests[security]==2.32.4; python_version >= "3.11"',
        source=SourceLocation(Path("requirements.txt"), 3),
    )

    assert requirement.name == "requests"
    assert requirement.extras == ("security",)
    assert requirement.pinned_version == "2.32.4"
    assert requirement.is_active({"python_version": "3.12"}) is True
    assert requirement.is_active({"python_version": "3.10"}) is False


def test_evidence_analyzer_returns_qualified_findings() -> None:
    project = ProjectUnit("npm:npm:.", Path("."), "javascript", "npm", "npm")
    package = PackageRef("npm", "left-pad", "left-pad", "pkg:npm/left-pad")
    bundle = EvidenceBundle(
        project,
        usages=(
            UsageEvidence(
                project.project_id,
                "javascript",
                "left-pad",
                SourceLocation(Path("index.js"), 1),
                mapped_package=package,
                mapping_confidence=MappingConfidence.EXACT,
            ),
        ),
        capabilities=(Capability("usage", CapabilityState.COMPLETE),),
    )

    report = EvidenceAnalyzer().analyze(bundle)

    assert isinstance(report, AnalysisReport)
    assert report.findings[0].package == PackageIdentity(
        "npm:npm:.", "npm", "left-pad", purl="pkg:npm/left-pad"
    )


def test_repository_scanner_returns_the_canonical_result(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"app","dependencies":{"left-pad":"1.3.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text(
        'import leftPad from "left-pad";\n',
        encoding="utf-8",
    )

    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            enabled_ecosystems=("npm",),
        ),
    )

    assert type(result) is ScanResult
    assert result.status == "incomplete"
    assert result.capability("security").state is CapabilityState.SKIPPED
    assert result.bundles[0].project.project_id == "npm:npm:."


def test_security_findings_keep_the_queried_version(tmp_path: Path) -> None:
    class FakeOSV:
        def scan(self, packages):
            return SimpleNamespace(
                vulnerabilities={
                    "requests": [{"id": "OSV-1", "summary": "affected", "severity": []}]
                },
                diagnostics=(),
                queried=dict(packages),
            )

    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    result = RepositoryScanner(osv_client=FakeOSV()).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            enabled_ecosystems=("PyPI",),
        ),
    )

    finding = next(
        item for item in result.findings if item.code == "security.vulnerability"
    )
    assert finding.package == PackageIdentity(
        "pypi:python:.", "PyPI", "requests", "2.31.0", purl="pkg:pypi/requests"
    )
    assert result.capability("security").state is CapabilityState.COMPLETE


@pytest.mark.parametrize("options", [("-c", "-r"), ("-r", "-c")])
def test_requirements_include_keeps_direct_and_constraint_contexts(
    tmp_path: Path, options
) -> None:
    from depcheck.analyzer.requirement_parser import RequirementParser

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("".join(f"{option} shared.txt\n" for option in options))
    (tmp_path / "shared.txt").write_text("requests==2.31.0\n")

    parsed = RequirementParser(manifest, project_root=tmp_path).parse_detailed()
    assert not parsed.diagnostics
    assert {item.kind for item in parsed.declarations} == {"direct", "constraint"}
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert {item.kind for item in result.bundles[0].declarations} == {
        "direct",
        "constraint",
    }
    assert result.bundles[0].resolved[0].direct


def test_security_preserves_every_affected_installation_instance(
    tmp_path: Path,
) -> None:
    import json

    class Session:
        def __init__(self):
            self.calls = []
            self.gets = 0

        def post(self, url, *, json, **kwargs):
            self.calls.extend(
                (q["package"]["ecosystem"], {q["package"]["name"]: q["version"]})
                for q in json["queries"]
            )
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {"id": identifier, "modified": "2020-01-01T00:00:00Z"}
                                for identifier in ("OSV-1", "OSV-2")
                            ]
                        }
                    ]
                },
            )

        def get(self, url, **kwargs):
            self.gets += 1
            identifier = url.rsplit("/", 1)[-1]
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "id": identifier,
                    "modified": "2020-01-01T00:00:00Z",
                    "aliases": ["CVE-shared"],
                    "affected": [
                        {
                            "package": {"name": "dep", "ecosystem": "npm"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                                }
                            ],
                        }
                    ],
                },
            )

    (tmp_path / "package.json").write_text('{"dependencies":{"dep":"1.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/dep": {"version": "1.0.0"},
                    "node_modules/a/node_modules/dep": {"version": "1.0.0"},
                    "node_modules/b/node_modules/dep": {"version": "1.1.0"},
                }
            }
        )
    )
    other = tmp_path / "other"
    other.mkdir()
    (other / "package.json").write_text('{"dependencies":{"dep":"1.0.0"}}')
    (other / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/dep": {"version": "1.0.0"}}})
    )
    session = Session()
    result = RepositoryScanner(osv_client=OSVClient(session=session)).scan(tmp_path)
    identities = {
        item.identity for bundle in result.bundles for item in bundle.resolved
    }

    assert set(result.vulnerabilities) == identities
    assert {
        finding.package
        for finding in result.findings
        if finding.code == "security.vulnerability"
    } == identities
    assert session.calls == [
        ("npm", {"dep": "1.0.0"}),
        ("npm", {"dep": "1.1.0"}),
        ("npm", {"dep": "1.0.0"}),
    ]
    assert session.gets == 2
    assert all(
        len(issues) == 1 and issues[0]["advisory_ids"] == ["OSV-1", "OSV-2"]
        for issues in result.vulnerabilities.values()
    )
    assert len(result.to_dict()["vulnerabilities"]) == 4


def test_compatibility_is_a_stage_of_the_repository_scan(tmp_path: Path) -> None:
    class FakeCompatibility:
        def check_detailed(self, manifest, *, python_version=None):
            assert [item.name for item in manifest.declarations] == ["requests"]
            return CompatibilityReport(
                conflicts=[
                    CompatibilityConflict(
                        "requests",
                        "2.31.0",
                        ">=2.32",
                        "demo",
                    )
                ],
                missing=[],
                unconstrained=[],
                suggestions={"requests": "==2.32.4"},
            )

    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")

    result = RepositoryScanner(compatibility_checker=FakeCompatibility()).scan(
        tmp_path,
        RepositoryScanOptions(
            security=False,
            compatibility=True,
            enabled_ecosystems=("PyPI",),
        ),
    )

    finding = next(
        item for item in result.findings if item.code == "compatibility.conflict"
    )
    assert finding.package == PackageIdentity(
        "pypi:python:.", "PyPI", "requests", purl="pkg:pypi/requests"
    )
    assert result.capability("compatibility").state is CapabilityState.COMPLETE
    assert result.metadata["compatibility"]["pypi:python:."]["suggestions"] == {
        "requests": "==2.32.4"
    }


def test_configured_ignores_match_scan_and_index(tmp_path: Path) -> None:
    from depcheck.indexing import RepositoryIndex, RepositoryIndexer

    (tmp_path / ".depcheck.toml").write_text(
        'security = false\nignore-packages = ["demo_pkg"]\n'
    )
    (tmp_path / "requirements.txt").write_text("demo-pkg>=1\n")
    (tmp_path / "app.py").write_text("import demo_pkg\n")
    result = RepositoryScanner().scan(tmp_path)
    RepositoryIndexer().refresh(tmp_path)
    assert result.findings == ()
    assert result.bundles[0].declarations == ()
    assert RepositoryIndex(tmp_path).dependencies() == []


def test_configured_compatibility_can_be_overridden(tmp_path: Path) -> None:
    class Compatibility:
        calls = 0

        def check_detailed(self, manifest, *, python_version=None):
            self.calls += 1
            return CompatibilityReport([], [], [], {})

    (tmp_path / ".depcheck.toml").write_text("security = false\ncompatibility = true\n")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    checker = Compatibility()
    scanner = RepositoryScanner(compatibility_checker=checker)
    scanner.scan(tmp_path)
    assert checker.calls == 1
    scanner.scan(tmp_path, RepositoryScanOptions(compatibility=False))
    assert checker.calls == 1


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_incomplete_usage_does_not_claim_dependencies_are_unused(
    tmp_path: Path, ecosystem: str
) -> None:
    if ecosystem == "PyPI":
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        (tmp_path / "app.py").write_text("import requests\nthis is invalid !!!\n")
    else:
        (tmp_path / "package.json").write_text('{"dependencies":{"react":"18.0.0"}}')
        (tmp_path / "app.js").write_text("const lib = import(resolveName());\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=(ecosystem,))
    )
    assert not result.capability("dependency_hygiene").complete
    assert not any(item.code == "dependency.unused" for item in result.findings)


@pytest.mark.parametrize(
    "vulns", [{"id": "OSV-1"}, ["OSV-1"], [{"summary": "no id"}], 7]
)
def test_osv_malformed_results_never_become_clean(vulns) -> None:

    class Session:
        def post(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"vulns": vulns}]},
            )

    result = OSVClient(session=Session()).scan({"requests": "2.31.0"})
    assert result.complete is False
    assert result.diagnostics[0].code == "osv.invalid-response"


def test_osv_stops_repeated_pagination_tokens() -> None:

    class Session:
        calls = 0

        def post(self, *args, **kwargs):
            self.calls += 1
            assert self.calls <= 2, "pagination must stop when the token repeats"
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"next_page_token": "same"}]},
            )

    result = OSVClient(session=Session()).scan({"requests": "2.31.0"})
    assert not result.complete


def test_osv_keeps_confirmed_vulnerabilities_when_later_batch_fails() -> None:
    import requests

    class Session:
        calls = 0

        def post(self, *args, **kwargs):
            self.calls += 1
            if self.calls > 1:
                raise requests.ConnectionError("connection interrupted")
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"vulns": [{"id": "OSV-1"}]}]},
            )

        def get(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {"id": "OSV-1", "summary": "affected"},
            )

    result = OSVClient(session=Session(), batch_size=1, max_attempts=1).scan(
        {"requests": "2.31.0", "httpx": "0.27.0"}
    )
    assert not result.complete
    assert result.vulnerabilities["requests"][0]["id"] == "OSV-1"


def test_osv_fix_candidates_respect_timeline_union_and_version_ordering():
    cases = [
        (
            "PyPI",
            "2.2",
            "ECOSYSTEM",
            [
                [
                    {"introduced": "0"},
                    {"fixed": "1.1"},
                    {"introduced": "2"},
                    {"fixed": "2.5"},
                ]
            ],
            [],
            "2.5",
        ),
        (
            "npm",
            "1.1.0",
            "SEMVER",
            [
                [{"introduced": "0"}, {"fixed": "1.2.0"}],
                [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
                [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}],
            ],
            ["3.0.0"],
            None,
        ),
        (
            "npm",
            "1.0.0-beta.2+build.7",
            "SEMVER",
            [[{"introduced": "1.0.0-beta.1"}, {"fixed": "1.0.0-beta.11"}]],
            [],
            "1.0.0-beta.11",
        ),
        (
            "Go",
            "v1.2.0",
            "SEMVER",
            [[{"introduced": "0"}, {"fixed": "1.3.0"}, {"limit": "*"}]],
            [],
            "1.3.0",
        ),
        (
            "PyPI",
            "2.0",
            "ECOSYSTEM",
            [[{"introduced": "0"}, {"last_affected": "2.0"}, {"limit": "3.0"}]],
            [],
            None,
        ),
        (
            "Maven",
            "2.0-final",
            "ECOSYSTEM",
            [[{"introduced": "0"}, {"fixed": "2.0-sp1"}]],
            [],
            None,
        ),
    ]
    for ecosystem, version, scheme, timelines, listed, expected in cases:
        for reverse in (False, True):
            detail = {
                "id": "TEST-range",
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": ecosystem},
                        "versions": listed,
                        "ranges": [
                            {
                                "type": scheme,
                                "events": list(reversed(events)) if reverse else events,
                            }
                            for events in timelines
                        ],
                    },
                    {
                        "package": {"name": "unrelated", "ecosystem": ecosystem},
                        "ranges": [
                            {
                                "type": scheme,
                                "events": [{"introduced": "0"}, {"fixed": "0.0.1"}],
                            }
                        ],
                    },
                ],
            }

            class Session:
                def post(self, *args, **kwargs):
                    return SimpleNamespace(
                        raise_for_status=lambda: None,
                        json=lambda: {"results": [{"vulns": [{"id": "TEST-range"}]}]},
                    )

                def get(self, *args, **kwargs):
                    return SimpleNamespace(
                        raise_for_status=lambda: None, json=lambda: detail
                    )

            result = OSVClient(session=Session()).scan_ecosystem(
                {"foo": version}, ecosystem
            )
            assert result.complete, (ecosystem, version, result.diagnostics)
            issue = result.vulnerabilities["foo"][0]
            assert issue["fix_version"] == expected, (ecosystem, version, reverse)
            assert issue["fix_version_status"] == (
                "candidate" if expected else "unknown"
            )
            assert "0.0.1" not in issue["fix_versions"]
            if ecosystem == "Maven":
                assert issue["fix_versions"] == ["2.0-sp1"]


def test_osv_mixed_invalid_details_keep_matches_and_valid_neighbors():
    details = {
        "good": {
            "affected": [
                {
                    "package": {"name": "good", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2"}],
                        }
                    ],
                }
            ]
        },
        "foreign-id": {"id": "TEST-another-advisory"},
        "bad-shape": {"severity": None},
        "bad-modified": {"modified": "2026-02-30T00:00:00Z"},
        "bad-withdrawal": {"withdrawn": True},
        "bad-alias": {"aliases": [""]},
        "alias-budget": {"aliases": ["CVE-repeated"] * 4097},
        "bad-events": {
            "affected": [
                {
                    "package": {"name": "bad-events", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0", "fixed": "2"}],
                        }
                    ],
                }
            ]
        },
        "over-budget": {
            "affected": [
                {
                    "package": {"name": "over-budget", "ecosystem": "PyPI"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}] * 4097}
                    ],
                }
            ]
        },
    }

    class Session:
        def post(self, url, *, json, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {"vulns": [{"id": "TEST-" + query["package"]["name"]}]}
                        for query in json["queries"]
                    ]
                },
            )

        def get(self, url, **kwargs):
            package = url.rsplit("/", 1)[-1].removeprefix("TEST-")
            detail = {"id": "TEST-" + package, **details[package]}
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: detail)

    result = OSVClient(session=Session()).scan(dict.fromkeys(details, "1"))
    assert not result.complete
    assert set(result.vulnerabilities) == set(details)
    assert len(result.diagnostics) == 8
    assert all(d.code == "osv.invalid-response" for d in result.diagnostics)
    assert any("budget" in d.message for d in result.diagnostics)
    assert result.vulnerabilities["good"][0]["fix_version"] == "2"
    for name in details.keys() - {"good"}:
        issue = result.vulnerabilities[name][0]
        assert issue["id"] == "TEST-" + name
        assert issue["fix_version"] is None
        assert issue["fix_version_status"] == "unknown"


def test_osv_revision_refresh_and_recovery_never_reuse_stale_details():
    import requests

    revisions = [f"2020-01-01T00:00:00.12345678{i}Z" for i in range(5)]
    stages = [
        ([revisions[0]], revisions[0], "2", None, "2", True, 1),
        ([revisions[0]], revisions[0], "2", None, "2", True, 1),
        ([revisions[1], revisions[0]], revisions[1], "3", None, "3", True, 2),
        ([None], revisions[2], "4", None, "4", True, 3),
        ([revisions[3], None], revisions[2], "4", "stale", None, False, 4),
        ([revisions[3]], revisions[3], "4", "network", None, False, 5),
        ([revisions[3]], revisions[3], "4", "withdrawn", None, True, 6),
        ([revisions[4]], revisions[4], "5", None, "5", True, 7),
    ]

    class Session:
        stage = None
        gets = 0

        def post(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "TEST-lifecycle",
                                    **(
                                        {"modified": revision}
                                        if revision is not None
                                        else {}
                                    ),
                                }
                                for revision in self.stage[0]
                            ]
                        }
                    ]
                },
            )

        def get(self, *args, **kwargs):
            self.gets += 1
            if self.stage[3] == "network":
                raise requests.ConnectionError("detail refresh interrupted")
            detail = {
                "id": "TEST-lifecycle",
                "modified": self.stage[1],
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": self.stage[2]},
                                ],
                            }
                        ],
                    }
                ],
                **({"withdrawn": revisions[3]} if self.stage[3] == "withdrawn" else {}),
            }
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: detail)

    session = Session()
    client = OSVClient(session=session, max_attempts=1)
    for stage in stages:
        session.stage = stage
        result = client.scan({"foo": "1"})
        assert result.complete is stage[5], stage
        assert session.gets == stage[6], stage
        if stage[3] == "withdrawn":
            assert not result.vulnerabilities
            assert result.diagnostics[0].code == "osv.withdrawn-advisory"
        else:
            issue = result.vulnerabilities["foo"][0]
            assert issue["id"] == "TEST-lifecycle"
            assert issue["fix_version"] == stage[4], stage
            if stage[3] == "stale":
                assert result.diagnostics[0].code == "osv.stale-detail"


def test_osv_alias_groups_are_transitive_order_independent_and_preserve_conflicts():
    import itertools
    import json
    import requests

    class Session:
        order = ("TEST-A", "TEST-B", "TEST-C", "TEST-D")
        phase = 0

        def post(self, *args, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": identifier,
                                    "modified": f"2020-01-01T00:00:0{self.phase}Z",
                                }
                                for identifier in self.order
                            ]
                        }
                    ]
                },
            )

        def get(self, url, **kwargs):
            identifier = url.rsplit("/", 1)[-1]
            if self.phase == 2 and identifier == "TEST-C":
                raise requests.ConnectionError("one alias source unavailable")
            aliases = {
                "TEST-A": ["CVE-shared"],
                "TEST-B": ["CVE-shared", "TEST-C"],
                "TEST-C": ["TEST-A"],
                "TEST-D": [],
            }
            events = [{"introduced": "0"}]
            if self.phase == 0 or identifier != "TEST-C":
                events.append({"fixed": "2" if identifier == "TEST-A" else "3"})
            detail = {
                "id": identifier,
                "modified": f"2020-01-01T00:00:0{self.phase}Z",
                "summary": identifier,
                "aliases": aliases[identifier],
                "related": ["TEST-A"],
                "upstream": ["TEST-A"],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": {
                            "TEST-A": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                            "TEST-B": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                            "TEST-C": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "TEST-D": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        }[identifier],
                    }
                ],
                "affected": [
                    {
                        "package": {"name": "foo", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM", "events": events}],
                    }
                ],
            }
            if self.phase == 3 and identifier == "TEST-C":
                detail["affected"][0]["package"]["name"] = "another-package"
            elif self.phase == 4 and identifier == "TEST-C":
                detail["affected"][0]["ranges"] = []
                detail["affected"][0]["versions"] = ["1"]
            return SimpleNamespace(raise_for_status=lambda: None, json=lambda: detail)

    session = Session()
    client = OSVClient(session=session, max_attempts=1)
    canonical = None
    for order in itertools.permutations(session.order):
        session.order = order
        result = client.scan({"foo": "1"})
        assert result.complete
        assert len(result.vulnerabilities["foo"]) == 2
        group, separate = result.vulnerabilities["foo"]
        assert group["advisory_ids"] == ["TEST-A", "TEST-B", "TEST-C"]
        assert group["aliases"] == ["CVE-shared", "TEST-B", "TEST-C"]
        assert group["fix_version"] == "3"
        assert {v["fix_version"] for v in group["advisories"]} == {"2", "3"}
        assert len(group["severity"]) == 3
        assert "modified" not in group
        assert all(v["modified"] for v in group["advisories"])
        assert separate["id"] == "TEST-D" and "advisories" not in separate
        serialized = json.dumps(result.vulnerabilities, sort_keys=True)
        canonical = canonical or serialized
        assert serialized == canonical
    for phase in (1, 2, 3, 4):
        session.phase = phase
        result = client.scan({"foo": "1"})
        assert result.complete is (phase != 2)
        group = result.vulnerabilities["foo"][0]
        assert group["advisory_ids"] == ["TEST-A", "TEST-B", "TEST-C"]
        assert group["fix_version"] == ("3" if phase == 4 else None)
        assert group["fix_version_status"] == ("candidate" if phase == 4 else "unknown")
        assert len(group["advisories"]) == 3


def test_osv_large_paginated_alias_chain_retains_sources_and_qualifies_fix_budget():
    count = 1100

    class Session:
        posts = 0

        def post(self, url, *, json, **kwargs):
            self.posts += 1
            later = bool(json["queries"][0].get("page_token"))
            start, stop = (600, count) if later else (0, 600)
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": f"TEST-{i:04d}",
                                    "modified": "2020-01-01T00:00:00Z",
                                }
                                for i in range(start, stop)
                            ],
                            **({"next_page_token": "rest"} if not later else {}),
                        }
                    ]
                },
            )

        def get(self, url, **kwargs):
            identifier = url.rsplit("/", 1)[-1]
            index = int(identifier.removeprefix("TEST-"))
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "id": identifier,
                    "modified": "2020-01-01T00:00:00Z",
                    "aliases": [f"TEST-{(index + 1) % count:04d}"],
                    "database_specific": {
                        "cwe_ids": ["CWE-77", "CWE-79", "CWE-89", "CWE-94"]
                    },
                    "affected": [
                        {
                            "package": {"name": "foo", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2"}],
                                }
                            ],
                        }
                    ],
                },
            )

    session = Session()
    result = OSVClient(session=session).scan({"foo": "1"})
    assert session.posts == 2
    assert not result.complete
    assert len(result.vulnerabilities["foo"]) == 1
    group = result.vulnerabilities["foo"][0]
    assert len(group["advisory_ids"]) == len(group["advisories"]) == count
    assert group["fix_version"] is None
    assert group["fix_version_status"] == "unknown"
    assert group["cwe_ids"] == ["CWE-77", "CWE-79", "CWE-89", "CWE-94"]
    assert len(group["identifier_references"]) == 4096
    assert group["identifier_references_omitted"] == count * 4 - 4096
    assert (
        sum(len(a["identifier_references"]) for a in group["advisories"]) == count * 4
    )
    assert any(d.code == "osv.identifier-group-incomplete" for d in result.diagnostics)
    assert result.diagnostics[-1].code == "osv.alias-group-incomplete"
    assert "4096-item budget" in result.diagnostics[-1].message


def test_osv_identifier_metadata_preserves_matches_and_qualifies_missing_or_bad_cwes():
    import requests

    assertions = {
        "CVE-2021-23337": {"database_specific": {"cwe_ids": ["CWE-77", "CWE-94"]}},
        "TEST-missing": {},
        "TEST-empty": {"database_specific": {"cwe_ids": []}},
        "TEST-partial": {
            "database_specific": {
                "cwe_ids": [
                    "CWE-79",
                    "CWE-79",
                    "CWE-0",
                    "CWE-01",
                    "CWE-７７",
                    None,
                    "https://untrusted.test/CWE-94",
                    "CWE-" + "9" * 64,
                ]
            }
        },
        "TEST-container": {"database_specific": []},
        "TEST-field": {"database_specific": {"cwe_ids": "CWE-79"}},
        "TEST-budget": {
            "database_specific": {"cwe_ids": ["CWE-89"] * 256 + ["CWE-94"]}
        },
        "CVE-2026-99999": {},
    }

    class Session:
        def post(self, url, *, json, **kwargs):
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [{"vulns": [{"id": name}]} for name in assertions]
                },
            )

        def get(self, url, **kwargs):
            identifier = url.rsplit("/", 1)[-1]
            if identifier == "CVE-2026-99999":
                raise requests.ConnectionError("unavailable source")
            return SimpleNamespace(
                raise_for_status=lambda: None,
                json=lambda: {
                    "id": identifier,
                    "aliases": [
                        "CVE-TEST",
                        "cve-2026-1234",
                        "CVE-2026-123",
                        "CVE-20261-12345",
                    ],
                    **assertions[identifier],
                },
            )

    result = OSVClient(session=Session(), max_attempts=1).scan(
        dict.fromkeys(assertions, "1")
    )
    assert not result.complete  # The unavailable source retains its batch match.
    assert set(result.vulnerabilities) == {name.lower() for name in assertions}
    issues = {values[0]["id"]: values[0] for values in result.vulnerabilities.values()}
    assert set(issues) == set(assertions)
    assert issues["CVE-2021-23337"]["cve_ids"] == ["CVE-2021-23337"]
    assert issues["CVE-2021-23337"]["weaknesses_status"] == "reported"
    for name in ("TEST-missing", "TEST-empty"):
        assert issues[name]["cve_ids"] == issues[name]["cwe_ids"] == []
        assert issues[name]["weaknesses_status"] == "not-provided"
    assert issues["TEST-partial"]["cwe_ids"] == ["CWE-79"]
    assert issues["TEST-budget"]["cwe_ids"] == ["CWE-89"]
    for name in ("TEST-partial", "TEST-container", "TEST-field", "TEST-budget"):
        assert issues[name]["weaknesses_status"] == "incomplete"
    assert (
        sum(d.code == "osv.invalid-weakness-metadata" for d in result.diagnostics) == 4
    )
    unavailable = issues["CVE-2026-99999"]
    assert unavailable["cve_ids"] == ["CVE-2026-99999"]
    assert unavailable["weaknesses_status"] == "incomplete"
    assert unavailable["identifier_references"][0]["field"] == "id"


def test_compatibility_honors_requirement_constraints(tmp_path: Path) -> None:

    class PyPI:
        def fetch_metadata(self, package, version=None):
            if version is None:
                return PyPIFetchResult({"releases": {"1.0": [{}], "2.0": [{}]}})
            return PyPIFetchResult({"info": {"requires_dist": []}})

    (tmp_path / "requirements.txt").write_text("demo>=1\n-c constraints.txt\n")
    (tmp_path / "constraints.txt").write_text("demo<2\n")
    result = RepositoryScanner(compatibility_checker=CompatibilityChecker(PyPI())).scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=True)
    )
    assert result.metadata["compatibility"]["pypi:python:."]["selected_versions"] == {
        "demo": "1.0"
    }


@pytest.mark.parametrize(
    "info,diagnostic",
    [
        ({"requires_dist": ["invalid requirement !!!"]}, "pypi.invalid-requires-dist"),
        ({"requires_dist": 7}, "pypi.invalid-requires-dist"),
        ({"requires_dist": "requests"}, "pypi.invalid-requires-dist"),
        (
            {"requires_dist": [], "requires_python": "broken"},
            "pypi.invalid-requires-python",
        ),
        (
            {"requires_dist": [], "requires_python": ">=>3.12"},
            "pypi.invalid-requires-python",
        ),
        (
            {"requires_dist": [], "requires_python": True},
            "pypi.invalid-requires-python",
        ),
    ],
    ids=[
        "invalid-requirement",
        "numeric-requires-dist",
        "string-requires-dist",
        "invalid-python",
        "malformed-python",
        "boolean-python",
    ],
)
def test_invalid_compatibility_metadata_is_incomplete(
    tmp_path: Path, info, diagnostic
) -> None:

    class PyPI:
        def fetch_metadata(self, package, version=None):
            return PyPIFetchResult({"info": info})

    (tmp_path / "requirements.txt").write_text("demo==1.0\n")
    result = RepositoryScanner(compatibility_checker=CompatibilityChecker(PyPI())).scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=True)
    )
    assert not result.capability("compatibility").complete
    assert any(d.code == diagnostic for d in result.diagnostics)
    assert result.metadata["compatibility"]["pypi:python:."]["complete"] is False


def test_python_full_version_marker_uses_requested_target() -> None:
    from depcheck.ecosystems.python import filter_python_manifest
    from depcheck.model import ManifestParseResult

    requirement = PythonRequirement.from_requirement(
        'demo==1; python_full_version == "3.10.7"',
        source=SourceLocation(Path("requirements.txt")),
    )
    filtered = filter_python_manifest(
        ManifestParseResult(declarations=(requirement,)), "3.10.7"
    )
    assert filtered.declarations == (requirement,)


def test_compatibility_backtracks_and_retains_proven_pinned_conflicts() -> None:

    class PyPI:
        def fetch_metadata(self, package, version=None):
            releases = {
                "alpha": {"1.0": [], "2.0": ["beta>=2"]},
                "beta": {"1.0": []},
            }
            if version is None:
                return PyPIFetchResult(
                    {"releases": {v: [{}] for v in releases[package]}}
                )
            return PyPIFetchResult(
                {"info": {"requires_dist": releases[package][version]}}
            )

    checker = CompatibilityChecker(PyPI())
    report = checker.check({"alpha": ">=1", "beta": "==1.0"})
    assert report.complete
    assert not report.conflicts
    assert report.resolution_status == "resolved"
    assert report.selected_versions == {"alpha": "1.0", "beta": "1.0"}
    compatible = checker.check({"alpha": "==1.0", "beta": "==1.0"})
    assert compatible.complete
    assert not compatible.conflicts
    pinned_conflict = checker.check({"alpha": "==2.0", "beta": "==1.0"})
    assert pinned_conflict.complete
    assert pinned_conflict.conflicts


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("quote", ["'", '"'])
def test_pyproject_preview_preserves_comments_markers_and_newlines(
    tmp_path, newline, quote
):

    marker = "python_version >= '3.11'" if quote == '"' else 'python_version >= "3.11"'
    original = (
        (
            f'[project]\nname="app-2.31.0"\nversion="2.31.0"\ndependencies = [\n  {quote}requests[socks]==2.31.0; {marker}{quote}, # retain\n]\n'
        )
        .replace("\n", newline)
        .encode()
    )
    path = tmp_path / "pyproject.toml"
    path.write_bytes(original)
    result = PyprojectUpdater(tmp_path).plan(
        path, {"requests": "==2.32.4"}, group="project"
    )
    assert result.diagnostics == ()
    assert result.matched == ("requests",)
    assert result.groups == ("project",)
    assert result.plan.updated_content.encode() == original.replace(
        b"==2.31.0", b"==2.32.4"
    )
    assert path.read_bytes() == original


def test_pyproject_preview_requires_unambiguous_group(tmp_path):

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests==1"]\n[project.optional-dependencies]\ntest=["requests==1; python_version < \'3.12\'", "requests==2; python_version >= \'3.12\'"]\ndocs=["requests==1"]\n'
    path.write_text(original)
    updater = PyprojectUpdater(tmp_path)
    result = updater.plan(path, {"requests": "3"})
    assert result.plan is None and result.matched == ()
    assert result.diagnostics[0].code == "update.ambiguous-target"
    result = updater.plan(path, {"requests": "3"}, group="optional:test")
    assert result.groups == ("optional:test",)
    assert result.plan.updated_content == original.replace(
        "requests==1;", "requests==3;"
    ).replace("requests==2;", "requests==3;")
    assert path.read_text() == original


@pytest.mark.parametrize(
    ("content", "updates", "group", "code"),
    [
        (
            '[project]\ndependencies=["requests @ https://example.org/a.whl"]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndynamic=["dependencies"]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["""requests==1"""]',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            "[project]\ndependencies=[42]",
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["bad !!!"]',
            {"requests": "2"},
            None,
            "update.invalid-target",
        ),
        ("[project", {"requests": "2"}, None, "update.invalid-target"),
        (
            '[project]\ndependencies=["requests==1"]',
            {"requests": "not-a-version"},
            None,
            "update.invalid-target",
        ),
        (
            '[project]\ndependencies=["requests==1"]',
            {"urllib3": "2"},
            None,
            "update.unsupported-target",
        ),
        (
            '[project]\ndependencies=["requests==1"]',
            {"requests": "2"},
            "optional:missing",
            "update.unsupported-target",
        ),
        (
            '[tool.poetry.dependencies]\nrequests="1"',
            {"requests": "2"},
            None,
            "update.unsupported-target",
        ),
    ],
)
def test_pyproject_preview_refuses_unsupported_targets(
    tmp_path, content, updates, group, code
):

    path = tmp_path / "pyproject.toml"
    path.write_text(content)
    result = PyprojectUpdater(tmp_path).plan(path, updates, group=group)
    assert result.plan is None and result.matched == ()
    assert result.diagnostics[0].code == code
    assert result.diagnostics[0].severity == "error"
    assert path.read_text() == content


def test_pyproject_preview_noop_and_file_atomicity(tmp_path):

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests>=1,<3", "urllib3 @ https://example.org/u.whl"]\n'
    path.write_text(original)
    updater = PyprojectUpdater(tmp_path)
    result = updater.plan(path, {"requests": "<3,>=1"})
    assert (
        result.plan is None
        and result.matched == ("requests",)
        and not result.diagnostics
    )
    result = updater.plan(path, {"requests": "2", "urllib3": "2"})
    assert result.plan is None and not result.matched and result.diagnostics
    assert path.read_text() == original


def test_pyproject_preview_rejects_external_symlink_before_read(tmp_path, monkeypatch):
    from depcheck.path_policy import ProjectPathError

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_text("[project]")
    link = root / "pyproject.toml"
    link.symlink_to(outside)

    def forbidden(*args, **kwargs):
        raise AssertionError("read before path validation")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    with pytest.raises(ProjectPathError):
        PyprojectUpdater(root).plan(link, {"requests": "2"})
    with pytest.raises(ProjectPathError):
        PyprojectUpdater(root).plan(root / "../outside.toml", {"requests": "2"})


@pytest.mark.parametrize(
    "entry",
    [r"requ\u0065sts==2.31.0", r"requests==2.31.0\u003b python_version < '3.12'"],
)
def test_pyproject_preview_refuses_escaped_tokens_without_corrupting_them(
    tmp_path, entry
):

    path = tmp_path / "pyproject.toml"
    original = f'[project]\ndependencies=["{entry}"]\n'
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(path, {"requests": "2.32.4"})
    assert result.plan is None
    assert result.diagnostics[0].code == "update.unsupported-target"
    assert path.read_text() == original


def test_pyproject_preview_preserves_spaced_extras(tmp_path):

    path = tmp_path / "pyproject.toml"
    original = "[project]\ndependencies=[\"requests [socks] ==2.31.0; python_version < '3.12'\"]\n"
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(path, {"requests": "2.32.4"})
    assert result.plan.updated_content == original.replace("2.31.0", "2.32.4")


@pytest.mark.parametrize(
    "suffix",
    [
        'dynamic=["optional-dependencies"]\n',
        "[project.optional-dependencies]\ntest=[42]\n",
        '[project.optional-dependencies]\ntest=["bad !!!"]\n',
    ],
)
def test_pyproject_preview_ignores_unaffected_groups(tmp_path, suffix):

    path = tmp_path / "pyproject.toml"
    original = '[project]\ndependencies=["requests==1"]\n' + suffix
    path.write_text(original)
    result = PyprojectUpdater(tmp_path).plan(
        path,
        {"requests": "2"},
        group="project" if suffix.startswith("dynamic") else None,
    )
    assert not result.diagnostics
    assert result.plan.updated_content == original.replace("requests==1", "requests==2")


@pytest.mark.parametrize(
    "encoding,newline,prefix",
    [
        ("utf-8", "\n", '标签="雪😀"; '),
        ("latin-1", "\r\n", 'é="é"; '),
        ("utf-8", "\r", '标签="雪😀"; '),
    ],
)
def test_python_import_columns_use_code_points_across_encodings(
    tmp_path, encoding, newline, prefix
):
    from depcheck.analyzer.import_scanner import ImportScanner

    line = (
        prefix
        + 'import yaml; from requests import get; __import__("pydantic"); importlib.import_module(name)'
    )
    source = f"# coding: {encoding}{newline}" + line + newline
    (tmp_path / "app.py").write_bytes(source.encode(encoding))
    (tmp_path / "broken.py").write_bytes(
        (f"# coding: {encoding}{newline}" + prefix + "import ?" + newline).encode(
            encoding
        )
    )
    result = ImportScanner().scan_detailed(tmp_path)
    assert [(i.module, i.source.line, i.source.column) for i in result.imports] == [
        ("yaml", 2, line.index("import yaml") + 1),
        ("requests", 2, line.index("from requests") + 1),
        ("pydantic", 2, line.index("__import__") + 1),
    ]
    dynamic = next(d for d in result.diagnostics if d.code == "usage.dynamic")
    assert (dynamic.source.line, dynamic.source.column) == (
        2,
        line.index("importlib.import_module") + 1,
    )
    syntax = next(d for d in result.diagnostics if d.code == "source.syntax-error")
    assert (syntax.source.line, syntax.source.column) == (
        2,
        len(prefix) + len("import ") + 1,
    )


def test_ast_source_positions_support_universal_newlines_without_byte_columns():
    import ast
    from depcheck.source_locations import SourcePositions

    lines = ['标签="雪😀"; first("one")', 'é="雪"; second("two")']
    for newline in ("\n", "\r\n", "\r"):
        text = newline.join(lines) + newline
        positions = SourcePositions(Path("fixture.py"), text)
        calls = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call)]
        assert [
            (positions.ast_node(n).line, positions.ast_node(n).column) for n in calls
        ] == [(1, lines[0].index("first") + 1), (2, lines[1].index("second") + 1)]


def test_notebook_columns_keep_cell_context_and_sarif_qualifies_virtual_regions(
    tmp_path,
):
    import json
    from depcheck.analyzer.import_scanner import ImportScanner
    from depcheck.output import build_sarif

    payload = {
        "cells": [
            {
                "cell_type": "code",
                "source": 'import importlib as loader\n标签="雪😀"; import yaml\n',
            },
            {
                "cell_type": "code",
                "source": [
                    'label="😀"; loader.import_module("yaml")\r',
                    'text="雪"; loader.import_module(name)\r',
                ],
            },
            {"cell_type": "code", "source": "\ud800\n"},
            {"cell_type": "code", "source": "import yaml\n"},
        ]
    }
    (tmp_path / "book.ipynb").write_text(json.dumps(payload))
    (tmp_path / "requirements.txt").write_text("requests==2.32.4\n")
    scan = ImportScanner().scan_detailed(tmp_path)
    assert [
        (i.module, i.source.line, i.source.column, i.kind) for i in scan.imports
    ] == [
        ("yaml", 2, 10, "regular"),
        ("yaml", 5, 12, "dynamic"),
        ("yaml", 12, 1, "regular"),
    ]
    assert {d.code for d in scan.diagnostics} == {
        "usage.dynamic",
        "source.notebook-syntax-error",
    }
    dynamic = next(d for d in scan.diagnostics if d.code == "usage.dynamic")
    assert (dynamic.source.line, dynamic.source.column) == (6, 11)
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    run = build_sarif(result)["runs"][0]
    missing = next(
        r
        for r in run["results"]
        if r["properties"]["finding_code"] == "dependency.missing"
    )
    assert len(missing["locations"]) == 3
    assert all(
        "region" not in location["physicalLocation"]
        for location in missing["locations"]
    )
    assert [
        location["properties"]["depcheck:reported-region"]["line"]
        for location in missing["locations"]
    ] == [2, 5, 12]
    assert all(
        location["properties"]["depcheck:region-status"] == "notebook-virtual"
        for location in missing["locations"]
    )
    assert all(
        "region" not in n["locations"][0]["physicalLocation"]
        for n in run["invocations"][0]["toolExecutionNotifications"]
        if n.get("locations")
    )
    assert (
        run["columnKind"] == "unicodeCodePoints"
        and not run["invocations"][0]["executionSuccessful"]
    )


class _ResolutionMetadata:
    def __init__(self, releases):
        self.releases = releases
        self.calls = []

    def fetch_metadata(self, package, version=None):
        self.calls.append((package, version))
        if version is None:
            return PyPIFetchResult(
                {"releases": {key: [{}] for key in self.releases[package]}}
            )
        return PyPIFetchResult({"info": self.releases[package][version]})


def test_metadata_resolver_backtracks_python_extras_and_prunes_rejected_branches():
    client = _ResolutionMetadata(
        {
            "app": {
                "3": {"requires_python": ">=3.99", "requires_dist": ["orphan==1"]},
                "2": {"requires_dist": ['support>=2; extra == "fast"', "orphan==1"]},
                "1": {"requires_dist": ['support<2; extra == "fast"']},
            },
            "support": {"1": {"requires_dist": []}, "2": {"requires_dist": []}},
            "orphan": {"1": {"requires_dist": []}},
        }
    )
    from depcheck.model import ManifestParseResult

    manifest = ManifestParseResult(
        declarations=tuple(
            PythonRequirement.from_requirement(
                raw, source=SourceLocation(Path("requirements.txt"))
            )
            for raw in ("app[fast]>=1", "support==1")
        )
    )
    report = CompatibilityChecker(client).check_detailed(
        manifest, python_version="3.11.0"
    )
    assert report.complete and report.resolution_status == "resolved"
    assert report.selected_versions == {"app": "1", "support": "1"}
    assert not report.python_conflicts and not report.conflicts
    assert "orphan" not in report.selected_versions


def test_metadata_resolver_context_selection_does_not_merge_unselected_groups():
    from depcheck.model import ManifestParseResult

    client = _ResolutionMetadata({"demo": {"1": {}, "2": {}}})
    manifest = ManifestParseResult(
        declarations=(
            PythonRequirement.from_requirement(
                "demo==1", source=SourceLocation(Path("pyproject.toml"))
            ),
            PythonRequirement.from_requirement(
                "demo==2",
                source=SourceLocation(Path("pyproject.toml")),
                group="dev:other",
            ),
        )
    )
    runtime = CompatibilityChecker(client).check_detailed(manifest)
    assert runtime.selected_versions == {"demo": "1"}
    assert runtime.resolution["unselected_groups"] == ["dev:other"]
    selected = CompatibilityChecker(client).check_detailed(
        manifest, dependency_groups=("dev:other",)
    )
    assert selected.complete and selected.resolution_status == "unsatisfiable"
    assert selected.conflicts and not selected.selected_versions


def test_metadata_resolver_unknown_and_budget_do_not_become_unsatisfiable(monkeypatch):
    from depcheck.compatibility.resolver import _Provider

    client = _ResolutionMetadata({"demo": {"1": {}}})
    monkeypatch.setattr(_Provider, "MAX_REQUESTS", 1)
    report = CompatibilityChecker(client).check({"demo": ">=1"})
    assert not report.complete and report.resolution_status == "incomplete"
    assert not report.selected_versions and not report.conflicts
    assert any(d.code == "compatibility.metadata-budget" for d in report.diagnostics)


def test_metadata_resolver_blocks_private_homonyms_reached_transitively():
    from depcheck.model import ManifestParseResult

    client = _ResolutionMetadata({"parent": {"1": {"requires_dist": ["secret>=1"]}}})
    manifest = ManifestParseResult(
        declarations=(
            PythonRequirement.from_requirement(
                "parent==1", source=SourceLocation(Path("requirements.txt"))
            ),
            PythonRequirement.from_requirement(
                "secret @ https://private.example/secret.whl",
                source=SourceLocation(Path("requirements.txt")),
            ),
        )
    )
    report = CompatibilityChecker(client).check_detailed(manifest)
    assert not report.complete and report.resolution_status == "incomplete"
    assert all(name != "secret" for name, _ in client.calls)
    assert not report.suggestions and not report.selected_versions


def test_metadata_resolver_lock_suggestions_use_a_consistent_relaxed_graph():
    from depcheck.model import ManifestParseResult

    client = _ResolutionMetadata(
        {
            "demo": {
                "1": {},
                "2": {"requires_dist": ["shared==1"]},
                "3": {"requires_dist": ["shared==2"]},
            },
            "shared": {"1": {}, "2": {}},
        }
    )
    manifest = ManifestParseResult(
        declarations=(
            PythonRequirement.from_requirement(
                "demo>=2", source=SourceLocation(Path("requirements.txt"))
            ),
            PythonRequirement.from_requirement(
                "shared==1", source=SourceLocation(Path("requirements.txt"))
            ),
            PythonRequirement.from_requirement(
                "demo==1",
                source=SourceLocation(Path("requirements.lock")),
                kind="locked",
            ),
        )
    )
    report = CompatibilityChecker(client).check_detailed(manifest)
    assert report.complete and report.resolution_status == "unsatisfiable"
    assert report.suggestions == {"demo": "==2"}
    assert not report.selected_versions


@pytest.mark.parametrize(
    "specifier,selected", [(">=1", "1.0"), (">=2.0b1", "2.0rc1"), ("==2.0a1", "2.0a1")]
)
def test_metadata_resolver_uses_pep440_prerelease_opt_in(specifier, selected):
    client = _ResolutionMetadata(
        {"demo": {"1.0": {}, "2.0a1": {}, "2.0b1": {}, "2.0rc1": {}}}
    )
    report = CompatibilityChecker(client).check({"demo": specifier})
    assert report.resolution_status == "resolved"
    assert report.selected_versions == {"demo": selected}


@pytest.mark.parametrize("pinned", [False, True])
def test_metadata_resolver_extras_keep_base_constraints_and_backtrack(pinned):
    client = _ResolutionMetadata(
        {
            "app": {
                "2": {
                    "requires_dist": [
                        'support<2; extra != "fast"',
                        'abandoned==1; extra == "fast"',
                    ]
                },
                "1": {"requires_dist": ['support>=2; extra == ""']},
            },
            "support": {"1": {}, "2": {}},
            "abandoned": {"1": {}},
        }
    )
    report = CompatibilityChecker(client).check(
        {"app[fast]": "==2" if pinned else ">=1", "support": "==2"}
    )
    assert report.complete
    if pinned:
        assert report.resolution_status == "unsatisfiable"
        assert report.conflicts and not report.selected_versions
    else:
        assert report.resolution_status == "resolved"
        assert report.selected_versions == {"app": "1", "support": "2"}
        assert not report.conflicts


def test_metadata_resolver_multiple_extras_union_base_and_named_contexts():
    client = _ResolutionMetadata(
        {
            "app": {
                "1": {
                    "requires_dist": [
                        'base==1; extra == ""',
                        'accelerator==1; extra == "fast"',
                        'documentation==1; extra == "docs"',
                    ]
                }
            },
            "base": {"1": {}},
            "accelerator": {"1": {}},
            "documentation": {"1": {}},
        }
    )
    report = CompatibilityChecker(client).check(
        {"app[fast]": "==1", "app[docs]": "==1"}
    )
    assert report.complete and report.resolution_status == "resolved"
    assert report.selected_versions == {
        "app": "1",
        "base": "1",
        "accelerator": "1",
        "documentation": "1",
    }
    assert client.calls.count(("app", "1")) == 1


@pytest.mark.parametrize(
    "marker",
    ['"gui" in extras', '"test" in dependency_groups', 'os_name ~= "posix"'],
)
def test_metadata_resolver_unsupported_marker_context_remains_incomplete(marker):
    client = _ResolutionMetadata(
        {"app": {"1": {"requires_dist": [f"support==1; {marker}"]}}}
    )
    report = CompatibilityChecker(client).check({"app": "==1"})
    assert not report.complete and report.resolution_status == "incomplete"
    assert not report.conflicts and not report.selected_versions
    assert [d.code for d in report.diagnostics] == ["pypi.invalid-requires-dist-marker"]
    assert client.calls == [("app", "1")]


def test_unknown_root_marker_preserves_inventory_and_blocks_metadata_queries(tmp_path):
    from depcheck.ecosystems.python import filter_python_manifest
    from depcheck.model import ManifestParseResult

    (tmp_path / "requirements.txt").write_text('demo==1; "gui" in extras\n')
    (tmp_path / "app.py").write_text("import demo\n")
    declaration = PythonRequirement.from_requirement(
        'demo==1; "gui" in extras',
        source=SourceLocation(tmp_path / "requirements.txt", 1),
    )
    manifest = ManifestParseResult(declarations=(declaration,))
    filtered = filter_python_manifest(manifest, "3.12")
    assert filtered.declarations == (declaration,)
    assert [d.code for d in filtered.diagnostics] == [
        "manifest.marker-evaluation-unknown"
    ]
    client = _ResolutionMetadata({})
    report = CompatibilityChecker(client).check_detailed(manifest)
    assert not report.complete and report.resolution_status == "incomplete"
    assert not report.selected_versions and not report.conflicts and not client.calls
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, python_version="3.12"
        ),
    )
    assert [item.package.name for item in result.bundles[0].declarations] == ["demo"]
    assert any(
        d.code == "manifest.marker-evaluation-unknown" for d in result.diagnostics
    )
    assert not next(
        capability
        for capability in result.bundles[0].capabilities
        if capability.name == "manifest"
    ).complete
    assert not any(f.code.startswith("dependency.") for f in result.findings)


@pytest.mark.parametrize("body", [b'{"info":{},"info":{}}', b"x" * 33])
def test_pypi_metadata_stream_budget_and_duplicate_keys_remain_incomplete(body):
    from depcheck.compatibility.pypi_client import PyPIClient

    class Response:
        status_code = 200
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.closed = True

        def raise_for_status(self):
            pass

        def iter_content(self, size):
            yield body

    response = Response()

    class Session:
        def get(self, url, **kwargs):
            assert url == "https://pypi.org/pypi/demo/1/json"
            assert kwargs["stream"] is True and kwargs["allow_redirects"] is False
            return response

    client = PyPIClient(session=Session(), max_attempts=1)
    client.MAX_RESPONSE_BYTES = 32
    result = client.fetch_metadata("demo", "1")
    assert result.data is None and not result.complete
    assert result.diagnostic.code == "pypi.invalid-response"
    assert response.closed


@pytest.mark.parametrize(
    "ecosystem,version,entry,extra,status",
    [
        ("PyPI", "1.0.0", {"versions": ["1.0"]}, [], "affected"),
        ("Go", "v1.2.3", {"versions": ["1.2.3"]}, [], "affected"),
        ("PyPI", "1.0", {}, [], "unknown"),
        (
            "PyPI",
            "1.0",
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
            [],
            "affected",
        ),
        (
            "PyPI",
            "2.0",
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                    }
                ]
            },
            [
                {
                    "package": {"name": "other", "ecosystem": "Maven"},
                    "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}],
                }
            ],
            "not-affected",
        ),
        (
            "npm",
            "1.0.0-beta.2",
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0-beta.1"},
                            {"fixed": "1.0.0-beta.3"},
                        ],
                    },
                    {"type": "GIT", "events": [{"introduced": "abc"}]},
                ]
            },
            [],
            "affected",
        ),
        (
            "npm",
            "1.0.0",
            {
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
                    },
                    {"type": "GIT", "events": [{"introduced": "abc"}]},
                ]
            },
            [],
            "unknown",
        ),
        (
            "PyPI",
            "2.0",
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"last_affected": "2.0"}],
                    }
                ]
            },
            [],
            "affected",
        ),
        (
            "PyPI",
            "2.0",
            {
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"limit": "2.0"}],
                    }
                ]
            },
            [],
            "not-affected",
        ),
        ("Maven", "1.0-final", {"versions": ["1.0-final"]}, [], "affected"),
        ("Maven", "1.0", {"versions": ["1.0-final"]}, [], "unknown"),
    ],
    ids=[
        "pep440-equality",
        "go-prefix",
        "missing-version-context",
        "unfixed-range",
        "unrelated-unsupported-package",
        "supported-positive-with-unknown-range",
        "unsupported-negative-coverage",
        "last-affected-inclusive",
        "limit-exclusive",
        "maven-literal",
        "maven-equality-unsupported",
    ],
)
def test_osv_membership_is_independent_of_fix_candidates(
    ecosystem, version, entry, extra, status
):
    from depcheck.security.osv_client import match_affected_version

    record = {
        "id": "OSV-MATCH",
        "affected": [
            {"package": {"ecosystem": ecosystem, "name": "demo"}, **entry},
            *extra,
        ],
    }
    actual, reason = match_affected_version(record, "demo", ecosystem, version)
    assert actual == status
    assert reason
