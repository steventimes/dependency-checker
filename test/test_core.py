"""Python manifests, compatibility resolution, and vulnerability semantics."""

import json
from itertools import combinations, combinations_with_replacement
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import JsonResponse

from depcheck.compatibility.checker import (
    CompatibilityChecker,
    CompatibilityConflict,
    CompatibilityReport,
)
from depcheck.compatibility.pypi_client import PyPIFetchResult
from depcheck.compatibility.pyproject_updater import PyprojectUpdater
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.python.parsers.lock import LockfileParser
from depcheck.ecosystems.python.parsers.pipfile import PipfileParser
from depcheck.ecosystems.python.parsers.pyproject import PyProjectParser
from depcheck.ecosystems.python.parsers.setup import SetupCfgParser, SetupPyParser
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
from depcheck.security.maven import MavenVersion
from depcheck.security.osv_client import OSVClient


def test_toml_locations_reuse_is_scoped_and_keyed_by_captured_text_and_path():
    from depcheck.filesystem.positions import SourcePositions, toml_position_scope

    path = Path("Cargo.toml")
    old = "flag=true\n"
    new = "# changed\nflag=true\n"
    with pytest.raises(RuntimeError, match="controlled"):
        with toml_position_scope():
            first = SourcePositions.toml(path, old)
            assert SourcePositions.toml(path, old) is first
            with toml_position_scope():
                assert SourcePositions.toml(path, old) is first
            changed = SourcePositions.toml(path, new)
            assert changed is not first and changed.key("flag").line == 2
            other = SourcePositions.toml(Path("member/Cargo.toml"), old)
            assert other.path != first.path and other is not first
            upper = SourcePositions.toml(Path("Member/Cargo.toml"), old)
            assert upper is not other
            assert str(upper.path) == str(Path("Member/Cargo.toml"))
            assert str(other.path) == str(Path("member/Cargo.toml"))
            raise RuntimeError("controlled scan failure")
    # Neither ordinary reads nor the next scan inherit a previous result.
    assert SourcePositions.toml(path, old) is not first
    with toml_position_scope():
        assert SourcePositions.toml(path, old) is not first


def test_toml_locations_reuse_evicts_without_dropping_large_input_positions():
    from depcheck.filesystem.positions import SourcePositions, toml_position_scope

    text = "flag=true\n"
    with toml_position_scope():
        first = SourcePositions.toml(Path("0.toml"), text)
        for index in range(1, 5):
            SourcePositions.toml(Path(f"{index}.toml"), text)
        assert SourcePositions.toml(Path("0.toml"), text) is not first
        large = "#" + "x" * (256 * 1024) + "\nflag=true\n"
        a = SourcePositions.toml(Path("large.toml"), large)
        b = SourcePositions.toml(Path("large.toml"), large)
        assert a is not b
        assert a.text == b.text == large
        assert a.key("flag").line == b.key("flag").line == 2


def test_toml_locations_preserve_boolean_items_and_dotted_table_origins():
    import tomllib

    from depcheck.filesystem.positions import SourcePositions

    text = (
        "# true and false here are not declarations\r\n"
        "[dependencies]\r\n"
        "serde.workspace = true\r\n"
        "foo.optional = false\r\n"
        'foo.version = "1"\r\n'
        '"点.key".workspace = true\r\n'
        "[other]\r\n"
        "flags = [true, false, true]\r\n"
        "nested = [{flag=true}, {flag=false}]\r\n"
    )
    assert tomllib.loads(text)["dependencies"]["foo"] == {
        "optional": False,
        "version": "1",
    }
    positions = SourcePositions.toml(Path("Cargo.toml"), text)
    for path, line in [
        (("dependencies", "serde"), 3),
        (("dependencies", "serde", "workspace"), 3),
        (("dependencies", "foo"), 4),
        (("dependencies", "foo", "optional"), 4),
        (("dependencies", "foo", "version"), 5),
        (("dependencies", "点.key"), 6),
    ]:
        location = positions.key(*path)
        assert (location.line, location.column) == (line, 1), path
    assert positions.key("dependencies").line == 2
    for index, column in enumerate([10, 16, 23]):
        location = positions.value("other", "flags", index)
        assert (location.line, location.column) == (8, column)
    for index, column in enumerate([12, 25]):
        location = positions.key("other", "nested", index, "flag")
        assert (location.line, location.column) == (9, column)
    assert positions.key("absent", "serde").line is None


def test_toml_locations_keep_explicit_headers_aot_indices_and_quoted_segments():
    from depcheck.filesystem.positions import SourcePositions

    text = (
        '"dot.key".first.flag = true\n'
        "[dependencies.explicit]\n"
        "workspace = true\n"
        "[[package]]\n"
        'name = "same"\n'
        "optional = true\n"
        "[[package]]\n"
        'name = "same"\n'
        "optional = true\n"
    )
    positions = SourcePositions.toml(Path("fixture.toml"), text)
    assert positions.key("dot.key", "first").line == 1
    assert positions.key("dot", "key").line is None
    assert positions.key("dependencies", "explicit").line == 2
    assert positions.key("dependencies", "explicit", "workspace").line == 3
    assert [positions.key("package", i).line for i in range(2)] == [4, 7]
    assert [positions.key("package", i, "name").line for i in range(2)] == [5, 8]
    assert [positions.key("package", i, "optional").line for i in range(2)] == [6, 9]


def test_toml_locations_missing_syntax_items_keep_native_inventory(
    tmp_path, monkeypatch
):
    from tomlkit.exceptions import TOMLKitError

    from depcheck.filesystem import positions

    def unavailable(self):
        raise TOMLKitError("Controlled unsupported syntax positioning")

    monkeypatch.setattr(positions._PositionedTomlParser, "parse", unavailable)
    path = tmp_path / "uv.lock"
    path.write_text(
        'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\nsource={registry="https://pypi.org/simple"}\n'
    )
    parsed = LockfileParser(path).parse_detailed()
    (record,) = parsed.declarations
    assert record.name == "requests" and record.pinned_version == "2.31.0"
    assert record.source.path == path and record.source.line is None
    assert record.source.column is None


def test_rubygems_advisory_ordering_matches_original_native_assertions():
    import hashlib

    from depcheck.security.rubygems import RubyGemsVersion

    folder = Path(__file__).parent / "fixtures/security/rubygems"
    provenance = json.loads((folder / "provenance.json").read_text())
    for item in provenance["retained_fixtures"]:
        assert (
            hashlib.sha256((folder / item["path"]).read_bytes()).hexdigest()
            == item["sha256"]
        )
    comparisons = json.loads((folder / "truth.json").read_text())["comparisons"]
    assert comparisons
    for first, second, expected in comparisons:
        left, right = RubyGemsVersion(first), RubyGemsVersion(second)
        assert (left > right) - (left < right) == expected, (first, second)
        assert (right > left) - (right < left) == -expected
        if expected == 0:
            assert left == right and hash(left) == hash(right)
    # Case-sensitive native strings and numeric prerelease segments differ
    # from PEP 440 normalization and lexical/SemVer ordering.
    assert RubyGemsVersion("1.A") < RubyGemsVersion("1.a")
    assert RubyGemsVersion("1.a9") < RubyGemsVersion("1.a10")
    assert RubyGemsVersion("1.0-pre") == RubyGemsVersion("1.pre.pre")
    assert RubyGemsVersion("1.2.pre.1") == RubyGemsVersion("1.2.0.pre.1.0")


@pytest.mark.parametrize(
    "raw",
    [
        "",
        " ",
        "1.0 ",
        "1.0\n",
        "1..2",
        "v1.2.3",
        "1.0+build",
        "1.0-x86_64-linux",
        "~>1.2",
        "1.版本",
        "1" * 257,
        None,
        1,
    ],
)
def test_rubygems_advisory_ordering_rejects_ambiguous_or_unbounded_inputs(raw):
    from depcheck.security.rubygems import RubyGemsVersion

    with pytest.raises(ValueError, match="bounded ASCII"):
        RubyGemsVersion(raw)


def test_rubygems_advisory_membership_and_fix_branches_remain_separate():
    from depcheck.security.advisories import match_affected_version, parse_advisory

    detail = {
        "id": "RUBYGEMS-BRANCHES",
        "affected": [
            {
                "package": {"ecosystem": "RubyGems", "name": "demo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.3"},
                            {"introduced": "1.3"},
                            {"fixed": "1.3.5"},
                        ],
                    }
                ],
            }
        ],
    }
    for version, status, fix in [
        ("1.2.2", "affected", "1.2.3"),
        ("1.2.3.0", "not-affected", None),
        ("1.3.1", "affected", "1.3.5"),
        ("1.3.5", "not-affected", None),
    ]:
        assert match_affected_version(detail, "demo", "RubyGems", version)[0] == status
        if fix:
            issue, _ = parse_advisory(detail, "demo", "RubyGems", version)
            assert (
                issue["fix_version"] == fix
                and issue["fix_version_status"] == "candidate"
            )
    entry = detail["affected"][0]
    entry["versions"] = ["1.7.0", "1.版本"]
    entry["ranges"].append(
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.*"}]}
    )
    for version, status in [
        ("1.3.1", "affected"),
        ("1.7", "affected"),
        ("1.版本", "affected"),
        ("3.0", "unknown"),
    ]:
        assert match_affected_version(detail, "demo", "RubyGems", version)[0] == status
        if status == "affected":
            assert (
                parse_advisory(detail, "demo", "RubyGems", version)[0][
                    "fix_version_status"
                ]
                == "unknown"
            )
    entry.pop("versions")
    entry["ranges"] = [
        {
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.a"},
                {"last_affected": "1.b9"},
                {"limit": "2"},
            ],
        }
    ]
    assert match_affected_version(detail, "demo", "RubyGems", "1.b9.0")[0] == "affected"
    assert (
        match_affected_version(detail, "demo", "RubyGems", "1.b10")[0] == "not-affected"
    )


def test_maven_ordering_matches_pinned_official_assertions():
    truth = json.loads(
        (Path(__file__).parent / "fixtures/security/truth.json").read_text()
    )["maven_ordering"]
    pairs = list(map(tuple, truth["ordered_pairs"]))
    for sequence in truth["ordered_sequences"]:
        pairs.extend(combinations(sequence, 2))
    for first, second in pairs:
        left, right = MavenVersion(first), MavenVersion(second)
        assert left < right and right > left, (first, second)
    equal_pairs = list(map(tuple, truth["equal_pairs"]))
    for group in truth["equivalent_groups"]:
        equal_pairs.extend(combinations_with_replacement(group, 2))
    for first, second in equal_pairs:
        left, right = MavenVersion(first), MavenVersion(second)
        assert left == right and not left < right and not right < left, (first, second)
        assert hash(left) == hash(right), (first, second)


def test_maven_unsupported_boundaries_preserve_positive_assertions():
    from depcheck.security.advisories import match_affected_version, parse_advisory

    detail = {
        "id": "OSV-MAVEN",
        "affected": [
            {
                "package": {"ecosystem": "Maven", "name": "group:artifact"},
                "versions": ["1.版本", "1.0-final"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.版本"}],
                    },
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.2"}, {"fixed": "1.3"}],
                    },
                ],
            }
        ],
    }
    for version, expected in [
        ("1.0", "affected"),
        ("1.2", "affected"),
        ("1.版本", "affected"),
        ("3.0", "unknown"),
    ]:
        assert (
            match_affected_version(detail, "group:artifact", "Maven", version)[0]
            == expected
        )
        if expected == "affected":
            issue, _ = parse_advisory(detail, "group:artifact", "Maven", version)
            assert issue["fix_version"] is None
    entry = detail["affected"][0]
    entry.pop("versions")
    entry["ranges"] = [
        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]},
    ]
    for version, expected in [("1.0-final", "affected"), ("3.0-final", "unknown")]:
        assert (
            match_affected_version(detail, "group:artifact", "Maven", version)[0]
            == expected
        )
        issue, _ = parse_advisory(detail, "group:artifact", "Maven", version)
        assert issue["fix_version_status"] == "unknown"
    entry["ranges"] = [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"limit": "2.*"}]}
    ]
    assert (
        match_affected_version(detail, "group:artifact", "Maven", "3.0")[0] == "unknown"
    )


@pytest.mark.parametrize("raw", ["1" * 257, "${version}", "[1,2)", "1.0\n", "1.版本"])
def test_maven_ordering_rejects_unsupported_inputs(raw):
    with pytest.raises(ValueError, match="bounded ASCII"):
        MavenVersion(raw)


def test_maven_ordering_handles_the_maximum_nested_token_budget():
    left = "a1" * 128
    right = left[:-1] + "2"
    assert MavenVersion(left) < MavenVersion(right)


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
            "# requests>=2\r\n[metadata]\r\ndescription = requests>=2\r\n[options]\r\ninstall_requires =\r\n    requests>=2\r\n    # ignored\r\n    requests<3\r\nsetup_requires =\r\n    wheel>=0.42\r\n    requests>=2\r\ntests_require =\r\n    pytest[testing]>=8; python_version >= '3.11'\r\n    pytest[testing]>=8; python_version >= '3.11'\r\n\r\n[options.extras_require]\r\ntest =\r\n    requests>=2\r\n    invalid !\r\n"
        ).encode()
    )
    parsed = SetupCfgParser(cfg).parse_detailed()
    build_test = [d for d in parsed.declarations if d.group in {"build", "dev:test"}]
    assert len(build_test) == 4
    assert [(d.name, d.group) for d in build_test] == [
        ("pytest", "dev:test"),
        ("pytest", "dev:test"),
        ("wheel", "build"),
        ("requests", "build"),
    ]
    assert build_test[0].extras == ("testing",)
    assert str(build_test[0].marker) == 'python_version >= "3.11"'
    assert (
        build_test[0].raw_requirement == "pytest[testing]>=8; python_version >= '3.11'"
    )
    assert "wheel" not in SetupCfgParser(cfg).parse()
    assert [(d.group, d.source.line, d.source.column) for d in parsed.declarations] == [
        ("runtime", 6, 5),
        ("runtime", 8, 5),
        ("dev:test", 13, 5),
        ("dev:test", 14, 5),
        ("build", 10, 5),
        ("build", 11, 5),
        ("optional:test", 18, 5),
    ]
    assert (parsed.diagnostics[0].source.line, parsed.diagnostics[0].source.column) == (
        19,
        5,
    )

    marker = tmp_path / "executed"
    (tmp_path / "payload.py").write_text(
        f"open({str(marker)!r}, 'w').write('unexpected')\n", encoding="utf-8"
    )
    cfg.write_text(
        "[options]\nsetup_requires = file: payload.py\ntests_require = attr: payload.requirements\n",
        encoding="utf-8",
    )
    unsupported = SetupCfgParser(cfg).parse_detailed()
    assert not unsupported.declarations
    assert [d.code for d in unsupported.diagnostics] == [
        "manifest.invalid-requirement"
    ] * 2
    assert sorted(d.source.line for d in unsupported.diagnostics) == [2, 3]
    assert not marker.exists()


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
    elif name in {"poetry.lock", "pdm.lock", "Pipfile.lock"}:
        assert [d.code for d in parsed.diagnostics] == [
            "resolution.python-lock-selection-unknown"
        ]
    else:
        assert not parsed.diagnostics
    assert [d.pinned_version for d in parsed.declarations] == ["2.31.0", "2.32.0"]
    assert [(d.source.line, d.source.column) for d in parsed.declarations] == expected


@pytest.mark.parametrize("lock_format", ["poetry", "pdm", "pipenv"])
def test_pipenv_compatibility_scan_retains_all_conditional_lock_metadata(
    tmp_path, lock_format
):
    """The scan stage must retain the metadata checked by the public checker."""
    if lock_format == "pipenv":
        (tmp_path / "Pipfile").write_text('[packages]\nrequests="*"\n')
        (tmp_path / "Pipfile.lock").write_text(
            json.dumps(
                {
                    "default": {
                        "requests": {
                            "version": "==2.31.0",
                            "markers": "sys_platform == 'win32'",
                        }
                    }
                }
            )
        )
    else:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname="demo"\nversion="1"\ndependencies=["requests"]\n'
        )
        (tmp_path / (lock_format + ".lock")).write_text(
            '[[package]]\nname="requests"\nversion="2.31.0"\ngroups=["docs"]\n'
        )

    class NoNetwork:
        def __getattr__(self, name):
            raise AssertionError("Conditional lock was flattened by scan projection")

    scan = RepositoryScanner(
        compatibility_checker=CompatibilityChecker(client=NoNetwork())
    ).scan(tmp_path, RepositoryScanOptions(security=False, compatibility=True))
    report = scan.metadata["compatibility"]["pypi:python:."]
    assert report["resolution_status"] == "incomplete"
    assert not report["selected_versions"] and not report["suggestions"]
    assert "compatibility.python-lock-selection-unknown" in {
        d.code for d in scan.diagnostics
    }


@pytest.mark.parametrize("invalid", ["NaN", "1e400", '"\\ud800"'])
def test_pipenv_lock_strict_json_rejects_invalid_context(tmp_path, invalid):
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        '{"default":{"requests":{"version":"==2.31.0","markers":' + invalid + "}}}"
    )
    parsed = LockfileParser(path).parse_detailed()
    assert not parsed.declarations
    assert parsed.diagnostics[0].code == "manifest.invalid-lockfile"


@pytest.mark.parametrize(
    "name",
    [
        "foo==1",
        "foo[extra]",
        "foo; python_version>'3'",
        "foo @ https://example.invalid/foo.whl",
    ],
)
def test_pipenv_package_keys_cannot_invent_requirements(tmp_path, name):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(
        json.dumps(
            {
                "default": {
                    name: {"git": "https://example.invalid/repo.git", "ref": "abcd"}
                }
            }
        )
    )
    parsed = LockfileParser(lock).parse_detailed()
    assert not parsed.declarations and parsed.diagnostics
    pipfile = tmp_path / "Pipfile"
    pipfile.write_text("[packages]\n" + json.dumps(name) + '="*"\n')
    parsed = PipfileParser(pipfile).parse_detailed()
    assert not parsed.declarations and parsed.diagnostics


def test_pipenv_budgets_cover_all_categories_and_redacted_expansion(
    tmp_path, monkeypatch
):
    import depcheck.ecosystems.python.parsers.lock as parser

    path = tmp_path / "Pipfile.lock"
    path.write_text(
        json.dumps(
            {
                "default": {"one": {"version": "==1"}},
                "docs": {"two": {"version": "==2"}},
            }
        )
    )
    monkeypatch.setattr(parser, "_MAX_PIPFILE_PACKAGES", 1)
    result = LockfileParser(path).parse_detailed()
    assert [item.name for item in result.declarations] == ["one"]
    assert "manifest.lock-package-limit" in {item.code for item in result.diagnostics}
    monkeypatch.setattr(parser, "_MAX_PIPFILE_PACKAGES", 20000)
    query = "https://example.invalid/repo?" + "&".join(f"p{i}=" for i in range(700))
    path.write_text(json.dumps({"default": {"one": {"version": "==1", "url": query}}}))
    result = LockfileParser(path).parse_detailed()
    assert len(result.declarations) == 1
    assert result.declarations[0].metadata["details_omitted"] is True
    assert "resolution.python-lock-context-limit" in {
        item.code for item in result.diagnostics
    }


@pytest.mark.parametrize("hashes", [[None], "sha256:value", {"sha256": "value"}])
def test_pipenv_hash_shapes_never_displace_conditions_or_claim_verification(
    tmp_path, hashes
):
    path = tmp_path / "Pipfile.lock"
    path.write_text(
        json.dumps(
            {
                "default": {
                    "requests": {
                        "version": "==2.31.0",
                        "hashes": hashes,
                        "markers": "sys_platform == 'win32'",
                    }
                }
            }
        )
    )
    result = LockfileParser(path).parse_detailed()
    (item,) = result.declarations
    assert item.metadata["context"]["package"]["markers"] == "sys_platform == 'win32'"
    assert item.metadata["omitted_package_fields"] == ["hashes"]
    assert "artifact_hash_count" not in item.metadata
    assert "manifest.invalid-lock-entry" in {d.code for d in result.diagnostics}


def test_pipenv_wildcards_and_inline_conditions_preserve_boolean_grouping(tmp_path):
    path = tmp_path / "Pipfile"
    path.write_text(
        '[packages]\nwaitress={version="3.*", sys_platform="== \'win32\'", '
        "markers=\"python_version < '3.10' or python_version >= '3.15'\"}\n"
        'gunicorn={version="26.2.*", sys_platform="== \'linux\'"}\n'
    )
    parsed = PipfileParser(path).parse_detailed()
    assert not parsed.diagnostics
    waitress, gunicorn = parsed.declarations
    assert (waitress.name, str(waitress.specifier), waitress.pinned_version) == (
        "waitress",
        "==3.*",
        None,
    )
    assert (gunicorn.name, str(gunicorn.specifier), gunicorn.pinned_version) == (
        "gunicorn",
        "==26.2.*",
        None,
    )
    assert not waitress.is_active({"python_version": "3.9", "sys_platform": "linux"})
    assert waitress.is_active({"python_version": "3.15", "sys_platform": "win32"})
    assert not waitress.is_active({"python_version": "3.12", "sys_platform": "win32"})


@pytest.mark.parametrize("raw_marker", [False, [], {}, "", "invalid comparison"])
def test_pipenv_invalid_inline_condition_never_becomes_unconditional(
    tmp_path, raw_marker
):
    path = tmp_path / "Pipfile"
    path.write_text(
        '[packages]\none={version="*",sys_platform='
        + json.dumps(raw_marker)
        + '}\ntwo="==2"\n'
    )
    result = PipfileParser(path).parse_detailed()
    assert [item.name for item in result.declarations] == ["two"]
    assert result.diagnostics


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
        14,
        18,
    ]
    assert any(
        "optional-dependencies" in d.message
        and (d.source.line, d.source.column) == (14, 23)
        for d in errors
    )
    assert LockfileParser(path).parse() == {"foo": None, "bar": None, "baz": None}
    assert path.read_bytes() == original


def test_uv_lock_large_inventory_qualifies_package_and_context_omissions(
    tmp_path, monkeypatch
):
    import json

    import depcheck.ecosystems.python.parsers.lock as locks

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
        f"[DEFAULT]\ndeps = requests>=2\n[options]\ninstall_requires = {placeholder}\nsetup_requires = {placeholder}\ntests_require = {placeholder}\n"
    )
    parsed = SetupCfgParser(path).parse_detailed()
    if valid:
        assert len(parsed.declarations) == 3
        assert {d.group for d in parsed.declarations} == {
            "runtime",
            "build",
            "dev:test",
        }
        assert all(
            d.name == "requests" and d.source.line is None for d in parsed.declarations
        )
    else:
        assert parsed.diagnostics[0].code == "manifest.invalid-setup-cfg"


def test_setup_py_positions_follow_literal_nodes_without_execution(tmp_path):
    path = tmp_path / "setup.py"
    marker = tmp_path / "executed"
    text = (
        f'open({str(marker)!r}, "w").write("unexpected")\n'
        'label = "中文"; setup(install_requires=["requests>=2",\n'
        '    "requests<3"], extras_require={"test": ["ignored>=1"],\n'
        '    "test": ["requests>=2", "pytest>=9"]},\n'
        "    setup_requires=['wheel>=0.42'], tests_require=['pytest[testing]>=8'])\n"
    )
    path.write_text(text, encoding="utf-8")
    parsed = SetupPyParser(path).parse_detailed()
    assert not parsed.diagnostics
    assert [(d.name, d.source.line) for d in parsed.declarations] == [
        ("requests", 2),
        ("requests", 3),
        ("pytest", 5),
        ("wheel", 5),
        ("requests", 4),
        ("pytest", 4),
    ]
    assert (
        parsed.declarations[0].source.column
        == text.splitlines()[1].index('"requests') + 1
    )
    assert [d.group for d in parsed.declarations] == [
        "runtime",
        "runtime",
        "dev:test",
        "build",
        "optional:test",
        "optional:test",
    ]
    assert "wheel" not in SetupPyParser(path).parse()
    assert not marker.exists()


@pytest.mark.parametrize(
    ("call", "names", "unknowns"),
    [
        ("setup(**options)", [], 1),
        (
            "setup(install_requires=['requests==2.31.0'], **options, **extra_options)",
            ["requests"],
            2,
        ),
        ("setup(**{'install_requires': ['requests==2.31.0']})", [], 1),
    ],
)
def test_setup_keyword_expansion_retains_partial_evidence_and_index_coverage(
    tmp_path, call, names, unknowns
):
    from depcheck.agent import DependencyAgentService

    path = tmp_path / "setup.py"
    marker = tmp_path / "executed"
    text = (
        f'open({str(marker)!r}, "w").write("unexpected")\n'
        "from setuptools import setup\n"
        f'label = "中文"; {call}\n'
    )
    path.write_text(text, encoding="utf-8")
    parsed = SetupPyParser(path).parse_detailed()
    assert [item.name for item in parsed.declarations] == names
    assert len(parsed.diagnostics) == unknowns
    assert all(item.code == "manifest.dynamic-setup-py" for item in parsed.diagnostics)
    assert all(item.source.line == 3 for item in parsed.diagnostics)
    assert parsed.diagnostics[0].source.column == text.splitlines()[2].index("**") + 1

    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    (bundle,) = scan.bundles
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert {d.package.name for d in bundle.declarations} == set(names)
    assert not any(
        f.code in {"dependency.missing", "dependency.unused"} for f in scan.findings
    )

    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    context = service.repository_context()
    assert context["projects"][0]["capabilities"]["manifest"]["complete"] is False
    if names:
        explanation = service.explain_dependency("requests")
        assert not explanation["evidence_complete"]
        assert len(explanation["declarations"]) == 1
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    assert not marker.exists()

    # Both roles survive a no-op refresh and then update from the same file.
    from depcheck.indexing.store import IndexStore

    with IndexStore(tmp_path, read_only=True) as store:
        assert set(store.file_digests("python")) == {"setup.py"}
        assert set(store.file_digests("manifest")) == {"setup.py"}
        assert any(item.module == "setuptools" for item in store.load_imports().imports)
    unchanged = service.index_repository()
    assert unchanged["status"] == "current"
    assert unchanged["scanned_python_files"] == unchanged["parsed_manifest_files"] == 0
    path.write_text(
        text.rsplit("\n", 2)[0] + '\nsetup(install_requires=["requests==2.32.4"])\n',
        encoding="utf-8",
    )
    refreshed = service.index_repository()
    assert refreshed["status"] == "updated"
    assert refreshed["scanned_python_files"] == refreshed["parsed_manifest_files"] == 1
    with IndexStore(tmp_path, read_only=True) as store:
        manifests = store.load_manifests()
        assert [
            (item.name, str(item.specifier)) for item in manifests.declarations
        ] == [("requests", "==2.32.4")]
        assert not manifests.diagnostics
        assert store.file_digests("python") == store.file_digests("manifest")
        assert any(item.module == "setuptools" for item in store.load_imports().imports)
    assert service.repository_context()["projects"][0]["capabilities"]["manifest"][
        "complete"
    ]
    assert not marker.exists()


def test_setup_keyword_expansion_original_scikit_learn_is_incomplete():
    import hashlib

    fixture = Path(__file__).parent / "fixtures/projects/setup-keywords"
    provenance = json.loads((fixture / "provenance.json").read_text())
    for record in provenance["files"]:
        data = (fixture / record["path"]).read_bytes()
        assert len(data) == record["bytes"]
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
    # Retained upstream source has dynamic metadata populated outside setup().
    parsed = SetupPyParser(fixture / "setup.py").parse_detailed()
    assert not parsed.declarations
    (diagnostic,) = parsed.diagnostics
    assert diagnostic.code == "manifest.dynamic-setup-py"
    assert (diagnostic.source.line, diagnostic.source.column) == (665, 11)


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
    import depcheck.ecosystems.python.parsers.pyproject as parser_module

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
    import depcheck.ecosystems.python.parsers.pyproject as parser_module

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
    from depcheck.ecosystems.python.manifest import PythonManifestCollector

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
    from depcheck.ecosystems.python.manifest import PythonManifestCollector

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
    from depcheck.ecosystems.python.parsers.pip_commands import PipInstallParser

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
    from depcheck.ecosystems.python.manifest import PythonManifestCollector

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
    tmp_path: Path, options, monkeypatch
) -> None:
    from depcheck.agent import DependencyAgentService
    from depcheck.ecosystems.python import manifest as manifests
    from depcheck.ecosystems.python.parsers import requirements as requirements_module
    from depcheck.ecosystems.python.parsers.requirements import RequirementParser
    from depcheck.output import build_cyclonedx

    manifest = tmp_path / "requirements.txt"
    manifest.write_text("-r requirements/dev.txt\n")
    nested = tmp_path / "requirements" / "dev.txt"
    nested.parent.mkdir()
    includes = "".join(f'{option} "../shared.txt"\n' for option in options)
    nested.write_text(includes + "-c ../constraints.txt\n")
    shared = tmp_path / "shared.txt"
    shared.write_text("# Original declaration position\nrequests==2.31.0\n")
    (tmp_path / "constraints.txt").write_text("-r shared.txt\nurllib3<3\n")
    assert manifests.PythonManifestCollector(tmp_path).find_dependency_file() == [
        manifest
    ]

    parsed = RequirementParser(manifest, project_root=tmp_path).parse_detailed()
    assert len(parsed.declarations) == 3
    assert not parsed.diagnostics
    assert {(item.name, item.kind, item.group) for item in parsed.declarations} == {
        ("requests", "direct", "runtime"),
        ("requests", "constraint", "runtime"),
        ("urllib3", "constraint", "runtime"),
    }
    assert [d.source.to_dict(tmp_path) for d in parsed.declarations] == [
        {"path": "shared.txt", "line": 2},
        {"path": "shared.txt", "line": 2},
        {"path": "constraints.txt", "line": 2},
    ]
    # Without caller-supplied repository authority, dev.txt cannot widen its root.
    default_root = RequirementParser(nested).parse_detailed()
    assert not default_root.declarations
    assert all(
        d.code == "manifest.include-outside-project-root"
        for d in default_root.diagnostics
    )

    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert {item.kind for item in result.bundles[0].declarations} == {
        "direct",
        "constraint",
    }
    assert [
        (r.package.name, r.version, r.direct) for r in result.bundles[0].resolved
    ] == [("requests", "2.31.0", True)]
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    record = service.explain_dependency("requests", ecosystem="PyPI")
    assert {d["kind"] for d in record["declarations"]} == {"direct", "constraint"}
    assert all(
        d["location"] == {"path": "shared.txt", "line": 2}
        for d in record["declarations"]
    )
    assert record["resolved_versions"] == ["2.31.0"]
    constraint = service.explain_dependency("urllib3", ecosystem="PyPI")
    assert constraint["resolved_versions"] == []
    assert constraint["declarations"][0]["kind"] == "constraint"
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    bom = build_cyclonedx(result)
    assert [c["name"] for c in bom["components"]] == ["requests"]
    assert bom["dependencies"][0]["dependsOn"] == [bom["components"][0]["bom-ref"]]
    shared.write_text("# Original declaration position\nrequests==2.32.0\n")
    service.index_repository()
    assert service.explain_dependency("requests", ecosystem="PyPI")[
        "resolved_versions"
    ] == ["2.32.0"]

    # Observe real reads: canonical escape rejection must happen before content I/O.
    outside = tmp_path.parent / (tmp_path.name + "-outside.txt")
    outside.write_text("outside-only==1\n")
    (nested.parent / "escape.txt").symlink_to(outside)
    original_read = requirements_module.read_text
    reads = []

    def read_inside(path, **kwargs):
        assert Path(path).resolve().is_relative_to(tmp_path.resolve())
        reads.append(Path(path).resolve())
        return original_read(path, **kwargs)

    monkeypatch.setattr(requirements_module, "read_text", read_inside)
    chain = tmp_path / "chain"
    chain.mkdir()
    for i in range(65):
        (chain / f"{i}.txt").write_text(f"-r {i + 1}.txt\n")
    nested.write_text(
        includes
        + "-c ../constraints.txt\n"
        + f"-r ../../{outside.name}\n"
        + "-r escape.txt\n-r ../requirements.txt\n"
        + f"-r {shared}\n"
        + "-r https://example.invalid/remote.txt\n-r ../chain/0.txt\n"
    )
    bounded = RequirementParser(manifest, project_root=tmp_path).parse_detailed()
    assert len(bounded.declarations) == 3
    codes = [d.code for d in bounded.diagnostics]
    assert codes.count("manifest.include-outside-project-root") == 3
    assert {
        "manifest.include-cycle",
        "manifest.include-budget",
        "manifest.include-not-found",
    } <= set(codes)
    assert outside.resolve() not in reads
    assert all(d.origin.get("public") is False for d in bounded.declarations)


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
            return JsonResponse(
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
            return JsonResponse(
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
            return JsonResponse(
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
            return JsonResponse(
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
            return JsonResponse(
                raise_for_status=lambda: None,
                json=lambda: {"results": [{"vulns": [{"id": "OSV-1"}]}]},
            )

        def get(self, *args, **kwargs):
            return JsonResponse(
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
            "npm",
            "1.0.0-beta.2+build.7",
            "ECOSYSTEM",
            [[{"introduced": "1.0.0-beta.1"}, {"fixed": "1.0.0-beta.11"}]],
            [],
            "1.0.0-beta.11",
        ),
        (
            "crates.io",
            "0.6.9",
            "ECOSYSTEM",
            [[{"introduced": "0.6.5"}, {"fixed": "0.6.10"}]],
            [],
            "0.6.10",
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
            "2.0-sp1",
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
                    return JsonResponse(
                        raise_for_status=lambda: None,
                        json=lambda: {"results": [{"vulns": [{"id": "TEST-range"}]}]},
                    )

                def get(self, *args, **kwargs):
                    return JsonResponse(
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


@pytest.mark.parametrize(
    "version,status,fix",
    [
        ("v0.16.0", "affected", "0.17.0"),
        ("0.16.0+build.7", "affected", "0.17.0"),
        ("v0.17.0-beta.2", "affected", "0.17.0"),
        ("v0.17.0", "not-affected", None),
        ("v0.17.0+incompatible", "not-affected", None),
    ],
)
def test_go_advisory_github_ecosystem_range_has_semver_precedence(version, status, fix):
    from depcheck.security.advisories import match_affected_version, parse_advisory

    detail = json.loads(
        (
            Path(__file__).parent / "fixtures/security/GHSA-4374-p667-p6c8.json"
        ).read_text()
    )
    package = "golang.org/x/net"
    assert match_affected_version(detail, package, "Go", version)[0] == status
    issue, diagnostics = parse_advisory(detail, package, "Go", version)
    assert not diagnostics
    assert issue["cve_ids"] == ["CVE-2023-39325"]
    assert issue["fix_version"] == fix
    assert issue["fix_version_status"] == ("candidate" if fix else "unknown")
    assert issue["fix_versions"] == ["0.17.0"]


@pytest.mark.parametrize(
    "listed,fix",
    [(["v1.2.0"], "v1.4.0"), (["v1.4.0+build.7"], None)],
)
def test_go_advisory_mixed_ranges_normalize_lists_and_preserve_raw_fixes(listed, fix):
    from depcheck.security.advisories import match_affected_version, parse_advisory

    ranges = [
        {
            "type": "SEMVER",
            "events": [{"introduced": "0"}, {"fixed": "1.3.0"}],
        },
        {
            "type": "ECOSYSTEM",
            "events": [{"introduced": "v1.0.0"}, {"fixed": "v1.4.0"}],
        },
    ]
    for reverse in (False, True):
        detail = {
            "id": "TEST-GO-MIXED",
            "affected": [
                {
                    "package": {"ecosystem": "Go", "name": "example.com/dep"},
                    "ranges": list(reversed(ranges)) if reverse else ranges,
                    "versions": listed,
                }
            ],
        }
        for version in ("v1.2.0+build.7", "1.2.0"):
            assert (
                match_affected_version(detail, "example.com/dep", "Go", version)[0]
                == "affected"
            )
            issue, diagnostics = parse_advisory(
                detail, "example.com/dep", "Go", version
            )
            assert not diagnostics
            assert issue["fix_version"] == fix
            assert issue["fix_version_status"] == ("candidate" if fix else "unknown")
            assert set(issue["fix_versions"]) == {"1.3.0", "v1.4.0"}


@pytest.mark.parametrize("kind,prefix", [("SEMVER", ""), ("ECOSYSTEM", "v")])
def test_go_advisory_pseudoversions_keep_timestamp_order_and_fixed_boundary(
    kind, prefix
):
    from depcheck.security.advisories import match_affected_version, parse_advisory

    fixed = prefix + "0.0.0-20200220183623-bac4c82f6975"
    detail = {
        "id": "TEST-GO-PSEUDOVERSION",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "golang.org/x/crypto"},
                "ranges": [
                    {
                        "type": kind,
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }
    for version, status in [
        ("v0.0.0-20200219234226-1ad67e1f0ef4", "affected"),
        ("v0.0.0-20200220183623-bac4c82f6975", "not-affected"),
    ]:
        assert (
            match_affected_version(detail, "golang.org/x/crypto", "Go", version)[0]
            == status
        )
        issue, diagnostics = parse_advisory(
            detail, "golang.org/x/crypto", "Go", version
        )
        assert not diagnostics
        assert issue["fix_version"] == (fixed if status == "affected" else None)
        assert issue["fix_versions"] == [fixed]


@pytest.mark.parametrize("boundary", ["v1.3", "v1.3.0-01", "go1.3.0", "vv1.3.0"])
def test_go_advisory_unsupported_native_ranges_preserve_only_positive_evidence(
    boundary,
):
    from depcheck.security.advisories import match_affected_version, parse_advisory

    detail = {
        "id": "TEST-GO-UNSUPPORTED",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "example.com/dep"},
                "versions": ["v1.0.0"],
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": boundary}],
                    },
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.0"}],
                    },
                ],
            }
        ],
    }
    for version, status in [
        ("v1.0.0", "affected"),
        ("1.0.0", "affected"),
        ("v1.1.0", "affected"),
        ("v2.0.0", "unknown"),
    ]:
        assert (
            match_affected_version(detail, "example.com/dep", "Go", version)[0]
            == status
        )
        issue, diagnostics = parse_advisory(detail, "example.com/dep", "Go", version)
        assert not diagnostics
        assert issue["fix_version_status"] == "unknown"
        assert issue["fix_versions"] == [boundary, "1.2.0"]

    detail["affected"][0]["ranges"] = [
        {
            "type": "SEMVER",
            "events": [{"introduced": "0"}, {"fixed": "v1.3.0"}],
        }
    ]
    with pytest.raises(ValueError, match="not valid SemVer"):
        match_affected_version(detail, "example.com/dep", "Go", "v1.1.0")
    issue, diagnostics = parse_advisory(detail, "example.com/dep", "Go", "v1.1.0")
    assert issue["fix_version_status"] == "unknown"
    assert diagnostics[0].code == "osv.invalid-response"


@pytest.mark.parametrize(
    "ecosystem,version,fixed",
    [("PyPI", "1.0", "2.0"), ("Go", "v1.0.0", "v2.0.0")],
)
@pytest.mark.parametrize(
    "empty_scope", ["matching", "wildcard", "package", "ecosystem"]
)
def test_osv_incomplete_fix_entries_preserve_matches_and_unrelated_coverage(
    ecosystem, version, fixed, empty_scope
):
    from depcheck.security.advisories import match_affected_version, parse_advisory

    empty_package = {
        "ecosystem": "npm" if empty_scope == "ecosystem" else ecosystem,
        "name": "*"
        if empty_scope == "wildcard"
        else "unrelated"
        if empty_scope == "package"
        else "demo",
    }
    detail = {
        "id": "TEST-INCOMPLETE-FIX",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": "demo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            },
            {"package": empty_package},
        ],
    }
    assert match_affected_version(detail, "demo", ecosystem, version)[0] == "affected"
    issue, diagnostics = parse_advisory(detail, "demo", ecosystem, version)
    assert not diagnostics
    incomplete = empty_scope in {"matching", "wildcard"}
    assert issue["fix_version"] == (None if incomplete else fixed)
    assert issue["fix_version_status"] == ("unknown" if incomplete else "candidate")
    assert issue["fix_versions"] == [fixed]
    if incomplete:
        assert "no affected-version evidence" in issue["fix_version_reason"]


@pytest.mark.parametrize("incomplete", [False, True])
def test_go_advisory_alias_groups_preserve_mixed_ranges_and_incomplete_fix(incomplete):
    from depcheck.security.advisories import group_aliases, parse_advisory

    details = {}
    issues = []
    for identifier, kind, fixed in [
        ("TEST-GO-A", "SEMVER", "1.3.0"),
        ("TEST-GO-B", "ECOSYSTEM", "v1.4.0"),
    ]:
        detail = {
            "id": identifier,
            "aliases": ["CVE-2023-39325"],
            "affected": [
                {
                    "package": {"ecosystem": "Go", "name": "example.com/dep"},
                    "versions": ["v1.2.0"],
                    "ranges": [
                        {
                            "type": kind,
                            "events": [{"introduced": "0"}, {"fixed": fixed}],
                        }
                    ],
                }
            ],
        }
        if incomplete and identifier == "TEST-GO-B":
            detail["affected"].append(
                {"package": {"ecosystem": "Go", "name": "example.com/dep"}}
            )
        issue, diagnostics = parse_advisory(detail, "example.com/dep", "Go", "v1.2.0")
        assert not diagnostics
        details[identifier] = (detail, None)
        issues.append(issue)
    for reverse in (False, True):
        grouped, diagnostics = group_aliases(
            list(reversed(issues)) if reverse else issues,
            details,
            "example.com/dep",
            "Go",
            "v1.2.0",
        )
        assert not diagnostics
        assert len(grouped) == 1
        group = grouped[0]
        assert group["advisory_ids"] == ["TEST-GO-A", "TEST-GO-B"]
        assert group["fix_version"] == (None if incomplete else "v1.4.0")
        assert group["fix_version_status"] == ("unknown" if incomplete else "candidate")
        assert group["fix_versions"] == ["1.3.0", "v1.4.0"]
        assert [issue["fix_versions"] for issue in group["advisories"]] == [
            ["1.3.0"],
            ["v1.4.0"],
        ]
        if incomplete:
            assert "no affected-version evidence" in group["fix_version_reason"]


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
            return JsonResponse(
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
            return JsonResponse(raise_for_status=lambda: None, json=lambda: detail)

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
            return JsonResponse(
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
            return JsonResponse(raise_for_status=lambda: None, json=lambda: detail)

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


def test_real_scoped_severity_corpus_preserves_ranges_scores_and_unknowns():
    from scripts.evaluate_corpus import evaluate_scoped_severity

    result = evaluate_scoped_severity(
        Path(__file__).parent / "fixtures/security/scoped"
    )
    assert result["passed"], [
        case for case in result["cases"] if case["mismatched_fields"]
    ]


def _scoped_severity_record(identifier="TEST-SEVERITY"):
    return {
        "id": identifier,
        "aliases": ["CVE-2026-12345"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Demo_Package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0"}],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize("scope", ["top", "package", "absent"])
def test_osv_scoped_severity_preserves_opaque_scores_and_source_extensions(scope):
    from depcheck.security.advisories import parse_advisory

    record = _scoped_severity_record()
    score = {
        "type": "PROVIDER_FUTURE_METHOD",
        "score": "opaque provider score",
        "source": "SELF",
        "extension": {"producer_note": "unverified assertion"},
    }
    if scope == "top":
        record["severity"] = [score]
    elif scope == "package":
        record["affected"][0]["severity"] = [score]
    issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
    assert not diagnostics
    assert issue["severity"] == ([] if scope == "absent" else [score])
    assert issue["severity_status"] == (
        "not-provided" if scope == "absent" else "reported"
    )
    assert issue["cve_ids"] == ["CVE-2026-12345"]
    assert issue["fix_version"] == "2.0"
    if scope == "absent":
        assert issue["severity_assertions"] == []
    else:
        assertion = issue["severity_assertions"][0]
        assert assertion["advisory_id"] == record["id"]
        assert assertion["field"] == (
            "/severity" if scope == "top" else "/affected/0/severity"
        )
        assert assertion["package"] == (
            None if scope == "top" else record["affected"][0]["package"]
        )
        assert assertion["applicability"] == "affected"
        assert assertion["severity"] == [score]


@pytest.mark.parametrize("unknown_scope", [False, True])
def test_osv_scoped_severity_separates_packages_versions_and_unknown_entries(
    unknown_scope,
):
    from depcheck.security.advisories import parse_advisory

    record = _scoped_severity_record()

    def score(label):
        return {"type": "PROVIDER", "score": label}

    record["affected"][0]["severity"] = [score("current")]
    record["affected"].extend(
        [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-package"},
                "versions": ["3.0"],
                "severity": [score("other-version")],
            },
            {
                "package": {"ecosystem": "PyPI", "name": "other-package"},
                "versions": ["1.0"],
                "severity": [score("other-package")],
            },
        ]
    )
    if unknown_scope:
        record["affected"].append(
            {
                "package": {"ecosystem": "PyPI", "name": "demo-package"},
                "severity": [score("unknown-version")],
            }
        )
    issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
    assert issue["severity"] == [score("current")]
    assert issue["severity_status"] == ("incomplete" if unknown_scope else "reported")
    assert [a["applicability"] for a in issue["severity_assertions"]] == [
        "affected",
        "not-affected",
        "not-affected",
        *(["unknown"] if unknown_scope else []),
    ]
    assert [a["field"] for a in issue["severity_assertions"]] == [
        f"/affected/{index}/severity" for index in range(4 if unknown_scope else 3)
    ]
    assert bool(diagnostics) is unknown_scope
    assert issue["severity_assertions"][2]["package"]["name"] == "other-package"
    assert issue["cve_ids"] == ["CVE-2026-12345"]


@pytest.mark.parametrize("raw", [None, "high", {}, [False], [{"score": "opaque"}]])
def test_osv_scoped_severity_malformed_shapes_retain_raw_and_positive_cve(raw):
    from depcheck.security.advisories import parse_advisory

    record = _scoped_severity_record()
    record["affected"][0]["severity"] = raw
    issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
    assert issue["severity"] == []
    assert issue["severity_assertions"][0]["severity"] == raw
    assert issue["severity_status"] == "incomplete"
    assert [(note.code, note.severity) for note in diagnostics] == [
        ("osv.incomplete-severity", "warning")
    ]
    assert issue["cve_ids"] == ["CVE-2026-12345"]
    assert issue["fix_version"] == "2.0"


@pytest.mark.parametrize("top", [[], [{"type": "PROVIDER", "score": "top"}]])
def test_osv_scoped_severity_conflicting_source_scopes_are_qualified(top):
    from depcheck.security.advisories import parse_advisory

    record = _scoped_severity_record()
    nested = [{"type": "PROVIDER", "score": "package"}]
    record["severity"] = top
    record["affected"][0]["severity"] = nested
    issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
    assert issue["severity"] == []
    assert issue["severity_status"] == "incomplete"
    assert [a["severity"] for a in issue["severity_assertions"]] == [top, nested]
    assert all(a["applicability"] == "unknown" for a in issue["severity_assertions"])
    assert any(note.code == "osv.incomplete-severity" for note in diagnostics)
    assert issue["fix_version"] == "2.0"


@pytest.mark.parametrize("budget", ["scores", "bytes", "work"])
def test_osv_scoped_severity_budgets_preserve_cve_and_explicit_incompleteness(budget):
    from depcheck.security.advisories import MAX_SEVERITY_BYTES, parse_advisory

    record = _scoped_severity_record()
    score = {"type": "PROVIDER", "score": "first"}
    record["affected"][0]["severity"] = [score]
    if budget == "scores":
        record["affected"][0]["severity"] = [
            {"type": "PROVIDER", "score": str(index)} for index in range(257)
        ]
    elif budget == "bytes":
        score["extension"] = "x" * MAX_SEVERITY_BYTES
    else:
        record["affected"][0].pop("ranges")
        record["affected"][0]["versions"] = ["1.0"] * 3000
        record["affected"].append(
            {
                "package": {"ecosystem": "PyPI", "name": "demo-package"},
                "versions": ["1.0"] * 1100,
                "severity": [{"type": "PROVIDER", "score": "later"}],
            }
        )
    issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
    assert issue["severity_status"] == "incomplete"
    assert issue["cve_ids"] == ["CVE-2026-12345"]
    assert any(note.code == "osv.incomplete-severity" for note in diagnostics)
    assert len(json.dumps(issue["severity_assertions"]).encode()) <= MAX_SEVERITY_BYTES
    if budget == "scores":
        assert len(issue["severity"]) == 256
        assert len(issue["severity_assertions"][0]["severity"]) == 256
        assert issue["severity_scores_omitted"] == 1
    elif budget == "bytes":
        assert issue["severity"] == issue["severity_assertions"] == []
        assert issue["severity_assertions_omitted"] == 1
    else:
        assert issue["severity"] == [score]
        assert issue["severity_assertions"][1]["applicability"] == "unknown"
        assert "budget" in issue["severity_assertions"][1]["reason"]
        assert any(note.code == "osv.invalid-response" for note in diagnostics)


def test_osv_scoped_severity_alias_projection_is_bounded_and_retains_sources():
    from depcheck.security.advisories import (
        MAX_SEVERITY_BYTES,
        group_aliases,
        parse_advisory,
    )

    details, issues = {}, []
    for index in range(20):
        record = _scoped_severity_record(f"TEST-{index:02d}")
        record["severity"] = [
            {"type": "PROVIDER", "score": f"{index}:{score}"} for score in range(256)
        ]
        issue, diagnostics = parse_advisory(record, "demo-package", "PyPI", "1.0")
        assert not diagnostics
        details[record["id"]] = (record, None)
        issues.append(issue)
    canonical = None
    for ordered in (issues, list(reversed(issues))):
        groups, diagnostics = group_aliases(
            ordered, details, "demo-package", "PyPI", "1.0"
        )
        assert len(groups) == 1
        group = groups[0]
        assert group["severity_status"] == "incomplete"
        assert len(group["severity"]) == 4096
        assert group["severity_scores_omitted"] == 1024
        assert group["severity_effective_omitted"] == 1024
        assert (
            len(json.dumps(group["severity_assertions"]).encode()) <= MAX_SEVERITY_BYTES
        )
        assert len(group["advisories"]) == 20
        assert all(len(source["severity"]) == 256 for source in group["advisories"])
        assert any(note.code == "osv.severity-group-incomplete" for note in diagnostics)
        serialized = json.dumps(group, sort_keys=True)
        canonical = canonical or serialized
        assert serialized == canonical


def test_osv_alias_groups_are_transitive_order_independent_and_preserve_conflicts():
    import itertools
    import json

    import requests

    class Session:
        order = ("TEST-A", "TEST-B", "TEST-C", "TEST-D")
        phase = 0

        def post(self, *args, **kwargs):
            return JsonResponse(
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
            return JsonResponse(raise_for_status=lambda: None, json=lambda: detail)

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
            return JsonResponse(
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
            return JsonResponse(
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
            return JsonResponse(
                raise_for_status=lambda: None,
                json=lambda: {
                    "results": [{"vulns": [{"id": name}]} for name in assertions]
                },
            )

        def get(self, url, **kwargs):
            identifier = url.rsplit("/", 1)[-1]
            if identifier == "CVE-2026-99999":
                raise requests.ConnectionError("unavailable source")
            return JsonResponse(
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


@pytest.mark.parametrize("target", ["3.11", "3.15"])
def test_python315_target_keeps_independent_lock_markers(target):
    from depcheck.ecosystems.python.collector import filter_python_manifest
    from depcheck.model import ManifestParseResult

    source = SourceLocation(Path("requirements.txt"))
    direct = PythonRequirement.from_requirement(
        'urllib3==1; python_version < "3.12"', source=source
    )
    locked = PythonRequirement.from_requirement(
        "urllib3==2.2.0", source=source, kind="locked"
    )
    conditional = PythonRequirement.from_requirement(
        'urllib3==1.26.18; python_version < "3.12"',
        source=source,
        kind="locked",
    )
    filtered = filter_python_manifest(
        ManifestParseResult(declarations=(direct, locked, conditional)), target
    )
    assert filtered.declarations == (
        (direct, locked, conditional) if target == "3.11" else (locked,)
    )
    assert not filtered.diagnostics


@pytest.mark.parametrize("target", ["3.11", "3.15"])
def test_python315_target_preserves_transitive_lock_security_and_index(
    tmp_path, target
):
    from depcheck.agent import DependencyAgentService

    (tmp_path / ".depcheck.toml").write_text(f'python-version = "{target}"\n')
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="demo"\nversion="1"\ndependencies=['
        "'requests==2.31.0', 'urllib3==2.2.0; python_version < \"3.12\"']\n"
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="requests"\nversion="2.31.0"\n'
        'source={registry="https://pypi.org/simple"}\n'
        'dependencies=[{name="urllib3"}]\n'
        '[[package]]\nname="urllib3"\nversion="2.2.0"\n'
        'source={registry="https://pypi.org/simple"}\n'
    )
    # The target is controlled; the advisory is the retained publisher snapshot.
    advisory = json.loads(
        (
            Path(__file__).parent / "fixtures/projects/multilingual/advisories/"
            "GHSA-34jh-p97f-mpxf.json"
        ).read_text()
    )
    queries = []

    class Session:
        def post(self, url, *, json, **kwargs):
            queries.extend(json["queries"])
            return JsonResponse(
                json=lambda: {
                    "results": [
                        {"vulns": [{"id": advisory["id"]}]}
                        if query["package"]["name"] == "urllib3"
                        else {}
                        for query in json["queries"]
                    ]
                }
            )

        def get(self, url, **kwargs):
            assert url.endswith(advisory["id"])
            return JsonResponse(json=lambda: advisory)

    result = RepositoryScanner(osv_client=OSVClient(session=Session())).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    (bundle,) = result.bundles
    resolved = {item.package.name: item for item in bundle.resolved}
    assert {name: item.version for name, item in resolved.items()} == {
        "requests": "2.31.0",
        "urllib3": "2.2.0",
    }
    (link,) = resolved["requests"].dependency_links
    assert link.instance_id == resolved["urllib3"].instance_id
    assert not any(
        d.code == "resolution.python-lock-edges-unknown" for d in result.diagnostics
    )
    direct = {
        item.package.name for item in bundle.declarations if item.kind == "direct"
    }
    assert ("urllib3" in direct) == (target == "3.11")
    assert any(
        query["package"]["name"] == "urllib3" and query["version"] == "2.2.0"
        for query in queries
    )
    assert any(
        identity.name == "urllib3" and issues[0]["id"] == advisory["id"]
        for identity, issues in result.vulnerabilities.items()
    )

    service = DependencyAgentService(tmp_path)
    service.index_repository()
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    explanation = service.explain_dependency(
        "urllib3", project_id=bundle.project.project_id
    )
    assert [row["version"] for row in explanation["resolutions"]] == ["2.2.0"]
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before


def test_python_full_version_marker_uses_requested_target() -> None:
    from depcheck.ecosystems.python.collector import filter_python_manifest
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
    from depcheck.filesystem import ProjectPathError

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
    from depcheck.ecosystems.python.imports import ImportScanner

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

    from depcheck.filesystem.positions import SourcePositions

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

    from depcheck.ecosystems.python.imports import ImportScanner
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
    from depcheck.ecosystems.python.collector import filter_python_manifest
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
        ("Maven", "1.0", {"versions": ["1.0-final"]}, [], "affected"),
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
        "maven-normalized-equality",
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


@pytest.mark.parametrize(
    "option",
    [
        "--index-url https://private.example/simple",
        "--pre --extra-index-url https://private.example/simple",
        "--trusted-host private.example --index https://private.example/simple",
        "--extra-index=https://private.example/simple",
        "--extra-index-url=https://pypi.org/simple",
        "--no-index",
        "-f./wheels",
        "-ihttps://user:dummy-secret@pypi.org/simple",
    ],
)
def test_requirements_source_context_survives_include_dedup(tmp_path, option):
    import json

    from depcheck.ecosystems.python.manifest import PythonManifestCollector

    (tmp_path / "requirements-base.txt").write_text("secret==1\nsecret==1\n")
    (tmp_path / "requirements.txt").write_text(f'-r"requirements-base.txt"\n{option}\n')
    collected = PythonManifestCollector(tmp_path).collect()
    assert len(collected.declarations) == 2
    assert all(item.origin.get("public") is False for item in collected.declarations)

    def unexpected(*args, **kwargs):
        pytest.fail("private requirement reached public OSV")

    result = RepositoryScanner(osv_client=SimpleNamespace(scan=unexpected)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert not result.capability("security").complete
    assert all(
        item.package.purl is None
        for bundle in result.bundles
        for item in bundle.resolved
    )
    assert "dummy-secret" not in json.dumps(result.to_dict())


def test_setup_cfg_interpolation_has_one_shared_preallocation_budget(tmp_path):
    path = tmp_path / "setup.cfg"
    path.write_text(
        "[DEFAULT]\na = "
        + "x" * 1024
        + "\nb = "
        + "%(a)s" * 100
        + "\nc = "
        + "%(b)s" * 100
        + "\n[options]\ninstall_requires = %(c)s\n"
    )
    result = SetupCfgParser(path).parse_detailed()
    assert not result.declarations
    assert [item.code for item in result.diagnostics] == ["manifest.invalid-setup-cfg"]
    assert "budget" in result.diagnostics[0].message
    path.write_text(
        "[DEFAULT]\ndeps = requests>=2\n[options]\ninstall_requires = %(deps)s\n[options.extras_require]\ntest = pytest>=8\n"
    )
    legitimate = SetupCfgParser(path).parse_detailed()
    assert {item.name for item in legitimate.declarations} == {"requests", "pytest"}

    # Each field fits separately; their combined expansion must share one budget.
    path.write_text(
        "[DEFAULT]\na = "
        + "x" * 1024
        + "\nb = "
        + "%(a)s" * 100
        + "\n[options]\ninstall_requires = "
        + "%(b)s" * 5
        + "\nsetup_requires = "
        + "%(b)s" * 5
        + "\ntests_require = "
        + "%(b)s" * 5
        + "\n"
    )
    shared = SetupCfgParser(path).parse_detailed()
    assert not shared.declarations
    assert [d.code for d in shared.diagnostics] == ["manifest.invalid-setup-cfg"]
    assert "budget" in shared.diagnostics[0].message


def test_python_source_credentials_do_not_enter_reports_or_indexes(tmp_path):
    import json

    from depcheck.agent import DependencyAgentService
    from depcheck.evidence.origins import PipenvSources, python_origin

    secret = "DUMMY_ONLY_CREDENTIAL"
    url = f"https://user:{secret}@pypi.org/simple?token={secret}"
    origin = python_origin({"registry": url})
    assert origin["public"] is False
    assert secret not in json.dumps(origin)
    assert secret not in json.dumps(
        PipenvSources([]).origin({"git": url, "ref": "main"})
    )
    (tmp_path / "requirements.txt").write_text(f"demo @ {url}\ninvalid ! {url}\n")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert secret not in json.dumps(result.to_dict())
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert secret not in json.dumps(service.query_dependencies())
    assert secret.encode() not in (tmp_path / ".depcheck/index.sqlite3").read_bytes()


@pytest.mark.parametrize("stage", ["query", "detail"])
@pytest.mark.parametrize("extension", [b"1e400", b'"\\ud800"'])
def test_strict_json_osv_rejects_unrepresentable_fields_and_closes_responses(
    stage, extension
):
    responses = []

    class Response(JsonResponse):
        def iter_content(self, chunk_size):
            yield self.raw

    def response(raw):
        item = Response(json=lambda: None)
        item.raw = raw
        responses.append(item)
        return item

    class Session:
        def post(self, *args, **kwargs):
            return response(
                b'{"extension":' + extension + b',"results":[{"vulns":[]}]}'
                if stage == "query"
                else b'{"results":[{"vulns":[{"id":"TEST-STRICT"}]}]}'
            )

        def get(self, *args, **kwargs):
            return response(
                b'{"id":"TEST-STRICT","affected":[],"extension":' + extension + b"}"
            )

    result = OSVClient(session=Session()).scan({"demo": "1.0.0"})
    assert not result.complete
    assert any(d.code == "osv.invalid-response" for d in result.diagnostics)
    assert all(item.closed for item in responses)
    if stage == "detail":
        assert result.vulnerabilities["demo"][0]["id"] == "TEST-STRICT"


def test_osv_streaming_bounds_redirects_and_owned_response_cleanup(monkeypatch):
    import depcheck.security.osv_client as module

    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 64)

    class Response(JsonResponse):
        def iter_content(self, chunk_size):
            yield b"x" * 65

    response = Response(json=lambda: {})

    class Session:
        def post(self, *args, **kwargs):
            assert kwargs["stream"] is True
            assert kwargs["allow_redirects"] is False
            return response

    client = OSVClient(session=Session())
    assert not client.scan({"demo": "1"}).complete
    assert response.closed
    response.status_code = 302
    result = client.scan({"demo": "1"})
    assert "redirect" in result.diagnostics[0].message
    assert response.closed


def test_uv_nested_source_credentials_are_redacted_before_retention(tmp_path):
    import json

    from depcheck.agent import DependencyAgentService

    secret = "DUMMY_UV_NESTED_SECRET"
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["demo==1"]\n'
    )
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="demo"\nversion="1"\nsource={registry="https://pypi.org/simple"}\ndependencies=[{name="child", source={registry="https://user:'
        + secret
        + '@private.example/simple"}}]\n'
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert result.bundles[0].resolved
    assert secret not in json.dumps(result.to_dict())
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert secret not in json.dumps(service.query_dependencies())
    assert secret.encode() not in (tmp_path / ".depcheck/index.sqlite3").read_bytes()


def test_osv_interpretation_has_a_semantic_record_budget(monkeypatch):
    import depcheck.security.osv_client as module
    from depcheck.profiling import capture_profile

    monkeypatch.setattr(module, "MAX_ADVISORY_RECORDS", 3)

    class Session:
        gets = 0

        def post(self, *args, **kwargs):
            return JsonResponse(
                json=lambda: {
                    "results": [{"vulns": [{"id": f"TEST-{i}"} for i in range(100)]}]
                }
            )

        def get(self, url, **kwargs):
            self.gets += 1
            return JsonResponse(
                json=lambda: {"id": url.rsplit("/", 1)[-1], "affected": []}
            )

    session = Session()
    client = OSVClient(session=session)
    with capture_profile() as profile:
        results = [
            client.scan_ecosystem({"demo": "1"}, ecosystem)
            for ecosystem in ("PyPI", "npm")
        ]
    assert session.gets == 6
    for result in results:
        assert not result.complete
        assert any(
            item.code == "osv.interpretation-budget" for item in result.diagnostics
        )
    assert profile["security.osv-scan"]["calls"] == 2
    assert profile["osv.work"]["scan_calls"] == 2
    assert profile["osv.work"]["input_coordinates"] == 2
    assert profile["osv.work"]["batch_calls"] == 2
    assert profile["osv.work"]["batch_coordinates"] == 2
    assert profile["osv.work"]["request_attempts"] == 8
    assert profile["osv.work"]["response_bytes"] > 0


def test_private_constraint_source_qualifies_public_lock_assertions(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="app"\nversion="1"\ndependencies=["demo==1"]\n'
    )
    (tmp_path / "requirements.txt").write_text(
        "-c constraints.txt\n--index-url https://private.example/simple\n"
    )
    (tmp_path / "constraints.txt").write_text("demo==1\n")
    (tmp_path / "uv.lock").write_text(
        'version=1\n[[package]]\nname="demo"\nversion="1"\nsource={registry="https://pypi.org/simple"}\n'
    )

    def unexpected(*args, **kwargs):
        pytest.fail("Private constraint source reached public OSV")

    result = RepositoryScanner(osv_client=SimpleNamespace(scan=unexpected)).scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert result.bundles[0].resolved
    assert all(item.package.purl is None for item in result.bundles[0].resolved)
    assert not result.capability("security").complete
