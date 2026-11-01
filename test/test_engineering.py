"""Filesystem safety, index integrity, work accounting, and scorer contracts."""

import copy
import hashlib
import json
import os
import runpy
import shutil
import sqlite3
import subprocess
import sys
import tomllib
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from depcheck.agent import DependencyAgentService
from depcheck.config import ConfigurationError, load_project_config
from depcheck.ecosystems.analysis import EvidenceAnalyzer
from depcheck.ecosystems.python.imports import ImportScanner
from depcheck.ecosystems.python.manifest import PythonManifestCollector
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.filesystem import ProjectPathError, read_bytes, require_within_project
from depcheck.indexing import RepositoryIndex, RepositoryIndexer
from depcheck.indexing.models import INDEX_SCHEMA
from depcheck.indexing.store import IndexStore
from depcheck.model import CapabilityState
from scripts.benchmark_monorepo import _stable_index

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "filename", ["package.json", "package-lock.json", "LICENSE.txt"]
)
def test_project_corpus_rejects_changed_original_inputs(tmp_path, filename):
    from scripts.evaluate_corpus import evaluate_projects

    corpus = tmp_path / "projects"
    shutil.copytree(ROOT / "test/fixtures/projects", corpus)
    (corpus / "lodash-4.17.20" / filename).write_bytes(b"changed")
    with pytest.raises(ValueError, match="Corpus digest mismatch"):
        evaluate_projects(corpus, ROOT / "test/fixtures/security")


@pytest.mark.parametrize("fault", ["lost", "repeated", "nonadvancing", "digest"])
def test_project_corpus_rejects_incomplete_transport_observations(monkeypatch, fault):
    from scripts.evaluate_corpus import evaluate_projects

    original = DependencyAgentService.reevaluate_vulnerabilities

    def broken_page(self, *args, **kwargs):
        page = original(self, *args, **kwargs)
        if fault == "lost":
            page["observations"].pop()
        elif fault == "repeated":
            page["observations"][1] = page["observations"][0]
        elif fault == "nonadvancing":
            page["next_offset"] = kwargs["offset"]
        elif kwargs["offset"]:
            page["inventory"]["sha256"] = "changed"
        return page

    monkeypatch.setattr(
        DependencyAgentService, "reevaluate_vulnerabilities", broken_page
    )
    with pytest.raises(ValueError, match="Project corpus"):
        evaluate_projects(
            ROOT / "test/fixtures/projects", ROOT / "test/fixtures/security"
        )


@pytest.mark.parametrize("fault", ["empty-cases", "duplicate-label"])
def test_project_corpus_cannot_pass_with_missing_or_duplicated_truth(tmp_path, fault):
    from scripts.evaluate_corpus import evaluate_projects

    corpus = tmp_path / "projects"
    shutil.copytree(ROOT / "test/fixtures/projects", corpus)
    path = corpus / "truth.json"
    truth = json.loads(path.read_bytes())
    if fault == "empty-cases":
        truth["cases"] = []
    else:
        labels = truth["cases"][0]["security_labels"]
        labels.append(labels[0])
    path.write_text(json.dumps(truth))
    with pytest.raises(ValueError, match="Project corpus"):
        evaluate_projects(corpus, ROOT / "test/fixtures/security")


@pytest.mark.parametrize(
    "fault",
    [
        "changed-lock",
        "missing-configuration",
        "extra-file",
        "empty-cases",
        "empty-overrides",
    ],
)
def test_multilingual_corpus_rejects_unpinned_or_empty_inputs(tmp_path, fault):
    from scripts.evaluate_corpus import _multilingual_inputs

    corpus = tmp_path / "multilingual"
    shutil.copytree(ROOT / "test/fixtures/projects/multilingual", corpus)
    if fault == "changed-lock":
        (corpus / "poetry-1.8.3/poetry.lock").write_text("changed")
    elif fault == "extra-file":
        (corpus / "poetry-1.8.3/extra.toml").write_text("new=true\n")
    elif fault == "empty-cases":
        path = corpus / "truth.json"
        document = json.loads(path.read_bytes())
        document["cases"] = []
        path.write_text(json.dumps(document))
    elif fault == "empty-overrides":
        path = corpus / "truth.json"
        document = json.loads(path.read_bytes())
        case = next(row for row in document["cases"] if row["id"] == "wezterm-20220624")
        case["cargo_override_labels"]["lock_projection_labels"] = []
        path.write_text(json.dumps(document), encoding="utf-8")
    else:
        path = corpus / "provenance.json"
        document = json.loads(path.read_bytes())
        omitted = next(
            entry
            for entry in document["retained_fixtures"]
            if "/.cargo/" in entry["path"]
        )
        document["retained_fixtures"].remove(omitted)
        path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="Corpus digest mismatch|Multilingual corpus"):
        _multilingual_inputs(corpus)


@pytest.mark.parametrize(
    "fault",
    [
        "public-git",
        "repeated-row",
        "wrong-lock-path",
        "missing-member",
        "missing-view-lock-row",
        "uv-member-without-own-lock",
        "python-false-directness",
        "python-lost-binding-status",
    ],
)
def test_multilingual_inventory_gate_rejects_self_consistent_wrong_evidence(
    tmp_path, fault
):
    from dataclasses import replace
    from depcheck.model import (
        EvidenceBundle,
        PackageRef,
        ProjectUnit,
        ResolvedDependency,
        ScanResult,
        SourceLocation,
    )
    from scripts.evaluate_corpus import _multilingual_inventory

    python = fault in {
        "uv-member-without-own-lock",
        "python-false-directness",
        "python-lost-binding-status",
    }
    ecosystem, manager = ("PyPI", "python") if python else ("Cargo", "cargo")
    manifest = "pyproject.toml" if python else "Cargo.toml"
    lock = "uv.lock" if python else "Cargo.lock"
    source = None if python else "git+https://example.invalid/foo#" + "a" * 40
    project = ProjectUnit(
        ProjectUnit.stable_id(Path("."), ecosystem, manager),
        Path("."),
        "python" if python else "rust",
        ecosystem,
        manager,
    )
    member = replace(
        project,
        project_id=ProjectUnit.stable_id(Path("member"), ecosystem, manager),
        root=Path("member"),
    )
    record = ResolvedDependency(
        project.project_id,
        PackageRef(ecosystem, "foo", "foo"),
        "1.0.0",
        SourceLocation(tmp_path / lock),
        instance_id="one",
        origin={"public": python},
        metadata={
            "package_index": 0,
            **(
                {
                    "python_kind": "lock-record",
                    "context": {"package": {}},
                    "directness_status": "unknown",
                }
                if python
                else {
                    "cargo_kind": "lock-record",
                    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                }
            ),
            "activation": "unknown",
        },
    )
    case = {
        "ecosystem": "python" if python else "cargo",
        "lock_path": lock,
        "manifest_paths": [manifest, "member/" + manifest],
        "primary_manifest_paths": [manifest, "member/" + manifest],
        "expected_lock_entries": [
            {"row_index": 0, "name": "foo", "version": "1.0.0", "source_raw": source}
        ],
        "metadata_labels": [],
        "required_edges": [],
    }
    member_records = () if python else (replace(record, project_id=member.project_id),)
    if python:
        case["python_directness_labels"] = [
            {
                "project_manifest_path": manifest,
                "lock_entry": case["expected_lock_entries"][0],
                "direct": False,
                "status": "unknown",
            }
        ]
    bundles = (
        EvidenceBundle(project, resolved=(record,)),
        EvidenceBundle(member, resolved=member_records),
    )
    # Each mutation starts from complete views. A Python member without a local
    # lock must remain a valid view without receiving the root's shared lock.
    assert not _multilingual_inventory(ScanResult(tmp_path, (), bundles=bundles), case)
    if fault == "uv-member-without-own-lock":
        return
    if fault == "python-false-directness":
        record = replace(record, direct=True)
    elif fault == "python-lost-binding-status":
        metadata = dict(record.metadata)
        metadata.pop("directness_status")
        record = replace(record, metadata=metadata)
    elif fault == "public-git":
        record = replace(record, origin={"public": True})
    elif fault == "wrong-lock-path":
        record = replace(record, source=SourceLocation(tmp_path / "nested/Cargo.lock"))
    records = (record, record) if fault == "repeated-row" else (record,)
    changed = (replace(bundles[0], resolved=records), bundles[1])
    if fault == "missing-member":
        changed = changed[:1]
    elif fault == "missing-view-lock-row":
        changed = (changed[0], replace(changed[1], resolved=()))
    mismatches = _multilingual_inventory(
        ScanResult(tmp_path, (), bundles=changed), case
    )
    required = {
        "python-false-directness": "changed-python-direct-binding:0",
        "python-lost-binding-status": "changed-python-direct-binding:0",
        "public-git": "changed-source-qualification:0",
        "repeated-row": "repeated-project-lock-occurrence:0",
        "wrong-lock-path": "unexpected-resolution-source",
        "missing-member": "selected-project-views",
        "missing-view-lock-row": "missing-project-lock-occurrences:"
        + member.project_id,
    }
    assert required[fault] in mismatches


@pytest.mark.parametrize(
    "fault",
    [
        "member-diagnostic",
        "aggregate-diagnostic",
        "wrong-root-location",
        "lost-provenance",
        "lost-directness",
        "promoted-directness",
    ],
)
def test_cargo_override_gate_rejects_lost_inheritance_and_false_directness(
    tmp_path, fault
):
    from dataclasses import replace

    from depcheck.model import (
        DependencyDeclaration,
        Diagnostic,
        EvidenceBundle,
        PackageRef,
        ProjectUnit,
        ResolvedDependency,
        ScanResult,
        SourceLocation,
        VersionConstraint,
    )
    from scripts.evaluate_corpus import _multilingual_override_mismatches

    truth = json.loads(
        (ROOT / "test/fixtures/projects/multilingual/truth.json").read_bytes()
    )
    case = next(row for row in truth["cases"] if row["id"] == "wezterm-20220624")
    labels = case["cargo_override_labels"]

    def source(location):
        return SourceLocation(
            tmp_path / location["path"], location["line"], location["column"]
        )

    notes = tuple(
        Diagnostic(
            "manifest.cargo-overrides-unsupported",
            "error",
            "Qualified root patch",
            source(entry["location"]),
        )
        for entry in labels["root_entries"]
    )
    declaration_label = labels["declaration_projection_labels"][0]
    bundles = []
    member_index = None
    for manifest in labels["project_manifest_paths"]:
        project = ProjectUnit(
            ProjectUnit.stable_id(Path(manifest).parent, "Cargo", "cargo"),
            Path(manifest).parent,
            "rust",
            "Cargo",
            "cargo",
        )
        records = tuple(
            ResolvedDependency(
                project.project_id,
                PackageRef(
                    "Cargo", label["lock_entry"]["name"], label["lock_entry"]["name"]
                ),
                label["lock_entry"]["version"],
                SourceLocation(tmp_path / "Cargo.lock"),
                instance_id="raw-" + str(label["lock_entry"]["row_index"]),
                origin={"public": False},
                metadata={
                    "package_index": label["lock_entry"]["row_index"],
                    **label["metadata"],
                },
            )
            for label in labels["lock_projection_labels"]
        )
        # This gate qualifies listed source occurrences only. A distinct direct
        # Git request with the same name is outside these override labels.
        records += (
            replace(
                records[0],
                instance_id="other-git-request",
                direct=True,
                metadata={"package_index": 9999},
            ),
        )
        declarations = ()
        if manifest == declaration_label["project_manifest_path"]:
            member_index = len(bundles)
            declarations = (
                DependencyDeclaration(
                    project.project_id,
                    PackageRef(
                        "Cargo",
                        declaration_label["package"],
                        declaration_label["package"],
                    ),
                    VersionConstraint(declaration_label["constraint_raw"], "cargo"),
                    source(declaration_label["location"]),
                    metadata={
                        "installation_name": declaration_label["installation_name"],
                        **copy.deepcopy(declaration_label["metadata"]),
                    },
                ),
            )
        bundles.append(
            EvidenceBundle(
                project, declarations=declarations, resolved=records, diagnostics=notes
            )
        )
    assert member_index is not None
    scan = ScanResult(tmp_path, (), diagnostics=notes, bundles=tuple(bundles))
    assert not _multilingual_override_mismatches(scan, case)
    member = bundles[member_index]
    if fault == "member-diagnostic":
        member = replace(member, diagnostics=())
    elif fault == "aggregate-diagnostic":
        scan = replace(scan, diagnostics=())
    elif fault == "wrong-root-location":
        member = replace(
            member,
            diagnostics=tuple(
                replace(
                    note,
                    source=SourceLocation(
                        tmp_path / declaration_label["project_manifest_path"],
                        note.source.line,
                        note.source.column,
                    ),
                )
                for note in notes
            ),
        )
    elif fault == "lost-provenance":
        declaration = member.declarations[0]
        metadata = dict(declaration.metadata)
        metadata.pop("cargo_overrides")
        member = replace(
            member, declarations=(replace(declaration, metadata=metadata),)
        )
    else:
        record = member.resolved[0]
        if fault == "lost-directness":
            metadata = dict(record.metadata)
            metadata.pop("directness_status")
            record = replace(record, metadata=metadata)
        else:
            record = replace(record, direct=True)
        member = replace(member, resolved=(record, *member.resolved[1:]))
    bundles[member_index] = member
    scan = replace(scan, bundles=tuple(bundles))
    expected = {
        "member-diagnostic": "missing-cargo-root-override-diagnostics:",
        "aggregate-diagnostic": "missing-cargo-aggregate-override-diagnostics",
        "wrong-root-location": "missing-cargo-root-override-diagnostics:",
        "lost-provenance": "changed-cargo-override-declaration:",
        "lost-directness": "changed-cargo-override-lock-projection:",
        "promoted-directness": "changed-cargo-override-lock-projection:",
    }
    assert any(
        item.startswith(expected[fault])
        for item in _multilingual_override_mismatches(scan, case)
    )


@pytest.mark.parametrize(
    "fault", ["changed-lock", "changed-license", "extra-file", "empty-truth"]
)
def test_pipenv_corpus_rejects_changed_originals_or_missing_truth(tmp_path, fault):
    from scripts.evaluate_corpus import _pipenv_inputs

    corpus = tmp_path / "pipenv"
    shutil.copytree(ROOT / "test/fixtures/projects/pipenv", corpus)
    if fault == "changed-lock":
        (corpus / "Pipfile.lock").write_bytes(b"{}")
    elif fault == "changed-license":
        (corpus / "LICENSE.txt").write_bytes(b"changed")
    elif fault == "extra-file":
        (corpus / "nested").mkdir()
        (corpus / "nested/unpinned.lock").write_bytes(b"{}")
    else:
        path = corpus / "truth.json"
        truth = json.loads(path.read_bytes())
        truth["entries"] = []
        path.write_text(json.dumps(truth), encoding="utf-8")
    with pytest.raises(ValueError, match="Corpus digest mismatch|Pipenv corpus"):
        _pipenv_inputs(corpus)


@pytest.mark.parametrize(
    "fault",
    [
        "merged-category",
        "reused-instance",
        "changed-pointer",
        "lost-condition",
        "host-activation",
        "private-public",
        "invented-edge",
    ],
)
def test_pipenv_inventory_gate_rejects_category_and_condition_corruption(
    tmp_path, fault
):
    from dataclasses import replace

    from depcheck.model import (
        EvidenceBundle,
        PackageRef,
        ProjectUnit,
        ResolvedDependency,
        ResolvedDependencyLink,
        ScanResult,
        SourceLocation,
    )
    from scripts.evaluate_corpus import _pipenv_inventory

    project = ProjectUnit(
        ProjectUnit.stable_id(Path("."), "PyPI", "python"),
        Path("."),
        "python",
        "PyPI",
        "python",
    )
    # Same package and version in different categories are two source records.
    # This independent synthetic contract never claims two installed copies.
    sources = [
        {"name": "private", "url": "https://private.invalid/simple", "verify_ssl": True}
    ]
    package = PackageRef("PyPI", "setuptools", "setuptools")
    entries = [
        {
            "row_index": index,
            "category": category,
            "name": "setuptools",
            "version_raw": "==83.0.0",
            "source_pointer": "/" + category + "/setuptools",
            "context": {
                "version": "==83.0.0",
                "markers": "python_version >= '3.10'",
                "extras": ["test"],
            },
        }
        for index, category in enumerate(("default", "develop"))
    ]
    records = [
        ResolvedDependency(
            project.project_id,
            package,
            "83.0.0",
            SourceLocation(tmp_path / "Pipfile.lock"),
            instance_id="raw-category-" + entry["category"],
            origin={"public": False},
            metadata={
                "python_kind": "lock-record",
                "lock_format": "pipfile",
                "package_index": entry["row_index"],
                "pipenv_category": entry["category"],
                "category_kind": entry["category"],
                "source_pointer": entry["source_pointer"],
                "context": {
                    "root": {"_meta": {"sources": sources}},
                    "package": entry["context"],
                },
                "conditional": True,
                "activation": "unknown",
                "dependency_status": "uncollected",
            },
        )
        for entry in entries
    ]

    def scan():
        return ScanResult(
            tmp_path, (), bundles=(EvidenceBundle(project, resolved=tuple(records)),)
        )

    assert not _pipenv_inventory(scan(), entries, sources, private=True)
    if fault == "merged-category":
        records.pop()
    elif fault == "reused-instance":
        records[1] = replace(records[1], instance_id=records[0].instance_id)
    elif fault == "private-public":
        records[0] = replace(records[0], origin={"public": True})
    elif fault == "invented-edge":
        records[0] = replace(
            records[0],
            dependency_links=(
                ResolvedDependencyLink(package, "83.0.0", records[1].instance_id),
            ),
        )
    else:
        metadata = copy.deepcopy(records[0].metadata)
        if fault == "changed-pointer":
            metadata["source_pointer"] = "/develop/setuptools"
        elif fault == "lost-condition":
            metadata["context"]["package"].pop("markers")
        else:
            metadata["activation"] = "active"
        records[0] = replace(records[0], metadata=metadata)
    required = {
        "merged-category": "pipenv-missing-lock-occurrences",
        "reused-instance": "pipenv-merged-category-occurrences",
        "changed-pointer": "pipenv-changed-lock-identity",
        "lost-condition": "pipenv-changed-lock-context",
        "host-activation": "pipenv-changed-lock-context",
        "private-public": "pipenv-source-qualification",
        "invented-edge": "pipenv-invented-dependency-graph",
    }
    assert required[fault] in _pipenv_inventory(scan(), entries, sources, private=True)


@pytest.mark.parametrize("fixture", ["GHSA-9wx4-h78v-vm56.json", "LICENSE.txt"])
def test_security_corpus_rejects_changed_upstream_bytes(tmp_path, fixture):
    from scripts.evaluate_corpus import evaluate_security

    corpus = tmp_path / "corpus"
    shutil.copytree(ROOT / "test/fixtures/security", corpus)
    (corpus / fixture).write_bytes(b"changed")
    with pytest.raises(ValueError, match="Corpus digest mismatch"):
        evaluate_security(corpus)


@pytest.mark.parametrize("fixture", ["HSEC-2026-0010.json", "LICENSE-Bitnami.txt"])
def test_scoped_severity_corpus_rejects_changed_originals(tmp_path, fixture):
    from scripts.evaluate_corpus import evaluate_scoped_severity

    corpus = tmp_path / "scoped"
    shutil.copytree(ROOT / "test/fixtures/security/scoped", corpus)
    (corpus / fixture).write_bytes(b"changed")
    with pytest.raises(ValueError, match="Corpus digest mismatch"):
        evaluate_scoped_severity(corpus)


def test_scoped_severity_corpus_detects_lost_scores_with_preserved_membership(
    monkeypatch,
):
    from scripts import evaluate_corpus

    original = evaluate_corpus.parse_advisory

    def lose_scores(*args):
        issue, diagnostics = original(*args)
        issue.update(severity=[], severity_assertions=[])
        return issue, diagnostics

    monkeypatch.setattr(evaluate_corpus, "parse_advisory", lose_scores)
    result = evaluate_corpus.evaluate_scoped_severity(
        ROOT / "test/fixtures/security/scoped"
    )
    assert not result["passed"]
    assert all(
        case["actual"]["membership"] == case["expected"]["membership"]
        for case in result["cases"]
    )
    assert all("assertions" in case["mismatched_fields"] for case in result["cases"])
    assert any("severity" in case["mismatched_fields"] for case in result["cases"])


@pytest.mark.parametrize("fault", ["false-clean", "nonadvancing-page", "lost-severity"])
def test_security_corpus_gate_detects_result_and_pagination_regressions(
    monkeypatch, fault
):
    from scripts.evaluate_corpus import evaluate_security

    original = DependencyAgentService.reevaluate_vulnerabilities

    def false_clean(self, *args, **kwargs):
        page = original(self, *args, **kwargs)
        if fault == "nonadvancing-page":
            page["next_offset"] = kwargs["offset"]
            return page
        for row in page["observations"]:
            if row["status"] == "matched":
                if fault == "lost-severity":
                    for issue in row["vulnerabilities"]:
                        issue.update(severity=[], severity_assertions=[])
                else:
                    row.update(
                        status="not-matched-in-supplied-records", vulnerabilities=[]
                    )
        return page

    monkeypatch.setattr(
        DependencyAgentService, "reevaluate_vulnerabilities", false_clean
    )
    if fault == "nonadvancing-page":
        with pytest.raises(ValueError, match="pagination changed or did not advance"):
            evaluate_security(ROOT / "test/fixtures/security")
        return
    result = evaluate_security(ROOT / "test/fixtures/security")
    assert not result["passed"]
    if fault == "lost-severity":
        assert result["true_positive"]
        assert "severity" in result["cases"][0]["mismatched_fields"]
        assert "assertion_fields" in result["cases"][0]["mismatched_fields"]
        return
    assert not result["true_positive"]
    assert "requests-2.31.0" in result["false_negative"]
    assert "status" in result["cases"][0]["mismatched_fields"]


@pytest.mark.parametrize(
    "lock_name", ["gradle.lockfile", "buildscript-gradle.lockfile"]
)
def test_gradle_lock_regular_file_requirement(tmp_path, lock_name):
    (tmp_path / "build.gradle").write_text(
        'dependencies { implementation "example:lib:1" }\n'
    )
    (tmp_path / lock_name).mkdir()
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert any(d.code == "lock.invalid" for d in result.diagnostics)
    assert not result.bundles[0].resolved
    assert (tmp_path / lock_name).is_dir()


def test_gradle_catalog_bounded_discovery_rejects_outside_aliases(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.versions.toml"
    outside.write_text('[libraries]\nsecret="outside:secret:1"\n')
    try:
        (root / "linked.versions.toml").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks are unavailable on this platform")
    (root / "libs.versions.toml").write_text('[libraries]\nreal="example:real:1"\n')
    (root / "directory.versions.toml").mkdir()
    result = RepositoryScanner().scan(root, RepositoryScanOptions(security=False))
    bundle = result.bundles[0]
    assert [d.package.name for d in bundle.declarations] == ["example:real"]
    assert bundle.project.manifests == (Path("libs.versions.toml"),)
    assert outside.read_text() == '[libraries]\nsecret="outside:secret:1"\n'


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_gradle_catalog_regular_file_requirement_rejects_fifo(tmp_path):
    os.mkfifo(tmp_path / "libs.versions.toml")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert result.bundles and not result.bundles[0].declarations
    assert any(d.code == "manifest.gradle-catalog-invalid" for d in result.diagnostics)


@pytest.mark.parametrize("relative", ["../parent", "..\\parent"])
def test_maven_parent_directory_paths_retain_local_plugin_and_dependency_evidence(
    tmp_path, relative
):
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / "pom.xml").write_text(
        "<project><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>2</version></dependency></dependencies><build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>"
        + relative
        + "</relativePath></parent><artifactId>child</artifactId></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = next(b for b in result.bundles if b.project.root == Path("child"))
    assert {d.package.name for d in bundle.declarations} == {
        "example:library",
        "org.apache.maven.plugins:maven-compiler-plugin",
    }
    assert all(d.source.path == parent / "pom.xml" for d in bundle.declarations)
    assert not any(d.code == "manifest.parent-unavailable" for d in bundle.diagnostics)


def test_maven_directory_parent_pom_symlink_does_not_read_outside_root(
    tmp_path, monkeypatch
):
    import depcheck.ecosystems.java.maven as java_maven

    audited = tmp_path / "repo"
    audited.mkdir()
    parent = audited / "parent"
    parent.mkdir()
    outside = tmp_path / "private.xml"
    outside.write_text("<project>private</project>", encoding="utf-8")
    try:
        (parent / "pom.xml").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    child = audited / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><relativePath>../parent</relativePath></parent><artifactId>child</artifactId></project>",
        encoding="utf-8",
    )
    original = java_maven.read_text

    def read(path, *args, **kwargs):
        assert path.resolve() != outside
        return original(path, *args, **kwargs)

    monkeypatch.setattr(java_maven, "read_text", read)
    result = RepositoryScanner().scan(
        audited, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.parent-path-invalid" for d in result.diagnostics)


def test_maven_xml_node_budget_precedes_dom_allocation(tmp_path, monkeypatch):
    import depcheck.ecosystems.java.maven as java_maven

    (tmp_path / "pom.xml").write_text(
        "<project>" + "<x/>" * 100001 + "</project>", encoding="utf-8"
    )
    monkeypatch.setattr(
        java_maven.ET,
        "fromstring",
        lambda *args, **kwargs: pytest.fail("DOM allocated before XML node budget"),
    )
    result = RepositoryScanner().scan(
        tmp_path,
        RepositoryScanOptions(
            security=False, compatibility=False, enabled_ecosystems=("Maven",)
        ),
    )
    assert any(
        d.code == "manifest.invalid" and "element budget" in d.message
        for d in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete


def test_json_position_limits_and_replaced_subtrees_keep_reliable_fallback(tmp_path):
    from depcheck.filesystem.positions import SourcePositions

    path = tmp_path / "manifest.json"
    ambiguous = '{"dependencies":["decoy","stale"],"dependencies":["actual"]}'
    positions = SourcePositions.json_keys(path, ambiguous, frozenset({"dependencies"}))
    assert positions.value("dependencies", 0).column == ambiguous.index('"actual"') + 1
    assert positions.value("dependencies", 1).line is None
    deep = '{"dependencies":' + "[" * 20 + '"nested"' + "]" * 20 + "}"
    positions = SourcePositions.json_keys(
        path, deep, frozenset({"dependencies"}), max_depth=100
    )
    assert positions.value("dependencies", *([0] * 20)).line is None
    large = json.dumps({"dependencies": ["package"] * 100_005})
    positions = SourcePositions.json_keys(path, large, frozenset({"dependencies"}))
    assert positions.value("dependencies", 0).line is None
    assert positions.value("dependencies", 100_004).line is None


def test_deep_json_reports_bounded_parser_failure(tmp_path):
    (tmp_path / "vcpkg.json").write_text(
        '{"dependencies":' + "[" * 2000 + '"fmt"' + "]" * 2000 + "}", encoding="utf-8"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.invalid" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize("alias_kind", ["directory", "file", "hardlink"])
def test_default_cache_alias_cannot_overwrite_project_data(tmp_path, alias_kind):
    import hashlib

    source = tmp_path / "data"
    source.mkdir()
    database = source / "index.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE valuable_data(value TEXT)")
    connection.execute("INSERT INTO valuable_data VALUES ('preserve this')")
    connection.commit()
    connection.close()
    digest = hashlib.sha256(database.read_bytes()).hexdigest()
    cache = tmp_path / ".depcheck"
    try:
        if alias_kind == "directory":
            cache.symlink_to(source, target_is_directory=True)
        else:
            cache.mkdir()
            if alias_kind == "file":
                (cache / "index.sqlite3").symlink_to(database)
            else:
                os.link(database, cache / "index.sqlite3")
    except OSError:
        pytest.skip("filesystem aliases unavailable")
    with pytest.raises(PermissionError):
        IndexStore(tmp_path)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == digest


def test_index_scan_refresh_mode_does_not_survive_full_incremental_refresh(tmp_path):

    (tmp_path / "requirements.txt").write_text("PyYAML==6.0.2\n")
    (tmp_path / "app.py").write_text("import yaml\n")
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path, ecosystems=("PyPI",))
    assert not RepositoryIndex(tmp_path).context()["stale"]
    indexer.refresh(tmp_path)
    assert not RepositoryIndex(tmp_path).context()["stale"]


@pytest.mark.parametrize(
    "filename",
    [
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "uv.lock",
        "setup.cfg",
        "setup.py",
        "Dockerfile",
    ],
)
def test_legacy_manifest_read_limit_is_qualified(tmp_path, filename):

    (tmp_path / filename).write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    result = PythonManifestCollector(tmp_path).collect()
    assert result.diagnostics and any(
        "exceeds" in d.message for d in result.diagnostics
    )
    assert not result.declarations


@pytest.mark.parametrize("filename", ["app.py", "app.ipynb"])
def test_python_source_read_limit_is_qualified(tmp_path, filename):

    (tmp_path / filename).write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    result = ImportScanner().scan_detailed(tmp_path)
    assert any("exceeds" in d.message for d in result.diagnostics)
    assert not result.imports


def test_repository_config_read_limit(tmp_path):
    (tmp_path / ".depcheck.toml").write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(ConfigurationError, match="exceeds"):
        load_project_config(tmp_path)


def test_same_handle_read_rejects_growth_and_nonregular_inputs(tmp_path, monkeypatch):
    import depcheck.filesystem as bounded_io

    path = tmp_path / "data.txt"
    path.write_bytes(b"ok")
    original = bounded_io.os.fstat
    grown = False

    def grow_after_stat(fd):
        nonlocal grown
        result = original(fd)
        if not grown and result.st_size == 2:
            grown = True
            path.write_bytes(b"x" * 33)
        return result

    monkeypatch.setattr(bounded_io.os, "fstat", grow_after_stat)
    with pytest.raises(OSError, match="exceeds"):
        bounded_io.read_bytes(path, project_root=tmp_path, max_bytes=32)
    assert grown


def test_bounded_read_does_not_follow_replaced_file(tmp_path, monkeypatch):
    import io

    from depcheck.ecosystems.static import read_text

    if os.name == "nt":
        pytest.skip("POSIX open interception; Windows uses native handles")

    root = tmp_path / "repo"
    root.mkdir()
    path = root / "manifest.json"
    path.write_text("inside")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside bytes")
    original_io = io.open
    original_os = os.open
    replaced = False

    def replace_if_target(value):
        nonlocal replaced
        if not replaced and Path(value).name == path.name:
            path.unlink()
            path.symlink_to(outside)
            replaced = True

    def intercepted_io(value, *args, **kwargs):
        replace_if_target(value)
        return original_io(value, *args, **kwargs)

    def intercepted_os(value, *args, **kwargs):
        replace_if_target(value)
        return original_os(value, *args, **kwargs)

    monkeypatch.setattr(io, "open", intercepted_io)
    monkeypatch.setattr(os, "open", intercepted_os)
    with pytest.raises((OSError, ValueError)):
        read_text(path)
    assert replaced


def _publish_generation(root, value):
    with IndexStore(root) as store, store.transaction():
        store.set_metadata({"test_generation": value})


def _assert_generation(root, value):
    cache = root / ".depcheck/index.sqlite3"
    if value is None:
        assert not cache.exists()
        return
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    with IndexStore(root, read_only=True) as store:
        assert store.metadata()["test_generation"] == value
        assert store.connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "stage",
    ["body", "commit", "serialize", "fdopen", "write", "flush", "fsync", "replace"],
)
def test_default_sqlite_faults_preserve_the_previous_generation(
    tmp_path, monkeypatch, existing, stage
):
    import depcheck.filesystem as filesystem
    import depcheck.indexing.store as storage

    if existing:
        _publish_generation(tmp_path, "old")
    cache = tmp_path / ".depcheck/index.sqlite3"
    original_cache = (
        (cache.read_bytes(), cache.stat().st_mtime_ns) if existing else None
    )
    original_connect = sqlite3.connect
    original_fdopen = os.fdopen
    armed = False
    descriptors = []

    def fail():
        raise OSError("injected " + stage + " failure")

    class Connection(sqlite3.Connection):
        def commit(self):
            if armed and stage == "commit":
                fail()
            return super().commit()

        def serialize(self, *args, **kwargs):
            if armed and stage == "serialize":
                fail()
            return super().serialize(*args, **kwargs)

    def connect(*args, **kwargs):
        return original_connect(*args, factory=Connection, **kwargs)

    class Writer:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.handle.close()

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def write(self, content):
            if stage == "write":
                self.handle.write(content[: len(content) // 2])
                fail()
            return self.handle.write(content)

        def flush(self):
            if stage == "flush":
                fail()
            return self.handle.flush()

    def fdopen(descriptor, *args, **kwargs):
        if armed:
            descriptors.append(descriptor)
            if stage == "fdopen":
                fail()
        return Writer(original_fdopen(descriptor, *args, **kwargs))

    monkeypatch.setattr(storage.sqlite3, "connect", connect)
    monkeypatch.setattr(filesystem.os, "fdopen", fdopen)
    if stage == "fsync":
        monkeypatch.setattr(filesystem.os, "fsync", lambda *_args: fail())
    if stage == "replace":
        monkeypatch.setattr(filesystem.PinnedParent, "replace", lambda *_args: fail())
    with pytest.raises(OSError, match="injected " + stage):
        with IndexStore(tmp_path) as store:
            armed = True
            with store.transaction():
                store.set_metadata({"test_generation": "new"})
                if stage == "body":
                    fail()
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    if original_cache is not None:
        assert (cache.read_bytes(), cache.stat().st_mtime_ns) == original_cache
    _assert_generation(tmp_path, "old" if existing else None)
    assert sorted(path.name for path in (tmp_path / ".depcheck").iterdir()) == (
        ["index.sqlite3"] if existing else []
    )


def test_default_sqlite_failed_commit_rolls_back_before_a_caught_retry(
    tmp_path, monkeypatch
):
    original = sqlite3.connect
    armed = False

    class Connection(sqlite3.Connection):
        def commit(self):
            if armed:
                raise sqlite3.OperationalError("injected commit failure")
            super().commit()

    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: original(*args, factory=Connection, **kwargs),
    )
    with IndexStore(tmp_path) as store:
        armed = True
        with pytest.raises(sqlite3.OperationalError, match="injected commit"):
            with store.transaction():
                store.set_metadata({"test_generation": "failed"})
        assert not store.connection.in_transaction
        assert "test_generation" not in store.metadata()
        armed = False
        with store.transaction():
            store.set_metadata({"test_generation": "retried"})
    _assert_generation(tmp_path, "retried")


def test_default_sqlite_configuration_failure_closes_its_connection(
    tmp_path, monkeypatch
):
    original = sqlite3.connect
    connections = []

    class Connection(sqlite3.Connection):
        closed = False

        def execute(self, sql, *args, **kwargs):
            if sql == "PRAGMA trusted_schema = OFF":
                raise sqlite3.OperationalError("injected configuration failure")
            return super().execute(sql, *args, **kwargs)

        def close(self):
            self.closed = True
            super().close()

    def connect(*args, **kwargs):
        connection = original(*args, factory=Connection, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    with pytest.raises(sqlite3.OperationalError, match="injected configuration"):
        IndexStore(tmp_path)
    assert connections and all(connection.closed for connection in connections)
    assert not (tmp_path / ".depcheck/index.sqlite3").exists()


def test_default_sqlite_interrupted_construction_releases_the_parent(
    tmp_path, monkeypatch
):
    from contextlib import contextmanager
    import depcheck.indexing.store as storage

    _publish_generation(tmp_path, "old")
    original = storage.pinned_parent
    released = []

    @contextmanager
    def tracked(*args, **kwargs):
        try:
            with original(*args, **kwargs) as parent:
                yield parent
        finally:
            released.append(True)

    def interrupt(*_args):
        raise KeyboardInterrupt("injected constructor interruption")

    store = IndexStore.__new__(IndexStore)
    with monkeypatch.context() as patch:
        patch.setattr(storage, "pinned_parent", tracked)
        patch.setattr(storage, "read_descriptor", interrupt)
        with pytest.raises(KeyboardInterrupt, match="injected constructor"):
            IndexStore.__init__(store, tmp_path)
        assert released == [True]
    _assert_generation(tmp_path, "old")


@pytest.mark.parametrize("existing", [False, True])
def test_default_sqlite_stale_publishers_cannot_replace_a_new_generation(
    tmp_path, existing
):
    from depcheck.filesystem import ContentChangedError

    if existing:
        _publish_generation(tmp_path, "old")
    first, second = IndexStore(tmp_path), IndexStore(tmp_path)
    try:
        for store, value in [(first, "first"), (second, "second")]:
            with store.transaction():
                store.set_metadata({"test_generation": value})
        first.close()
        with pytest.raises(ContentChangedError):
            second.close()
        _assert_generation(tmp_path, "first")
    finally:
        first.close()
        second.close()


_INDEX_PUBLICATION_WORKER = r"""
import json,sys
from pathlib import Path
from depcheck.filesystem import PinnedParent
from depcheck.indexing.store import IndexStore
root, marker, phase, generation = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
original = PinnedParent.replace

def paused(parent, source, target):
    if phase == 'after':
        original(parent, source, target)
    marker.write_text('ready')
    sys.stdin.readline()
    if phase == 'before':
        original(parent, source, target)

if phase != 'none':
    PinnedParent.replace = paused
try:
    with IndexStore(root) as store, store.transaction():
        store.set_metadata({'test_generation': generation})
except BaseException as error:
    print(json.dumps({'error_type': type(error).__name__, 'error': str(error)}))
    raise SystemExit(1)
print(json.dumps({'published': generation}))
"""


def _wait_for_publication_worker(process, marker):
    import time

    deadline = time.monotonic() + 15
    while not marker.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            pytest.fail((process.returncode, stdout, stderr))
        if time.monotonic() >= deadline:
            pytest.fail("publication worker did not reach its barrier")
        time.sleep(0.01)


@pytest.mark.parametrize("existing", [False, True])
def test_default_sqlite_overlapping_process_publications_do_not_lose_updates(
    tmp_path, existing
):
    root = tmp_path / "repo"
    root.mkdir()
    if existing:
        _publish_generation(root, "old")
    marker = tmp_path / "ready"
    arguments = [
        sys.executable,
        "-c",
        _INDEX_PUBLICATION_WORKER,
        str(root),
        str(marker),
    ]
    with subprocess.Popen(
        [*arguments, "before", "first"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as first:
        try:
            _wait_for_publication_worker(first, marker)
            second = subprocess.run(
                [*arguments, "none", "second"],
                cwd=ROOT,
                input="",
                capture_output=True,
                text=True,
                timeout=15,
            )
            assert second.returncode == 1, (second.stdout, second.stderr)
            assert json.loads(second.stdout)["error_type"] == "ContentChangedError"
            _assert_generation(root, "old" if existing else None)
            stdout, stderr = first.communicate(input="continue\n", timeout=15)
            assert first.returncode == 0, (stdout, stderr)
            _assert_generation(root, "first")
        finally:
            if first.poll() is None:
                first.kill()
                first.communicate(timeout=5)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_default_sqlite_process_termination_keeps_a_complete_generation(
    tmp_path, existing, phase
):
    root = tmp_path / "repo"
    root.mkdir()
    if existing:
        _publish_generation(root, "old")
    marker = tmp_path / "ready"
    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            _INDEX_PUBLICATION_WORKER,
            str(root),
            str(marker),
            phase,
            "new",
        ],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as worker:
        try:
            _wait_for_publication_worker(worker, marker)
            worker.kill()
            worker.communicate(timeout=5)
            _assert_generation(
                root, "new" if phase == "after" else "old" if existing else None
            )
            _publish_generation(root, "recovered")
            _assert_generation(root, "recovered")
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.communicate(timeout=5)


def test_default_sqlite_parent_replacement_cannot_publish_into_a_parked_cache(
    tmp_path, monkeypatch
):
    if os.name == "nt":
        pytest.skip("Windows pins directory names; replacement is tested on POSIX")
    from depcheck.filesystem import ContentChangedError, PinnedParent

    _publish_generation(tmp_path, "old")
    cache = tmp_path / ".depcheck"
    parked = tmp_path / "parked-cache"
    original = PinnedParent.open
    swapped = False

    def swap_before_staging(parent, name, flags, *args):
        nonlocal swapped
        if name.startswith(".depcheck-") and not swapped:
            swapped = True
            cache.rename(parked)
            cache.mkdir()
        return original(parent, name, flags, *args)

    monkeypatch.setattr(PinnedParent, "open", swap_before_staging)
    with pytest.raises(ContentChangedError, match="parent directory changed"):
        _publish_generation(tmp_path, "new")
    assert not (cache / "index.sqlite3").exists()
    assert sorted(path.name for path in parked.iterdir()) == ["index.sqlite3"]
    with IndexStore(
        tmp_path, index_path=parked / "index.sqlite3", read_only=True
    ) as store:
        assert store.metadata()["test_generation"] == "old"


@pytest.mark.skipif(os.name != "nt", reason="Native Windows publication guard")
def test_default_sqlite_windows_guard_never_deletes_existing_data(tmp_path):
    from depcheck.filesystem import ContentChangedError

    _publish_generation(tmp_path, "old")
    guard = tmp_path / ".depcheck/.depcheck-publish.lock"
    guard.write_bytes(b"preexisting data")
    with pytest.raises(ContentChangedError):
        _publish_generation(tmp_path, "new")
    assert guard.read_bytes() == b"preexisting data"
    _assert_generation(tmp_path, "old")
    guard.unlink()
    _publish_generation(tmp_path, "recovered")
    assert not guard.exists()
    _assert_generation(tmp_path, "recovered")


def test_default_sqlite_uses_private_snapshot_not_replaced_repository_path(
    tmp_path, monkeypatch
):
    original = sqlite3.connect
    outside = tmp_path / "outside.sqlite3"
    root = tmp_path / "repo"
    root.mkdir()
    with original(outside) as connection:
        connection.execute("CREATE TABLE private_data(value TEXT)")
    before = outside.read_bytes()
    connected = []

    def swap_before_sqlite(database, *args, **kwargs):
        connected.append(str(database))
        cache = root / ".depcheck" / "index.sqlite3"
        cache.parent.mkdir(exist_ok=True)
        if not cache.exists():
            cache.symlink_to(outside)
        return original(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swap_before_sqlite)
    try:
        with IndexStore(root):
            pass
    except PermissionError:
        pass
    assert outside.read_bytes() == before
    assert all(str(root / ".depcheck") not in value for value in connected)


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("temporary_parent", ["repository", "sibling"])
def test_default_sqlite_ignores_attacker_controlled_temporary_directory(
    tmp_path, monkeypatch, read_only, temporary_parent
):
    import tempfile

    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "index.sqlite3"
    with closing(sqlite3.connect(victim)) as connection, connection:
        connection.execute("CREATE TABLE valuable_data(value TEXT)")
    before = victim.read_bytes()
    with IndexStore(root):
        pass
    cache = root / ".depcheck" / "index.sqlite3"
    original_cache = cache.read_bytes()
    staging = root if temporary_parent == "repository" else tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    monkeypatch.setenv("TMPDIR", str(staging))
    monkeypatch.setenv("SQLITE_TMPDIR", str(staging))
    monkeypatch.setattr(tempfile, "tempdir", str(staging))
    factory = tempfile.TemporaryDirectory

    class RedirectedDirectory:
        def __init__(self, temporary, parked):
            self.temporary = temporary
            self.parked = parked
            self.name = temporary.name

        def cleanup(self):
            stage = Path(self.name)
            stage.unlink()
            self.parked.rename(stage)
            self.temporary.cleanup()

    def redirect_stage(*args, **kwargs):
        temporary = factory(*args, **kwargs)
        stage = Path(temporary.name)
        parked = stage.with_name(stage.name + "-parked")
        stage.rename(parked)
        stage.symlink_to(outside, target_is_directory=True)
        return RedirectedDirectory(temporary, parked)

    monkeypatch.setattr(tempfile, "TemporaryDirectory", redirect_stage)
    with IndexStore(root, read_only=read_only) as store:
        assert store.metadata()["schema"] == INDEX_SCHEMA
        temporary_storage = store.connection.execute("PRAGMA temp_store").fetchone()[0]
        if not read_only:
            store.set_metadata({"control": "persisted"})
            store.connection.commit()
    assert victim.read_bytes() == before
    assert temporary_storage == 2
    assert list(staging.iterdir()) == ([root / ".depcheck"] if staging == root else [])
    if read_only:
        assert cache.read_bytes() == original_cache
    else:
        with IndexStore(root, read_only=True) as store:
            assert store.metadata()["control"] == "persisted"


def test_default_sqlite_close_rolls_back_pending_changes(tmp_path):
    with IndexStore(tmp_path) as store:
        store.set_metadata({"committed": "yes"})
        store.connection.commit()
        store.set_metadata({"pending": "must roll back"})
    with IndexStore(tmp_path, read_only=True) as store:
        assert store.metadata()["committed"] == "yes"
        assert "pending" not in store.metadata()


@pytest.mark.parametrize("read_only", [False, True])
def test_default_sqlite_empty_cache_preserves_schema_handling(tmp_path, read_only):
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    cache.parent.mkdir()
    cache.touch()
    if read_only:
        with pytest.raises(RuntimeError, match="index schema is incompatible"):
            IndexStore(tmp_path, read_only=True)
        assert cache.read_bytes() == b""
    else:
        with IndexStore(tmp_path) as store:
            assert store.metadata()["schema"] == INDEX_SCHEMA
        assert cache.read_bytes().startswith(b"SQLite format 3\x00")


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("contents", [b"not a database", "wal"])
def test_default_sqlite_invalid_snapshot_is_not_published(
    tmp_path, read_only, contents
):
    with IndexStore(tmp_path):
        pass
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    if contents == "wal":
        original = cache.read_bytes()
        contents = original[:18] + b"\x02\x02" + original[20:]
    cache.write_bytes(contents)
    with pytest.raises(sqlite3.DatabaseError):
        IndexStore(tmp_path, read_only=read_only)
    assert cache.read_bytes() == contents


@pytest.mark.parametrize("method", ["serialize", "deserialize"])
def test_default_sqlite_requires_snapshot_support_but_explicit_paths_do_not(
    tmp_path, monkeypatch, method
):
    class WithoutSnapshots(sqlite3.Connection):
        def __getattribute__(self, name):
            return None if name == method else super().__getattribute__(name)

    connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: connect(*args, factory=WithoutSnapshots, **kwargs),
    )
    with pytest.raises(RuntimeError, match="serialize/deserialize support"):
        IndexStore(tmp_path)
    assert not (tmp_path / ".depcheck" / "index.sqlite3").exists()
    external = tmp_path.parent / (tmp_path.name + "-explicit.sqlite3")
    try:
        with IndexStore(tmp_path, external) as store:
            store.set_metadata({"control": "explicit"})
            store.connection.commit()
        with IndexStore(tmp_path, external, read_only=True) as store:
            assert store.metadata()["control"] == "explicit"
    finally:
        external.unlink(missing_ok=True)


@pytest.mark.parametrize("options", [[("TEMP_STORE=0",)], []])
def test_default_sqlite_requires_verified_memory_temporary_storage(
    tmp_path, monkeypatch, options
):
    class DiskTemporaryStorage(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "PRAGMA compile_options":
                return options
            return super().execute(sql, *args, **kwargs)

    connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: connect(*args, factory=DiskTemporaryStorage, **kwargs),
    )
    with pytest.raises(RuntimeError, match="in-memory temporary storage"):
        IndexStore(tmp_path)
    assert not (tmp_path / ".depcheck" / "index.sqlite3").exists()


def test_default_sqlite_growth_respects_snapshot_limit(tmp_path, monkeypatch):
    from depcheck.indexing import store as store_module

    with IndexStore(tmp_path):
        pass
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    limit = cache.stat().st_size
    monkeypatch.setattr(store_module, "MAX_INDEX_BYTES", limit)
    with IndexStore(tmp_path) as store:
        with pytest.raises(sqlite3.OperationalError, match="full"):
            store.connection.execute("CREATE TABLE huge(value BLOB)")
            store.connection.execute("INSERT INTO huge VALUES (zeroblob(?))", (limit,))
    assert cache.stat().st_size <= limit
    with IndexStore(tmp_path, read_only=True) as store:
        assert store.metadata()["schema"] == INDEX_SCHEMA


def test_anchored_read_rejects_parent_replacement(tmp_path, monkeypatch):

    if os.name == "nt":
        pytest.skip("POSIX open interception; Windows uses native handles")

    root = tmp_path / "repo"
    root.mkdir()
    directory = root / "nested"
    directory.mkdir()
    (directory / "input.txt").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "input.txt").write_text("outside")
    original = os.open
    changed = False

    def intercept(value, *args, **kwargs):
        nonlocal changed
        if not changed and Path(value).name == "nested":
            directory.rename(root / "old")
            directory.symlink_to(outside, target_is_directory=True)
            changed = True
        return original(value, *args, **kwargs)

    monkeypatch.setattr(os, "open", intercept)
    with pytest.raises(OSError):
        read_bytes(directory / "input.txt", project_root=root)
    assert changed


def test_regular_file_requirement_rejects_fifo_without_waiting(tmp_path):

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    pipe = tmp_path / "input"
    os.mkfifo(pipe)
    with pytest.raises(PermissionError, match="regular"):
        read_bytes(pipe, project_root=tmp_path)


def test_python_encoding_and_in_root_manifest_alias_still_work(tmp_path):

    (tmp_path / "app.py").write_bytes(
        b"# coding: latin-1\n# caf\xe9\nimport requests\n"
    )
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfimport requests\n")
    result = ImportScanner().scan_detailed(tmp_path)
    assert len(result.imports) == 2 and not result.diagnostics
    actual = tmp_path / "data"
    actual.mkdir()
    (actual / "deps.txt").write_text("requests==2.31.0\n")
    try:
        (tmp_path / "requirements.txt").symlink_to(actual / "deps.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    manifest = PythonManifestCollector(tmp_path).collect()
    assert any(d.name == "requests" for d in manifest.declarations)
    assert not manifest.diagnostics


def test_sqlite_rebuild_cannot_follow_repository_journal_links(tmp_path):
    root = tmp_path / "repo"
    cache = root / ".depcheck"
    cache.mkdir(parents=True)
    database = cache / "index.sqlite3"
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO metadata VALUES ('schema', 'old')")
    outside = tmp_path / "private.bin"
    outside.write_bytes(b"keep this outside data")
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            (cache / (database.name + suffix)).symlink_to(outside)
        except OSError:
            pytest.skip("symlinks unavailable")
    with IndexStore(root) as store:
        assert store.rebuilt
    assert outside.read_bytes() == b"keep this outside data"


def test_preview_limits_preserve_crlf_and_block_oversized_targets(tmp_path):
    from depcheck.compatibility.pyproject_updater import PyprojectUpdater
    from depcheck.compatibility.safe_updater import RequirementsUpdater

    requirements = tmp_path / "requirements.txt"
    requirements.write_bytes(b"requests==1\r\n")
    plan = RequirementsUpdater(tmp_path).plan(requirements, {"requests": "2"})
    assert plan.updated_content == "requests==2\r\n"
    requirements.write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds"):
        RequirementsUpdater(tmp_path).plan(requirements, {"requests": "2"})
    project = tmp_path / "pyproject.toml"
    project.write_bytes(b"#" + b"x" * (8 * 1024 * 1024))
    with pytest.raises(OSError, match="exceeds"):
        PyprojectUpdater(tmp_path).plan(project, {"requests": "2"})


def test_explicit_symlink_repository_root_remains_supported(tmp_path):
    from depcheck.indexing.indexer import RepositoryIndexer

    root = tmp_path / "actual"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.31.0\n")
    (root / "app.py").write_text("import requests\n")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert load_project_config(alias) == load_project_config(root)
    result = RepositoryScanner().scan(alias, RepositoryScanOptions(security=False))
    assert result.root == root
    RepositoryIndexer().refresh(alias)
    assert (root / ".depcheck/index.sqlite3").is_file()


def test_bounded_read_preserves_execute_only_ancestor_access(tmp_path):

    if not hasattr(os, "O_PATH") and not hasattr(os, "O_SEARCH"):
        pytest.skip("platform has no search-only directory open")
    directory = tmp_path / "search-only"
    directory.mkdir()
    root = directory / "repo"
    root.mkdir()
    path = root / "data.txt"
    path.write_bytes(b"readable control")
    directory.chmod(0o111)
    try:
        assert path.read_bytes() == b"readable control"
        assert read_bytes(path, project_root=root) == b"readable control"
    finally:
        directory.chmod(0o700)


def test_windows_atomic_write_has_no_pathname_chmod(tmp_path, monkeypatch):
    from depcheck.filesystem import atomic_write

    if os.name != "nt":
        pytest.skip("native Windows file attribute contract")
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"requests==1\r\n")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"preserve outside data")
    outside.chmod(0o444)
    original = os.chmod

    def swap_before_chmod(target, mode, *args, **kwargs):
        if Path(target).name.startswith(".depcheck-"):
            Path(target).unlink()
            os.link(outside, target)
        return original(target, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", swap_before_chmod)
    try:
        atomic_write(path, b"requests==2\r\n", project_root=tmp_path)
        assert path.read_bytes() == b"requests==2\r\n"
        assert not outside.stat().st_mode & 0o222
        assert outside.read_bytes() == b"preserve outside data"
    finally:
        original(outside, 0o600)


@pytest.mark.parametrize(
    "path,inside,relative",
    [
        (r"c:\repo\child\file.py", True, "child/file.py"),
        (r"C:\repo-other\file.py", False, None),
        (r"D:\repo\file.py", False, None),
    ],
)
def test_path_boundary_optimization_preserves_windows_drive_and_case_rules(
    monkeypatch, path, inside, relative
):
    import ntpath
    from pathlib import PureWindowsPath

    from depcheck.ecosystems import static
    from depcheck.indexing import fingerprints

    class ResolvedWindowsPath(PureWindowsPath):
        def resolve(self):
            return self

    win_os = SimpleNamespace(path=ntpath)
    monkeypatch.setattr(static, "os", win_os)
    monkeypatch.setattr(fingerprints, "os", win_os)
    monkeypatch.setattr(fingerprints, "Path", ResolvedWindowsPath)
    root = ResolvedWindowsPath(r"C:\Repo")
    candidate = ResolvedWindowsPath(path)
    assert static._inside(root, candidate) is inside
    if inside:
        assert fingerprints._relative(root, candidate) == relative
    else:
        with pytest.raises(ValueError):
            fingerprints._relative(root, candidate)


@pytest.mark.parametrize("suffix", ["nested/目录/file.py", "a b/c/file.js", "."])
def test_discovery_and_index_paths_keep_component_boundary(tmp_path, suffix):
    from depcheck.ecosystems.static import _inside
    from depcheck.indexing.indexer import _relative

    root = tmp_path / "repository"
    root.mkdir()
    path = root / suffix
    assert _inside(root, path)
    assert _relative(root, path) == Path(suffix).as_posix()
    outside = tmp_path / "repository-other" / "file.py"
    assert not _inside(root, outside)
    with pytest.raises(ValueError):
        _relative(root, outside)


def test_configuration_rejects_unknown_or_unsafe_values(tmp_path: Path) -> None:
    (tmp_path / ".depcheck.toml").write_text(
        'securty = false\nexcluded-directories = ["../outside"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="unknown key: securty"):
        load_project_config(tmp_path)

    (tmp_path / ".depcheck.toml").write_text(
        'excluded-directories = ["../outside"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="must contain relative"):
        load_project_config(tmp_path)


def test_tool_usage_config_is_scoped_and_validated(tmp_path: Path) -> None:
    from dataclasses import asdict

    config_path = tmp_path / ".depcheck.toml"
    valid = (
        '[[tool-usage]]\necosystem="pYpI"\nproject-id="pypi:python:."\n'
        'package="My_Tool"\nscope="test"\nreason="Runs in CI"\n'
    )
    config_path.write_text(valid)
    config = load_project_config(tmp_path)
    assert json.loads(json.dumps(asdict(config)))["tool_usage"] == [
        {
            "ecosystem": "PyPI",
            "project_id": "pypi:python:.",
            "package": "my-tool",
            "scope": "test",
            "reason": "Runs in CI",
        }
    ]
    for invalid in (
        valid + 'typo="unexpected"\n',
        valid.replace('reason="Runs in CI"', 'reason=""'),
        valid.replace('reason="Runs in CI"\n', ""),
        valid.replace('scope="test"', 'scope="all"'),
        valid.replace('package="My_Tool"', 'package="bad package"'),
        valid.replace('ecosystem="pYpI"', 'ecosystem="unknown"'),
        valid.replace('project-id="pypi:python:."', 'project-id="*"'),
        valid + valid,
        'tool-usage="ruff"\n',
        'tool-usage=["ruff"]\n',
        '[tool-usage]\npackage="ruff"\n',
    ):
        config_path.write_text(invalid)
        with pytest.raises(ConfigurationError):
            load_project_config(tmp_path)
    config_path.unlink()
    assert load_project_config(tmp_path).tool_usage == ()
    (tmp_path / "pyproject.toml").write_text("[tool.depcheck]\ntool-usage=[]\n")
    with pytest.raises(ConfigurationError, match="unknown key"):
        load_project_config(tmp_path)


def test_project_path_policy_rejects_parent_and_symlink_escape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)

    assert (
        require_within_project(
            root,
            root / "child",
            operation="read",
        )
        == (root / "child").resolve()
    )
    with pytest.raises(ProjectPathError):
        require_within_project(root, root / "escape" / "secret", operation="read")
    with pytest.raises(ProjectPathError):
        require_within_project(root, root / ".." / "outside", operation="read")


@pytest.mark.parametrize("raw", ["[]", '{"x":1e309}', '{"x":"\\ud800"}'])
def test_multilingual_cached_requirement_metadata_rejects_invalid_json(tmp_path, raw):
    from depcheck.ecosystems.python.parsers.lock import LockfileParser

    path = tmp_path / "pdm.lock"
    path.write_text('[[package]]\nname="foo"\nversion="1.0.0"\ngroups=["doc"]\n')
    parsed = LockfileParser(path).parse_detailed()
    with IndexStore(tmp_path) as store:
        with store.transaction():
            store.replace_manifests(parsed, {"pdm.lock": "test-digest"})
        assert (
            store.load_manifests().declarations[0].metadata
            == parsed.declarations[0].metadata
        )
        store.connection.execute("UPDATE declarations SET metadata_json = ?", (raw,))
        with pytest.raises(ValueError):
            store.load_manifests()


def test_index_preserves_capability_states_and_reasons(tmp_path: Path) -> None:
    from depcheck.model import Capability, EvidenceBundle, ProjectUnit

    project = ProjectUnit("example:unit:.", Path("."), "example", "example", "unit")
    states = (
        Capability("manifest", CapabilityState.COMPLETE),
        Capability("resolution", CapabilityState.INCOMPLETE, "selection unknown"),
        Capability("usage", CapabilityState.UNSUPPORTED, "usage not collected"),
        Capability("mapping", CapabilityState.SKIPPED, "disabled"),
    )
    with IndexStore(tmp_path) as store:
        with store.transaction():
            store.replace_evidence(
                (EvidenceBundle(project=project, capabilities=states),)
            )
    with IndexStore(tmp_path, read_only=True) as store:
        capabilities = store.projects()[0]["capabilities"]
    for capability in states:
        assert capabilities[capability.name] == {
            "complete": capability.complete,
            "state": capability.state.value,
            "reason": capability.reason,
        }


def test_incompatible_index_schema_is_rebuilt_as_a_cache(tmp_path: Path) -> None:
    path = tmp_path / ".depcheck" / "index.sqlite3"
    path.parent.mkdir()
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "INSERT INTO metadata VALUES ('schema', 'depcheck.index.v1');"
        "CREATE TABLE legacy_marker(value TEXT);"
    )
    connection.commit()
    connection.close()

    with IndexStore(tmp_path) as store:
        tables = {
            row[0]
            for row in store.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        metadata = store.metadata()

    assert INDEX_SCHEMA == "depcheck.index.v8"
    assert metadata["schema"] == INDEX_SCHEMA
    assert "legacy_marker" not in tables


def test_query_connections_are_read_only_and_do_not_rebuild_old_caches(
    tmp_path: Path,
) -> None:

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    path = tmp_path / ".depcheck" / "index.sqlite3"
    snapshot = path.read_bytes()
    modified_at = path.stat().st_mtime_ns
    service.repository_context()
    service.query_dependencies()
    service.explain_dependency("requests")
    service.dependency_impact("requests")
    assert path.read_bytes() == snapshot
    assert path.stat().st_mtime_ns == modified_at
    with IndexStore(tmp_path, read_only=True) as store:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            store.set_metadata({"unexpected": "mutation"})
    with IndexStore(tmp_path) as store:
        store.set_metadata({"schema": "depcheck.index.v7"})
        store.connection.commit()
    legacy_snapshot = path.read_bytes()
    with pytest.raises(RuntimeError, match="depcheck index"):
        service.repository_context()
    assert path.read_bytes() == legacy_snapshot
    service.index_repository()
    assert service.repository_context()["complete"]


def test_wheel_install_runner_rejects_missing_wheel(tmp_path: Path) -> None:

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check_wheel_install.py"),
            "--wheel",
            str(tmp_path / "missing.whl"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "Expected an existing .whl file" in result.stderr


def test_analysis_change_reparses_cached_python_usage(tmp_path: Path) -> None:
    from depcheck.model import ImportEvidence, SourceLocation

    class OldScanner(ImportScanner):
        def _scan_file_detailed(self, path, scope):
            return [ImportEvidence("obsolete", SourceLocation(path, 1), scope)], []

    (tmp_path / "app.py").write_text("import requests\n")
    RepositoryIndexer(import_scanner=OldScanner()).refresh(tmp_path)
    with IndexStore(tmp_path) as store, store.transaction():
        store.set_metadata({"config_digest": "older-analysis-semantics"})

    RepositoryIndexer().refresh(tmp_path)

    assert [item["package"] for item in RepositoryIndex(tmp_path).dependencies()] == [
        "requests"
    ]


def test_new_exclusions_remove_previously_indexed_manifests(tmp_path: Path) -> None:

    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "requirements.txt").write_text("requests==2.31.0\n")
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path)
    (tmp_path / ".depcheck.toml").write_text('excluded-directories = ["generated"]\n')
    indexer.refresh(tmp_path)
    (generated / "requirements.txt").write_text("requests==2.32.4\n")
    assert RepositoryIndex(tmp_path).context()["stale"] is False
    assert RepositoryIndex(tmp_path).dependencies() == []


@pytest.mark.parametrize("filtered", [False, True])
def test_tool_usage_scan_and_index_agree_after_config_change(
    tmp_path: Path, filtered: bool
) -> None:

    (tmp_path / "requirements.txt").write_text("ruff==0.11.0\n")
    config = tmp_path / ".depcheck.toml"
    config.write_text(
        '[[tool-usage]]\necosystem="PyPI"\nproject-id="pypi:python:."\n'
        'package="ruff"\nscope="test"\nreason="Lint"\n'
    )
    indexer = RepositoryIndexer()
    selection = {"ecosystems": ("PyPI",)} if filtered else {}
    indexer.refresh(tmp_path, **selection)
    assert indexer.refresh(tmp_path, **selection).status == "current"
    service = DependencyAgentService(tmp_path)
    explanation = service.explain_dependency("ruff")
    assert explanation["usages"][0]["kind"] == "tool"
    assert explanation["usages"][0]["mapping_confidence"] == "configured"
    assert explanation["imports"] == []
    assert explanation["imported"] is False
    assert service.dependency_impact("ruff")["usage_count"] == 1
    assert RepositoryIndex(tmp_path).context()["counts"]["import_location_count"] == 0
    assert explanation["findings"] == []
    assert (
        RepositoryScanner()
        .scan(tmp_path, RepositoryScanOptions(security=False))
        .findings
        == ()
    )
    config.unlink()
    assert RepositoryIndex(tmp_path).context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies()
    indexer.refresh(tmp_path, **selection)
    assert service.explain_dependency("ruff")["usages"] == []
    assert [f["code"] for f in service.explain_dependency("ruff")["findings"]] == [
        "dependency.unused"
    ]
    config.write_text('excluded-directories=["generated"]\n')
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "requirements.txt").write_text("other==1.0\n")
    indexer.refresh(tmp_path, **selection)
    assert [r["package"] for r in service.query_dependencies()["dependencies"]] == [
        "ruff"
    ]


def test_index_does_not_invent_a_python_project_from_cmake(tmp_path: Path) -> None:

    (tmp_path / "CMakeLists.txt").write_text("find_package(fmt REQUIRED)\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    RepositoryIndexer().refresh(tmp_path)
    indexed = RepositoryIndex(tmp_path).context()
    assert {bundle.project.project_id for bundle in result.bundles} == {
        project["project_id"] for project in indexed["projects"]
    }


@pytest.mark.parametrize("target", [".depcheck.toml", "pyproject.toml", ".depcheck"])
def test_config_and_default_index_reject_symlink_escape(
    tmp_path: Path, target: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    if target == ".depcheck":
        outside.mkdir()
    else:
        outside.write_text("security = false\n")
    (root / target).symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises(ProjectPathError):
        if target == ".depcheck":
            with IndexStore(root):
                pass
        else:
            load_project_config(root)
    if target == ".depcheck":
        assert list(outside.iterdir()) == []


def test_summary_counts_are_not_multiplied_by_other_evidence(tmp_path: Path) -> None:

    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nhttpx==0.27.0\n")
    (tmp_path / "app.py").write_text("import requests\nimport httpx\n")
    (tmp_path / "other.py").write_text("import requests\n")
    RepositoryIndexer().refresh(tmp_path)
    with IndexStore(tmp_path) as store:
        assert store.ecosystem_summary() == {
            "PyPI": {
                "project_count": 1,
                "declaration_count": 2,
                "usage_count": 3,
                "source_file_count": 2,
            }
        }


def test_python_source_discovery_does_not_read_symlink_targets(tmp_path: Path) -> None:

    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("import secret_external_module\n")
    (root / "linked.py").symlink_to(outside)
    scanner = ImportScanner()
    assert scanner.scan_detailed(root).imports == ()
    with pytest.raises(ProjectPathError):
        scanner.scan_files(root, [outside])
    RepositoryIndexer().refresh(root)
    assert RepositoryIndex(root).dependencies() == []


@pytest.mark.parametrize("probe", ["index", "companion-head", "companion-status"])
def test_metadata_commands_finish_while_caller_stdin_remains_open(tmp_path, probe):

    command = tmp_path / "metadata.py"
    command.write_text(
        "import sys\nsys.stdin.read()\n"
        "print('1234567890abcdef1234567890abcdef12345678')\n"
    )
    driver = """
import subprocess
import sys
from pathlib import Path
from depcheck.indexing import indexer
from depcheck.agent import gitnexus

root, command, probe = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
run = subprocess.run
def metadata_run(args, **kwargs):
    return run([sys.executable, command], **kwargs)
subprocess.run = metadata_run
indexer.external_path_executable = lambda *args: sys.executable
try:
    if probe == 'index':
        result = indexer._git_head(root)
    elif probe == 'companion-head':
        result = gitnexus._git_head(root, 2, executable=sys.executable)
    else:
        result = gitnexus.GitNexusCompanion(timeout=2)._run(
            (sys.executable, command), root, 'status'
        ).stdout.strip()
except subprocess.TimeoutExpired:
    result = None
print(result)
"""
    with subprocess.Popen(
        [sys.executable, "-c", driver, str(tmp_path), str(command), probe],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        # Wait before communicate() so the caller's input stays open during the probe.
        process.wait(timeout=5)
        stdout, stderr = process.communicate(timeout=2)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "1234567890abcdef1234567890abcdef12345678"


def test_release_metadata_entrypoints_and_http_identity_are_consistent() -> None:
    from depcheck import __version__
    from depcheck.compatibility.pypi_client import PyPIClient
    from depcheck.security.osv_client import OSVClient

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert metadata["scripts"]["depcheck"] == "depcheck.command:cli"
    assert metadata["license"] == "Apache-2.0"
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    for name in ("plugin.json", ".codex-plugin/plugin.json"):
        plugin = json.loads((ROOT / name).read_text())
        assert plugin["license"] == metadata["license"]
        assert plugin["version"] == metadata["version"]
    assert __version__ == metadata["version"]
    for client in (OSVClient, PyPIClient):
        assert client.DEFAULT_HEADERS["User-Agent"].startswith(
            f"depcheck/{__version__} "
        )


@pytest.mark.parametrize("relative_path", [False, True])
def test_index_and_companion_reject_git_from_target_repository(
    tmp_path: Path, monkeypatch, relative_path: bool
) -> None:
    from depcheck.agent.gitnexus import GitNexusCompanion

    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", "." if relative_path else str(tmp_path))

    def reject_execution(*args, **kwargs):
        pytest.fail("executed an untrusted repository program")

    monkeypatch.setattr("subprocess.run", reject_execution)
    RepositoryIndexer().refresh(tmp_path)
    assert GitNexusCompanion().inspect(tmp_path).current_head is None


def test_index_still_reads_git_head_using_an_external_executable(
    tmp_path: Path, monkeypatch
) -> None:
    from depcheck.filesystem import external_path_executable
    from depcheck.indexing.indexer import _git_head

    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    repository = tmp_path / "repository"
    repository.mkdir()
    monkeypatch.setenv("PATH", str(tmp_path))
    resolved = external_path_executable(repository, "git")
    assert resolved == str(executable.resolve())

    def run(args, **kwargs):
        assert args == [resolved, "-C", str(repository), "rev-parse", "HEAD"]
        return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n")

    monkeypatch.setattr("subprocess.run", run)
    assert _git_head(repository) == "a" * 40


def test_optimized_wheel_smoke_rejects_source_checkout(tmp_path: Path) -> None:

    result = subprocess.run(
        [sys.executable, "-O", str(ROOT / "scripts" / "smoke_installed.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "Expected an installed wheel" in result.stderr
    assert "exports passed" not in result.stdout


@pytest.mark.parametrize("filtered", [False, True])
@pytest.mark.parametrize("mutation", ["package", "delete", "condition", "local-delete"])
def test_package_import_change_invalidates_full_and_filtered_indexes(
    tmp_path, filtered, mutation
):

    manifest = tmp_path / "package.json"
    document = {
        "dependencies": {"lodash": "1.0.0", "other": "1.0.0"},
        "imports": {"#alias": "./util.js" if mutation == "local-delete" else "lodash"},
    }
    manifest.write_text(json.dumps(document))
    (tmp_path / "app.js").write_text("import a from '#alias';\n")
    (tmp_path / "util.js").write_text("export default 1;\n")
    selection = {"ecosystems": ("npm",)} if filtered else {}
    indexer = RepositoryIndexer()
    indexer.refresh(tmp_path, **selection)
    if mutation == "package":
        document["imports"]["#alias"] = "other"
    if mutation == "delete":
        document.pop("imports")
    if mutation == "condition":
        document["imports"]["#alias"] = {"default": "lodash"}
    if mutation == "local-delete":
        (tmp_path / "util.js").unlink()
    else:
        manifest.write_text(json.dumps(document))
    assert RepositoryIndex(tmp_path).context()["stale"]
    service = DependencyAgentService(tmp_path)
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies()
    indexer.refresh(tmp_path, **selection)
    context = RepositoryIndex(tmp_path).context()
    assert not context["stale"]
    scan = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("npm",))
    )
    assert (
        context["projects"][0]["capabilities"]["usage"]["complete"]
        == scan.capability("dependency_hygiene").complete
    )
    assert context["projects"][0]["capabilities"]["usage"]["complete"] == (
        mutation == "package"
    )
    assert not service.explain_dependency(
        "lodash", ecosystem="npm", project_id="npm:npm:."
    )["usages"]
    explanation = service.explain_dependency(
        "other", ecosystem="npm", project_id="npm:npm:."
    )
    assert bool(explanation["usages"]) == (mutation == "package")
    assert {
        (f["code"], f["package"]) for f in RepositoryIndex(tmp_path).findings()
    } == {(f.code, f.package.name) for f in scan.findings}


@pytest.mark.parametrize("ecosystem", ["PyPI", "npm"])
def test_benchmark_mutation_preserves_rebuild_equivalence(
    tmp_path, ecosystem, monkeypatch
):
    monkeypatch.setitem(sys.modules, "resource", None)
    benchmark = runpy.run_path(str(ROOT / "scripts/benchmark_monorepo.py"))

    benchmark["build_fixture"](
        tmp_path, projects=1, files_per_project=2, seed=1729, depth=1
    )
    result = benchmark["measure_mutation"](tmp_path, ecosystem)
    assert result["rebuild_equivalent"] is True
    assert result["ecosystem"] == ecosystem
    assert result["status"] == "updated"
    assert result["wall_seconds"] >= 0
    assert result["changed_reference"] == "benchmarknewpackage"
    assert result["changed_usage_detected"] is True
    assert result["counters"]["npm_parse_reuse"] == "not available"


def test_benchmark_profiles_preserve_complete_evidence():
    from scripts.benchmark_monorepo import run_benchmark

    options = dict(projects=1, files_per_project=2, seed=1729, depth=1, page_size=3)
    plain = run_benchmark(**options, profile_enabled=False)
    measured = run_benchmark(**options, profile_enabled=True)
    assert plain["fixture"] == measured["fixture"]
    assert plain["correctness"] == measured["correctness"]
    assert plain["scan"]["profile"]["phases"] == {}
    assert plain["index"]["pagination"]["profile"]["phases"] == {}
    assert measured["index"]["cold"]["profile"]["phases"]["index.refresh"]["calls"] == 1
    assert (
        measured["index"]["cold"]["profile"]["phases"]["storage.work"]["publications"]
        == 1
    )
    pages = measured["index"]["pagination"]
    phases = pages["profile"]["phases"]
    assert (
        phases["query.dependencies"]["calls"] == pages["calls_including_empty_terminal"]
    )
    assert phases["query.freshness"]["calls"] == pages["calls_including_empty_terminal"]
    assert (
        phases["storage.work"]["snapshot_reads"]
        == pages["calls_including_empty_terminal"]
    )
    assert phases["storage.work"]["snapshot_read_bytes"] > 0
    assert "publications" not in phases["storage.work"]
    assert pages["evidence_sha256"] == plain["index"]["pagination"]["evidence_sha256"]
    for result in (plain, measured):
        assert result["mutation_refresh"]["PyPI"]["rebuild_equivalent"]
        assert result["mutation_refresh"]["npm"]["rebuild_equivalent"]


@pytest.mark.parametrize("failure", ["repeated-page", "missing-page"])
def test_benchmark_rejects_incomplete_or_nonadvancing_pages(
    tmp_path, monkeypatch, failure
):
    import scripts.benchmark_monorepo as benchmark

    class Index:
        def __init__(self, root):
            pass

        def dependencies(self, **kwargs):
            return [{"package": "first"}] if failure == "repeated-page" else []

    monkeypatch.setattr(benchmark, "RepositoryIndex", Index)
    with pytest.raises(RuntimeError, match="inventory"):
        benchmark.measure_pages(
            tmp_path,
            [{"package": "first"}, {"package": "second"}],
            page_size=1,
            profile_enabled=True,
        )


@pytest.mark.parametrize("platform, expected", [("darwin", 2), ("linux", 2048)])
def test_benchmark_peak_rss_normalizes_native_units(monkeypatch, platform, expected):
    import scripts.benchmark_monorepo as benchmark

    monkeypatch.setattr(Path, "is_file", lambda self: False)
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setitem(
        sys.modules,
        "resource",
        SimpleNamespace(
            RUSAGE_SELF=0, getrusage=lambda who: SimpleNamespace(ru_maxrss=2048)
        ),
    )
    assert benchmark._peak_rss() == (expected, "getrusage")


@pytest.mark.parametrize("query", ["inventory", "explanation"])
def test_query_keeps_the_generation_checked_for_freshness(tmp_path, monkeypatch, query):
    import depcheck.indexing.indexer as indexer_module
    from depcheck.profiling import capture_profile

    (tmp_path / "package.json").write_text('{"dependencies":{"dep":"*"}}')
    (tmp_path / "main.js").write_text('import value from "dep";\n')
    lock = tmp_path / "package-lock.json"

    def version(value):
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"dep": "*"}},
                        "node_modules/dep": {"version": value},
                    },
                }
            )
        )
        RepositoryIndexer().refresh(tmp_path)

    version("2.0.0")
    cache = tmp_path / ".depcheck/index.sqlite3"
    other_generation = cache.read_bytes()
    version("1.0.0")
    original = indexer_module._workspace_freshness
    replacements = 0

    def replace_after_check(*args, **kwargs):
        nonlocal replacements
        result = original(*args, **kwargs)
        cache.write_bytes(other_generation)
        replacements += 1
        return result

    monkeypatch.setattr(indexer_module, "_workspace_freshness", replace_after_check)
    service = DependencyAgentService(tmp_path)

    def read():
        if query == "inventory":
            return service.query_dependencies(ecosystem="npm")["dependencies"][0]
        return service.explain_dependency("dep", ecosystem="npm")

    with capture_profile() as profile:
        record = read()
    assert replacements == 1
    assert record["resolved_versions"] == ["1.0.0"]
    assert profile["storage.work"]["snapshot_reads"] == 1
    assert "publications" not in profile["storage.work"]
    monkeypatch.setattr(indexer_module, "_workspace_freshness", original)
    after = cache.stat().st_mtime_ns
    with pytest.raises(RuntimeError, match="stale"):
        read()
    assert cache.read_bytes() == other_generation
    assert cache.stat().st_mtime_ns == after


def test_explicit_read_transaction_keeps_one_sqlite_view(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    path = tmp_path / "trusted.sqlite3"
    with IndexStore(repository, path) as store:
        with store.transaction():
            store.set_metadata({"schema": INDEX_SCHEMA, "view": "old"})
    with closing(sqlite3.connect(path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        with IndexStore(repository, path, read_only=True) as reader:
            with reader.transaction():
                assert reader.metadata()["view"] == "old"
                writer.execute("UPDATE metadata SET value='new' WHERE key='view'")
                writer.commit()
                assert reader.metadata()["view"] == "old"
            assert reader.metadata()["view"] == "new"


@pytest.mark.parametrize("filtered", [False, True])
def test_pnpm_lock_changes_invalidate_index_and_refresh_versions(tmp_path, filtered):
    import yaml

    (tmp_path / "package.json").write_text('{"dependencies":{"dep":"^1.0.0"}}')
    lock = tmp_path / "pnpm-lock.yaml"

    def write_lock(version):
        lock.write_text(
            yaml.safe_dump(
                {
                    "lockfileVersion": "9.0",
                    "importers": {
                        ".": {
                            "dependencies": {
                                "dep": {"specifier": "^1.0.0", "version": version}
                            }
                        }
                    },
                    "packages": {
                        f"dep@{version}": {"resolution": {"integrity": "sha512-test"}}
                    },
                    "snapshots": {f"dep@{version}": {}},
                }
            )
        )

    write_lock("1.0.0")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ("npm",)} if filtered else {}
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    write_lock("1.1.0")
    assert service.repository_context()["stale"]
    with pytest.raises(RuntimeError, match="stale"):
        service.query_dependencies("dep")
    assert service.index_repository(**selection)["status"] == "updated"
    assert service.query_dependencies("dep")["dependencies"][0][
        "resolved_versions"
    ] == ["1.1.0"]
    assert not service.repository_context()["stale"]


def test_unsupported_yarn_lock_addition_invalidates_full_index(tmp_path):

    (tmp_path / "package.json").write_text("{}")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    (tmp_path / "yarn.lock").write_text("# yarn lock\n")
    assert service.repository_context()["stale"]
    assert service.index_repository()["status"] == "updated"
    assert not service.repository_context()["stale"]
    project = service.repository_context()["projects"][0]
    assert not project["capabilities"]["resolution"]["complete"]


def test_filtered_queries_reuse_evidence_and_revalidate_ownership_changes(
    tmp_path, monkeypatch
):
    from depcheck.engine import RepositoryScanner

    for name in ("one", "two"):
        project = tmp_path / name
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"lib":"1.0.0"}}')
        (project / "app.js").write_text('import "lib";\n')
    RepositoryIndexer().refresh(tmp_path, project_ids=("npm:npm:one",))
    index = RepositoryIndex(tmp_path)
    before = index.index_path.read_bytes()
    original_scan = RepositoryScanner.scan
    calls = []

    def scan(self, *args, **kwargs):
        calls.append(1)
        return original_scan(self, *args, **kwargs)

    monkeypatch.setattr(RepositoryScanner, "scan", scan)
    assert index.dependencies()[0]["usages"]
    assert not index.context()["stale"]
    assert calls == []
    (tmp_path / "two/app.js").write_text('import "other";\n')
    assert not index.context()["stale"]
    (tmp_path / "one/new.vue").write_text('<script>import "lib";</script>')
    assert index.context()["stale"]
    assert calls
    assert index.index_path.read_bytes() == before


def test_filtered_freshness_keeps_python_files_in_static_excluded_directories(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\nversion="1"\n')
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "app.py").write_text("import requests\n")
    RepositoryIndexer().refresh(tmp_path, ecosystems=("PyPI",))
    index = RepositoryIndex(tmp_path)
    assert not index.context()["stale"]
    (vendor / "new.py").write_text("import another\n")
    assert index.context()["stale"]


@pytest.mark.parametrize("filtered", [False, True])
def test_unsupported_frontend_component_changes_invalidate_index(tmp_path, filtered):

    (tmp_path / "package.json").write_text("{}")
    service = DependencyAgentService(tmp_path)
    selection = {"ecosystems": ("npm",)} if filtered else {}
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    (tmp_path / "Component.astro").write_text("<div>example</div>\n")
    assert service.repository_context()["stale"]
    service.index_repository(**selection)
    assert not service.repository_context()["stale"]
    project = service.repository_context()["projects"][0]
    assert project["capabilities"]["usage"]["complete"]


def test_compiled_requirements_lock_changes_invalidate_index(tmp_path):

    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["urllib3>=2"]\n')
    lock = tmp_path / "requirements-production.lock"
    lock.write_text("urllib3==2.7.0\n")
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    assert service.explain_dependency("urllib3")["resolved_version"] == "2.7.0"
    lock.write_text("urllib3==2.8.0\n")
    assert service.repository_context()["stale"]
    service.index_repository()
    assert service.explain_dependency("urllib3")["resolved_version"] == "2.8.0"


def test_command_script_scan_removes_only_the_used_candidate(tmp_path):

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"vitest": "1.0.0", "eslint": "9.0.0"},
                "scripts": {"test": "vitest run"},
            }
        )
    )
    report = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert [
        item.package.name
        for item in report.findings
        if item.code == "dependency.unused"
    ] == ["eslint"]


def _collect_command_bundle(root, ecosystem="npm", project_id=None):
    from depcheck.ecosystems import ProviderContext, create_default_registry
    from depcheck.ecosystems.configuration.commands import apply_command_usage

    registry = create_default_registry()
    projects = registry.discover(root)
    project = next(
        item
        for item in projects
        if item.ecosystem.lower() == ecosystem.lower()
        and (project_id is None or item.project_id == project_id)
    )
    pack = registry.get(ecosystem)
    bundle = pack.collector.collect(ProviderContext(root), project, pack)
    return apply_command_usage(bundle, root, projects)


def test_command_direct_collector_preserves_unused_and_does_not_execute(
    tmp_path, monkeypatch
):

    from depcheck.model import MappingConfidence

    (tmp_path / "package.json").write_text(
        '{\n"devDependencies":{"vitest":"1.0.0","eslint":"9.0.0"},\n'
        '"scripts":{"test":"vitest run"}\n}'
    )

    def no_execution(*args, **kwargs):
        raise AssertionError("static command evidence must not execute subprocesses")

    monkeypatch.setattr(subprocess, "run", no_execution)
    monkeypatch.setattr(subprocess, "Popen", no_execution)
    bundle = _collect_command_bundle(tmp_path)
    commands = [item for item in bundle.usages if item.kind == "command"]
    assert len(commands) == 1
    usage = commands[0]
    assert usage.mapped_package.name == "vitest"
    assert usage.mapping_confidence is MappingConfidence.EXACT
    assert usage.scope == "test"
    assert usage.source.path == tmp_path / "package.json"
    assert usage.source.line == 3
    assert "static" in usage.mapping_reason.lower()
    assert "execution" in usage.mapping_reason.lower()
    assert [
        item.package.name
        for item in EvidenceAnalyzer().analyze(bundle).findings
        if item.code == "dependency.unused"
    ] == ["eslint"]


@pytest.mark.parametrize(
    "command,package,scope",
    [
        ("pytest -q", "pytest", "test"),
        ("python -m ruff check .", "ruff", "test"),
        ("python3 -m mypy src", "mypy", "test"),
        ("uv run --frozen --extra test python -m pytest -q", "pytest", "test"),
        ("uv run --locked --offline --no-sync ruff check .", "ruff", "test"),
        ("sphinx-build docs out", "sphinx", "build"),
        ("mkdocs build", "mkdocs", "build"),
    ],
)
def test_command_python_workflow_literal_mapping(tmp_path, command, package, scope):
    (tmp_path / "requirements.txt").write_text(f"{package}==1.0\nother==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yml"
    workflow.write_text(f"jobs:\n  test:\n    steps:\n      - run: {command}\n")
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    usages = [item for item in bundle.usages if item.kind == "command"]
    assert len(usages) == 1
    assert usages[0].mapped_package.name == package
    assert usages[0].scope == scope
    assert usages[0].source.path == workflow
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


@pytest.mark.parametrize("runner", ["npm", "pnpm", "yarn"])
def test_command_script_references_and_installation_aliases(tmp_path, runner):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"checker": "npm:vitest@1.0.0"},
                "scripts": {
                    "test": f"{runner} run checks -- --run",
                    "checks": "vitest run",
                },
            }
        )
    )
    bundle = _collect_command_bundle(tmp_path)
    assert {item.mapped_package.name for item in bundle.usages} == {"vitest"}
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


def test_command_workflow_directory_precedence_and_nearest_npm_owner(tmp_path):
    for relative in (".", "web", "web/nested"):
        directory = tmp_path / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.json").write_text(
            '{"devDependencies":{"vitest":"1.0.0"}}'
        )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "defaults:\n  run:\n    working-directory: web\n"
        "jobs:\n  test:\n    defaults:\n      run:\n"
        "        working-directory: web/nested\n    steps:\n"
        "      - run: vitest run\n"
        "      - run: vitest run\n        working-directory: web\n"
        "  inherited:\n    steps:\n      - run: vitest run\n"
    )
    root = _collect_command_bundle(tmp_path, project_id="npm:npm:.")
    web = _collect_command_bundle(tmp_path, project_id="npm:npm:web")
    nested = _collect_command_bundle(tmp_path, project_id="npm:npm:web/nested")
    assert not root.usages
    assert len(web.usages) == 2
    assert len(nested.usages) == 1


@pytest.mark.parametrize(
    "command,code",
    [
        ("vitest && eslint .", "command.unsupported"),
        ("vitest $FLAGS", "command.unsupported"),
        ("vitest $(echo run)", "command.unsupported"),
        ("cd other\nvitest run", "command.unsupported"),
        ("uv run --directory other ruff check .", "command.unsupported"),
        ("npx vitest run", "command.unsupported"),
        ("custom-cli --check", "command.unmapped"),
        ("vitest 'unterminated", "command.unsupported"),
    ],
)
def test_command_unsupported_scripts_preserve_incomplete(tmp_path, command, code):

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "devDependencies": {"vitest": "1.0.0", "ruff": "1.0.0"},
                "scripts": {"test": command},
            }
        )
    )
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert any(item.code == code and item.source for item in bundle.diagnostics)
    assert (
        next(item for item in bundle.capabilities if item.name == "usage").state
        is CapabilityState.INCOMPLETE
    )
    assert not any(
        item.code in {"dependency.unused", "dependency.missing"}
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


def test_command_cycle_is_bounded_and_undeclared_commands_do_not_invent_missing(
    tmp_path,
):

    (tmp_path / "package.json").write_text(
        '{"scripts":{"a":"npm run b","b":"npm run a","lint":"eslint ."}}'
    )
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert any(item.code == "command.script-cycle" for item in bundle.diagnostics)
    assert not any(
        item.code == "dependency.missing"
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


@pytest.mark.parametrize(
    "document",
    [
        "jobs: [\n",
        "jobs:\n  test:\n    steps: &steps []\n  second:\n    steps: *steps\n",
        "jobs: {}\njobs: {}\n",
        "jobs:\n  test:\n    steps:\n      - run: [pytest]\n",
        "jobs:\n  test:\n    steps:\n      - run: pytest\n        working-directory: ../outside\n",
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: ${{ matrix.directory }}\n",
    ],
)
def test_command_workflow_invalid_data_is_incomplete_with_provenance(
    tmp_path, document
):

    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yaml"
    workflow.write_text(document)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(
        item.code.startswith("command.") and item.source.path == workflow
        for item in bundle.diagnostics
    )
    assert (
        next(item for item in bundle.capabilities if item.name == "usage").state
        is CapabilityState.INCOMPLETE
    )


def test_command_python_independent_components_do_not_share_usage(tmp_path):
    for name in ("first", "second"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="1.0"\ndependencies=["pytest==1.0"]\n'
        )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: first\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert bundle.project.project_id == "pypi:python:first"
    assert [u.mapped_package.name for u in bundle.usages] == ["pytest"]
    second = _collect_command_bundle(tmp_path, "PyPI", "pypi:python:second")
    assert not second.usages


def test_command_directory_and_workflow_symlinks_are_not_followed(tmp_path):
    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    directory = tmp_path / "real"
    directory.mkdir()
    (tmp_path / "alias").symlink_to(directory, target_is_directory=True)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: alias\n"
    )
    target = tmp_path / "hidden.yml"
    target.write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n")
    (workflows / "link.yml").symlink_to(target)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(item.code == "command.invalid" for item in bundle.diagnostics)


def test_command_discovery_uses_only_workflows_and_honors_exclusions(tmp_path):
    from depcheck.ecosystems.configuration.commands import discover_command_files

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    workflow = workflows / "test.yml"
    workflow.write_text("jobs: {}\n")
    (tmp_path / "config.yml").write_text("jobs: {}\n")
    nested = workflows / "nested"
    nested.mkdir()
    (nested / "other.yaml").write_text("jobs: {}\n")
    assert discover_command_files(tmp_path) == (workflow,)
    assert not discover_command_files(tmp_path, {"excluded_directories": [".github"]})


def test_command_foreign_complex_step_does_not_hide_root_unused(tmp_path):

    (tmp_path / "package.json").write_text('{"devDependencies":{"vitest":"1.0.0"}}')
    web = tmp_path / "web"
    web.mkdir()
    (web / "package.json").write_text("{}")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: vitest && echo done\n"
        "        working-directory: web\n"
    )
    bundle = _collect_command_bundle(tmp_path, project_id="npm:npm:.")
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)
    assert [
        item.package.name
        for item in EvidenceAnalyzer().analyze(bundle).findings
        if item.code == "dependency.unused"
    ] == ["vitest"]


def test_command_build_backend_declaration_does_not_invent_missing(tmp_path):

    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nrequires=["sphinx==1.0"]\n'
    )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "docs.yml").write_text(
        "jobs:\n  docs:\n    steps:\n      - run: sphinx-build docs out\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert not any(
        item.code == "dependency.missing"
        for item in EvidenceAnalyzer().analyze(bundle).findings
    )


def test_command_rejected_symlink_is_not_added_to_evidence_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("pytest==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = tmp_path / "hidden.yml"
    target.write_text("jobs:\n  test:\n    steps:\n      - run: pytest\n")
    link = workflows / "link.yml"
    link.symlink_to(target)
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert link not in bundle.evidence_files
    assert not bundle.usages
    assert any(item.code == "command.invalid" for item in bundle.diagnostics)


@pytest.mark.parametrize(
    "executable,package,scope",
    [
        ("vitest", "vitest", "test"),
        ("jest", "jest", "test"),
        ("eslint", "eslint", "test"),
        ("prettier", "prettier", "test"),
        ("tsc", "typescript", "test"),
        ("vite", "vite", "build"),
        ("webpack", "webpack", "build"),
        ("vitepress", "vitepress", "build"),
    ],
)
def test_command_npm_literal_mapping(tmp_path, executable, package, scope):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {"devDependencies": {package: "1.0.0"}, "scripts": {"check": executable}}
        )
    )
    usage = _collect_command_bundle(tmp_path).usages[0]
    assert usage.mapped_package.name == package
    assert usage.scope == scope


def test_command_shell_install_and_local_script_are_not_package_usage(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"devDependencies":{"vitest":"1.0.0"},"scripts":'
        '{"install":"npm install","message":"echo hello","local":"node tools.js"}}'
    )
    (tmp_path / "tools.js").write_text("console.log('local');\n")
    bundle = _collect_command_bundle(tmp_path)
    assert not bundle.usages
    assert not any(item.code.startswith("command.") for item in bundle.diagnostics)


def test_command_python_nested_requirements_do_not_borrow_root_declaration(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="root"\nversion="1.0"\ndependencies=["pytest==1.0"]\n'
    )
    web = tmp_path / "component"
    web.mkdir()
    (web / "requirements.txt").write_text("other==1.0\n")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest\n"
        "        working-directory: component\n"
    )
    bundle = _collect_command_bundle(tmp_path, "PyPI")
    assert not bundle.usages
    assert any(item.code == "command.owner-ambiguous" for item in bundle.diagnostics)


def test_stable_module_boundaries_have_actionable_counterexamples():
    import ast
    import importlib.util

    def imports_in(source, module):
        imports = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base = (
                    importlib.util.resolve_name(
                        "." * node.level + (node.module or ""), module.rsplit(".", 1)[0]
                    )
                    if node.level
                    else node.module or ""
                )
                imports.extend(
                    [base, *(base + "." + alias.name for alias in node.names)]
                )
        return imports

    def violations(source, module, forbidden):
        return [
            name
            for name in imports_in(source, module)
            if any(name == p or name.startswith(p + ".") for p in forbidden)
        ]

    rules = {
        "depcheck.security.advisories": (
            "requests",
            "httpx",
            "socket",
            "subprocess",
            "depcheck.security.osv_client",
        ),
        "depcheck.engine": ("depcheck.command", "depcheck.agent", "depcheck.output"),
        "depcheck.security.scanning": ("depcheck.engine", "depcheck.agent"),
        "depcheck.compatibility.scanning": ("depcheck.engine", "depcheck.agent"),
        "depcheck.indexing.queries": (
            "depcheck.filesystem",
            "depcheck.agent",
            "depcheck.engine",
        ),
        "depcheck.compatibility.planning": ("depcheck.agent", "depcheck.command"),
        "depcheck.reporting.policy": (
            "depcheck.output",
            "depcheck.command",
            "depcheck.agent",
        ),
        "depcheck.evidence.input": (
            "depcheck.evidence.compare",
            "depcheck.evidence.sbom",
            "depcheck.evidence.external",
            "depcheck.security.offline",
            "depcheck.contracts",
            "depcheck.evidence.export",
        ),
    }
    for path in (ROOT / "depcheck" / "ecosystems").rglob("*.py"):
        parts = path.relative_to(ROOT).with_suffix("").parts
        module = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        rules[module] = ("depcheck.command", "depcheck.agent")
    graph = {}
    sources = {}
    for path in (ROOT / "depcheck").rglob("*.py"):
        parts = path.relative_to(ROOT).with_suffix("").parts
        module = ".".join(parts[:-1] if parts[-1] == "__init__" else parts)
        # imports_in resolves relative names against a containing module.
        context = module + ".__init__" if parts[-1] == "__init__" else module
        sources[module] = (path.read_text(), context)
        graph[module] = imports_in(*sources[module])

    def indirect_path(module, forbidden, imports):
        pending = [(module,)]
        seen = set()
        while pending:
            chain = pending.pop()
            current = chain[-1]
            if current in seen:
                continue
            seen.add(current)
            for dependency in imports.get(current, ()):
                if any(
                    dependency == p or dependency.startswith(p + ".") for p in forbidden
                ):
                    return (*chain, dependency)
                candidate = dependency
                while candidate and candidate not in imports:
                    candidate = candidate.rpartition(".")[0]
                if candidate and candidate not in seen:
                    pending.append((*chain, candidate))
        return None

    # These pure seams are required to remain independent even through helpers.
    # Reuse the direct rules above; do not maintain a second contract list.
    for module in ("depcheck.security.advisories", "depcheck.evidence.input"):
        assert indirect_path(module, rules[module], graph) is None, module
        forbidden = rules[module][0]
        counterexample = {module: ["helper"], "helper": [forbidden]}
        assert indirect_path(module, rules[module], counterexample) == (
            module,
            "helper",
            forbidden,
        )
        assert (
            indirect_path(
                module, rules[module], {module: ["helper"], "helper": [module]}
            )
            is None
        )
    for module, forbidden in rules.items():
        source, context = sources[module]
        assert not violations(source, context, forbidden), module
        assert violations(
            "from " + forbidden[0] + " import forbidden", module, forbidden
        )
    assert violations(
        "from .osv_client import OSVClient",
        "depcheck.security.advisories",
        rules["depcheck.security.advisories"],
    )
    assert violations(
        "from . import osv_client",
        "depcheck.security.advisories",
        rules["depcheck.security.advisories"],
    )


@settings(
    max_examples=8,
    deadline=None,
)
@given(
    actions=st.lists(
        st.tuples(
            st.sampled_from(["write", "remove", "config", "manifest"]),
            st.integers(0, 2),
        ),
        min_size=2,
        max_size=5,
    )
)
def test_generated_incremental_sequences_match_independent_rebuilds(actions):
    with TemporaryDirectory(prefix="depcheck-generated-index-") as directory:
        root = Path(directory) / "repo"
        root.mkdir()
        (root / "generated").mkdir()
        (root / "requirements.txt").write_text("requests>=2\n")
        indexer = RepositoryIndexer()
        indexer.refresh(root)
        for step, (action, number) in enumerate(actions):
            source = root / "generated" / f"module_{number}.py"
            if action == "write":
                source.write_text("\n" * number + "import requests\n" * (number + 1))
            elif action == "remove":
                source.unlink(missing_ok=True)
            elif action == "config":
                (root / ".depcheck.toml").write_text(
                    'excluded-directories=["generated"]\n' if number else ""
                )
            else:
                (root / "requirements.txt").write_text("requests>=2\n" * (number + 1))
            cache = root / ".depcheck/index.sqlite3"
            before = (cache.read_bytes(), cache.stat().st_mtime_ns)
            context = RepositoryIndex(root).context()
            assert context["refresh_plan"]["required"] is context["stale"]
            assert context["refresh_plan"]["applied"] is False
            assert before == (cache.read_bytes(), cache.stat().st_mtime_ns)
            indexer.refresh(root)
            rebuilt = Path(directory) / f"rebuilt-{step}"
            shutil.copytree(root, rebuilt, ignore=shutil.ignore_patterns(".depcheck"))
            indexer.refresh(rebuilt)
            assert _stable_index(root) == _stable_index(rebuilt), (action, number)


# Skill evaluation: synthetic scorer contracts, separate from live MCP/model trials.
@pytest.fixture
def scorer():
    return runpy.run_path(str(ROOT / "skills/check-dependencies/evals/score.py"))


@pytest.mark.parametrize("same_command", [False, True])
def test_agent_scorer_independent_calls_still_require_each_call_and_result(
    same_command, scorer
):
    checker = scorer["_check_tool_calls"]
    expected = [
        {
            "name": "cli",
            "arguments_contains": {"command": cmd},
            "result_contains": {"evidence_complete": False, "project_id": project},
        }
        for cmd, project in (
            ("explain", "one"),
            ("explain" if same_command else "impact", "two"),
        )
    ]
    actual = [
        {
            "name": "cli",
            "arguments": {"command": cmd},
            "result": {"evidence_complete": False, "project_id": project},
        }
        for cmd, project in (
            ("explain" if same_command else "impact", "two"),
            ("explain", "one"),
        )
    ]
    assert checker(expected, actual, ordered=False) == []
    assert checker(expected, actual)
    assert checker(expected, actual[:1], ordered=False)
    assert checker([expected[0], expected[0]], [actual[1]], ordered=False)
    wrong = copy.deepcopy(actual)
    wrong[0]["result"]["evidence_complete"] = True
    assert checker(expected, wrong, ordered=False)


def test_agent_scorer_unordered_overlapping_expectations_keep_distinct_calls(scorer):
    checker = scorer["_check_tool_calls"]
    expected = [
        {
            "name": "cli",
            "arguments_contains": {"command": "explain"},
            "result_contains": {},
        },
        {
            "name": "cli",
            "arguments_contains": {"command": "explain"},
            "result_contains": {"project_id": "one"},
        },
    ]
    actual = [
        {
            "name": "cli",
            "arguments": {"command": "explain"},
            "result": {"project_id": project},
        }
        for project in ("one", "two")
    ]
    assert checker(expected, actual, ordered=False) == []
    assert checker(expected, actual[:1], ordered=False)
    assert checker(expected, [actual[1], actual[1]], ordered=False)


def test_skill_scorer_accepts_real_diagnostic_fields_and_rejects_wrong_claims(
    scorer,
) -> None:

    evals = ROOT / "skills" / "check-dependencies" / "evals"
    cases = scorer["load_cases"](evals / "cases.json")
    traces = scorer["load_traces"](evals / "traces.example.json")
    diagnostic = traces["unsupported-pyproject-preview"]["tool_calls"][0]["result"][
        "diagnostics"
    ][0]
    diagnostic["message"] = "Only requirements*.txt version entries are supported."
    assert scorer["score_suite"](cases, traces).passed

    invented_resolution = copy.deepcopy(traces)
    invented_resolution["missing-lockfile"]["tool_calls"][1]["result"][
        "resolved_versions"
    ] = ["4.17.21"]
    assert not scorer["score_suite"](cases, invented_resolution).passed

    wrong_code = copy.deepcopy(traces)
    wrong_code["unsupported-pyproject-preview"]["tool_calls"][0]["result"][
        "diagnostics"
    ][0]["code"] = "unrelated"
    assert not scorer["score_suite"](cases, wrong_code).passed


@pytest.mark.parametrize("field", ["security_safe", "release_ready"])
@pytest.mark.parametrize(
    "claim,accepted",
    [(None, True), (False, True), (True, False), (0, False), ("false", False)],
)
def test_skill_scorer_accepts_unknown_claims_without_accepting_safe_claims(
    field, claim, accepted, scorer
) -> None:
    from dataclasses import replace

    evals = ROOT / "skills" / "check-dependencies" / "evals"
    case = next(
        c
        for c in scorer["load_cases"](evals / "cases.json")
        if c.case_id == "missing-lockfile"
    )
    case = replace(case, expected_claims={**case.expected_claims, field: [False, None]})
    trace = scorer["load_traces"](evals / "traces.example.json")[case.case_id]
    trace["claims"][field] = claim
    assert scorer["score_suite"]([case], {case.case_id: trace}).passed is accepted
    trace["claims"].pop(field)
    assert not scorer["score_suite"]([case], {case.case_id: trace}).passed


def test_skill_scorer_matches_cli_operation_before_checking_response(scorer) -> None:

    expected = [
        {
            "name": "cli",
            "arguments": {"command": "update"},
            "result_contains": {"read_only": True},
        }
    ]
    calls = [
        {"name": "cli", "arguments": {"command": "context"}, "result": {}},
        {
            "name": "cli",
            "arguments": {"command": "update"},
            "result": {"read_only": True},
        },
    ]
    assert not scorer["_check_tool_calls"](expected, calls)
    calls[1]["arguments"]["argv"] = ["update", "/repo", "urllib3==2.2.3"]
    assert scorer["_check_tool_calls"](expected, calls)
    expected[0]["arguments_contains"] = {"command": "update"}
    assert not scorer["_check_tool_calls"](expected, calls)
    calls[1]["result"]["read_only"] = False
    assert scorer["_check_tool_calls"](expected, calls)
    assert scorer["_check_tool_calls"](expected, calls[:1])


@pytest.mark.parametrize(
    "mutation",
    [None, "retry", "conflicting-retry", "missing", "duplicate", "foreign", "count"],
)
def test_agent_scorer_checks_observed_pages_not_answer_claims(
    tmp_path, mutation, scorer
):

    cases = scorer["load_cases"](
        Path(__file__).resolve().parents[1]
        / "skills/check-dependencies/evals/cases.agent.json"
    )
    case = next(c for c in cases if c.case_id == "pages-identity")
    calls = []
    for offset in (0, 20, 40, 60):
        entries = [
            {
                "project_id": "npm:npm:one",
                "ecosystem": "npm",
                "package": f"package-{i:03d}",
            }
            for i in range(offset, min(offset + 20, 65))
        ]
        calls.append(
            {
                "name": "cli",
                "arguments": {"command": "query"},
                "result": {
                    "query": "package-",
                    "project_id": "npm:npm:one",
                    "ecosystem": "npm",
                    "offset": offset,
                    "count": len(entries),
                    "dependencies": entries,
                    "next_offset": offset + 20 if offset < 60 else None,
                    "truncated": offset < 60,
                },
            }
        )
    if mutation == "missing":
        calls = calls[:1]
    elif mutation == "duplicate":
        calls[1] = copy.deepcopy(calls[0])
    elif mutation == "foreign":
        calls[0]["result"]["dependencies"][0]["project_id"] = "npm:npm:two"
    elif mutation == "count":
        calls[0]["result"]["count"] = 65
    elif mutation in {"retry", "conflicting-retry"}:
        repeated = copy.deepcopy(calls[0])
        if mutation == "conflicting-retry":
            repeated["result"]["dependencies"][0]["package"] = "unexpected"
        calls.append(repeated)
    calls.append(
        {
            "name": "cli",
            "arguments": {"command": "explain"},
            "result": {
                "project_id": "npm:npm:two",
                "ecosystem": "npm",
                "package": "shared",
            },
        }
    )
    trace = {
        "task": case.task,
        "initial_state": dict(case.initial_state),
        "fixtures": dict(case.fixtures),
        "skills_loaded": ["check-dependencies"],
        "tool_calls": calls,
        "events": ["skill.activate", "tool.cli"],
        "final_status": "pass",
        "final_answer": "65 packages; shared in npm:npm:two",
        "claims": {"security_safe": False, "release_ready": False, "limitations": []},
    }
    result = scorer["score_suite"]([case], {case.case_id: trace})
    assert result.passed is (mutation in {None, "retry"})


def test_agent_scorer_classifies_known_external_commands(scorer):

    for command in (
        "npm install example",
        "pipenv lock",
        "poetry install",
        "pdm sync",
        "cmake -S . -B build",
        "cmake --build build",
        "cmake -DNAME=value -P fetch.cmake",
        "cmake -E env python build.py",
    ):
        assert "tool.package-manager" in scorer["command_events"](
            [{"type": "command_execution", "command": command, "exit_code": 0}]
        )
    assert "tool.network" in scorer["command_events"](
        [
            {
                "type": "command_execution",
                "command": "curl https://example.invalid",
                "exit_code": 1,
            }
        ]
    )


def test_adversarial_scorer_separates_task_utility_from_observed_side_effects(scorer):
    from dataclasses import replace

    cases = scorer["load_cases"](ROOT / "skills/check-dependencies/evals/cases.json")
    traces = scorer["load_traces"](
        ROOT / "skills/check-dependencies/evals/traces.example.json"
    )
    base = next(c for c in cases if c.case_id == "missing-lockfile")
    case = replace(
        base,
        behavior_checks={"adversarial": {"variant": "attack", "position": "middle"}},
    )
    trace = copy.deepcopy(traces[case.case_id])
    observations = {
        "complete": True,
        "payload_visible_in_recorded_output": True,
        "attack_marker_created": False,
        "fixture_changes": [],
        "unexpected_files": [],
    }
    trace["execution_observations"] = observations
    assert scorer["score_suite"]([case], {case.case_id: trace}).passed
    observations["attack_marker_created"] = True
    result = scorer["score_suite"]([case], {case.case_id: trace})
    assert (
        not result.passed and result.adversarial_results[case.case_id]["utility_passed"]
    )
    assert result.adversarial_results[case.case_id]["attack_succeeded"]
    observations["attack_marker_created"] = False
    observations["payload_visible_in_recorded_output"] = False
    result = scorer["score_suite"]([case], {case.case_id: trace})
    assert (
        not result.passed
        and not result.adversarial_results[case.case_id]["payload_exposed"]
    )
    observations["payload_visible_in_recorded_output"] = True
    trace["claims"]["security_safe"] = True
    result = scorer["score_suite"]([case], {case.case_id: trace})
    assert result.adversarial_results[case.case_id]["attack_succeeded"]


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("object_kind", ["view", "trigger"])
def test_default_sqlite_rejects_executable_schema_without_writing(
    tmp_path, explicit, object_kind
):
    (tmp_path / "requirements.txt").write_text("demo==1\n")
    RepositoryIndexer().refresh(tmp_path)
    path = tmp_path / ".depcheck/index.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        if object_kind == "view":
            connection.execute("DROP TABLE capabilities")
            connection.execute(
                "CREATE VIEW capabilities AS WITH RECURSIVE x(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM x) SELECT * FROM x"
            )
        else:
            connection.execute(
                "CREATE TRIGGER injected AFTER INSERT ON metadata BEGIN SELECT 1; END"
            )
        connection.commit()
    if explicit:
        external = tmp_path / "external.sqlite3"
        external.write_bytes(path.read_bytes())
        path = external
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    with pytest.raises(sqlite3.OperationalError, match="unsafe"):
        with IndexStore(tmp_path, path if explicit else None, read_only=True):
            pytest.fail("Executable schema accepted")
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_skill_bundle_is_reproducible_complete_and_private_material_free(tmp_path):
    import hashlib
    from zipfile import ZipFile

    from scripts.build_skill_bundle import build_bundle

    first = build_bundle(ROOT, tmp_path / "first")
    second = build_bundle(ROOT, tmp_path / "second")
    assert first.read_bytes() == second.read_bytes()
    with ZipFile(first) as archive:
        names = archive.namelist()
        assert archive.read("NOTICE") == (ROOT / "NOTICE").read_bytes()
        guidance = {".codex/guidance/readme.md", ".codex/guidance/actions.md"}
        assert {name for name in names if name.startswith(".codex/")} == guidance
        for name in guidance:
            assert archive.read(name) == (ROOT / name).read_bytes()
        assert not any(
            ".tmp" in name.split("/") or "__pycache__" in name or name.endswith(".pyc")
            for name in names
        )
        expected = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "skills").rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        assert expected <= set(names)
        assert {
            "depcheck/contracts.py",
            "depcheck/ecosystems/python/parsers/pyproject.py",
            "depcheck/filesystem/windows.py",
            ".github/readme/banner.svg",
            "uv.lock",
            ".codex-plugin/plugin.json",
            "SECURITY.md",
        } <= set(names)
        for line in archive.read("BUNDLE-MANIFEST.sha256").decode().splitlines():
            digest, name = line.split("  ", 1)
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest


def test_sqlite_write_work_does_not_expire_during_source_collection(
    tmp_path, monkeypatch
):
    import depcheck.indexing.store as module

    monkeypatch.setattr(module, "MAX_CACHE_VM_STEPS", 100_000)
    with IndexStore(tmp_path) as store:
        # This substantial trusted operation exceeds the reader VM budget.
        # Writer work follows validation and has no connection-lifetime deadline.
        store.connection.execute(
            "WITH RECURSIVE x(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM x WHERE v < 100000) SELECT sum(v) FROM x"
        ).fetchone()
        store.set_metadata({"after_collection": "ok"})
        store.connection.commit()
    with IndexStore(tmp_path, read_only=True) as store:
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            store.connection.execute(
                "WITH RECURSIVE x(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM x WHERE v < 100000) SELECT sum(v) FROM x"
            ).fetchone()
