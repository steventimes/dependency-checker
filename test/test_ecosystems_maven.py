"""Maven collection, ownership, and qualified static evidence."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from depcheck.agent import DependencyAgentService
from depcheck.ecosystems.java.collector import create_maven_pack
from depcheck.ecosystems.registry import ProviderContext
from depcheck.engine import RepositoryScanner, RepositoryScanOptions
from depcheck.output import build_cyclonedx


def test_unmapped_java_namespace_has_project_and_reference_location(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><artifactId>example</artifactId></project>"
    )
    source = tmp_path / "Main.java"
    source.write_text("package local;\n\nimport vendor.unknown.Client;\n")
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    diagnostic = next(d for d in result.diagnostics if d.code == "mapping.unresolved")
    assert diagnostic.source is not None
    assert (
        diagnostic.source.path,
        diagnostic.source.line,
        diagnostic.source.column,
    ) == (source, 3, 8)
    assert "maven:maven:." in diagnostic.message
    assert "vendor.unknown.Client" in diagnostic.message
    assert not result.capability("dependency_hygiene").complete


@pytest.mark.parametrize("application_dependency", [False, True])
def test_maven_plugins_preserve_configuration_without_application_or_security_claims(
    tmp_path, application_dependency
):
    library = (
        "<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.0-jre</version></dependency></dependencies>"
        if application_dependency
        else ""
    )
    text = (
        "<project>\n<groupId>example</groupId><artifactId>app</artifactId><version>1</version>\n"
        "<properties><plugin.version>3.13.0</plugin.version><processor.version>28.0-jre</processor.version></properties>\n"
        + library
        + "\n"
        "<build><pluginManagement><plugins>\n"
        "<plugin><artifactId>maven-compiler-plugin</artifactId><version>${plugin.version}</version></plugin>\n"
        "</plugins></pluginManagement><plugins>\n"
        "<plugin><artifactId>maven-compiler-plugin</artifactId>\n"
        "<executions><execution><id>compile-it</id><phase>compile</phase><goals><goal>compile</goal></goals></execution></executions>\n"
        "<dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>29.0-jre</version></dependency></dependencies>\n"
        "<configuration><target>not executed</target><annotationProcessorPaths><path><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>${processor.version}</version></path></annotationProcessorPaths></configuration></plugin>\n"
        "</plugins></build>\n"
        "<reporting><plugins><plugin><artifactId>maven-project-info-reports-plugin</artifactId><version>3.9.0</version><reportSets><reportSet><id>basic</id><reports><report>summary</report></reports></reportSet></reportSets></plugin></plugins></reporting>\n"
        "<profiles><profile><id>ci</id><activation><file><exists>../private-marker</exists></file></activation>\n"
        "<properties><profile.version>9</profile.version></properties><build><plugins>\n"
        "<plugin><groupId>org.codehaus.mojo</groupId><artifactId>versions-maven-plugin</artifactId><version>${profile.version}</version></plugin>\n"
        "</plugins></build></profile></profiles>\n</project>\n"
    )
    (tmp_path / "pom.xml").write_text(text, encoding="utf-8")
    (tmp_path / "Main.java").write_text(
        "import com.google.common.collect.ImmutableList;\n", encoding="utf-8"
    )
    queries = []

    def query(packages, ecosystem):
        queries.append((dict(packages), ecosystem))
        return SimpleNamespace(
            vulnerabilities={}, queried=dict(packages), diagnostics=(), complete=True
        )

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=query)).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            compatibility=False,
            public_maven_packages=("com.google.guava:guava",),
        ),
    )
    bundle = next(b for b in result.bundles if b.project.manager == "maven")
    configuration = [d for d in bundle.declarations if d.kind == "conditional"]
    assert len(configuration) == 6
    assert all(
        d.scope == "build" and d.metadata["activation"] == "unknown"
        for d in configuration
    )
    assert {d.metadata["maven_kind"] for d in configuration} == {
        "build-plugin",
        "plugin-management",
        "plugin-dependency",
        "annotation-processor",
        "reporting-plugin",
    }
    compiler = [
        d
        for d in configuration
        if d.package.name == "org.apache.maven.plugins:maven-compiler-plugin"
    ]
    assert len(compiler) == 2
    management = next(
        d for d in compiler if d.metadata["maven_kind"] == "plugin-management"
    )
    actual = next(d for d in compiler if d.metadata["maven_kind"] == "build-plugin")
    assert (
        management.constraint.normalized == "3.13.0"
        and actual.constraint.normalized is None
    )
    assert actual.metadata["executions"][0]["id"] == "compile-it"
    assert actual.metadata["executions"][0]["phase"] == "compile"
    assert actual.metadata["executions"][0]["goals"] == ["compile"]
    assert actual.metadata["configuration_present"] is True
    reporting = next(
        d for d in configuration if d.metadata["maven_kind"] == "reporting-plugin"
    )
    assert reporting.metadata["report_sets"][0]["id"] == "basic"
    assert reporting.metadata["report_sets"][0]["reports"] == ["summary"]
    dependency = next(
        d for d in configuration if d.metadata["maven_kind"] == "plugin-dependency"
    )
    assert dependency.package.name == "com.google.guava:guava"
    assert dependency.metadata["classpath"] == "plugin"
    assert (
        dependency.metadata["owner_plugin"]
        == "org.apache.maven.plugins:maven-compiler-plugin"
    )
    processor = next(
        d for d in configuration if d.metadata["maven_kind"] == "annotation-processor"
    )
    assert processor.package.name == "com.google.guava:guava"
    assert processor.metadata["classpath"] == "annotation-processor"
    assert (
        processor.metadata["owner_plugin"]
        == "org.apache.maven.plugins:maven-compiler-plugin"
    )
    assert processor.constraint.raw == "${processor.version}"
    assert processor.constraint.normalized == "28.0-jre"
    assert (processor.source.line, processor.source.column) == (
        11,
        text.splitlines()[10].index("<path>") + 1,
    )
    profile = next(d for d in configuration if d.metadata.get("profile"))
    assert profile.metadata["profile"]["id"] == "ci"
    assert (
        profile.metadata["profile"]["activation"]["file"]["exists"]
        == "../private-marker"
    )
    assert (
        profile.constraint.raw == "${profile.version}"
        and profile.constraint.normalized is None
    )
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(
        d.code == "resolution.maven-plugin-activation-unknown"
        for d in bundle.diagnostics
    )
    if application_dependency:
        assert queries == [({"com.google.guava:guava": "31.0-jre"}, "Maven")]
        assert not any(f.code == "dependency.missing" for f in result.findings)
    else:
        assert queries == [] and not bundle.resolved
        assert any(
            f.code == "dependency.missing"
            and f.package.name == "com.google.guava:guava"
            for f in result.findings
        )
    assert not result.capability("security").complete
    assert not any(
        f.code == "dependency.unused" and f.package.name.endswith("-plugin")
        for f in result.findings
    )
    assert (actual.source.line, actual.source.column) == (8, 1)
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    record = service.explain_dependency(
        "org.apache.maven.plugins:maven-compiler-plugin", ecosystem="Maven"
    )
    assert len(record["declarations"]) == 2 and record["resolved_versions"] == []
    assert not record["evidence_complete"]
    application = service.explain_dependency(
        "com.google.guava:guava", ecosystem="Maven"
    )
    assert application["resolved_versions"] == (
        ["31.0-jre"] if application_dependency else []
    )
    processors = [
        d
        for d in application["declarations"]
        if d["metadata"].get("maven_kind") == "annotation-processor"
    ]
    assert len(processors) == 1
    assert processors[0]["constraint"]["normalized"] == "28.0-jre"
    bom = build_cyclonedx(result)
    compiler_components = [
        c
        for c in bom["components"]
        if c["name"] == "org.apache.maven.plugins:maven-compiler-plugin"
    ]
    assert len(compiler_components) == 1
    assert (
        len(
            [
                p
                for p in compiler_components[0]["properties"]
                if p["name"] == "depcheck:conditional-declaration"
            ]
        )
        == 2
    )
    assert compiler_components[0]["bom-ref"] not in bom["dependencies"][0]["dependsOn"]

    processor_assertions = [
        json.loads(prop["value"])
        for component in bom["components"]
        for prop in component["properties"]
        if prop["name"] == "depcheck:conditional-declaration"
        and json.loads(prop["value"])["metadata"].get("maven_kind")
        == "annotation-processor"
    ]
    assert len(processor_assertions) == 1
    assert processor_assertions[0]["metadata"]["classpath"] == "annotation-processor"
    assert processor_assertions[0]["metadata"]["activation"] == "unknown"
    assert processor_assertions[0]["constraint"] == "${processor.version}"


def test_maven_plugin_inheritance_keeps_declaring_context_and_false_boundaries(
    tmp_path,
):
    parent = tmp_path / "pom.xml"
    parent.write_text(
        "<project><groupId>example</groupId><artifactId>parent</artifactId><version>1</version><properties><plugin.version>3.1</plugin.version></properties><build><plugins>"
        "<plugin><artifactId>maven-compiler-plugin</artifactId><version>${plugin.version}</version><executions><execution><id>private</id><inherited>false</inherited><goals><goal>compile</goal></goals></execution></executions></plugin>"
        "<plugin><artifactId>maven-antrun-plugin</artifactId><version>3.0</version><inherited>false</inherited></plugin>"
        "<plugin><artifactId>maven-resources-plugin</artifactId><version>3.3</version><inherited>false</inherited><executions><execution><id>keep</id><inherited>true</inherited><goals><goal>resources</goal></goals></execution><execution><id>implicit-drop</id><goals><goal>resources</goal></goals></execution></executions></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>child</artifactId><properties><plugin.version>9.0</plugin.version></properties></project>",
        encoding="utf-8",
    )
    service = DependencyAgentService(tmp_path)
    service.index_repository()
    record = service.explain_dependency(
        "org.apache.maven.plugins:maven-compiler-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    )
    assert record["declarations"][0]["constraint"]["normalized"] == "3.1"
    assert record["declarations"][0]["location"]["path"] == "pom.xml"
    assert record["declarations"][0]["metadata"]["property_context"] == "declaring-pom"
    assert record["declarations"][0]["metadata"]["executions"] == []
    assert not service.explain_dependency(
        "org.apache.maven.plugins:maven-antrun-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    ).get("declared", False)
    inherited_execution = service.explain_dependency(
        "org.apache.maven.plugins:maven-resources-plugin",
        ecosystem="Maven",
        project_id="maven:maven:child",
    )
    assert (
        inherited_execution["declarations"][0]["metadata"]["executions"][0]["id"]
        == "keep"
    )
    assert len(inherited_execution["declarations"][0]["metadata"]["executions"]) == 1
    parent.write_text(
        parent.read_text().replace(
            "<plugin.version>3.1</plugin.version>",
            "<plugin.version>3.2</plugin.version>",
        ),
        encoding="utf-8",
    )
    assert service.repository_context()["stale"]
    service.index_repository()
    assert (
        service.explain_dependency(
            "org.apache.maven.plugins:maven-compiler-plugin",
            ecosystem="Maven",
            project_id="maven:maven:child",
        )["declarations"][0]["constraint"]["normalized"]
        == "3.2"
    )


@pytest.mark.parametrize(
    "group",
    ["<groupId>${unknown}</groupId>", "<groupId/>", "<groupId>bad:group</groupId>"],
)
def test_maven_invalid_plugin_identity_does_not_invent_default_or_lose_libraries(
    tmp_path, group
):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies><build><plugins><plugin>"
        + group
        + "<artifactId>wrong-plugin</artifactId><version>1</version></plugin></plugins></build></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert {d.package.name for d in bundle.declarations} == {"example:library"}
    assert any(
        d.code == "manifest.maven-plugin-identity-unresolved"
        for d in bundle.diagnostics
    )
    assert not next(c for c in bundle.capabilities if c.name == "manifest").complete


def test_maven_profile_activation_is_data_and_unknown_layers_are_qualified(
    tmp_path, monkeypatch
):
    outside = tmp_path.parent / "outside-activation-marker"
    original = Path.is_file

    def is_file(path):
        assert path != outside, "profile activation performed a filesystem probe"
        return original(path)

    monkeypatch.setattr(Path, "is_file", is_file)
    text = (
        "<project>\n<groupId>owner</groupId><artifactId>app</artifactId><version>1</version>\n"
        "<properties><extension.version>2</extension.version><extension.scope>provided</extension.scope><profile.version>88</profile.version></properties>\n"
        "<build><extensions>\n"
        "<extension><groupId>example</groupId><artifactId>ext</artifactId><version>1</version></extension>\n"
        "<extension><groupId>example</groupId><artifactId>ext</artifactId><version>${extension.version}</version><scope>${extension.scope}</scope><type>zip</type><classifier>native</classifier></extension>\n"
        "<extension><groupId>example</groupId><artifactId>ext</artifactId><version>${external.version}</version><type>${external.type}</type><classifier>${external.classifier}</classifier></extension>\n"
        "<extension><artifactId>missing-group</artifactId><version>1</version></extension>\n"
        "</extensions></build>\n"
        "<dependencies><dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>7</version></dependency><dependency><groupId>example</groupId><artifactId>managed-only</artifactId></dependency></dependencies>\n"
        "<profiles><profile><id>x</id><activation><file><exists>"
        + str(outside)
        + "</exists></file><jdk>[17,)</jdk><property><name>profile-toggle</name><value>on</value></property><custom><nested><value>unknown</value></nested></custom></activation><properties><profile.version>99</profile.version></properties><dependencies>\n"
        "<dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>1</version></dependency>\n"
        "<dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>1</version></dependency>\n"
        "<dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>${profile.version}</version><scope>runtime</scope></dependency>\n"
        "<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.0-jre</version><scope>test</scope><type>jar</type><classifier>tests</classifier></dependency>\n"
        "<dependency><groupId>example</groupId><artifactId>unknown-lib</artifactId><version>${profile.version}</version><scope>${profile.scope}</scope><type>${profile.type}</type><classifier>${profile.classifier}</classifier></dependency>\n"
        "</dependencies><dependencyManagement><dependencies>\n"
        "<dependency><groupId>example</groupId><artifactId>managed-only</artifactId><version>9</version><scope>provided</scope></dependency>\n"
        "<dependency><groupId>example</groupId><artifactId>managed-only</artifactId><version>9</version><scope>provided</scope></dependency>\n"
        "<dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>8</version><scope>import</scope><type>pom</type></dependency>\n"
        '</dependencies></dependencyManagement><build><plugins><plugin><artifactId>maven-antrun-plugin</artifactId><version>3</version><configuration><target><touch file="'
        + str(tmp_path / "executed")
        + '"/></target></configuration></plugin></plugins></build></profile>\n'
        "<profile><id>y</id><dependencies><dependency><groupId>example</groupId><artifactId>conditional-lib</artifactId><version>6</version><scope>runtime</scope></dependency></dependencies></profile></profiles></project>"
    )
    (tmp_path / "pom.xml").write_text(text, encoding="utf-8")
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project><parent><groupId>owner</groupId><artifactId>app</artifactId><version>1</version></parent><artifactId>child</artifactId></project>",
        encoding="utf-8",
    )
    (tmp_path / "Main.java").write_text(
        "import com.google.common.collect.ImmutableList;\n", encoding="utf-8"
    )
    queries = []

    def query(packages, ecosystem):
        queries.append((dict(packages), ecosystem))
        return SimpleNamespace(
            vulnerabilities={}, queried=dict(packages), diagnostics=(), complete=True
        )

    result = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=query)).scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            compatibility=False,
            public_maven_packages=("example:ext", "com.google.guava:guava"),
        ),
    )
    profile_rows = [
        d
        for b in result.bundles
        for d in b.declarations
        if d.metadata.get("maven_kind") in {"profile-dependency", "profile-management"}
    ]
    assert len(profile_rows) == 9
    extensions = [
        d
        for b in result.bundles
        for d in b.declarations
        if d.metadata.get("maven_kind") == "build-extension"
    ]
    assert len(extensions) == 3
    root = next(b for b in result.bundles if b.project.root == Path("."))
    assert all(d.project_id == root.project.project_id for d in extensions)
    assert [
        (
            d.constraint.raw,
            d.constraint.normalized,
            d.source.line,
            d.metadata["maven_scope"],
            d.metadata["maven_type"],
            d.metadata["maven_classifier"],
        )
        for d in extensions
    ] == [
        ("1", "1", 5, "", "", ""),
        ("${extension.version}", "2", 6, "${extension.scope}", "zip", "native"),
        (
            "${external.version}",
            None,
            7,
            "",
            "${external.type}",
            "${external.classifier}",
        ),
    ]
    for extension in extensions:
        assert extension.package.name == "example:ext" and not extension.package.purl
        assert extension.source.path == (tmp_path / "pom.xml").resolve()
        assert extension.source.column == 1
        assert extension.kind == "conditional" and extension.scope == "build"
        assert extension.metadata["classpath"] == "build-extension"
        assert extension.metadata["plugin_context"] == "build.extensions"
        assert extension.metadata["declaring_pom"] == "pom.xml"
        assert extension.metadata["source_relationship"] == "current-pom"
        assert extension.metadata["property_context"] == "declaring-pom"
        assert extension.metadata["inherited"] == "unknown"
        assert extension.metadata["activation"] == "unknown"
        assert extension.metadata["effective_model"] == "not-evaluated"
    assert not queries
    assert all(
        [(r.package.name, r.version) for r in b.resolved]
        == [("example:conditional-lib", "7")]
        for b in result.bundles
    )
    assert all(d.project_id == root.project.project_id for d in profile_rows)
    assert [d.source.line for d in profile_rows] == [12, 13, 14, 15, 16, 18, 19, 20, 22]
    assert [d.metadata["profile"]["index"] for d in profile_rows] == [0] * 8 + [1]
    assert [d.metadata["profile"]["id"] for d in profile_rows] == ["x"] * 8 + ["y"]
    assert [
        (
            d.metadata["maven_kind"],
            d.package.name,
            d.constraint.raw,
            d.constraint.normalized,
        )
        for d in profile_rows
    ] == [
        ("profile-dependency", "example:conditional-lib", "1", "1"),
        ("profile-dependency", "example:conditional-lib", "1", "1"),
        ("profile-dependency", "example:conditional-lib", "${profile.version}", None),
        ("profile-dependency", "com.google.guava:guava", "32.0-jre", "32.0-jre"),
        ("profile-dependency", "example:unknown-lib", "${profile.version}", None),
        ("profile-management", "example:managed-only", "9", "9"),
        ("profile-management", "example:managed-only", "9", "9"),
        ("profile-management", "example:conditional-lib", "8", "8"),
        ("profile-dependency", "example:conditional-lib", "6", "6"),
    ]
    for d in profile_rows:
        assert d.kind == "conditional" and d.scope == "unknown"
        assert not d.package.purl
        assert d.metadata["activation"] == "unknown"
        assert d.metadata["effective_model"] == "not-evaluated"
        assert d.metadata["property_context"] == "unevaluated-profile"
        assert d.metadata["source_relationship"] == "current-pom"
        assert d.metadata["declaring_pom"] == "pom.xml"
        assert d.metadata["inherited"] == "unknown"
    assert profile_rows[3].metadata["maven_scope"] == "test"
    assert profile_rows[3].metadata["maven_classifier"] == "tests"
    assert profile_rows[4].metadata["maven_scope"] == "${profile.scope}"
    assert profile_rows[4].metadata["maven_type"] == "${profile.type}"
    assert profile_rows[4].metadata["maven_classifier"] == "${profile.classifier}"
    assert profile_rows[7].metadata["maven_scope"] == "import"
    assert profile_rows[7].metadata["maven_type"] == "pom"
    assert all(
        d.constraint.normalized is None
        for b in result.bundles
        for d in b.declarations
        if d.kind == "direct" and d.package.name == "example:managed-only"
    )
    # This mixed fixture is incomplete; retain the existing missing-warning gate.
    assert not next(c for c in root.capabilities if c.name == "manifest").complete
    assert not result.capability("security").complete
    codes = {d.code for d in result.diagnostics}
    assert {
        "manifest.maven-plugin-identity-unresolved",
        "manifest.maven-profile-activation-uncollected",
    } <= codes
    assert "manifest.maven-build-extensions-uncollected" not in codes
    assert "manifest.maven-profile-dependencies-uncollected" not in codes
    assert not any(
        d.package.name.endswith("missing-group")
        for b in result.bundles
        for d in b.declarations
    )
    assert not (tmp_path / "executed").exists()
    record = next(
        d
        for b in result.bundles
        for d in b.declarations
        if d.metadata.get("maven_kind") == "build-plugin"
    )
    assert record.metadata["profile"]["activation"]["file"]["exists"] == str(outside)
    assert record.metadata["profile"]["activation"]["uncollected_conditions"] is True
    assert record.metadata["profile"]["activation"]["jdk"] == "[17,)"
    assert record.metadata["profile"]["activation"]["property"] == {
        "name": "profile-toggle",
        "value": "on",
    }
    assert (
        "<value>unknown</value>"
        in profile_rows[0].metadata["profile"]["activation_xml"]
    )
    assert profile_rows[0].metadata["profile"] == record.metadata["profile"]

    service = DependencyAgentService(tmp_path)
    service.index_repository(ecosystems=("maven",))
    cache = tmp_path / ".depcheck" / "index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    page = service.query_dependencies("example:ext", ecosystem="Maven")
    assert len(page["dependencies"]) == 1
    indexed = page["dependencies"][0]
    assert indexed["project_id"] == root.project.project_id
    assert indexed["resolved_versions"] == [] and indexed["purl"] is None
    explanation = service.explain_dependency("example:ext", ecosystem="Maven")
    assert not explanation["evidence_complete"]
    assert explanation["resolved_versions"] == []
    assert [d["location"]["line"] for d in explanation["declarations"]] == [5, 6, 7]
    assert [d["constraint"]["normalized"] for d in explanation["declarations"]] == [
        "1",
        "2",
        None,
    ]
    assert all(
        d["metadata"]["classpath"] == "build-extension"
        for d in explanation["declarations"]
    )
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    bom = build_cyclonedx(result)
    components = [c for c in bom["components"] if c["name"] == "example:ext"]
    assert len(components) == 1
    component = components[0]
    assert not component.get("version") and not component.get("purl")
    assert component["bom-ref"] not in bom["dependencies"][0]["dependsOn"]
    assertions = [
        json.loads(prop["value"])
        for prop in component["properties"]
        if prop["name"] == "depcheck:conditional-declaration"
    ]
    assert len(assertions) == 3
    assert [a["source"]["line"] for a in assertions] == [5, 6, 7]
    assert {a["constraint"] for a in assertions} == {
        "1",
        "${extension.version}",
        "${external.version}",
    }
    assert all(
        a["scope"] == "build"
        and a["metadata"]["maven_kind"] == "build-extension"
        and a["metadata"]["activation"] == "unknown"
        and a["metadata"]["effective_model"] == "not-evaluated"
        for a in assertions
    )

    shared = service.explain_dependency(
        "example:conditional-lib", ecosystem="Maven", project_id=root.project.project_id
    )
    assert shared["resolved_versions"] == ["7"]
    assert len(shared["declarations"]) == 6
    management = service.explain_dependency(
        "example:managed-only", ecosystem="Maven", project_id=root.project.project_id
    )
    assert management["resolved_versions"] == []
    assert len(management["declarations"]) == 3
    only_profile = service.query_dependencies(
        "com.google.guava:guava", ecosystem="Maven"
    )
    assert len(only_profile["dependencies"]) == 1
    guava = only_profile["dependencies"][0]
    assert guava["resolved_versions"] == [] and guava["purl"] is None
    assert not guava["evidence_complete"]
    assert guava["declarations"][0]["metadata"]["profile"]["id"] == "x"
    profile_assertions = [
        (c, json.loads(prop["value"]))
        for c in bom["components"]
        for prop in c["properties"]
        if prop["name"] == "depcheck:conditional-declaration"
        and json.loads(prop["value"])["metadata"]["maven_kind"]
        in {"profile-dependency", "profile-management"}
    ]
    assert len(profile_assertions) == 9
    for c, assertion in profile_assertions:
        assert not c.get("version") and not c.get("purl")
        # A versionless unconditional managed-only declaration already owns its
        # direct component. Its conditional management adds evidence, not an edge.
        if c["name"] != "example:managed-only":
            assert c["bom-ref"] not in bom["dependencies"][0]["dependsOn"]
        assert assertion["scope"] == "unknown"
        assert assertion["metadata"]["activation"] == "unknown"
        assert assertion["metadata"]["property_context"] == "unevaluated-profile"
    child_id = next(
        b.project.project_id for b in result.bundles if b.project.root == Path("child")
    )
    assert {
        (
            c["name"],
            c.get("version"),
            next(
                p["value"]
                for p in c["properties"]
                if p["name"] == "depcheck:identity:project-id"
            ),
        )
        for c in bom["components"]
        if c["bom-ref"] in bom["dependencies"][0]["dependsOn"]
    } == {
        ("example:conditional-lib", "7", root.project.project_id),
        ("example:managed-only", None, root.project.project_id),
        ("example:conditional-lib", "7", child_id),
        ("example:managed-only", None, child_id),
    }
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before

    # A separate controlled fixture has complete declaration inventory while
    # profile activation remains unknown. It must not imply availability or absence.
    pure = tmp_path.parent / (tmp_path.name + "-profile-only")
    pure.mkdir(exist_ok=True)
    (pure / "pom.xml").write_text(
        "<project><groupId>owner</groupId><artifactId>pure</artifactId><version>1</version><profiles><profile><id>only</id><activation><file><exists>"
        + str(outside)
        + "</exists></file><jdk>[17,)</jdk><property><name>profile-toggle</name><value>on</value></property></activation><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.0-jre</version></dependency></dependencies></profile></profiles></project>",
        encoding="utf-8",
    )
    (pure / "Main.java").write_text(
        "import com.google.common.collect.ImmutableList;\n", encoding="utf-8"
    )
    pure_result = RepositoryScanner(
        osv_client=SimpleNamespace(scan_ecosystem=query)
    ).scan(
        pure,
        RepositoryScanOptions(
            security=True,
            compatibility=False,
            public_maven_packages=("com.google.guava:guava",),
        ),
    )
    pure_bundle = pure_result.bundles[0]
    assert next(c for c in pure_bundle.capabilities if c.name == "manifest").complete
    assert not next(
        c for c in pure_bundle.capabilities if c.name == "resolution"
    ).complete
    assert pure_bundle.declarations[0].metadata["activation"] == "unknown"
    assert not pure_bundle.resolved and not queries
    assert any(
        d.code == "analysis.maven-profile-availability-unknown"
        for d in pure_result.diagnostics
    )
    assert not any(
        f.code == "dependency.missing" and f.package.name == "com.google.guava:guava"
        for f in pure_result.findings
    )


def test_maven_plugin_metadata_expansion_is_bounded(tmp_path):
    plugin = "<plugin><artifactId>maven-compiler-plugin</artifactId><version>1</version></plugin>"
    (tmp_path / "pom.xml").write_text(
        "<project><profiles><profile><id>large</id><activation><property><name>"
        + "x" * 2000
        + "</name></property></activation><build><plugins>"
        + plugin * 7000
        + "</plugins></build></profile></profiles></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declarations = [d for b in result.bundles for d in b.declarations]
    assert 0 < len(declarations) < 7000
    assert any(d.code == "manifest.maven-plugin-budget" for d in result.diagnostics)
    assert not result.capability("dependency_hygiene").complete

    depth = sys.getrecursionlimit() + 100
    (tmp_path / "pom.xml").write_text(
        "<project><profiles><profile><activation><custom>"
        + "<node>" * depth
        + "value"
        + "</node>" * depth
        + "</custom></activation></profile></profiles></project>",
        encoding="utf-8",
    )
    deep = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(d.code == "manifest.invalid" for d in deep.diagnostics)
    assert not next(
        c for c in deep.bundles[0].capabilities if c.name == "manifest"
    ).complete


def test_maven_without_declared_plugins_does_not_imply_complete_build_resolution(
    tmp_path,
):
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency><groupId>example</groupId><artifactId>library</artifactId><version>1</version></dependency></dependencies></project>",
        encoding="utf-8",
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    bundle = result.bundles[0]
    assert [r.version for r in bundle.resolved] == ["1"]
    assert next(c for c in bundle.capabilities if c.name == "manifest").complete
    assert not next(c for c in bundle.capabilities if c.name == "resolution").complete
    assert any(
        d.code == "resolution.maven-build-graph-unknown" for d in bundle.diagnostics
    )


@pytest.mark.parametrize(
    ("extension", "expected"), [("true", "build-extension"), ("${unknown}", "unknown")]
)
def test_maven_namespace_and_plugin_extension_assertions_keep_unicode_positions(
    tmp_path, extension, expected
):
    text = (
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><!--备注--><build><plugins><plugin><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version><extensions>'
        + extension
        + "</extensions></plugin></plugins></build></project>"
    )
    (tmp_path / "pom.xml").write_text(text, encoding="utf-8")
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    declaration = result.bundles[0].declarations[0]
    assert declaration.metadata["classpath"] == expected
    assert (declaration.source.line, declaration.source.column) == (
        1,
        text.index("<plugin>") + 1,
    )
    assert not result.bundles[0].resolved


def test_maven_declarations_and_version_diagnostics_keep_xml_positions(tmp_path):
    (tmp_path / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <!-- <dependency> is a comment, not evidence -->\n"
        "  <dependencies>\n"
        '    <dependency label="a > b">\n'
        "      <groupId>example</groupId><artifactId>library</artifactId>\n"
        "      <version>${unknown}</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    declaration = result.bundles[0].declarations[0]
    assert (declaration.source.line, declaration.source.column) == (4, 5)
    diagnostic = next(
        d for d in result.diagnostics if d.code == "manifest.unsupported-expression"
    )
    assert (diagnostic.source.line, diagnostic.source.column) == (4, 5)
    assert not result.capability("dependency_hygiene").complete


def test_maven_inherited_management_keeps_parent_location(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <groupId>example</groupId><artifactId>parent</artifactId><version>1</version>\n"
        "  <dependencyManagement><dependencies>\n"
        "    <dependency>\n"
        "      <groupId>example</groupId><artifactId>library</artifactId><version>2</version>\n"
        "    </dependency>\n"
        "  </dependencies></dependencyManagement>\n"
        "</project>\n"
    )
    child = tmp_path / "child"
    child.mkdir()
    (child / "pom.xml").write_text(
        "<project>\n"
        "  <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>\n"
        "  <artifactId>child</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId></dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    bundle = next(b for b in result.bundles if b.project.root == Path("child"))
    constraint = next(d for d in bundle.declarations if d.kind == "constraint")
    direct = next(d for d in bundle.declarations if d.kind == "direct")
    assert (
        constraint.source.path,
        constraint.source.line,
        constraint.source.column,
    ) == (tmp_path / "pom.xml", 4, 5)
    assert (direct.source.path, direct.source.line, direct.source.column) == (
        child / "pom.xml",
        5,
        5,
    )
    assert direct.constraint.normalized == "2"

    # Controlled reactor, not a claim about the original my-cloud POMs.
    (tmp_path / "pom.xml").write_text(
        "<project>\n"
        "  <parent><groupId>external</groupId><artifactId>boot-parent</artifactId><version>1</version><relativePath/></parent>\n"
        "  <groupId>example</groupId><artifactId>parent</artifactId><version>1</version>\n"
        "  <modules><module>child</module><module>explicit</module></modules>\n"
        "  <properties><library.version>2</library.version></properties>\n"
        "  <dependencyManagement><dependencies>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId><version>${library.version}</version></dependency>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId><version>${library.version}</version></dependency>\n"
        "    <dependency><groupId>external</groupId><artifactId>bom</artifactId><version>1</version><type>pom</type><scope>import</scope></dependency>\n"
        "  </dependencies></dependencyManagement>\n"
        "</project>\n"
    )
    (child / "pom.xml").write_text(
        "<project>\n"
        "  <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>\n"
        "  <artifactId>child</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId></dependency>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId></dependency>\n"
        "    <dependency><groupId>external</groupId><artifactId>unknown</artifactId></dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    (explicit / "pom.xml").write_text(
        "<project>\n"
        "  <parent><groupId>example</groupId><artifactId>parent</artifactId><version>1</version></parent>\n"
        "  <artifactId>explicit</artifactId>\n"
        "  <dependencies>\n"
        "    <dependency><groupId>example</groupId><artifactId>library</artifactId><version>3</version></dependency>\n"
        "    <dependency><groupId>external</groupId><artifactId>unknown</artifactId></dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    inherited = next(b for b in result.bundles if b.project.root == Path("child"))
    managed = [
        d
        for d in inherited.declarations
        if d.kind == "constraint" and d.package.name == "example:library"
    ]
    assert [
        (d.constraint.raw, d.constraint.normalized, d.source.line) for d in managed
    ] == [("${library.version}", "2", 7), ("${library.version}", "2", 8)]
    requested = [
        d
        for d in inherited.declarations
        if d.kind == "direct" and d.package.name == "example:library"
    ]
    assert [
        (d.constraint.raw, d.constraint.normalized, d.source.line) for d in requested
    ] == [("", "2", 5), ("", "2", 6)]
    assert all(
        d.metadata["managed"] and d.source.path == child / "pom.xml" for d in requested
    )
    override = next(b for b in result.bundles if b.project.root == Path("explicit"))
    direct = next(
        d
        for d in override.declarations
        if d.package.name == "example:library" and d.kind == "direct"
    )
    assert direct.constraint.normalized == "3" and not direct.metadata["managed"]
    unknown = [
        d
        for b in result.bundles
        for d in b.declarations
        if d.package.name == "external:unknown"
    ]
    assert len(unknown) == 2
    assert all(d.constraint.normalized is None for d in unknown)
    assert {
        "manifest.parent-unavailable",
        "manifest.bom-unavailable",
        "manifest.version-unresolved",
    } <= {d.code for d in result.diagnostics}

    service = DependencyAgentService(tmp_path)
    service.index_repository(ecosystems=("maven",))
    cache = tmp_path / ".depcheck/index.sqlite3"
    before = cache.read_bytes(), cache.stat().st_mtime_ns
    page = service.query_dependencies(
        "example:library", ecosystem="Maven", evidence_limit=100
    )
    assert page["count"] == 3
    explanation = service.explain_dependency(
        "example:library", ecosystem="Maven", project_id=inherited.project.project_id
    )
    assert explanation["resolved_versions"] == ["2"]
    assert len(explanation["declarations"]) == 4
    assert {
        (d["kind"], d["location"]["path"], d["location"]["line"])
        for d in explanation["declarations"]
    } == {
        ("constraint", "pom.xml", 7),
        ("constraint", "pom.xml", 8),
        ("direct", "child/pom.xml", 5),
        ("direct", "child/pom.xml", 6),
    }
    assert service.explain_dependency(
        "example:library", ecosystem="Maven", project_id=override.project.project_id
    )["resolved_versions"] == ["3"]
    for owner in [inherited.project.project_id, override.project.project_id]:
        unresolved = service.explain_dependency(
            "external:unknown", ecosystem="Maven", project_id=owner
        )
        assert unresolved["resolved_versions"] == []
        assert len(unresolved["declarations"]) == 1
        assert unresolved["declarations"][0]["constraint"]["normalized"] is None
    assert (cache.read_bytes(), cache.stat().st_mtime_ns) == before
    components = []
    unknown_components = []
    for component in build_cyclonedx(result)["components"]:
        if component["name"] == "external:unknown":
            props = {p["name"]: p["value"] for p in component["properties"]}
            unknown_components.append(
                (props["depcheck:identity:project-id"], component.get("version"))
            )
            assert "purl" not in component
        if component["name"] == "example:library":
            props = {p["name"]: p["value"] for p in component["properties"]}
            components.append(
                (props["depcheck:identity:project-id"], component.get("version"))
            )
            assert "purl" not in component
    # Repeated declarations do not invent multiple installations of one component.
    assert sorted(components) == sorted(
        [(inherited.project.project_id, "2"), (override.project.project_id, "3")]
    )

    assert sorted(unknown_components) == sorted(
        [(inherited.project.project_id, None), (override.project.project_id, None)]
    )


@pytest.mark.parametrize("version", ["", "${external.version}"])
def test_unresolved_maven_managed_versions_are_not_unpinned_findings(tmp_path, version):
    rendered = f"<version>{version}</version>" if version else ""
    (tmp_path / "pom.xml").write_text(
        "<project><dependencyManagement><dependencies><dependency>"
        "<groupId>org.example</groupId><artifactId>platform</artifactId><version>1.0.0</version>"
        "<type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>"
        "<dependencies><dependency><groupId>org.example</groupId><artifactId>managed</artifactId>"
        + rendered
        + "</dependency><dependency><groupId>org.example</groupId><artifactId>floating</artifactId>"
        "<version>[1.0,2.0)</version></dependency></dependencies></project>"
    )
    result = RepositoryScanner().scan(tmp_path, RepositoryScanOptions(security=False))
    assert not result.capability("dependency_hygiene").complete
    assert {
        f.package.name for f in result.findings if f.code == "dependency.unpinned"
    } == {"org.example:floating"}


@pytest.mark.parametrize("parent_version", ["1.0.0", "${revision}"])
def test_maven_parent_mismatch_preserves_child_declarations(tmp_path, parent_version):
    (tmp_path / "pom.xml").write_text(
        """<project>
  <groupId>unrelated</groupId><artifactId>reactor</artifactId><version>1.0.0</version>
  <properties><managed.version>9.9.9</managed.version></properties>
  <dependencyManagement><dependencies><dependency>
    <groupId>example</groupId><artifactId>managed</artifactId><version>9.9.9</version>
  </dependency></dependencies></dependencyManagement>
</project>"""
    )
    child = tmp_path / "component"
    child.mkdir()
    (child / "pom.xml").write_text(
        f"""<project>
  <parent>
    <groupId>external</groupId><artifactId>parent</artifactId><version>{parent_version}</version>
  </parent>
  <artifactId>component</artifactId>
  <dependencies>
    <dependency><groupId>example</groupId><artifactId>pinned</artifactId><version>2.0.0</version></dependency>
    <dependency><groupId>example</groupId><artifactId>managed</artifactId></dependency>
    <dependency><groupId>example</groupId><artifactId>expression</artifactId><version>${{managed.version}}</version></dependency>
  </dependencies>
</project>"""
    )

    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, enabled_ecosystems=("Maven",))
    )
    bundle = next(
        item for item in result.bundles if item.project.root == Path("component")
    )
    direct = {
        item.package.name: item for item in bundle.declarations if item.kind == "direct"
    }

    assert set(direct) == {"example:pinned", "example:managed", "example:expression"}
    assert direct["example:managed"].constraint.normalized is None
    assert direct["example:expression"].constraint.normalized == "${managed.version}"
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("example:pinned", "2.0.0")
    ]
    assert all(
        not item.complete
        for item in bundle.capabilities
        if item.name in {"manifest", "resolution"}
    )
    assert "manifest.parent-coordinate-mismatch" in {
        item.code for item in bundle.diagnostics
    }


def test_maven_management_supplies_version_and_maps_java_usage(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "main" / "java" / "example"
    source.mkdir(parents=True)
    (tmp_path / "pom.xml").write_text(
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement><dependencies><dependency>
    <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
    <version>33.2.1-jre</version>
  </dependency></dependencies></dependencyManagement>
  <dependencies><dependency>
    <groupId>com.google.guava</groupId><artifactId>guava</artifactId>
  </dependency></dependencies>
</project>
""",
        encoding="utf-8",
    )
    (source / "App.java").write_text(
        "package example;\nimport com.google.common.collect.ImmutableList;\n",
        encoding="utf-8",
    )
    pack = create_maven_pack()
    context = ProviderContext(tmp_path)
    project = pack.detector.detect(context)[0]

    bundle = pack.collector.collect(context, project, pack)

    direct = [item for item in bundle.declarations if item.kind == "direct"]
    assert [item.constraint.normalized for item in direct] == ["33.2.1-jre"]
    assert [(item.package.name, item.version) for item in bundle.resolved] == [
        ("com.google.guava:guava", "33.2.1-jre")
    ]
    assert bundle.usages[0].mapped_package.name == "com.google.guava:guava"


def test_maven_public_lookup_requires_caller_coordinate_assertion(tmp_path):
    from depcheck.security.osv_client import OSVScanResult

    (tmp_path / "pom.xml").write_text(
        "<project><repositories><repository><url>https://private.example</url></repository></repositories><dependencies><dependency><groupId>example</groupId><artifactId>private</artifactId><version>1</version></dependency></dependencies></project>"
    )
    queries = []

    def query(packages, ecosystem):
        queries.append((packages, ecosystem))
        return OSVScanResult({}, (), packages)

    scanner = RepositoryScanner(osv_client=SimpleNamespace(scan_ecosystem=query))
    blocked = scanner.scan(
        tmp_path, RepositoryScanOptions(security=True, compatibility=False)
    )
    assert not queries
    assert blocked.bundles[0].resolved[0].package.purl is None
    assert any(
        item.code == "security.identity-unverified" for item in blocked.diagnostics
    )
    scanner.scan(
        tmp_path,
        RepositoryScanOptions(
            security=True,
            compatibility=False,
            public_maven_packages=("example:private",),
        ),
    )
    assert queries == [({"example:private": "1"}, "Maven")]
    with pytest.raises(ValueError, match="exact"):
        scanner.scan(
            tmp_path, RepositoryScanOptions(public_maven_packages=("example:x:y",))
        )


def test_maven_dependency_expansion_uses_one_parse_budget(tmp_path):
    dependency = "<dependency><groupId>example</groupId><artifactId>lib</artifactId><version>${large}</version></dependency>"
    (tmp_path / "pom.xml").write_text(
        "<project><properties><large>"
        + "1" * 10000
        + "</large></properties><dependencies>"
        + "".join(
            dependency.replace(
                "<artifactId>lib</artifactId>", f"<artifactId>lib{i}</artifactId>"
            )
            for i in range(1000)
        )
        + "</dependencies></project>"
    )
    result = RepositoryScanner().scan(
        tmp_path, RepositoryScanOptions(security=False, compatibility=False)
    )
    assert any(
        item.code == "manifest.invalid" and "budget" in item.message
        for item in result.diagnostics
    )
    assert not result.capability("dependency_hygiene").complete
