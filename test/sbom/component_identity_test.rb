# frozen_string_literal: true

require "test_helper"

class ComponentIdentityTest < Minitest::Test
  def test_cyclonedx_retains_component_instances_versions_and_purls
    components = [
      { "type" => "library", "name" => "same", "version" => "1", "bom-ref" => "first", "purl" => "pkg:npm/same@1" },
      { "type" => "library", "name" => "same", "version" => "1", "bom-ref" => "second", "purl" => "pkg:npm/same@1" },
      { "type" => "library", "name" => "same", "version" => "2", "bom-ref" => "third", "purl" => "pkg:npm/same@2" },
      { "type" => "library", "name" => "same", "version" => "1", "purl" => "pkg:gem/same@1" },
      { "type" => "library", "name" => "same", "version" => "1", "purl" => "pkg:pypi/same@1" }
    ]
    document = { "bomFormat" => "CycloneDX", "specVersion" => "1.6", "components" => components,
      "metadata" => { "component" => { "name" => "app", "type" => "application", "bom-ref" => "app-id" } },
      "dependencies" => [{ "ref" => "app-id", "dependsOn" => %w[first second third] }] }
    bom = Sbom.parse_string(JSON.generate(document), preserve_instances: true)
    assert_equal 5, bom.packages.size
    assert_equal %w[first second third], bom.packages.filter_map { |package| package[:id] }
    assert_equal "app-id", bom.document[:component_id]
    assert_equal %w[first second third], bom.relationships.map { |rel| rel[:target] }
  end

  def test_cyclonedx_xml_preserves_duplicate_instances_and_root
    bom = Sbom.parse_string(<<~XML, preserve_instances: true)
      <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
        <metadata><component type="application" bom-ref="app"><name>app</name></component></metadata>
        <components>
          <component type="library" bom-ref="one"><name>same</name><version>1</version></component>
          <component type="library" bom-ref="two"><name>same</name><version>1</version></component>
        </components>
        <dependencies><dependency ref="app"><dependency ref="one"/><dependency ref="two"/></dependency></dependencies>
      </bom>
    XML
    assert_equal %w[one two], bom.packages.map { |package| package[:id] }
    assert_equal "app", bom.document[:component_id]
    assert_equal %w[one two], bom.relationships.map { |rel| rel[:target] }
  end

  def test_spdx_json_and_tag_value_preserve_referenced_instances
    document = { "spdxVersion" => "SPDX-2.3", "SPDXID" => "SPDXRef-DOCUMENT", "name" => "example",
      "packages" => %w[one two].map { |id| { "name" => "same", "versionInfo" => "1", "SPDXID" => id } },
      "relationships" => [{ "spdxElementId" => "one", "relationshipType" => "DEPENDS_ON", "relatedSpdxElement" => "two" }] }
    tag = "SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nDocumentName: example\n\n" +
      %w[one two].map { |id| "PackageName: same\nSPDXID: #{id}\nPackageVersion: 1\n\n" }.join +
      "Relationship: one DEPENDS_ON two\n"
    [JSON.generate(document), tag].each do |content|
      bom = Sbom.parse_string(content, preserve_instances: true)
      assert_equal %w[one two], bom.packages.map { |package| package[:id] }
      assert_equal "one", bom.relationships.first[:source_id]
      assert_equal "two", bom.relationships.first[:target_id]
    end
  end

  def test_nested_components_are_containment_not_dependency_edges
    document = { "bomFormat" => "CycloneDX", "specVersion" => "1.6", "components" => [
      { "name" => "outer", "bom-ref" => "outer", "components" => [{ "name" => "inner", "bom-ref" => "inner" }] }
    ] }
    bom = Sbom.parse_string(JSON.generate(document), preserve_instances: true)
    assert_equal 2, bom.packages.size
    assert_equal [{ source: "outer", target: "inner", type: "CONTAINS" }], bom.relationships
  end

  def test_package_addition_retains_identities_but_replaces_the_same_record
    bom = Sbom::Data::Sbom.new(preserve_instances: true)
    %w[one two].each { |id| bom.add_package(name: "same", version: "1", id: id) }
    bom.add_package(name: "same", version: "1", id: "two", description: "updated")
    assert_equal 2, bom.packages.size
    assert_equal "updated", bom.packages.last[:description]
  end
end
