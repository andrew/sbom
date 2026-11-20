# frozen_string_literal: true

require "test_helper"
require "tempfile"

class CompatibilityTest < Minitest::Test
  def document
    { "bomFormat" => "CycloneDX", "specVersion" => "1.6",
      "metadata" => { "component" => { "name" => "app", "bom-ref" => "app-id" } },
      "components" => %w[one two].map { |id| { "name" => "same", "version" => "1", "bom-ref" => id } },
      "dependencies" => [{ "ref" => "app-id", "dependsOn" => %w[one two] }] }
  end

  def test_default_serialization_keeps_public_package_keys_and_relationships
    input = document
    input["components"].first["components"] = [{ "name" => "nested", "bom-ref" => "nested" }]
    bom = Sbom.parse_string(JSON.generate(input))
    assert_equal "two", bom.to_h[:packages][["same", "1"]][:id]
    refute bom.document.key?(:component_id)
    serialized = JSON.parse(JSON.generate(bom.to_h))
    assert serialized["packages"].key?('["same", "1"]')
    assert_equal "DEPENDS_ON", bom.relationships.first[:type]

    instances = Sbom.parse_string(JSON.generate(input), preserve_instances: true)
    assert_equal 3, instances.packages.size
    assert_equal "CONTAINS", instances.relationships.first[:type]
    assert_equal "app-id", instances.document[:component_id]
  end

  def test_default_add_package_replaces_name_version_when_metadata_changes
    bom = Sbom::Data::Sbom.new
    bom.add_package(name: "same", version: "1", id: "one")
    bom.add_package(name: "same", version: "1", id: "two", purl: "pkg:npm/same@1")
    assert_equal 1, bom.packages.size
    assert_equal "two", bom.to_h[:packages][["same", "1"]][:id]

    instances = Sbom::Data::Sbom.new(preserve_instances: true)
    %w[one two].each { |id| instances.add_package(name: "same", version: "1", id: id) }
    assert_equal 2, instances.packages.size
  end

  def test_autodetection_fallback_and_format_parsers_receive_opt_in
    spdx = { "spdxVersion" => "SPDX-2.3", "name" => "app",
      "packages" => %w[one two].map { |id| { "name" => "same", "versionInfo" => "1", "SPDXID" => id } } }
    wrapped = JSON.generate("sbom" => spdx)
    xml = '<bom><components><component bom-ref="one"><name>same</name><version>1</version></component><component bom-ref="two"><name>same</name><version>1</version></component></components></bom>'
    [wrapped, spdx.to_yaml, xml].each do |content|
      assert_equal 1, Sbom.parse_string(content).packages.size
      assert_equal 2, Sbom.parse_string(content, preserve_instances: true).packages.size
    end
    assert_equal 2, Sbom::Parser.new(preserve_instances: true).parse_string(wrapped).packages.size
    assert_equal 2, Sbom::Spdx::Parser.new(preserve_instances: true).parse(spdx.to_yaml, :yaml).packages.size
    assert_equal 2, Sbom::Cyclonedx::Parser.new(preserve_instances: true).parse(xml, :xml).packages.size
  end

  def test_file_parsing_preserves_instances_only_when_requested
    Tempfile.create(["app", ".cdx.json"]) do |file|
      file.write(JSON.generate(document))
      file.flush
      assert_equal 1, Sbom.parse_file(file.path).packages.size
      instances = Sbom.parse_file(file.path, preserve_instances: true)
      assert_equal %w[one two], instances.packages.map { |pkg| pkg[:id] }
      assert_equal 2, instances.to_h[:packages].size
    end
  end
end
