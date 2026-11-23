# frozen_string_literal: true

require "test_helper"
require "tempfile"
require "timeout"

class ParseCostTest < Minitest::Test
  DEEP_YAML = "SPDXID: SPDXRef-DOCUMENT\nx: #{"[" * 200_000}#{"]" * 200_000}\n"

  def test_deeply_nested_yaml_file_is_rejected_quickly
    Tempfile.create(["deep", ".spdx.yaml"]) do |file|
      file.write(DEEP_YAML)
      file.flush

      error = Timeout.timeout(5) { assert_raises(Sbom::ParserError) { Sbom.parse_file(file.path) } }
      assert_match "nested deeper than 100 levels", error.message
      assert_includes Timeout.timeout(5) { Sbom.validate_file(file.path) }.errors.first, "nested deeper"
    end
  end

  def test_deeply_nested_yaml_is_rejected_quickly_when_the_format_is_detected
    Timeout.timeout(5) { assert_raises(Sbom::ParserError) { Sbom.parse_string(DEEP_YAML) } }
  end

  def test_deeply_nested_yaml_is_rejected_when_only_the_sbom_type_is_given
    content = "SPDXID: SPDXRef-DOCUMENT\nx: #{"[" * 200}#{"]" * 200}\npackages:\n- name: a\n  SPDXID: SPDXRef-a\n"

    assert_raises(Sbom::ParserError) { Sbom.parse_string(content, sbom_type: :spdx) }
  end

  def test_yaml_at_the_depth_limit_still_loads
    nested = "#{"[" * 99}#{"]" * 99}"

    assert_equal "SPDXRef-DOCUMENT", Sbom::YamlLoader.safe_load("SPDXID: SPDXRef-DOCUMENT\nx: #{nested}\n")["SPDXID"]
    assert_raises(Sbom::ParserError) { Sbom::YamlLoader.safe_load("x: [#{nested}]\n") }
  end

  def test_cyclonedx_xml_fields_are_read_from_child_elements
    sbom = Sbom.parse_string(<<~XML)
      <bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:other="urn:other" version="1">
        <metadata>
          <timestamp>2026-01-01T00:00:00Z</timestamp>
          <component type="application" bom-ref="root"><name>app</name><version>2.0.0</version></component>
          <supplier><name>Example Org</name></supplier>
        </metadata>
        <components>
          <component type="library" bom-ref="a">
            <other:name>ignored</other:name>
            <name>a</name>
            <version>1.0.0</version>
            <description>first</description>
            <supplier><name>A Corp</name></supplier>
            <hashes><hash alg="SHA-256">#{"a" * 64}</hash><hash alg="SHA-1">#{"b" * 40}</hash></hashes>
            <licenses><license><id>MIT</id></license></licenses>
            <purl>pkg:npm/a@1.0.0</purl>
            <externalReferences><reference type="vcs"><url>https://example.com/a</url></reference></externalReferences>
            <components><component type="library" bom-ref="b"><name>b</name><version>2.0.0</version></component></components>
          </component>
        </components>
        <dependencies>
          <dependency ref="root"><dependency ref="a"/><dependency ref="b"/></dependency>
        </dependencies>
      </bom>
    XML

    assert_equal "app", sbom.document[:name]
    assert_equal %w[a b], sbom.packages.map { |package| package[:name] }

    package = sbom.packages.first
    assert_equal "1.0.0", package[:version]
    assert_equal "first", package[:description]
    assert_equal "MIT", package[:license_concluded]
    assert_equal %w[SHA256 SHA1], package[:checksums].map(&:first)
    assert_equal [%w[PACKAGE_MANAGER purl pkg:npm/a@1.0.0], %w[vcs vcs https://example.com/a]], package[:external_references]
    assert_equal %w[a b], sbom.relationships.map { |relationship| relationship[:target] }
  end

  def test_prefixed_xml_elements_match_only_in_the_default_namespace
    uri = "http://cyclonedx.org/schema/bom/1.6"
    components = '<c:components><c:component type="library"><c:name>a</c:name><c:version>1</c:version></c:component>' \
                 "<o:component><o:name>other</o:name></o:component></c:components>"

    both = Sbom.parse_string(%(<bom xmlns="#{uri}" xmlns:c="#{uri}" xmlns:o="urn:other">#{components}</bom>))
    assert_equal ["a"], both.packages.map { |package| package[:name] }

    prefix_only = Sbom.parse_string(%(<c:bom xmlns:c="#{uri}" xmlns:o="urn:other">#{components}</c:bom>), sbom_type: :cyclonedx)
    assert_empty prefix_only.packages
  end
end
