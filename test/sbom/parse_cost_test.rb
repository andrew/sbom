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
end
