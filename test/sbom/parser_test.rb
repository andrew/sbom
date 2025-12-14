# frozen_string_literal: true

require "test_helper"

class ParserTest < Minitest::Test
  def test_parse_spdx_json_file
    file = fixture_path("spdx/minimal.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert_equal "SPDX-2.3", sbom.version
    assert_equal 1, sbom.packages.count
    assert_equal "rails", sbom.packages.first[:name]
    assert_equal "7.0.0", sbom.packages.first[:version]
  end

  def test_parse_cyclonedx_json_file
    file = fixture_path("cyclonedx/minimal.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert_equal "1.6", sbom.version
    assert_equal 1, sbom.packages.count
    assert_equal "rails", sbom.packages.first[:name]
  end

  def test_parse_file_not_found
    assert_raises(Sbom::ParserError) do
      Sbom::Parser.parse_file("nonexistent.json")
    end
  end

  def test_parse_string_spdx
    content = File.read(fixture_path("spdx/minimal.spdx.json"))
    sbom = Sbom::Parser.parse_string(content)

    assert_equal :spdx, sbom.sbom_type
    assert_equal 1, sbom.packages.count
  end

  def test_parse_string_cyclonedx
    content = File.read(fixture_path("cyclonedx/minimal.cdx.json"))
    sbom = Sbom::Parser.parse_string(content)

    assert_equal :cyclonedx, sbom.sbom_type
    assert_equal 1, sbom.packages.count
  end

  def test_auto_detection_from_content
    spdx_content = File.read(fixture_path("spdx/minimal.spdx.json"))
    cdx_content = File.read(fixture_path("cyclonedx/minimal.cdx.json"))

    spdx = Sbom::Parser.parse_string(spdx_content, sbom_type: :auto)
    cdx = Sbom::Parser.parse_string(cdx_content, sbom_type: :auto)

    assert_equal :spdx, spdx.sbom_type
    assert_equal :cyclonedx, cdx.sbom_type
  end
end
