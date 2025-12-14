# frozen_string_literal: true

require "test_helper"

class GeneratorTest < Minitest::Test
  def test_generate_spdx_json
    generator = Sbom::Generator.new(sbom_type: :spdx, format: :json)
    generator.generate("Test Project", { packages: {} })

    output = generator.output
    data = JSON.parse(output)

    assert_equal "SPDX-2.3", data["spdxVersion"]
    assert_equal "Test Project", data["name"]
  end

  def test_generate_cyclonedx_json
    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {} })

    output = generator.output
    data = JSON.parse(output)

    assert_equal "CycloneDX", data["bomFormat"]
    assert_equal "1.6", data["specVersion"]
  end

  def test_generator_sbom_type
    spdx_gen = Sbom::Generator.new(sbom_type: :spdx)
    cdx_gen = Sbom::Generator.new(sbom_type: :cyclonedx)

    assert_equal :spdx, spdx_gen.sbom_type
    assert_equal :cyclonedx, cdx_gen.sbom_type
  end

  def test_generator_format
    json_gen = Sbom::Generator.new(sbom_type: :spdx, format: :json)
    tag_gen = Sbom::Generator.new(sbom_type: :spdx, format: :tag)

    assert_equal :json, json_gen.format
    assert_equal :tag, tag_gen.format
  end

  def test_generate_with_packages
    packages = {
      "rails" => { name: "rails", version: "7.0.0", license_concluded: "MIT" }
    }

    generator = Sbom::Generator.new(sbom_type: :spdx, format: :json)
    generator.generate("Test", { packages: packages })

    data = JSON.parse(generator.output)
    assert_equal 1, data["packages"].count
    assert_equal "rails", data["packages"].first["name"]
  end

  def test_to_h
    generator = Sbom::Generator.new(sbom_type: :spdx, format: :json)
    generator.generate("Test Project", { packages: {} })

    hash = generator.to_h
    assert_kind_of Hash, hash
    assert_equal "SPDX-2.3", hash["spdxVersion"]
  end

  def test_class_method_generate
    gen = Sbom::Generator.generate("Test", { packages: {} }, sbom_type: :spdx)
    assert_kind_of Sbom::Generator, gen
    refute_nil gen.output
  end
end
