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

  def test_cyclonedx_vulnerabilities_full
    vulnerabilities = [
      {
        id: "CVE-2024-1234",
        source: { name: "NVD", url: "https://nvd.nist.gov/" },
        ratings: [
          { severity: "high", score: 8.1, method: "CVSSv31" }
        ],
        description: "A critical vulnerability in lodash",
        affects: [
          { ref: "pkg:npm/lodash@4.17.20" }
        ],
        published: "2024-01-15T00:00:00Z",
        updated: "2024-01-20T12:00:00Z"
      }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    assert data["vulnerabilities"]
    assert_equal 1, data["vulnerabilities"].count

    vuln = data["vulnerabilities"].first
    assert_equal "CVE-2024-1234", vuln["id"]
    assert_equal "NVD", vuln["source"]["name"]
    assert_equal "https://nvd.nist.gov/", vuln["source"]["url"]
    assert_equal 1, vuln["ratings"].count
    assert_equal "high", vuln["ratings"].first["severity"]
    assert_equal 8.1, vuln["ratings"].first["score"]
    assert_equal "CVSSv31", vuln["ratings"].first["method"]
    assert_equal "A critical vulnerability in lodash", vuln["description"]
    assert_equal 1, vuln["affects"].count
    assert_equal "pkg:npm/lodash@4.17.20", vuln["affects"].first["ref"]
    assert_equal "2024-01-15T00:00:00Z", vuln["published"]
    assert_equal "2024-01-20T12:00:00Z", vuln["updated"]
  end

  def test_cyclonedx_vulnerabilities_minimal
    vulnerabilities = [
      { id: "GHSA-1234-5678-9012" }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    assert data["vulnerabilities"]
    vuln = data["vulnerabilities"].first
    assert_equal "GHSA-1234-5678-9012", vuln["id"]
    assert_nil vuln["source"]
    assert_nil vuln["ratings"]
    assert_nil vuln["description"]
    assert_nil vuln["affects"]
  end

  def test_cyclonedx_vulnerabilities_empty_array_omitted
    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: [] })

    data = JSON.parse(generator.output)
    refute data.key?("vulnerabilities")
  end

  def test_cyclonedx_vulnerabilities_nil_omitted
    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {} })

    data = JSON.parse(generator.output)
    refute data.key?("vulnerabilities")
  end

  def test_cyclonedx_vulnerabilities_multiple_ratings
    vulnerabilities = [
      {
        id: "CVE-2024-5678",
        ratings: [
          { severity: "critical", score: 9.8, method: "CVSSv31" },
          { severity: "high", score: 8.5, method: "CVSSv2" }
        ]
      }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)
    vuln = data["vulnerabilities"].first

    assert_equal 2, vuln["ratings"].count
    assert_equal "critical", vuln["ratings"][0]["severity"]
    assert_equal "high", vuln["ratings"][1]["severity"]
  end

  def test_cyclonedx_vulnerabilities_multiple_affects
    vulnerabilities = [
      {
        id: "CVE-2024-9999",
        affects: [
          { ref: "pkg:npm/lodash@4.17.20" },
          { ref: "pkg:npm/lodash@4.17.19" }
        ]
      }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)
    vuln = data["vulnerabilities"].first

    assert_equal 2, vuln["affects"].count
    assert_equal "pkg:npm/lodash@4.17.20", vuln["affects"][0]["ref"]
    assert_equal "pkg:npm/lodash@4.17.19", vuln["affects"][1]["ref"]
  end

  def test_cyclonedx_vulnerabilities_skips_without_id
    vulnerabilities = [
      { description: "Missing ID vulnerability" },
      { id: "CVE-2024-1111" }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    assert_equal 1, data["vulnerabilities"].count
    assert_equal "CVE-2024-1111", data["vulnerabilities"].first["id"]
  end
end
