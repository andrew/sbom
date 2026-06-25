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

  def test_cyclonedx_vulnerability_analysis
    vulnerabilities = [
      {
        id: "CVE-2024-1234",
        analysis: {
          state: "resolved",
          justification: "code_not_reachable",
          response: ["update"],
          detail: "Patched by distro",
          first_issued: "2024-01-15T00:00:00Z",
          last_updated: "2024-01-20T12:00:00Z"
        }
      }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)
    analysis = data["vulnerabilities"].first["analysis"]

    assert_equal "resolved", analysis["state"]
    assert_equal "code_not_reachable", analysis["justification"]
    assert_equal ["update"], analysis["response"]
    assert_equal "Patched by distro", analysis["detail"]
    assert_equal "2024-01-15T00:00:00Z", analysis["firstIssued"]
    assert_equal "2024-01-20T12:00:00Z", analysis["lastUpdated"]
  end

  def test_cyclonedx_vulnerability_analysis_partial
    vulnerabilities = [
      { id: "CVE-2024-1234", analysis: { state: "in_triage" } }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    assert_equal({ "state" => "in_triage" }, data["vulnerabilities"].first["analysis"])
  end

  def test_cyclonedx_vulnerability_analysis_response_scalar_wrapped
    vulnerabilities = [
      { id: "CVE-2024-1234", analysis: { response: "will_not_fix" } }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    assert_equal ["will_not_fix"], data["vulnerabilities"].first["analysis"]["response"]
  end

  def test_cyclonedx_vulnerability_analysis_empty_omitted
    vulnerabilities = [
      { id: "CVE-2024-1234", analysis: {} }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: {}, vulnerabilities: vulnerabilities })

    data = JSON.parse(generator.output)

    refute data["vulnerabilities"].first.key?("analysis")
  end

  def test_cyclonedx_component_pedigree_patches
    packages = [
      {
        name: "libquicktime",
        version: "1.2.4",
        purl: "pkg:brew/libquicktime@1.2.4",
        pedigree: {
          patches: [
            {
              type: "backport",
              diff: { url: "https://deb.debian.org/.../libquicktime_1.2.4-12.debian.tar.xz" },
              resolves: [
                { type: "security", id: "CVE-2016-2399", source: { name: "NVD" } },
                { type: "security", id: "CVE-2017-9122", references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-9122"] }
              ]
            },
            {
              type: "unofficial",
              resolves: [
                { type: "defect", id: "https://github.com/foo/bar/issues/1", name: "build fix" }
              ]
            }
          ],
          notes: "Debian-maintained patch set"
        }
      }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: packages })

    data = JSON.parse(generator.output)
    pedigree = data["components"].first["pedigree"]

    assert_equal "Debian-maintained patch set", pedigree["notes"]
    assert_equal 2, pedigree["patches"].count

    p1 = pedigree["patches"][0]
    assert_equal "backport", p1["type"]
    assert_equal "https://deb.debian.org/.../libquicktime_1.2.4-12.debian.tar.xz", p1["diff"]["url"]
    refute p1["diff"].key?("text")
    assert_equal 2, p1["resolves"].count
    assert_equal "security", p1["resolves"][0]["type"]
    assert_equal "CVE-2016-2399", p1["resolves"][0]["id"]
    assert_equal "NVD", p1["resolves"][0]["source"]["name"]
    assert_equal ["https://nvd.nist.gov/vuln/detail/CVE-2017-9122"], p1["resolves"][1]["references"]

    p2 = pedigree["patches"][1]
    assert_equal "unofficial", p2["type"]
    refute p2.key?("diff")
    assert_equal "defect", p2["resolves"][0]["type"]
    assert_equal "build fix", p2["resolves"][0]["name"]
  end

  def test_cyclonedx_component_pedigree_omitted_when_empty
    packages = [
      { name: "x", version: "1", pedigree: {} },
      { name: "y", version: "1" }
    ]

    generator = Sbom::Generator.new(sbom_type: :cyclonedx, format: :json)
    generator.generate("Test Project", { packages: packages })

    data = JSON.parse(generator.output)

    refute data["components"][0].key?("pedigree")
    refute data["components"][1].key?("pedigree")
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
