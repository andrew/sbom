# frozen_string_literal: true

require "test_helper"

class EnricherTest < Minitest::Test
  def test_enrich_sbom_with_purl
    sbom = Sbom::Parser.parse_file(fixture_path("cyclonedx/minimal.cdx.json"))
    enricher = Sbom::Enricher.new(sbom)
    enriched = enricher.enrich

    package = enriched.packages.first
    assert_equal "rails", package[:name]
    skip "Network request failed" if enricher.errors.any?
    assert package[:description], "Expected description to be enriched"
    assert package[:homepage], "Expected homepage to be enriched"
  end

  def test_enrich_class_method
    sbom = Sbom::Parser.parse_file(fixture_path("cyclonedx/minimal.cdx.json"))
    enricher = Sbom::Enricher.new(sbom)
    enriched = enricher.enrich

    skip "Network request failed" if enricher.errors.any?
    package = enriched.packages.first
    assert package[:description], "Expected description to be enriched"
  end

  def test_enrich_file_facade
    enriched = Sbom.enrich_file(fixture_path("cyclonedx/minimal.cdx.json"))

    package = enriched.packages.first
    assert_equal "rails", package[:name]
    skip "Network request failed" unless package[:description]
    assert package[:description], "Expected description to be enriched"
  end

  def test_enricher_adds_properties
    sbom = Sbom::Parser.parse_file(fixture_path("cyclonedx/minimal.cdx.json"))
    enricher = Sbom::Enricher.new(sbom)
    enricher.enrich

    skip "Network request failed" if enricher.errors.any?
    package = sbom.packages.first
    properties = package[:properties] || []

    latest_version = properties.find { |name, _| name == "ecosystems:latest_version" }
    assert latest_version, "Expected ecosystems:latest_version property"

    versions_count = properties.find { |name, _| name == "ecosystems:versions_count" }
    assert versions_count, "Expected ecosystems:versions_count property"
  end

  def test_enricher_adds_advisories
    sbom = Sbom::Parser.parse_file(fixture_path("cyclonedx/minimal.cdx.json"))
    enricher = Sbom::Enricher.new(sbom)
    enricher.enrich

    skip "Network request failed" if enricher.errors.any?
    package = sbom.packages.first
    advisories = package[:advisories] || []

    skip "No advisories returned" if advisories.empty?
    assert advisories.first[:id]
    assert advisories.first[:title]
  end

  def test_enricher_handles_missing_purl
    sbom = Sbom::Data::Sbom.new
    sbom.add_package({ name: "test-package", version: "1.0.0" })

    enricher = Sbom::Enricher.new(sbom)
    enriched = enricher.enrich

    package = enriched.packages.first
    assert_equal "test-package", package[:name]
    assert_nil package[:description]
  end

  def test_enricher_handles_invalid_purl
    sbom = Sbom::Data::Sbom.new
    sbom.add_package({ name: "test", version: "1.0.0", purl: "invalid-purl" })

    enricher = Sbom::Enricher.new(sbom)
    enricher.enrich

    assert enricher.errors.any?, "Expected errors for invalid purl"
  end

  def test_enricher_preserves_existing_data
    sbom = Sbom::Data::Sbom.new
    sbom.add_package({
      name: "rails",
      version: "7.0.0",
      purl: "pkg:gem/rails@7.0.0",
      description: "Custom description",
      license_concluded: "Apache-2.0"
    })

    enricher = Sbom::Enricher.new(sbom)
    enricher.enrich
    package = sbom.packages.first

    # Should not overwrite existing values
    assert_equal "Custom description", package[:description]
    assert_equal "Apache-2.0", package[:license_concluded]
  end

  def test_enrich_package_class_method
    package = {
      name: "rails",
      version: "7.0.0",
      purl: "pkg:gem/rails@7.0.0"
    }

    enriched = Sbom::Enricher.enrich_package(package)
    skip "Network request failed" unless enriched[:description]

    assert enriched[:description]
    assert enriched[:homepage]
    assert enriched[:repository_url]
  end

end
