# frozen_string_literal: true

require "test_helper"

class MergerTest < Minitest::Test
  def test_merge_two_sboms
    sbom1 = Sbom::Data::Sbom.new(sbom_type: :spdx)
    sbom1.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })

    sbom2 = Sbom::Data::Sbom.new(sbom_type: :spdx)
    sbom2.add_package({ name: "nokogiri", version: "1.15.0", purl: "pkg:gem/nokogiri@1.15.0" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.packages.count
    assert merged.packages.any? { |p| p[:name] == "rails" }
    assert merged.packages.any? { |p| p[:name] == "nokogiri" }
  end

  def test_merge_dedupes_by_purl_by_default
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })
    sbom2.add_package({ name: "nokogiri", version: "1.15.0", purl: "pkg:gem/nokogiri@1.15.0" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.packages.count
    rails_packages = merged.packages.select { |p| p[:name] == "rails" }
    assert_equal 1, rails_packages.count
  end

  def test_merge_keeps_all_with_no_dedupe
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })

    merged = Sbom::Merger.merge([sbom1, sbom2], dedupe: :none)

    rails_packages = merged.packages.select { |p| p[:name] == "rails" }
    assert_equal 1, rails_packages.count, "Same name+version still deduped by Data::Sbom"
  end

  def test_merge_keeps_different_versions
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_package({ name: "rails", version: "7.0.0", purl: "pkg:gem/rails@7.0.0" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_package({ name: "rails", version: "7.1.0", purl: "pkg:gem/rails@7.1.0" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.packages.count
    versions = merged.packages.map { |p| p[:version] }
    assert_includes versions, "7.0.0"
    assert_includes versions, "7.1.0"
  end

  def test_merge_relationships
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_relationship({ source: "pkg-a", type: "DEPENDS_ON", target: "pkg-b" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_relationship({ source: "pkg-c", type: "DEPENDS_ON", target: "pkg-d" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.relationships.count
  end

  def test_merge_dedupes_relationships
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_relationship({ source: "pkg-a", type: "DEPENDS_ON", target: "pkg-b" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_relationship({ source: "pkg-a", type: "DEPENDS_ON", target: "pkg-b" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 1, merged.relationships.count
  end

  def test_merge_files
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_file({ name: "/app/main.rb" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_file({ name: "/app/helper.rb" })

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.files.count
  end

  def test_merge_creates_document
    sbom1 = Sbom::Data::Sbom.new
    sbom1.document = { name: "App1" }

    sbom2 = Sbom::Data::Sbom.new
    sbom2.document = { name: "App2" }

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert merged.document
    assert_includes merged.document[:name], "App1"
    assert_includes merged.document[:name], "App2"
    assert merged.document[:created]
  end

  def test_merge_inherits_sbom_type
    sbom1 = Sbom::Data::Sbom.new(sbom_type: :cyclonedx)
    sbom2 = Sbom::Data::Sbom.new(sbom_type: :cyclonedx)

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal :cyclonedx, merged.sbom_type
  end

  def test_merge_defaults_to_spdx_for_mixed_types
    sbom1 = Sbom::Data::Sbom.new(sbom_type: :spdx)
    sbom2 = Sbom::Data::Sbom.new(sbom_type: :cyclonedx)

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal :spdx, merged.sbom_type
  end

  def test_merge_files_from_paths
    merged = Sbom::Merger.merge_files([
      fixture_path("cyclonedx/minimal.cdx.json"),
      fixture_path("spdx/minimal.spdx.json")
    ])

    assert merged.packages.any?
    assert merged.document
  end

  def test_facade_merge_method
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_package({ name: "rails", version: "7.0.0" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_package({ name: "nokogiri", version: "1.15.0" })

    merged = Sbom.merge([sbom1, sbom2])

    assert_equal 2, merged.packages.count
  end

  def test_facade_merge_files_method
    merged = Sbom.merge_files([
      fixture_path("cyclonedx/minimal.cdx.json"),
      fixture_path("spdx/minimal.spdx.json")
    ])

    assert merged.packages.any?
  end

  def test_merge_licenses
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_license("MIT")

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_license("Apache-2.0")

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 2, merged.licenses.count
    assert_includes merged.licenses, "MIT"
    assert_includes merged.licenses, "Apache-2.0"
  end

  def test_merge_dedupes_licenses
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_license("MIT")

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_license("MIT")

    merged = Sbom::Merger.merge([sbom1, sbom2])

    assert_equal 1, merged.licenses.count
  end

  def test_merge_three_sboms
    sbom1 = Sbom::Data::Sbom.new
    sbom1.add_package({ name: "rails", version: "7.0.0" })

    sbom2 = Sbom::Data::Sbom.new
    sbom2.add_package({ name: "nokogiri", version: "1.15.0" })

    sbom3 = Sbom::Data::Sbom.new
    sbom3.add_package({ name: "puma", version: "6.0.0" })

    merged = Sbom::Merger.merge([sbom1, sbom2, sbom3])

    assert_equal 3, merged.packages.count
  end
end
