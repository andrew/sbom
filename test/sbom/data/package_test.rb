# frozen_string_literal: true

require "test_helper"

class PackageTest < Minitest::Test
  def setup
    @package = Sbom::Data::Package.new
  end

  def test_name
    @package.name = "rails"
    assert_equal "rails", @package.name
  end

  def test_version
    @package.name = "rails"
    @package.version = "7.0.0"
    assert_equal "7.0.0", @package.version
    assert_equal "rails_7.0.0", @package.id
  end

  def test_package_type_normalization
    @package.package_type = "library"
    assert_equal "LIBRARY", @package.package_type
  end

  def test_checksum
    @package.add_checksum("SHA256", "abc123def456abc123def456abc123def456abc123def456abc123def456abc1")
    assert_equal 1, @package.checksums.count
    assert_equal ["SHA256", "abc123def456abc123def456abc123def456abc123def456abc123def456abc1"], @package.checksums.first
  end

  def test_invalid_checksum_rejected
    @package.add_checksum("SHA256", "invalid")
    assert_equal 0, @package.checksums.count
  end

  def test_purl
    @package.purl = "pkg:gem/rails@7.0.0"
    assert_equal "pkg:gem/rails@7.0.0", @package.purl
  end

  def test_parsed_purl
    @package.purl = "pkg:gem/rails@7.0.0"
    assert_equal "gem", @package.purl_type
    assert_equal "rails", @package.purl_name
    assert_equal "7.0.0", @package.purl_version
  end

  def test_generate_purl
    @package.name = "rails"
    @package.version = "7.0.0"
    purl = @package.generate_purl(type: "gem")
    assert_equal "pkg:gem/rails@7.0.0", purl
    assert_equal purl, @package.purl
  end

  def test_generate_purl_with_namespace
    @package.name = "core"
    @package.version = "16.0.0"
    purl = @package.generate_purl(type: "npm", namespace: "@angular")
    assert_equal "pkg:npm/%40angular/core@16.0.0", purl
  end

  def test_external_references
    @package.add_external_reference("vcs", "website", "https://github.com/rails/rails")
    assert_equal 1, @package.external_references.count
  end

  def test_license
    @package.license_concluded = "MIT"
    assert_equal "MIT", @package.license_concluded
  end

  def test_supplier
    @package.set_supplier("Organization", "Ruby on Rails")
    assert_equal "Ruby on Rails", @package.supplier
    assert_equal "Organization", @package.supplier_type
  end

  def test_to_h
    @package.name = "rails"
    @package.version = "7.0.0"
    hash = @package.to_h
    assert_equal "rails", hash[:name]
    assert_equal "7.0.0", hash[:version]
  end

  def test_reset
    @package.name = "rails"
    @package.reset!
    assert_nil @package.name
  end
end
