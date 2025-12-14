# frozen_string_literal: true

require "test_helper"

class RealWorldTest < Minitest::Test
  def test_parse_alpine_spdx
    file = fixture_path("spdx/alpine.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 0
    assert sbom.relationships.count > 0
  end

  def test_parse_alpine_cyclonedx
    file = fixture_path("cyclonedx/alpine.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 0
  end

  def test_parse_nginx_spdx
    file = fixture_path("spdx/nginx.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 10
  end

  def test_parse_nginx_cyclonedx
    file = fixture_path("cyclonedx/nginx.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 10
  end

  def test_parse_python_spdx
    file = fixture_path("spdx/python.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 100
  end

  def test_parse_python_cyclonedx
    file = fixture_path("cyclonedx/python.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 100
  end

  def test_alpine_packages_have_names
    file = fixture_path("cyclonedx/alpine.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    sbom.packages.each do |pkg|
      refute_nil pkg[:name], "Package should have a name"
    end
  end

  def test_nginx_has_purls
    file = fixture_path("cyclonedx/nginx.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    packages_with_purl = sbom.packages.select do |p|
      refs = p[:external_references] || []
      refs.any? { |r| r[1] == "purl" }
    end
    assert packages_with_purl.count > 0, "Should have packages with PURLs"
  end

  def test_spdx_relationships_parsed
    file = fixture_path("spdx/alpine.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert sbom.relationships.count > 0
    sbom.relationships.each do |rel|
      assert(rel[:source] || rel[:source_id], "Relationship should have source or source_id")
      assert(rel[:target] || rel[:target_id], "Relationship should have target or target_id")
      refute_nil rel[:type]
    end
  end

  def test_document_info_parsed
    file = fixture_path("spdx/alpine.spdx.json")
    sbom = Sbom::Parser.parse_file(file)

    refute_nil sbom.document
    refute_nil sbom.document[:name]
  end

  def test_parse_juice_shop_cyclonedx
    file = fixture_path("cyclonedx/juice-shop.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 100, "Juice Shop should have many packages"
  end

  def test_parse_laravel_cyclonedx
    file = fixture_path("cyclonedx/laravel.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 50, "Laravel should have many packages"
  end

  def test_parse_keycloak_cyclonedx
    file = fixture_path("cyclonedx/keycloak.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 100, "Keycloak should have many packages"
  end

  def test_parse_snyk_purl_cyclonedx
    file = fixture_path("cyclonedx/snyk-purl.cdx.json")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 0
  end

  def test_parse_laravel_cyclonedx_xml
    file = fixture_path("cyclonedx/laravel.cdx.xml")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 50, "Laravel XML should have many packages"
  end

  def test_parse_juice_shop_cyclonedx_xml
    file = fixture_path("cyclonedx/juice-shop.cdx.xml")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :cyclonedx, sbom.sbom_type
    assert sbom.packages.count > 100, "Juice Shop XML should have many packages"
  end

  def test_parse_spdx_tag_value
    file = fixture_path("spdx/example.spdx")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 0, "Tag-value SPDX should have packages"
  end

  def test_parse_spdx_yaml
    file = fixture_path("spdx/example.spdx.yaml")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 0, "YAML SPDX should have packages"
  end

  def test_parse_spdx_xml
    file = fixture_path("spdx/example.spdx.xml")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 0, "XML SPDX should have packages"
  end

  def test_parse_spdx_rdf
    file = fixture_path("spdx/example.spdx.rdf")
    sbom = Sbom::Parser.parse_file(file)

    assert_equal :spdx, sbom.sbom_type
    assert sbom.packages.count > 0, "RDF SPDX should have packages"
  end
end
