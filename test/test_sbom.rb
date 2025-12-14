# frozen_string_literal: true

require "test_helper"

class TestSbom < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Sbom::VERSION
  end

  def test_parse_file_class_method
    assert_respond_to Sbom, :parse_file
  end

  def test_parse_string_class_method
    assert_respond_to Sbom, :parse_string
  end

  def test_generate_class_method
    assert_respond_to Sbom, :generate
  end

  def test_validate_file_class_method
    assert_respond_to Sbom, :validate_file
  end

  def test_parser_class_exists
    assert_kind_of Class, Sbom::Parser
  end

  def test_generator_class_exists
    assert_kind_of Class, Sbom::Generator
  end

  def test_validator_class_exists
    assert_kind_of Class, Sbom::Validator
  end

  def test_data_models_exist
    assert_kind_of Class, Sbom::Data::Package
    assert_kind_of Class, Sbom::Data::Document
    assert_kind_of Class, Sbom::Data::SbomFile
    assert_kind_of Class, Sbom::Data::Relationship
    assert_kind_of Class, Sbom::Data::Sbom
  end

  def test_error_classes_exist
    assert_kind_of Class, Sbom::Error
    assert_kind_of Class, Sbom::ParserError
    assert_kind_of Class, Sbom::GeneratorError
    assert_kind_of Class, Sbom::ValidatorError
  end
end
