# frozen_string_literal: true

require "json"
require "yaml"
require "rexml/document"
require "purl"

require_relative "sbom/version"
require_relative "sbom/error"

# Data models
require_relative "sbom/data/document"
require_relative "sbom/data/package"
require_relative "sbom/data/file"
require_relative "sbom/data/relationship"
require_relative "sbom/data/sbom"

# License handling
require_relative "sbom/license/scanner"

# SPDX implementation
require_relative "sbom/spdx/parser"
require_relative "sbom/spdx/generator"

# CycloneDX implementation
require_relative "sbom/cyclonedx/parser"
require_relative "sbom/cyclonedx/generator"

# Facade classes
require_relative "sbom/parser"
require_relative "sbom/generator"
require_relative "sbom/validation_result"
require_relative "sbom/validator"
require_relative "sbom/output"
require_relative "sbom/enricher"
require_relative "sbom/merger"

module Sbom
  class << self
    def parse_file(filename, sbom_type: :auto)
      Parser.parse_file(filename, sbom_type: sbom_type)
    end

    def parse_string(content, sbom_type: :auto)
      Parser.parse_string(content, sbom_type: sbom_type)
    end

    def generate(project_name, sbom_data, sbom_type: :spdx, format: :json)
      Generator.generate(project_name, sbom_data, sbom_type: sbom_type, format: format)
    end

    def validate_file(filename, sbom_type: :auto)
      Validator.validate_file(filename, sbom_type: sbom_type)
    end

    def enrich(sbom)
      Enricher.enrich(sbom)
    end

    def enrich_file(filename, sbom_type: :auto)
      sbom = parse_file(filename, sbom_type: sbom_type)
      Enricher.enrich(sbom)
    end

    def merge(sboms, dedupe: :purl)
      Merger.merge(sboms, dedupe: dedupe)
    end

    def merge_files(filenames, dedupe: :purl)
      Merger.merge_files(filenames, dedupe: dedupe)
    end
  end
end
