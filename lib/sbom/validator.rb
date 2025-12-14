# frozen_string_literal: true

require "json"
require "pathname"

module Sbom
  class Validator
    SPDX_VERSIONS = %w[2.2 2.3].freeze
    CYCLONEDX_VERSIONS = %w[1.4 1.5 1.6 1.7].freeze

    EXTENSION_MAP = {
      ".spdx" => :spdx,
      ".spdx.json" => :spdx,
      ".spdx.yaml" => :spdx,
      ".spdx.yml" => :spdx,
      ".spdx.xml" => :spdx,
      ".spdx.rdf" => :spdx,
      ".cdx.json" => :cyclonedx,
      ".bom.json" => :cyclonedx,
      ".cdx.xml" => :cyclonedx,
      ".bom.xml" => :cyclonedx
    }.freeze

    def initialize(sbom_type: :auto, version: nil, schema_dir: nil)
      @sbom_type = sbom_type
      @version = version
      @schema_dir = schema_dir || default_schema_dir
    end

    def validate_file(filename)
      raise ValidatorError, "File not found: #{filename}" unless File.exist?(filename)
      raise ValidatorError, "Empty file: #{filename}" if File.size(filename).zero?

      content = File.read(filename)
      sbom_type = detect_type(filename, content)

      validate_content(content, sbom_type)
    end

    def validate_file!(filename)
      result = validate_file(filename)
      raise ValidatorError, "Invalid SBOM: #{result.errors.join(', ')}" if result.invalid?

      result
    end

    def validate_string(content, sbom_type: nil)
      sbom_type ||= detect_type_from_content(content)
      validate_content(content, sbom_type)
    end

    def validate_string!(content, sbom_type: nil)
      result = validate_string(content, sbom_type: sbom_type)
      raise ValidatorError, "Invalid SBOM: #{result.errors.join(', ')}" if result.invalid?

      result
    end

    def self.validate_file(filename, sbom_type: :auto)
      new(sbom_type: sbom_type).validate_file(filename)
    end

    def self.validate_file!(filename, sbom_type: :auto)
      new(sbom_type: sbom_type).validate_file!(filename)
    end

    private

    def default_schema_dir
      spec_dir = File.expand_path("../../spec", __dir__)
      return spec_dir if File.directory?(spec_dir)

      nil
    end

    def detect_type(filename, content)
      return @sbom_type unless @sbom_type == :auto

      EXTENSION_MAP.each do |ext, type|
        return type if filename.end_with?(ext)
      end

      detect_type_from_content(content)
    end

    def detect_type_from_content(content)
      stripped = content.strip

      if stripped.start_with?("{")
        begin
          data = JSON.parse(stripped)
          return :cyclonedx if data["bomFormat"] == "CycloneDX"
          return :spdx if data["spdxVersion"]
        rescue JSON::ParserError
          nil
        end
      end

      return :spdx if stripped.include?("SPDXVersion:")
      return :spdx if stripped.include?("<spdx:")
      return :cyclonedx if stripped.include?("cyclonedx")

      :unknown
    end

    def validate_content(content, sbom_type)
      case sbom_type
      when :spdx
        validate_spdx(content)
      when :cyclonedx
        validate_cyclonedx(content)
      else
        ValidationResult.new(valid: false, errors: ["Unknown SBOM format"])
      end
    end

    def validate_spdx(content)
      stripped = content.strip

      if stripped.start_with?("{")
        validate_spdx_json(content)
      elsif stripped.include?("SPDXID:")
        validate_spdx_yaml(content)
      else
        validate_spdx_tag(content)
      end
    end

    def validate_spdx_json(content)
      unless json_schemer_available?
        return ValidationResult.new(valid: true, format: :spdx, version: extract_spdx_version_json(content))
      end

      schema_path = spdx_schema_path
      unless schema_path && File.exist?(schema_path)
        return ValidationResult.new(valid: true, format: :spdx, version: extract_spdx_version_json(content))
      end

      begin
        data = JSON.parse(content)
        schema = JSONSchemer.schema(Pathname.new(schema_path))
        errors = schema.validate(data).map { |e| e["error"] }

        if errors.empty?
          version = data["spdxVersion"]&.gsub("SPDX-", "")
          ValidationResult.new(valid: true, format: :spdx, version: version)
        else
          ValidationResult.new(valid: false, format: :spdx, errors: errors.first(5))
        end
      rescue JSON::ParserError => e
        ValidationResult.new(valid: false, format: :spdx, errors: ["JSON parse error: #{e.message}"])
      end
    end

    def validate_spdx_yaml(content)
      begin
        data = YAML.safe_load(content)
        version = data["spdxVersion"]&.gsub("SPDX-", "")
        ValidationResult.new(valid: true, format: :spdx, version: version)
      rescue Psych::SyntaxError => e
        ValidationResult.new(valid: false, format: :spdx, errors: ["YAML parse error: #{e.message}"])
      end
    end

    def validate_spdx_tag(content)
      version = nil
      content.each_line do |line|
        if line.start_with?("SPDXVersion:")
          version = line.split(":").last.strip.gsub("SPDX-", "")
          break
        end
      end

      ValidationResult.new(valid: true, format: :spdx, version: version)
    end

    def validate_cyclonedx(content)
      stripped = content.strip

      if stripped.start_with?("{")
        validate_cyclonedx_json(content)
      else
        validate_cyclonedx_xml(content)
      end
    end

    def validate_cyclonedx_json(content)
      unless json_schemer_available?
        return ValidationResult.new(valid: true, format: :cyclonedx, version: extract_cyclonedx_version_json(content))
      end

      versions_to_try = @version ? [@version] : CYCLONEDX_VERSIONS.reverse

      begin
        data = JSON.parse(content)
      rescue JSON::ParserError => e
        return ValidationResult.new(valid: false, format: :cyclonedx, errors: ["JSON parse error: #{e.message}"])
      end

      versions_to_try.each do |version|
        schema_path = cyclonedx_schema_path(version)
        next unless schema_path && File.exist?(schema_path)

        schema = JSONSchemer.schema(Pathname.new(schema_path))
        return ValidationResult.new(valid: true, format: :cyclonedx, version: version) if schema.valid?(data)
      end

      ValidationResult.new(valid: false, format: :cyclonedx, errors: ["Does not match any known CycloneDX schema"])
    end

    def validate_cyclonedx_xml(content)
      begin
        doc = REXML::Document.new(content)
        root = doc.root

        if root && root.name == "bom"
          namespace = root.namespace
          version = namespace&.match(/bom[\/\-](\d+\.\d+)/)&.captures&.first
          return ValidationResult.new(valid: true, format: :cyclonedx, version: version)
        end
      rescue REXML::ParseException => e
        return ValidationResult.new(valid: false, format: :cyclonedx, errors: ["XML parse error: #{e.message}"])
      end

      ValidationResult.new(valid: false, format: :cyclonedx, errors: ["Not a valid CycloneDX XML document"])
    end

    def extract_spdx_version_json(content)
      data = JSON.parse(content)
      data["spdxVersion"]&.gsub("SPDX-", "")
    rescue JSON::ParserError
      nil
    end

    def extract_cyclonedx_version_json(content)
      data = JSON.parse(content)
      data["specVersion"]
    rescue JSON::ParserError
      nil
    end

    def spdx_schema_path
      return nil unless @schema_dir

      File.join(@schema_dir, "spdx", "schemas", "spdx-schema.json")
    end

    def cyclonedx_schema_path(version)
      return nil unless @schema_dir

      File.join(@schema_dir, "cyclonedx", "schema", "bom-#{version}.schema.json")
    end

    def json_schemer_available?
      require "json_schemer"
      true
    rescue LoadError
      false
    end
  end
end
