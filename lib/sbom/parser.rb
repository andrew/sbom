# frozen_string_literal: true

module Sbom
  class Parser
    EXTENSION_MAP = {
      ".spdx" => [:spdx, :tag],
      ".spdx.json" => [:spdx, :json],
      ".spdx.yaml" => [:spdx, :yaml],
      ".spdx.yml" => [:spdx, :yaml],
      ".spdx.xml" => [:spdx, :xml],
      ".spdx.rdf" => [:spdx, :rdf],
      ".cdx.json" => [:cyclonedx, :json],
      ".bom.json" => [:cyclonedx, :json],
      ".cdx.xml" => [:cyclonedx, :xml],
      ".bom.xml" => [:cyclonedx, :xml]
    }.freeze

    def initialize(sbom_type: :auto, preserve_instances: false)
      @sbom_type = sbom_type
      @preserve_instances = preserve_instances
    end

    def parse_file(filename)
      raise ParserError, "File not found: #{filename}" unless File.exist?(filename)
      raise ParserError, "Empty file: #{filename}" if File.size(filename).zero?

      content = File.read(filename)
      sbom_type, format = detect_type_from_filename(filename)

      parse_string(content, sbom_type: sbom_type, format: format)
    end

    def parse_string(content, sbom_type: nil, format: nil)
      sbom_type ||= @sbom_type

      if sbom_type == :auto
        sbom_type, format = detect_type_from_content(content)
      end

      case sbom_type
      when :spdx
        parser = Spdx::Parser.new(preserve_instances: @preserve_instances)
        parser.parse(content, format)
      when :cyclonedx
        parser = Cyclonedx::Parser.new(preserve_instances: @preserve_instances)
        parser.parse(content, format)
      else
        try_both_parsers(content)
      end
    end

    def self.parse_file(filename, sbom_type: :auto, preserve_instances: false)
      new(sbom_type: sbom_type, preserve_instances: preserve_instances).parse_file(filename)
    end

    def self.parse_string(content, sbom_type: :auto, preserve_instances: false)
      new(sbom_type: sbom_type, preserve_instances: preserve_instances).parse_string(content)
    end

    private

    def detect_type_from_filename(filename)
      EXTENSION_MAP.each do |ext, (type, format)|
        return [type, format] if filename.end_with?(ext)
      end

      return [:cyclonedx, :json] if filename.end_with?(".json")
      return [:cyclonedx, :xml] if filename.end_with?(".xml")

      [:auto, nil]
    end

    def detect_type_from_content(content)
      stripped = content.strip

      if stripped.start_with?("{")
        begin
          data = JSON.parse(stripped)
          return [:cyclonedx, :json] if data["bomFormat"] == "CycloneDX"
          return [:spdx, :json] if data["spdxVersion"]
        rescue JSON::ParserError
          nil
        end
      end

      return [:spdx, :tag] if stripped.include?("SPDXVersion:")
      return [:spdx, :rdf] if stripped.include?("<spdx:")
      return [:cyclonedx, :xml] if stripped.include?("cyclonedx")

      [:auto, nil]
    end

    def try_both_parsers(content)
      begin
        spdx_parser = Spdx::Parser.new(preserve_instances: @preserve_instances)
        result = spdx_parser.parse(content)
        return result if result.packages.any? || result.files.any?
      rescue StandardError
        nil
      end

      begin
        cdx_parser = Cyclonedx::Parser.new(preserve_instances: @preserve_instances)
        return cdx_parser.parse(content)
      rescue StandardError
        nil
      end

      raise ParserError, "Unable to parse SBOM content"
    end
  end
end
