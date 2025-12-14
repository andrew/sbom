# frozen_string_literal: true

module Sbom
  class Generator
    VALID_FORMATS = %i[tag json yaml].freeze
    VALID_TYPES = %i[spdx cyclonedx].freeze

    def initialize(sbom_type: :spdx, format: :json, application: "sbom", version: Sbom::VERSION)
      @sbom_type = validate_type(sbom_type)
      @format = validate_format(format, @sbom_type)
      @application = application
      @version = version
      @generator = create_generator
    end

    def generate(project_name, sbom_data)
      @generator.generate(project_name, sbom_data)
    end

    def output
      @generator.output
    end

    def to_h
      @generator.to_h
    end

    def sbom_type
      @sbom_type
    end

    def format
      @format
    end

    def self.generate(project_name, sbom_data, sbom_type: :spdx, format: :json)
      gen = new(sbom_type: sbom_type, format: format)
      gen.generate(project_name, sbom_data)
      gen
    end

    private

    def validate_type(type)
      type_sym = type.to_s.downcase.to_sym
      return type_sym if VALID_TYPES.include?(type_sym)

      :spdx
    end

    def validate_format(format, sbom_type)
      format_sym = format.to_s.downcase.to_sym

      if sbom_type == :cyclonedx
        return :json
      end

      return format_sym if VALID_FORMATS.include?(format_sym)

      :json
    end

    def create_generator
      if @sbom_type == :cyclonedx
        Cyclonedx::Generator.new(
          format: @format,
          application: @application,
          version: @version
        )
      else
        Spdx::Generator.new(
          format: @format,
          application: @application,
          version: @version
        )
      end
    end
  end
end
