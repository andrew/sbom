# frozen_string_literal: true

module Sbom
  class ValidationResult
    attr_reader :format, :version, :errors

    def initialize(valid:, format: nil, version: nil, errors: [])
      @valid = valid
      @format = format
      @version = version
      @errors = errors
    end

    def valid?
      @valid
    end

    def invalid?
      !@valid
    end

    def to_s
      if valid?
        "#{format} #{version}"
      else
        "Invalid: #{errors.join(', ')}"
      end
    end
  end
end
