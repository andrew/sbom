# frozen_string_literal: true

module Sbom
  class Error < StandardError; end

  class ParserError < Error; end

  class GeneratorError < Error; end

  class ValidatorError < Error; end

  class UnsupportedFormatError < Error; end
end
