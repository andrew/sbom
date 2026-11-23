# frozen_string_literal: true

module Sbom
  # Psych takes minutes to parse a small document nested hundreds of
  # thousands of levels deep, so depth is checked on the event stream first.
  module YamlLoader
    MAX_DEPTH = 100

    class DepthHandler < Psych::Handler
      def initialize
        super
        @depth = 0
      end

      def start_sequence(*)
        descend
      end

      def start_mapping(*)
        descend
      end

      def end_sequence
        @depth -= 1
      end

      def end_mapping
        @depth -= 1
      end

      def descend
        @depth += 1
        raise ParserError, "YAML nested deeper than #{MAX_DEPTH} levels" if @depth > MAX_DEPTH
      end
    end

    def self.safe_load(content)
      Psych::Parser.new(DepthHandler.new).parse(content)
      YAML.safe_load(content)
    end
  end
end
