# frozen_string_literal: true

module Sbom
  module Data
    class Relationship
      attr_accessor :source, :target, :relationship_type,
                    :source_id, :target_id,
                    :source_type, :target_type

      def initialize(source: nil, target: nil, relationship_type: nil)
        @source = source
        @target = target
        @relationship_type = relationship_type&.strip
        @source_id = nil
        @target_id = nil
        @source_type = nil
        @target_type = nil
      end

      def reset!
        @source = nil
        @target = nil
        @relationship_type = nil
        @source_id = nil
        @target_id = nil
        @source_type = nil
        @target_type = nil
      end

      def to_h
        {
          source: @source,
          target: @target,
          type: @relationship_type,
          source_id: @source_id,
          target_id: @target_id,
          source_type: @source_type,
          target_type: @target_type
        }.compact
      end
    end
  end
end
