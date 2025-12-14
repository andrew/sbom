# frozen_string_literal: true

module Sbom
  module Data
    class Document
      DEFAULTS = {
        name: "NOT DEFINED",
        id: "NOT_DEFINED"
      }.freeze

      def initialize
        @data = {}
      end

      def reset!
        @data = {}
      end

      def name
        @data[:name] || DEFAULTS[:name]
      end

      def name=(value)
        @data[:name] = value
      end

      def id
        @data[:id] || DEFAULTS[:id]
      end

      def id=(value)
        @data[:id] = value
      end

      def version
        @data[:version]
      end

      def version=(value)
        @data[:version] = value
      end

      def sbom_type
        @data[:type]
      end

      def sbom_type=(value)
        @data[:type] = value&.downcase
      end

      def data_license
        @data[:data_license]
      end

      def data_license=(value)
        @data[:data_license] = value
      end

      def license_list_version
        @data[:license_list_version]
      end

      def license_list_version=(value)
        @data[:license_list_version] = value
      end

      def created
        @data[:created]
      end

      def created=(value)
        @data[:created] = value
      end

      def namespace
        @data[:namespace]
      end

      def namespace=(value)
        @data[:namespace] = value
      end

      def add_creator(creator_type, creator_name)
        @data[:creators] ||= []
        @data[:creators] << [creator_type, creator_name]
      end

      def creators
        @data[:creators] || []
      end

      def metadata_type
        @data[:metadata_type]
      end

      def metadata_type=(value)
        @data[:metadata_type] = value
      end

      def metadata_supplier
        @data[:metadata_supplier]
      end

      def metadata_supplier=(value)
        @data[:metadata_supplier] = value
      end

      def metadata_version
        @data[:metadata_version]
      end

      def metadata_version=(value)
        @data[:metadata_version] = value
      end

      def lifecycle
        @data[:lifecycle]
      end

      def lifecycle=(value)
        @data[:lifecycle] = value
      end

      def [](key)
        @data[key.to_sym]
      end

      def []=(key, value)
        @data[key.to_sym] = value
      end

      def to_h
        @data.dup
      end

      def copy_from(document_hash)
        document_hash.each do |key, value|
          @data[key.to_sym] = value
        end
      end
    end
  end
end
