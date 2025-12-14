# frozen_string_literal: true

module Sbom
  module Data
    class SbomFile
      VALID_FILE_TYPES = %w[
        SOURCE BINARY ARCHIVE APPLICATION AUDIO IMAGE
        TEXT VIDEO DOCUMENTATION SPDX OTHER
      ].freeze

      VALID_ALGORITHMS = %w[
        MD5 SHA1 SHA256 SHA384 SHA512
        SHA3-256 SHA3-384 SHA3-512
        BLAKE2b-256 BLAKE2b-384 BLAKE2b-512 BLAKE3
      ].freeze

      DEFAULTS = {
        name: "TBD",
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

      def add_file_type(file_type)
        type = file_type.to_s.upcase.strip
        return unless VALID_FILE_TYPES.include?(type)

        @data[:file_types] ||= []
        @data[:file_types] << type unless @data[:file_types].include?(type)
      end

      def file_types
        @data[:file_types] || []
      end

      def add_checksum(algorithm, value)
        return unless valid_checksum?(value) && valid_algorithm?(algorithm)

        @data[:checksums] ||= []
        @data[:checksums] << [algorithm.strip, value.downcase]
      end

      def checksums
        @data[:checksums] || []
      end

      def license_concluded
        @data[:license_concluded]
      end

      def license_concluded=(value)
        @data[:license_concluded] = value
      end

      def add_license_info_in_file(license)
        @data[:license_info_in_file] ||= []
        @data[:license_info_in_file] << license
      end

      def license_info_in_file
        @data[:license_info_in_file] || []
      end

      def license_comment
        @data[:license_comment]
      end

      def license_comment=(value)
        @data[:license_comment] = clean_text(value)
      end

      def copyright_text
        @data[:copyright_text]
      end

      def copyright_text=(value)
        @data[:copyright_text] = clean_text(value)
      end

      def comment
        @data[:comment]
      end

      def comment=(value)
        @data[:comment] = clean_text(value)
      end

      def notice
        @data[:notice]
      end

      def notice=(value)
        @data[:notice] = clean_text(value)
      end

      def add_contributor(contributor)
        @data[:contributors] ||= []
        @data[:contributors] << contributor
      end

      def contributors
        @data[:contributors] || []
      end

      def attribution
        @data[:attribution]
      end

      def attribution=(value)
        @data[:attribution] = value
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

      private

      def valid_checksum?(value)
        return false unless value.is_a?(String)

        length = value.length
        return false unless [32, 40, 64, 96, 128].include?(length)

        value.match?(/\A[0-9a-fA-F]+\z/)
      end

      def valid_algorithm?(algorithm)
        VALID_ALGORITHMS.include?(algorithm.strip)
      end

      def clean_text(text)
        return nil if text.nil? || text.empty?

        text.gsub(/<\/?text>/, "").strip
      end
    end
  end
end
