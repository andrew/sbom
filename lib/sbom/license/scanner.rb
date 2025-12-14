# frozen_string_literal: true

require "json"

module Sbom
  module License
    class Scanner
      SPECIAL_VALUES = %w[NOASSERTION NONE].freeze

      class << self
        def instance
          @instance ||= new
        end
      end

      def initialize
        @licenses = {}
        @license_names = {}
        @deprecated = {}
        load_license_data
      end

      def find_license(license_id)
        return "UNKNOWN" if license_id.nil? || license_id.empty?
        return license_id if SPECIAL_VALUES.include?(license_id.upcase)
        return license_id if license_id.start_with?("LicenseRef")

        normalized = license_id.strip

        return @licenses[normalized] if @licenses.key?(normalized)

        downcased = normalized.downcase
        @licenses.each do |id, _|
          return id if id.downcase == downcased
        end

        @license_names.each do |name, id|
          return id if name.downcase == downcased
        end

        "UNKNOWN"
      end

      def valid?(license_id)
        find_license(license_id) != "UNKNOWN"
      end

      def deprecated?(license_id)
        @deprecated[license_id] || false
      end

      def osi_approved?(license_id)
        return false unless @licenses.key?(license_id)

        @licenses[license_id][:osi_approved]
      end

      def validate_expression(expression)
        return "NOASSERTION" if expression.nil? || expression.empty?

        tokens = expression.split(/\s+(AND|OR|WITH)\s+/i)

        tokens.map do |token|
          next token if %w[AND OR WITH].include?(token.upcase)

          cleaned = token.gsub(/[()]/, "").strip
          next token if cleaned.empty?

          found = find_license(cleaned)
          found == "UNKNOWN" ? "NOASSERTION" : token
        end.join(" ")
      end

      def license_list_version
        @license_list_version
      end

      private

      def load_license_data
        data_path = File.join(File.dirname(__FILE__), "data", "spdx_licenses.json")

        return unless File.exist?(data_path)

        data = JSON.parse(File.read(data_path))
        @license_list_version = data["licenseListVersion"]

        data["licenses"].each do |license|
          id = license["licenseId"]
          @licenses[id] = {
            name: license["name"],
            osi_approved: license["isOsiApproved"],
            deprecated: license["isDeprecatedLicenseId"]
          }
          @license_names[license["name"]] = id
          @deprecated[id] = license["isDeprecatedLicenseId"]
        end
      end
    end
  end
end
