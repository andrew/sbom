# frozen_string_literal: true

module Sbom
  module Data
    class Package
      VALID_TYPES = %w[
        APPLICATION FRAMEWORK LIBRARY CONTAINER OPERATING-SYSTEM
        DEVICE FIRMWARE FILE MACHINE-LEARNING-MODEL DATA
        DEVICE-DRIVER PLATFORM CRYPTOGRAPHIC-ASSET
      ].freeze

      VALID_SUPPLIER_TYPES = %w[Person Organization].freeze

      VALID_ALGORITHMS = %w[
        MD5 SHA1 SHA256 SHA384 SHA512
        SHA3-256 SHA3-384 SHA3-512
        BLAKE2b-256 BLAKE2b-384 BLAKE2b-512 BLAKE3
      ].freeze

      VALID_EXTERNAL_REF_CATEGORIES = %w[
        vcs issue-tracker website advisories bom mailing-list
        social chat documentation support source-distribution
        distribution distribution-intake license build-meta
        build-system release-notes security-contact model-card
        log configuration evidence formulation attestation
        threat-model adversary-model risk-assessment
        vulnerability-assertion exploitability-statement
        pentest-report static-analysis-report dynamic-analysis-report
        runtime-analysis-report component-analysis-report
        maturity-report certification-report codified-infrastructure
        quality-metrics poam electronic-signature digital-signature
        rfc-9116 other
      ].freeze

      URL_PATTERN = %r{
        \A(https?|ssh|git|svn|sftp|ftp)://
        [a-z0-9]+([\-\.]{1}[a-z0-9]+){0,100}\.[a-z]{2,5}
        (:[0-9]{1,5})?(/.*)?
      \z}xi

      def initialize
        @data = {}
      end

      def reset!
        @data = {}
      end

      def name
        @data[:name]
      end

      def name=(value)
        @data[:name] = value
      end

      def id
        @data[:id]
      end

      def id=(value)
        @data[:id] = value
      end

      def version
        @data[:version]
      end

      def version=(value)
        @data[:version] = value
        @data[:id] ||= "#{name}_#{value}" if name
      end

      def package_type
        @data[:type]
      end

      def package_type=(value)
        normalized = value.to_s.upcase.tr("_", "-").strip
        @data[:type] = VALID_TYPES.include?(normalized) ? normalized : "FILE"
      end

      def supplier
        @data[:supplier]
      end

      def supplier_type
        @data[:supplier_type]
      end

      def set_supplier(type, name)
        return if name.nil? || name.empty?

        @data[:supplier_type] = normalize_supplier_type(type)
        @data[:supplier] = name
      end

      def originator
        @data[:originator]
      end

      def originator_type
        @data[:originator_type]
      end

      def set_originator(type, name)
        return if name.nil? || name.empty?

        @data[:originator_type] = normalize_supplier_type(type)
        @data[:originator] = name
      end

      def download_location
        @data[:download_location]
      end

      def download_location=(value)
        @data[:download_location] = value if valid_url?(value)
      end

      def filename
        @data[:filename]
      end

      def filename=(value)
        @data[:filename] = value
      end

      def homepage
        @data[:homepage]
      end

      def homepage=(value)
        @data[:homepage] = value if valid_url?(value)
      end

      def source_info
        @data[:source_info]
      end

      def source_info=(value)
        @data[:source_info] = clean_text(value) unless value.nil? || value.empty?
      end

      def files_analyzed
        @data[:files_analyzed]
      end

      def files_analyzed=(value)
        @data[:files_analyzed] = value
      end

      def add_checksum(algorithm, value)
        return unless valid_checksum?(value) && valid_algorithm?(algorithm)

        @data[:checksums] ||= []
        @data[:checksums] << [algorithm.strip, value.downcase]
      end

      def checksums
        @data[:checksums] || []
      end

      def add_property(name, value)
        return if value.nil?

        @data[:properties] ||= []
        @data[:properties] << [name.strip, value]
      end

      def properties
        @data[:properties] || []
      end

      def add_tag(name)
        return if name.nil?

        @data[:tags] ||= []
        @data[:tags] << name.strip
      end

      def tags
        @data[:tags] || []
      end

      def license_concluded
        @data[:license_concluded]
      end

      def license_concluded=(value)
        @data[:license_concluded] = value
      end

      def license_declared
        @data[:license_declared]
      end

      def set_license_declared(license, name = nil)
        @data[:license_declared] = license
        @data[:license_name] = name if name
      end

      def license_name
        @data[:license_name]
      end

      def license_list
        @data[:license_list]
      end

      def license_list=(value)
        @data[:license_list] = value
      end

      def license_comments
        @data[:license_comments]
      end

      def license_comments=(value)
        @data[:license_comments] = clean_text(value) unless value.nil? || value.empty?
      end

      def add_license_info_in_files(license_info)
        @data[:license_info_in_files] ||= []
        @data[:license_info_in_files] << license_info
      end

      def license_info_in_files
        @data[:license_info_in_files] || []
      end

      def copyright_text
        @data[:copyright_text]
      end

      def copyright_text=(value)
        @data[:copyright_text] = clean_text(value) unless value.nil? || value.empty?
      end

      def comment
        @data[:comment]
      end

      def comment=(value)
        @data[:comment] = clean_text(value) unless value.nil? || value.empty?
      end

      def summary
        @data[:summary]
      end

      def summary=(value)
        @data[:summary] = clean_text(value) unless value.nil? || value.empty?
      end

      def description
        @data[:description]
      end

      def description=(value)
        @data[:description] = clean_text(value) unless value.nil? || value.empty?
      end

      def add_attribution(value)
        @data[:attributions] ||= []
        @data[:attributions] << value
      end

      def attributions
        @data[:attributions] || []
      end

      def add_external_reference(category, ref_type, locator)
        if %w[SECURITY PACKAGE-MANAGER PACKAGE_MANAGER].include?(category) &&
           %w[cpe22Type cpe23Type purl].include?(ref_type)
          entry = [category, ref_type.strip, locator]
        else
          normalized_type = VALID_EXTERNAL_REF_CATEGORIES.include?(ref_type.downcase) ? ref_type.downcase : "other"
          entry = [category, normalized_type.strip, locator]
        end

        @data[:external_references] ||= []
        @data[:external_references] << entry
      end

      def external_references
        @data[:external_references] || []
      end

      def purl
        external_references.find { |_, type, _| type == "purl" }&.last
      end

      def purl=(value)
        return if value.nil? || value.to_s.empty?

        add_external_reference("PACKAGE_MANAGER", "purl", value.to_s)
      end

      def parsed_purl
        return nil unless purl

        Purl.parse(purl)
      rescue Purl::InvalidPackageURL
        nil
      end

      def purl_type
        parsed_purl&.type
      end

      def purl_namespace
        parsed_purl&.namespace
      end

      def purl_name
        parsed_purl&.name
      end

      def purl_version
        parsed_purl&.version
      end

      def generate_purl(type:, namespace: nil, qualifiers: nil, subpath: nil)
        purl_obj = Purl::PackageURL.new(
          type: type,
          namespace: namespace,
          name: name,
          version: version,
          qualifiers: qualifiers,
          subpath: subpath
        )
        self.purl = purl_obj.to_s
        purl_obj.to_s
      end

      def cpe
        external_references.find { |_, type, _| type.start_with?("cpe") }&.last
      end

      def set_cpe(vector, cpe_type = "cpe23Type")
        return unless %w[cpe22Type cpe23Type].include?(cpe_type)

        add_external_reference("SECURITY", cpe_type, vector)
      end

      def add_evidence(evidence)
        @data[:evidence] ||= []
        @data[:evidence] << evidence
      end

      def evidence
        @data[:evidence] || []
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

      def copy_from(package_hash)
        package_hash.each do |key, value|
          @data[key.to_sym] = value
        end
      end

      private

      def normalize_supplier_type(type)
        normalized = type.to_s.downcase.strip
        case normalized
        when "person", "author"
          "Person"
        when "unknown"
          "UNKNOWN"
        else
          "Organization"
        end
      end

      def valid_url?(url)
        return false if url.nil? || url.include?(" ")

        url.match?(URL_PATTERN)
      end

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
        return nil if text.nil?

        text.to_s
            .encode("UTF-8", invalid: :replace, undef: :replace, replace: "")
            .gsub(/<\/?text>/, "")
            .strip
      end
    end
  end
end
