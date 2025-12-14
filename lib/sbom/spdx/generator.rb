# frozen_string_literal: true

require "json"
require "yaml"
require "securerandom"
require "time"

module Sbom
  module Spdx
    class Generator
      SPDX_VERSION = "SPDX-2.3"
      SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"

      FORMAT_TAG = :tag
      FORMAT_JSON = :json
      FORMAT_YAML = :yaml

      LIFECYCLE_MAP = {
        "design" => "Design",
        "pre-build" => "Source",
        "build" => "Build",
        "post-build" => "Analyzed",
        "operations" => "Deployed",
        "discovery" => "Runtime"
      }.freeze

      def initialize(format: FORMAT_TAG, application: "sbom", version: Sbom::VERSION)
        @format = validate_format(format)
        @application = application
        @version = version
        @spec_version = ENV.fetch("SBOM_SPDX_VERSION", SPDX_VERSION)
        @organization = ENV["SBOM_ORGANIZATION"]

        @tag_output = []
        @json_output = {}
        @packages = []
        @files = []
        @relationships = []
        @licenses = []
        @elements = {}
      end

      def generate(project_name, sbom_data)
        return if sbom_data.nil? || (sbom_data.respond_to?(:empty?) && sbom_data.empty?)

        data = sbom_data.is_a?(Hash) ? sbom_data : sbom_data.to_h

        @spec_version = data[:version] if data[:version]&.start_with?("SPDX")
        uuid = data[:uuid]

        doc_name = extract_document_name(data, project_name)
        organization = extract_organization(data)
        lifecycle = extract_lifecycle(data)

        generate_document_header(doc_name, uuid, lifecycle, organization)
        generate_packages(data[:packages])
        generate_files(data[:files])
        generate_relationships(data[:relationships])
        generate_license_info(data[:licenses])

        finalize_output
      end

      def output
        case @format
        when FORMAT_JSON
          JSON.pretty_generate(@json_output)
        when FORMAT_YAML
          @json_output.to_yaml
        else
          @tag_output.join("\n")
        end
      end

      def to_h
        @json_output
      end

      private

      def validate_format(format)
        fmt = format.to_s.downcase.to_sym
        return fmt if [FORMAT_TAG, FORMAT_JSON, FORMAT_YAML].include?(fmt)

        FORMAT_JSON
      end

      def extract_document_name(data, default)
        return default unless data[:document]

        data[:document][:name] || default
      end

      def extract_organization(data)
        return @organization unless data[:document]

        data[:document][:metadata_supplier] || @organization
      end

      def extract_lifecycle(data)
        return nil unless data[:document]

        data[:document][:lifecycle]
      end

      def generate_document_header(name, uuid, lifecycle, organization)
        namespace = uuid || "#{SPDX_NAMESPACE}#{name}-#{SecureRandom.uuid}"
        timestamp = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        @elements["SPDXRef-DOCUMENT"] = name

        if @format == FORMAT_TAG
          @tag_output << "SPDXVersion: #{@spec_version}"
          @tag_output << "DataLicense: CC0-1.0"
          @tag_output << "SPDXID: SPDXRef-DOCUMENT"
          @tag_output << "DocumentName: #{name}"
          @tag_output << "DocumentNamespace: #{namespace}"
          @tag_output << "Creator: Tool: #{@application}-#{@version}"
          @tag_output << "Creator: Organization: #{organization}" if organization
          @tag_output << "Created: #{timestamp}"

          if lifecycle
            sbom_type = LIFECYCLE_MAP[lifecycle] || lifecycle
            @tag_output << "CreatorComment: <text>SBOM Type: #{sbom_type}</text>"
          end

          @tag_output << ""
        else
          @json_output = {
            "spdxVersion" => @spec_version,
            "dataLicense" => "CC0-1.0",
            "SPDXID" => "SPDXRef-DOCUMENT",
            "name" => name,
            "documentNamespace" => namespace,
            "creationInfo" => {
              "created" => timestamp,
              "creators" => ["Tool: #{@application}-#{@version}"]
            }
          }

          @json_output["creationInfo"]["creators"] << "Organization: #{organization}" if organization

          if lifecycle
            sbom_type = LIFECYCLE_MAP[lifecycle] || lifecycle
            @json_output["creationInfo"]["comment"] = "SBOM Type: #{sbom_type}"
          end
        end
      end

      def generate_packages(packages_data)
        return unless packages_data

        packages = packages_data.is_a?(Hash) ? packages_data.values : packages_data
        packages.each_with_index do |pkg, index|
          generate_package(pkg, index + 1)
        end
      end

      def generate_package(pkg, index)
        name = pkg[:name]
        return unless name

        spdx_id = pkg[:id] || "SPDXRef-Package-#{index}-#{sanitize_id(name)}"
        @elements[spdx_id] = name

        if @format == FORMAT_TAG
          @tag_output << "##### Package: #{name}"
          @tag_output << ""
          @tag_output << "PackageName: #{name}"
          @tag_output << "SPDXID: #{spdx_id}"
          @tag_output << "PackageVersion: #{pkg[:version]}" if pkg[:version]

          if pkg[:supplier_type] && pkg[:supplier]
            @tag_output << "PackageSupplier: #{pkg[:supplier_type]}: #{pkg[:supplier]}"
          end

          @tag_output << "PackageDownloadLocation: #{pkg[:download_location] || 'NOASSERTION'}"
          @tag_output << "FilesAnalyzed: #{pkg[:files_analyzed] || 'false'}"
          @tag_output << "PackageLicenseConcluded: #{pkg[:license_concluded] || 'NOASSERTION'}"
          @tag_output << "PackageLicenseDeclared: #{pkg[:license_declared] || 'NOASSERTION'}"
          @tag_output << "PackageCopyrightText: #{pkg[:copyright_text] || 'NOASSERTION'}"

          pkg[:external_references]&.each do |ref|
            @tag_output << "ExternalRef: #{ref[0]} #{ref[1]} #{ref[2]}"
          end

          @tag_output << ""

          @relationships << ["SPDXRef-DOCUMENT", "DESCRIBES", spdx_id]
        else
          package_json = {
            "SPDXID" => spdx_id,
            "name" => name,
            "downloadLocation" => pkg[:download_location] || "NOASSERTION",
            "filesAnalyzed" => pkg[:files_analyzed] == "true" || pkg[:files_analyzed] == true,
            "licenseConcluded" => pkg[:license_concluded] || "NOASSERTION",
            "licenseDeclared" => pkg[:license_declared] || "NOASSERTION",
            "copyrightText" => pkg[:copyright_text] || "NOASSERTION"
          }

          package_json["versionInfo"] = pkg[:version] if pkg[:version]

          if pkg[:supplier_type] && pkg[:supplier]
            package_json["supplier"] = "#{pkg[:supplier_type]}: #{pkg[:supplier]}"
          end

          if pkg[:checksums]&.any?
            package_json["checksums"] = pkg[:checksums].map do |algo, value|
              { "algorithm" => algo, "checksumValue" => value }
            end
          end

          if pkg[:external_references]&.any?
            package_json["externalRefs"] = pkg[:external_references].map do |ref|
              {
                "referenceCategory" => ref[0],
                "referenceType" => ref[1],
                "referenceLocator" => ref[2]
              }
            end
          end

          @packages << package_json
          @relationships << {
            "spdxElementId" => "SPDXRef-DOCUMENT",
            "relationshipType" => "DESCRIBES",
            "relatedSpdxElement" => spdx_id
          }
        end
      end

      def generate_files(files_data)
        return unless files_data

        files = files_data.is_a?(Hash) ? files_data.values : files_data
        files.each_with_index do |file, index|
          generate_file(file, index + 1)
        end
      end

      def generate_file(file, index)
        name = file[:name]
        return unless name

        spdx_id = file[:id] || "SPDXRef-File-#{index}-#{sanitize_id(name)}"
        @elements[spdx_id] = name

        if @format == FORMAT_TAG
          @tag_output << "FileName: #{name}"
          @tag_output << "SPDXID: #{spdx_id}"
          @tag_output << "LicenseConcluded: #{file[:license_concluded] || 'NOASSERTION'}"
          @tag_output << "FileCopyrightText: #{file[:copyright_text] || 'NOASSERTION'}"
          @tag_output << ""
        else
          file_json = {
            "SPDXID" => spdx_id,
            "fileName" => name,
            "licenseConcluded" => file[:license_concluded] || "NOASSERTION",
            "copyrightText" => file[:copyright_text] || "NOASSERTION"
          }

          if file[:checksums]&.any?
            file_json["checksums"] = file[:checksums].map do |algo, value|
              { "algorithm" => algo, "checksumValue" => value }
            end
          end

          @files << file_json
        end
      end

      def generate_relationships(relationships_data)
        return unless relationships_data

        relationships_data.each do |rel|
          source_id = rel[:source_id] || find_element_id(rel[:source])
          target_id = rel[:target_id] || find_element_id(rel[:target])
          rel_type = rel[:type] || rel[:relationship_type]

          next unless source_id && target_id && rel_type

          if @format == FORMAT_TAG
            @relationships << [source_id, rel_type, target_id]
          else
            @relationships << {
              "spdxElementId" => source_id,
              "relationshipType" => rel_type,
              "relatedSpdxElement" => target_id
            }
          end
        end
      end

      def generate_license_info(licenses_data)
        return unless licenses_data&.any?

        licenses_data.each do |lic|
          if @format == FORMAT_TAG
            @tag_output << "LicenseID: #{lic[:id]}"
            @tag_output << "LicenseName: #{lic[:name]}" if lic[:name]
            @tag_output << "ExtractedText: <text>#{lic[:text]}</text>" if lic[:text]
            @tag_output << ""
          else
            @licenses << {
              "licenseId" => lic[:id],
              "name" => lic[:name],
              "extractedText" => lic[:text]
            }.compact
          end
        end
      end

      def finalize_output
        if @format == FORMAT_TAG
          @relationships.each do |rel|
            if rel.is_a?(Array)
              @tag_output << "Relationship: #{rel[0]} #{rel[1]} #{rel[2]}"
            end
          end
        else
          @json_output["packages"] = @packages if @packages.any?
          @json_output["files"] = @files if @files.any?
          @json_output["relationships"] = @relationships if @relationships.any?
          @json_output["hasExtractedLicensingInfos"] = @licenses if @licenses.any?
        end
      end

      def find_element_id(name)
        @elements.key(name) || @elements.find { |id, n| n == name }&.first
      end

      def sanitize_id(str)
        str.to_s.gsub(/[^a-zA-Z0-9.\-]/, "-")
      end
    end
  end
end
