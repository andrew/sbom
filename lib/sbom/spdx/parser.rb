# frozen_string_literal: true

require "json"
require "yaml"
require "rexml/document"

module Sbom
  module Spdx
    class Parser
      FORMAT_TAG = :tag
      FORMAT_JSON = :json
      FORMAT_YAML = :yaml
      FORMAT_XML = :xml
      FORMAT_RDF = :rdf

      def initialize
        @document = Data::Document.new
        @packages = {}
        @files = {}
        @relationships = []
        @licenses = []
        @elements = {}
      end

      def parse(content, format = nil)
        format ||= detect_format(content)

        case format
        when FORMAT_JSON
          parse_json(content)
        when FORMAT_YAML
          parse_yaml(content)
        when FORMAT_TAG
          parse_tag_value(content)
        when FORMAT_XML
          parse_xml(content)
        when FORMAT_RDF
          parse_rdf(content)
        else
          raise ParserError, "Unknown SPDX format"
        end

        build_sbom
      end

      private

      def detect_format(content)
        stripped = content.strip
        return FORMAT_JSON if stripped.start_with?("{")
        return FORMAT_XML if stripped.start_with?("<") && stripped.include?("<SpdxDocument")
        return FORMAT_RDF if stripped.start_with?("<") && stripped.include?("<spdx:")
        return FORMAT_TAG if stripped.include?("PackageName:")

        begin
          YAML.safe_load(stripped)
          return FORMAT_YAML if stripped.include?("SPDXID:")
        rescue StandardError
          nil
        end

        FORMAT_TAG
      end

      def parse_json(content)
        data = JSON.parse(content)
        data = data["sbom"] if data["sbom"]
        data = data["predicate"] if data["predicateType"]&.include?("spdx")
        parse_spdx_data(data)
      rescue JSON::ParserError => e
        raise ParserError, "Invalid JSON: #{e.message}"
      end

      def parse_yaml(content)
        data = YAML.safe_load(content)
        parse_spdx_data(data)
      rescue Psych::SyntaxError => e
        raise ParserError, "Invalid YAML: #{e.message}"
      end

      def parse_spdx_data(data)
        return unless data["spdxVersion"] || data["SPDXID"]

        @document.version = data["spdxVersion"]
        @document.id = data["SPDXID"]
        @document.name = data["name"]
        @document.data_license = data["dataLicense"]
        @document.namespace = data["documentNamespace"]
        @document.sbom_type = "spdx"

        if data["creationInfo"]
          @document.created = data["creationInfo"]["created"]
          @document.license_list_version = data["creationInfo"]["licenseListVersion"]

          Array(data["creationInfo"]["creators"]).each do |creator|
            type, name = creator.split(": ", 2)
            if type == "Organization"
              @document.metadata_supplier = name
            else
              @document.add_creator(type, name)
            end
          end
        end

        Array(data["packages"]).each do |pkg_data|
          parse_json_package(pkg_data)
        end

        Array(data["files"]).each do |file_data|
          parse_json_file(file_data)
        end

        Array(data["relationships"]).each do |rel_data|
          parse_json_relationship(rel_data)
        end

        Array(data["hasExtractedLicensingInfos"]).each do |lic_data|
          @licenses << {
            id: lic_data["licenseId"],
            name: lic_data["name"],
            text: lic_data["extractedText"],
            comment: lic_data["comment"]
          }
        end
      end

      def parse_json_package(data)
        package = Data::Package.new
        package.name = data["name"]
        package.id = data["SPDXID"]
        package.version = data["versionInfo"]
        package.download_location = data["downloadLocation"]
        package.files_analyzed = data["filesAnalyzed"]
        package.license_concluded = data["licenseConcluded"]
        package.set_license_declared(data["licenseDeclared"])
        package.copyright_text = data["copyrightText"]
        package.description = data["description"]
        package.summary = data["summary"]
        package.comment = data["comment"]
        package.homepage = data["homepage"]
        package.filename = data["packageFileName"]

        if data["supplier"]
          type, name = data["supplier"].split(": ", 2)
          package.set_supplier(type, name) if name
        end

        if data["originator"]
          type, name = data["originator"].split(": ", 2)
          package.set_originator(type, name) if name
        end

        if data["primaryPackagePurpose"]
          package.package_type = data["primaryPackagePurpose"]
        end

        Array(data["checksums"]).each do |checksum|
          package.add_checksum(checksum["algorithm"], checksum["checksumValue"])
        end

        Array(data["externalRefs"]).each do |ref|
          package.add_external_reference(
            ref["referenceCategory"],
            ref["referenceType"],
            ref["referenceLocator"]
          )
        end

        @elements[package.id] = package.name
        @packages[[package.name, package.version]] = package.to_h
      end

      def parse_json_file(data)
        file = Data::SbomFile.new
        file.name = data["fileName"]
        file.id = data["SPDXID"]
        file.license_concluded = data["licenseConcluded"]
        file.copyright_text = data["copyrightText"]
        file.comment = data["comment"]

        Array(data["fileTypes"]).each do |type|
          file.add_file_type(type)
        end

        Array(data["checksums"]).each do |checksum|
          file.add_checksum(checksum["algorithm"], checksum["checksumValue"])
        end

        @elements[file.id] = file.name
        @files[file.name] = file.to_h
      end

      def parse_json_relationship(data)
        rel = Data::Relationship.new
        rel.source_id = data["spdxElementId"]
        rel.target_id = data["relatedSpdxElement"]
        rel.relationship_type = data["relationshipType"]
        rel.source = @elements[rel.source_id]
        rel.target = @elements[rel.target_id]

        @relationships << rel.to_h
      end

      def parse_tag_value(content)
        lines = content.split("\n")
        current_package = nil
        current_file = nil

        lines.each do |line|
          next if line.strip.empty? || line.start_with?("#")

          tag, value = parse_tag_line(line)
          next unless tag && value

          case tag
          when "SPDXVersion"
            @document.version = value
            @document.sbom_type = "spdx"
          when "DataLicense"
            @document.data_license = value
          when "SPDXID"
            if current_package
              current_package.id = value
              @elements[value] = current_package.name
            elsif current_file
              current_file.id = value
              @elements[value] = current_file.name
            else
              @document.id = value
              @elements[value] = @document.name
            end
          when "DocumentName"
            @document.name = value
            @elements[@document.id] = value if @document.id
          when "DocumentNamespace"
            @document.namespace = value
          when "LicenseListVersion"
            @document.license_list_version = value
          when "Creator"
            type, name = value.split(" ", 2)
            if type == "Organization"
              @document.metadata_supplier = name
            else
              @document.add_creator(type, name)
            end
          when "Created"
            @document.created = value
          when "PackageName"
            save_package(current_package) if current_package
            current_file = nil
            current_package = Data::Package.new
            current_package.name = value
          when "PackageVersion"
            current_package&.version = value
          when "PackageSupplier"
            if current_package
              type, name = value.split(" ", 2)
              current_package.set_supplier(type, name)
            end
          when "PackageOriginator"
            if current_package
              type, name = value.split(" ", 2)
              current_package.set_originator(type, name)
            end
          when "PackageDownloadLocation"
            current_package&.download_location = value
          when "FilesAnalyzed"
            current_package&.files_analyzed = value
          when "PackageChecksum"
            if current_package
              algo, checksum = value.split(": ", 2)
              current_package.add_checksum(algo, checksum)
            end
          when "PackageLicenseConcluded"
            current_package&.license_concluded = value
          when "PackageLicenseDeclared"
            current_package&.set_license_declared(value)
          when "PackageCopyrightText"
            current_package&.copyright_text = value
          when "PackageDescription"
            current_package&.description = value
          when "PackageSummary"
            current_package&.summary = value
          when "PackageComment"
            current_package&.comment = value
          when "PackageHomePage"
            current_package&.homepage = value
          when "PackageFileName"
            current_package&.filename = value
          when "PrimaryPackagePurpose"
            current_package&.package_type = value
          when "ExternalRef"
            if current_package
              parts = value.split(" ", 3)
              current_package.add_external_reference(parts[0], parts[1], parts[2]) if parts.length >= 3
            end
          when "FileName"
            save_file(current_file) if current_file
            save_package(current_package) if current_package
            current_package = nil
            current_file = Data::SbomFile.new
            current_file.name = value
          when "FileType"
            current_file&.add_file_type(value)
          when "FileChecksum"
            if current_file
              algo, checksum = value.split(": ", 2)
              current_file.add_checksum(algo, checksum)
            end
          when "LicenseConcluded"
            current_file&.license_concluded = value
          when "FileCopyrightText"
            current_file&.copyright_text = value
          when "Relationship"
            parse_tag_relationship(value)
          end
        end

        save_package(current_package) if current_package
        save_file(current_file) if current_file
      end

      def parse_tag_line(line)
        return nil unless line.include?(":")

        tag, value = line.split(":", 2)
        [tag.strip, value&.strip]
      end

      def parse_tag_relationship(value)
        parts = value.split(" ")
        return unless parts.length >= 3

        rel = Data::Relationship.new
        rel.source_id = parts[0]
        rel.relationship_type = parts[1]
        rel.target_id = parts[2]
        rel.source = @elements[rel.source_id]
        rel.target = @elements[rel.target_id]

        @relationships << rel.to_h
      end

      def save_package(package)
        return unless package&.name

        @elements[package.id] = package.name if package.id
        @packages[[package.name, package.version]] = package.to_h
      end

      def save_file(file)
        return unless file&.name

        @elements[file.id] = file.name if file.id
        @files[file.name] = file.to_h
      end

      def parse_xml(content)
        doc = REXML::Document.new(content)
        root = doc.root
        return unless root

        namespace = root.namespace

        @document.version = root.elements["spdxVersion"]&.text
        @document.id = root.elements["SPDXID"]&.text
        @document.name = root.elements["name"]&.text
        @document.data_license = root.elements["dataLicense"]&.text
        @document.sbom_type = "spdx"

        root.elements.each("packages") do |pkg|
          parse_xml_package(pkg, namespace)
        end
      rescue REXML::ParseException => e
        raise ParserError, "Invalid XML: #{e.message}"
      end

      def parse_xml_package(pkg, _namespace)
        package = Data::Package.new
        package.name = pkg.elements["name"]&.text
        package.version = pkg.elements["versionInfo"]&.text
        package.id = pkg.elements["SPDXID"]&.text

        @elements[package.id] = package.name if package.id
        @packages[[package.name, package.version]] = package.to_h
      end

      def parse_rdf(content)
        lines = content.split("\n")

        current_name = nil
        current_version = nil

        lines.each do |line|
          if (match = line.match(/<spdx:name>(.+?)<\/spdx:name>/))
            current_name = match[1]
          elsif (match = line.match(/<spdx:versionInfo>(.+?)<\/spdx:versionInfo>/))
            current_version = match[1]
            if current_name
              package = Data::Package.new
              package.name = current_name
              package.version = current_version
              @packages[[current_name, current_version]] = package.to_h
              current_name = nil
              current_version = nil
            end
          elsif (match = line.match(/<spdx:spdxVersion>(.+?)<\/spdx:spdxVersion>/))
            @document.version = match[1]
            @document.sbom_type = "spdx"
          end
        end
      end

      def build_sbom
        sbom = Data::Sbom.new(sbom_type: :spdx)
        sbom.version = @document.version
        sbom.add_document(@document.to_h)
        sbom.add_packages(@packages)
        sbom.add_files(@files)
        sbom.add_relationships(@relationships)
        sbom.add_licenses(@licenses)
        sbom
      end
    end
  end
end
