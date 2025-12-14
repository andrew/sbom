# frozen_string_literal: true

module Sbom
  module Data
    class Sbom
      attr_accessor :sbom_type, :version, :uuid, :bom_version

      def initialize(sbom_type: :auto)
        @sbom_type = sbom_type
        @document = nil
        @files = {}
        @packages = {}
        @relationships = []
        @licenses = []
        @annotations = []
        @properties = []
      end

      def document
        @document
      end

      def document=(doc)
        @document = doc.is_a?(Hash) ? doc : doc&.to_h
      end

      def add_document(doc)
        @document = doc.is_a?(Hash) ? doc : doc&.to_h
      end

      def files
        @files.values
      end

      def add_file(file)
        data = file.is_a?(Hash) ? file : file.to_h
        key = data[:name]
        @files[key] = data if key
      end

      def add_files(files_hash)
        @files.merge!(files_hash) if files_hash.is_a?(Hash) && files_hash.any?
      end

      def packages
        @packages.values
      end

      def add_package(package)
        data = package.is_a?(Hash) ? package : package.to_h
        key = [data[:name], data[:version]]
        @packages[key] = data if data[:name]
      end

      def add_packages(packages_hash)
        @packages.merge!(packages_hash) if packages_hash.is_a?(Hash) && packages_hash.any?
      end

      def relationships
        @relationships
      end

      def add_relationship(relationship)
        data = relationship.is_a?(Hash) ? relationship : relationship.to_h
        @relationships << data
      end

      def add_relationships(relationships_list)
        @relationships.concat(relationships_list) if relationships_list.is_a?(Array)
      end

      def licenses
        @licenses
      end

      def add_license(license)
        @licenses << license
      end

      def add_licenses(licenses_list)
        @licenses.concat(licenses_list) if licenses_list.is_a?(Array)
      end

      def annotations
        @annotations
      end

      def add_annotation(annotation)
        @annotations << annotation
      end

      def add_annotations(annotations_list)
        @annotations.concat(annotations_list) if annotations_list.is_a?(Array)
      end

      def add_property(name, value)
        @properties << [name.strip, value]
      end

      def properties
        @properties
      end

      def to_h
        result = {
          type: @sbom_type,
          version: @version,
          uuid: @uuid,
          bom_version: @bom_version
        }

        result[:document] = @document if @document
        result[:files] = @files if @files.any?
        result[:packages] = @packages if @packages.any?
        result[:relationships] = @relationships if @relationships.any?
        result[:licenses] = @licenses if @licenses.any?
        result[:annotations] = @annotations if @annotations.any?
        result[:properties] = @properties if @properties.any?

        result.compact
      end
    end
  end
end
