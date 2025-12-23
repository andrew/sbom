# frozen_string_literal: true

module Sbom
  class Merger
    attr_reader :sboms, :options, :result

    def initialize(sboms, dedupe: :purl)
      @sboms = sboms
      @options = { dedupe: dedupe }
      @result = nil
    end

    def merge
      @result = Data::Sbom.new(sbom_type: determine_sbom_type)
      @result.version = determine_version

      build_document
      merge_packages
      merge_files
      merge_relationships
      merge_licenses
      merge_annotations

      @result
    end

    def determine_sbom_type
      types = @sboms.map(&:sbom_type).uniq
      return types.first if types.size == 1

      :spdx
    end

    def determine_version
      versions = @sboms.map(&:version).compact.uniq
      versions.first
    end

    def build_document
      names = @sboms.map { |s| s.document&.dig(:name) }.compact
      merged_name = names.any? ? "Merged: #{names.join(', ')}" : "Merged SBOM"

      @result.document = {
        name: merged_name,
        id: "SPDXRef-DOCUMENT",
        created: Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
      }
    end

    def merge_packages
      seen_purls = {}

      @sboms.each do |sbom|
        sbom.packages.each do |pkg|
          if @options[:dedupe] == :purl && pkg[:purl]
            next if seen_purls[pkg[:purl]]

            seen_purls[pkg[:purl]] = true
          end

          @result.add_package(pkg)
        end
      end
    end

    def merge_files
      @sboms.each do |sbom|
        sbom.files.each do |file|
          @result.add_file(file)
        end
      end
    end

    def merge_relationships
      seen = Set.new

      @sboms.each do |sbom|
        sbom.relationships.each do |rel|
          key = [rel[:source], rel[:type], rel[:target]]
          next if seen.include?(key)

          seen.add(key)
          @result.add_relationship(rel)
        end
      end
    end

    def merge_licenses
      seen = Set.new

      @sboms.each do |sbom|
        sbom.licenses.each do |lic|
          next if seen.include?(lic)

          seen.add(lic)
          @result.add_license(lic)
        end
      end
    end

    def merge_annotations
      @sboms.each do |sbom|
        sbom.annotations.each do |ann|
          @result.add_annotation(ann)
        end
      end
    end

    class << self
      def merge(sboms, dedupe: :purl)
        new(sboms, dedupe: dedupe).merge
      end

      def merge_files(filenames, dedupe: :purl)
        sboms = filenames.map { |f| Parser.parse_file(f) }
        merge(sboms, dedupe: dedupe)
      end
    end
  end
end
