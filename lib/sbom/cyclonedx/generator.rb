# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module Sbom
  module Cyclonedx
    class Generator
      DEFAULT_VERSION = "1.6"
      SUPPORTED_VERSIONS = %w[1.4 1.5 1.6 1.7].freeze

      LIFECYCLE_PHASES = %w[
        design pre-build build post-build operations discovery decommission
      ].freeze

      def initialize(format: :json, application: "sbom", version: Sbom::VERSION)
        @format = format
        @application = application
        @app_version = version
        @spec_version = ENV.fetch("SBOM_CYCLONEDX_VERSION", DEFAULT_VERSION)
        @organization = ENV["SBOM_ORGANIZATION"]

        @output = {}
        @components = []
        @dependencies = []
        @vulnerabilities = []
        @element_refs = {}
      end

      def generate(project_name, sbom_data)
        return if sbom_data.nil? || (sbom_data.respond_to?(:empty?) && sbom_data.empty?)

        data = sbom_data.is_a?(Hash) ? sbom_data : sbom_data.to_h

        @spec_version = normalize_version(data[:version]) if data[:version]

        uuid = data[:uuid] || "urn:uuid:#{SecureRandom.uuid}"
        bom_version = data[:bom_version] || "1"

        component_data = extract_component_data(data)
        generate_document_header(project_name, component_data, uuid, bom_version)
        generate_components(data[:packages])
        generate_dependencies(data[:relationships])
        generate_vulnerabilities(data[:vulnerabilities])

        finalize_output
      end

      def output
        JSON.pretty_generate(@output)
      end

      def to_h
        @output
      end

      private

      def normalize_version(version)
        return version if SUPPORTED_VERSIONS.include?(version)

        match = version.to_s.match(/(\d+\.\d+)/)
        return match[1] if match && SUPPORTED_VERSIONS.include?(match[1])

        DEFAULT_VERSION
      end

      def extract_component_data(data)
        result = {
          type: "application",
          supplier: @organization,
          version: nil,
          bom_ref: nil,
          timestamp: nil,
          creator: nil,
          lifecycle: nil
        }

        return result unless data[:document]

        doc = data[:document]
        result[:type] = doc[:metadata_type] || "application"
        result[:supplier] = doc[:metadata_supplier] || @organization
        result[:version] = doc[:metadata_version]
        result[:bom_ref] = doc[:bom_ref]
        result[:lifecycle] = doc[:lifecycle]
        result[:timestamp] = doc[:created]
        result[:creator] = doc[:creators]&.first

        result
      end

      def generate_document_header(name, component_data, uuid, bom_version)
        timestamp = component_data[:timestamp] || Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        @output = {
          "bomFormat" => "CycloneDX",
          "specVersion" => @spec_version,
          "serialNumber" => uuid,
          "version" => bom_version.to_i
        }

        metadata = {
          "timestamp" => timestamp
        }

        if version_at_least?("1.5")
          metadata["tools"] = {
            "components" => [
              {
                "type" => "application",
                "name" => @application,
                "version" => @app_version
              }
            ]
          }
        else
          metadata["tools"] = [
            {
              "vendor" => "sbom",
              "name" => @application,
              "version" => @app_version
            }
          ]
        end

        if component_data[:supplier]
          metadata["supplier"] = { "name" => component_data[:supplier] }
        end

        if component_data[:lifecycle] && LIFECYCLE_PHASES.include?(component_data[:lifecycle])
          metadata["lifecycles"] = [{ "phase" => component_data[:lifecycle] }]
        end

        metadata["component"] = {
          "type" => component_data[:type],
          "name" => name
        }

        metadata["component"]["version"] = component_data[:version] if component_data[:version]
        metadata["component"]["bom-ref"] = component_data[:bom_ref] if component_data[:bom_ref]

        @output["metadata"] = metadata
      end

      def generate_components(packages_data)
        return unless packages_data

        packages = packages_data.is_a?(Hash) ? packages_data.values : packages_data
        packages.each_with_index do |pkg, index|
          generate_component(pkg, index + 1)
        end
      end

      def generate_component(pkg, index)
        name = pkg[:name]
        return unless name

        bom_ref = pkg[:bom_ref] || pkg[:id] || "#{index}-#{name}"
        @element_refs[name] = bom_ref

        component = {
          "type" => normalize_component_type(pkg[:type]),
          "name" => name,
          "bom-ref" => bom_ref
        }

        component["version"] = pkg[:version] if pkg[:version]
        component["description"] = pkg[:description] if pkg[:description]
        component["copyright"] = pkg[:copyright_text] if pkg[:copyright_text]

        if pkg[:supplier] && pkg[:supplier_type]
          component["supplier"] = { "name" => pkg[:supplier] }
        end

        if version_at_least?("1.7") && pkg[:originator]
          component["authors"] = [{ "name" => pkg[:originator] }]
        elsif pkg[:originator]
          component["author"] = pkg[:originator]
        end

        if pkg[:checksums]&.any?
          component["hashes"] = pkg[:checksums].map do |algo, value|
            { "alg" => normalize_algorithm(algo), "content" => value }
          end
        end

        licenses = extract_licenses(pkg)
        component["licenses"] = licenses if licenses.any?

        purl = pkg[:purl] || find_purl(pkg)
        component["purl"] = purl if purl

        if pkg[:external_references]&.any?
          refs = pkg[:external_references].reject { |r| r[1] == "purl" }
          if refs.any?
            component["externalReferences"] = refs.map do |ref|
              { "type" => ref[1], "url" => ref[2] }
            end
          end
        end

        if pkg[:properties]&.any?
          component["properties"] = pkg[:properties].map do |prop|
            { "name" => prop[0], "value" => prop[1].to_s }
          end
        end

        @components << component
      end

      def generate_dependencies(relationships_data)
        return unless relationships_data&.any?

        deps_map = {}

        relationships_data.each do |rel|
          source = rel[:source] || @element_refs.key(rel[:source_id])
          target = rel[:target] || @element_refs.key(rel[:target_id])

          next unless source && target

          source_ref = @element_refs[source] || source
          target_ref = @element_refs[target] || target

          deps_map[source_ref] ||= []
          deps_map[source_ref] << target_ref unless deps_map[source_ref].include?(target_ref)
        end

        deps_map.each do |ref, depends_on|
          @dependencies << {
            "ref" => ref,
            "dependsOn" => depends_on
          }
        end
      end

      def generate_vulnerabilities(vulnerabilities_data)
        return unless vulnerabilities_data&.any?

        vulnerabilities_data.each do |vuln|
          generate_vulnerability(vuln)
        end
      end

      def generate_vulnerability(vuln)
        return unless vuln[:id]

        vulnerability = { "id" => vuln[:id] }

        if vuln[:source]
          source = {}
          source["name"] = vuln[:source][:name] if vuln[:source][:name]
          source["url"] = vuln[:source][:url] if vuln[:source][:url]
          vulnerability["source"] = source if source.any?
        end

        if vuln[:ratings]&.any?
          vulnerability["ratings"] = vuln[:ratings].map do |rating|
            r = {}
            r["severity"] = rating[:severity] if rating[:severity]
            r["score"] = rating[:score] if rating[:score]
            r["method"] = rating[:method] if rating[:method]
            r
          end.reject(&:empty?)
        end

        vulnerability["description"] = vuln[:description] if vuln[:description]

        if vuln[:affects]&.any?
          vulnerability["affects"] = vuln[:affects].map do |affect|
            { "ref" => affect[:ref] }
          end
        end

        vulnerability["published"] = vuln[:published] if vuln[:published]
        vulnerability["updated"] = vuln[:updated] if vuln[:updated]

        @vulnerabilities << vulnerability
      end

      def finalize_output
        @output["components"] = @components if @components.any?
        @output["dependencies"] = @dependencies if @dependencies.any?
        @output["vulnerabilities"] = @vulnerabilities if @vulnerabilities.any?
      end

      def version_at_least?(version)
        Gem::Version.new(@spec_version) >= Gem::Version.new(version)
      end

      def normalize_component_type(type)
        return "library" unless type

        normalized = type.to_s.downcase.tr("_", "-")

        valid_types = %w[
          application framework library container operating-system
          device firmware file machine-learning-model data
          device-driver platform cryptographic-asset
        ]

        return "cryptographic-asset" if normalized == "cryptographic-asset" && version_at_least?("1.6")
        return "library" if normalized == "cryptographic-asset"

        valid_types.include?(normalized) ? normalized : "library"
      end

      def normalize_algorithm(algo)
        algo.to_s.gsub(/^SHA(\d)/, 'SHA-\1')
      end

      def extract_licenses(pkg)
        licenses = []

        license_id = pkg[:license_concluded] || pkg[:license_declared]
        return licenses unless license_id
        return licenses if %w[NOASSERTION NONE].include?(license_id.upcase)

        if license_id.include?(" AND ") || license_id.include?(" OR ")
          licenses << { "expression" => license_id }
        else
          license_entry = { "license" => {} }

          if license_id.start_with?("LicenseRef")
            license_entry["license"]["name"] = license_id
          else
            license_entry["license"]["id"] = license_id
          end

          if version_at_least?("1.6")
            if pkg[:license_concluded]
              license_entry["license"]["acknowledgement"] = "concluded"
            else
              license_entry["license"]["acknowledgement"] = "declared"
            end
          end

          licenses << license_entry
        end

        licenses
      end

      def find_purl(pkg)
        return nil unless pkg[:external_references]

        ref = pkg[:external_references].find { |r| r[1] == "purl" }
        ref&.last
      end
    end
  end
end
