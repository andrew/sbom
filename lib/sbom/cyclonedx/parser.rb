# frozen_string_literal: true

require "json"
require "rexml/document"

module Sbom
  module Cyclonedx
    class Parser
      FORMAT_JSON = :json
      FORMAT_XML = :xml

      def initialize
        @document = Data::Document.new
        @packages = {}
        @files = {}
        @relationships = []
        @licenses = []
        @version = nil
      end

      def parse(content, format = nil)
        format ||= detect_format(content)

        case format
        when FORMAT_JSON
          parse_json(content)
        when FORMAT_XML
          parse_xml(content)
        else
          raise ParserError, "Unknown CycloneDX format"
        end

        build_sbom
      end

      private

      def detect_format(content)
        stripped = content.strip
        return FORMAT_JSON if stripped.start_with?("{")
        return FORMAT_XML if stripped.start_with?("<")

        FORMAT_JSON
      end

      def parse_json(content)
        data = JSON.parse(content)
        return unless data["bomFormat"] == "CycloneDX"

        @version = data["specVersion"]
        @document.version = @version
        @document.sbom_type = "cyclonedx"
        @document.id = data["serialNumber"]

        parse_metadata(data["metadata"]) if data["metadata"]
        parse_components(data["components"]) if data["components"]
        parse_dependencies(data["dependencies"]) if data["dependencies"]
      rescue JSON::ParserError => e
        raise ParserError, "Invalid JSON: #{e.message}"
      end

      def parse_xml(content)
        doc = REXML::Document.new(content)
        root = doc.root
        return unless root && root.name == "bom"

        @schema = root.namespace
        @version = root.attributes["version"] || extract_version_from_namespace(@schema)
        @document.version = @version
        @document.sbom_type = "cyclonedx"
        @document.id = root.attributes["serialNumber"]

        parse_xml_metadata(root.elements["metadata"]) if root.elements["metadata"]
        parse_xml_components(root.elements["components"]) if root.elements["components"]
        parse_xml_dependencies(root.elements["dependencies"]) if root.elements["dependencies"]
      rescue REXML::ParseException => e
        raise ParserError, "Invalid XML: #{e.message}"
      end

      def parse_metadata(metadata)
        @document.created = metadata["timestamp"]

        if metadata["component"]
          @document.name = metadata["component"]["name"]
          @document.metadata_type = metadata["component"]["type"]
          @document.metadata_version = metadata["component"]["version"]
        end

        if metadata["supplier"]
          @document.metadata_supplier = metadata["supplier"]["name"]
        end

        if metadata["manufacture"]
          @document.metadata_supplier ||= metadata["manufacture"]["name"]
        end

        Array(metadata["lifecycles"]).each do |lc|
          @document.lifecycle = lc["phase"] if lc["phase"]
        end
      end

      def parse_components(components, parent_ref = nil)
        components.each do |comp|
          parse_component(comp, parent_ref)
        end
      end

      def parse_component(comp, parent_ref = nil)
        package = Data::Package.new
        package.name = comp["name"]
        package.version = comp["version"]
        package.id = comp["bom-ref"]
        package.package_type = comp["type"]
        package.description = comp["description"]
        package.copyright_text = comp["copyright"]

        if comp["supplier"]
          package.set_supplier("Organization", comp["supplier"]["name"])
        end

        if comp["author"]
          package.set_originator("Person", comp["author"])
        end

        Array(comp["hashes"]).each do |hash|
          algo = hash["alg"]&.gsub("-", "")
          package.add_checksum(algo, hash["content"]) if algo
        end

        Array(comp["licenses"]).each do |lic|
          if lic["license"]
            license_id = lic["license"]["id"] || lic["license"]["name"]
            package.license_concluded = license_id
            package.set_license_declared(license_id)
          elsif lic["expression"]
            package.license_concluded = lic["expression"]
            package.set_license_declared(lic["expression"])
          end
        end

        if comp["purl"]
          package.purl = comp["purl"]
        end

        Array(comp["externalReferences"]).each do |ref|
          package.add_external_reference(ref["type"], ref["type"], ref["url"])
        end

        Array(comp["properties"]).each do |prop|
          package.add_property(prop["name"], prop["value"])
        end

        @packages[[package.name, package.version]] = package.to_h

        if parent_ref
          rel = Data::Relationship.new
          rel.source = parent_ref
          rel.target = package.id || package.name
          rel.relationship_type = "DEPENDS_ON"
          @relationships << rel.to_h
        end

        if comp["components"]
          parse_components(comp["components"], package.id || package.name)
        end
      end

      def parse_dependencies(dependencies)
        dependencies.each do |dep|
          ref = dep["ref"]
          Array(dep["dependsOn"]).each do |depends_on|
            rel = Data::Relationship.new
            rel.source = ref
            rel.target = depends_on
            rel.relationship_type = "DEPENDS_ON"
            @relationships << rel.to_h
          end
        end
      end

      def parse_xml_metadata(metadata)
        timestamp = metadata.elements["timestamp"]
        @document.created = timestamp.text if timestamp

        component = metadata.elements["component"]
        if component
          @document.name = component.elements["name"]&.text
          @document.metadata_type = component.attributes["type"]
          @document.metadata_version = component.elements["version"]&.text
        end

        supplier = metadata.elements["supplier"]
        @document.metadata_supplier = supplier.elements["name"]&.text if supplier
      end

      def parse_xml_components(components)
        components.elements.each("component") do |comp|
          parse_xml_component(comp)
        end
      end

      def parse_xml_component(comp)
        package = Data::Package.new
        package.name = comp.elements["name"]&.text
        package.version = comp.elements["version"]&.text
        package.id = comp.attributes["bom-ref"]
        package.package_type = comp.attributes["type"]
        package.description = comp.elements["description"]&.text

        supplier = comp.elements["supplier"]
        if supplier
          package.set_supplier("Organization", supplier.elements["name"]&.text)
        end

        comp.elements.each("hashes/hash") do |hash|
          algo = hash.attributes["alg"]&.gsub("-", "")
          package.add_checksum(algo, hash.text) if algo
        end

        comp.elements.each("licenses/license") do |lic|
          license_id = lic.elements["id"]&.text || lic.elements["name"]&.text
          if license_id
            package.license_concluded = license_id
            package.set_license_declared(license_id)
          end
        end

        purl = comp.elements["purl"]
        package.purl = purl.text if purl

        comp.elements.each("externalReferences/reference") do |ref|
          ref_type = ref.attributes["type"]
          url = ref.elements["url"]&.text
          package.add_external_reference(ref_type, ref_type, url) if url
        end

        @packages[[package.name, package.version]] = package.to_h

        nested = comp.elements["components"]
        parse_xml_components(nested) if nested
      end

      def parse_xml_dependencies(dependencies)
        dependencies.elements.each("dependency") do |dep|
          ref = dep.attributes["ref"]
          dep.elements.each("dependency") do |child|
            rel = Data::Relationship.new
            rel.source = ref
            rel.target = child.attributes["ref"]
            rel.relationship_type = "DEPENDS_ON"
            @relationships << rel.to_h
          end
        end
      end

      def extract_version_from_namespace(namespace)
        return nil unless namespace

        match = namespace.match(/bom[\/\-](\d+\.\d+)/)
        match[1] if match
      end

      def build_sbom
        sbom = Data::Sbom.new(sbom_type: :cyclonedx)
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
