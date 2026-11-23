# frozen_string_literal: true

require "json"
require "rexml/document"

module Sbom
  module Cyclonedx
    class Parser
      include XmlLookup

      FORMAT_JSON = :json
      FORMAT_XML = :xml

      def initialize(preserve_instances: false)
        @preserve_instances = preserve_instances
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

        metadata = xml_child(root, "metadata")
        components = xml_child(root, "components")
        dependencies = xml_child(root, "dependencies")
        parse_xml_metadata(metadata) if metadata
        parse_xml_components(components) if components
        parse_xml_dependencies(dependencies) if dependencies
      rescue REXML::ParseException => e
        raise ParserError, "Invalid XML: #{e.message}"
      end

      def parse_metadata(metadata)
        @document.created = metadata["timestamp"]

        if metadata["component"]
          @document.name = metadata["component"]["name"]
          @document.metadata_type = metadata["component"]["type"]
          @document.metadata_version = metadata["component"]["version"]
          @document[:component_id] = metadata["component"]["bom-ref"] if @preserve_instances
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

        @packages[Data::Package.identity_key(package.to_h, preserve_instances: @preserve_instances)] = package.to_h

        if parent_ref
          rel = Data::Relationship.new
          rel.source = parent_ref
          rel.target = package.id || package.name
          rel.relationship_type = @preserve_instances ? "CONTAINS" : "DEPENDS_ON"
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
        timestamp = xml_child(metadata, "timestamp")
        @document.created = timestamp.text if timestamp

        component = xml_child(metadata, "component")
        if component
          @document.name = xml_child(component, "name")&.text
          @document.metadata_type = component.attributes["type"]
          @document.metadata_version = xml_child(component, "version")&.text
          @document[:component_id] = component.attributes["bom-ref"] if @preserve_instances
        end

        supplier = xml_child(metadata, "supplier")
        @document.metadata_supplier = xml_child(supplier, "name")&.text if supplier
      end

      def parse_xml_components(components)
        xml_children(components, "component").each do |comp|
          parse_xml_component(comp)
        end
      end

      def parse_xml_component(comp)
        package = Data::Package.new
        package.name = xml_child(comp, "name")&.text
        package.version = xml_child(comp, "version")&.text
        package.id = comp.attributes["bom-ref"]
        package.package_type = comp.attributes["type"]
        package.description = xml_child(comp, "description")&.text

        supplier = xml_child(comp, "supplier")
        if supplier
          package.set_supplier("Organization", xml_child(supplier, "name")&.text)
        end

        xml_children(comp, "hashes", "hash").each do |hash|
          algo = hash.attributes["alg"]&.gsub("-", "")
          package.add_checksum(algo, hash.text) if algo
        end

        xml_children(comp, "licenses", "license").each do |lic|
          license_id = xml_child(lic, "id")&.text || xml_child(lic, "name")&.text
          if license_id
            package.license_concluded = license_id
            package.set_license_declared(license_id)
          end
        end

        purl = xml_child(comp, "purl")
        package.purl = purl.text if purl

        xml_children(comp, "externalReferences", "reference").each do |ref|
          ref_type = ref.attributes["type"]
          url = xml_child(ref, "url")&.text
          package.add_external_reference(ref_type, ref_type, url) if url
        end

        @packages[Data::Package.identity_key(package.to_h, preserve_instances: @preserve_instances)] = package.to_h

        nested = xml_child(comp, "components")
        parse_xml_components(nested) if nested
      end

      def parse_xml_dependencies(dependencies)
        xml_children(dependencies, "dependency").each do |dep|
          ref = dep.attributes["ref"]
          xml_children(dep, "dependency").each do |child|
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
        sbom = Data::Sbom.new(sbom_type: :cyclonedx, preserve_instances: @preserve_instances)
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
