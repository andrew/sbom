# frozen_string_literal: true

module Sbom
  # Direct child lookups; REXML's XPath is several times slower per call.
  module XmlLookup
    def xml_child(element, name)
      element.children.find { |child| xml_named?(child, name) }
    end

    def xml_children(element, *path)
      path.reduce([element]) do |parents, name|
        parents.flat_map do |parent|
          parent.children.select { |child| xml_named?(child, name) }
        end
      end
    end

    # A prefixed element only counts when its prefix is bound to the default namespace.
    def xml_named?(node, name)
      return false unless node.is_a?(REXML::Element) && node.name == name

      node.prefix.empty? || node.namespace == node.namespace("")
    end
  end
end
