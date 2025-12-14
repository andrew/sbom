# frozen_string_literal: true

module Sbom
  class Enricher
    attr_reader :sbom, :errors

    def initialize(sbom)
      @sbom = sbom
      @errors = []
    end

    def enrich
      @sbom.packages.each do |package|
        enrich_package(package)
      end
      @sbom
    end

    def enrich_package(package)
      purl_string = package[:purl] || find_purl_in_external_refs(package)
      return unless purl_string

      parsed = parse_purl(purl_string)
      return unless parsed

      lookup_data = fetch_lookup(parsed)
      enrich_from_lookup(package, lookup_data) if lookup_data

      advisories = fetch_advisories(parsed)
      enrich_from_advisories(package, advisories) if advisories&.any?
    rescue StandardError => e
      @errors << { purl: purl_string, error: e.message }
    end

    def self.enrich(sbom)
      new(sbom).enrich
    end

    def self.enrich_package(package)
      purl_string = package[:purl] || find_purl_in_refs(package)
      return package unless purl_string

      parsed = Purl.parse(purl_string)
      return package unless parsed

      lookup_data = parsed.lookup
      apply_lookup_enrichment(package, lookup_data) if lookup_data

      advisories = parsed.advisories
      apply_advisory_enrichment(package, advisories) if advisories&.any?

      package
    rescue StandardError
      package
    end

    private

    def find_purl_in_external_refs(package)
      refs = package[:external_references] || []
      refs.find { |_, type, _| type == "purl" }&.last
    end

    def self.find_purl_in_refs(package)
      refs = package[:external_references] || []
      refs.find { |_, type, _| type == "purl" }&.last
    end

    def parse_purl(purl_string)
      Purl.parse(purl_string)
    rescue Purl::InvalidPackageURL
      @errors << { purl: purl_string, error: "Invalid PURL format" }
      nil
    end

    def fetch_lookup(parsed_purl)
      parsed_purl.lookup
    rescue StandardError => e
      @errors << { purl: parsed_purl.to_s, error: "Lookup failed: #{e.message}" }
      nil
    end

    def fetch_advisories(parsed_purl)
      parsed_purl.advisories
    rescue StandardError => e
      @errors << { purl: parsed_purl.to_s, error: "Advisories fetch failed: #{e.message}" }
      []
    end

    def enrich_from_lookup(package, data)
      self.class.apply_lookup_enrichment(package, data)
    end

    def enrich_from_advisories(package, advisories)
      self.class.apply_advisory_enrichment(package, advisories)
    end

    def self.apply_lookup_enrichment(package, data)
      pkg_data = data[:package] || {}
      version_data = data[:version] || {}

      package[:description] ||= pkg_data[:description]
      package[:homepage] ||= pkg_data[:homepage]
      package[:download_location] ||= version_data[:download_url]

      if pkg_data[:licenses] && !package[:license_concluded]
        package[:license_concluded] = pkg_data[:licenses]
      end

      package[:repository_url] ||= pkg_data[:repository_url]
      package[:registry_url] ||= pkg_data[:registry_url]
      package[:documentation_url] ||= pkg_data[:documentation_url]

      if pkg_data[:maintainers]&.any? && !package[:supplier]
        first_maintainer = pkg_data[:maintainers].first
        package[:supplier] = first_maintainer[:login] if first_maintainer
        package[:supplier_type] = "Organization"
      end

      if pkg_data[:keywords]&.any?
        package[:tags] ||= []
        package[:tags].concat(pkg_data[:keywords]).uniq!
      end

      package[:properties] ||= []
      if pkg_data[:latest_version]
        package[:properties] << ["ecosystems:latest_version", pkg_data[:latest_version]]
      end
      if pkg_data[:latest_version_published_at]
        package[:properties] << ["ecosystems:latest_version_published_at", pkg_data[:latest_version_published_at]]
      end
      if pkg_data[:versions_count]
        package[:properties] << ["ecosystems:versions_count", pkg_data[:versions_count].to_s]
      end
      if version_data[:published_at]
        package[:properties] << ["ecosystems:version_published_at", version_data[:published_at]]
      end

      package
    end

    def self.apply_advisory_enrichment(package, advisories)
      package[:advisories] ||= []

      advisories.each do |advisory|
        package[:advisories] << {
          id: advisory[:id],
          title: advisory[:title],
          description: advisory[:description],
          severity: advisory[:severity],
          cvss_score: advisory[:cvss_score],
          url: advisory[:url],
          published_at: advisory[:published_at],
          source: advisory[:source_kind],
          references: advisory[:references]
        }
      end

      package
    end
  end
end
