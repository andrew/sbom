# SBOM

A Ruby library for parsing, generating, and validating Software Bill of Materials in SPDX and CycloneDX formats.

## Installation

Add to your Gemfile:

```ruby
gem 'sbom'
```

Or install directly:

```bash
gem install sbom
```

## Usage

### Parsing SBOMs

```ruby
require 'sbom'

# Parse from file (auto-detects format)
sbom = Sbom.parse_file("example.spdx.json")

# Parse from string
sbom = Sbom.parse_string(content, sbom_type: :cyclonedx)

# Parsed data is returned as hashes
sbom.packages.each do |pkg|
  puts "#{pkg[:name]} @ #{pkg[:version]}"
  puts "  License: #{pkg[:license_concluded]}"
end

sbom.relationships.each do |rel|
  puts "#{rel[:source_id]} --[#{rel[:type]}]--> #{rel[:target_id]}"
end
```

### Generating SBOMs

```ruby
# Generate SPDX JSON
generator = Sbom::Generator.new(sbom_type: :spdx, format: :json)
generator.generate("MyProject", { packages: packages_data })
puts generator.output

# Generate CycloneDX
generator = Sbom::Generator.new(sbom_type: :cyclonedx)
generator.generate("MyProject", sbom_data)
File.write("sbom.cdx.json", generator.output)
```

### Validating SBOMs

```ruby
result = Sbom.validate_file("example.cdx.json")

if result.valid?
  puts "#{result.format}: version #{result.version}"
else
  puts "Invalid: #{result.errors.join(', ')}"
end

# Or raise on invalid
Sbom::Validator.validate_file!("example.cdx.json")
```

### Enriching SBOMs

Enrich packages with metadata from [ecosyste.ms](https://ecosyste.ms):

```ruby
# Enrich an entire SBOM
sbom = Sbom.parse_file("example.cdx.json")
enriched = Sbom.enrich(sbom)

# Or parse and enrich in one step
enriched = Sbom.enrich_file("example.cdx.json")

```

Enrichment adds: description, homepage, download location, license, repository URL, registry URL, documentation URL, supplier info, and security advisories.

### Merging SBOMs

Combine multiple SBOMs into one:

```ruby
# Merge from files (dedupes by PURL by default)
merged = Sbom.merge_files(["app1.cdx.json", "app2.spdx.json"])

# Merge SBOM objects
merged = Sbom.merge([sbom1, sbom2, sbom3])

# Keep all packages without deduplication
merged = Sbom.merge([sbom1, sbom2], dedupe: :none)
```

Merging works across formats. Packages are deduplicated by PURL by default. Relationships and licenses are also deduplicated.

### Building Packages

The Package class provides an object interface for building package data:

```ruby
package = Sbom::Data::Package.new
package.name = "rails"
package.version = "7.0.0"
package.license_concluded = "MIT"
package.add_checksum("SHA256", "abc123...")

# Generate a PURL
package.generate_purl(type: "gem")
# => "pkg:gem/rails@7.0.0"

# Or set an existing PURL
package.purl = "pkg:npm/%40angular/core@16.0.0"

# Access parsed PURL components
package.purl_type      # => "npm"
package.purl_namespace # => "@angular"
package.purl_name      # => "core"
package.purl_version   # => "16.0.0"

# Convert to hash for generation
package.to_h
```

## CLI

```bash
# Parse and display SBOM
sbom parse example.spdx.json
sbom parse example.cdx.json --format json

# Validate SBOM against schema
sbom validate example.spdx.json

# Convert between formats
sbom convert example.spdx.json --type cyclonedx --output example.cdx.json

# Generate new SBOM
sbom generate --name MyProject --type spdx --format json

# Document commands
sbom document outline example.cdx.json
sbom document info example.spdx.json
sbom document query example.cdx.json --package rails
sbom document query example.cdx.json --license MIT

# Enrich SBOM with ecosyste.ms data
sbom enrich example.cdx.json
sbom enrich example.cdx.json --output enriched.json
cat example.cdx.json | sbom enrich -

# Merge multiple SBOMs
sbom merge app1.cdx.json app2.spdx.json --output merged.json
sbom merge app1.json app2.json --no-dedupe
sbom merge app1.json app2.json --type cyclonedx
```

## Supported Formats

**SPDX** (versions 2.2, 2.3):
- Tag-Value (.spdx)
- JSON (.spdx.json)
- YAML (.spdx.yaml, .spdx.yml)
- XML (.spdx.xml)
- RDF (.spdx.rdf)

**CycloneDX** (versions 1.4, 1.5, 1.6, 1.7):
- JSON (.cdx.json, .bom.json)
- XML (.cdx.xml, .bom.xml)

## Related Libraries

- [purl](https://github.com/andrew/purl) - Package URL (PURL) parsing and generation
- [vers](https://github.com/andrew/vers) - Version range parsing and matching

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then run `rake test` to run the tests.

The project uses git submodules for the official SPDX and CycloneDX specifications:

```bash
git submodule update --init --recursive
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/andrew/sbom.
