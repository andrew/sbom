# frozen_string_literal: true

require_relative "lib/sbom/version"

Gem::Specification.new do |spec|
  spec.name = "sbom"
  spec.version = Sbom::VERSION
  spec.authors = ["Andrew Nesbitt"]
  spec.email = ["andrewnez@gmail.com"]

  spec.summary = "Parse, generate, and validate Software Bill of Materials (SBOM)"
  spec.description = "A Ruby library for working with Software Bill of Materials in SPDX and CycloneDX formats. Supports parsing, generation, validation, and format conversion."
  spec.homepage = "https://github.com/andrew/sbom"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/ spec/])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "json_schemer", "~> 2.0"
  spec.add_dependency "purl", "~> 1.6"
  spec.add_dependency "rexml", "~> 3.2"
end
