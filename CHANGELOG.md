## [Unreleased]

- Add CycloneDX vulnerabilities array support to generator

## [0.3.0] - 2025-12-23

- Add `merge` command to CLI for combining multiple SBOMs into one
- Add `Sbom.merge` and `Sbom.merge_files` library methods
- Add `Sbom::Merger` class for merging SBOMs with configurable deduplication
- Merge deduplicates packages by PURL by default, with option to keep all
- Supports merging across formats (SPDX + CycloneDX)

## [0.2.0] - 2025-12-14

- Add `enrich` command to CLI for enriching SBOMs with data from ecosyste.ms
- Add `Sbom.enrich` and `Sbom.enrich_file` library methods
- Add `Sbom::Enricher` class for enriching packages with metadata and security advisories
- Enrichment adds: description, homepage, download location, license, repository URL, registry URL, documentation URL, supplier info, and security advisories

## [0.1.0] - 2025-12-14

- Initial release
