# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "sbom"

require "minitest/autorun"

module TestHelpers
  def fixture_path(filename)
    File.join(File.dirname(__FILE__), "fixtures", filename)
  end

  def spec_path(filename)
    File.join(File.dirname(__FILE__), "..", "spec", filename)
  end

  def read_fixture(filename)
    File.read(fixture_path(filename))
  end

  def cyclonedx_schema_path(version)
    spec_path("cyclonedx/schema/bom-#{version}.schema.json")
  end

  def spdx_schema_path
    spec_path("spdx/schemas/spdx-schema.json")
  end
end

class Minitest::Test
  include TestHelpers
end
