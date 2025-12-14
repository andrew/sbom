# frozen_string_literal: true

require "json"
require "yaml"

module Sbom
  class Output
    VALID_FORMATS = %i[tag json yaml].freeze

    def initialize(filename: nil, format: :tag)
      @filename = filename
      @format = validate_format(format)
      @output_type = filename && !filename.empty? ? :file : :console
    end

    def generate(data)
      formatted = format_data(data)
      send_output(formatted)
    end

    def format
      @format
    end

    def output_type
      @output_type
    end

    private

    def validate_format(format)
      format_sym = format.to_s.downcase.to_sym
      return format_sym if VALID_FORMATS.include?(format_sym)

      :tag
    end

    def format_data(data)
      case @format
      when :json
        format_json(data)
      when :yaml
        format_yaml(data)
      else
        format_tag(data)
      end
    end

    def format_json(data)
      if data.is_a?(String)
        data
      else
        JSON.pretty_generate(data)
      end
    end

    def format_yaml(data)
      if data.is_a?(String)
        YAML.safe_load(data).to_yaml
      else
        data.to_yaml
      end
    end

    def format_tag(data)
      if data.is_a?(Array)
        data.join("\n")
      else
        data.to_s
      end
    end

    def send_output(content)
      if @output_type == :file
        write_to_file(content)
      else
        puts content
      end
    end

    def write_to_file(content)
      File.write(@filename, content + "\n")
    rescue Errno::ENOENT, Errno::EACCES => e
      warn "Unable to write to file: #{e.message}"
      puts content
    end
  end
end
