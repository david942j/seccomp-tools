# frozen_string_literal: true

require 'json'

require 'seccomp-tools/audit'
require 'seccomp-tools/cli/base'
require 'seccomp-tools/cli/filter_input'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/logger'

module SeccompTools
  module CLI
    # Handle 'audit' command.
    class Audit < Base
      include FilterInput

      # Summary of this command.
      SUMMARY = 'Assess a seccomp filter for weaknesses and escape routes.'
      # Usage of this command.
      USAGE = "audit - #{SUMMARY}\n\nUsage: seccomp-tools audit [options] [BPF_FILE|EXEC]".freeze

      # Instantiate an {Audit} object.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:format] = :human
      end

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          option_filter_source(opt, 'audit')
          option_arch(opt, 'With an executable or --pid the architecture is auto-detected instead.')

          opt.on('-f', '--format FORMAT', %i[human json], 'Output format, one of <human|json>.',
                 'Default: human') do |f|
            option[:format] = f
          end
        end
      end

      # Reads the filter(s) from a BPF file, an executable, or an existing process, then reports the
      # weaknesses of each.
      # @return [void]
      def handle
        return unless super

        filters = collect_filters
        return if filters.empty?

        option[:format] == :json ? emit_json(filters) : emit_human(filters)
      end

      private

      # Prints each filter's report, warning first when several filters stack.
      def emit_human(filters)
        if filters.size > 1
          Logger.warn("#{filters.size} filters are installed; they stack, so a syscall must pass every one " \
                      '(most restrictive wins). Each is audited separately below.')
        end
        each_report(filters) { |report| output { report.to_s } }
      end

      # Prints one JSON document describing every stacked filter.
      def emit_json(filters)
        reports = []
        each_report(filters) { |report| reports << report.to_h }
        output { "#{JSON.pretty_generate(stacked_filters: filters.size, reports:)}\n" }
      end

      # Yields the {Audit::Report} of each filter, labelling stacked filters like +explain+ does.
      def each_report(filters)
        filters.each_with_index do |(raw, arch, source), idx|
          label = filters.size > 1 ? "#{source} (filter ##{idx})" : source
          insts = SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)
          yield SeccompTools::Audit.new(insts, arch:, source: label).audit
        end
      end
    end
  end
end
