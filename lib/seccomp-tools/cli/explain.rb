# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/cli/filter_input'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/explain'
require 'seccomp-tools/logger'

module SeccompTools
  module CLI
    # Handle 'explain' command.
    class Explain < Base
      include FilterInput

      # Summary of this command.
      SUMMARY = 'Summarize a seccomp filter as a per-action policy.'
      # Usage of this command.
      USAGE = "explain - #{SUMMARY}\n\nUsage: seccomp-tools explain [options] [BPF_FILE|EXEC]".freeze

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt, 'With an executable or --pid the architecture is auto-detected instead.')
          option_filter_source(opt, 'explain')
        end
      end

      # Reads the filter(s) from a BPF file, an executable, or an existing process, then prints the
      # policy of each.
      # @return [void]
      def handle
        return unless super

        filters = collect_filters
        if filters.size > 1
          Logger.warn("#{filters.size} filters are installed; they stack, so a syscall must pass every one " \
                      '(most restrictive wins). Each is explained separately below.')
        end
        filters.each_with_index do |(raw, arch, source), idx|
          label = filters.size > 1 ? "#{source} (filter ##{idx})" : source
          insts = SeccompTools::Disasm.to_bpf(raw, arch).map(&:inst)
          output { SeccompTools::Explain.new(insts, arch:, source: label).summarize.to_s }
        end
      end
    end
  end
end
