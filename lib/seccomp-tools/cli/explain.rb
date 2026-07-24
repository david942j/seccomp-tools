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

      # Instantiate an {Explain} object.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:limit] = 1
        option[:pid] = nil
        option[:timeout] = nil
      end

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt, 'With an executable or --pid the architecture is auto-detected instead.')

          opt.on('-c', '--sh-exec <command>', 'Executes the given command (via sh) and explains its seccomp.',
                 'Use this to pass arguments or pipe things to the execution file.') do |command|
            option[:command] = command
          end

          opt.on('-l', '--limit LIMIT', Integer, 'Explain only the first LIMIT installed filters.',
                 'Only meaningful when the input is an executable or --pid. Default: 1') do |l|
            option[:limit] = l
          end

          opt.on('-p', '--pid PID', Integer, 'Explain the seccomp filters installed on an existing process.',
                 'You must have CAP_SYS_ADMIN (e.g. be root) to use this option.') do |p|
            option[:pid] = p
          end

          opt.on('-t', '--timeout SEC', Float, 'Timeout (seconds) for the execution. Default: no timeout') do |t|
            option[:timeout] = t
          end
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
