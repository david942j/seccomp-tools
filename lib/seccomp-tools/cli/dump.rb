# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/cli/filter_input'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      include FilterInput

      # Summary of this command.
      SUMMARY = 'Automatically dump seccomp bpf from execution file(s).'
      # Usage of this command.
      USAGE = "dump - #{SUMMARY}\nNOTE : This function is only available on Linux." \
              "\n\nUsage: seccomp-tools dump [EXEC] [options]".freeze

      # Instantiate a {Dump} object, dumping the first filter as disassembly by default.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:format] = :disasm
      end

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-f', '--format FORMAT', %i[disasm raw inspect],
                 'Output format. FORMAT can only be one of <disasm|raw|inspect>.',
                 'Default: disasm') do |f|
                   option[:format] = f
                 end

          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.',
                 'If multiple seccomp syscalls have been invoked (see --limit),',
                 'results will be written to FILE, FILE_1, FILE_2.. etc.',
                 'For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...') do |o|
                   option[:ofile] = o
                 end

          option_filter_source(
            opt, 'dump',
            sh_exec: ['e.g. use `-c "./bin > /dev/null"` to dump seccomp without being mixed with stdout.',
                      'Takes precedence over the [EXEC] argument.'],
            limit: ['The target process is killed once it reaches LIMIT.'],
            timeout: ['This option is ignored when --pid is given.']
          )
        end
      end

      # Traces the target process and writes out the seccomp filters it installs.
      #
      # Only available on Linux, logs an error and returns otherwise.
      # @return [void]
      def handle
        return unless dumping_supported?
        return unless super

        collect_filters.each { |bpf, arch| emit(bpf, arch) }
      end

      private

      # A positional argument is always an executable to trace, never a raw BPF blob to read: that is
      # +disasm+'s job, and a non-ELF executable (a shell script wrapping the target) must still run.
      # @return [Boolean]
      def accepts_raw_bpf?
        false
      end

      # Writes one dumped filter in the requested format.
      # @return [void]
      def emit(bpf, arch)
        case option[:format]
        when :inspect then output { "\"#{bpf.bytes.map { |b| format('\\x%02X', b) }.join}\"\n" }
        when :raw then output { bpf }
        when :disasm then output { SeccompTools::Disasm.disasm(bpf, arch:) }
        end
      end
    end
  end
end
