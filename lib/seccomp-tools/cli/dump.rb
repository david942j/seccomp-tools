require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/dumper'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      # Summary of this command.
      SUMMARY = 'Automatically dump seccomp bpf from execution file.'.freeze
      # Usage of this command.
      USAGE = ('dump - ' + SUMMARY + "\n\n" + 'Usage: seccomp-tools dump [exec] [options]').freeze

      def initialize(*)
        super
        option[:format] = :disasm
        option[:limit] = 1
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-c', '--sh-exec <command>', 'Executes the given command (via sh).',
                 'Use this option if want to pass arguments or do pipe things to the execution file.') do |command|
            option[:command] = command
          end

          opt.on('-f', '--format FORMAT', %i[disasm raw inspect],
                 'Output format. FORMAT can only be one of <disasm|raw|inspect>.',
                 'Default: disasm') do |f|
                   option[:format] = f
                 end

          opt.on('-l', '--limit LIMIT', 'Limit the number of calling "prctl(PR_SET_SECCOMP)".',
                 'The target process will be killed whenever its calling times reaches LIMIT.',
                 'Default: 1', Integer) do |l|
                   option[:limit] = l
                 end

          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.',
                 'If multiple seccomp syscalls have been invoked (see --limit),',
                 'results will be written to FILE, FILE_1, FILE_2.. etc.',
                 'For example, "--output out.bpf" and the output files are out.bpf, out_1.bpf, ...') do |o|
                   option[:ofile] = o
                 end
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super
        option[:command] = argv.shift unless argv.empty?
        SeccompTools::Dumper.dump('/bin/sh', '-c', option[:command], limit: option[:limit]) do |bpf, arch|
          case option[:format]
          when :inspect then output { '"' + bpf.bytes.map { |b| format('\\x%02X', b) }.join + "\"\n" }
          when :raw then output { bpf }
          when :disasm then output { SeccompTools::Disasm.disasm(bpf, arch: arch) }
          end
        end
      end
    end
  end
end
