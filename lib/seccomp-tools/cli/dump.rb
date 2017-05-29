require 'shellwords'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/dumper'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Dump < Base
      SUMMARY = 'Automatically dump seccomp bpf from execution file'.freeze

      def initialize(argv)
        super
        option[:format] = :disasm
      end

      def usage
        'Usage: seccomp-tools dump [exec] [options]'
      end

      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-e', '--exec <command>', 'Executes the given command.',
                 'Use this option if want to pass arguments to target process.') do |command|
            option[:command] = command
          end

          opt.on('-f', '--format FORMAT', %i[disasm raw inspect],
                 'Output format. FORMAT can only be one of <disasm|raw|inspect>.',
                 'Default: disasm') do |f|
            option[:format] = f
          end
        end
      end

      def handle
        return unless super
        option[:command] = argv.shift unless argv.empty?
        SeccompTools::Dumper.dump(*Shellwords.split(option[:command])) do |bpf|
          case option[:format]
          when :inspect then output('"' + bpf.bytes.map { |b| format('\\x%02X', b) }.join + "\"\n")
          when :raw then output(bpf)
          when :disasm then nil # TODO: output(SeccompTools::Disasm.disasm(bpf))
          end
        end
      end

      private

      # Write data to stdout or file(s).
      def output(data)
        # if file name not present, just output to stdout.
        return $stdout.write(data) if option[:ofile].nil?
        # times of calling output
        @serial ||= 0
      end
    end
  end
end
