require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm'

module SeccompTools
  module CLI
    # Handle 'dump' command.
    class Disasm < Base
      # Summary of this command.
      SUMMARY = 'Disassembly seccomp bpf.'.freeze
      # Usage of this command.
      USAGE = ('disasm - ' + SUMMARY + "\n\n" + 'Usage: seccomp-tools disasm BPF_FILE [options]').freeze

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.') do |o|
            option[:ofile] = o
          end
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super
        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?
        output(SeccompTools::Disasm.disasm(IO.binread(option[:ifile])))
      end
    end
  end
end
