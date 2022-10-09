# frozen_string_literal: true

require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'

module SeccompTools
  module CLI
    # Handle 'disasm' command.
    class Disasm < Base
      # Summary of this command.
      SUMMARY = 'Disassemble seccomp bpf.'
      # Usage of this command.
      USAGE = "disasm - #{SUMMARY}\n\nUsage: seccomp-tools disasm BPF_FILE [options]"

      def initialize(*)
        super
        option[:bpf] = true
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.') do |o|
            option[:ofile] = o
          end
          opt.on('--[no-]bpf',
                 'Display BPF bytes (code, jt, etc.).',
                 'Output with \'--no-bpf\' is a valid syntax for passing to "seccomp-tools asm".',
                 'Default: true') do |f|
                   option[:bpf] = f
                 end

          option_arch(opt)
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super

        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?

        output { SeccompTools::Disasm.disasm(input, arch: option[:arch], display_bpf: option[:bpf]) }
      end
    end
  end
end
