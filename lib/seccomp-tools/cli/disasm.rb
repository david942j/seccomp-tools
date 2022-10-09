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
        option[:arg_infer] = true
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage
          opt.on('-o', '--output FILE', 'Output result into FILE instead of stdout.') do |o|
            option[:ofile] = o
          end
          option_arch(opt)
          opt.on('--[no-]bpf', 'Display BPF bytes (code, jt, etc.).',
                 'Default: true') do |f|
                   option[:bpf] = f
                 end
          opt.on('--[no-]arg-infer', 'Display syscall arguments with parameter names when possible.',
                 'Default: true') do |f|
                   option[:arg_infer] = f
                 end
          opt.on('--asm-able', 'Output with this flag is a valid input of "seccomp-tools asm".',
                 'By default, "seccomp-tools disasm" is in a human-readable format that easy for analysis.',
                 'Passing this flag can have the output be simplified to a valid input for "seccomp-tools asm".',
                 'This flag implies "--no-bpf --no-arg-infer".',
                 'Default: false') do |_f|
                   option[:bpf] = false
                   option[:arg_infer] = false
                 end
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super

        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?

        output do
          SeccompTools::Disasm.disasm(input, arch: option[:arch], display_bpf: option[:bpf],
                                             arg_infer: option[:arg_infer])
        end
      end
    end
  end
end
