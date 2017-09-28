require 'set'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/emulator'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Handle 'emu' command.
    class Emu < Base
      # Summary of this command.
      SUMMARY = 'Emulate seccomp rules.'.freeze
      # Usage of this command.
      USAGE = ('emu - ' +
               SUMMARY +
               "\n\n" \
               'Usage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]').freeze

      def initialize(*)
        super
        option[:verbose] = 1
      end

      # Define option parser.
      # @return [OptionParser]
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt)

          opt.on('-q', '--[no-]quiet', 'Run quietly, only show emulation result.') do |v|
            option[:verbose] = 0 if v
          end
        end
      end

      # Handle options.
      # @return [void]
      def handle
        return unless super
        option[:ifile] = argv.shift
        return CLI.show(parser.help) if option[:ifile].nil?
        raw = input
        insts = SeccompTools::Disasm.to_bpf(raw, option[:arch]).map(&:inst)
        disasm = SeccompTools::Disasm.disasm(raw, arch: option[:arch])
        sys, *args = argv
        sys = Integer(sys) if sys
        args.map! { |v| Integer(v) }
        trace = Set.new
        res = SeccompTools::Emulator.new(insts, sys_nr: sys, args: args, arch: option[:arch]).run do |ctx|
          trace << ctx[:pc]
        end

        if option[:verbose] >= 1
          disasm = disasm.lines
          output { disasm.shift }
          output { disasm.shift }
          disasm.each_with_index do |line, idx|
            output do
              next line if trace.member?(idx)
              Util.colorize(line, t: :gray)
            end
            # Too much remain, omit them.
            rem = disasm.size - idx - 1
            break output { Util.colorize("... (omitting #{rem} lines)\n", t: :gray) } if rem > 3 && idx > res[:pc] + 4
          end
          output { "\n" }
        end
        output do
          ret_type = Const::BPF::ACTION.invert[res[:ret] & 0x7fff0000]
          errno = ret_type == :ERRNO ? "(#{res[:ret] & 0xffff})" : ''
          format("return %s%s at line %04d\n", ret_type, errno, res[:pc])
        end
      end
    end
  end
end
