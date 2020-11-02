# frozen_string_literal: true

require 'set'

require 'seccomp-tools/cli/base'
require 'seccomp-tools/const'
require 'seccomp-tools/disasm/disasm'
require 'seccomp-tools/emulator'
require 'seccomp-tools/util'

module SeccompTools
  module CLI
    # Handle 'emu' command.
    class Emu < Base
      # Summary of this command.
      SUMMARY = 'Emulate seccomp rules.'
      # Usage of this command.
      USAGE = "emu - #{SUMMARY}\n\nUsage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]"

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
        sys, *args = argv
        sys = evaluate_sys_nr(sys) if sys
        args.map! { |v| Integer(v) }
        trace = Set.new
        res = SeccompTools::Emulator.new(insts, sys_nr: sys, args: args, arch: option[:arch]).run do |ctx|
          trace << ctx[:pc]
        end

        if option[:verbose] >= 1
          disasm = SeccompTools::Disasm.disasm(raw, arch: option[:arch]).lines
          output_emulate_path(disasm, trace, res)
        end
        output do
          ret_type = Const::BPF::ACTION.invert[res[:ret] & Const::BPF::SECCOMP_RET_ACTION_FULL]
          errno = ret_type == :ERRNO ? "(#{res[:ret] & Const::BPF::SECCOMP_RET_DATA})" : ''
          format("return %s%s at line %04d\n", ret_type, errno, res[:pc])
        end
      end

      private

      # @param [String] str
      # @return [Integer]
      def evaluate_sys_nr(str)
        consts = SeccompTools::Const::Syscall.const_get(option[:arch].to_s.upcase)
        consts[str.to_sym] || Integer(str)
      end

      # output the path during emulation
      # @param [Array<String>] disasm
      # @param [Set] trace
      # @param [{Symbol => Object}] result
      def output_emulate_path(disasm, trace, result)
        output { disasm.shift }
        output { disasm.shift }
        disasm.each_with_index do |line, idx|
          output do
            next line if trace.member?(idx)

            Util.colorize(line, t: :gray)
          end
          # Too much remain, omit them.
          rem = disasm.size - idx - 1
          break output { Util.colorize("... (omitting #{rem} lines)\n", t: :gray) } if rem > 3 && idx > result[:pc] + 4
        end
        output { "\n" }
      end
    end
  end
end
