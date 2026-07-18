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
      USAGE = "emu - #{SUMMARY}\n\nUsage: seccomp-tools emu [options] BPF_FILE [sys_nr [arg0 [arg1 ... arg5]]]".freeze

      # Instantiate an {Emu} object, defaulting to verbose output.
      #
      # Takes the same arguments as {Base#initialize}.
      def initialize(*)
        super
        option[:verbose] = 1
      end

      # Define option parser.
      # @return [OptionParser]
      #   The parser of this command's options.
      def parser
        @parser ||= OptionParser.new do |opt|
          opt.banner = usage

          option_arch(opt)

          opt.on('-q', '--[no-]quiet', 'Run quietly, only show emulation result.') do |v|
            option[:verbose] = 0 if v
          end

          opt.on('-i', '--ip=VAL', Integer, 'Set instruction pointer.') do |val|
            option[:instruction_pointer] = val
          end
        end
      end

      # Emulates the filter against the given syscall and shows the resulting action.
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
        res = SeccompTools::Emulator.new(
          insts,
          sys_nr: sys,
          args:,
          instruction_pointer: option[:instruction_pointer] && Integer(option[:instruction_pointer]),
          arch: option[:arch]
        ).run

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

      # Resolves a syscall given on the command line, by name or by number.
      #
      # @param [String] str
      #   A syscall name valid for +option[:arch]+, or an integer literal.
      # @return [Integer]
      #   The syscall number.
      # @raise [ArgumentError]
      #   If +str+ is neither a known syscall name nor a valid integer.
      def evaluate_sys_nr(str)
        consts = SeccompTools::Const::Syscall.const_get(option[:arch].to_s.upcase)
        consts[str.to_sym] || Integer(str)
      end

      # Outputs the disassembly, highlighting the lines that were executed during emulation.
      #
      # @param [Array<String>] disasm
      #   Lines of the disassembly, including the two header lines.
      # @param [Set<Integer>] trace
      #   Line numbers that were reached.
      # @param [{Symbol => Integer}] result
      #   The emulation result, as returned by {SeccompTools::Emulator#run}.
      # @return [void]
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
