# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/instruction/base'
require 'seccomp-tools/util'

module SeccompTools
  module Instruction
    # Instruction ld, loads a value into the accumulator register A.
    #
    # The value can be an immediate, a word of +struct seccomp_data+, or a slot of the scratch
    # memory. {LDX} inherits from this class and targets the X register instead.
    class LD < Base
      # Decompile instruction.
      # @return [String]
      #   The assignment as assembly, e.g. +"A = sys_number"+.
      def decompile
        ret = "#{reg} = "
        _, _reg, type = symbolize
        return ret + type[:val].to_s if type[:rel] == :immi
        return ret + "mem[#{type[:val]}]" if type[:rel] == :mem

        ret + seccomp_data_str
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:ld, Symbol, {rel: Symbol, val: Integer}]]
      #   The target register and the value being loaded, whose +:rel+ is one of +:immi+, +:mem+
      #   or +:data+.
      def symbolize
        type = load_val
        [:ld, reg.downcase.to_sym, type]
      end

      # Name of the register being loaded into.
      # @return [String]
      #   The accumulator register, +"A"+.
      def reg
        'A'
      end

      # See {Base#branch}.
      # @param [SeccompTools::Disasm::Context] context
      #   Current context.
      # @return [Array<(Integer, SeccompTools::Disasm::Context)>]
      #   Always the next line, with the loaded value recorded in the context.
      def branch(context)
        ctx = context.dup
        ctx.load(reg, **load_val)
        [[line + 1, ctx]]
      end

      private

      def mode
        @mode ||= MODE.invert[code & 0xe0]
        # Seccomp doesn't support these modes
        invalid if @mode.nil? || @mode == :ind || @mode == :msh
        @mode
      end

      def load_val
        return { rel: :immi, val: k } if mode == :imm
        return { rel: :immi, val: SIZEOF_SECCOMP_DATA } if mode == :len
        return { rel: :mem, val: k } if mode == :mem

        { rel: :data, val: k }
      end

      # struct seccomp_data {
      #   int nr;
      #   __u32 arch;
      #   __u64 instruction_pointer;
      #   __u64 args[6];
      # };
      def seccomp_data_str
        case k
        when 0 then 'sys_number'
        when 4 then 'arch'
        when 8, 12 then hi_word?(k) ? 'instruction_pointer >> 32' : 'instruction_pointer'
        else
          idx = Array.new(12) { |i| (i * 4) + 16 }.index(k)
          return 'INVALID' if idx.nil?

          args_name(idx)
        end
      end

      # Is the 32-bit word at byte offset +k+ the high half of its 64-bit +seccomp_data+ field?
      # The high word comes second on little-endian architectures but first on big-endian ones
      # (s390x); see +arch_arg_offset_hi+ in libseccomp.
      def hi_word?(k)
        (k % 8 == 4) ^ Const::Endian.big?(arch)
      end

      def args_name(idx)
        hi = hi_word?((idx * 4) + 16)
        default = hi ? "args[#{idx / 2}] >> 32" : "args[#{idx / 2}]"
        return default unless show_arg_infer?

        sys_nrs = contexts.map { |ctx| ctx.known_data[0] }.uniq
        return default if sys_nrs.size != 1 || sys_nrs.first.nil?

        sys = Const::Syscall.const_get(arch.upcase.to_sym).invert[sys_nrs.first]
        args = Const::SYS_ARG[sys]
        return default if args.nil? || args[idx / 2].nil? # function prototype doesn't have that argument

        comment = "# #{sys}(#{args.join(', ')})"
        arg_name = Util.colorize(args[idx / 2], t: :args)
        "#{hi ? "#{arg_name} >> 32" : arg_name} #{Util.colorize(comment, t: :gray)}"
      end
    end
  end
end
