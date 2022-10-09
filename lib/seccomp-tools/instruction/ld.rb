# frozen_string_literal: true

require 'seccomp-tools/const'
require 'seccomp-tools/instruction/base'
require 'seccomp-tools/util'

module SeccompTools
  module Instruction
    # Instruction ld.
    class LD < Base
      # Decompile instruction.
      def decompile
        ret = "#{reg} = "
        _, _reg, type = symbolize
        return ret + type[:val].to_s if type[:rel] == :immi
        return ret + "mem[#{type[:val]}]" if type[:rel] == :mem

        ret + seccomp_data_str
      end

      # @return [void]
      def symbolize
        type = load_val
        [:ld, reg.downcase.to_sym, type]
      end

      # Accumulator register.
      # @return ['A']
      def reg
        'A'
      end

      # See {Base#branch}.
      # @param [Context] context
      #   Current context.
      # @return [Array<(Integer, Context)>]
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
        when 8 then 'instruction_pointer'
        when 12 then 'instruction_pointer >> 32'
        else
          idx = Array.new(12) { |i| i * 4 + 16 }.index(k)
          return 'INVALID' if idx.nil?

          args_name(idx)
        end
      end

      def args_name(idx)
        default = idx.even? ? "args[#{idx / 2}]" : "args[#{idx / 2}] >> 32"
        return default unless show_arg_infer?

        sys_nrs = contexts.map { |ctx| ctx.known_data[0] }.uniq
        return default if sys_nrs.size != 1 || sys_nrs.first.nil?

        sys = Const::Syscall.const_get(arch.upcase.to_sym).invert[sys_nrs.first]
        args = Const::SYS_ARG[sys]
        return default if args.nil? || args[idx / 2].nil? # function prototype doesn't have that argument

        comment = "# #{sys}(#{args.join(', ')})"
        arg_name = Util.colorize(args[idx / 2], t: :args)
        "#{idx.even? ? arg_name : "#{arg_name} >> 32"} #{Util.colorize(comment, t: :gray)}"
      end
    end
  end
end
