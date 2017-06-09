require 'seccomp-tools/instruction/base'

module SeccompTools
  module Instruction
    # Instruction ld.
    class LD < Base
      # Decompile instruction.
      def decompile
        ret = reg + ' = '
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
        nctx = context.dup
        type = load_val
        nctx[reg] = case type[:rel]
                    when :immi then nil
                    when :mem then context[type[:val]]
                    when :data then type[:val]
                    end
        [[line + 1, nctx]]
      end

      private

      def mode
        @mode ||= MODE.invert[code & 0xe0]
        # Seccomp doesn't support this mode
        invalid if @mode.nil? || @mode == :ind
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
          idx.even? ? "args[#{idx / 2}]" : "args[#{idx / 2}] >> 32"
        end
      end
    end
  end
end
