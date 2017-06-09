require 'seccomp-tools/instruction/ld'

module SeccompTools
  module Instruction
    # Instruction st.
    class ST < LD
      # Decompile instruction.
      def decompile
        "mem[#{k}] = #{reg}"
      end

      def symbolize
        [:st, reg.downcase.to_sym, k]
      end

      # @return [Array<(Integer, Context)>]
      def branch(context)
        ctx = context.dup
        ctx[k] = ctx[reg]
        [[line + 1, ctx]]
      end
    end
  end
end
