# frozen_string_literal: true

require 'seccomp-tools/instruction/ld'

module SeccompTools
  module Instruction
    # Instruction st, stores the accumulator register A into a slot of the scratch memory.
    #
    # {STX} inherits from this class and stores the X register instead.
    class ST < LD
      # Decompile instruction.
      # @return [String]
      #   The store as assembly, e.g. +"mem[0] = A"+.
      def decompile
        "mem[#{k}] = #{reg}"
      end

      # See {Instruction::Base#symbolize}.
      # @return [[:st, (:a, :x), Integer]]
      #   The source register and the index of the target memory slot.
      def symbolize
        [:st, reg.downcase.to_sym, k]
      end

      # See {Base#branch}.
      # @param [SeccompTools::Disasm::Context] context
      #   Current context.
      # @return [Array<(Integer, SeccompTools::Disasm::Context)>]
      #   Always the next line, with the stored value recorded in the context.
      def branch(context)
        ctx = context.dup
        ctx.store(k, reg)
        [[line + 1, ctx]]
      end
    end
  end
end
