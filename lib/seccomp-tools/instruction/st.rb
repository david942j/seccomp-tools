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
      # @param [Symbolic::State] state
      #   Current state.
      # @return [Array<(Integer, Symbolic::State)>]
      #   Always the next line, with the register's value recorded in the scratch slot.
      def branch(state)
        mem = state.mem.dup
        mem[k] = reg == 'X' ? state.x : state.a
        [[line + 1, state.with(mem:)]]
      end
    end
  end
end
